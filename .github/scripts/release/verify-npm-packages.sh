#!/usr/bin/env bash

# Verify the npm packages of a CLI release, either as built
# (build-npm-packages.sh) or as fetched back from the registry (`npm pack`).
#
# Usage: verify-npm-packages.sh <assets-dir> <version>
#
# <assets-dir> must hold every `<name>-<version>.tgz` plus the cargo-dist
# archives they were built from. Checks, for every package:
#   - the file list is exactly the expected one (so no npm-shrinkwrap.json,
#     lockfile, binding.gyp, or anything else can ride along)
#   - no lifecycle scripts and no dependencies of any kind
#   - the platform binary is byte-identical to the one in the release archive
#   - the main package pins every platform package to this exact version
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=.github/scripts/release/common.sh
source "${ROOT}/.github/scripts/release/common.sh"

usage="usage: verify-npm-packages.sh <assets-dir> <version>"
assets_dir="${1:?$usage}"
version="${2:?$usage}"
shk_require_semver "$version"

for command in jq tar unzip; do
  if ! command -v "$command" >/dev/null 2>&1; then
    shk_error "${command} is required to verify the npm packages"
    exit 1
  fi
done
if [[ ! -d "$assets_dir" ]]; then
  shk_error "npm package directory not found: ${assets_dir}"
  exit 1
fi
assets_dir="$(cd "$assets_dir" && pwd)"
workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

# Fields that would make the package manager run code at install time or pull
# in anything beyond the pinned platform packages.
readonly forbidden_fields_filter='
  [
    "scripts", "dependencies", "devDependencies", "peerDependencies",
    "bundleDependencies", "bundledDependencies", "gypfile"
  ] as $forbidden
  | [keys[] | select(. as $key | $forbidden | index($key))]
  | join(", ")
'

# Print the package.json of a tarball after checking its paths, entry types,
# identity, exact file list, and install-time fields.
verify_tarball() {
  local package="$1"
  shift
  local tarball="${assets_dir}/${package}-${version}.tgz"
  if [[ ! -f "$tarball" ]]; then
    shk_error "missing npm package tarball: ${package}-${version}.tgz"
    return 1
  fi

  local entries listing expected
  entries="$(tar -tzf "$tarball")"
  if grep -E -q '(^/|(^|/)\.\.(/|$))' <<<"$entries"; then
    shk_error "${package}: npm package contains an unsafe archive path"
    return 1
  fi
  listing="$(tar -tvzf "$tarball")"
  if awk '$1 !~ /^[-d]/ { unsafe = 1 } END { exit unsafe ? 0 : 1 }' <<<"$listing"; then
    shk_error "${package}: npm package contains a link or special archive entry"
    return 1
  fi

  entries="$(grep -v '/$' <<<"$entries" | LC_ALL=C sort)"
  expected="$(printf 'package/%s\n' package.json LICENSE README.md "$@" | LC_ALL=C sort)"
  if [[ "$entries" != "$expected" ]]; then
    shk_error "${package}: unexpected npm package contents: ${entries//$'\n'/, } (expected: ${expected//$'\n'/, })"
    return 1
  fi

  local manifest name manifest_version forbidden
  manifest="$(tar -xzOf "$tarball" package/package.json)"
  name="$(jq -r '.name // empty' <<<"$manifest")"
  manifest_version="$(jq -r '.version // empty' <<<"$manifest")"
  if [[ "$name" != "$package" || "$manifest_version" != "$version" ]]; then
    shk_error "npm package identity mismatch: expected ${package}@${version}, found ${name}@${manifest_version}"
    return 1
  fi
  forbidden="$(jq -r "$forbidden_fields_filter" <<<"$manifest")"
  if [[ -n "$forbidden" ]]; then
    shk_error "${package}: package.json must not define: ${forbidden}"
    return 1
  fi
  printf '%s\n' "$manifest"
}

expected_optional_dependencies='{}'
while read -r target os cpu libc binary; do
  package="$(shk_npm_platform_package "$os" "$cpu")"
  tarball="${assets_dir}/${package}-${version}.tgz"
  manifest="$(verify_tarball "$package" "bin/${binary}" THIRD_PARTY_LICENSES.md)"

  if ! jq -e --arg os "$os" --arg cpu "$cpu" --arg libc "$libc" '
    .os == [$os]
    and .cpu == [$cpu]
    and (if $libc == "-" then has("libc") | not else .libc == [$libc] end)
    and (has("bin") | not)
    and (has("optionalDependencies") | not)
  ' <<<"$manifest" >/dev/null; then
    shk_error "${package}: unexpected os/cpu/libc, bin, or optionalDependencies in package.json"
    exit 1
  fi

  if [[ "$binary" != *.exe ]] \
    && ! tar -tvzf "$tarball" | awk -v path="package/bin/${binary}" \
      '$NF == path && $1 ~ /^-rwx/ { found = 1 } END { exit found ? 0 : 1 }'; then
    shk_error "${package}: bin/${binary} is not executable in the tarball"
    exit 1
  fi

  archive_name="$(shk_cli_archive_name "$target")"
  archive="${assets_dir}/${archive_name}"
  if [[ ! -f "$archive" ]]; then
    shk_error "missing CLI archive to compare ${package} against: ${archive_name}"
    exit 1
  fi
  shk_extract_cli_binary "$archive" "$binary" "${workdir}/release-binary"
  tar -xzOf "$tarball" "package/bin/${binary}" > "${workdir}/npm-binary"
  release_sha256="$(shk_sha256_of "${workdir}/release-binary")"
  npm_sha256="$(shk_sha256_of "${workdir}/npm-binary")"
  recorded_sha256="$(jq -r '.shkBinary.binarySha256 // empty' <<<"$manifest")"
  recorded_archive_sha256="$(jq -r '.shkBinary.archiveSha256 // empty' <<<"$manifest")"
  if [[ "$npm_sha256" != "$release_sha256" || "$recorded_sha256" != "$release_sha256" ]]; then
    shk_error "${package}: binary does not match ${archive_name} (npm ${npm_sha256}, recorded ${recorded_sha256:-none}, release ${release_sha256})"
    exit 1
  fi
  if [[ "$recorded_archive_sha256" != "$(shk_sha256_of "$archive")" ]]; then
    shk_error "${package}: recorded archive SHA-256 does not match ${archive_name}"
    exit 1
  fi

  expected_optional_dependencies="$(jq --arg name "$package" --arg version "$version" \
    '. + {($name): $version}' <<<"$expected_optional_dependencies")"
  echo "npm package ok: ${package}@${version} (binary matches ${archive_name})"
done < <(shk_npm_platforms)

manifest="$(verify_tarball "$SHK_NPM_PACKAGE" bin/shk.js)"
if ! jq -e --argjson expected "$expected_optional_dependencies" '
  .bin == {shk: "bin/shk.js"}
  and .optionalDependencies == $expected
  and (has("os") | not)
  and (has("cpu") | not)
' <<<"$manifest" >/dev/null; then
  shk_error "${SHK_NPM_PACKAGE}: bin must be shk and optionalDependencies must pin every platform package to ${version}"
  exit 1
fi
echo "npm package ok: ${SHK_NPM_PACKAGE}@${version} (no dependencies, no install scripts)"

unexpected=()
shopt -s nullglob
for tarball in "$assets_dir"/*.tgz; do
  name="$(basename "$tarball" "-${version}.tgz")"
  if ! grep -F -x -q "$name" < <(shk_npm_package_names); then
    unexpected+=("$(basename "$tarball")")
  fi
done
if [[ "${#unexpected[@]}" -gt 0 ]]; then
  shk_error "unexpected npm package tarball(s): ${unexpected[*]}"
  exit 1
fi

echo "npm packages verified for v${version}"
