#!/usr/bin/env bash

# Build the npm packages for a CLI release from the cargo-dist archives.
#
# Usage: build-npm-packages.sh <assets-dir> <version> <out-dir>
#
# <assets-dir> must hold `shk-cli-<target>.{tar.xz,zip}` and the matching
# `.sha256` file for every target in `shk_npm_platforms`. Each archive is
# checked against its published SHA-256 before the binary is taken from it.
# Writes one `<name>-<version>.tgz` per package to <out-dir>:
#
#   security-harness-kit-<os>-<cpu>   the prebuilt binary, gated by os/cpu/libc
#   security-harness-kit              launcher + exact-version optionalDependencies
#
# No package has dependencies, install scripts, or a lockfile/shrinkwrap.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=.github/scripts/release/common.sh
source "${ROOT}/.github/scripts/release/common.sh"

usage="usage: build-npm-packages.sh <assets-dir> <version> <out-dir>"
assets_dir="${1:?$usage}"
version="${2:?$usage}"
out_dir="${3:?$usage}"
shk_require_stable_version "$version"

for command in jq npm tar unzip; do
  if ! command -v "$command" >/dev/null 2>&1; then
    shk_error "${command} is required to build the npm packages"
    exit 1
  fi
done
if [[ ! -d "$assets_dir" ]]; then
  shk_error "CLI asset directory not found: ${assets_dir}"
  exit 1
fi
assets_dir="$(cd "$assets_dir" && pwd)"
mkdir -p "$out_dir"
out_dir="$(cd "$out_dir" && pwd)"

template_dir="${ROOT}/packaging/npm"
repository_url="https://github.com/Kazuki-tam/security-harness-kit"
workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

pack() {
  local package_dir="$1"
  # --ignore-scripts: packing must not run lifecycle scripts even if one is
  # ever added by mistake; verify-npm-packages.sh rejects them outright.
  (cd "$package_dir" && npm pack --ignore-scripts --loglevel=error --pack-destination "$out_dir" >/dev/null)
}

base_manifest() {
  jq -n \
    --arg version "$version" \
    --arg repository "$repository_url" \
    '{
      version: $version,
      license: "MIT",
      repository: {type: "git", url: ("git+" + $repository + ".git")},
      homepage: $repository,
      bugs: {url: ($repository + "/issues")}
    }'
}

optional_dependencies='{}'
while read -r target os cpu libc binary cpus; do
  package="$(shk_npm_platform_package "$os" "$cpu")"
  archive_name="$(shk_cli_archive_name "$target")"
  archive="${assets_dir}/${archive_name}"
  if [[ ! -f "$archive" || ! -f "${archive}.sha256" ]]; then
    shk_error "missing CLI archive or checksum for ${target}: ${archive_name}"
    exit 1
  fi
  if ! (cd "$assets_dir" && shk_verify_sha256_file "${archive_name}.sha256"); then
    shk_error "SHA-256 mismatch for ${archive_name}"
    exit 1
  fi
  archive_sha256="$(shk_sha256_of "$archive")"

  package_dir="${workdir}/${package}"
  mkdir -p "${package_dir}/bin"
  shk_extract_cli_binary "$archive" "$binary" "${package_dir}/bin/${binary}"
  chmod 755 "${package_dir}/bin/${binary}"
  binary_sha256="$(shk_sha256_of "${package_dir}/bin/${binary}")"

  cp "${ROOT}/LICENSE" "${ROOT}/THIRD_PARTY_LICENSES.md" "$package_dir/"
  sed \
    -e "s|@PACKAGE@|${package}|g" \
    -e "s|@TARGET@|${target}|g" \
    -e "s|@ARCHIVE@|${archive_name}|g" \
    -e "s|@VERSION@|${version}|g" \
    "${template_dir}/README.platform.md" > "${package_dir}/README.md"

  base_manifest | jq \
    --arg name "$package" \
    --arg target "$target" \
    --arg os "$os" \
    --arg cpus "$cpus" \
    --arg libc "$libc" \
    --arg binary "$binary" \
    --arg archive "$archive_name" \
    --arg archive_sha256 "$archive_sha256" \
    --arg binary_sha256 "$binary_sha256" \
    '{
      name: $name,
      version,
      description: ("Prebuilt shk binary for " + $target + ". Install security-harness-kit instead."),
      license, repository, homepage, bugs,
      os: [$os],
      cpu: ($cpus | split(","))
    }
    + (if $libc == "-" then {} else {libc: [$libc]} end)
    + {
      files: [("bin/" + $binary), "THIRD_PARTY_LICENSES.md"],
      preferUnplugged: true,
      shkBinary: {
        target: $target,
        archive: $archive,
        archiveSha256: $archive_sha256,
        binarySha256: $binary_sha256
      }
    }' > "${package_dir}/package.json"

  pack "$package_dir"
  optional_dependencies="$(jq --arg name "$package" --arg version "$version" \
    '. + {($name): $version}' <<<"$optional_dependencies")"
  echo "built ${package}@${version} from ${archive_name} (binary sha256 ${binary_sha256})"
done < <(shk_npm_platforms)

package_dir="${workdir}/${SHK_NPM_PACKAGE}"
mkdir -p "${package_dir}/bin"
cp "${template_dir}/shk.js" "${package_dir}/bin/shk.js"
chmod 755 "${package_dir}/bin/shk.js"
cp "${ROOT}/LICENSE" "${ROOT}/README.md" "$package_dir/"
base_manifest | jq \
  --arg name "$SHK_NPM_PACKAGE" \
  --argjson optional_dependencies "$optional_dependencies" \
  '{
    name: $name,
    version,
    description: "shk: local-first security harness CLI for AI coding agents (secret and PII scanning, masking, AI tool hooks)",
    keywords: ["security", "secrets", "pii", "scanner", "ai", "hooks", "cli"],
    license, repository, homepage, bugs,
    bin: {shk: "bin/shk.js"},
    files: ["bin/shk.js"],
    engines: {node: ">=18"},
    optionalDependencies: $optional_dependencies
  }' > "${package_dir}/package.json"
pack "$package_dir"
echo "built ${SHK_NPM_PACKAGE}@${version}"
