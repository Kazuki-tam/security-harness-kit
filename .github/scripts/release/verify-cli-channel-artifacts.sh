#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=.github/scripts/release/common.sh
source "${ROOT}/.github/scripts/release/common.sh"

assets_dir="${1:?usage: verify-cli-channel-artifacts.sh <assets-dir> <version>}"
version="${2:?usage: verify-cli-channel-artifacts.sh <assets-dir> <version>}"
shk_require_semver "$version"

if [[ ! -d "$assets_dir" ]]; then
  shk_error "CLI channel asset directory not found: ${assets_dir}"
  exit 1
fi
assets_dir="$(cd "$assets_dir" && pwd)"
workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT
shopt -s nullglob

for command in grep jq tar; do
  if ! command -v "$command" >/dev/null 2>&1; then
    shk_error "${command} is required to verify CLI channel artifacts"
    exit 1
  fi
done

verify_checksum() {
  local checksum_file="$1"
  (
    cd "$assets_dir"
    shk_verify_sha256_file "$(basename "$checksum_file")"
  )
}

dist_manifests=("$assets_dir"/*-dist-manifest.json)
if [[ "${#dist_manifests[@]}" -eq 0 ]]; then
  shk_error "no dist manifests found; cannot derive the required CLI archives"
  exit 1
fi
expected_archives=()
seen_archives=$'\n'
for manifest in "${dist_manifests[@]}"; do
  if ! jq empty "$manifest" >/dev/null 2>&1; then
    shk_error "invalid dist manifest: $(basename "$manifest")"
    exit 1
  fi
  manifest_archives=()
  while IFS= read -r archive_name; do
    [[ -n "$archive_name" ]] && manifest_archives+=("$archive_name")
  done < <(
    jq -r '
      (.artifacts // {})
      | to_entries[]
      | select(.value.kind == "executable-zip")
      | .value.name // empty
    ' "$manifest"
  )
  if [[ "${#manifest_archives[@]}" -ne 1 ]]; then
    shk_error "expected exactly one executable archive in $(basename "$manifest"), found ${#manifest_archives[@]}"
    exit 1
  fi
  archive_name="${manifest_archives[0]}"
  if [[ "$archive_name" == */* || ! "$archive_name" =~ ^shk-cli-[A-Za-z0-9_.-]+\.(tar\.xz|zip)$ ]]; then
    shk_error "unsafe or unexpected executable archive name in $(basename "$manifest"): ${archive_name}"
    exit 1
  fi
  if [[ "$seen_archives" == *$'\n'"${archive_name}"$'\n'* ]]; then
    shk_error "duplicate executable archive across dist manifests: ${archive_name}"
    exit 1
  fi
  seen_archives+="${archive_name}"$'\n'
  expected_archives+=("$archive_name")
done
for archive_name in "${expected_archives[@]}"; do
  archive="$assets_dir/$archive_name"
  if [[ ! -f "$archive" ]]; then
    shk_error "missing required CLI archive: ${archive_name}"
    exit 1
  fi
  checksum_file="${archive}.sha256"
  if [[ ! -f "$checksum_file" ]]; then
    shk_error "missing checksum for CLI archive: $(basename "$archive")"
    exit 1
  fi
  verify_checksum "$checksum_file"
done

verify_download_tag() {
  local label="$1"
  local path="$2"
  local repo_prefix="https://github.com/Kazuki-tam/security-harness-kit/releases/download"
  local referenced_tags
  referenced_tags="$(
    grep -r -h -E -o 'https://github\.com/Kazuki-tam/security-harness-kit/releases/download/[^/"[:space:]]+' "$path" 2>/dev/null \
      | sed 's#https://github.com/Kazuki-tam/security-harness-kit/releases/download/##' \
      | sort -u || true
  )"
  if ! grep -F -x -q "v${version}" <<<"$referenced_tags"; then
    shk_error "${label} does not reference ${repo_prefix}/v${version}"
    exit 1
  fi
  local unexpected_tags
  unexpected_tags="$(
    printf '%s\n' "$referenced_tags" \
      | grep -F -v -x "v${version}" \
      || true
  )"
  if [[ -n "$unexpected_tags" ]]; then
    shk_error "${label} references unexpected release tag(s): ${unexpected_tags//$'\n'/, }"
    exit 1
  fi
  echo "channel URL ok: ${label}"
}

shell_installers=("$assets_dir"/*-installer.sh)
powershell_installers=("$assets_dir"/*-installer.ps1)
if [[ "${#shell_installers[@]}" -ne 1 || "${#powershell_installers[@]}" -ne 1 ]]; then
  shk_error "expected exactly one shell and one PowerShell CLI installer in ${assets_dir}"
  exit 1
fi
verify_download_tag "$(basename "${shell_installers[0]}")" "${shell_installers[0]}"
verify_download_tag "$(basename "${powershell_installers[0]}")" "${powershell_installers[0]}"

formulas=("$assets_dir"/*.rb)
if [[ "${#formulas[@]}" -ne 1 ]]; then
  shk_error "expected exactly one Homebrew formula in ${assets_dir}"
  exit 1
fi
verify_download_tag "Homebrew formula" "${formulas[0]}"

npm_packages=("$assets_dir"/*-npm-package.tar.gz "$assets_dir"/*.tgz)
if [[ "${#npm_packages[@]}" -ne 1 ]]; then
  shk_error "expected exactly one npm package in ${assets_dir}"
  exit 1
fi
npm_package="${npm_packages[0]}"
archive_entries="$(tar -tzf "$npm_package")"
if grep -E -q '(^/|(^|/)\.\.(/|$))' <<<"$archive_entries"; then
  shk_error "npm package contains an unsafe archive path"
  exit 1
fi
archive_listing="$(tar -tvzf "$npm_package")"
if awk '$1 !~ /^[-d]/ { unsafe = 1 } END { exit unsafe ? 0 : 1 }' <<<"$archive_listing"; then
  shk_error "npm package contains a link or special archive entry"
  exit 1
fi
package_json_path="$(
  printf '%s\n' "$archive_entries" \
    | awk -F/ 'NF == 2 && $2 == "package.json" && path == "" { path = $0 } END { print path }'
)"
if [[ -z "$package_json_path" ]]; then
  shk_error "npm package does not contain a top-level package.json"
  exit 1
fi
package_json="$(tar -xzOf "$npm_package" "$package_json_path")"
package_name="$(jq -r '.name // empty' <<<"$package_json")"
package_version="$(jq -r '.version // empty' <<<"$package_json")"
if [[ "$package_name" != "security-harness-kit" || "$package_version" != "$version" ]]; then
  shk_error "npm package identity mismatch: expected security-harness-kit@${version}"
  exit 1
fi
npm_content="$workdir/npm-content.txt"
if ! (
  # Avoid extracting archive paths and cap the combined text inspected from a
  # compromised or malformed registry package at 10 MiB (ulimit uses 512-byte blocks).
  ulimit -f 20480
  tar -xzOf "$npm_package" > "$npm_content"
); then
  shk_error "npm package content exceeds the safe inspection limit or is unreadable"
  exit 1
fi
verify_download_tag "npm package" "$npm_content"

echo "CLI channel artifacts verified for v${version}"
