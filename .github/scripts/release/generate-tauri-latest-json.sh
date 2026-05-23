#!/usr/bin/env bash
set -euo pipefail

assets_dir="${1:-release-assets}"
out="${2:-${assets_dir}/latest.json}"
repo="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
release_tag="${RELEASE_TAG:?RELEASE_TAG is required}"
version="${RELEASE_VERSION:?RELEASE_VERSION is required}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=.github/scripts/release/common.sh
source "${ROOT}/.github/scripts/release/common.sh"

shk_require_semver "$version"

if [[ ! -d "$assets_dir" ]]; then
  echo "assets directory not found: ${assets_dir}" >&2
  exit 1
fi

platforms_json="$(mktemp)"
printf '{}' > "$platforms_json"

add_platform() {
  local platform="$1"
  local target="$2"
  local asset_pattern="$3"
  local sig_pattern="$4"
  shopt -s nullglob
  local assets=( "${assets_dir}"/shk-desktop_"${version}"_"${target}"_${asset_pattern} )
  local sigs=( "${assets_dir}"/shk-desktop_"${version}"_"${target}"_${sig_pattern} )

  if ((${#assets[@]} == 0 && ${#sigs[@]} == 0)); then
    return 0
  fi

  if ((${#assets[@]} != 1 || ${#sigs[@]} != 1)); then
    echo "expected one update asset and one signature for ${platform}; got ${#assets[@]} assets and ${#sigs[@]} signatures" >&2
    exit 1
  fi

  local asset_name signature tmp
  asset_name="$(basename "${assets[0]}")"
  signature="$(tr -d '\r\n' < "${sigs[0]}")"
  tmp="$(mktemp)"

  jq \
    --arg platform "$platform" \
    --arg url "https://github.com/${repo}/releases/download/${release_tag}/${asset_name}" \
    --arg signature "$signature" \
    '. + {($platform): {url: $url, signature: $signature}}' \
    "$platforms_json" > "$tmp"
  mv "$tmp" "$platforms_json"
}

add_platform "linux-x86_64" "x86_64-unknown-linux-gnu" "*.AppImage" "*.AppImage.sig"
add_platform "linux-aarch64" "aarch64-unknown-linux-gnu" "*.AppImage" "*.AppImage.sig"
add_platform "darwin-x86_64" "x86_64-apple-darwin" "*.app.tar.gz" "*.app.tar.gz.sig"
add_platform "darwin-aarch64" "aarch64-apple-darwin" "*.app.tar.gz" "*.app.tar.gz.sig"
add_platform "windows-x86_64" "x86_64-pc-windows-msvc" "*setup*.exe" "*setup*.exe.sig"

platform_count="$(jq 'length' "$platforms_json")"
if [[ "$platform_count" == "0" ]]; then
  echo "no Tauri updater artifacts found in ${assets_dir}" >&2
  exit 1
fi

pub_date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
jq -n \
  --arg version "$version" \
  --arg pub_date "$pub_date" \
  --arg notes "See the GitHub release notes for desktop v${version}." \
  --slurpfile platforms "$platforms_json" \
  '{
    version: $version,
    notes: $notes,
    pub_date: $pub_date,
    platforms: $platforms[0]
  }' > "$out"

rm -f "$platforms_json"
echo "wrote ${out}"
