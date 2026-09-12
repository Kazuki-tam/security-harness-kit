#!/usr/bin/env bash
# Publish version-free desktop assets defensively. GitHub release assets cannot
# be replaced atomically, so each content asset is retried and downloaded for
# byte-for-byte verification before metadata is updated.
set -euo pipefail

stable_dir="${1:-release-assets-stable}"
updater_metadata="${2:-release-assets/latest.json}"
release_tag="${3:-desktop-latest}"
repo="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=.github/scripts/release/common.sh
source "${ROOT}/.github/scripts/release/common.sh"

expected_assets=(
  shk-desktop-aarch64-apple-darwin.dmg
  shk-desktop-x86_64-apple-darwin.dmg
  shk-desktop-aarch64-unknown-linux-gnu.AppImage
  shk-desktop-aarch64-unknown-linux-gnu.deb
  shk-desktop-x86_64-unknown-linux-gnu.AppImage
  shk-desktop-x86_64-unknown-linux-gnu.deb
  shk-desktop-x86_64-pc-windows-msvc-setup.exe
  shk-desktop-x86_64-pc-windows-msvc.msi
  shk-desktop.sha256sum
  shk-desktop-latest.json
)

if [[ ! -d "$stable_dir" ]]; then
  shk_error "stable assets directory not found: ${stable_dir}"
  exit 1
fi
if [[ ! -f "$updater_metadata" ]]; then
  shk_error "updater metadata not found: ${updater_metadata}"
  exit 1
fi

for name in "${expected_assets[@]}"; do
  if [[ ! -f "${stable_dir}/${name}" ]]; then
    shk_error "stable asset not found: ${stable_dir}/${name}"
    exit 1
  fi
done

shopt -s nullglob
actual_assets=( "${stable_dir}"/shk-desktop-* "${stable_dir}/shk-desktop.sha256sum" )
if ((${#actual_assets[@]} != ${#expected_assets[@]})); then
  shk_error "expected ${#expected_assets[@]} stable assets; got ${#actual_assets[@]}"
  exit 1
fi

is_expected_asset() {
  local candidate="$1"
  local expected
  for expected in "${expected_assets[@]}"; do
    if [[ "$candidate" == "$expected" ]]; then
      return 0
    fi
  done
  return 1
}

for path in "${actual_assets[@]}"; do
  if ! is_expected_asset "$(basename "$path")"; then
    shk_error "unexpected stable asset: ${path}"
    exit 1
  fi
done

verify_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$verify_dir"
}
trap cleanup EXIT

verify_remote_asset() {
  local name="$1"
  local source_path="$2"
  rm -f "${verify_dir}/${name}"
  gh release download "$release_tag" \
    --pattern "$name" \
    --dir "$verify_dir" \
    --clobber >/dev/null &&
    cmp -s "$source_path" "${verify_dir}/${name}"
}

upload_and_verify() {
  local path="$1"
  local name
  name="$(basename "$path")"
  shk_retry 5 2 16 gh release upload "$release_tag" "$path" --clobber
  if ! shk_retry 5 2 16 verify_remote_asset "$name" "$path"; then
    shk_error "published asset verification failed: ${name}"
    exit 1
  fi
  echo "published and verified ${name}"
}

# Upload binary content first, followed by its checksum and release manifest.
# The updater metadata is intentionally published only after the complete
# stable asset set has been verified.
for name in "${expected_assets[@]:0:8}"; do
  upload_and_verify "${stable_dir}/${name}"
done
upload_and_verify "${stable_dir}/shk-desktop.sha256sum"
upload_and_verify "${stable_dir}/shk-desktop-latest.json"

remote_assets="$(shk_retry 5 2 16 gh api \
  "repos/${repo}/releases/tags/${release_tag}" \
  --jq '.assets[] | [.id, .name] | @tsv')"
while IFS=$'\t' read -r asset_id asset_name; do
  if [[ "$asset_name" != "latest.json" ]] && ! is_expected_asset "$asset_name"; then
    shk_retry 5 2 16 gh api --method DELETE \
      "repos/${repo}/releases/assets/${asset_id}"
    echo "removed stale asset ${asset_name}"
  fi
done <<<"$remote_assets"

remote_assets="$(shk_retry 5 2 16 gh api \
  "repos/${repo}/releases/tags/${release_tag}" \
  --jq '.assets[] | [.id, .name] | @tsv')"
stable_asset_count=0
while IFS=$'\t' read -r _ asset_name; do
  if [[ "$asset_name" == "latest.json" ]]; then
    continue
  fi
  if ! is_expected_asset "$asset_name"; then
    shk_error "unexpected published asset remains: ${asset_name}"
    exit 1
  fi
  stable_asset_count=$((stable_asset_count + 1))
done <<<"$remote_assets"
if ((stable_asset_count != ${#expected_assets[@]})); then
  shk_error "expected ${#expected_assets[@]} published stable assets; got ${stable_asset_count}"
  exit 1
fi

echo "verified complete stable asset set"
upload_and_verify "$updater_metadata"
