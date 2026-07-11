#!/usr/bin/env bash
set -euo pipefail

assets_dir="${1:?assets directory required}"
version="${RELEASE_VERSION:?RELEASE_VERSION required}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=.github/scripts/release/common.sh
source "${ROOT}/.github/scripts/release/common.sh"

shk_require_semver "$version"

if [[ ! -d "$assets_dir" ]]; then
  echo "assets directory not found: ${assets_dir}" >&2
  exit 1
fi

require_asset() {
  local pattern="$1"
  shopt -s nullglob
  local matches=( "$assets_dir"/$pattern )
  if ((${#matches[@]} == 0)); then
    echo "missing unsigned desktop asset matching ${pattern}" >&2
    exit 1
  fi
  echo "ok: ${pattern}"
}

require_asset "shk-desktop_${version}_x86_64-unknown-linux-gnu_*.AppImage"
require_asset "shk-desktop_${version}_x86_64-unknown-linux-gnu_*.deb"
require_asset "shk-desktop_${version}_aarch64-unknown-linux-gnu_*.AppImage"
require_asset "shk-desktop_${version}_aarch64-unknown-linux-gnu_*.deb"
require_asset "shk-desktop_${version}_x86_64-apple-darwin_*.app.tar.gz"
require_asset "shk-desktop_${version}_aarch64-apple-darwin_*.app.tar.gz"
require_asset "shk-desktop_${version}_x86_64-pc-windows-msvc_*.exe"

for asset in "$assets_dir"/shk-desktop_*; do
  if [[ ! -s "$asset" ]]; then
    echo "empty unsigned desktop asset: ${asset}" >&2
    exit 1
  fi
done
echo "ok: unsigned desktop assets are non-empty"

echo "unsigned desktop release assets verified for ${version}"
