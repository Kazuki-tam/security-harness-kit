#!/usr/bin/env bash
set -euo pipefail

assets_dir="${1:-release-assets}"
checksum_file="${assets_dir}/shk-desktop.sha256sum"

shopt -s nullglob
files=( "${assets_dir}"/shk-desktop_* )

if ((${#files[@]} == 0)); then
  echo "no desktop release assets found in ${assets_dir}" >&2
  exit 1
fi

(
  cd "$assets_dir"
  sha256sum shk-desktop_*
) > "$checksum_file"

echo "wrote ${checksum_file}"
