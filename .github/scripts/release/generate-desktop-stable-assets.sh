#!/usr/bin/env bash
# Copy the versioned desktop installers to version-free file names so the
# `desktop-latest` release can serve immutable download URLs such as
#   https://github.com/<repo>/releases/download/desktop-latest/shk-desktop-aarch64-apple-darwin.dmg
# The copies are byte-identical to the attested `shk-desktop_*` assets, so the
# provenance attestation of the versioned release still verifies them.
set -euo pipefail

assets_dir="${1:-release-assets}"
out_dir="${2:-release-assets-stable}"
version="${RELEASE_VERSION:?RELEASE_VERSION is required}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=.github/scripts/release/common.sh
source "${ROOT}/.github/scripts/release/common.sh"

shk_require_semver "$version"

if [[ ! -d "$assets_dir" ]]; then
  echo "assets directory not found: ${assets_dir}" >&2
  exit 1
fi

mkdir -p "$out_dir"
rm -f "${out_dir}"/shk-desktop-* "${out_dir}/shk-desktop.sha256sum"

copied=0

# copy_installer <target> <glob suffix> <stable suffix>
copy_installer() {
  local target="$1"
  local pattern="$2"
  local stable_suffix="$3"
  shopt -s nullglob
  local matches=( "${assets_dir}"/shk-desktop_"${version}"_"${target}"_${pattern} )

  if ((${#matches[@]} == 0)); then
    return 0
  fi
  if ((${#matches[@]} != 1)); then
    echo "expected one ${pattern} installer for ${target}; got ${#matches[@]}" >&2
    exit 1
  fi

  local stable_name="shk-desktop-${target}${stable_suffix}"
  cp "${matches[0]}" "${out_dir}/${stable_name}"
  echo "${stable_name} <- $(basename "${matches[0]}")"
  copied=$((copied + 1))
}

for target in x86_64-apple-darwin aarch64-apple-darwin; do
  copy_installer "$target" "*.dmg" ".dmg"
done

for target in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu; do
  copy_installer "$target" "*.AppImage" ".AppImage"
  copy_installer "$target" "*.deb" ".deb"
done

copy_installer "x86_64-pc-windows-msvc" "*setup*.exe" "-setup.exe"
copy_installer "x86_64-pc-windows-msvc" "*.msi" ".msi"

if ((copied == 0)); then
  echo "no desktop installers found in ${assets_dir}" >&2
  exit 1
fi

# The versioned manifest tells the website which release the stable links
# currently resolve to.
if [[ -f "${assets_dir}/shk-desktop-latest.json" ]]; then
  cp "${assets_dir}/shk-desktop-latest.json" "${out_dir}/shk-desktop-latest.json"
fi

(
  cd "$out_dir"
  shopt -s nullglob
  installers=( shk-desktop-*.dmg shk-desktop-*.AppImage shk-desktop-*.deb shk-desktop-*.exe shk-desktop-*.msi )
  sha256sum "${installers[@]}"
) > "${out_dir}/shk-desktop.sha256sum"

echo "wrote ${out_dir} (${copied} installers)"
