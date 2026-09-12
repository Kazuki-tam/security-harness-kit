#!/usr/bin/env bash
# Copy the versioned desktop installers to version-free file names so the
# `desktop-latest` release can serve stable download URLs such as
#   https://github.com/<repo>/releases/download/desktop-latest/shk-desktop-aarch64-apple-darwin.dmg
# The copies are byte-identical to the attested `shk-desktop_*` assets, so the
# versioned assets' provenance attestation covers the same content digest.
set -euo pipefail

assets_dir="${1:-release-assets}"
out_dir="${2:-release-assets-stable}"
version="${RELEASE_VERSION:?RELEASE_VERSION is required}"
release_tag="${RELEASE_TAG:?RELEASE_TAG is required}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=.github/scripts/release/common.sh
source "${ROOT}/.github/scripts/release/common.sh"

shk_require_semver "$version"

if [[ ! -d "$assets_dir" ]]; then
  echo "assets directory not found: ${assets_dir}" >&2
  exit 1
fi

assets_dir_abs="$(cd "$assets_dir" && pwd -P)"
out_parent="$(dirname "$out_dir")"
mkdir -p "$out_parent"
out_parent_abs="$(cd "$out_parent" && pwd -P)"
if [[ -d "$out_dir" ]]; then
  out_dir_abs="$(cd "$out_dir" && pwd -P)"
else
  out_dir_abs="${out_parent_abs}/$(basename "$out_dir")"
fi
if [[ "$assets_dir_abs" == "$out_dir_abs" ]]; then
  echo "output directory must differ from assets directory" >&2
  exit 1
fi

staging_dir="$(mktemp -d "${out_parent_abs}/.shk-desktop-stable.XXXXXX")"
backup_dir=""
cleanup() {
  if [[ -n "${staging_dir:-}" ]]; then
    rm -rf "$staging_dir"
  fi
  if [[ -n "${backup_dir:-}" && -e "$backup_dir" ]]; then
    if [[ -e "$out_dir" ]]; then
      rm -rf "$backup_dir"
    else
      mv "$backup_dir" "$out_dir"
    fi
  fi
}
trap cleanup EXIT

# copy_installer <target> <glob suffix> <stable suffix>
copy_installer() {
  local target="$1"
  local pattern="$2"
  local stable_suffix="$3"
  shopt -s nullglob
  local matches=( "${assets_dir}"/shk-desktop_"${version}"_"${target}"_${pattern} )

  if ((${#matches[@]} == 0)); then
    echo "missing ${pattern} installer for ${target}" >&2
    exit 1
  fi
  if ((${#matches[@]} != 1)); then
    echo "expected one ${pattern} installer for ${target}; got ${#matches[@]}" >&2
    exit 1
  fi

  local stable_name="shk-desktop-${target}${stable_suffix}"
  cp "${matches[0]}" "${staging_dir}/${stable_name}"
  echo "${stable_name} <- $(basename "${matches[0]}")"
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

manifest="${assets_dir}/shk-desktop-latest.json"
if [[ ! -f "$manifest" ]]; then
  echo "desktop release manifest not found: ${manifest}" >&2
  exit 1
fi
if ! jq -e \
  --arg version "$version" \
  --arg release_tag "$release_tag" \
  '.product == "shk-desktop"
    and .version == $version
    and .release_tag == $release_tag' \
  "$manifest" >/dev/null; then
  echo "desktop release manifest does not match ${release_tag} (${version})" >&2
  exit 1
fi
cp "$manifest" "${staging_dir}/shk-desktop-latest.json"

(
  cd "$staging_dir"
  shopt -s nullglob
  installers=( shk-desktop-*.dmg shk-desktop-*.AppImage shk-desktop-*.deb shk-desktop-*.exe shk-desktop-*.msi )
  if ((${#installers[@]} != 8)); then
    echo "expected 8 stable installers; got ${#installers[@]}" >&2
    exit 1
  fi
  sha256sum "${installers[@]}"
) > "${staging_dir}/shk-desktop.sha256sum"

if [[ -e "$out_dir" ]]; then
  backup_dir="${out_dir}.backup.$$"
  if [[ -e "$backup_dir" ]]; then
    echo "backup path already exists: ${backup_dir}" >&2
    exit 1
  fi
  mv "$out_dir" "$backup_dir"
fi

if ! mv "$staging_dir" "$out_dir"; then
  if [[ -n "$backup_dir" ]]; then
    mv "$backup_dir" "$out_dir"
  fi
  exit 1
fi
staging_dir=""
if [[ -n "$backup_dir" ]]; then
  rm -rf "$backup_dir"
fi

echo "wrote ${out_dir} (8 installers)"
