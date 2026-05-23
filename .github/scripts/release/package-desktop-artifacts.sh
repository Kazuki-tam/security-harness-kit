#!/usr/bin/env bash
set -euo pipefail

target="${1:?target triple required}"
version="${2:?version required}"
out="${3:?output directory required}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=.github/scripts/release/common.sh
source "${ROOT}/.github/scripts/release/common.sh"

shk_require_semver "$version"

bundle="target/${target}/release/bundle"

if [[ ! -d "$bundle" ]]; then
  echo "bundle directory not found: $bundle" >&2
  exit 1
fi

mkdir -p "$out"

copy_glob() {
  local subdir="$1"
  shopt -s nullglob
  local files=( "$bundle/$subdir"/* )
  if ((${#files[@]} == 0)); then
    echo "no artifacts in $bundle/$subdir" >&2
    return 1
  fi
  local copied=0
  for file in "${files[@]}"; do
    [[ -f "$file" ]] || continue
    local base
    base="$(basename "$file")"
    cp "$file" "$out/shk-desktop_${version}_${target}_${base#shk_}"
    copied=$((copied + 1))
  done
  if ((copied == 0)); then
    echo "no file artifacts in $bundle/$subdir" >&2
    return 1
  fi
}

case "$(uname -s)" in
  Darwin)
    copy_glob dmg
    copy_glob macos
    ;;
  Linux)
    copy_glob appimage
    copy_glob deb
    ;;
  MINGW* | MSYS* | CYGWIN* | Windows*)
    copy_glob msi
    copy_glob nsis
    ;;
  *)
    echo "unsupported platform for packaging: $(uname -s)" >&2
    exit 1
    ;;
esac

echo "packaged desktop artifacts into $out"
ls -la "$out"
