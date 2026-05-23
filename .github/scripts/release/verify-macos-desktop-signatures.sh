#!/usr/bin/env bash
set -euo pipefail

artifacts_dir="${1:?artifact directory required}"

if [[ ! -d "$artifacts_dir" ]]; then
  echo "artifact directory not found: ${artifacts_dir}" >&2
  exit 1
fi

shopt -s nullglob globstar
dmg_files=( "${artifacts_dir}"/*.dmg )
app_archives=( "${artifacts_dir}"/*.app.tar.gz )

if ((${#dmg_files[@]} == 0)); then
  echo "no macOS DMG artifacts found in ${artifacts_dir}" >&2
  exit 1
fi

if ((${#app_archives[@]} == 0)); then
  echo "no macOS updater app archives found in ${artifacts_dir}" >&2
  exit 1
fi

verify_app() {
  local app="$1"

  codesign --verify --deep --strict --verbose=2 "$app"
  spctl --assess --type execute --verbose=4 "$app"
  xcrun stapler validate "$app"
  echo "valid macOS app signature and notarization: $(basename "$app")"
}

for dmg in "${dmg_files[@]}"; do
  spctl --assess --type open --context context:primary-signature --verbose=4 "$dmg"
  xcrun stapler validate "$dmg"
  echo "valid macOS DMG signature and notarization: $(basename "$dmg")"
done

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

for archive in "${app_archives[@]}"; do
  archive_dir="${tmpdir}/$(basename "$archive" .tar.gz)"
  mkdir -p "$archive_dir"
  tar -xzf "$archive" -C "$archive_dir"

  app_count=0
  apps=( "$archive_dir"/**/*.app )
  for app in "${apps[@]}"; do
    verify_app "$app"
    app_count=$((app_count + 1))
  done

  if ((app_count == 0)); then
    echo "no .app bundle found in $(basename "$archive")" >&2
    exit 1
  fi
done
