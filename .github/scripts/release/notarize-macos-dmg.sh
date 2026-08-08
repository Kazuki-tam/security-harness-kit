#!/usr/bin/env bash
set -euo pipefail

# Tauri notarizes the .app bundle but not the DMG built from it, so Gatekeeper
# assesses the DMG as "Unnotarized Developer ID". Submit each DMG for
# notarization and staple the ticket so the DMG passes spctl offline.
# Keep this script bash-3.2 compatible; macOS runners resolve `bash` to 3.2.

bundle_dir="${1:?dmg bundle directory required}"

: "${APPLE_ID:?APPLE_ID is required}"
: "${APPLE_PASSWORD:?APPLE_PASSWORD is required}"
: "${APPLE_TEAM_ID:?APPLE_TEAM_ID is required}"

if [[ ! -d "$bundle_dir" ]]; then
  echo "dmg bundle directory not found: ${bundle_dir}" >&2
  exit 1
fi

shopt -s nullglob
dmg_files=( "${bundle_dir}"/*.dmg )

if ((${#dmg_files[@]} == 0)); then
  echo "no DMG artifacts found in ${bundle_dir}" >&2
  exit 1
fi

for dmg in "${dmg_files[@]}"; do
  echo "notarizing $(basename "$dmg")"
  xcrun notarytool submit "$dmg" \
    --apple-id "$APPLE_ID" \
    --password "$APPLE_PASSWORD" \
    --team-id "$APPLE_TEAM_ID" \
    --wait
  # notarytool --wait can exit 0 on an Invalid submission; stapling only
  # succeeds when a ticket was actually issued, so it is the real gate.
  xcrun stapler staple "$dmg"
  echo "notarized and stapled: $(basename "$dmg")"
done
