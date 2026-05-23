#!/usr/bin/env bash
set -euo pipefail

out="${1:?output config path required}"
repo="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
pubkey="${TAURI_UPDATER_PUBKEY:?TAURI_UPDATER_PUBKEY is required}"

mkdir -p "$(dirname "$out")"

jq -n \
  --arg pubkey "$pubkey" \
  --arg endpoint "https://github.com/${repo}/releases/download/desktop-latest/latest.json" \
  '{
    bundle: {
      createUpdaterArtifacts: true
    },
    plugins: {
      updater: {
        pubkey: $pubkey,
        endpoints: [$endpoint],
        windows: {
          installMode: "passive"
        }
      }
    }
  }' > "$out"

echo "wrote ${out}"
