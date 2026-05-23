#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=.github/scripts/release/common.sh
source "${ROOT}/.github/scripts/release/common.sh"

out="${1:?output config path required}"
repo="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
pubkey="${TAURI_UPDATER_PUBKEY:?TAURI_UPDATER_PUBKEY is required}"
windows_signing_mode="$(shk_windows_signing_mode)"
windows_sign_command="${TAURI_WINDOWS_SIGN_COMMAND:-}"
windows_certificate_thumbprint=""
if [[ "$windows_signing_mode" == "certificate" ]]; then
  windows_certificate_thumbprint="$(shk_normalize_windows_thumbprint "$TAURI_WINDOWS_CERTIFICATE_THUMBPRINT")"
fi
windows_digest_algorithm="${TAURI_WINDOWS_DIGEST_ALGORITHM:-sha256}"
windows_timestamp_url="${TAURI_WINDOWS_TIMESTAMP_URL:-}"
windows_tsp="${TAURI_WINDOWS_TSP:-false}"

mkdir -p "$(dirname "$out")"

jq -n \
  --arg pubkey "$pubkey" \
  --arg endpoint "https://github.com/${repo}/releases/download/desktop-latest/latest.json" \
  --arg windows_signing_mode "$windows_signing_mode" \
  --arg windows_sign_command "$windows_sign_command" \
  --arg windows_certificate_thumbprint "$windows_certificate_thumbprint" \
  --arg windows_digest_algorithm "$windows_digest_algorithm" \
  --arg windows_timestamp_url "$windows_timestamp_url" \
  --argjson windows_tsp "$windows_tsp" \
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
  }
  | if $windows_signing_mode == "command" then
      .bundle.windows = {
        signCommand: $windows_sign_command
      }
    elif $windows_signing_mode == "certificate" then
      .bundle.windows = {
        certificateThumbprint: $windows_certificate_thumbprint,
        digestAlgorithm: $windows_digest_algorithm,
        timestampUrl: $windows_timestamp_url,
        tsp: $windows_tsp
      }
    else
      .
    end' > "$out"

echo "wrote ${out}"
