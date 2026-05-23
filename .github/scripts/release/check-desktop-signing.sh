#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=.github/scripts/release/common.sh
source "${ROOT}/.github/scripts/release/common.sh"

shk_require_env \
  "Tauri updater signing" \
  TAURI_UPDATER_PUBKEY \
  TAURI_SIGNING_PRIVATE_KEY

if [[ -n "${TAURI_SIGNING_PRIVATE_KEY_PASSWORD:-}" && -z "${TAURI_SIGNING_PRIVATE_KEY:-}" ]]; then
  shk_error "TAURI_SIGNING_PRIVATE_KEY_PASSWORD is set without TAURI_SIGNING_PRIVATE_KEY"
  exit 1
fi

is_windows_release_runner() {
  [[ "${RUNNER_OS:-}" == "Windows" ]] || [[ "${SHK_REQUIRE_WINDOWS_CODESIGN:-}" == "true" ]]
}

is_macos_release_runner() {
  [[ "${RUNNER_OS:-}" == "macOS" ]] || [[ "${RUNNER_OS:-}" == "macos" ]] || [[ "${SHK_REQUIRE_MACOS_CODESIGN:-}" == "true" ]]
}

if is_macos_release_runner; then
  shk_require_macos_signing
fi

if is_windows_release_runner; then
  shk_require_windows_signing
fi
