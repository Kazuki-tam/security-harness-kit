#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=.github/scripts/release/common.sh
source "${ROOT}/.github/scripts/release/common.sh"

shk_require_tauri_updater_signing

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
  # An invalid signing config must fail even when unsigned Windows is allowed.
  windows_mode="$(shk_windows_signing_mode)"
  if [[ "$windows_mode" == "none" && "${SHK_ALLOW_UNSIGNED_WINDOWS:-}" == "true" ]]; then
    echo "WARNING: Windows Authenticode signing is not configured; continuing unsigned (SHK_ALLOW_UNSIGNED_WINDOWS=true)."
  else
    shk_require_windows_signing
  fi
fi
