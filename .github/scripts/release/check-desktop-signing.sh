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
  shk_require_windows_signing
fi
