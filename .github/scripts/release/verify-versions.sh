#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=.github/scripts/release/common.sh
source "${ROOT}/.github/scripts/release/common.sh"

component="${RELEASE_COMPONENT:?RELEASE_COMPONENT is required}"
expected="${RELEASE_VERSION:?RELEASE_VERSION is required}"

shk_require_semver "$expected"

workspace_version="$(shk_workspace_version)"
tauri_version="$(shk_tauri_version)"
package_version="$(shk_desktop_package_version)"

verify_cli() {
  if [[ "$expected" != "$workspace_version" ]]; then
    echo "CLI version mismatch: expected ${expected} vs Cargo.toml ${workspace_version}" >&2
    exit 1
  fi
}

verify_desktop() {
  if [[ "$expected" != "$tauri_version" ]]; then
    echo "Desktop version mismatch: expected ${expected} vs tauri.conf.json ${tauri_version}" >&2
    exit 1
  fi
  if [[ "$expected" != "$package_version" ]]; then
    echo "Desktop version mismatch: expected ${expected} vs package.json ${package_version}" >&2
    exit 1
  fi
}

case "$component" in
  cli)
    verify_cli
    ;;
  desktop)
    verify_desktop
    ;;
  both)
    verify_cli
    verify_desktop
    ;;
  *)
    echo "unsupported RELEASE_COMPONENT: ${component}" >&2
    exit 1
    ;;
esac

echo "release versions verified for ${component} v${expected}"
