#!/usr/bin/env bash
set -euo pipefail

warn() {
  if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
    echo "::warning::$*"
  else
    echo "warning: $*" >&2
  fi
}

error() {
  if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
    echo "::error::$*"
  else
    echo "error: $*" >&2
  fi
}

require_all() {
  local label="$1"
  shift
  local missing=()

  for name in "$@"; do
    if [[ -z "${!name:-}" ]]; then
      missing+=("$name")
    fi
  done

  if ((${#missing[@]} > 0)); then
    error "${label} is required. Missing: ${missing[*]}"
    exit 1
  fi

  echo "${label} is configured."
}

check_all_or_none() {
  local label="$1"
  shift
  local present=()
  local missing=()

  for name in "$@"; do
    if [[ -n "${!name:-}" ]]; then
      present+=("$name")
    else
      missing+=("$name")
    fi
  done

  if ((${#present[@]} == 0)); then
    warn "${label} is not configured; desktop artifacts will be built without this signing/notarization path."
    return 0
  fi

  if ((${#missing[@]} > 0)); then
    error "${label} is partially configured. Missing: ${missing[*]}"
    exit 1
  fi

  echo "${label} is configured."
}

check_all_or_none \
  "macOS signing and notarization" \
  APPLE_CERTIFICATE \
  APPLE_CERTIFICATE_PASSWORD \
  APPLE_SIGNING_IDENTITY \
  APPLE_ID \
  APPLE_PASSWORD \
  APPLE_TEAM_ID

if [[ "${1:-}" == "--require-updater" ]]; then
  require_all \
    "Tauri updater signing" \
    TAURI_UPDATER_PUBKEY \
    TAURI_SIGNING_PRIVATE_KEY
else
  check_all_or_none \
    "Tauri updater signing" \
    TAURI_UPDATER_PUBKEY \
    TAURI_SIGNING_PRIVATE_KEY
fi

if [[ -n "${TAURI_SIGNING_PRIVATE_KEY_PASSWORD:-}" && -z "${TAURI_SIGNING_PRIVATE_KEY:-}" ]]; then
  error "TAURI_SIGNING_PRIVATE_KEY_PASSWORD is set without TAURI_SIGNING_PRIVATE_KEY"
  exit 1
fi
