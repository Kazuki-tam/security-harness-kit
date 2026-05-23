#!/usr/bin/env bash
set -euo pipefail

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

require_all \
  "Tauri updater signing" \
  TAURI_UPDATER_PUBKEY \
  TAURI_SIGNING_PRIVATE_KEY

if [[ -n "${TAURI_SIGNING_PRIVATE_KEY_PASSWORD:-}" && -z "${TAURI_SIGNING_PRIVATE_KEY:-}" ]]; then
  error "TAURI_SIGNING_PRIVATE_KEY_PASSWORD is set without TAURI_SIGNING_PRIVATE_KEY"
  exit 1
fi
