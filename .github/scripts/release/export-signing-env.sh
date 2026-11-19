#!/usr/bin/env bash

# Hand the desktop signing secrets to the steps that follow this one.
#
# Usage: export-signing-env.sh <updater|all>
#
# The secrets are set on this step only (see its `env:` in the workflow) and
# written to GITHUB_ENV from here. Steps that run before it - third-party
# actions, dependency installation - never have them in their environment.
#
#   updater  the Tauri updater key pair
#   all      the updater key pair, plus the Apple signing secrets on a macOS
#            runner and the Windows signing secrets on a Windows runner
#
# Every name is always exported: a secret that does not apply to this runner,
# or is not configured, is exported empty, as an unset secret is.
set -euo pipefail

mode="${1:?usage: export-signing-env.sh <updater|all>}"
github_env="${GITHUB_ENV:?GITHUB_ENV is required}"

updater_names=(
  TAURI_UPDATER_PUBKEY
  TAURI_SIGNING_PRIVATE_KEY
  TAURI_SIGNING_PRIVATE_KEY_PASSWORD
)
macos_names=(
  APPLE_CERTIFICATE
  APPLE_CERTIFICATE_PASSWORD
  APPLE_SIGNING_IDENTITY
  APPLE_ID
  APPLE_PASSWORD
  APPLE_TEAM_ID
  KEYCHAIN_PASSWORD
)
windows_names=(
  TAURI_WINDOWS_SIGN_COMMAND
  TAURI_WINDOWS_CERTIFICATE_THUMBPRINT
  TAURI_WINDOWS_DIGEST_ALGORITHM
  TAURI_WINDOWS_TIMESTAMP_URL
  TAURI_WINDOWS_TSP
)

case "$mode" in
  updater | all) ;;
  *)
    echo "error: unknown mode: ${mode}" >&2
    exit 1
    ;;
esac

# A multi-line value needs a delimiter that no line of it equals.
delimiter="shk_signing_env_${RANDOM}${RANDOM}${RANDOM}"

export_name() {
  local name="$1" applies="$2" value=""
  if [[ "$applies" == "true" ]]; then
    value="${!name:-}"
  fi
  if [[ "$value" == *"$delimiter"* ]]; then
    echo "error: ${name} contains the GITHUB_ENV delimiter" >&2
    exit 1
  fi
  {
    printf '%s<<%s\n' "$name" "$delimiter"
    printf '%s\n' "$value"
    printf '%s\n' "$delimiter"
  } >> "$github_env"
}

for name in "${updater_names[@]}"; do
  export_name "$name" true
done

if [[ "$mode" == "all" ]]; then
  is_macos=false
  is_windows=false
  case "${RUNNER_OS:-}" in
    macOS) is_macos=true ;;
    Windows) is_windows=true ;;
  esac
  for name in "${macos_names[@]}"; do
    export_name "$name" "$is_macos"
  done
  for name in "${windows_names[@]}"; do
    export_name "$name" "$is_windows"
  done
fi
