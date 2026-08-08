#!/usr/bin/env bash

# Shared helpers for release scripts. Source from repo root.

readonly SHK_SEMVER_RE='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'

shk_error() {
  if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
    echo "::error::$*"
  else
    echo "error: $*" >&2
  fi
}

shk_require_semver() {
  local version="$1"
  if [[ ! "$version" =~ $SHK_SEMVER_RE ]]; then
    shk_error "invalid semver: ${version}"
    exit 1
  fi
}

shk_require_env() {
  local label="$1"
  shift
  local missing=()

  for name in "$@"; do
    if [[ -z "${!name:-}" ]]; then
      missing+=("$name")
    fi
  done

  if ((${#missing[@]} > 0)); then
    shk_error "${label} is required. Missing: ${missing[*]}"
    exit 1
  fi

  echo "${label} is configured."
}

shk_require_bool_env() {
  local name="$1"
  local value="${!name:-}"
  case "$value" in
    true | false)
      ;;
    *)
      shk_error "${name} must be true or false"
      exit 1
      ;;
  esac
}

shk_require_tauri_updater_signing() {
  shk_require_env \
    "Tauri updater signing" \
    TAURI_UPDATER_PUBKEY \
    TAURI_SIGNING_PRIVATE_KEY

  if [[ -n "${TAURI_SIGNING_PRIVATE_KEY_PASSWORD:-}" && -z "${TAURI_SIGNING_PRIVATE_KEY:-}" ]]; then
    shk_error "TAURI_SIGNING_PRIVATE_KEY_PASSWORD is set without TAURI_SIGNING_PRIVATE_KEY"
    exit 1
  fi
}

shk_normalize_windows_thumbprint() {
  local raw="$1"
  local normalized
  normalized="$(printf '%s' "$raw" | tr -d '[:space:]:' | tr '[:lower:]' '[:upper:]')"

  if [[ ! "$normalized" =~ ^[0-9A-F]{40}$ ]]; then
    shk_error "TAURI_WINDOWS_CERTIFICATE_THUMBPRINT must be a 40-character SHA-1 hex thumbprint"
    exit 1
  fi

  printf '%s' "$normalized"
}

shk_windows_signing_mode() {
  local has_command=false
  local has_certificate=false

  [[ -n "${TAURI_WINDOWS_SIGN_COMMAND:-}" ]] && has_command=true
  if [[ -n "${TAURI_WINDOWS_CERTIFICATE_THUMBPRINT:-}" || -n "${TAURI_WINDOWS_TIMESTAMP_URL:-}" ]]; then
    has_certificate=true
  fi

  if [[ "$has_command" == true && "$has_certificate" == true ]]; then
    shk_error "configure either TAURI_WINDOWS_SIGN_COMMAND or certificate thumbprint signing, not both"
    exit 1
  fi

  if [[ "$has_command" == true ]]; then
    if [[ "${TAURI_WINDOWS_SIGN_COMMAND}" != *"%1"* ]]; then
      shk_error "TAURI_WINDOWS_SIGN_COMMAND must include %1 as the file placeholder"
      exit 1
    fi
    printf 'command'
    return
  fi

  if [[ "$has_certificate" == true ]]; then
    shk_require_env \
      "Windows Authenticode signing" \
      TAURI_WINDOWS_CERTIFICATE_THUMBPRINT \
      TAURI_WINDOWS_TIMESTAMP_URL >/dev/null

    TAURI_WINDOWS_DIGEST_ALGORITHM="${TAURI_WINDOWS_DIGEST_ALGORITHM:-sha256}"
    case "$TAURI_WINDOWS_DIGEST_ALGORITHM" in
      sha1 | sha256)
        ;;
      *)
        shk_error "TAURI_WINDOWS_DIGEST_ALGORITHM must be sha1 or sha256"
        exit 1
        ;;
    esac

    TAURI_WINDOWS_TSP="${TAURI_WINDOWS_TSP:-false}"
    shk_require_bool_env TAURI_WINDOWS_TSP
    shk_normalize_windows_thumbprint "$TAURI_WINDOWS_CERTIFICATE_THUMBPRINT" >/dev/null
    printf 'certificate'
    return
  fi

  printf 'none'
}

shk_require_windows_signing() {
  local mode
  mode="$(shk_windows_signing_mode)"
  if [[ "$mode" == "none" ]]; then
    shk_error "Windows Authenticode signing is required. Configure TAURI_WINDOWS_SIGN_COMMAND or certificate thumbprint signing."
    exit 1
  fi

  case "$mode" in
    command)
      echo "Windows Authenticode signing is configured with a custom sign command."
      ;;
    certificate)
      echo "Windows Authenticode signing is configured with a certificate thumbprint."
      ;;
  esac
}

shk_require_macos_signing() {
  shk_require_env \
    "macOS Developer ID signing" \
    APPLE_CERTIFICATE \
    APPLE_CERTIFICATE_PASSWORD \
    APPLE_SIGNING_IDENTITY \
    KEYCHAIN_PASSWORD

  shk_require_env \
    "macOS notarization" \
    APPLE_ID \
    APPLE_PASSWORD \
    APPLE_TEAM_ID

  echo "macOS Developer ID signing and notarization are configured."
}

shk_workspace_version() {
  awk -F'"' '/^version = / { print $2; exit }' Cargo.toml
}

shk_tauri_version() {
  jq -r .version apps/shk-desktop/src-tauri/tauri.conf.json
}

shk_desktop_package_version() {
  jq -r .version apps/shk-desktop/package.json
}

shk_gh_output() {
  printf '%s\n' "$@"
}

shk_desktop_release_notes() {
  local version="$1"
  local windows_note
  if [[ "${SHK_ALLOW_UNSIGNED_WINDOWS:-}" == "true" && "$(shk_windows_signing_mode)" == "none" ]]; then
    windows_note='Windows installers are **not** Authenticode-signed in this release; SmartScreen may warn on first run. Choose "More info", then "Run anyway".'
  else
    windows_note="Windows installers are Authenticode-signed and verified during release."
  fi
  cat <<EOF
## shk Desktop v${version}

Installers for macOS, Linux, and Windows are attached as \`shk-desktop_*\` assets.
macOS installers are Developer ID signed, notarized, stapled, and verified during release.
${windows_note}
Checksums are in \`shk-desktop.sha256sum\`.
Machine-readable desktop release metadata is in \`shk-desktop-latest.json\`.
Tauri updater metadata is published as \`latest.json\` and mirrored to the \`desktop-latest\` release.
EOF
}

shk_winget_release_notes() {
  cat <<EOF

## Windows Package Manager

Generated WinGet manifests for the CLI are attached as \`shk-winget-manifests.zip\`.
These files are for maintainers to validate and submit to \`microsoft/winget-pkgs\`;
WinGet is not an official install method until that submission is accepted.
EOF
}

shk_desktop_unsigned_release_notes() {
  local version="$1"
  cat <<EOF
## shk Desktop v${version} (unsigned)

Installers for macOS, Linux, and Windows are attached as \`shk-desktop_*\` assets.
These builds are **not** Developer ID signed, notarized, or Authenticode-signed.
The in-app updater is enabled; keep the same Tauri updater signing keys across all
desktop releases so existing installs can update in place.

### First launch

- **macOS**: Gatekeeper may block the app. Open via right-click, then Open, or remove
  quarantine after install:
  \`xattr -dr com.apple.quarantine /Applications/shk.app\`
- **Windows**: SmartScreen may warn on first run. Choose "More info", then "Run anyway".

Checksums are in \`shk-desktop.sha256sum\`.
Machine-readable desktop release metadata is in \`shk-desktop-latest.json\`.
Tauri updater metadata is published as \`latest.json\` and mirrored to the \`desktop-latest\` release.
EOF
}
