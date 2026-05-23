#!/usr/bin/env bash

# Shared helpers for release scripts. Source from repo root.

readonly SHK_SEMVER_RE='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'

shk_require_semver() {
  local version="$1"
  if [[ ! "$version" =~ $SHK_SEMVER_RE ]]; then
    echo "invalid semver: ${version}" >&2
    exit 1
  fi
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
  cat <<EOF
## shk Desktop v${version}

Installers for macOS, Linux, and Windows are attached as \`shk-desktop_*\` assets.
Checksums are in \`shk-desktop.sha256sum\`.
Machine-readable desktop release metadata is in \`shk-desktop-latest.json\`.
Tauri updater metadata is published as \`latest.json\` and mirrored to the \`desktop-latest\` release.
EOF
}
