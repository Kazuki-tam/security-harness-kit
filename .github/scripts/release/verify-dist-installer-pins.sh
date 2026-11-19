#!/usr/bin/env bash

# Check that the cargo-dist installer hashes pinned in release.yml are the
# ones upstream publishes for the pinned version. Needs the network; run in CI
# so a dist version bump that forgets the hashes fails on the pull request,
# not on release day.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=.github/scripts/release/common.sh
source "${ROOT}/.github/scripts/release/common.sh"

workflow="${ROOT}/.github/workflows/release.yml"
pinned() {
  awk -F'"' -v key="  $1: " 'index($0, key) == 1 { print $2; exit }' "$workflow"
}
version="$(pinned DIST_VERSION)"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

for kind in sh ps1; do
  key="DIST_INSTALLER_$(printf '%s' "$kind" | tr '[:lower:]' '[:upper:]')_SHA256"
  expected="$(pinned "$key")"
  asset="cargo-dist-installer.${kind}"
  curl --retry 3 --retry-all-errors --proto '=https' --tlsv1.2 -LsSf \
    -o "${workdir}/${asset}" \
    "https://github.com/axodotdev/cargo-dist/releases/download/v${version}/${asset}"
  actual="$(shk_sha256_of "${workdir}/${asset}")"
  if [[ "$actual" != "$expected" ]]; then
    shk_error "${key} in release.yml is ${expected:-unset}, but ${asset} for v${version} has SHA-256 ${actual}"
    exit 1
  fi
  echo "ok: ${asset} v${version} matches ${key}"
done
