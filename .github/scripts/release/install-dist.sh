#!/usr/bin/env bash

# Install the pinned cargo-dist release on a Unix runner.
#
# Usage: install-dist.sh   (reads DIST_VERSION and DIST_INSTALLER_SH_SHA256)
#
# The installer script is a release asset upstream can replace, and it runs in
# jobs that build and publish release artifacts. It is downloaded to a file,
# checked against the pinned SHA-256, and only then run.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=.github/scripts/release/common.sh
source "${ROOT}/.github/scripts/release/common.sh"

version="${DIST_VERSION:?DIST_VERSION is required}"
expected="${DIST_INSTALLER_SH_SHA256:?DIST_INSTALLER_SH_SHA256 is required}"
url="https://github.com/axodotdev/cargo-dist/releases/download/v${version}/cargo-dist-installer.sh"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT
installer="${workdir}/cargo-dist-installer.sh"

curl --retry 3 --retry-all-errors --proto '=https' --tlsv1.2 -LsSf -o "$installer" "$url"
actual="$(shk_sha256_of "$installer")"
if [[ "$actual" != "$expected" ]]; then
  shk_error "cargo-dist installer for v${version} has SHA-256 ${actual}, expected ${expected}. Update DIST_INSTALLER_SH_SHA256 in the release workflows only after reviewing the new installer."
  exit 1
fi
sh "$installer"
