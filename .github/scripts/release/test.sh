#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"

assert_output() {
  local description="$1"
  local expected="$2"
  shift 2
  local actual
  actual="$("$@")"
  if [[ "$actual" != "$expected" ]]; then
    echo "FAIL: ${description}" >&2
    echo "expected: ${expected}" >&2
    echo "actual:   ${actual}" >&2
    exit 1
  fi
  echo "ok: ${description}"
}

resolve_tag() {
  env GITHUB_EVENT_NAME=push GITHUB_REF="refs/tags/$1" GITHUB_REF_NAME="$1" \
    ./.github/scripts/release/resolve-target.sh
}

assert_output "cli tag" $'component=cli\nversion=0.3.4\nrelease_tag=v0.3.4\nbuild_cli=true\nbuild_desktop=false\nmake_latest=true' \
  resolve_tag v0.3.4

assert_output "desktop tag" $'component=desktop\nversion=0.4.0\nrelease_tag=desktop-v0.4.0\nbuild_cli=false\nbuild_desktop=true\nmake_latest=false' \
  resolve_tag desktop-v0.4.0

assert_output "combined tag" $'component=both\nversion=1.2.3\nrelease_tag=shk-v1.2.3\nbuild_cli=true\nbuild_desktop=true\nmake_latest=true' \
  resolve_tag shk-v1.2.3

if resolve_tag vbad >/dev/null 2>&1; then
  echo "FAIL: invalid tag should fail" >&2
  exit 1
fi
echo "ok: invalid tag rejected"

RELEASE_COMPONENT=cli RELEASE_VERSION=0.3.4 \
  ./.github/scripts/release/verify-versions.sh

RELEASE_COMPONENT=desktop RELEASE_VERSION=0.3.4 \
  ./.github/scripts/release/verify-versions.sh

if RELEASE_COMPONENT=desktop RELEASE_VERSION=9.9.9 \
  ./.github/scripts/release/verify-versions.sh >/dev/null 2>&1; then
  echo "FAIL: desktop version mismatch should fail" >&2
  exit 1
fi
echo "ok: desktop version mismatch rejected"

if ./.github/scripts/release/check-desktop-signing.sh >/dev/null 2>&1; then
  echo "FAIL: missing required updater signing config should fail" >&2
  exit 1
fi
echo "ok: missing updater signing config rejected"

TAURI_UPDATER_PUBKEY=public-key TAURI_SIGNING_PRIVATE_KEY=private-key \
  ./.github/scripts/release/check-desktop-signing.sh >/dev/null
echo "ok: updater signing config accepted"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
printf 'mac dmg\n' > "$tmpdir/shk-desktop_0.3.4_aarch64-apple-darwin_shk.dmg"
printf 'mac updater\n' > "$tmpdir/shk-desktop_0.3.4_aarch64-apple-darwin_shk.app.tar.gz"
printf 'mac-signature\n' > "$tmpdir/shk-desktop_0.3.4_aarch64-apple-darwin_shk.app.tar.gz.sig"
printf 'linux appimage\n' > "$tmpdir/shk-desktop_0.3.4_x86_64-unknown-linux-gnu_shk.AppImage"
printf 'linux-signature\n' > "$tmpdir/shk-desktop_0.3.4_x86_64-unknown-linux-gnu_shk.AppImage.sig"

./.github/scripts/release/generate-desktop-checksums.sh "$tmpdir" >/dev/null
GITHUB_REPOSITORY=Kazuki-tam/security-harness-kit \
  RELEASE_TAG=desktop-v0.3.4 \
  RELEASE_VERSION=0.3.4 \
  ./.github/scripts/release/generate-desktop-manifest.sh "$tmpdir" >/dev/null

jq -e \
  '.product == "shk-desktop"
    and .version == "0.3.4"
    and .release_tag == "desktop-v0.3.4"
    and (.assets | length) == 5
    and ([.assets[].sha256] | all(length == 64))' \
  "$tmpdir/shk-desktop-latest.json" >/dev/null
echo "ok: desktop release manifest generated"

TAURI_UPDATER_PUBKEY=public-key \
  GITHUB_REPOSITORY=Kazuki-tam/security-harness-kit \
  ./.github/scripts/release/generate-tauri-updater-config.sh "$tmpdir/tauri-updater.json" >/dev/null
jq -e \
  '.bundle.createUpdaterArtifacts == true
    and .plugins.updater.pubkey == "public-key"
    and (.plugins.updater.endpoints[0] | test("/desktop-latest/latest.json$"))' \
  "$tmpdir/tauri-updater.json" >/dev/null
echo "ok: Tauri updater config generated"

GITHUB_REPOSITORY=Kazuki-tam/security-harness-kit \
  RELEASE_TAG=desktop-v0.3.4 \
  RELEASE_VERSION=0.3.4 \
  ./.github/scripts/release/generate-tauri-latest-json.sh "$tmpdir" >/dev/null
jq -e \
  '.version == "0.3.4"
    and .platforms."linux-x86_64".signature == "linux-signature"
    and .platforms."darwin-aarch64".signature == "mac-signature"
    and (.platforms."linux-x86_64".url | test("/desktop-v0.3.4/"))' \
  "$tmpdir/latest.json" >/dev/null
echo "ok: Tauri latest.json generated"

echo "release script tests passed"
