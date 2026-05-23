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

if SHK_REQUIRE_MACOS_CODESIGN=true \
  TAURI_UPDATER_PUBKEY=public-key \
  TAURI_SIGNING_PRIVATE_KEY=private-key \
  ./.github/scripts/release/check-desktop-signing.sh >/dev/null 2>&1; then
  echo "FAIL: missing macOS signing config should fail" >&2
  exit 1
fi
echo "ok: missing macOS signing config rejected"

if SHK_REQUIRE_MACOS_CODESIGN=true \
  TAURI_UPDATER_PUBKEY=public-key \
  TAURI_SIGNING_PRIVATE_KEY=private-key \
  APPLE_CERTIFICATE=certificate \
  APPLE_CERTIFICATE_PASSWORD=password \
  APPLE_SIGNING_IDENTITY="Developer ID Application: Example (TEAMID)" \
  KEYCHAIN_PASSWORD=keychain-password \
  ./.github/scripts/release/check-desktop-signing.sh >/dev/null 2>&1; then
  echo "FAIL: missing macOS notarization config should fail" >&2
  exit 1
fi
echo "ok: missing macOS notarization config rejected"

SHK_REQUIRE_MACOS_CODESIGN=true \
  TAURI_UPDATER_PUBKEY=public-key \
  TAURI_SIGNING_PRIVATE_KEY=private-key \
  APPLE_CERTIFICATE=certificate \
  APPLE_CERTIFICATE_PASSWORD=password \
  APPLE_SIGNING_IDENTITY="Developer ID Application: Example (TEAMID)" \
  KEYCHAIN_PASSWORD=keychain-password \
  APPLE_ID=developer@example.com \
  APPLE_PASSWORD=app-specific-password \
  APPLE_TEAM_ID=TEAMID \
  ./.github/scripts/release/check-desktop-signing.sh >/dev/null
echo "ok: macOS signing and notarization config accepted"

if SHK_REQUIRE_WINDOWS_CODESIGN=true \
  TAURI_UPDATER_PUBKEY=public-key \
  TAURI_SIGNING_PRIVATE_KEY=private-key \
  ./.github/scripts/release/check-desktop-signing.sh >/dev/null 2>&1; then
  echo "FAIL: missing Windows signing config should fail" >&2
  exit 1
fi
echo "ok: missing Windows signing config rejected"

if SHK_REQUIRE_WINDOWS_CODESIGN=true \
  TAURI_UPDATER_PUBKEY=public-key \
  TAURI_SIGNING_PRIVATE_KEY=private-key \
  TAURI_WINDOWS_SIGN_COMMAND="trusted-signing-cli sign" \
  ./.github/scripts/release/check-desktop-signing.sh >/dev/null 2>&1; then
  echo "FAIL: Windows sign command without placeholder should fail" >&2
  exit 1
fi
echo "ok: invalid Windows sign command rejected"

if SHK_REQUIRE_WINDOWS_CODESIGN=true \
  TAURI_UPDATER_PUBKEY=public-key \
  TAURI_SIGNING_PRIVATE_KEY=private-key \
  TAURI_WINDOWS_SIGN_COMMAND="trusted-signing-cli sign %1" \
  TAURI_WINDOWS_CERTIFICATE_THUMBPRINT=00112233445566778899AABBCCDDEEFF00112233 \
  TAURI_WINDOWS_TIMESTAMP_URL=https://timestamp.example.invalid \
  ./.github/scripts/release/check-desktop-signing.sh >/dev/null 2>&1; then
  echo "FAIL: mixed Windows signing modes should fail" >&2
  exit 1
fi
echo "ok: mixed Windows signing modes rejected"

if SHK_REQUIRE_WINDOWS_CODESIGN=true \
  TAURI_UPDATER_PUBKEY=public-key \
  TAURI_SIGNING_PRIVATE_KEY=private-key \
  TAURI_WINDOWS_CERTIFICATE_THUMBPRINT=not-a-thumbprint \
  TAURI_WINDOWS_TIMESTAMP_URL=https://timestamp.example.invalid \
  ./.github/scripts/release/check-desktop-signing.sh >/dev/null 2>&1; then
  echo "FAIL: invalid Windows certificate thumbprint should fail" >&2
  exit 1
fi
echo "ok: invalid Windows certificate thumbprint rejected"

if SHK_REQUIRE_WINDOWS_CODESIGN=true \
  TAURI_UPDATER_PUBKEY=public-key \
  TAURI_SIGNING_PRIVATE_KEY=private-key \
  TAURI_WINDOWS_CERTIFICATE_THUMBPRINT=00112233445566778899AABBCCDDEEFF00112233 \
  TAURI_WINDOWS_TIMESTAMP_URL=https://timestamp.example.invalid \
  TAURI_WINDOWS_TSP=maybe \
  ./.github/scripts/release/check-desktop-signing.sh >/dev/null 2>&1; then
  echo "FAIL: invalid Windows TSP value should fail" >&2
  exit 1
fi
echo "ok: invalid Windows TSP value rejected"

SHK_REQUIRE_WINDOWS_CODESIGN=true \
  TAURI_UPDATER_PUBKEY=public-key \
  TAURI_SIGNING_PRIVATE_KEY=private-key \
  TAURI_WINDOWS_SIGN_COMMAND="trusted-signing-cli sign %1" \
  ./.github/scripts/release/check-desktop-signing.sh >/dev/null
echo "ok: Windows sign command accepted"

SHK_REQUIRE_WINDOWS_CODESIGN=true \
  TAURI_UPDATER_PUBKEY=public-key \
  TAURI_SIGNING_PRIVATE_KEY=private-key \
  TAURI_WINDOWS_CERTIFICATE_THUMBPRINT=00112233445566778899AABBCCDDEEFF00112233 \
  TAURI_WINDOWS_TIMESTAMP_URL=https://timestamp.example.invalid \
  ./.github/scripts/release/check-desktop-signing.sh >/dev/null
echo "ok: Windows certificate signing config accepted"

tmpdir="$(mktemp -d)"
case "$(uname -s)" in
  Darwin)
    fake_package_target="test-apple-darwin"
    fake_bundle_dirs=(dmg macos)
    fake_bundle_files=(dmg/shk.dmg macos/shk.app.tar.gz)
    fake_packaged_files=(shk.dmg shk.app.tar.gz)
    ;;
  Linux)
    fake_package_target="test-unknown-linux-gnu"
    fake_bundle_dirs=(appimage deb)
    fake_bundle_files=(appimage/shk.AppImage deb/shk_0.3.4_amd64.deb)
    fake_packaged_files=(shk.AppImage 0.3.4_amd64.deb)
    ;;
  *)
    fake_package_target=""
    ;;
esac
trap 'rm -rf "$tmpdir" ${fake_package_target:+"target/${fake_package_target}"}' EXIT
printf 'mac dmg\n' > "$tmpdir/shk-desktop_0.3.4_aarch64-apple-darwin_shk.dmg"
printf 'mac updater\n' > "$tmpdir/shk-desktop_0.3.4_aarch64-apple-darwin_shk.app.tar.gz"
printf 'mac-signature\n' > "$tmpdir/shk-desktop_0.3.4_aarch64-apple-darwin_shk.app.tar.gz.sig"
printf 'linux appimage\n' > "$tmpdir/shk-desktop_0.3.4_x86_64-unknown-linux-gnu_shk.AppImage"
printf 'linux-signature\n' > "$tmpdir/shk-desktop_0.3.4_x86_64-unknown-linux-gnu_shk.AppImage.sig"

if [[ -n "$fake_package_target" ]]; then
  for dir in "${fake_bundle_dirs[@]}"; do
    mkdir -p "target/${fake_package_target}/release/bundle/${dir}"
  done
  for file in "${fake_bundle_files[@]}"; do
    printf 'artifact\n' > "target/${fake_package_target}/release/bundle/${file}"
  done
  ./.github/scripts/release/package-desktop-artifacts.sh "$fake_package_target" 0.3.4 "$tmpdir/packaged" >/dev/null
  for file in "${fake_packaged_files[@]}"; do
    test -f "$tmpdir/packaged/shk-desktop_0.3.4_${fake_package_target}_${file}"
  done
  echo "ok: desktop package artifacts are selected by target"
fi

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

TAURI_UPDATER_PUBKEY=public-key \
  TAURI_WINDOWS_SIGN_COMMAND="trusted-signing-cli sign %1" \
  GITHUB_REPOSITORY=Kazuki-tam/security-harness-kit \
  ./.github/scripts/release/generate-tauri-updater-config.sh "$tmpdir/tauri-updater-windows-sign-command.json" >/dev/null
jq -e \
  '.bundle.createUpdaterArtifacts == true
    and .bundle.windows.signCommand == "trusted-signing-cli sign %1"' \
  "$tmpdir/tauri-updater-windows-sign-command.json" >/dev/null
echo "ok: Tauri Windows sign command config generated"

TAURI_UPDATER_PUBKEY=public-key \
  TAURI_WINDOWS_CERTIFICATE_THUMBPRINT="00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00 11 22 33" \
  TAURI_WINDOWS_TIMESTAMP_URL=https://timestamp.example.invalid \
  GITHUB_REPOSITORY=Kazuki-tam/security-harness-kit \
  ./.github/scripts/release/generate-tauri-updater-config.sh "$tmpdir/tauri-updater-windows-thumbprint.json" >/dev/null
jq -e \
  '.bundle.createUpdaterArtifacts == true
    and .bundle.windows.certificateThumbprint == "00112233445566778899AABBCCDDEEFF00112233"
    and .bundle.windows.digestAlgorithm == "sha256"
    and .bundle.windows.timestampUrl == "https://timestamp.example.invalid"
    and .bundle.windows.tsp == false' \
  "$tmpdir/tauri-updater-windows-thumbprint.json" >/dev/null
echo "ok: Tauri Windows certificate config generated"

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
