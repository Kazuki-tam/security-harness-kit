#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"
source ./.github/scripts/release/common.sh

current_version="$(shk_workspace_version)"

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

assert_contains() {
  local description="$1"
  local actual="$2"
  local expected="$3"
  if [[ "$actual" != *"$expected"* ]]; then
    echo "FAIL: ${description}" >&2
    echo "missing: ${expected}" >&2
    exit 1
  fi
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

resolve_unsigned_tag() {
  env GITHUB_EVENT_NAME=push GITHUB_REF="refs/tags/$1" GITHUB_REF_NAME="$1" \
    ./.github/scripts/release/resolve-unsigned-target.sh
}

assert_output "unsigned desktop tag" $'component=desktop-unsigned\nversion=0.4.0\nrelease_tag=desktop-unsigned-v0.4.0' \
  resolve_unsigned_tag desktop-unsigned-v0.4.0

if resolve_unsigned_tag desktop-v0.4.0 >/dev/null 2>&1; then
  echo "FAIL: signed desktop tag should not resolve as unsigned" >&2
  exit 1
fi
echo "ok: signed desktop tag rejected by unsigned resolver"

if resolve_tag vbad >/dev/null 2>&1; then
  echo "FAIL: invalid tag should fail" >&2
  exit 1
fi
echo "ok: invalid tag rejected"

RELEASE_COMPONENT=cli RELEASE_VERSION="$current_version" \
  ./.github/scripts/release/verify-versions.sh

RELEASE_COMPONENT=desktop RELEASE_VERSION="$current_version" \
  ./.github/scripts/release/verify-versions.sh

RELEASE_COMPONENT=desktop-unsigned RELEASE_VERSION="$current_version" \
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

if ./.github/scripts/release/check-desktop-updater-signing.sh >/dev/null 2>&1; then
  echo "FAIL: missing updater-only signing config should fail" >&2
  exit 1
fi
echo "ok: missing updater-only signing config rejected"

TAURI_UPDATER_PUBKEY=public-key TAURI_SIGNING_PRIVATE_KEY=private-key \
  ./.github/scripts/release/check-desktop-updater-signing.sh >/dev/null
echo "ok: updater-only signing config accepted"

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
    fake_bundle_files=(appimage/shk.AppImage "deb/shk_${current_version}_amd64.deb")
    fake_packaged_files=(shk.AppImage "${current_version}_amd64.deb")
    ;;
  *)
    fake_package_target=""
    ;;
esac
target_existed=false
[[ -d target ]] && target_existed=true
mkdir -p target
relative_winget_dir="$(mktemp -d target/winget-release-test.XXXXXX)"
cleanup_release_test() {
  rm -rf "$tmpdir" "$relative_winget_dir"
  if [[ -n "$fake_package_target" ]]; then
    rm -rf "target/${fake_package_target}"
  fi
  if [[ "$target_existed" == false ]]; then
    rmdir target 2>/dev/null || true
  fi
}
trap cleanup_release_test EXIT
printf 'mac dmg\n' > "$tmpdir/shk-desktop_${current_version}_aarch64-apple-darwin_shk.dmg"
printf 'mac updater\n' > "$tmpdir/shk-desktop_${current_version}_aarch64-apple-darwin_shk.app.tar.gz"
printf 'mac-signature\n' > "$tmpdir/shk-desktop_${current_version}_aarch64-apple-darwin_shk.app.tar.gz.sig"
printf 'linux appimage\n' > "$tmpdir/shk-desktop_${current_version}_x86_64-unknown-linux-gnu_shk.AppImage"
printf 'linux-signature\n' > "$tmpdir/shk-desktop_${current_version}_x86_64-unknown-linux-gnu_shk.AppImage.sig"

if [[ -n "$fake_package_target" ]]; then
  for dir in "${fake_bundle_dirs[@]}"; do
    mkdir -p "target/${fake_package_target}/release/bundle/${dir}"
  done
  for file in "${fake_bundle_files[@]}"; do
    printf 'artifact\n' > "target/${fake_package_target}/release/bundle/${file}"
  done
  ./.github/scripts/release/package-desktop-artifacts.sh "$fake_package_target" "$current_version" "$tmpdir/packaged" >/dev/null
  for file in "${fake_packaged_files[@]}"; do
    test -f "$tmpdir/packaged/shk-desktop_${current_version}_${fake_package_target}_${file}"
  done
  echo "ok: desktop package artifacts are selected by target"
fi

./.github/scripts/release/generate-desktop-checksums.sh "$tmpdir" >/dev/null
GITHUB_REPOSITORY=Kazuki-tam/security-harness-kit \
  RELEASE_TAG="desktop-v${current_version}" \
  RELEASE_VERSION="$current_version" \
  ./.github/scripts/release/generate-desktop-manifest.sh "$tmpdir" >/dev/null

jq -e \
  --arg version "$current_version" \
  --arg tag "desktop-v${current_version}" \
  '.product == "shk-desktop"
    and .version == $version
    and .release_tag == $tag
    and (.assets | length) == 5
    and ([.assets[].sha256] | all(length == 64))' \
  "$tmpdir/shk-desktop-latest.json" >/dev/null
echo "ok: desktop release manifest generated"

printf 'windows exe\n' > "$tmpdir/shk.exe"
(
  cd "$tmpdir"
  zip -q shk-cli-x86_64-pc-windows-msvc.zip shk.exe
  rm -f shk.exe
)
printf '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  shk-cli-x86_64-pc-windows-msvc.zip\n' \
  > "$tmpdir/shk-cli-x86_64-pc-windows-msvc.zip.sha256"
printf 'stale\n' > "$tmpdir/stale.txt"
(
  cd "$tmpdir"
  zip -q shk-winget-manifests.zip stale.txt
  rm -f stale.txt
)
GITHUB_REPOSITORY=Kazuki-tam/security-harness-kit \
  RELEASE_TAG="v${current_version}" \
  RELEASE_VERSION="$current_version" \
  ./.github/scripts/release/generate-winget-manifests.sh "$tmpdir" >/dev/null
test -s "$tmpdir/shk-winget-manifests.zip"
if command -v unzip >/dev/null 2>&1; then
  winget_version_manifest="$(unzip -p "$tmpdir/shk-winget-manifests.zip" \
    "winget/manifests/k/Kazuki-tam/shk/${current_version}/Kazuki-tam.shk.yaml")"
  winget_locale_manifest="$(unzip -p "$tmpdir/shk-winget-manifests.zip" \
    "winget/manifests/k/Kazuki-tam/shk/${current_version}/Kazuki-tam.shk.locale.en-US.yaml")"
  winget_installer_manifest="$(unzip -p "$tmpdir/shk-winget-manifests.zip" \
    "winget/manifests/k/Kazuki-tam/shk/${current_version}/Kazuki-tam.shk.installer.yaml")"

  assert_contains "winget version manifest package id" "$winget_version_manifest" "PackageIdentifier: Kazuki-tam.shk"
  assert_contains "winget version manifest version" "$winget_version_manifest" "PackageVersion: ${current_version}"
  assert_contains "winget locale manifest description" "$winget_locale_manifest" "ShortDescription: Local-first security harness CLI for AI coding agents"
  assert_contains "winget installer manifest type" "$winget_installer_manifest" "InstallerType: zip"
  assert_contains "winget installer nested type" "$winget_installer_manifest" "NestedInstallerType: portable"
  assert_contains "winget installer command alias" "$winget_installer_manifest" "PortableCommandAlias: shk"
  assert_contains "winget installer URL" "$winget_installer_manifest" "InstallerUrl: https://github.com/Kazuki-tam/security-harness-kit/releases/download/v${current_version}/shk-cli-x86_64-pc-windows-msvc.zip"
  assert_contains "winget installer SHA256" "$winget_installer_manifest" "InstallerSha256: 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
  if unzip -Z1 "$tmpdir/shk-winget-manifests.zip" | awk '$0 == "stale.txt" { found = 1 } END { exit found ? 0 : 1 }'; then
    echo "FAIL: winget manifest archive retained stale entries" >&2
    exit 1
  fi
fi
echo "ok: winget manifests generated"

printf 'windows exe\n' > "$relative_winget_dir/shk.exe"
(
  cd "$relative_winget_dir"
  zip -q shk-cli-x86_64-pc-windows-msvc.zip shk.exe
  rm -f shk.exe
)
printf '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  shk-cli-x86_64-pc-windows-msvc.zip\n' \
  > "$relative_winget_dir/shk-cli-x86_64-pc-windows-msvc.zip.sha256"
winget_output="$(
  GITHUB_REPOSITORY=Kazuki-tam/security-harness-kit \
    RELEASE_TAG="v${current_version}" \
    RELEASE_VERSION="$current_version" \
    ./.github/scripts/release/generate-winget-manifests.sh "$relative_winget_dir"
)"
assert_output "winget reports resolved output path" \
  "wrote ${ROOT}/${relative_winget_dir}/shk-winget-manifests.zip" \
  printf '%s' "$winget_output"

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
  GITHUB_REPOSITORY=Kazuki-tam/security-harness-kit \
  ./.github/scripts/release/generate-tauri-updater-config.sh \
    "$tmpdir/tauri-updater-bundles.json" appimage,deb >/dev/null
jq -e \
  '.bundle.createUpdaterArtifacts == true
    and .bundle.targets == ["appimage", "deb"]' \
  "$tmpdir/tauri-updater-bundles.json" >/dev/null
echo "ok: Tauri updater bundle targets generated"

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
  RELEASE_TAG="desktop-v${current_version}" \
  RELEASE_VERSION="$current_version" \
  ./.github/scripts/release/generate-tauri-latest-json.sh "$tmpdir" >/dev/null
jq -e \
  --arg version "$current_version" \
  --arg tag "desktop-v${current_version}" \
  '.version == $version
    and .platforms."linux-x86_64".signature == "linux-signature"
    and .platforms."darwin-aarch64".signature == "mac-signature"
    and (.platforms."linux-x86_64".url | contains("/" + $tag + "/"))' \
  "$tmpdir/latest.json" >/dev/null
echo "ok: Tauri latest.json generated"

echo "release script tests passed"
