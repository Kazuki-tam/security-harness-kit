#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"
source ./.github/scripts/release/common.sh

current_version="$(shk_workspace_version)"

release_workflow="$(<.github/workflows/release.yml)"
unsigned_release_workflow="$(<.github/workflows/release-desktop-unsigned.yml)"

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

assert_contains "CLI channel verification covers every CLI-producing tag" \
  "$release_workflow" "needs.prepare.outputs.build_cli == 'true'"
if [[ "$release_workflow" == *"startsWith(needs.prepare.outputs.release_tag, 'v')"* ]]; then
  echo "FAIL: CLI channel verification must not skip combined or cli-v tags" >&2
  exit 1
fi

# A job skipped because an upstream matrix leg failed reports `skipped`, not
# `failure`, so the publish gate must require `success` for every track that
# is being built instead of merely rejecting `failure`.
publish_gate="$(awk '/^  publish:$/ { in_job = 1 } in_job && /^    steps:$/ { exit } in_job { print }' .github/workflows/release.yml)"
for job in build-global-artifacts build-desktop-artifacts; do
  if [[ "$publish_gate" == *"needs.${job}.result != 'failure'"* ]]; then
    echo "FAIL: publish gate must not accept a skipped ${job} job via != 'failure'" >&2
    exit 1
  fi
done
assert_contains "publish gate requires a successful CLI build when the CLI is built" \
  "$publish_gate" "needs.prepare.outputs.build_cli != 'true' ||"
assert_contains "publish gate requires the CLI installers job to succeed" \
  "$publish_gate" "needs.build-global-artifacts.result == 'success'"
assert_contains "publish gate requires a successful desktop build when the desktop is built" \
  "$publish_gate" "needs.prepare.outputs.build_desktop != 'true' ||"
assert_contains "publish gate requires the desktop job to succeed" \
  "$publish_gate" "needs.build-desktop-artifacts.result == 'success'"
echo "ok: publish gate requires success for every built track"

# release.yml installs dist from DIST_VERSION, but dist-workspace.toml declares
# cargo-dist-version; a dist bump must update both.
dist_config_version="$(awk -F'"' '/^cargo-dist-version = / { print $2; exit }' dist-workspace.toml)"
dist_workflow_version="$(awk -F'"' '/^  DIST_VERSION: / { print $2; exit }' .github/workflows/release.yml)"
if [[ ! "$dist_config_version" =~ $SHK_SEMVER_RE ]]; then
  echo "FAIL: could not read cargo-dist-version from dist-workspace.toml" >&2
  exit 1
fi
if [[ ! "$dist_workflow_version" =~ $SHK_SEMVER_RE ]]; then
  echo "FAIL: could not read top-level env DIST_VERSION from release.yml" >&2
  exit 1
fi
if [[ "$dist_config_version" != "$dist_workflow_version" ]]; then
  echo "FAIL: release.yml DIST_VERSION ${dist_workflow_version} != dist-workspace.toml cargo-dist-version ${dist_config_version}" >&2
  exit 1
fi
echo "ok: dist version pinned consistently (${dist_config_version})"

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

# Prerelease versions would be published as stable/Latest (moving the v1
# action tag and pushing Homebrew/npm), so every resolver fails closed.
for prerelease_tag in v1.2.3-rc.1 cli-v1.2.3-beta desktop-v1.2.3-rc.1 shk-v1.2.3-alpha.2; do
  if prerelease_output="$(resolve_tag "$prerelease_tag" 2>&1)"; then
    echo "FAIL: prerelease tag ${prerelease_tag} should be rejected" >&2
    exit 1
  fi
  assert_contains "prerelease rejection explains itself (${prerelease_tag})" \
    "$prerelease_output" "prerelease versions are not supported"
done
echo "ok: prerelease tags rejected by release resolver"

if GITHUB_EVENT_NAME=workflow_dispatch RELEASE_COMPONENT=cli RELEASE_VERSION=1.2.3-rc.1 \
  ./.github/scripts/release/resolve-target.sh >/dev/null 2>&1; then
  echo "FAIL: prerelease workflow_dispatch version should be rejected" >&2
  exit 1
fi
echo "ok: prerelease dispatch version rejected by release resolver"

if prerelease_output="$(resolve_unsigned_tag desktop-unsigned-v0.4.0-rc.1 2>&1)"; then
  echo "FAIL: prerelease unsigned desktop tag should be rejected" >&2
  exit 1
fi
assert_contains "unsigned prerelease rejection explains itself" \
  "$prerelease_output" "prerelease versions are not supported"
echo "ok: prerelease tag rejected by unsigned resolver"

if resolve_tag v1 >/dev/null 2>&1; then
  echo "FAIL: moving action tag should not resolve as a release" >&2
  exit 1
fi
echo "ok: moving action tag rejected by release resolver"

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

SHK_REQUIRE_WINDOWS_CODESIGN=true \
  SHK_ALLOW_UNSIGNED_WINDOWS=true \
  TAURI_UPDATER_PUBKEY=public-key \
  TAURI_SIGNING_PRIVATE_KEY=private-key \
  ./.github/scripts/release/check-desktop-signing.sh >/dev/null
echo "ok: unsigned Windows accepted with explicit opt-in"

if SHK_REQUIRE_WINDOWS_CODESIGN=true \
  SHK_ALLOW_UNSIGNED_WINDOWS=true \
  TAURI_UPDATER_PUBKEY=public-key \
  TAURI_SIGNING_PRIVATE_KEY=private-key \
  TAURI_WINDOWS_SIGN_COMMAND="trusted-signing-cli sign %1" \
  TAURI_WINDOWS_CERTIFICATE_THUMBPRINT=00112233445566778899AABBCCDDEEFF00112233 \
  TAURI_WINDOWS_TIMESTAMP_URL=https://timestamp.example.invalid \
  ./.github/scripts/release/check-desktop-signing.sh >/dev/null 2>&1; then
  echo "FAIL: opt-in must not mask an invalid Windows signing config" >&2
  exit 1
fi
echo "ok: opt-in does not mask invalid Windows signing config"

SHK_REQUIRE_WINDOWS_CODESIGN=true \
  SHK_ALLOW_UNSIGNED_WINDOWS=true \
  TAURI_UPDATER_PUBKEY=public-key \
  TAURI_SIGNING_PRIVATE_KEY=private-key \
  TAURI_WINDOWS_SIGN_COMMAND="trusted-signing-cli sign %1" \
  ./.github/scripts/release/check-desktop-signing.sh >/dev/null
echo "ok: configured Windows signing still validated when opt-in is set"

if ./.github/scripts/release/notarize-macos-dmg.sh /nonexistent >/dev/null 2>&1; then
  echo "FAIL: notarize without Apple credentials should fail" >&2
  exit 1
fi
echo "ok: notarize without Apple credentials rejected"

notarize_tmp="$(mktemp -d)"
if APPLE_ID=apple-id APPLE_PASSWORD=app-password APPLE_TEAM_ID=TEAMID \
  ./.github/scripts/release/notarize-macos-dmg.sh "$notarize_tmp" >/dev/null 2>&1; then
  echo "FAIL: notarize with no DMG artifacts should fail" >&2
  exit 1
fi
rm -rf "$notarize_tmp"
echo "ok: notarize with no DMG artifacts rejected"

# Stapling retries. Stubs stand in for xcrun and sleep, so nothing reaches Apple.
staple_tmp="$(mktemp -d)"
mkdir -p "$staple_tmp/bin" "$staple_tmp/dmg"
touch "$staple_tmp/dmg/shk.dmg"
cat > "$staple_tmp/bin/xcrun" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "$STUB_DIR/xcrun.log"
echo "$#" > "$STUB_DIR/xcrun.argc"
if [[ "${1:-}" != "stapler" ]]; then
  exit "${STUB_OTHER_STATUS:-0}"
fi
attempt="$(grep -c '^stapler' "$STUB_DIR/xcrun.log")"
if ((attempt <= STUB_STAPLE_FAILURES)); then
  echo "The network connection was lost." >&2
  exit 68
fi
STUB
cat > "$staple_tmp/bin/sleep" <<'STUB'
#!/usr/bin/env bash
echo "$1" >> "$STUB_DIR/sleep.log"
STUB
chmod +x "$staple_tmp/bin/xcrun" "$staple_tmp/bin/sleep"

reset_staple_stubs() {
  rm -f "$staple_tmp/xcrun.log" "$staple_tmp/sleep.log" "$staple_tmp/shim.log"
  touch "$staple_tmp/xcrun.log" "$staple_tmp/sleep.log"
}

staple_call_count() {
  grep -c "^$1" "$staple_tmp/xcrun.log" || true
}

sleep_delays() {
  tr '\n' ' ' < "$staple_tmp/sleep.log"
}

run_notarize_with_stubs() {
  PATH="$staple_tmp/bin:$PATH" STUB_DIR="$staple_tmp" STUB_STAPLE_FAILURES="$1" \
    APPLE_ID=apple-id APPLE_PASSWORD=app-password APPLE_TEAM_ID=TEAMID \
    ./.github/scripts/release/notarize-macos-dmg.sh "$staple_tmp/dmg" 2>&1
}

run_shim_with_stubs() {
  local failures="$1"
  shift
  PATH="$staple_tmp/bin:$PATH" STUB_DIR="$staple_tmp" STUB_STAPLE_FAILURES="$failures" \
    SHK_REAL_XCRUN="$staple_tmp/bin/xcrun" SHK_STAPLE_LOG="$staple_tmp/shim.log" \
    ./.github/scripts/release/xcrun-shim/xcrun "$@"
}

reset_staple_stubs
notarize_output="$(run_notarize_with_stubs 2)"
assert_contains "notarize reports the DMG after a retried staple" \
  "$notarize_output" "notarized and stapled: shk.dmg"
assert_output "notarize staples until the ticket arrives" "3" staple_call_count "stapler staple"
assert_output "notarize does not resubmit on a staple retry" "1" staple_call_count "notarytool submit"
assert_output "notarize backs off between staple attempts" "15 30 " sleep_delays
echo "ok: notarize retries a transient staple failure"

reset_staple_stubs
if notarize_output="$(run_notarize_with_stubs 99)"; then
  echo "FAIL: notarize should fail once the staple attempts run out" >&2
  exit 1
fi
if [[ "$notarize_output" == *"notarized and stapled"* ]]; then
  echo "FAIL: notarize reported success for a DMG with no ticket" >&2
  exit 1
fi
assert_output "notarize bounds the staple attempts" "5" staple_call_count "stapler staple"
assert_output "notarize does not resubmit when stapling keeps failing" "1" staple_call_count "notarytool submit"
assert_output "notarize caps the staple backoff" "15 30 60 120 " sleep_delays
echo "ok: notarize fails after the staple attempts run out"

reset_staple_stubs
run_shim_with_stubs 2 stapler staple -v shk.app
assert_output "xcrun shim keeps stapler arguments" "stapler staple -v shk.app" tail -n 1 "$staple_tmp/xcrun.log"
assert_output "xcrun shim retries stapling" "3" staple_call_count "stapler staple -v shk.app"
assert_output "xcrun shim backs off between attempts" "15 30 " sleep_delays
assert_contains "xcrun shim keeps stapler output for the workflow to print" \
  "$(<"$staple_tmp/shim.log")" "The network connection was lost."
echo "ok: xcrun shim retries a transient staple failure"

reset_staple_stubs
run_shim_with_stubs 0 stapler staple -v "my app.app"
assert_output "xcrun shim does not split stapler arguments" "4" cat "$staple_tmp/xcrun.argc"

reset_staple_stubs
if run_shim_with_stubs 99 stapler staple -v shk.app; then
  echo "FAIL: xcrun shim should fail once the staple attempts run out" >&2
  exit 1
fi
assert_output "xcrun shim bounds the attempts" "5" staple_call_count "stapler staple -v shk.app"
assert_contains "xcrun shim logs that it gave up" \
  "$(<"$staple_tmp/shim.log")" "gave up stapling"
echo "ok: xcrun shim fails after the staple attempts run out"

reset_staple_stubs
PATH="$staple_tmp/bin:$PATH" STUB_DIR="$staple_tmp" STUB_STAPLE_FAILURES=0 \
  SHK_REAL_XCRUN="$staple_tmp/bin/xcrun" SHK_STAPLE_LOG="$staple_tmp/missing-dir/shim.log" \
  ./.github/scripts/release/xcrun-shim/xcrun stapler staple -v shk.app >/dev/null 2>&1
assert_output "xcrun shim still staples when the log cannot be written" "1" \
  staple_call_count "stapler staple -v shk.app"
echo "ok: xcrun shim staples without a writable log"

reset_staple_stubs
run_shim_with_stubs 0 notarytool submit --team-id "team id"
assert_output "xcrun shim keeps other commands' arguments" "notarytool submit --team-id team id" \
  tail -n 1 "$staple_tmp/xcrun.log"
assert_output "xcrun shim does not split other commands' arguments" "4" cat "$staple_tmp/xcrun.argc"
passthrough_status=0
STUB_OTHER_STATUS=7 run_shim_with_stubs 0 --find stapler || passthrough_status=$?
assert_output "xcrun shim keeps the exit status of other commands" "7" echo "$passthrough_status"
assert_output "xcrun shim does not retry other commands" "" sleep_delays
if [[ -e "$staple_tmp/shim.log" ]]; then
  echo "FAIL: xcrun shim should only log stapling" >&2
  exit 1
fi
echo "ok: xcrun shim passes other commands through unchanged"

rm -rf "$staple_tmp"

if [[ ! -x ./.github/scripts/release/xcrun-shim/xcrun ]]; then
  echo "FAIL: xcrun shim must be executable" >&2
  exit 1
fi
# Calling plain `xcrun` here would find the shim on PATH and recurse forever.
assert_contains "xcrun shim defaults to an absolute path" \
  "$(<./.github/scripts/release/xcrun-shim/xcrun)" 'real_xcrun="${SHK_REAL_XCRUN:-/usr/bin/xcrun}"'
assert_contains "signed desktop build retries stapling through the xcrun shim" \
  "$release_workflow" 'export PATH="${GITHUB_WORKSPACE}/.github/scripts/release/xcrun-shim:${PATH}"'
assert_contains "signed desktop build prints the stapler log" \
  "$release_workflow" 'cat "$SHK_STAPLE_LOG"'
assert_contains "signed desktop build warns when Tauri bypasses the xcrun shim" \
  "$release_workflow" 'Tauri did not staple through xcrun-shim'
echo "ok: signed desktop build uses the xcrun shim"

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
    printf 'helper\n' > "target/${fake_package_target}/release/bundle/${dir}/bundle_dmg.sh"
    printf 'icon\n' > "target/${fake_package_target}/release/bundle/${dir}/icon.icns"
    printf 'log\n' > "target/${fake_package_target}/release/bundle/${dir}/debug.log"
  done
  for file in "${fake_bundle_files[@]}"; do
    printf 'artifact\n' > "target/${fake_package_target}/release/bundle/${file}"
  done
  ./.github/scripts/release/package-desktop-artifacts.sh "$fake_package_target" "$current_version" "$tmpdir/packaged" >/dev/null
  for file in "${fake_packaged_files[@]}"; do
    test -f "$tmpdir/packaged/shk-desktop_${current_version}_${fake_package_target}_${file}"
  done
  packaged_files=( "$tmpdir/packaged"/* )
  test "${#packaged_files[@]}" -eq "${#fake_packaged_files[@]}"
  echo "ok: desktop package artifacts are selected by target"
  ln -s debug.log "target/${fake_package_target}/release/bundle/${fake_bundle_dirs[0]}/linked.${fake_bundle_files[0]##*.}"
  if ./.github/scripts/release/package-desktop-artifacts.sh "$fake_package_target" "$current_version" "$tmpdir/rejected-package" >/dev/null 2>&1; then
    echo "FAIL: symlinked distribution artifact must be rejected" >&2
    exit 1
  fi
  echo "ok: desktop packaging excludes helpers and rejects symlinks"
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

stable_src="$tmpdir/stable-src"
stable_out="$tmpdir/stable-out"
mkdir -p "$stable_src"
for suffix in \
  "aarch64-apple-darwin_${current_version}_aarch64.dmg" \
  "aarch64-apple-darwin_shk.app.tar.gz" \
  "aarch64-apple-darwin_shk.app.tar.gz.sig" \
  "x86_64-apple-darwin_${current_version}_x64.dmg" \
  "x86_64-unknown-linux-gnu_${current_version}_amd64.AppImage" \
  "x86_64-unknown-linux-gnu_${current_version}_amd64.deb" \
  "aarch64-unknown-linux-gnu_${current_version}_arm64.AppImage" \
  "aarch64-unknown-linux-gnu_${current_version}_arm64.deb" \
  "x86_64-pc-windows-msvc_${current_version}_x64-setup.exe" \
  "x86_64-pc-windows-msvc_${current_version}_x64_en-US.msi"; do
  printf '%s\n' "$suffix" > "$stable_src/shk-desktop_${current_version}_${suffix}"
done
cp "$tmpdir/shk-desktop-latest.json" "$stable_src/shk-desktop-latest.json"
RELEASE_TAG="desktop-v${current_version}" RELEASE_VERSION="$current_version" \
  ./.github/scripts/release/generate-desktop-stable-assets.sh "$stable_src" "$stable_out" >/dev/null
for stable in \
  shk-desktop-aarch64-apple-darwin.dmg \
  shk-desktop-x86_64-apple-darwin.dmg \
  shk-desktop-x86_64-unknown-linux-gnu.AppImage \
  shk-desktop-x86_64-unknown-linux-gnu.deb \
  shk-desktop-aarch64-unknown-linux-gnu.AppImage \
  shk-desktop-aarch64-unknown-linux-gnu.deb \
  shk-desktop-x86_64-pc-windows-msvc-setup.exe \
  shk-desktop-x86_64-pc-windows-msvc.msi \
  shk-desktop-latest.json \
  shk-desktop.sha256sum; do
  test -f "$stable_out/$stable"
done
# Stable copies must be byte-identical to the versioned installer.
cmp -s "$stable_src/shk-desktop_${current_version}_aarch64-apple-darwin_${current_version}_aarch64.dmg" \
  "$stable_out/shk-desktop-aarch64-apple-darwin.dmg"
# Updater bundles and signatures stay out of the stable set.
if ls "$stable_out"/*.tar.gz "$stable_out"/*.sig >/dev/null 2>&1; then
  echo "FAIL: stable assets must only contain installers" >&2
  exit 1
fi
(cd "$stable_out" && shk_verify_sha256_file shk-desktop.sha256sum)
assert_output "stable checksum file lists every installer" "8" \
  bash -c "wc -l < '$stable_out/shk-desktop.sha256sum' | tr -d ' '"
echo "ok: desktop stable assets generated"

printf 'preserve existing output\n' > "$stable_out/preserved.txt"
printf 'second dmg\n' > "$stable_src/shk-desktop_${current_version}_aarch64-apple-darwin_other.dmg"
if RELEASE_TAG="desktop-v${current_version}" RELEASE_VERSION="$current_version" \
  ./.github/scripts/release/generate-desktop-stable-assets.sh "$stable_src" "$stable_out" >/dev/null 2>&1; then
  echo "FAIL: stable asset generation must reject ambiguous installers" >&2
  exit 1
fi
test -f "$stable_out/preserved.txt"
rm "$stable_out/preserved.txt"
echo "ok: desktop stable assets reject ambiguous installers"

rm "$stable_src/shk-desktop_${current_version}_aarch64-apple-darwin_other.dmg"
rm "$stable_src/shk-desktop_${current_version}_x86_64-pc-windows-msvc_${current_version}_x64_en-US.msi"
if RELEASE_TAG="desktop-v${current_version}" RELEASE_VERSION="$current_version" \
  ./.github/scripts/release/generate-desktop-stable-assets.sh "$stable_src" "$tmpdir/stable-missing" >/dev/null 2>&1; then
  echo "FAIL: stable asset generation must reject missing installers" >&2
  exit 1
fi
echo "ok: desktop stable assets reject missing installers"

printf 'restored msi\n' \
  > "$stable_src/shk-desktop_${current_version}_x86_64-pc-windows-msvc_${current_version}_x64_en-US.msi"
jq '.version = "9.9.9"' "$stable_src/shk-desktop-latest.json" \
  > "$stable_src/shk-desktop-latest.invalid.json"
mv "$stable_src/shk-desktop-latest.invalid.json" "$stable_src/shk-desktop-latest.json"
if RELEASE_TAG="desktop-v${current_version}" RELEASE_VERSION="$current_version" \
  ./.github/scripts/release/generate-desktop-stable-assets.sh "$stable_src" "$tmpdir/stable-invalid-manifest" >/dev/null 2>&1; then
  echo "FAIL: stable asset generation must reject a mismatched manifest" >&2
  exit 1
fi
echo "ok: desktop stable assets reject a mismatched manifest"

cp "$tmpdir/shk-desktop-latest.json" "$stable_src/shk-desktop-latest.json"
if RELEASE_TAG="desktop-v${current_version}" RELEASE_VERSION="$current_version" \
  ./.github/scripts/release/generate-desktop-stable-assets.sh "$stable_src" "$stable_src" >/dev/null 2>&1; then
  echo "FAIL: stable asset generation must reject an in-place output directory" >&2
  exit 1
fi
echo "ok: desktop stable assets reject an in-place output directory"

assert_contains "release workflow uses verified stable desktop publishing" \
  "$release_workflow" "./.github/scripts/release/publish-desktop-stable-assets.sh"
assert_contains "signed release serializes desktop-latest publishing" \
  "$release_workflow" "group: shk-desktop-latest-publish"
assert_contains "unsigned release shares desktop-latest publishing lock" \
  "$unsigned_release_workflow" "group: shk-desktop-latest-publish"

fake_gh_bin="$tmpdir/fake-gh-bin"
fake_gh_remote="$tmpdir/fake-gh-remote"
fake_gh_log="$tmpdir/fake-gh.log"
fake_gh_state="$tmpdir/fake-gh-state"
mkdir -p "$fake_gh_bin" "$fake_gh_remote" "$fake_gh_state"
cat > "$fake_gh_bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

command="$1"
subcommand="${2:-}"
shift 2 || true

case "${command}:${subcommand}" in
  release:upload)
    tag="$1"
    path="$2"
    name="$(basename "$path")"
    if [[ "${SHK_FAKE_FAIL_ONCE:-}" == "$name" && ! -e "${SHK_FAKE_GH_STATE}/${name}" ]]; then
      touch "${SHK_FAKE_GH_STATE}/${name}"
      echo "fail:${name}" >> "$SHK_FAKE_GH_LOG"
      exit 1
    fi
    cp "$path" "${SHK_FAKE_GH_REMOTE}/${name}"
    echo "upload:${name}" >> "$SHK_FAKE_GH_LOG"
    ;;
  release:download)
    pattern=""
    destination=""
    while (($# > 0)); do
      case "$1" in
        --pattern)
          pattern="$2"
          shift 2
          ;;
        --dir)
          destination="$2"
          shift 2
          ;;
        *)
          shift
          ;;
      esac
    done
    mkdir -p "$destination"
    cp "${SHK_FAKE_GH_REMOTE}/${pattern}" "${destination}/${pattern}"
    echo "download:${pattern}" >> "$SHK_FAKE_GH_LOG"
    ;;
  api:--method)
    method="$1"
    endpoint="$2"
    if [[ "$method" != "DELETE" || "$endpoint" != */releases/assets/999 ]]; then
      exit 1
    fi
    if [[ "${SHK_FAKE_KEEP_STALE:-}" != "true" ]]; then
      rm -f "${SHK_FAKE_GH_REMOTE}/shk-desktop-obsolete.pkg"
    fi
    echo "delete:shk-desktop-obsolete.pkg" >> "$SHK_FAKE_GH_LOG"
    ;;
  api:*)
    asset_id=1
    for path in "${SHK_FAKE_GH_REMOTE}"/*; do
      name="$(basename "$path")"
      if [[ "$name" == "shk-desktop-obsolete.pkg" ]]; then
        printf '999\t%s\n' "$name"
      else
        printf '%s\t%s\n' "$asset_id" "$name"
        asset_id=$((asset_id + 1))
      fi
    done
    ;;
  *)
    exit 1
    ;;
esac
EOF
chmod +x "$fake_gh_bin/gh"

printf 'stale\n' > "$fake_gh_remote/shk-desktop-obsolete.pkg"
printf 'updater metadata\n' > "$tmpdir/latest.json"
PATH="$fake_gh_bin:$PATH" \
  GITHUB_REPOSITORY=Kazuki-tam/security-harness-kit \
  SHK_FAKE_GH_LOG="$fake_gh_log" \
  SHK_FAKE_GH_REMOTE="$fake_gh_remote" \
  SHK_FAKE_GH_STATE="$fake_gh_state" \
  SHK_FAKE_FAIL_ONCE=shk-desktop-x86_64-apple-darwin.dmg \
  ./.github/scripts/release/publish-desktop-stable-assets.sh \
  "$stable_out" "$tmpdir/latest.json" >/dev/null

test ! -e "$fake_gh_remote/shk-desktop-obsolete.pkg"
cmp -s "$tmpdir/latest.json" "$fake_gh_remote/latest.json"
assert_output "stable publisher retries a failed upload" "1" \
  awk '$0 == "fail:shk-desktop-x86_64-apple-darwin.dmg" { count++ } END { print count + 0 }' "$fake_gh_log"
assert_output "stable publisher uploads updater metadata last" "upload:latest.json" \
  awk '/^upload:/ { last = $0 } END { print last }' "$fake_gh_log"
if ! awk '
  $0 == "delete:shk-desktop-obsolete.pkg" { deleted = NR }
  $0 == "upload:latest.json" { latest = NR }
  END { exit !(deleted > 0 && latest > deleted) }
' "$fake_gh_log"; then
  echo "FAIL: stale stable assets must be removed before updater metadata is published" >&2
  exit 1
fi
echo "ok: desktop stable assets are retried, verified, pruned, and published metadata-last"

printf 'stale again\n' > "$fake_gh_remote/shk-desktop-obsolete.pkg"
: > "$fake_gh_log"
if PATH="$fake_gh_bin:$PATH" \
  GITHUB_REPOSITORY=Kazuki-tam/security-harness-kit \
  SHK_FAKE_GH_LOG="$fake_gh_log" \
  SHK_FAKE_GH_REMOTE="$fake_gh_remote" \
  SHK_FAKE_GH_STATE="$fake_gh_state" \
  SHK_FAKE_KEEP_STALE=true \
  ./.github/scripts/release/publish-desktop-stable-assets.sh \
  "$stable_out" "$tmpdir/latest.json" >/dev/null 2>&1; then
  echo "FAIL: stable publisher must reject a stale asset that remains after deletion" >&2
  exit 1
fi
if grep -q '^upload:latest.json$' "$fake_gh_log"; then
  echo "FAIL: updater metadata must not publish before final asset-set validation" >&2
  exit 1
fi
echo "ok: failed final asset validation does not publish updater metadata"

printf 'windows exe\n' > "$tmpdir/shk.exe"
(
  cd "$tmpdir"
  zip -q shk-cli-x86_64-pc-windows-msvc.zip shk.exe
  rm -f shk.exe
)
printf '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  shk-cli-x86_64-pc-windows-msvc.zip\n' \
  > "$tmpdir/shk-cli-x86_64-pc-windows-msvc.zip.sha256"

installer_fixture_dir="$tmpdir/installer-checksum"
mkdir -p "$installer_fixture_dir"
printf 'mac archive\n' > "$installer_fixture_dir/shk-cli-aarch64-apple-darwin.tar.xz"
printf 'linux archive\n' > "$installer_fixture_dir/shk-cli-x86_64-unknown-linux-gnu.tar.xz"
fixture_sha256() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{ print $1 }'
  else
    shasum -a 256 "$path" | awk '{ print $1 }'
  fi
}
installer_digest_a="$(fixture_sha256 "$installer_fixture_dir/shk-cli-aarch64-apple-darwin.tar.xz")"
installer_digest_b="$(fixture_sha256 "$installer_fixture_dir/shk-cli-x86_64-unknown-linux-gnu.tar.xz")"
printf '%s  shk-cli-aarch64-apple-darwin.tar.xz\n' "$installer_digest_a" \
  > "$installer_fixture_dir/shk-cli-aarch64-apple-darwin.tar.xz.sha256"
printf '%s  shk-cli-x86_64-unknown-linux-gnu.tar.xz\n' "$installer_digest_b" \
  > "$installer_fixture_dir/shk-cli-x86_64-unknown-linux-gnu.tar.xz.sha256"

write_installer_checksum_fixture() {
  local digest_a="$1"
  local digest_b="$2"
  cat > "$installer_fixture_dir/shk-cli-installer.sh" <<EOF
case "\$_artifact_name" in
    "shk-cli-aarch64-apple-darwin.tar.xz")
        _checksum_style="sha256"
        _checksum_value="${digest_a}"
        ;;
    "shk-cli-x86_64-unknown-linux-gnu.tar.xz")
        _checksum_style="sha256"
        _checksum_value="${digest_b}"
        ;;
esac
EOF
}

assert_installer_verification_fails() {
  local description="$1"
  if ./.github/scripts/release/verify-cli-installer-checksums.sh \
    "$installer_fixture_dir" >/dev/null 2>&1; then
    echo "FAIL: ${description}" >&2
    exit 1
  fi
  echo "ok: ${description}"
}

write_installer_checksum_fixture "$installer_digest_a" "$installer_digest_b"
./.github/scripts/release/verify-cli-installer-checksums.sh "$installer_fixture_dir" >/dev/null
echo "ok: CLI shell installer checksums verified"

write_installer_checksum_fixture "$installer_digest_b" "$installer_digest_a"
assert_installer_verification_fails "misplaced CLI shell installer checksums rejected"

write_installer_checksum_fixture "$installer_digest_a" "$installer_digest_b"
sed -i.bak -e '/_checksum_style=/d' -e '/_checksum_value=/d' \
  "$installer_fixture_dir/shk-cli-installer.sh"
rm "$installer_fixture_dir/shk-cli-installer.sh.bak"
assert_installer_verification_fails "missing CLI shell installer checksum metadata rejected"

printf 'case "$_artifact_name" in\nesac\n' \
  > "$installer_fixture_dir/shk-cli-installer.sh"
assert_installer_verification_fails "CLI shell installer with no archive entries rejected"

write_installer_checksum_fixture "$installer_digest_a" "$installer_digest_b"
sed -i.bak '/shk-cli-x86_64-unknown-linux-gnu.tar.xz")/,/;;/d' \
  "$installer_fixture_dir/shk-cli-installer.sh"
rm "$installer_fixture_dir/shk-cli-installer.sh.bak"
assert_installer_verification_fails "CLI shell installer with a missing archive entry rejected"

write_installer_checksum_fixture "$installer_digest_a" "$installer_digest_b"
printf 'tampered archive\n' \
  > "$installer_fixture_dir/shk-cli-aarch64-apple-darwin.tar.xz"
assert_installer_verification_fails "CLI archive with a mismatched published checksum rejected"

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

unsigned_assets="$tmpdir/unsigned-assets"
mkdir -p "$unsigned_assets"
for target in \
  "x86_64-unknown-linux-gnu" \
  "aarch64-unknown-linux-gnu" \
  "x86_64-apple-darwin" \
  "aarch64-apple-darwin" \
  "x86_64-pc-windows-msvc"; do
  case "$target" in
    *linux*)
      printf 'linux\n' > "$unsigned_assets/shk-desktop_${current_version}_${target}_shk.AppImage"
      printf 'linux\n' > "$unsigned_assets/shk-desktop_${current_version}_${target}_shk.deb"
      ;;
    *apple-darwin)
      printf 'mac\n' > "$unsigned_assets/shk-desktop_${current_version}_${target}_shk.app.tar.gz"
      ;;
    *windows*)
      printf 'windows\n' > "$unsigned_assets/shk-desktop_${current_version}_${target}_shk-setup.exe"
      ;;
  esac
done
RELEASE_VERSION="$current_version" \
  ./.github/scripts/release/verify-unsigned-desktop-assets.sh "$unsigned_assets" >/dev/null
echo "ok: unsigned desktop asset verification"

# The npm packaging table must cover exactly the targets cargo-dist builds.
dist_targets="$(awk -F'[][]' '/^targets = / { print $2 }' dist-workspace.toml | tr -d '" ' | tr ',' '\n' | LC_ALL=C sort)"
npm_targets="$(shk_npm_platforms | awk '{ print $1 }' | LC_ALL=C sort)"
if [[ -z "$dist_targets" || "$dist_targets" != "$npm_targets" ]]; then
  echo "FAIL: shk_npm_platforms targets differ from dist-workspace.toml targets" >&2
  echo "dist: ${dist_targets//$'\n'/ }" >&2
  echo "npm:  ${npm_targets//$'\n'/ }" >&2
  exit 1
fi
echo "ok: npm platform packages cover every dist target"
if grep -E -q '^(installers|publish-jobs) = .*"npm"' dist-workspace.toml; then
  echo "FAIL: dist must not generate or publish its own npm installer (it ships npm-shrinkwrap.json)" >&2
  exit 1
fi
echo "ok: dist npm installer stays disabled"

# cargo-dist-shaped archives. The "binary" is a shell script so the launcher
# test below can run it on any POSIX host.
channel_fixture="$tmpdir/cli-channel-artifacts"
mkdir -p "$channel_fixture"
channel_stage="$tmpdir/cli-channel-stage"
for channel_archive in \
  shk-cli-aarch64-apple-darwin.tar.xz \
  shk-cli-aarch64-unknown-linux-gnu.tar.xz \
  shk-cli-x86_64-apple-darwin.tar.xz \
  shk-cli-x86_64-pc-windows-msvc.zip \
  shk-cli-x86_64-unknown-linux-gnu.tar.xz; do
  channel_target="${channel_archive#shk-cli-}"
  channel_target="${channel_target%.tar.xz}"
  channel_target="${channel_target%.zip}"
  channel_stage_dir="$channel_stage/shk-cli-${channel_target}"
  mkdir -p "$channel_stage_dir"
  printf 'readme\n' > "$channel_stage_dir/README.md"
  case "$channel_archive" in
    *.zip)
      printf '#!/bin/sh\necho "fixture shk %s $*"\nexit 7\n' "$channel_target" > "$channel_stage_dir/shk.exe"
      (cd "$channel_stage_dir" && zip -q "$channel_fixture/$channel_archive" shk.exe README.md)
      ;;
    *)
      printf '#!/bin/sh\necho "fixture shk %s $*"\nexit 7\n' "$channel_target" > "$channel_stage_dir/shk"
      chmod 755 "$channel_stage_dir/shk"
      tar -cJf "$channel_fixture/$channel_archive" -C "$channel_stage" "shk-cli-${channel_target}"
      ;;
  esac
  channel_digest="$(fixture_sha256 "$channel_fixture/$channel_archive")"
  printf '%s  %s\n' "$channel_digest" "$channel_archive" \
    > "$channel_fixture/$channel_archive.sha256"
done
for channel_archive in \
  shk-cli-aarch64-apple-darwin.tar.xz \
  shk-cli-aarch64-unknown-linux-gnu.tar.xz \
  shk-cli-x86_64-apple-darwin.tar.xz \
  shk-cli-x86_64-pc-windows-msvc.zip \
  shk-cli-x86_64-unknown-linux-gnu.tar.xz; do
  target="${channel_archive#shk-cli-}"
  target="${target%.tar.xz}"
  target="${target%.zip}"
  jq -n --arg archive "$channel_archive" \
    '{artifacts: {archive: {kind: "executable-zip", name: $archive}}}' \
    > "$channel_fixture/${target}-dist-manifest.json"
done
printf '%s\n' "https://github.com/Kazuki-tam/security-harness-kit/releases/download/v${current_version}" \
  > "$channel_fixture/shk-cli-installer.sh"
printf '%s\n' "https://github.com/Kazuki-tam/security-harness-kit/releases/download/v${current_version}" \
  > "$channel_fixture/shk-cli-installer.ps1"
printf '%s\n' "url \"https://github.com/Kazuki-tam/security-harness-kit/releases/download/v${current_version}/shk-cli-x86_64-unknown-linux-gnu.tar.xz\"" \
  > "$channel_fixture/shk.rb"
./.github/scripts/release/build-npm-packages.sh \
  "$channel_fixture" "$current_version" "$channel_fixture" >/dev/null
echo "ok: npm packages built from CLI archives"
./.github/scripts/release/verify-cli-channel-artifacts.sh \
  "$channel_fixture" "$current_version" >/dev/null
echo "ok: CLI channel artifact references verified"

sed -i.bak "s|releases/download/v${current_version}|releases/download/shk-v${current_version}|" \
  "$channel_fixture/shk.rb"
rm "$channel_fixture/shk.rb.bak"
if ./.github/scripts/release/verify-cli-channel-artifacts.sh \
  "$channel_fixture" "$current_version" >/dev/null 2>&1; then
  echo "FAIL: non-cargo-dist Homebrew download tag should fail" >&2
  exit 1
fi
echo "ok: non-cargo-dist CLI channel tag rejected"

sed -i.bak "s|releases/download/shk-v${current_version}|releases/download/v${current_version}|" \
  "$channel_fixture/shk.rb"
rm "$channel_fixture/shk.rb.bak"

printf '%s\n' \
  "https://github.com/third-party/project/releases/download/shk-v${current_version}/asset" \
  >> "$channel_fixture/shk.rb"
./.github/scripts/release/verify-cli-channel-artifacts.sh \
  "$channel_fixture" "$current_version" >/dev/null
echo "ok: unrelated third-party release URLs ignored"

# --- npm packages: dependency-free main package + per-platform binaries ---
npm_package_names=()
while IFS= read -r npm_package_name; do
  npm_package_names+=("$npm_package_name")
done < <(shk_npm_package_names)
if [[ "${#npm_package_names[@]}" -ne 6 || "${npm_package_names[5]}" != "security-harness-kit" ]]; then
  echo "FAIL: expected five platform packages followed by security-harness-kit" >&2
  exit 1
fi
for npm_package_name in "${npm_package_names[@]}"; do
  npm_tarball="$channel_fixture/${npm_package_name}-${current_version}.tgz"
  npm_entries="$(tar -tzf "$npm_tarball")"
  for forbidden_entry in npm-shrinkwrap.json package-lock.json binding.gyp node_modules; do
    if [[ "$npm_entries" == *"$forbidden_entry"* ]]; then
      echo "FAIL: ${npm_package_name} tarball contains ${forbidden_entry}" >&2
      exit 1
    fi
  done
  if ! tar -xzOf "$npm_tarball" package/package.json \
    | jq -e '(has("scripts") or has("dependencies")) | not' >/dev/null; then
    echo "FAIL: ${npm_package_name} defines scripts or dependencies" >&2
    exit 1
  fi
done
echo "ok: npm packages ship no shrinkwrap, lockfile, install scripts, or dependencies"

assert_output "npm main package pins every platform package to the release version" \
  "security-harness-kit-darwin-arm64@${current_version} security-harness-kit-darwin-x64@${current_version} security-harness-kit-linux-arm64@${current_version} security-harness-kit-linux-x64@${current_version} security-harness-kit-win32-x64@${current_version}" \
  bash -c "tar -xzOf '$channel_fixture/security-harness-kit-${current_version}.tgz' package/package.json \
    | jq -r '[.optionalDependencies | to_entries[] | \"\(.key)@\(.value)\"] | join(\" \")'"
assert_output "npm linux package is restricted to glibc" \
  '{"os":["linux"],"cpu":["arm64"],"libc":["glibc"]}' \
  bash -c "tar -xzOf '$channel_fixture/security-harness-kit-linux-arm64-${current_version}.tgz' package/package.json \
    | jq -c '{os, cpu, libc}'"
assert_output "npm windows package ships shk.exe for win32-x64" \
  '{"os":["win32"],"cpu":["x64"],"files":["bin/shk.exe","THIRD_PARTY_LICENSES.md"]}' \
  bash -c "tar -xzOf '$channel_fixture/security-harness-kit-win32-x64-${current_version}.tgz' package/package.json \
    | jq -c '{os, cpu, files}'"

# Tamper with one built tarball, expect the channel verification to reject it
# for the stated reason, then restore the pristine tarballs.
npm_pristine="$tmpdir/npm-pristine"
mkdir -p "$npm_pristine"
cp "$channel_fixture"/*.tgz "$npm_pristine/"
npm_repack() {
  local package="$1"
  shift
  local dir="$tmpdir/npm-repack"
  rm -rf "$dir"
  mkdir -p "$dir"
  tar -xzf "$channel_fixture/${package}-${current_version}.tgz" -C "$dir"
  (cd "$dir/package" && "$@")
  COPYFILE_DISABLE=1 tar -czf "$channel_fixture/${package}-${current_version}.tgz" -C "$dir" package
}
npm_edit_manifest() {
  jq "$1" package.json > package.json.new
  mv package.json.new package.json
}
expect_npm_rejected() {
  local description="$1"
  local expected_error="$2"
  local output
  if output="$(./.github/scripts/release/verify-cli-channel-artifacts.sh \
    "$channel_fixture" "$current_version" 2>&1)"; then
    echo "FAIL: ${description} should fail" >&2
    exit 1
  fi
  assert_contains "${description} error" "$output" "$expected_error"
  echo "ok: ${description} rejected"
  rm -f "$channel_fixture"/*.tgz
  cp "$npm_pristine"/*.tgz "$channel_fixture/"
}

npm_repack security-harness-kit npm_edit_manifest '.version = "9.9.9"'
expect_npm_rejected "mismatched npm package identity" "npm package identity mismatch"

npm_repack security-harness-kit bash -c 'printf "{}\n" > npm-shrinkwrap.json'
expect_npm_rejected "npm package with a shrinkwrap" "unexpected npm package contents"

npm_repack security-harness-kit npm_edit_manifest '.scripts = {postinstall: "node install.js"}'
expect_npm_rejected "npm package with an install script" "package.json must not define: scripts"

npm_repack security-harness-kit-linux-x64 npm_edit_manifest '.dependencies = {"left-pad": "1.0.0"}'
expect_npm_rejected "npm platform package with a dependency" "package.json must not define: dependencies"

npm_repack security-harness-kit npm_edit_manifest \
  '.optionalDependencies["security-harness-kit-linux-x64"] |= "^" + .'
expect_npm_rejected "npm main package with a version range" "optionalDependencies must pin every platform package"

npm_repack security-harness-kit-darwin-arm64 bash -c 'printf "tampered\n" >> bin/shk'
expect_npm_rejected "npm platform binary that differs from the release archive" "binary does not match shk-cli-aarch64-apple-darwin.tar.xz"

npm_repack security-harness-kit-linux-arm64 npm_edit_manifest 'del(.libc)'
expect_npm_rejected "npm linux package without the glibc restriction" "unexpected os/cpu/libc"

npm_repack security-harness-kit ln -s /etc/passwd unsafe-link
expect_npm_rejected "npm package link entry" "contains a link or special archive entry"

rm "$channel_fixture/security-harness-kit-win32-x64-${current_version}.tgz"
expect_npm_rejected "missing npm platform package" "missing npm package tarball: security-harness-kit-win32-x64-${current_version}.tgz"

cp "$channel_fixture/security-harness-kit-${current_version}.tgz" \
  "$channel_fixture/security-harness-kit-freebsd-x64-${current_version}.tgz"
expect_npm_rejected "unlisted npm package tarball" "unexpected npm package tarball(s)"

./.github/scripts/release/verify-cli-channel-artifacts.sh \
  "$channel_fixture" "$current_version" >/dev/null
echo "ok: restored npm packages verify again"

# Launcher: unpack the tarballs the way a package manager lays them out and
# run the `shk` bin. The fixture binary echoes its arguments and exits 7.
npm_install_dir="$tmpdir/npm-install/node_modules"
npm_unpack() {
  local package="$1"
  mkdir -p "$npm_install_dir/$package"
  tar -xzf "$channel_fixture/${package}-${current_version}.tgz" \
    -C "$npm_install_dir/$package" --strip-components=1
}
npm_unpack security-harness-kit
npm_launcher="$npm_install_dir/security-harness-kit/bin/shk.js"
npm_host="$(node -p 'process.platform + "-" + process.arch')"
npm_host_target="$(shk_npm_platforms | awk -v host="$npm_host" '$2 "-" $3 == host { print $1 }')"
if [[ -n "$npm_host_target" && "$npm_host" != win32-* ]]; then
  if launcher_output="$(node "$npm_launcher" scan --flag 2>&1)"; then
    echo "FAIL: launcher without the platform package should fail" >&2
    exit 1
  else
    launcher_status=$?
  fi
  if [[ "$launcher_status" -ne 2 ]]; then
    echo "FAIL: launcher without the platform package exited ${launcher_status}, expected 2" >&2
    exit 1
  fi
  assert_contains "launcher names the missing platform package" "$launcher_output" \
    "security-harness-kit-${npm_host}@${current_version} is not installed"
  echo "ok: launcher fails closed when the platform package is missing"

  npm_unpack "security-harness-kit-${npm_host}"
  if launcher_output="$(node "$npm_launcher" scan --flag 2>&1)"; then
    launcher_status=0
  else
    launcher_status=$?
  fi
  if [[ "$launcher_status" -ne 7 || "$launcher_output" != "fixture shk ${npm_host_target} scan --flag" ]]; then
    echo "FAIL: launcher did not run the platform binary (exit ${launcher_status}): ${launcher_output}" >&2
    exit 1
  fi
  echo "ok: launcher runs the platform binary and forwards arguments and exit code"
else
  echo "skip: launcher run test (no POSIX platform package for ${npm_host})"
fi

if launcher_output="$(node -e '
  Object.defineProperty(process, "platform", { value: "freebsd" });
  require(process.argv[1]);
' "$npm_launcher" 2>&1)"; then
  echo "FAIL: launcher on an unsupported platform should fail" >&2
  exit 1
else
  launcher_status=$?
fi
if [[ "$launcher_status" -ne 2 ]]; then
  echo "FAIL: launcher on an unsupported platform exited ${launcher_status}, expected 2" >&2
  exit 1
fi
assert_contains "launcher explains the unsupported platform" "$launcher_output" \
  "no prebuilt binary for freebsd-"
assert_contains "launcher lists supported platforms" "$launcher_output" \
  "darwin-arm64, darwin-x64, linux-arm64, linux-x64, win32-x64"
echo "ok: launcher reports unsupported platforms with exit 2"

# Publishing: platform packages first, the main package last, skipping
# versions that already exist. `npm` is stubbed; nothing reaches a registry.
npm_stub="$tmpdir/npm-stub"
mkdir -p "$npm_stub/bin"
cat > "$npm_stub/bin/npm" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  view)
    grep -F -x -q "$2" "$NPM_STUB_STATE/published"
    ;;
  publish)
    name="$(basename "$2" .tgz)"
    [[ "$2" == /* ]] || { echo "publish path must be absolute: $2" >&2; exit 1; }
    if [[ "$name" == "${NPM_STUB_FAIL:-}-"* ]]; then
      exit 1
    fi
    shift 2
    printf '%s %s\n' "$name" "$*" >> "$NPM_STUB_STATE/publish.log"
    tar -xzOf "$NPM_STUB_DIR/${name}.tgz" package/package.json \
      | jq -r '"\(.name)@\(.version)"' >> "$NPM_STUB_STATE/published"
    ;;
  *)
    echo "unexpected npm call: $*" >&2
    exit 1
    ;;
esac
STUB
chmod +x "$npm_stub/bin/npm"
npm_stub_reset() {
  rm -rf "$npm_stub/state"
  mkdir -p "$npm_stub/state"
  : > "$npm_stub/state/published"
  : > "$npm_stub/state/publish.log"
}
npm_stub_publish() {
  env PATH="$npm_stub/bin:$PATH" NPM_STUB_STATE="$npm_stub/state" NPM_STUB_DIR="$channel_fixture" \
    NPM_STUB_FAIL="${NPM_STUB_FAIL:-}" \
    ./.github/scripts/release/publish-npm-packages.sh "$channel_fixture" "$current_version"
}

npm_stub_reset
npm_stub_publish >/dev/null
expected_publish_log=""
for npm_package_name in "${npm_package_names[@]}"; do
  expected_publish_log+="${npm_package_name}-${current_version} --provenance --access public"$'\n'
done
if [[ "$(<"$npm_stub/state/publish.log")"$'\n' != "$expected_publish_log" ]]; then
  echo "FAIL: npm packages must publish platform packages first and the main package last" >&2
  cat "$npm_stub/state/publish.log" >&2
  exit 1
fi
echo "ok: npm publish order is platform packages, then the main package"

: > "$npm_stub/state/publish.log"
npm_stub_publish >/dev/null
if [[ -s "$npm_stub/state/publish.log" ]]; then
  echo "FAIL: already-published npm packages must be skipped" >&2
  exit 1
fi
echo "ok: already-published npm packages are skipped"

npm_stub_reset
if NPM_STUB_FAIL=security-harness-kit-linux-x64 npm_stub_publish >/dev/null 2>&1; then
  echo "FAIL: a failed platform publish must fail the job" >&2
  exit 1
fi
if grep -q "^security-harness-kit-${current_version} " "$npm_stub/state/publish.log"; then
  echo "FAIL: the main npm package must not publish after a platform package failed" >&2
  exit 1
fi
echo "ok: main npm package is not published when a platform package fails"

npm_stub_reset
mv "$channel_fixture/security-harness-kit-win32-x64-${current_version}.tgz" "$tmpdir/"
if npm_stub_publish >/dev/null 2>&1 || [[ -s "$npm_stub/state/publish.log" ]]; then
  echo "FAIL: a missing npm tarball must stop publishing before anything is published" >&2
  exit 1
fi
mv "$tmpdir/security-harness-kit-win32-x64-${current_version}.tgz" "$channel_fixture/"
echo "ok: missing npm tarball stops publishing before the first publish"

assert_contains "release workflow publishes npm packages through the publish script" \
  "$release_workflow" './.github/scripts/release/publish-npm-packages.sh dist-global "${RELEASE_VERSION}"'
assert_contains "release workflow uploads the npm tarballs" \
  "$release_workflow" "target/distrib/security-harness-kit-*.tgz"
if [[ "$release_workflow" == *"npm-package.tar.gz"* || "$release_workflow" == *"NODE_AUTH_TOKEN"* || "$release_workflow" == *"NPM_TOKEN"* ]]; then
  echo "FAIL: release workflow must not publish the dist npm installer or use an npm token" >&2
  exit 1
fi
echo "ok: release workflow publishes the dependency-free npm packages over OIDC"

rm "$channel_fixture/shk-cli-aarch64-apple-darwin.tar.xz"
if ./.github/scripts/release/verify-cli-channel-artifacts.sh \
  "$channel_fixture" "$current_version" >/dev/null 2>&1; then
  echo "FAIL: missing required CLI platform archive should fail" >&2
  exit 1
fi
echo "ok: missing required CLI platform archive rejected"

printf 'archive %s\n' "shk-cli-aarch64-apple-darwin.tar.xz" \
  > "$channel_fixture/shk-cli-aarch64-apple-darwin.tar.xz"
channel_digest="$(fixture_sha256 "$channel_fixture/shk-cli-aarch64-apple-darwin.tar.xz")"
printf '%s  %s\n' "$channel_digest" "shk-cli-aarch64-apple-darwin.tar.xz" \
  > "$channel_fixture/shk-cli-aarch64-apple-darwin.tar.xz.sha256"
jq -n \
  '{artifacts: {archive: {kind: "executable-zip", name: "shk-cli-riscv64gc-unknown-linux-gnu.tar.xz"}}}' \
  > "$channel_fixture/riscv64gc-unknown-linux-gnu-dist-manifest.json"
if ./.github/scripts/release/verify-cli-channel-artifacts.sh \
  "$channel_fixture" "$current_version" >/dev/null 2>&1; then
  echo "FAIL: a dist manifest target without an archive should fail" >&2
  exit 1
fi
echo "ok: dist manifest target automatically requires an archive"
rm "$channel_fixture/riscv64gc-unknown-linux-gnu-dist-manifest.json"

cp "$channel_fixture/aarch64-apple-darwin-dist-manifest.json" \
  "$channel_fixture/duplicate-dist-manifest.json"
if ./.github/scripts/release/verify-cli-channel-artifacts.sh \
  "$channel_fixture" "$current_version" >/dev/null 2>&1; then
  echo "FAIL: duplicate executable archives across dist manifests should fail" >&2
  exit 1
fi
echo "ok: duplicate dist manifest archive rejected"
rm "$channel_fixture/duplicate-dist-manifest.json"

mirror_script=./.github/scripts/release/mirror-cli-release.sh

assert_output "mirror tag for combined release" "v1.2.3" "$mirror_script" tag shk-v1.2.3
assert_output "mirror tag for cli-prefixed release" "v1.2.3" "$mirror_script" tag cli-v1.2.3

if "$mirror_script" tag "v1.2.3" >/dev/null 2>&1; then
  echo "FAIL: plain v tag should not need a mirror" >&2
  exit 1
fi
echo "ok: mirror rejects plain v tag"

if "$mirror_script" tag "desktop-v1.2.3" >/dev/null 2>&1; then
  echo "FAIL: desktop tag should not resolve to a CLI mirror" >&2
  exit 1
fi
echo "ok: mirror rejects desktop tag"

if "$mirror_script" tag "shk-vnot-a-version" >/dev/null 2>&1; then
  echo "FAIL: non-semver source tag should be rejected" >&2
  exit 1
fi
echo "ok: mirror rejects non-semver source tag"

mirror_notes="$("$mirror_script" notes shk-v1.2.3)"
assert_contains "mirror notes download path" "$mirror_notes" "releases/download/v1.2.3"
assert_contains "mirror notes canonical tag" "$mirror_notes" "releases/tag/shk-v1.2.3"

mirror_assets="$tmpdir/mirror-assets"
mkdir -p "$mirror_assets"
printf 'archive\n' > "$mirror_assets/shk-cli-x86_64-apple-darwin.tar.xz"
printf 'checksum\n' > "$mirror_assets/shk-cli-x86_64-apple-darwin.tar.xz.sha256"
printf 'installer\n' > "$mirror_assets/shk-cli-installer.sh"
printf 'sums\n' > "$mirror_assets/sha256.sum"
printf 'formula\n' > "$mirror_assets/shk.rb"
printf 'source\n' > "$mirror_assets/source.tar.gz"
printf 'desktop\n' > "$mirror_assets/shk-desktop_1.2.3_x86_64-apple-darwin_1.2.3_x64.dmg"
printf 'updater\n' > "$mirror_assets/latest.json"
mirror_selected="$("$mirror_script" select "$mirror_assets")"
assert_contains "mirror selects CLI archive" "$mirror_selected" "shk-cli-x86_64-apple-darwin.tar.xz"
assert_contains "mirror selects installer" "$mirror_selected" "shk-cli-installer.sh"
assert_contains "mirror selects Homebrew formula" "$mirror_selected" "shk.rb"
if [[ "$mirror_selected" == *".dmg"* || "$mirror_selected" == *"latest.json"* ]]; then
  echo "FAIL: mirror selection must exclude desktop assets" >&2
  exit 1
fi
echo "ok: mirror selection excludes desktop assets"

mirror_empty="$tmpdir/mirror-empty"
mkdir -p "$mirror_empty"
printf 'sums\n' > "$mirror_empty/sha256.sum"
if "$mirror_script" select "$mirror_empty" >/dev/null 2>&1; then
  echo "FAIL: mirror selection without CLI archives should fail" >&2
  exit 1
fi
echo "ok: mirror selection requires CLI archives"

bash -c 'source "$1"; require_same_commit shk-v1.2.3 source-sha v1.2.3 source-sha' _ "$mirror_script"
echo "ok: mirror accepts a tag at the source commit"

if bash -c 'source "$1"; require_same_commit shk-v1.2.3 source-sha v1.2.3 other-sha' _ "$mirror_script" >/dev/null 2>&1; then
  echo "FAIL: mirror tag at a different commit should be rejected" >&2
  exit 1
fi
echo "ok: mirror rejects a tag at a different commit"

release_body_dir="$tmpdir/release-body"
mkdir -p "$release_body_dir/bin" "$release_body_dir/notes"
cat > "$release_body_dir/bin/dist" <<'STUB'
#!/usr/bin/env bash
echo '{"announcement_github_body":"## Install stub"}'
STUB
chmod +x "$release_body_dir/bin/dist"
echo "## CLI notes stub" > "$release_body_dir/notes/v1.2.3.md"
echo "## Desktop notes stub" > "$release_body_dir/notes/desktop-v1.2.3.md"

release_body_first_line() {
  (
    cd "$release_body_dir"
    env PATH="$release_body_dir/bin:$PATH" SHK_RELEASE_NOTES_DIR="$release_body_dir/notes" \
      RELEASE_COMPONENT="$1" RELEASE_VERSION="$2" \
      "${ROOT}/.github/scripts/release/generate-release-body.sh" body.md >/dev/null
    head -n 1 body.md
  )
}

assert_output "CLI notes lead the release body" "## CLI notes stub" release_body_first_line cli 1.2.3
assert_contains "CLI release body keeps the dist announcement" \
  "$(<"$release_body_dir/body.md")" "## Install stub"
assert_contains "CLI release body includes the npm install command" \
  "$(<"$release_body_dir/body.md")" "npm install -g security-harness-kit@1.2.3"
assert_output "desktop notes lead the release body" "## Desktop notes stub" release_body_first_line desktop 1.2.3
assert_output "combined release body starts with the CLI notes" "## CLI notes stub" release_body_first_line both 1.2.3
assert_contains "combined release body includes the desktop notes" \
  "$(<"$release_body_dir/body.md")" "## Desktop notes stub"
assert_output "release body without notes starts with the dist announcement" "## Install stub" release_body_first_line cli 9.9.9

echo "release script tests passed"
