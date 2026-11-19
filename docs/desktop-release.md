# Desktop Release

Signed desktop releases via `desktop-vX.Y.Z` (or combined `shk-vX.Y.Z`) are the
default as of `desktop-v0.6.0`: macOS builds are Developer ID signed and
notarized, and Windows ships unsigned under the explicit opt-in described in
[Releasing without Windows Authenticode signing](#releasing-without-windows-authenticode-signing)
until Authenticode signing is configured. The **unsigned early access** path
below remains available for maintainers.

## Unsigned early access

Publish unsigned desktop builds from tags matching `desktop-unsigned-vX.Y.Z`.
The **Release Desktop (unsigned)** workflow can also be run manually, but manual
runs only build and upload GitHub Actions artifacts for validation. Tag pushes
publish the GitHub Release and update `desktop-latest/latest.json`.

These builds still require **Tauri updater signing** secrets and publish the same
`shk-desktop_*` assets, checksums, `shk-desktop-latest.json`, SBOM, attestation,
and updater metadata as signed releases when run from a tag.

Keep the same `TAURI_UPDATER_PUBKEY` and `TAURI_SIGNING_PRIVATE_KEY` across
unsigned and signed releases so existing installs can update in place.

### What unsigned means

| Platform | Included | Not included |
|----------|----------|--------------|
| Linux x86_64 / aarch64 | AppImage, `.deb` | — |
| macOS Intel / Apple Silicon | updater `.app.tar.gz` only | `.dmg`, Developer ID, notarization |
| Windows x86_64 | NSIS `.exe` only | `.msi`, Authenticode |

macOS and Windows installers from unsigned releases are **not** Developer ID signed,
notarized, or Authenticode-signed. Users may need to bypass Gatekeeper or
SmartScreen on first launch. See [Installation](installation.md#desktop-app-unsigned-early-access).

For OSS production repositories, store updater signing secrets in a protected
GitHub environment such as `release` with required reviewers instead of exposing
them broadly at repository scope.

## Signed production releases

When OS code signing is configured, release from tags matching `desktop-vX.Y.Z`
or `shk-vX.Y.Z`. macOS production releases require Developer ID signing and
notarization. Windows production releases require Authenticode code signing.

## Required GitHub Secrets

All desktop releases require:

- `TAURI_UPDATER_PUBKEY`
- `TAURI_SIGNING_PRIVATE_KEY`
- `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` when the private key is encrypted

macOS **signed** releases also require:

- `APPLE_CERTIFICATE` base64-encoded Developer ID Application `.p12`
- `APPLE_CERTIFICATE_PASSWORD`
- `APPLE_SIGNING_IDENTITY`, for example
  `Developer ID Application: Example, Inc. (TEAMID)`
- `KEYCHAIN_PASSWORD`
- `APPLE_ID`
- `APPLE_PASSWORD`, an app-specific password
- `APPLE_TEAM_ID`

Windows **signed** releases require one of the following signing configurations.
Configure exactly one mode; the release check fails if both are present.

Custom signer, recommended for cloud signing services such as Azure Trusted
Signing, SignPath, or a hardware-backed signing service:

- `TAURI_WINDOWS_SIGN_COMMAND`

The command must include `%1`, which Tauri replaces with the artifact path:

```text
trusted-signing-cli sign %1
```

Certificate thumbprint signing, for certificates installed in the Windows
runner's certificate store:

- `TAURI_WINDOWS_CERTIFICATE_THUMBPRINT`
- `TAURI_WINDOWS_TIMESTAMP_URL`
- `TAURI_WINDOWS_DIGEST_ALGORITHM` optional, defaults to `sha256`
- `TAURI_WINDOWS_TSP` optional, defaults to `false`

The thumbprint may include spaces or colons; release scripts normalize it before
passing it to Tauri. Invalid thumbprints fail before bundling starts.

### Releasing without Windows Authenticode signing

When macOS signing is configured but Windows Authenticode signing is not yet
available, a signed release can explicitly opt in to shipping an **unsigned**
Windows NSIS installer by setting the repository variable
`SHK_ALLOW_UNSIGNED_WINDOWS=true`.

The opt-in is deliberately narrow:

- It only applies when **no** Windows signing mode is configured. An invalid or
  mixed Windows signing configuration still fails the release.
- Signature verification still runs; it accepts `NotSigned` artifacts only
  under the opt-in and still rejects broken or tampered signatures.
- macOS Developer ID signing and notarization remain required.

Remove the variable once Authenticode signing is configured so future releases
fail loudly instead of silently shipping unsigned Windows installers.

## Release Gates

The unsigned workflow fails if updater signing secrets are missing and verifies
that all five desktop target artifacts are present before publishing.

The macOS **signed** release jobs fail unless Developer ID signing and notarization are
configured. Tauri notarizes the `.app` bundle but not the DMG built from it, so
after bundling the workflow notarizes and staples each `.dmg` itself
(`notarize-macos-dmg.sh`), then verifies `.dmg` artifacts and extracted
`.app` bundles from updater archives with `codesign`, `spctl`, and
`xcrun stapler validate`.

Stapling gets up to five attempts because GitHub runners intermittently lose
the connection to Apple's ticket service. `notarize-macos-dmg.sh` retries the DMG
directly. Tauri staples the `.app` itself and ignores the result, so the build step
puts `.github/scripts/release/xcrun-shim` on `PATH` to retry that call and prints
what happened from `tauri-stapler.log`. The verify step above still rejects any
artifact without a ticket.

The Windows **signed** release job fails unless Authenticode signing is configured. After
bundling, the workflow verifies every generated `.exe` and `.msi` with
`Get-AuthenticodeSignature` and fails the release when any signature is invalid.

The desktop build jobs do not put the signing secrets in the job environment.
A `load signing secrets` step (`load updater signing secrets` in the unsigned
workflow), placed after the third-party actions and `pnpm install`, writes
them to `GITHUB_ENV` through `.github/scripts/release/export-signing-env.sh`.
The main part of those actions and the dependency installation therefore run
without them, and the build steps only get the secrets of their own platform
(Apple secrets on macOS, Windows signing settings on Windows). The post-job
phase of the earlier actions (cache saves, checkout cleanup) runs after the
build and does see them. A new signing secret has to be added to that step's
`env:` and to the script's name list; `test.sh` compares the two.

Pull request CI runs desktop `tauri build --no-bundle` smoke tests on Linux,
macOS, and Windows. Signed installer bundling remains release-only because it
needs production signing secrets.

## CLI releases

The CLI channels (release archives, installers, Homebrew, npm) and the CLI
mirror that combined `shk-vX.Y.Z` releases need are documented in
[CLI Release](cli-release.md).

## Release Checklist

1. Update versions with `cargo run -p xtask -- bump-version X.Y.Z` so
   `Cargo.toml`, `apps/shk-desktop/package.json`, and
   `apps/shk-desktop/src-tauri/tauri.conf.json` stay aligned.
   When a release changes behavior for existing users, add
   `docs/release-notes/vX.Y.Z.md` or `docs/release-notes/desktop-vX.Y.Z.md`;
   the publish job puts it above the generated release body.
2. Confirm the `release` GitHub environment has updater signing secrets.
   For signed releases, also configure macOS Developer ID/notarization secrets
   and one Windows Authenticode signing mode.
3. Run `.github/scripts/release/test.sh` locally or rely on the CI
   `release-scripts` job.
4. Push `desktop-unsigned-vX.Y.Z` for an unsigned desktop-only release,
   `desktop-vX.Y.Z` for a signed desktop-only release, or `shk-vX.Y.Z` for a
   combined CLI and desktop release.
5. After publishing, verify the GitHub release assets, `shk-desktop.sha256sum`,
   `shk-desktop-latest.json`, and the `desktop-latest` release: `latest.json`
   must point at the new tag, and the version-free installers
   (`shk-desktop-<target>.dmg` / `.AppImage` / `.deb` / `-setup.exe` / `.msi`)
   plus their `shk-desktop.sha256sum` must match the new assets. These stable
   names back the website's download links; unsigned releases do not update
   them.
6. For `shk-vX.Y.Z` (or `cli-vX.Y.Z`) releases, run the
   [CLI mirror](cli-release.md#combined-releases-and-the-cli-mirror) so the installers
   and Homebrew formula resolve; the mirror command verifies all three
   published channels, npm included, before it succeeds.

### Unsigned release checklist

1. Confirm updater signing secrets are configured (`TAURI_UPDATER_PUBKEY`,
   `TAURI_SIGNING_PRIVATE_KEY`, and password when the key is encrypted).
2. Align desktop manifest versions as in the signed checklist above.
3. Push `desktop-unsigned-vX.Y.Z` to publish, or run **Release Desktop (unsigned)**
   from Actions with the target version for a build-only validation run.
4. For tag releases, verify assets and that `desktop-latest/latest.json` points
   at the new unsigned release tag.
5. Install the build on at least one macOS and one Windows machine and confirm
   the expected Gatekeeper / SmartScreen warnings and workarounds documented in
   [Installation](installation.md#desktop-app-unsigned-early-access).

## Local validation

```bash
# Frontend + Rust quality gates
pnpm -C apps/shk-desktop install --frozen-lockfile
pnpm -C apps/shk-desktop fmt:check
pnpm -C apps/shk-desktop lint
pnpm -C apps/shk-desktop test:run
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all

# Release script regression
./.github/scripts/release/test.sh

# Desktop smoke build (no installer bundle)
cd apps/shk-desktop
SHK_ALLOW_MISSING_UPDATER_PUBKEY=1 pnpm tauri build --no-bundle
```

For a local distribution build, set updater signing env vars and run the same
scripts used in CI (`generate-tauri-updater-config.sh`, `pnpm tauri build`).
