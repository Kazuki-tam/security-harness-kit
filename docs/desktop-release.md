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

Pull request CI runs desktop `tauri build --no-bundle` smoke tests on Linux,
macOS, and Windows. Signed installer bundling remains release-only because it
needs production signing secrets.

## Combined releases and the CLI mirror

Combined (`shk-vX.Y.Z`) and CLI-prefixed (`cli-vX.Y.Z`) tags publish every
asset under that tag, but the cargo-dist-generated install channels — the
shell/PowerShell installers and the Homebrew formula — embed
download URLs that follow cargo-dist's own `vX.Y.Z` convention, because the
workflow's `dist build` calls carry no announcement tag and cargo-dist cannot
parse the `shk-v*` / `cli-v*` conventions at all. Without a `vX.Y.Z` release,
these channels 404 (this bit `shk-v0.6.1`, the first combined release). The
npm packages carry the binaries themselves and do not depend on the mirror.

For a combined or `cli-v*` release, the published-channel verification job
intentionally fails until the required mirror exists. After the publish jobs
complete, mirror the CLI assets, then rerun the failed verification job:

```bash
./.github/scripts/release/mirror-cli-release.sh run shk-vX.Y.Z
```

The script downloads the CLI assets from the canonical release, verifies their
checksums, creates the `vX.Y.Z` tag at the same commit, and publishes a
non-latest mirror release with byte-identical assets (so the SHA-256 values in
the already-published Homebrew formula still match). It temporarily disables
the Release workflow while the tag is created — a `v*` tag push would
otherwise re-trigger it and publish a duplicate CLI release — and re-enables
it on exit. Before returning, it also verifies the published installer,
Homebrew, and npm channels against the mirror tag, commit, embedded download
URLs, archive checksums, and the binaries inside the npm packages.

All CLI-producing tags run the same published-channel verification in the
release workflow after Homebrew and npm publishing. To rerun it manually:

```bash
./.github/scripts/release/verify-cli-channels.sh vX.Y.Z
```

This is a maintainer-side step by design: the "Protect release tags" ruleset
only lets repository admins create `v*` refs, so the workflow's own
`GITHUB_TOKEN` cannot create the mirror tag from CI. Plain `vX.Y.Z` CLI
releases need no mirror.

## npm packages

CLI releases publish six npm packages from `release.yml`: the main
`security-harness-kit` package and one `security-harness-kit-<os>-<cpu>`
package per cargo-dist target (`darwin-arm64`, `darwin-x64`, `linux-arm64`,
`linux-x64`, `win32-x64`). The `win32-x64` package also installs on arm64,
where the launcher falls back to it. cargo-dist's own npm installer is not used, because
it downloads the binary at install time and ships an `npm-shrinkwrap.json` for
its runtime dependencies.

- `build-npm-packages.sh` runs in the `build installers` job. It checks every
  `shk-cli-<target>` archive against its `.sha256` file, takes the binary out
  of it, and packs it with `os` / `cpu` / `libc` fields. Each platform
  `package.json` records the archive and binary SHA-256 in `shkBinary`. The
  main package holds only the launcher (`packaging/npm/shk.js`) and pins every
  platform package to the release version in `optionalDependencies`.
- `verify-npm-packages.sh` then requires an exact file list for every tarball
  (so no shrinkwrap or lockfile can be added), no lifecycle scripts, no
  dependencies, and a binary that is byte-identical to the one in the release
  archive. The same check runs again on the tarballs fetched back from the
  registry in the `verify published CLI channels` job.
- `publish-npm-packages.sh` publishes the platform packages first and the main
  package last, after every platform package is visible on the registry. It
  skips versions that already exist, so a failed job can be rerun.
- The tarballs are also attached to the GitHub release and covered by the
  build provenance attestation.

The target list lives in `shk_npm_platforms` in
`.github/scripts/release/common.sh`; `test.sh` fails when it differs from
`targets` in `dist-workspace.toml`.

### One-time setup for a new platform package

Publishing uses npm trusted publishing (OIDC), which is configured per package
on npmjs.com and can only be configured for a package that already exists.
Before the first release that includes a new package name, a maintainer with
publish rights must:

1. Publish a placeholder version of that name by hand, for example `0.0.0`
   with only a `package.json` and a README, and deprecate it.
2. Open the package settings on npmjs.com and add a trusted publisher:
   repository `Kazuki-tam/security-harness-kit`, workflow `release.yml`, and
   the same environment setting as `security-harness-kit`.

Until this is done for all five platform packages, the `publish npm packages`
job fails on the first missing one and does not publish the main package.

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
   [CLI mirror](#combined-releases-and-the-cli-mirror) so the installers
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
