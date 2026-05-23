# Desktop Release

The desktop app is released from tags matching `desktop-vX.Y.Z` or `shk-vX.Y.Z`.
macOS production releases require Developer ID signing and notarization. Windows
production releases require Authenticode code signing. All desktop releases also
require Tauri updater signing.

For OSS production repositories, prefer storing signing secrets in a protected
GitHub environment such as `release` with required reviewers instead of exposing
them broadly at repository scope.

## Required GitHub Secrets

All desktop releases require:

- `TAURI_UPDATER_PUBKEY`
- `TAURI_SIGNING_PRIVATE_KEY`
- `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` when the private key is encrypted

macOS releases also require:

- `APPLE_CERTIFICATE` base64-encoded Developer ID Application `.p12`
- `APPLE_CERTIFICATE_PASSWORD`
- `APPLE_SIGNING_IDENTITY`, for example
  `Developer ID Application: Example, Inc. (TEAMID)`
- `KEYCHAIN_PASSWORD`
- `APPLE_ID`
- `APPLE_PASSWORD`, an app-specific password
- `APPLE_TEAM_ID`

Windows releases require one of the following signing configurations.
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

## Release Gates

The macOS release jobs fail unless Developer ID signing and notarization are
configured. After bundling, the workflow verifies `.dmg` artifacts and extracted
`.app` bundles from updater archives with `codesign`, `spctl`, and
`xcrun stapler validate`.

The Windows release job fails unless Authenticode signing is configured. After
bundling, the workflow verifies every generated `.exe` and `.msi` with
`Get-AuthenticodeSignature` and fails the release when any signature is invalid.

Pull request CI runs a Windows desktop `tauri build --no-bundle` smoke test.
Signed installer bundling remains release-only because it needs production
signing secrets.

## Release Checklist

1. Update `Cargo.toml`, `apps/shk-desktop/package.json`, and
   `apps/shk-desktop/src-tauri/tauri.conf.json` to the same version.
2. Confirm the `release` GitHub environment has the updater signing secrets,
   macOS Developer ID/notarization secrets, and one Windows Authenticode signing
   mode configured.
3. Run `.github/scripts/release/test.sh` locally or rely on the CI
   `release-scripts` job.
4. Push `desktop-vX.Y.Z` for a desktop-only release, or `shk-vX.Y.Z` for a
   combined CLI and desktop release.
5. After publishing, verify the GitHub release assets, `shk-desktop.sha256sum`,
   `shk-desktop-latest.json`, and the `desktop-latest` updater metadata.
