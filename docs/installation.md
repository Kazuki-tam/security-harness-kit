# Installation

`shk` is distributed as a single CLI binary. The `shk` and `security-harness-kit` binaries expose the same CLI.

## Install With Script

macOS and Linux releases can be installed with the bundled installer:

```bash
curl -fsSL https://raw.githubusercontent.com/Kazuki-tam/security-harness-kit/main/scripts/install.sh | sh
```

The installer downloads the latest matching release archive, verifies it against `SHA256SUMS`, and installs both `shk` and `security-harness-kit`.

To uninstall installed binaries:

```bash
curl -fsSL https://raw.githubusercontent.com/Kazuki-tam/security-harness-kit/main/scripts/uninstall.sh | sh
```

## Download A Release Archive

Tagged releases publish platform archives and a `SHA256SUMS` manifest:

```text
shk-aarch64-unknown-linux-gnu.tar.gz
shk-aarch64-apple-darwin.tar.gz
shk-x86_64-pc-windows-msvc.zip
shk-x86_64-unknown-linux-gnu.tar.gz
shk-sbom.cdx.json
shk.json
shk.rb
SHA256SUMS
*.bundle
```

Verify the archive before unpacking:

```bash
shasum -a 256 -c SHA256SUMS
```

Each archive contains both `shk` and `security-harness-kit`.

Release assets are signed with `cosign` keyless signing. Verify a downloaded asset with its matching bundle:

```bash
cosign verify-blob \
  --bundle shk-x86_64-unknown-linux-gnu.tar.gz.bundle \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp 'https://github.com/Kazuki-tam/security-harness-kit/.github/workflows/release.yml@refs/tags/v.*' \
  shk-x86_64-unknown-linux-gnu.tar.gz
```

Releases also publish a CycloneDX SBOM (`shk-sbom.cdx.json`). Tagged releases generate GitHub artifact attestations for release assets.

## Scoop

Windows releases include a generated Scoop manifest (`shk.json`) as a release asset. To install from the latest release asset:

```powershell
scoop install https://github.com/Kazuki-tam/security-harness-kit/releases/latest/download/shk.json
```

To install a pinned release, replace `latest/download` with `download/v0.1.5`. For long-term distribution, copy the generated `shk.json` into a Scoop bucket repository. The generated manifest includes `checkver` and `autoupdate` metadata for bucket-based updates.

## Homebrew

macOS and Linux releases include a generated Homebrew formula (`shk.rb`) as a release asset. To install from the latest release asset:

```bash
brew install --formula https://github.com/Kazuki-tam/security-harness-kit/releases/latest/download/shk.rb
```

To install a pinned release, replace `latest/download` with `download/v0.1.5`. For long-term distribution, copy the generated `shk.rb` into a Homebrew tap repository.

Intel macOS (`x86_64-apple-darwin`) release artifacts are not published. Apple Silicon macOS, Linux x86_64/aarch64, and Windows x86_64 are supported.

## Build From Source

Building from source requires Rust 1.85 or newer.

```bash
git clone https://github.com/Kazuki-tam/security-harness-kit.git
cd security-harness-kit
cargo build --release
```

The release binaries are written to:

```text
target/release/shk
target/release/security-harness-kit
```

