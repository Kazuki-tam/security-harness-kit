# CLI Release

Maintainer notes for releasing the `shk` CLI. The pipeline is
`.github/workflows/release.yml`; desktop signing, notarization, and the
updater are covered in [Desktop Release](desktop-release.md).

## Tags and channels

| Tag | Publishes |
| --- | --- |
| `vX.Y.Z` | CLI only |
| `cli-vX.Y.Z` | CLI only; needs the [CLI mirror](#combined-releases-and-the-cli-mirror) |
| `shk-vX.Y.Z` | CLI and desktop together; needs the CLI mirror |

A CLI release publishes:

- the GitHub release with the `shk-cli-<target>` archives, their `.sha256`
  files, the shell and PowerShell installers, the npm tarballs, an SBOM, and
  build provenance attestations
- the Homebrew formula, pushed to `Kazuki-tam/homebrew-tap` with the
  `HOMEBREW_TAP_TOKEN` secret (a personal access token that expires; check it
  before tagging)
- the [npm packages](#npm-packages), published with npm trusted publishing
- WinGet manifests as a release asset for maintainers to submit

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
   with only a `package.json` and a README, and deprecate it. npm lists a new
   package as `0.0.0-stage` for a few minutes before `0.0.0` appears, and
   `npm deprecate` fails with "No version found" until it does; retry then.
2. Shortly before the release, open the package settings on npmjs.com and add
   a trusted publisher for GitHub Actions:

   | Field | Value |
   | --- | --- |
   | Organization or user | `Kazuki-tam` |
   | Repository | `security-harness-kit` |
   | Workflow filename | `release.yml` |
   | Environment name | same as `security-harness-kit` (empty) |
   | Allowed actions | **Allow npm publish** (the workflow runs `npm publish`; `npm dist-tag` is not needed) |

   All fields are case-sensitive, npm does not check them when saving, and a
   saved configuration cannot be edited, only deleted and created again.

A new trusted publisher configuration **expires after 2 days** unless a
publish through it succeeds in that time. Create it on the day of the release
or the day before. If it has expired, delete it and create it again; the
package name and placeholder stay. Once the first release has published
through it, the configuration is permanent.

The five current platform packages were reserved with a deprecated `0.0.0`
placeholder on 2026-11-15. Their trusted publisher configurations still have
to be valid when the first release that publishes them runs.

Until every platform package has a valid trusted publisher, the
`publish npm packages` job fails on the first one without it and does not
publish the main package. Fix the configuration and rerun the job; it skips
what is already published.

Setting "Require two-factor authentication and disallow tokens" under
Publishing access is recommended for all six packages. It does not affect
trusted publishing.

## Release Checklist

1. Update versions with `cargo run -p xtask -- bump-version X.Y.Z`. When the
   release changes behavior for existing users, add
   `docs/release-notes/vX.Y.Z.md`; the publish job puts it above the generated
   release body.
2. Run `.github/scripts/release/test.sh` locally or rely on the CI
   `release-scripts` job.
3. Confirm on npmjs.com that every platform package has a valid trusted
   publisher (see [npm packages](#npm-packages)), and that
   `HOMEBREW_TAP_TOKEN` has not expired.
4. Push `vX.Y.Z` for a CLI-only release, or `shk-vX.Y.Z` for a combined CLI
   and desktop release.
5. After the run, check the GitHub release assets, the Homebrew formula, and
   `npm view security-harness-kit version`. The `verify published CLI channels`
   job checks all three.
6. For `shk-vX.Y.Z` or `cli-vX.Y.Z`, run the
   [CLI mirror](#combined-releases-and-the-cli-mirror) and rerun the failed
   verification job.
