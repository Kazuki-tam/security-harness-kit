---
name: release
description: >
  Run a shk release end to end: pre-flight checks, tag selection and push,
  workflow monitoring, post-release verification, the CLI mirror for combined
  tags, and follow-up PRs. Use when the user says "release vX.Y.Z", "ship the
  release", "tag a release", "publish the CLI/desktop", or asks how to release.
---

# release

Runbook for releasing the CLI, the desktop app, or both. The release pipeline
is `.github/workflows/release.yml`; maintainer docs live in
[docs/desktop-release.md](../../../docs/desktop-release.md).

## 1. Pre-flight (on a clean, up-to-date `main`)

The version bump must already be merged (use the `bump-version` skill).
Historical statements — e.g. the `desktop-v0.6.0` signing milestone in
README.md and docs/installation.md — carry a `<!-- shk-version-pin -->` marker
that bump-version respects; pin any new sentence that names a past release.

```bash
RELEASE_COMPONENT=<cli|desktop|both> RELEASE_VERSION=X.Y.Z \
  bash .github/scripts/release/verify-versions.sh
bash .github/scripts/release/test.sh
```

For desktop releases while Windows Authenticode is unconfigured, the repo
variable `SHK_ALLOW_UNSIGNED_WINDOWS=true` must exist
(`gh variable list`). Delete it once Authenticode signing lands.

## 2. Choose the tag

| Tag | Publishes | Latest? | Notes |
|-----|-----------|---------|-------|
| `vX.Y.Z` | CLI only | yes | URLs correct by construction |
| `desktop-vX.Y.Z` | desktop only | no | |
| `shk-vX.Y.Z` | CLI + desktop | yes | needs the CLI mirror (step 5); one failed desktop leg sinks the whole publish, CLI included |
| `cli-vX.Y.Z` | CLI only | yes | needs the CLI mirror (step 5); prefer `vX.Y.Z` |

When decoupling matters (e.g. desktop legs are risky), prefer separate
`vX.Y.Z` + `desktop-vX.Y.Z` pushes over `shk-vX.Y.Z`.

## 3. Tag and push

Tags are annotated, subject style `vX.Y.Z — <headline>`:

```bash
git tag -a <tag> -m "<tag> — <headline>"
git push origin <tag>
```

The push prints `Cannot create ref due to creations being restricted` — that
is ruleset bypass noise, not a failure. Verify with
`git ls-remote --tags origin <tag>`.

## 4. Watch the run and verify

```bash
gh run list --workflow=release.yml --limit 1
gh run watch <run-id> --exit-status
```

On failure: delete the tag remotely and locally
(`git push origin :refs/tags/<tag>`; `git tag -d <tag>`), fix on `main`,
re-tag, re-push. Nothing publishes until the `publish` job, so early failures
are safe to retry this way.

After a green run:

```bash
gh release view <tag> --json isDraft,assets
npm view security-harness-kit version dist-tags   # CLI releases
gh api repos/Kazuki-tam/homebrew-tap/contents/Formula/shk.rb --jq .content | base64 -d | head -20
```

Do NOT `curl` released assets to verify them — shk's own action guard blocks
external transfers. Use `gh release download` instead.

## 5. CLI mirror (only for `shk-v*` / `cli-v*` tags)

cargo-dist embeds `releases/download/vX.Y.Z/...` URLs in the installers,
Homebrew formula, and npm package regardless of the pushed tag, so combined
releases must mirror the CLI assets to a `vX.Y.Z` release:

```bash
./.github/scripts/release/mirror-cli-release.sh run shk-vX.Y.Z
```

The script handles tag creation, checksum verification, and the temporary
Release-workflow disable/re-enable (a `v*` tag push would otherwise re-trigger
the pipeline and fail on the duplicate npm publish). If it aborts, confirm the
workflow is re-enabled: `gh workflow enable release.yml`. Background in
[docs/desktop-release.md](../../../docs/desktop-release.md#combined-releases-and-the-cli-mirror).

## 6. Follow-ups

- PR bumping the CLI pin in **both** workflows to the new tag. This can only
  happen *after* the release ships (both download a released binary), and the
  PR touches `.github/workflows/`, so the maintainer must merge it from the
  GitHub web UI.
  - `.github/workflows/ci.yml` — `shk-version:` in the composite-action smoke
    step. Edit in place.
  - `.github/workflows/shk.yml` — `SHK_VERSION=` in the self-scan job. This
    file is **generated**, so regenerate it instead of hand-editing:
    `shk ci init github --force --shk-version vX.Y.Z --fail-on high`.
    It is not in `xtask bump-version`'s file list, so nothing else moves it —
    it had silently drifted to `v0.3.14` by the v0.6.3 release.
- A new CLI subcommand may only be enabled in ci.yml's smoke step after the
  release carrying it ships (same reason).
- Desktop releases: sanity-check `desktop-latest/latest.json` points at the new
  tag, and confirm the in-app updater offers the new version.
