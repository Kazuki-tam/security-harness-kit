# Security Policy

## Supported Versions

Security fixes are applied to the latest release on the default branch. Older releases may receive backports at maintainer discretion.

| Version | Supported |
| ------- | --------- |
| latest  | yes       |
| older   | no        |

## Reporting a Vulnerability

**Do not open a public GitHub issue for undisclosed security vulnerabilities.**

Please report security issues only through
[GitHub private vulnerability reporting](https://github.com/Kazuki-tam/security-harness-kit/security/advisories/new).
Include a clear description, reproduction steps, and impact assessment.

## Supply Chain Expectations

Release assets are published with:

- Per-archive SHA256 checksums
- CycloneDX SBOM (`shk-sbom.cdx.json`)
- GitHub artifact attestations (verify with `gh attestation verify`)

For CI, pin `shk` to a specific release tag and verify checksums (or attestations) rather than installing from `latest` via `curl | sh`.

## Out of Scope

- Findings in third-party dependencies already tracked by RustSec / npm advisories unless they enable exploitation of `shk` itself
- Secret patterns missed by heuristic detection (documented limitation of pattern-based scanning)
