# `shk deps` test fixtures

Inputs for the tests of the experimental `shk deps` commands. Nothing here is
a real advisory or a real lockfile: package names start with `fx-`, advisory
ids use the year `9999`, and URLs point at `example.invalid`.

## `osv/synthetic/`

One OSV record per file, named `<id>.json` like the entries of the OSV
`all.zip` dump. Tests zip the directory in memory. The records follow two
shapes: the RustSec export (no `schema_version`, `informational` and
`categories` under `affected[].database_specific`, `SEMVER` ranges starting at
`0.0.0-0`) and the GitHub / OpenSSF export (`schema_version`, `ECOSYSTEM`
ranges starting at `0`).

| Record | Case |
| --- | --- |
| `RUSTSEC-9999-0001`, `GHSA-fx01-0001-aaaa` | One group joined only through a shared CVE alias; only the RUSTSEC record has CVSS (v3.1) |
| `RUSTSEC-9999-0002`, `GHSA-fx02-0002-bbbb` | The representative has no summary, no `fixed` and no CVSS; the GHSA record supplies them (CVSS v4) |
| `RUSTSEC-9999-0003` | Several `introduced` events in one range, stored out of order (CVSS v3.0) |
| `RUSTSEC-9999-0004` | `last_affected`; no CVSS in the group |
| `RUSTSEC-9999-0005` | Two `SEMVER` ranges and a `GIT` range; CVSS base score 0.0 |
| `RUSTSEC-9999-0006` | `introduced` and `fixed` on the same version |
| `RUSTSEC-9999-0007` | Pre-release bounds |
| `RUSTSEC-9999-0008` | A range that is not semver plus an exact `versions` entry; CVSS vector that does not parse |
| `RUSTSEC-9999-0009` | `withdrawn` |
| `RUSTSEC-9999-0010` / `-0011` / `-0012` | `informational`: `unsound` / `unmaintained` / `notice` |
| `MAL-9999-0001` | Malicious package listed by exact `versions` |
| `RUSTSEC-9999-0013` | RustSec `malicious` category |
| `RUSTSEC-9999-0014` | `MAL-` alias |
| `GHSA-fx03-0003-cccc` | Several `affected[]` entries, one for another ecosystem |
| `RUSTSEC-9999-0015` | Severity only under `affected[].severity` |
| `RUSTSEC-9999-0016` | Long multi-byte summary with control characters |
| `OSV-9999-0002`, `CVE-9999-0009` | A group with neither a RUSTSEC nor a GHSA record |
| `BROKEN-not-json` | An entry that is not valid JSON |

## `lockfiles/`

Each directory holds one `Cargo.lock`.

| Directory | Case |
| --- | --- |
| `affected/` | Every package matches a record above, except `fx-app` (local) and `fx-withdrawn` |
| `unaffected/` | Versions just outside each range, and a package with no record |
| `sources/` | crates.io (registry and sparse), git, another registry and local packages, including local and git packages that share a name with an affected crate |
| `v3/`, `no-version/` | Lockfile versions read like version 4 |
| `unsupported-version/`, `invalid-toml/` | Lockfiles that cannot be audited |
| `empty/` | No packages |

Excerpts of real advisories are not included yet; they are added once the
record shapes above have been checked against a real dump.
