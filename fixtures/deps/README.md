# `shk deps` test fixtures

Inputs for the tests of the experimental `shk deps` commands. Nothing here is
a real lockfile. Apart from `osv/real/`, nothing is a real advisory either:
package names start with `fx-`, advisory ids use the year `9999`, and URLs
point at `example.invalid`.

## `osv/synthetic/`

One OSV record per file, named `<id>.json` like the entries of the OSV
`all.zip` dump. Tests zip the directory in memory. The records follow two
shapes found in the real dump: the RustSec export (`informational` and
`categories` under `affected[].database_specific`, `SEMVER` ranges starting at
`0.0.0-0`, no `versions`) and the GitHub / OpenSSF export (ranges starting at
`0`, optional `versions`).

| Record | Case |
| --- | --- |
| `RUSTSEC-9999-0001`, `GHSA-fx01-0001-aaaa` | One group joined only through a shared CVE alias; only the RUSTSEC record has CVSS (v3.1) |
| `RUSTSEC-9999-0002`, `GHSA-fx02-0002-bbbb` | The representative has no summary, no `fixed` and no CVSS; the GHSA record supplies them (CVSS v4) |
| `RUSTSEC-9999-0003` | Several `introduced` events in one range, stored out of order (CVSS v3.0) |
| `RUSTSEC-9999-0004` | `last_affected`; no CVSS in the group; no `schema_version` |
| `RUSTSEC-9999-0005` | Two `SEMVER` ranges and a `GIT` range; CVSS base score 0.0 |
| `RUSTSEC-9999-0006` | `introduced` and `fixed` on the same version |
| `RUSTSEC-9999-0007` | Pre-release bounds |
| `GHSA-fx08-0008-dddd` | An `ECOSYSTEM` range that is not semver (`0.4`) plus an exact `versions` entry; CVSS vector that does not parse |
| `RUSTSEC-9999-0009` | `withdrawn` |
| `RUSTSEC-9999-0010` / `-0011` / `-0012` | `informational`: `unsound` / `unmaintained` / `notice` |
| `MAL-9999-0001` | Malicious package listed by exact `versions` |
| `RUSTSEC-9999-0013` | RustSec `malicious` category |
| `RUSTSEC-9999-0014` | `MAL-` alias |
| `GHSA-fx03-0003-cccc` | Several `affected[]` entries: two crates, one crate listed twice, and one entry for another ecosystem |
| `RUSTSEC-9999-0015` | Severity only under `affected[].severity` |
| `RUSTSEC-9999-0016` | Long multi-byte summary with control characters |
| `OSV-9999-0002`, `CVE-9999-0009` | A group with neither a RUSTSEC nor a GHSA record |
| `BROKEN-not-json` | An entry that is not valid JSON |

## `osv/real/`

Records copied byte for byte from the OSV crates.io dump
(`https://storage.googleapis.com/osv-vulnerabilities/crates.io/all.zip`,
downloaded 2026-11-28, 3,226 records). Do not edit them.

| Record | Case |
| --- | --- |
| `RUSTSEC-2020-0071`, `GHSA-wcg3-cvx6-7396` | `time`: one group; 8 `introduced` events in one RUSTSEC range; the GHSA record lists the crate twice and, unlike RUSTSEC, covers 0.2.0 |
| `RUSTSEC-2026-0543`, `RUSTSEC-2024-0370` | `unmaintained` (`chrono`, `proc-macro-error`) |
| `RUSTSEC-2024-0429`, `GHSA-wrw7-89jp-8q8g` | `glib`: no CVSS on the RUSTSEC record, CVSS v4 on the GHSA record |
| `RUSTSEC-2024-0393`, `GHSA-rm66-9gh4-4gp8` | Same, with a range starting at `0.0.0-0` / `0` |
| `RUSTSEC-2021-0109`, `GHSA-45p7-c959-rgcm`, `GHSA-cw98-cx2m-9qqg` | One RUSTSEC record joined to two GHSA records, one of them with CVSS |
| `MAL-2025-49350`, `RUSTSEC-2025-0154` | Malicious package reported by both OpenSSF (exact `versions`) and RustSec (`malicious` category); their shared GHSA alias is not in the dump |
| `RUSTSEC-2025-0158` | RustSec `malicious` category with no alias |
| `RUSTSEC-2025-0029`, `RUSTSEC-2022-0058` | `unsound`, `notice` |
| `GHSA-pq5v-rwp8-p7gm`, `RUSTSEC-2025-0131` | `last_affected` |
| `RUSTSEC-2020-0053` | `withdrawn` |
| `GHSA-gq4p-4hxv-5rg9` | `affected[]` for crates.io and PyPI |
| `GHSA-83hf-93m4-rgwq` | A `versions` entry that is not semver (`0.1`) |

Sources and licences: `RUSTSEC-*` records come from the
[RustSec Advisory Database](https://github.com/rustsec/advisory-db) (CC0-1.0,
as stated in each record), `GHSA-*` records from the
[GitHub Advisory Database](https://github.com/github/advisory-database)
(CC-BY-4.0) and `MAL-*` records from
[OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages)
(Apache-2.0), all as redistributed by [OSV](https://osv.dev).

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
| `real/` | Versions of the crates in `osv/real/`, including `time` 0.2.0 (GHSA only), 0.2.22 (both) and 0.2.23 (fixed) |
