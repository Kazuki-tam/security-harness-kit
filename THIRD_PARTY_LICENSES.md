# Third-Party Licenses

## gitleaks default rules

`crates/shk-rules/src/gitleaks_rules.rs` contains generated rules adapted from the gitleaks default configuration:

- Project: https://github.com/gitleaks/gitleaks
- Source: https://raw.githubusercontent.com/gitleaks/gitleaks/8863af47d64c3681422523e36837957c74d4af4b/config/gitleaks.toml
- Source ref: 8863af47d64c3681422523e36837957c74d4af4b
- License: MIT

## Advisory data for `shk deps`

`shk deps update` downloads the crates.io advisory dump published by
[OSV](https://osv.dev) (`https://storage.googleapis.com/osv-vulnerabilities/crates.io/all.zip`)
to the user's cache directory. The data is not bundled with `shk`.
`fixtures/deps/osv/real/` holds a small number of these records, unmodified,
as test fixtures. The records come from:

- [RustSec Advisory Database](https://github.com/rustsec/advisory-db) (`RUSTSEC-*`): CC0-1.0
- [GitHub Advisory Database](https://github.com/github/advisory-database) (`GHSA-*`): [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/), © GitHub, Inc.
- [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages) (`MAL-*`): [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0)

Finding messages quote an advisory's id and summary, and reports link to the
advisory on osv.dev.

## glib safety backport

`vendor/glib/` contains glib 0.18.5 (MIT), copyright the gtk-rs contributors,
with the upstream VariantStrIter fix from gtk-rs/gtk-rs-core#1343.
The original license and copyright are preserved in `vendor/glib/LICENSE`
and `vendor/glib/COPYRIGHT`. See `vendor/README.md` and
`vendor/glib-provenance.json` for provenance and verification.
