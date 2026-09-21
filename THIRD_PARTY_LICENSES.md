# Third-Party Licenses

## gitleaks default rules

`crates/shk-rules/src/gitleaks_rules.rs` contains generated rules adapted from the gitleaks default configuration:

- Project: https://github.com/gitleaks/gitleaks
- Source: https://raw.githubusercontent.com/gitleaks/gitleaks/8863af47d64c3681422523e36837957c74d4af4b/config/gitleaks.toml
- Source ref: 8863af47d64c3681422523e36837957c74d4af4b
- License: MIT

## glib safety backport

`vendor/glib/` contains glib 0.18.5 (MIT), copyright the gtk-rs contributors,
with the upstream VariantStrIter fix from gtk-rs/gtk-rs-core#1343.
The original license and copyright are preserved in `vendor/glib/LICENSE`
and `vendor/glib/COPYRIGHT`. See `vendor/README.md` and
`vendor/glib-provenance.json` for provenance and verification.
