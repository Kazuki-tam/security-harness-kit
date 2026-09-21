# Reviewed dependency backports

## glib 0.18.5

GTK3 in Tauri 2 requires glib 0.18. The published release contains
[RUSTSEC-2024-0429](https://rustsec.org/advisories/RUSTSEC-2024-0429.html).
The copy in `glib/` contains only the two-line fix approved upstream in
[gtk-rs-core#1343](https://github.com/gtk-rs/gtk-rs-core/pull/1343): the pointer
passed to the C out-parameter is mutable, and is passed by mutable reference.
No package version is changed to hide the advisory.

`glib-provenance.json` records the crates.io archive SHA-256, every original
file hash and the patched file hash. The original archive was verified before
extraction. `python3 .github/scripts/ci/verify-glib-patch.py` checks the complete
vendored tree and proves that reversing exactly those two edits recovers the
published source file. CI also exercises string iteration in optimized Linux
builds, where the original undefined behavior is reproducible.

CI uses cargo-audit 0.22.1, which also matches path dependencies by name/version.
Only after re-verifying this source, the audit command excludes the already-fixed
RUSTSEC-2024-0429. There is no global advisory exception. Other glib advisories and
all other unsound advisories still fail the audit. When updating cargo-audit,
preserve audit coverage of the upstream glib version: 0.22.2 skips path sources.

Keep the upstream MIT license and copyright. Do not edit other files here or
add blanket advisory ignores. Remove the patch, provenance and regression gate
when the GTK/Tauri dependency line can use an unaffected published glib.
