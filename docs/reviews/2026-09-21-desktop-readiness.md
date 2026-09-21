# Desktop readiness review — 2026-09-21

## Decision

The fixes below pass the local automated gates, including 91.64% Rust line coverage.
Native macOS acceptance was expanded in the second review pass. This is not a certification that
all repository code is vulnerability-free or that release acceptance is complete.
The review concentrated on desktop masking/pseudonymization, external app launch,
input accessibility and first-use navigation. Broader CLI/core behavior was
covered by the existing test suite, not an exhaustive manual source audit.

## Review and correction rounds

1. **Async state and side effects:** Redaction could display an obsolete result or
   error after clearing/replacing input. An Office save dialog could continue
   writing the previous input after reset. Added generation checks before starting
   the write and before publishing results, synchronous duplicate-run guards and
   project/unmount invalidation. Pseudonymization now abandons pending key
   confirmations on reset/unmount, checks validity after each preparation await,
   and prevents duplicate execution. Already-started native writes are not
   cancelled by resetting the UI.
2. **External app URL boundary:** Directory names containing `&`, `=`, `+` or `%`
   were not encoded as query values. They could change the requested path or add
   parameters. Encode everything except URI unreserved characters. A regression
   test parses both supported deep links and verifies exactly one parameter with
   the original canonical path, including delimiters and Japanese characters.
3. **UI and accessibility:** A first-time user entering masking had no route back
   to welcome. Added a localized back button and verified navigation in the
   browser. Added an accessible input name/description, disabled spell checking
   and automatic correction for sensitive input, replaced incomplete tab roles
   with pressed buttons, and enforced the input lock for browser drops. The
   run/clear toolbar moved above the input so it remains visible at the minimum
   supported window size (980×640). Japanese
   introductory copy now asks users to review results instead of implying that
   every copied value is safe.
4. **Runtime error handling:** Browser preview crashed when native webview lookup
   threw synchronously, outside the existing promise rejection handler. Moved
   initialization into the handled promise chain. Verified the screen renders
   after the fix and added a regression test for unavailable native webviews.
5. **Dependency audit:** Updated `event-listener` 5.4.1 → 5.4.2, `plist`
   1.9.0 → 1.10.1 and `wayland-scanner` 0.31.10 → 0.31.11. This removes
   the old quick-xml 0.39.4 dependency (now 0.41.0 / 0.42.0). Removed the
   two blanket XML advisory exceptions from `.cargo/audit.toml` and `deny.toml`.
   The initial normal audit hid those two vulnerabilities; a second audit from
   outside the repository exposed them before remediation.
6. **Linux dependency safety:** Backported the exact two-line upstream
   `VariantStrIter` fix into a vendored glib 0.18.5, preserving its original version
   and license. The provenance manifest records the verified crates.io archive
   and all file hashes. CI rejects unrelated modifications, symlinks, reverted
   patches and registry fallback; six rejection tests pass. Added an optimized
   Linux iterator regression and made unsound advisories fail CI. Updated
   pdf-extract 0.12.0 → 0.12.1 too. CI's cargo-audit 0.22.1 still matches the local
   patched version, so its command excludes only RUSTSEC-2024-0429 immediately
   after re-verifying the exact backport. No global exception was added; other
   current/future glib advisories remain covered by this audit version.
7. **Release configuration:** Build-time validation now decodes the updater public
   key with the same Base64/Minisign parsers and whitespace normalization as the
   application. Missing values require an explicit non-distribution override;
   malformed values fail even with that override. Errors never echo the value.
   Three tests cover valid, absent, malformed and non-UTF-8 values. Corrected the
   previous misleading comment: an absent key breaks updates; it does not make
   the updater accept unsigned payloads.
8. **Accessible removal:** Native testing exposed a 2.5-second confirmation timer
   in the project list. Confirmation now persists while the menu remains open,
   and resets when reopened. The label explicitly says files are retained. A
   regression test waits a simulated minute and checks cancellation/reconfirmation.
9. **Re-review:** Inspected the final diff for stale success/error handling,
   abandoned confirmations, duplicate operations, unmount cleanup and query-value
   preservation. Re-ran the relevant gates after the changes.

## Validation

- `cargo test --all`: **1,049 passed; 3 ignored** (real 1Password integration tests).
- `cargo fmt --all -- --check`: passed.
- `bash ./.github/scripts/ci/rust-coverage.sh`: passed, **91.64% lines**.
- Release-script regression suite and six dependency-backport verifier tests: passed.
- `cargo clippy --all-targets --all-features -- -D warnings`: passed.
- `pnpm -C apps/shk-desktop test:run`: **168 passed**, including 10 new tests.
- Frontend `fmt:check`, `lint`, and `build` (TypeScript + Vite): passed.
- `pnpm -C apps/shk-desktop audit --prod`: no known vulnerabilities reported.
- `cargo-audit` 0.22.2 against the freshly fetched RustSec DB: **0 vulnerability
  entries, 0 unsound warnings, 0 ignores** locally. Seven unmaintained dependency warnings
  remain. The path-patched glib is protected by provenance verification plus the
  Linux optimized test; the audit count alone does not validate the backport.
  CI deliberately retains 0.22.1's name/version matching with the source-verified
  exception above, so future advisories on the vendored version remain visible.
- Browser: Japanese welcome → mask → welcome, mask input/output layout, and
  recovery from the unavailable-webview initialization path checked at 1280×720.
  At 980×640, confirmed the run/clear toolbar is visible and sample input enables
  the run button.
- Reviewed Tauri CSP/capabilities, masking output restrictions and atomic writes,
  clone argument construction, and frontend persistence sites. This sampling is
  not a complete security audit of those subsystems.

## Native macOS acceptance

Built the actual debug `.app` with Tauri and exercised native IPC using a dedicated
`/private/tmp` fixture project (no user project scanned or modified):

- Open-folder dialog, project registration and scan: two expected demo findings.
- Text masking, native clipboard copy and paste: `[REDACTED]` verified.
- Office file dialog, DOCX preview, save dialog and saved-path feedback.
- Reopened the resulting archive programmatically: document XML contains the
  redaction and no original demo email.
- Removed only the test project's list registration and cleared test input.

These checks cover the debug app on macOS, not signed distribution artifacts.

## Release acceptance still required

- Linux/Windows CI for this exact revision, especially the optimized glib test.
- Signed packaged application and updater acceptance with the release public key.
  Read-only GitHub metadata confirms Apple signing/notarization and updater secret
  names exist in the `release` Environment. Values were not read. Windows signing
  secret names were absent; `SHK_ALLOW_UNSIGNED_WINDOWS` exists as an environment
  variable, but its value was not read. Configuration presence is not acceptance.
- Actual OS key store / 1Password integration (three tests intentionally ignored).
  A dedicated test Vault name was requested; no private vault was accessed.
- Native drag/drop, external app launch, Windows/Linux interactive acceptance and
  assistive technology acceptance beyond accessibility-tree inspection.

Seven maintenance warnings remain for transitive `proc-macro-error` (GTK macros),
`ttf-parser` (PDF extraction), and five `unic-*` crates (Tauri URL patterns).
They are unmaintained notices, not currently reported vulnerability/unsoundness
entries. The repository's existing `unmaintained = "workspace"` policy remains
unchanged. Maintainers should revisit them on GTK/Tauri/PDF dependency updates;
new vulnerability/unsound advisories must block CI. Remove the glib backport when
GTK/Tauri accepts an unaffected published version.

The pre-existing untracked `docs/assets/shk-overview.png` was left untouched.
No application release or production installation was performed. The audit tool
was installed only under `/tmp/shk-review-tools` for this review.
