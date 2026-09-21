# Desktop readiness review — 2026-09-21

## Decision

The fixes below pass the local automated gates, including 91.68% Rust line coverage.
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
9. **Artifact verification and packaging:** Added
   `cargo run -p xtask -- verify-updater-artifacts <directory>` to both desktop
   release workflows. It verifies every detached signature against the exact
   release public key and payload, rejects missing signatures/orphan signatures,
   malformed encodings, mismatched keys, tampered payloads and symlinks. Five
   tests use only public Minisign example material; this module has 100% line
   coverage locally. Packaging now allows only expected payload/signature types,
   excluding Tauri helper scripts, icons and logs. A packaging regression also
   rejects symlinks. The unsigned-OS-signature workflow still requires valid
   updater signatures and verifies the glib backport too.
10. **Clipboard lifecycle re-review:** Late clipboard success/failure after a
    workspace reset could restore stale feedback or launch an AI app. Clipboard
    operations now retain a request generation, suppress stale notices and return
    false to callers after invalidation. Feedback timers cannot erase a newer
    copy's feedback. Seven regression cases cover current/stale success/failure,
    launch suppression, path copying and timer ordering. In-flight OS clipboard
    writes themselves cannot be cancelled; no raw original is sent by these
    copy actions.
11. **Re-review:** Inspected the final diff for stale success/error handling,
   abandoned confirmations, duplicate operations, unmount cleanup and query-value
   preservation. Re-ran the relevant gates after the changes.

## Validation

- `cargo test --all`: **1,054 passed; 3 ignored** (real 1Password integration tests).
- `cargo fmt --all -- --check`: passed.
- `bash ./.github/scripts/ci/rust-coverage.sh`: passed, **91.68% lines**.
- Release-script regression suite and six dependency-backport verifier tests: passed.
- `cargo clippy --all-targets --all-features -- -D warnings`: passed.
- `pnpm -C apps/shk-desktop test:run`: **175 passed**, including 17 new tests.
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

OS Keychain acceptance additionally passed in an isolated temporary project:
key creation, deterministic repeat masking, encrypted restore-map round trip,
rejection of a modified map with no output written, and deletion of only the
key created for that test. No existing key material was read or printed.

The signed ARM macOS artifact from the branch build was also downloaded into
`/tmp` and verified with `codesign --verify --deep --strict` and Gatekeeper
(`source=Notarized Developer ID`). Launched that signed app and verified real
text masking plus the production updater check returning "up to date". No
application update was installed and no release was published. This updater
check does not exercise installing a newer version. The copy-and-open ChatGPT
action also completed successfully, with the masked result copied and the
installed ChatGPT application observed running; no message was submitted.

## Remote validation and remaining acceptance

- [CI for c32a5b8](https://github.com/Kazuki-tam/security-harness-kit/actions/runs/35613435018):
  all jobs passed on Linux, macOS and Windows, including the optimized glib
  regression and the 90% first-party line-coverage gate. Vendored upstream code
  remains outside the first-party metric, as registry dependency code was before
  vendoring; the reviewed backport has separate provenance and regression gates.
- [Five-platform branch distribution build](https://github.com/Kazuki-tam/security-harness-kit/actions/runs/35612287987):
  all builds passed, including macOS ARM/Intel signature and notarization checks.
  Windows Authenticode is absent under the existing explicit
  `SHK_ALLOW_UNSIGNED_WINDOWS=true` release Environment policy; updater signing
  remains required. No Environment setting or credential was changed.
- [CI for 988c012](https://github.com/Kazuki-tam/security-harness-kit/actions/runs/35614270074):
  all jobs passed. The
  [artifact verification build](https://github.com/Kazuki-tam/security-harness-kit/actions/runs/35614381735)
  adds verification that updater signatures match the configured public key on
  all five targets. Its first attempt failed on Windows (the WiX toolset
  download returned HTTP 504) and Linux x86_64 (linuxdeploy could not fetch its
  helpers); both are external download outages during bundling, before any
  project code ran. Re-running exactly those jobs on the same commit passed, so
  all five targets have now passed the signature verification.
- [CI for b1d6364](https://github.com/Kazuki-tam/security-harness-kit/actions/runs/35616562942)
  (clipboard lifecycle fix): the `coverage` job's first attempt failed while
  `apt-get update` fetched the Microsoft package index (HTTP 403), before the
  repository was built; it was re-run on the same commit. See the pull request
  checks for the final state.
- Real 1Password tests were attempted against the pre-existing dedicated
  `shk-integration-test` Vault after a successful metadata-only availability
  check. **All three failed because item operations timed out waiting for
  authorization**, including the `op` error `authorization timeout`. This is
  not a passing integration result. The user was asked to authorize the CLI and
  request a retry; no account settings or access controls were changed.
- Native drag/drop and project-directory deep links still need interactive
  acceptance beyond the focused code/regression checks. AI application launch
  was exercised on macOS as described above. Windows/Linux native
  interactive flows and assistive-technology behavior were not exercised;
  automated builds/tests cover those platforms, while native interaction was
  tested on macOS.
- PR #301 had no review comments at the time of this review; GitHub reported
  `REVIEW_REQUIRED`. No release was published.

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

## Final validation update — 2026-09-22 JST

- Application commit `b1d6364` passed [all CI jobs](https://github.com/Kazuki-tam/security-harness-kit/actions/runs/35616562942)
  and [all five distribution builds](https://github.com/Kazuki-tam/security-harness-kit/actions/runs/35616752191).
  Real updater signatures match the release public key on every target; macOS
  ARM/Intel signing and notarization passed. Publish jobs were skipped.
- Local gates: 1,054 Rust tests, 175 frontend tests, formatting, lint/clippy,
  frontend build, and 91.68% Rust line coverage passed. The three optional real
  1Password tests are separately recorded as authorization failures above.
- Commit `a240d45` changes only the two Python backport verification/test files.
  Application source is identical to `b1d6364`. All eight verifier tests pass
  locally, including rejection of a redirected/removed Cargo patch with an
  unchanged lockfile. Its [CI run](https://github.com/Kazuki-tam/security-harness-kit/actions/runs/35618116070)
  is still running at this update.
- An automatic approval review initially rejected this last push because its
  destination was unverified. Read-only checks confirmed the origin matches
  the existing public repository and PR; re-review approved the same operation.
  The two-file change was pushed successfully. No approval bypass was used.
- Unconditional production sign-off remains **on hold**: real 1Password item
  operations need user authorization and a successful retry. The native
  platform/assistive-technology acceptance limits above remain explicit.
