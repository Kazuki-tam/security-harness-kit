## Read before upgrading

### Projects may show managed hooks as outdated or missing

The project status no longer trusts the `_shk_managed` marker alone. A managed hook must run `shk scan … --hook-mode <tool>` as one plain command, so hand-edited commands (wrappers such as `sh -c` or `timeout 30 …`, `… || true`, `2>&1`) are shown as not installed. Claude Code projects whose hooks were installed by v0.7.7 or earlier are shown with outdated pre and post matchers. Apply the recommended fix, or run `shk hooks install-ai --tool claude-code`, and commit the result. ([#460](https://github.com/Kazuki-tam/security-harness-kit/pull/460), [#462](https://github.com/Kazuki-tam/security-harness-kit/pull/462))

The desktop app shares its scanning and masking with the CLI, so the detection and masking changes in the [CLI v0.8.0 release notes](https://github.com/Kazuki-tam/security-harness-kit/releases/tag/v0.8.0) apply here too. In particular, values written directly next to Japanese text are now found.

## Fixed

- Text from a repository could crash a label lookup into a reload loop. Each panel now has its own error boundary. ([#440](https://github.com/Kazuki-tam/security-harness-kit/pull/440))
- All blocked reasons are listed, including `policy_error` and `payload_too_large`. ([#440](https://github.com/Kazuki-tam/security-harness-kit/pull/440))
- A failed Office save keeps the mask result, and clone errors are shown inline. ([#440](https://github.com/Kazuki-tam/security-harness-kit/pull/440))
- Audit log reads no longer follow symlinks and are capped in size. ([#440](https://github.com/Kazuki-tam/security-harness-kit/pull/440))
- Updater signing variables can no longer be built into the frontend (Vite `envPrefix` narrowed to `VITE_` and `TAURI_ENV_`). ([#440](https://github.com/Kazuki-tam/security-harness-kit/pull/440))

## Changes

- **Dependencies:** updated Tauri plugins and frontend packages, and fixed the open RustSec advisories. ([#461](https://github.com/Kazuki-tam/security-harness-kit/pull/461), [#479](https://github.com/Kazuki-tam/security-harness-kit/pull/479))
