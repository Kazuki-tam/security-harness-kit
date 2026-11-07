## Read before applying the recommended fix

The desktop app now recommends "Refresh Claude Code managed hooks", selected by default, for projects whose managed hooks lack `"onFailure": "block"`. After you apply it, Claude Code blocks tool calls and prompts in that project when `shk` is missing, cannot start, or times out. ([#420](https://github.com/Kazuki-tam/security-harness-kit/pull/420))

If the project commits `.claude/settings.json`, this reaches everyone who uses it, including teammates, cloud sessions, and CI runners. Install `shk` in those environments before committing the change. Recovery steps are in the [CLI v0.7.7 release notes](https://github.com/Kazuki-tam/security-harness-kit/releases/tag/v0.7.7).

## Changes

- **Linux key store:** key access now uses a pure-Rust Secret Service backend, and error messages from the store use new wording. ([#419](https://github.com/Kazuki-tam/security-harness-kit/pull/419))
- **Dependencies:** updated Tauri plugins and frontend packages.

