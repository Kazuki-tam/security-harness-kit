# security-harness-kit (`shk`)

![Overview illustration of shk scanning code, masking secrets, enforcing hooks, and producing safe reports](docs/assets/shk-overview.jpg)

`shk` is a local-first guardrail for AI-assisted development. It helps keep secrets, PII, and risky project surfaces out of AI tool context, Git commits, generated output, and everyday local workflows.

```bash
shk scan .
```

Example output:

```text
3 findings

HIGH  secret.openai_api_key  src/app.ts:12    Possible OpenAI API key detected
MED   pii.ja.phone           config/dev.ts:5  Japanese phone number detected
MED   pii.en.ssn             docs/test.md:8   US Social Security Number detected
```

## Why

AI coding agents can read project files, run commands, and transform sensitive input into new files. `shk` adds local checks around those workflows so teams can audit, mask, or block risky content before it leaves the intended boundary.

`shk` can:

- Scan project paths and Git-staged files for common secrets and PII.
- Mask sensitive content from stdin or files.
- Install Git pre-commit hooks.
- Install managed hooks for Claude Code, Cursor, and Codex.
- Generate a GitHub Actions workflow that runs `shk scan` on every pull request.
- Diagnose ignore file and `.env` safety coverage.
- Deploy AI agent skills to Claude Code, Codex, and Cursor project directories.

## Installation

macOS and Linux releases can be installed with the bundled installer:

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/Kazuki-tam/security-harness-kit/releases/latest/download/shk-cli-installer.sh | sh
```

Windows releases can be installed from PowerShell:

```powershell
powershell -c "irm https://github.com/Kazuki-tam/security-harness-kit/releases/latest/download/shk-cli-installer.ps1 | iex"
```

See [Installation](docs/installation.md) for release archives, checksums, Homebrew, source builds, and [uninstall](docs/installation.md#uninstall) instructions.

## Quick Start

Create a project policy file:

```bash
shk init
```

Scan the current project:

```bash
shk scan .
```

Output a machine-readable report:

```bash
shk scan . --json
```

Mask sensitive content from stdin:

```bash
shk mask < prompt.txt
```

Install a Git pre-commit hook:

```bash
shk hooks install
```

Install AI tool hooks in audit mode:

```bash
shk hooks install-ai --audit
```

Generate a GitHub Actions workflow that scans every pull request:

```bash
shk ci init github
```

Install the shk agent skill for Claude Code and Codex/Cursor:

```bash
shk skills install
```

Check ignore coverage:

```bash
shk doctor ignore
```

## Documentation

- [Installation](docs/installation.md)
- [Commands](docs/commands.md)
- [Configuration](docs/configuration.md)
- [Detection Model](docs/detection-model.md)
- [GitHub Actions Integration](docs/ci.md)

## Common Commands

```bash
shk init
shk init --strict

shk scan .
shk scan . --json
shk scan --staged

shk mask < prompt.txt
shk mask --json < prompt.txt

shk doctor
shk doctor ignore --fix
shk doctor env --dotenvx

shk hooks install
shk hooks install-ai --dry-run
shk hooks install-ai --audit

shk ci init github
shk ci init github --dry-run
shk ci init github --mode audit
shk ci init github --shk-version v0.2.3

shk skills install
shk skills install --tool claude-code --global
shk skills status
```

## Configuration

`shk` reads policy from `shk.toml` in the current working directory. Read-only commands can use built-in defaults. Commands that write files or tool configuration require a project policy file.

Create the default policy:

```bash
shk init
```

Create a stricter starter policy:

```bash
shk init --strict
```

See [Configuration](docs/configuration.md) for the full `shk.toml` reference, custom rules, and suppression options.

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No findings at or above the active threshold, or command completed successfully. |
| `1` | Scan findings met or exceeded the active threshold. |
| `2` | Blocking AI pre-hook triggered, or `shk scan --staged` was run outside a Git repository. |

## Safety Notes

- Scans and masking run locally.
- Built-in detection is pattern-based and includes hand-tuned `shk` rules plus generated gitleaks-derived `secret.gitleaks.*` rules; use it as an AI/local workflow guardrail, not as a complete replacement for dedicated secret scanning platforms.
- JSON reports use `redacted_value: "[REDACTED]"`.
- Hook audit logs contain metadata such as counts, tool name, hook phase, and display path.
- Allowlist `value_hash` entries are deterministic fingerprints for suppression, not cryptographic secret storage.
- Post-tool hooks are non-blocking.
- `doctor ignore --fix` appends missing patterns to `.gitignore`; it does not remove existing entries.
- `mask --output` requires `shk.toml` and refuses sensitive env files and protected home configuration files.

## Development

```bash
cargo build
cargo test --all
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
```

CI runs on macOS, Linux, and Windows.

## License

MIT. See [LICENSE](LICENSE).
