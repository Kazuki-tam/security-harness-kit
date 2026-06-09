# security-harness-kit (`shk`)

![Overview illustration of shk scanning code, masking secrets, enforcing hooks, and producing safe reports](docs/assets/shk-overview.jpg)

`shk` is a local-first guardrail for AI-assisted development. It helps keep secrets, PII, and risky project surfaces out of AI tool context, Git commits, generated output, and everyday local workflows. It can also encrypt `.env` files and inject decrypted values only when running local commands.

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

With `shk`, you can:

- Scan project paths and Git-staged files for common secrets and PII across source code, Markdown, plain text, Office documents (`.docx`, `.xlsx`, `.pptx`), and text-layer `.pdf` files.
- Mask sensitive content from stdin, text files, and Office documents (`.docx`, `.xlsx`, `.pptx`).
- Encrypt `.env` files, store private keys in the OS credential store, and run commands with decrypted values injected only at runtime.
- Install Git pre-commit hooks.
- Install managed hooks for Claude Code, Cursor, and Codex.
- Preview metadata-only audit logs to understand blocked hook activity without storing detected values.
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
powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://github.com/Kazuki-tam/security-harness-kit/releases/latest/download/shk-cli-installer.ps1 | iex"
```

The `ExecutionPolicy Bypass` flag applies only to that PowerShell process and does not change the user's system policy.
If downloaded PowerShell scripts are managed by your organization and still blocked, use the manual `.zip` install in [Installation](docs/installation.md#manual-windows-zip-install).

After the package is accepted into the Windows Package Manager community repository, Windows users can also install with:

```powershell
winget install Kazuki-tam.shk
```

macOS and Linux users can also install via Homebrew:

```bash
brew install Kazuki-tam/homebrew-tap/shk
```

See [Installation](docs/installation.md) for release archives, checksums, WinGet manifests, Homebrew, source builds, and [uninstall](docs/installation.md#uninstall) instructions.

For CI or security-sensitive environments, prefer a pinned release archive with checksum and GitHub artifact attestation verification over installing from `latest`. See [Verified Archive Install](docs/installation.md#verified-archive-install).

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

Encrypt a `.env` file and run a command with decrypted values:

```bash
shk env encrypt .env --in-place
shk env run -- npm test
```

Install a Git pre-commit hook:

```bash
shk hooks install
```

Install AI tool hooks in audit mode:

```bash
shk hooks install-ai --audit
```

Install AI tool hooks that still block but keep metadata-only block logs:

```bash
shk hooks install-ai --log-blocked
shk audit
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
shk init --yes --no-npm-hardening

shk scan .
shk scan . --json
shk scan --staged
shk scan --git-history
shk scan --git-history --preview
shk scan --git-history --ref HEAD~50..HEAD

shk mask < prompt.txt
shk mask --json < prompt.txt
shk mask report.docx --output report.redacted.docx

shk doctor
shk doctor ignore --fix
shk doctor env --dotenvx
shk doctor workflows --fix

shk audit
shk audit --reason action-guard
shk audit --since 7d --tool cursor
shk audit --json

shk env dotenvx import-keys .env.keys
shk env encrypt .env --in-place
shk env run -- npm test
shk env key import
shk env key list
shk env key delete --env staging
shk env key export --instructions
shk env decrypt .env --output .env.local

shk hooks install
shk hooks install-ai --dry-run
shk hooks install-ai --audit
shk hooks install-ai --log-blocked

shk ci init github
shk ci init github --dry-run
shk ci init github --mode audit
shk ci init github --shk-version v0.3.15

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

When `package.json` is present, `shk init` can also apply package-manager supply-chain hardening such as `ignore-scripts=true`, npm `min-release-age=7`, and equivalent pnpm/Yarn/Bun age gates. Use `--no-npm-hardening` to skip that setup in automated runs.

See [Configuration](docs/configuration.md) for the full `shk.toml` reference, custom rules, and suppression options.

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No findings at or above the active threshold, or command completed successfully. |
| `1` | Scan findings met or exceeded the active threshold. |
| `2` | Blocking AI pre-hook triggered, or a Git-specific scan mode was run outside a Git repository. |

## Safety Notes

- Scans and masking run locally.
- Document scanning extracts text from Office documents and text-layer PDFs. Image-only PDFs require OCR outside `shk`; when no text can be extracted, scan reports an informational skip finding.
- Office document masking writes a new `.docx`, `.xlsx`, or `.pptx` file and requires `--output`.
- `shk scan --git-history` scans committed blobs reachable from Git refs. Use `--preview` to inspect candidate counts before a broad history scan, and `--ref`, `--since`, or `--max-commits` to narrow the scope.
- Built-in detection is pattern-based and includes hand-tuned `shk` rules plus generated gitleaks-derived `secret.gitleaks.*` rules; use it as an AI/local workflow guardrail, not as a complete replacement for dedicated secret scanning platforms.
- JSON reports use `redacted_value: "[REDACTED]"`.
- Hook audit logs contain metadata such as counts, tool name, hook phase, rule IDs, action categories, and display path; they do not store raw matched values, prompt bodies, or command text.
- Use `shk audit` to summarize `.shk/audit.log`; add `--no-paths` when path labels should not be printed.
- Allowlist `value_hash` entries are deterministic fingerprints for suppression, not cryptographic secret storage.
- Post-tool hooks are non-blocking.
- `doctor ignore --fix` appends missing patterns to `.gitignore`; it does not remove existing entries.
- `doctor workflows` flags `actions/checkout` steps missing `persist-credentials: false`; `--fix` requires `shk.toml` and edits flagged workflows in place.
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
