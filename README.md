# security-harness-kit (`shk`)

An AI-agent security harness that detects, masks, and blocks sensitive data before it reaches AI tools, Git commits, or unsafe project surfaces.

```
shk scan .
```

```
4 findings

HIGH  secret.openai_api_key  src/app.ts:12    Possible OpenAI API key detected
MED   pii.ja.phone           config/dev.ts:5  Japanese phone number detected
MED   pii.en.ssn             docs/test.md:8   US Social Security Number detected
LOW   ignore.missing_env     .gitignore        Missing .env pattern
```

## Why

AI coding agents (Claude Code, Cursor, Codex, and others) read your project files and execute shell commands. Without guardrails, they silently ingest `.env` files, private keys, personal information, and other sensitive data — and pass it to external APIs.

`shk` sits between your project and your AI tools:

- **Detect** secrets and PII before AI agents read them
- **Mask** sensitive data before passing content to AI tools
- **Block** risky Git commits before they happen
- **Diagnose** ignore file coverage across Git and AI tools

`shk` is local-first with no telemetry, no cloud dependency, and no required configuration.

## Installation

### Install with script

macOS and Linux releases can be installed with the bundled installer:

```bash
curl -fsSL https://raw.githubusercontent.com/Kazuki-tam/security-harness-kit/main/scripts/install.sh | sh
```

Optional environment variables:

```bash
SHK_VERSION=v0.1.0 SHK_INSTALL_DIR="$HOME/.local/bin" sh scripts/install.sh
```

The installer downloads the matching release archive, verifies it against `SHA256SUMS`, and installs both `shk` and `security-harness-kit`.

Uninstall installed binaries:

```bash
curl -fsSL https://raw.githubusercontent.com/Kazuki-tam/security-harness-kit/main/scripts/uninstall.sh | sh
```

For custom install locations, pass the same directory used during install:

```bash
SHK_INSTALL_DIR="$HOME/.local/bin" sh scripts/uninstall.sh
```

### Download a release archive

Tagged releases publish platform archives and a `SHA256SUMS` manifest:

```text
shk-aarch64-unknown-linux-gnu.tar.gz
shk-aarch64-apple-darwin.tar.gz
shk-x86_64-pc-windows-msvc.zip
shk-x86_64-unknown-linux-gnu.tar.gz
shk-sbom.cdx.json
shk.json
shk.rb
SHA256SUMS
*.bundle
```

Verify the archive before unpacking:

```bash
shasum -a 256 -c SHA256SUMS
```

Each archive contains both `shk` and `security-harness-kit`.

Release assets are signed with `cosign` keyless signing. Verify a downloaded asset with its matching bundle:

```bash
cosign verify-blob \
  --bundle shk-x86_64-unknown-linux-gnu.tar.gz.bundle \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp 'https://github.com/Kazuki-tam/security-harness-kit/.github/workflows/release.yml@refs/tags/v.*' \
  shk-x86_64-unknown-linux-gnu.tar.gz
```

Releases also publish a CycloneDX SBOM (`shk-sbom.cdx.json`). Tagged releases generate GitHub artifact attestations for the release assets so provenance can be verified through GitHub's attestation tooling.

### Scoop

Windows releases include a generated Scoop manifest (`shk.json`) as a release asset. To test a release manifest locally:

```powershell
scoop install https://github.com/Kazuki-tam/security-harness-kit/releases/download/v0.1.0/shk.json
```

For long-term distribution, copy the generated `shk.json` into a Scoop bucket repository.

### Homebrew

macOS/Linux releases include a generated Homebrew formula (`shk.rb`) as a release asset. To test a release formula locally:

```bash
brew install --formula https://github.com/Kazuki-tam/security-harness-kit/releases/download/v0.1.0/shk.rb
```

For long-term distribution, copy the generated `shk.rb` into a Homebrew tap repository.

Note: Intel macOS (`x86_64-apple-darwin`) release artifacts are not published. Apple Silicon macOS, Linux x86_64/aarch64, and Windows x86_64 are supported.

### Build from source

Requires Rust 1.85+.

```bash
cd security-harness-kit
cargo build --release
# Binaries: target/release/shk  target/release/security-harness-kit
```

Both `shk` and `security-harness-kit` resolve to the same CLI.

Homebrew, npm wrappers, macOS notarization, and Windows Authenticode signing are planned next.

## Quick start

```bash
# Create a project policy file first
shk init

# Scan the current project
shk scan .

# Output machine-readable JSON
shk scan . --json

# Mask sensitive content from stdin before sending to an AI tool
cat prompt.txt | shk mask

# Install Git pre-commit hook (blocks commits containing secrets)
shk hooks install

# Install AI tool hooks (audit mode first — recommended)
shk hooks install-ai --audit

# Check ignore file coverage
shk doctor ignore
```

## Commands

### `shk scan`

Scan a repository or path for secrets, PII, and unsafe patterns.

```bash
shk scan                        # scan current directory
shk scan ./src                  # scan a specific path
shk scan . --json               # structured JSON output
shk scan . --fail-on medium     # fail on medium severity or above
shk scan . --include-binary     # opt into scanning binary-looking files
shk scan . --follow-symlinks    # opt into symlink traversal
shk scan . --no-color           # disable colored human output
shk scan --staged               # scan only Git-staged files (pre-commit)
shk scan . --hook-mode cursor --audit < payload.json
```

Exit codes:

| Code | Meaning |
|------|---------|
| `0` | No findings above threshold |
| `1` | Findings at or above the fail threshold |
| `2` | Blocking AI pre-hook triggered |

In hook mode, `--audit` always exits `0` and appends metadata-only findings to `.shk/audit.log`. Because this writes project metadata, it requires `shk.toml`; run `shk init` first.

### `shk mask`

Redact sensitive values from stdin or a file before they reach an AI tool.

```bash
shk mask < prompt.txt               # mask stdin
shk mask prompt.txt                 # mask a file
shk mask prompt.txt --output out.txt
shk mask --json < prompt.txt        # JSON output with findings + masked content
shk mask --redaction partial < prompt.txt
shk mask --hook-mode cursor < payload.json
```

Masking is line-oriented by default: any line with a match becomes `[REDACTED_LINE]`. `--redaction partial` masks only matched values and preserves the configured prefix/suffix (`preserve_prefix` / `preserve_suffix`, default `4` each).

`mask --output` writes a file, so it requires a project `shk.toml` and refuses sensitive env files (`.env`, `.env.*`) and protected home configuration files such as `.zshrc`, `.bashrc`, `.profile`, `.ssh/config`, `.gitconfig`, and `.npmrc`.

### `shk doctor`

Run all project security diagnostics.

```bash
shk doctor           # full diagnostic report
shk doctor --json

shk doctor ignore                   # check ignore file coverage
shk doctor ignore ./path --fix      # append missing patterns to ignore files

shk doctor version                  # check latest GitHub release
shk doctor --json version

shk doctor env                      # check .env file safety
shk doctor env --dotenvx            # also inspect dotenvx artifact files
```

`doctor version` compares the installed CLI version with the latest GitHub release and reports whether an update is available. It does not modify the installed binary; rerun the install script or use your package manager to upgrade.

`doctor ignore` checks ignore-style files such as `.gitignore`, `.cursorignore`, `.clineignore`, `.aiderignore`, `.continueignore`, `.codeiumignore`, `.tabnineignore`, `.ignore`, and `.aiignore`. It also inspects Claude Code `permissions.deny` entries in `.claude/settings.json` and Codex `.codex/config.toml` sandbox/hook settings. `--fix` requires `shk.toml` and appends missing patterns conservatively to `.gitignore` without removing existing entries.

`doctor env --dotenvx` reports known dotenvx artifacts such as `.env.vault` and warns when `.env.keys` is present in the project because it may contain private key material.

### `shk hooks install`

Install a Git pre-commit hook that runs `shk scan --staged` before every commit.

```bash
shk hooks install
```

The hook uses managed markers (`# shk-managed-start` / `# shk-managed-end`) and is idempotent — re-running is safe. Installing hooks writes project files and requires `shk.toml`; run `shk init` first.

### `shk hooks install-ai`

Install `shk` as a security hook inside AI tool configurations.

```bash
shk hooks install-ai                        # write project hooks for supported tools
shk hooks install-ai --dry-run              # preview changes without applying
shk hooks install-ai --audit               # log-only mode (never blocks)
shk hooks install-ai --tool claude-code    # limit to one tool
shk hooks install-ai --global              # write to user-level config instead of project
shk hooks install-ai --tool cursor --fail-closed
```

**Recommended adoption sequence:**

```bash
# Step 1 — audit mode: hooks run but never block
shk hooks install-ai --audit

# Step 2 — review .shk/audit.log, add allowlist entries to shk.toml if needed

# Step 3 — upgrade to blocking mode
shk hooks install-ai
```

Supported tools: `claude-code`, `cursor`, `codex`.

#### What gets installed

**Claude Code** (`.claude/settings.json`):
- `PreToolUse` on `Read|Write|Bash|WebFetch` — scans parameters; exits `2` to block
- `PostToolUse` on `WebFetch|WebSearch|Bash` — scans output; always exits `0` (warn only)

**Cursor** (`.cursor/hooks.json`):
- `beforeReadFile`, `beforeShellExecution`, `beforeMCPExecution`, `beforeSubmitPrompt`

**Codex** (`.codex/config.toml`):
- `PreToolUse` (all tools) — blocks on detection
- `PostToolUse` (all tools) — warns only

Managed entries are tagged with `"_shk_managed": true` or `# shk-managed-start`. Re-running replaces managed entries only and leaves user-defined hooks untouched.

### `shk init`

Generate a starter `shk.toml` policy file.

```bash
shk init           # default policy
shk init --strict  # fail-on medium, full PII detection enabled
```

`shk policy init` remains available as a longer alias.

## Configuration

Default policy file: `shk.toml` in the project root. Read-only commands can use built-in defaults, but commands that write files require this file so accidental AI-initiated writes fail closed.

```toml
[scan]
include = ["**/*"]
exclude = [".git/**", "node_modules/**", "dist/**", "build/**", "coverage/**", "**/*.svg", "**/*.png", "**/*.jpg", "**/*.jpeg", "**/*.gif", "**/*.webp", "**/*.ico", "**/*.avif", "**/*.bmp", "**/*.tif", "**/*.tiff", "**/*.mp4", "**/*.m4v", "**/*.mov", "**/*.webm", "**/*.mkv", "**/*.avi", "**/*.ogv", "**/*.mp3", "**/*.m4a", "**/*.wav", "**/*.flac", "**/*.aac", "**/*.ogg", "**/*.opus", "**/*.woff", "**/*.woff2", "**/*.ttf", "**/*.otf", "**/*.eot"]
max_file_size_bytes = 1048576
follow_symlinks = false
include_binary = false
binary_detection_bytes = 8192
fancy_regex_timeout_ms_per_file = 100  # config-only today; not yet wired

[rules]
secrets = true
pii = true
pii_languages = ["en", "ja"]   # universal rules + English and Japanese PII
env = true
internal_terms = false   # set true to enable [[custom_rules]] with kind = "internal"

[thresholds]
default_fail_on = "high"
scan_fail_on = "high"
pre_commit_fail_on = "high"

[mask]
mode = "strict"
redaction = "full"

# Project-specific sensitive terms. Patterns use Rust regex syntax.
# [[custom_rules]]
# id = "internal.codename"
# pattern = "ProjectNebula|社外秘|CONFIDENTIAL_CLIENT_X"
# severity = "high"
# kind = "internal"
# message = "Internal confidential term detected"

[doctor.ignore]
required_patterns = [".env", ".env.*", "!.env.example", "secrets/**", "*.pem", "*.key"]
```

### Custom rules

Add `[[custom_rules]]` entries to `shk.toml` for project-specific confidential words, codenames, or regex patterns:

```toml
[[custom_rules]]
id = "internal.codename"
pattern = "ProjectNebula|社外秘|CONFIDENTIAL_CLIENT_X"
severity = "high"
kind = "internal"
message = "Internal confidential term detected"
case_insensitive = false
enabled = true
```

Custom rules participate in scan, mask, hook mode, inline suppression, and `[[allowlist]]` just like built-in rules. Keep raw secret values out of `shk.toml`; use custom rules for terms/classes of data, and `value_hash` allowlists for value-specific suppression.

### Suppression

**Inline** (in files that support comments):

```
# not real credential: synthetic example value only
API_KEY=sk-abc123  # shk-ignore secret.openai_api_key
# shk-ignore-next-line secret.generic_api_key
SECRET=value
```

**Policy allowlist** in `shk.toml`:

```toml
# Suppress by path and rule
[[allowlist]]
rule_id = "secret.generic_api_key"
path = "fixtures/**"
reason = "Intentional test fixture"
expires = "2026-12-31"

# Suppress a specific value by HMAC hash (no raw secret in config)
[[allowlist]]
rule_id = "pii.email"
value_hash = "sha256-hmac:a3f1..."
reason = "Public support address"
```

Raw secret values must never appear in `shk.toml`. Use `value_hash` for value-specific suppression.

## Detection model

### Severity levels

| Level | Examples |
|-------|---------|
| `critical` | Private key blocks |
| `high` | OpenAI-style keys, AWS access key IDs |
| `medium` | Generic API key assignments, email, US SSN, Japanese phone/postal code |
| `low` | Policy warnings such as expired allowlist entries |
| `info` | Recommendations and manual checks |

### Rule categories

| Category | Description |
|----------|-------------|
| `secret` | LLM/cloud/SaaS provider keys, database URLs, JWT/Bearer tokens, generic API key assignments, private key blocks |
| `pii` | Email, credit card, IP addresses, English/Japanese personal information patterns |
| `ignore` | Scanner skip notices and policy warnings |

### PII coverage

Currently implemented PII rules:

- Universal when `pii = true`: email, Luhn-validated credit card numbers, IPv4, IPv6
- English (`pii_languages = ["en"]`): phone number, US SSN, and label-anchored ZIP/postal code, EIN, passport number, street address, and personal name
- Japanese (`pii_languages = ["ja"]`): phone number, label-anchored/`〒` postal code, passport number, label-anchored My Number, corporate number, driver license number, bank account, health insurance card, and personal name

Personal names and English street addresses are label-anchored only; free-standing detection is intentionally disabled to avoid high false positive rates.

### JSON output

```bash
shk scan . --json
```

```json
{
  "version": 1,
  "scanned_paths": ["src/app.ts"],
  "findings": [
    {
      "rule_id": "secret.openai_api_key",
      "severity": "high",
      "kind": "secret",
      "file": "src/app.ts",
      "line": 12,
      "column": 18,
      "message": "Possible OpenAI API key detected",
      "redacted_value": "[REDACTED]",
      "confidence": 0.9
    }
  ],
  "summary": {
    "total": 1,
    "by_severity": {
      "high": 1
    }
  },
  "exit_threshold": "high",
  "suppressed": 0,
  "color_mode": "never"
}
```

Raw secret values never appear in JSON output. `redacted_value` is always `[REDACTED]`.

## Safety principles

- Local-first — no telemetry, no network access by default
- Never prints raw secret values
- Best-effort zeroization for raw match/input buffers in scanner and masker paths
- Read-only integrations first
- Conservative `--fix` behavior — appends only, never removes
- Explicit opt-in for any provider or network access
- Keeps audit logs and JSON reports redacted/metadata-only

## Building

```bash
cargo build
cargo test --all
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings

# Release
cargo build --release
```

CI runs on macOS, Linux, and Windows.

## License

MIT — see [LICENSE](LICENSE).
