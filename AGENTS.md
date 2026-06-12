# AGENTS.md — `shk`

This repository is a **local-first security harness CLI for AI coding agents** (`shk`). This file is agent-oriented guidance (build, test, conventions), not a human-focused README. For the open format, see the [AGENTS.md project site](https://agents.md/).

## Stack

- **Language**: Rust (single-binary distribution; end users should not need Rust installed).
- **Workspace** (`Cargo.toml` `members`):
  - `crates/shk-core` — policy, scanning, masking, JSON reports, suppression helpers.
  - `crates/shk-rules` — built-in rules (secrets, PII, etc.).
  - `crates/shk-cli` — `clap`-based CLI (binary `shk`).
    - **`src/lib.rs`** (crate `shk_cli`) — `run()` entry (tests and external callers).
    - **`src/main.rs`** — thin wrapper calling `shk_cli::run()`.
    - **`src/args.rs`** — `clap` CLI definitions.
    - **`src/commands/`** — `scan`, `mask`, `audit`, etc. (move `doctor` / others here if this layer grows).
    - Other modules: `color`, `doctor`, `hooks`, `hook_payload`, `hook_output`, `hook_audit_log`, `audit_log`, `output`, `policy_cmd`, `workflow_hardening` (GitHub Actions `persist-credentials` checks).
  - `crates/shk-integrations` — markers/constants for managed AI hooks; parsers may move here over time.
  - `xtask` — development-only generator tasks, including gitleaks rule import.

## Setup

```bash
# From repository root
cargo build
cargo test --all
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings

# Line coverage (requires cargo-llvm-cov + llvm-tools-preview; same gate as CI)
bash ./.github/scripts/ci/rust-coverage.sh
```

Release build:

```bash
cargo build --release
# Binary: target/release/shk
```

## Exit codes

| Code | Meaning | Commands |
|------|---------|----------|
| `0` | No findings above threshold / success | `shk scan`, `shk scan --staged`, `shk mask`, `shk clipboard scan`, `shk clipboard mask`, `shk doctor`, `shk audit`, `shk scan --audit` |
| `1` | Findings at or above the fail threshold | `shk scan`, `shk scan --staged`, `shk clipboard scan` |
| `2` | Blocking AI pre-hook triggered / runtime or config error | `shk scan --hook-mode <tool>` (block), `shk scan --staged` outside a Git repo, `shk clipboard …` when the OS clipboard is unavailable |

- `--audit` mode **always exits 0** (log-only; never blocks).
- `--log-blocked` keeps blocking behavior and writes metadata-only blocked-event entries to `.shk/audit.log`.
- Post-execution hooks (`--post`) **always exit 0** — data is already in the AI's context.
- Exit code 2 from a blocking pre-hook causes the AI tool to abort the pending operation.

Do not change exit code semantics without updating `crates/shk-cli/src/lib.rs` **and** this table.

## Quality gates (before merge / when editing this repo)

Keep **green** on all supported platforms when possible:

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all`

When changing the desktop app under `apps/shk-desktop`, also keep the frontend checks green from the repository root:

- `pnpm -C apps/shk-desktop fmt:check`
- `pnpm -C apps/shk-desktop lint`
- `pnpm -C apps/shk-desktop test:run`

**Security / context hygiene**

- Never commit or print **raw secret material** in logs, tests, or fixtures beyond what already exists in `fixtures/` demos.
- JSON reports use `redacted_value: "[REDACTED]"` (spec §6).
- `.shk/audit.log` entries must stay **metadata-only** (counts, tool name, hook phase, rule IDs, action category, relative path label) — implementation is in `audit_log::append_line`; hook payload shaping lives in `hook_audit_log`.

## Common dev commands

```bash
# Scan repo/path (default fail-on high → exit 1 when exceeded)
cargo run -p shk-cli --bin shk -- scan .

# JSON only, relax threshold (similar to CI smoke)
cargo run -p shk-cli --bin shk -- scan fixtures/basic --json --fail-on critical

# Mask (stdin)
cargo run -p shk-cli --bin shk -- mask --json < fixtures/pii.txt

# Clipboard (scan or mask OS clipboard text; --write replaces the clipboard)
cargo run -p shk-cli --bin shk -- clipboard scan --json
cargo run -p shk-cli --bin shk -- clipboard mask
cargo run -p shk-cli --bin shk -- clipboard mask --write

# Doctor
cargo run -p shk-cli --bin shk -- doctor
cargo run -p shk-cli --bin shk -- doctor ignore fixtures/project
cargo run -p shk-cli --bin shk -- doctor env
cargo run -p shk-cli --bin shk -- doctor workflows # actions/checkout persist-credentials: false
cargo run -p shk-cli --bin shk -- doctor workflows --fix

# Audit log preview
cargo run -p shk-cli --bin shk -- audit
cargo run -p shk-cli --bin shk -- audit --reason action-guard --no-paths

# Policy template
cargo run -p shk-cli --bin shk -- policy init --strict

# Git pre-commit (requires a `.git` directory)
cargo run -p shk-cli --bin shk -- hooks install

# AI tool hooks (writes project or `~/.cursor` / etc. with `--global`; use `--dry-run` first)
cargo run -p shk-cli --bin shk -- hooks install-ai --dry-run

# Skills (deploy embedded Claude Code / Codex / Cursor skill to project)
cargo run -p shk-cli --bin shk -- skills install --dry-run
cargo run -p shk-cli --bin shk -- skills install                   # .claude/skills/ + .agents/skills/
cargo run -p shk-cli --bin shk -- skills install --tool claude-code
cargo run -p shk-cli --bin shk -- skills install --tool codex
cargo run -p shk-cli --bin shk -- hooks install-ai --tool cursor --audit
cargo run -p shk-cli --bin shk -- hooks install-ai --tool cursor --log-blocked
cargo run -p shk-cli --bin shk -- hooks install-ai --tool claude-code --global --dry-run

# Hook-mode scan (stdin = tool JSON payload; blocking pre hooks → exit 2, stdout = tool-specific JSON)
cargo run -p shk-cli --bin shk -- scan . --hook-mode cursor < /path/to/payload.json
cargo run -p shk-cli --bin shk -- scan . --hook-mode cursor --log-blocked < /path/to/payload.json

# Regenerate generated gitleaks-derived rules (pin source ref when updating)
cargo run -p xtask -- import-gitleaks-rules \
  --input https://raw.githubusercontent.com/gitleaks/gitleaks/<commit>/config/gitleaks.toml \
  --output crates/shk-rules/src/gitleaks_rules.rs \
  --source-ref <commit>
cargo run -p xtask -- import-gitleaks-rules --check \
  --input https://raw.githubusercontent.com/gitleaks/gitleaks/<commit>/config/gitleaks.toml \
  --output crates/shk-rules/src/gitleaks_rules.rs \
  --source-ref <commit>
```

## Adding a new rule

Built-in rules have two sources:

- Hand-tuned `shk` rules in `crates/shk-rules/src/lib.rs` inside the `RULES` static vec.
- Generated gitleaks-derived rules in `crates/shk-rules/src/gitleaks_rules.rs`, generated by `xtask`.

For a single curated rule, add a hand-tuned rule. For upstream gitleaks coverage changes, update the pinned gitleaks source ref and regenerate `gitleaks_rules.rs` with `cargo run -p xtask -- import-gitleaks-rules`.

**Steps:**

1. Add a `CompiledRule` entry to `RULES`:

```rust
CompiledRule {
    id: "secret.my_service_key",   // stable, never rename once shipped
    severity: Severity::High,
    kind: Kind::Secret,            // Secret | Pii | Env | AiContext | Ignore | Git
    re: Regex::new(r"(?i)\bmsk-[a-zA-Z0-9]{32}\b")
        .unwrap_or_else(|_| Regex::new("^$").unwrap()),
    message: "Possible MyService key detected",
    confidence: 0.88,
},
```

2. Add a false-positive guard fixture under `fixtures/` if the pattern is broad.

3. Add a unit test in the `#[cfg(test)]` block of `shk-rules/src/lib.rs`:

```rust
#[test]
fn detects_my_service_key() {
    let s = r#"key = "msk-abcdefghijklmnopqrstuvwxyz012345""#;
    let cfg = RuleEngineConfig::default();
    let m = scan_content(s, "demo.env", &cfg);
    assert!(m.iter().any(|x| x.rule_id == "secret.my_service_key"), "{m:?}");
}
```

**Constraints:**
- Prefer `regex` crate over `fancy-regex`; use `fancy-regex` only when lookaround is unavoidable.
- `fancy-regex` rules need a ReDoS fixture under `fixtures/redos/`.
- PII rules namespaced `pii.en.*` / `pii.ja.*` are gated by `pii_languages` in `rule_applies()` — no extra wiring needed.
- `rule_id` must be stable; changing it after release breaks existing `[[allowlist]]` entries in users' `shk.toml`.
- Do not manually edit `crates/shk-rules/src/gitleaks_rules.rs`; regenerate it through `xtask`.
- gitleaks-derived rule ids use `secret.gitleaks.<upstream-id>`.
- Keep gitleaks license/source information in `THIRD_PARTY_LICENSES.md` and the generated file header when updating the upstream source ref.

## Tests and fixtures

- **Integration**: `crates/shk-cli/tests/smoke.rs`
- **Core**: `crates/shk-core/tests/scan_fixture.rs`, plus `#[cfg(test)]` in `scanner`, `finding`, `masker`, `suppression`
- **Rules**: `crates/shk-rules` `#[cfg(test)]` (detection, `redact_line_for_display`)
- **Fixtures**: `fixtures/basic/`, `fixtures/pii.txt`, `fixtures/project/`

## shk.toml reference

Default file: `shk.toml` in the project root. Created by `shk policy init`.

```toml
[scan]
include = ["**/*"]
exclude = [".git/**", "node_modules/**", "dist/**", "build/**", "coverage/**", "**/*.svg", "**/*.png", "**/*.jpg", "**/*.jpeg", "**/*.gif", "**/*.webp", "**/*.ico", "**/*.avif", "**/*.bmp", "**/*.tif", "**/*.tiff", "**/*.mp4", "**/*.m4v", "**/*.mov", "**/*.webm", "**/*.mkv", "**/*.avi", "**/*.ogv", "**/*.mp3", "**/*.m4a", "**/*.wav", "**/*.flac", "**/*.aac", "**/*.ogg", "**/*.opus", "**/*.woff", "**/*.woff2", "**/*.ttf", "**/*.otf", "**/*.eot"]
max_file_size_bytes = 1048576          # files larger than this are skipped
binary_detection_bytes = 8192
follow_symlinks = false
include_binary = false

[rules]
secrets = true
pii = true
pii_languages = ["en", "ja"]
env = true
internal_terms = false

[thresholds]
default_fail_on = "high"
scan_fail_on = "high"
pre_commit_fail_on = "high"

[mask]
mode = "strict"
min_severity = "medium"
redaction = "match"
# preserve_prefix = 4   # only when redaction = "partial"
# preserve_suffix = 4

[doctor.ignore]
required_patterns = [".env", ".env.*", "!.env.example", "secrets/**", "*.pem", "*.key"]

# Suppress a specific finding by path + rule
[[allowlist]]
rule_id = "secret.generic_api_key"
path = "fixtures/**"
reason = "Intentional test fixture"

# Suppress by value hash: HMAC-SHA256(raw_value, rule_id), lowercase hex, prefixed "sha256-hmac:"
[[allowlist]]
rule_id = "pii.email"
value_hash = "sha256-hmac:a3f1..."
reason = "Public support address"
expires = "2026-12-31"    # expired entries produce warning findings
```

Key facts:
- Raw secret values must **never** appear in `shk.toml`; use `value_hash` for value-specific suppression.
- Inline suppression: `# shk-ignore [rule_id]` or `# shk-ignore-next-line [rule_id]` (comment-capable formats only).
- Policy is resolved relative to `std::env::current_dir()` — run from the project root.

## Commit conventions

Use [Conventional Commits](https://www.conventionalcommits.org/) style: `feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`. Keep the subject under 72 characters. Reference issue numbers in the body when applicable.

## Coding notes

- **Never log or emit raw secrets in JSON** (`redacted_value` is `[REDACTED]` per spec §6).
- **`context_before` / `context_after`**: do not ship raw neighbor lines; run `shk_rules::redact_line_for_display` so patterns align with detection rules (toward “redacted lines only” in spec §6).
- **Document scanning/masking**: document text extraction for scan lives in `crates/shk-core/src/document_masker.rs` alongside Office masking helpers. `.docx`, `.xlsx`, `.pptx`, and text-layer `.pdf` scan by extracted text; Office mask supports `.docx`, `.xlsx`, `.pptx` only and requires `--output`.
- **Policy resolution**: `mask`, `doctor`, `policy init`, and `hooks install` resolve policy relative to **`std::env::current_dir()`**. From a subdirectory, `cd` to the project root or consider a future `--project-root` flag.
- **`Policy::default()` vs `serde::Default`**: beware `#[derive(Default)]` on structs with `bool` fields that should default to `true` (e.g. `RulesSection` needs an explicit `Default` impl).
- **Paths**: scanning `canonicalize`s the root and matches `ignore` walker paths with `strip_prefix`.
- **Windows**: respect path separators and `pre-commit` shebang limitations.

## CI

`.github/workflows/ci.yml` runs `fmt`, `clippy`, `tests`, `release` build, and smoke checks on **ubuntu**, **macOS**, and **Windows**.

## License

MIT — see `LICENSE`.
