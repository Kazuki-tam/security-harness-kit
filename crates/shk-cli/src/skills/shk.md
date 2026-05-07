---
name: shk
description: >
  Security scanning, PII detection, secret masking, and AI hook installation using the shk CLI.
  Use when the user asks to: scan for secrets/credentials/sensitive data, detect or mask PII,
  set up security hooks for Claude Code/Cursor/Codex, run security diagnostics (shk doctor),
  or guard content flowing through MCP tools or external data connections.
---

# shk — Security Harness Kit

`shk` is a local-first security harness CLI for AI-assisted development. It scans for secrets and
PII, masks sensitive content, manages AI tool hooks, and runs project diagnostics.

## Quick reference

```
shk scan [PATH]                      # scan directory (default: .)
shk scan . --json                    # JSON report
shk scan --staged                    # scan git-staged files (pre-commit)
shk mask < file.txt                  # mask PII/secrets from stdin
shk mask file.txt --json             # JSON output with findings + masked content
shk hooks install-ai                 # install hooks for Claude Code / Cursor / Codex
shk hooks install-ai --tool claude-code --global
shk hooks install-ai --dry-run       # preview changes
shk doctor                           # full project diagnostics
shk doctor ignore --fix              # fix missing .gitignore entries
shk skills install                   # install this skill (claude-code + codex)
shk skills install --tool claude-code --global
shk skills install --tool codex --global
```

## Scanning

Run `shk scan .` to detect secrets, API keys, and PII in the current directory.

Exit codes:
- 0: no findings at or above threshold
- 1: findings at or above threshold
- 2: blocking AI hook triggered

Useful flags:
- `--fail-on <info|low|medium|high|critical>` — override threshold
- `--verbose` — show informational skip findings
- `--json` — machine-readable JSON report
- `--staged` — only scan git-staged files

## Masking

`shk mask` redacts secrets and PII from stdin or a file before sending content to an AI tool.

```bash
# Mask a prompt before passing to an LLM
shk mask prompt.txt | claude

# Partial redaction (preserve 4-char prefix/suffix)
shk mask --redaction partial < data.txt
```

## AI hook integration

`shk hooks install-ai` writes managed entries to `.claude/settings.json`,
`.cursor/hooks.json`, and `.codex/config.toml`.

Each hook runs `shk scan --hook-mode <tool>` on the payload before AI tool execution.
Pre-hooks block on findings (exit 2); post-hooks warn only (exit 0).

```bash
shk hooks install-ai                             # all detected tools
shk hooks install-ai --audit                     # non-blocking, writes .shk/audit.log
shk hooks install-ai --tool claude-code
shk hooks install-ai --tool claude-code --global
shk hooks install-ai --tool claude-code --apply-deny
```

## External data sources and MCP integration

**Important limitations:**
- `WebFetch` and MCP tool results flow directly into the model context — hooks can detect
  findings but cannot transform (mask) the response before it enters context.
- `shk mask` is only effective when you control the data pipeline via the `Bash` tool.

When fetching external data via `Bash`, pipe through `shk mask` before writing to files or
injecting into prompts:

```bash
# Fetch and mask before use — effective because Bash controls the pipe
curl https://api.example.com/data | shk mask

# Write masked output to a file for later use
curl https://api.example.com/data | shk mask > safe_data.txt

# JSON output with findings list
shk mask --json < downloaded_file.txt
```

When `WebFetch` or MCP tools are used instead, the PostToolUse hook installed by
`shk hooks install-ai` will **scan and warn** about findings in the response, but cannot
redact the content before it enters context.

**When shk reports findings on a WebFetch or MCP response, follow these rules:**

1. **Do not echo raw matched values in your reply.** Replace any value flagged by shk with
   `[REDACTED]` when summarizing or quoting the fetched content.
2. **Warn the user explicitly.** State that shk detected sensitive data in the response,
   include the rule IDs and severity from the findings (e.g. `secret.github_token` / High),
   and recommend the user review whether the source should have returned that data.
3. **Do not proceed with tasks that depend on the flagged values** (e.g. using a detected
   API key to make further requests) unless the user explicitly confirms they want to continue.
4. **Suggest a remediation step**, such as running `shk mask` on a saved copy of the response
   or checking `shk doctor` to ensure hooks are installed for future requests.

Hook-mode scanning (used internally by installed hooks):

```bash
# Pre-hook: scan tool payload from stdin, block on findings (exit 2)
shk scan . --hook-mode claude-code < hook_payload.json

# Post-hook: scan inbound content, always non-blocking
shk scan . --hook-mode claude-code --post < response_payload.json

# Audit mode: log findings to .shk/audit.log, never block
shk scan . --hook-mode claude-code --audit < hook_payload.json
```

Add domain-specific rules in `shk.toml` to detect internal identifiers or API response patterns
from custom MCP tools:

```toml
[rules]
secrets = true
pii = true
internal_terms = true   # enable custom term matching
```

## Diagnostics

```bash
shk doctor                   # full suite: hooks, ignore, env, AI tool status
shk doctor ignore            # check .gitignore / AI tool ignore coverage
shk doctor ignore --fix      # append missing patterns to .gitignore
shk doctor env               # detect plaintext .env secrets
shk doctor version           # check for shk updates
```

## Configuration (shk.toml)

`shk policy init` creates a starter `shk.toml`. Key sections:

```toml
[rules]
secrets = true
pii = true
pii_languages = ["en", "ja"]

[thresholds]
default_fail_on = "high"

[[allowlist]]
rule_id = "secret.generic_api_key"
path = "fixtures/**"
reason = "Test fixture"
```

Inline suppression: append `# shk-ignore` or `# shk-ignore-next-line <rule_id>` to a line.

## Skills management

```bash
shk skills list                              # show available built-in skills
shk skills status                            # check installation status
shk skills install                           # install for all tools (claude-code + codex)
shk skills install --tool claude-code        # .claude/skills/shk.md
shk skills install --tool codex             # .agents/skills/shk/SKILL.md
shk skills install --tool claude-code --global   # ~/.claude/skills/shk.md
shk skills install --tool codex --global    # ~/.agents/skills/shk/SKILL.md
shk skills install --force                  # overwrite existing
shk skills install --dry-run                # preview without writing
```
