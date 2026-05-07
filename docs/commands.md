# Commands

This page describes the implemented `shk` CLI commands and options.

## `shk init`

Create a starter `shk.toml` policy file in the current directory.

```bash
shk init
shk init --strict
shk init --force
```

`--strict` writes medium fail thresholds. `--force` overwrites an existing policy file.

`shk policy init` is also available as a longer alias:

```bash
shk policy init
shk policy init --strict
shk policy init --force
```

## `shk scan`

Scan a repository or path for secrets, PII, and configured custom rules.

```bash
shk scan
shk scan ./src
shk scan . --json
shk scan . --verbose
shk scan . --fail-on medium
shk scan . --include-binary
shk scan . --follow-symlinks
shk scan --staged
shk scan . --no-color
```

Options:

| Option | Behavior |
|--------|----------|
| `PATH` | Path to scan. Defaults to `.`. |
| `--json` | Print a JSON report. |
| `--verbose` | Include informational skip findings in human output. |
| `--fail-on <severity>` | Override the configured failure threshold. Valid values: `info`, `low`, `medium`, `high`, `critical`. |
| `--include-binary` | Scan binary-looking files instead of reporting `scan.binary_skipped` info findings. |
| `--follow-symlinks` | Follow symlinks during traversal. |
| `--staged` | Scan Git-staged files. Intended for pre-commit usage. |
| `--no-color` | Disable colored human output. This is a global option. |

Exit codes:

| Code | Meaning |
|------|---------|
| `0` | No findings at or above the active threshold, or command completed successfully. |
| `1` | Scan findings met or exceeded the active threshold. |
| `2` | Blocking AI pre-hook triggered, or `shk scan --staged` was run outside a Git repository. |

## `shk scan --hook-mode`

Read an AI tool hook JSON payload from stdin, scan the extracted hook body, and print tool-specific hook output.

```bash
shk scan . --hook-mode cursor < payload.json
shk scan . --hook-mode claude-code --audit < payload.json
shk scan . --hook-mode codex --post < payload.json
```

Supported hook mode tools are `claude-code`, `codex`, and `cursor`.

Hook mode notes:

- `--hook-mode` cannot be combined with `--staged`.
- `--audit` appends metadata-only JSON lines to `.shk/audit.log`, always exits `0`, and requires a project `shk.toml`.
- `--post` is non-blocking and always exits `0`. It reports findings in tool output for review.
- Cursor pre-hook scans use the pre-commit threshold by default.

## `shk mask`

Redact sensitive values from stdin or a file.

```bash
shk mask < prompt.txt
shk mask prompt.txt
shk mask prompt.txt --output out.txt
shk mask --json < prompt.txt
shk mask --redaction partial < prompt.txt
shk mask --hook-mode cursor < payload.json
```

Options:

| Option | Behavior |
|--------|----------|
| `FILE` | Optional input file. If omitted, stdin is used. |
| `--json` | Print masked content and findings as JSON. |
| `--output <path>` | Write masked content to a file. Requires `shk.toml`. |
| `--redaction full` | Replace any line containing a finding with `[REDACTED_LINE]`. |
| `--redaction partial` | Replace matched values and preserve the configured prefix/suffix. |
| `--hook-mode <tool>` | Read a hook payload from stdin and print tool-specific masked hook output. |
| `--post` | Post-tool hook mode. Requires `--hook-mode <tool>`. |

When no `FILE` is provided, `shk mask` reads stdin until EOF. In an interactive
terminal, run it with input redirection (`shk mask < prompt.txt`) or provide a
file path (`shk mask prompt.txt`).

`mask --output` refuses sensitive env files and protected home configuration files. Binary or non-UTF-8 input is passed through unchanged in human output and reported as `mask.binary_passthrough` in JSON output.

## `shk doctor`

Run project diagnostics.

```bash
shk doctor
shk doctor --json
```

`shk doctor` runs the available diagnostics for the current directory.

### `shk doctor ignore`

Check ignore coverage across Git and AI-oriented ignore files.

```bash
shk doctor ignore
shk doctor ignore ./path
shk doctor ignore ./path --fix
```

The ignore diagnostic checks `.gitignore`, `.cursorignore`, `.cursorindexingignore`, `.codeiumignore`, `.clineignore`, `.aiderignore`, `.continueignore`, `.tabnineignore`, `.ignore`, and `.aiignore` when present.

It also reports on Claude Code `.claude/settings.json` read deny entries and Codex `.codex/config.toml` hook/sandbox settings when those files exist.

`--fix` requires `shk.toml` and appends missing required patterns to `.gitignore`.

### `shk doctor env`

Check plaintext `.env` files at the project root.

```bash
shk doctor env
shk doctor env --dotenvx
shk doctor env ./path
```

`.env.example` is excluded from the plaintext env file warning. With `--dotenvx`, the diagnostic also reports known dotenvx artifact files such as `.env.keys` and `.env.vault`.

### `shk doctor version`

Check the latest GitHub release version.

```bash
shk doctor version
shk doctor --json version
```

This command reports whether an update is available. It does not modify the installed binary.

## `shk hooks install`

Install a Git pre-commit hook that runs `shk scan --staged`.

```bash
shk hooks install
shk hooks install --pre-commit
```

The command requires a Git repository and a project `shk.toml`. The hook uses managed markers and can be re-run.

## `shk hooks install-ai`

Install managed AI tool hooks for supported tools.

```bash
shk hooks install-ai
shk hooks install-ai --dry-run
shk hooks install-ai --audit
shk hooks install-ai --tool cursor
shk hooks install-ai --tool claude-code --global
shk hooks install-ai --tool claude-code --apply-deny
shk hooks install-ai --tool cursor --fail-closed
```

Options:

| Option | Behavior |
|--------|----------|
| `--dry-run` | Print planned changes without writing config files. |
| `--audit` | Add `--audit` to installed hook commands. |
| `--global` | Write user-level config files under the user's home directory. |
| `--tool <tool>` | Limit installation to one of `claude-code`, `codex`, or `cursor`. |
| `--fail-closed` | Cursor hooks only. Sets `failClosed` on managed entries. |
| `--apply-deny` | Claude Code only. Merges recommended `permissions.deny` entries for sensitive files and dangerous actions. |

Without `--tool`, the command targets Claude Code, Codex, and Cursor. Non-dry-run installation requires a project `shk.toml`.

Installed entries:

| Tool | Config file | Managed entries |
|------|-------------|-----------------|
| Claude Code | `.claude/settings.json` | `PreToolUse` for `Read|Write|Bash|WebFetch`; `PostToolUse` for `WebFetch|WebSearch|Bash`. |
| Cursor | `.cursor/hooks.json` | `beforeReadFile`, `beforeShellExecution`, `beforeMCPExecution`, `beforeSubmitPrompt`. |
| Codex | `.codex/config.toml` | `PreToolUse`, `PermissionRequest`, and `PostToolUse` blocks; also ensures `features.codex_hooks = true`. |

Managed entries are tagged with `"_shk_managed": true` or `# shk-managed-start` / `# shk-managed-end`. Re-running replaces managed entries and leaves non-managed entries in place.

In pre-hook mode, `shk` also runs an action guard before content scanning. It blocks sensitive file access, destructive filesystem operations, direct database mutation commands, privilege or system changes, external transfer commands, and package manager operations when they are visible in the hook payload. Tune this with `[action_guard]` in `shk.toml`; `--audit` remains non-blocking.
