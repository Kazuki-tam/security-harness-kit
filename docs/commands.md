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

## `shk status`

Show a concise project health summary.

```bash
shk status
```

The status command reports whether `shk.toml` exists, whether the Git pre-commit hook and managed AI hooks are installed, whether bundled AI skills are installed, and whether a newer `shk` release is available.

Update checks are limited to `shk status` and `shk doctor version`; scan and hook commands do not contact the network for version notices.

## `shk completions`

Generate shell completion scripts.

```bash
shk completions bash > /usr/local/etc/bash_completion.d/shk
shk completions zsh > "${fpath[1]}/_shk"
shk completions fish > ~/.config/fish/completions/shk.fish
```

Supported shells are `bash`, `zsh`, `fish`, `powershell`, and `elvish`.

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
| `--verbose` | Include informational skip findings in human-readable output. |
| `--fail-on <severity>` | Override the configured failure threshold. Valid values: `info`, `low`, `medium`, `high`, `critical`. |
| `--include-binary` | Scan binary-looking files instead of reporting `scan.binary_skipped` info findings. |
| `--follow-symlinks` | Follow symlinks during traversal. |
| `--staged` | Scan Git-staged files. Intended for pre-commit usage. |
| `--no-color` | Disable colored human-readable output. This is a global option. |

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

`mask --output` refuses sensitive env files and protected home configuration files. Binary or non-UTF-8 input is passed through unchanged in human-readable output and reported as `mask.binary_passthrough` in JSON output.

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

`.env.example` and dotenvx-encrypted env files are excluded from the plaintext env file warning. With `--dotenvx`, the diagnostic also reports known dotenvx artifact files such as `.env.keys` and `.env.vault`.

### `shk doctor version`

Check the latest GitHub release version.

```bash
shk doctor version
shk doctor --json version
```

This command reports whether an update is available. It does not modify the installed binary.

## `shk env dotenvx`

Store dotenvx private keys in the operating system credential store and inject them only when running a command through dotenvx.

```bash
shk env dotenvx import-keys .env.keys
shk env dotenvx list
shk env dotenvx run -- npm test
shk env dotenvx run -f .env.production -- npm start
shk env dotenvx run --env production -- npm start
shk env dotenvx run --key DOTENV_PRIVATE_KEY_PRODUCTION -- npm start
shk env dotenvx delete --env production
shk env dotenvx delete --key DOTENV_PRIVATE_KEY_PRODUCTION
shk env dotenvx delete --all
```

This command group uses the platform credential store through the `keyring` crate: macOS Keychain, Windows Credential Manager, and Linux Secret Service / keyutils depending on platform support.

`import-keys` reads only `DOTENV_PRIVATE_KEY` and `DOTENV_PRIVATE_KEY_<ENV>` entries from a `.env.keys`-style file. Raw key values are never printed. `run` reads the stored keys for the current project and invokes `dotenvx run -- <command>` with those values present only in the child process environment. `delete` requires an explicit target: `--all`, `--key <DOTENV_PRIVATE_KEY*>`, or `--env <name>`.

There is intentionally no `export` command because printing or writing raw private keys defeats the purpose of moving `.env.keys` into the OS credential store.

Run options:

| Option | Behavior |
|--------|----------|
| `--dotenvx-bin <bin>` | dotenvx executable to invoke. Defaults to `dotenvx`. |
| `-f, --file <file>` | Pass one or more dotenvx env files to `dotenvx run`. |
| `--key <DOTENV_PRIVATE_KEY*>` | Inject only the named stored private key. Repeatable. |
| `--env <name>` | Inject `DOTENV_PRIVATE_KEY_<NAME>`. Use `default` for `DOTENV_PRIVATE_KEY`. Repeatable. |
| `-- <command>` | Command to run through `dotenvx run`. Required. |

Delete options:

| Option | Behavior |
|--------|----------|
| `--all` | Delete every stored dotenvx private key for the current project. |
| `--key <DOTENV_PRIVATE_KEY*>` | Delete one exact stored private key. |
| `--env <name>` | Delete `DOTENV_PRIVATE_KEY_<NAME>`. Use `default` for `DOTENV_PRIVATE_KEY`. |

## `shk secrets push`

Push a dotenv payload into AWS Secrets Manager or GCP Secret Manager without printing raw secret values.

```bash
# Store the whole dotenv file as one secret.
shk secrets push --provider aws --target app/prod/dotenv --from .env.production

# Store each dotenv key as a separate secret under a target prefix.
shk secrets push --provider gcp --mode per-key --target-prefix app/prod/ --from .env.keys

# Preview writes and target names without invoking provider CLIs.
shk secrets push --profile prod --dry-run
```

Options:

| Option | Behavior |
|--------|----------|
| `--profile <name>` | Read defaults from `[secrets.profiles.<name>]` in `shk.toml`. CLI flags override profile values. |
| `--provider <aws|gcp>` | Secret manager provider. Required unless configured by profile. |
| `--target <name>` | Blob mode target secret name. Cannot be combined with `--target-prefix`. |
| `--target-prefix <prefix>` | Per-key mode target prefix. Cannot be combined with `--target`. |
| `--from <file>` | Source dotenv file. Required unless configured by profile. |
| `--mode <blob|per-key>` | `blob` stores the full file as one payload. `per-key` stores each dotenv key separately. Defaults to `blob`. |
| `--dry-run` | Print planned writes, target names, and metadata without calling AWS or GCP. |
| `--audit` | Append metadata-only entries to `.shk/audit.log`. Raw values are not logged. |
| `--confirm` | Prompt before writing. In non-interactive environments, pass `--yes` or use `--dry-run`. |
| `--yes` | Skip confirmation prompts. |
| `--create-if-missing` | Create provider secrets when they do not already exist. |
| `--strict` | Treat dotenv lint warnings as failures. |
| `--no-scan` | Skip the pre-push PII scan. Use only for an explicit exception. |
| `--region <region>` | AWS region. Otherwise AWS CLI environment/config is used. |
| `--project <project>` | GCP project. Otherwise gcloud environment/config is used. |
| `--location <location>` | GCP location. Defaults to `global`. |
| `--expected-env <name>` | Lint hint for values such as `NODE_ENV`. |

Behavior notes:

- `shk secrets push` requires a project root and reads `shk.toml` from that root.
- The source file is scanned for PII before push unless `--no-scan` is passed.
- Blob mode requires `--target`; per-key mode requires `--target-prefix`.
- Per-key mode accepts dotenv-style `KEY=value` lines, rejects duplicate keys, and validates keys as `[A-Z_][A-Z0-9_]*`.
- AWS and GCP writes are performed through the official `aws` and `gcloud` CLIs. Arguments are passed directly, not through a shell.

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
shk hooks install-ai --apply-sandbox
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
| `--apply-sandbox` | Applies supported sandbox hardening. Claude Code gets `sandbox.enabled`, hard-fail, and no unsandboxed escape hatch. Project installs also add a home-read deny with project read re-allow; global installs skip those project-relative read rules. Codex gets `sandbox_mode = "workspace-write"` and `approval_policy = "on-request"` when absent or risky. Cursor has no local sandbox setting in `hooks.json`, so managed hooks are set fail-closed. |

Without `--tool`, the command targets Claude Code, Codex, and Cursor. Non-dry-run installation requires a project `shk.toml`.

Installed entries:

| Tool | Config file | Managed entries |
|------|-------------|-----------------|
| Claude Code | `.claude/settings.json` | `UserPromptSubmit`; `PreToolUse` for `Read|Write|Bash|WebFetch|mcp__.*`; `PostToolUse` for `WebFetch|WebSearch|Bash|mcp__.*|Skill|Agent`. |
| Cursor | `.cursor/hooks.json` | `beforeReadFile`, `beforeShellExecution`, `beforeMCPExecution`, `beforeSubmitPrompt`. |
| Codex | `.codex/config.toml` | `PreToolUse`, `PermissionRequest`, and `PostToolUse` blocks; also ensures `features.codex_hooks = true`. |

Managed entries are tagged with `"_shk_managed": true` or `# shk-managed-start` / `# shk-managed-end`. Re-running replaces managed entries and leaves non-managed entries in place.

See [Uninstall](installation.md#uninstall) for removing managed hooks, skills, generated workflows, and stored dotenvx keys.

In pre-hook mode, `shk` also runs an action guard before content scanning. It blocks sensitive file access, destructive filesystem operations, direct database mutation commands, privilege or system changes, external transfer commands, and package manager operations when they are visible in the hook payload. Tune this with `[action_guard]` in `shk.toml`; `--audit` remains non-blocking.

## `shk ci init github`

Generate a GitHub Actions workflow that installs `shk` from the bundled cargo-dist installer and runs `shk scan` on every pull request and push to `main`.

```bash
shk ci init github
shk ci init github --dry-run
shk ci init github --mode audit
shk ci init github --fail-on critical
shk ci init github --shk-version v0.2.3
shk ci init github --output .github/workflows/security.yml --force
```

Options:

| Option | Behavior |
|--------|----------|
| `--mode <blocking|audit>` | `blocking` (default) fails the workflow when findings meet `--fail-on`. `audit` always exits `0` and is intended for non-blocking adoption. |
| `--fail-on <severity>` | Severity threshold for blocking mode. Valid values: `info`, `low`, `medium`, `high` (default), `critical`. Ignored under `--mode audit` (a warning is printed). |
| `--path <path>` | Path passed to `shk scan`. Defaults to `.`. |
| `--repo <owner/name>` | GitHub repository hosting `shk` releases. Defaults to `Kazuki-tam/security-harness-kit`. |
| `--shk-version <version>` | Release version to install. Accepts `latest` (default) or a SemVer-ish tag such as `v0.2.3`. |
| `--installer-name <name>` | cargo-dist shell installer asset name. Defaults to `shk-cli-installer.sh`. |
| `--output <path>` | Workflow destination path. Defaults to `.github/workflows/shk.yml`. |
| `--dry-run` | Print the workflow YAML to stdout without writing it. |
| `--force` | Overwrite an existing workflow file. |

Generated workflows include `permissions: contents: read` and a `concurrency` block with `cancel-in-progress: true` so reruns on the same ref supersede in-flight jobs. The CLI rejects unsafe values for `--repo`, `--shk-version`, and `--installer-name` to keep the generated installer URL well-formed.

See [GitHub Actions integration](ci.md) for a full guide covering the generated YAML, blocking vs audit rollout, pinning a release, and PR Required Check setup.

## `shk skills`

Manage Claude Code / Codex / Cursor skills bundled with `shk`. Skills are embedded in the binary and deployed to project directories on demand.

```bash
shk skills list
shk skills status
shk skills install
shk skills install --tool claude-code
shk skills install --tool codex
shk skills install --tool cursor
shk skills install --tool all --global
shk skills install --dry-run
shk skills install --force
```

### `shk skills list`

Print the built-in skills available for installation.

### `shk skills status`

Show the installation status for all supported tools (project and global paths).

### `shk skills install`

Install the `shk` skill to the current project's skill directories.

Options:

| Option | Behavior |
|--------|----------|
| `--tool <tool>` | Target: `claude-code`, `codex`, `cursor`, or `all` (default: `all`). |
| `--global` | Write to user-level directories (`~/.claude/skills/` or `~/.agents/skills/`) instead of the project. |
| `--dry-run` | Print planned paths without writing files. |
| `--force` | Overwrite an existing skill file. |

Install destinations:

| Tool | Project path | Global path |
|------|-------------|-------------|
| `claude-code` | `.claude/skills/shk.md` | `~/.claude/skills/shk.md` |
| `codex` / `cursor` | `.agents/skills/shk/SKILL.md` | `~/.agents/skills/shk/SKILL.md` |

The Codex and Cursor paths follow the [open agent skills standard](https://agentskills.io). The skill file is embedded in the `shk` binary at build time and requires no network access.
