# Commands

This page describes the implemented `shk` CLI commands and options.

## `shk init`

Create a starter `shk.toml` policy file in the current directory.

```bash
shk init
shk init --strict
shk init --force
shk init --yes --no-npm-hardening
```

`--strict` writes medium fail thresholds. `--force` overwrites an existing policy file.

When `package.json` is detected, `shk init` can apply package-manager supply-chain hardening. For npm projects it writes project `.npmrc` settings such as `ignore-scripts=true` and `min-release-age=7`. For pnpm, Yarn, or Bun projects it writes the corresponding age-gate setting to `pnpm-workspace.yaml`, `.yarnrc.yml`, or `bunfig.toml`. Pass `--no-npm-hardening` to skip this step, including in `--yes` mode.

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

Scan a repository or path for secrets, PII, and configured custom rules. Text is also extracted from supported document formats: `.docx`, `.xlsx`, `.pptx`, and text-layer `.pdf` files.

```bash
shk scan
shk scan ./src
shk scan . --json
shk scan . --verbose
shk scan . --fail-on medium
shk scan . --include-binary
shk scan . --follow-symlinks
shk scan --staged
shk scan --git-history
shk scan --git-history --preview
shk scan --git-history --ref HEAD~50..HEAD
shk scan --git-history --since 30.days.ago
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
| `--git-history` | Scan committed Git history reachable from refs. Reports paths as `<commit>:<path>`. |
| `--preview` | With `--git-history`, print candidate commit/path/blob counts and sample paths without scanning blob contents. |
| `--ref <rev>` | With `--git-history`, scan a Git revision or revision range instead of `--all`, e.g. `main` or `HEAD~50..HEAD`. |
| `--since <date>` | With `--git-history`, limit history to commits newer than a Git date expression, e.g. `30.days.ago` or `2026-01-01`. |
| `--max-commits <n>` | With `--git-history`, limit history traversal to the most recent `n` commits in the selected scope. |
| `--no-color` | Disable colored human-readable output. This is a global option. |

`--git-history` scans committed blobs from Git history, not the working tree or index. By default it uses `git log --all`, so local branches, tags, and remote-tracking refs are considered. Deleted secrets can still be detected because the older blob is read from the commit where the file existed. Uncommitted changes and unreachable objects are not scanned.

Use `--preview` before a broad history scan to see the selected scope, candidate commit/path counts, unique blob count, policy-filtered blob count, and up to 10 sample `<commit>:<path>` labels. With `--json`, preview emits the same metadata as machine-readable JSON and exits `0`.

Document scan notes:

- Office findings are labelled as `<file>:<internal-entry>`, for example `report.docx:word/document.xml` or `workbook.xlsx:xl/sharedStrings.xml`. Use the same label in `[[allowlist]].path` when suppressing a finding by path.
- PDF findings are labelled with the PDF file path itself, for example `report.pdf`.
- PDF support uses the embedded text layer. Image-only PDFs are not OCRed; they produce `scan.document_text_empty` when no extractable text is found.

Exit codes:

| Code | Meaning |
|------|---------|
| `0` | No findings at or above the active threshold, or command completed successfully. |
| `1` | Scan findings met or exceeded the active threshold. |
| `2` | Blocking AI pre-hook triggered, or a Git-specific scan mode was run outside a Git repository. |

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
shk mask report.docx --output report.redacted.docx
shk mask --json < prompt.txt
shk mask --redaction match < prompt.txt
shk mask --redaction partial < prompt.txt
shk mask --min-severity medium < prompt.txt
shk mask --hook-mode cursor < payload.json
```

Options:

| Option | Behavior |
|--------|----------|
| `FILE` | Optional input file. If omitted, stdin is used. |
| `--json` | Print masked content and findings as JSON. |
| `--output <path>` | Write masked content to a file. Requires `shk.toml`. |
| `--redaction full` | Replace any line containing a finding with `[REDACTED_LINE]`. |
| `--redaction match` | Replace only matched values with `[REDACTED]` (default). |
| `--redaction partial` | Replace matched values and preserve the configured prefix/suffix. |
| `--min-severity <severity>` | Override `[mask].min_severity` for this run. Defaults to `medium`. |
| `--hook-mode <tool>` | Read a hook payload from stdin and print tool-specific masked hook output. |
| `--post` | Post-tool hook mode. Requires `--hook-mode <tool>`. |

When no `FILE` is provided, `shk mask` reads stdin until EOF. In an interactive
terminal, run it with input redirection (`shk mask < prompt.txt`) or provide a
file path (`shk mask prompt.txt`).

`mask --output` refuses sensitive env files and protected home configuration files. Binary or non-UTF-8 input is passed through unchanged in human-readable output and reported as `mask.binary_passthrough` in JSON output.

Office document masking supports `.docx`, `.xlsx`, and `.pptx` files and always requires `--output` so the original document is left unchanged. JSON output reports `[DOCUMENT_WRITTEN]` as `masked_content` and includes findings from the rewritten document. PDF masking is not supported; use `shk scan` to detect text-layer PDF findings and convert or redact PDFs with a dedicated PDF tool.

## `shk doctor`

Run project diagnostics.

```bash
shk doctor
shk doctor --json
```

`shk doctor` runs the available diagnostics for the current directory. The full check includes Git hooks, managed AI hooks, ignore coverage, plaintext env files, and npm/package-manager supply-chain hardening when `package.json` is present.

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

`.env.example`, dotenvx-encrypted env files, and `shk env encrypt` output files are excluded from the plaintext env file warning. If an encrypted env file contains newly added or edited plaintext values, `doctor env` reports the plaintext key names and recommends re-running `shk env encrypt <file> --in-place`. With `--dotenvx`, the diagnostic also reports known dotenvx artifact files such as `.env.keys` and `.env.vault`.

### `shk doctor version`

Check the latest GitHub release version.

```bash
shk doctor version
shk doctor --json version
```

This command reports whether an update is available. It does not modify the installed binary.

## `shk env encrypt` / `shk env decrypt`

Encrypt and decrypt dotenv payloads with `shk` native encryption. This is separate from the external dotenvx command integration: dotenvx support remains available under `shk env dotenvx`, while native encryption lets `shk` operate without an external dotenv encryption tool.

```bash
shk env encrypt .env --in-place
shk env run -- npm test
shk env key import
shk env key export --instructions
shk env decrypt .env --output .env.local
shk env encrypt .env --output .env.shk
shk env encrypt .env.production --env production --output .env.production.shk
shk env run -f .env.production --env production -- npm start
shk env decrypt .env.production.shk --env production --output .env.production.local
```

The encryption key pair is generated per project and environment label, with the public key written to the `.env` file as `DOTENV_PUBLIC_KEY*` and the private key stored in the operating system credential store as `DOTENV_PRIVATE_KEY*`. Values are written as `KEY="encrypted:..."`, preserving key names and the dotenv file shape. Use `--in-place` on `encrypt` to keep the `.env` filename while replacing plaintext values with encrypted values. Use `--output` to write a separate encrypted file instead. Existing output files are refused unless `--force` is passed. `decrypt` always requires `--output` so plaintext is not written to stdout accidentally. Prefer `shk env run` for day-to-day use: it decrypts values in memory and injects only the resulting application variables into the child process.

Files written by `shk env encrypt` include a comment-only `[SHK_NATIVE_ENV]` header before the `DOTENV_PUBLIC_KEY*` block. This makes native `shk` output recognizable when reading the file, while preserving the existing encrypted dotenv value shape.

To add or update a variable in an encrypted env file, edit the line as plaintext, then immediately re-run encryption:

```bash
# Add or edit lines in .env, for example NEW_API_KEY=...
shk env encrypt .env --in-place
shk doctor env
```

Existing `encrypted:` values are left encrypted, and only plaintext values are encrypted on the next `encrypt` run. `doctor env` warns when an encrypted env file still contains plaintext keys, which helps catch a missed re-encryption step before commit or release.

For existing dotenvx users, import keys once and then switch the runtime command:

```bash
shk env dotenvx import-keys .env.keys
shk env run -f .env -- npm test
```

`shk env run`, `decrypt`, and `encrypt` first use native `shk` keys. If none exist, they can reuse imported dotenvx `DOTENV_PRIVATE_KEY*` values from the OS credential store, derive the public key when needed, and attempt to adopt the key into the native store. This keeps existing dotenvx-encrypted files usable while removing the external `dotenvx` binary from the normal execution path. After a native command reports that the imported key was adopted, the imported dotenvx copy can be removed with `shk env dotenvx delete --all` if the project no longer needs `shk env dotenvx run`. If adoption prints a warning, keep the imported dotenvx copy or import the key with `shk env key import`.

| Option | Meaning |
|--------|---------|
| `--output <file>` | Destination file. Required unless `encrypt --in-place` is used. |
| `--in-place` | Encrypt only: replace the source file contents with encrypted data. |
| `--env <name>` | Use `DOTENV_PRIVATE_KEY_<NAME>` and `DOTENV_PUBLIC_KEY_<NAME>`. Use `default` for `DOTENV_PRIVATE_KEY` / `DOTENV_PUBLIC_KEY`. Defaults to `default`. |
| `--key <DOTENV_PRIVATE_KEY*>` | Use an exact private key variable name instead of deriving one from `--env`. |
| `--force` | Overwrite an existing output file. |
| `--remove-source` | Encrypt only: delete the plaintext source file after successful encryption. |

`shk env run` accepts `-f, --file <file>` repeatedly and defaults to `.env` when no file is provided. It uses the default project key unless `--env` or `--key` is supplied. Unlike `shk env dotenvx run`, it does not invoke an external `dotenvx` binary and does not pass `DOTENV_PRIVATE_KEY*` into the child process.

## `shk env key`

Register local decryption keys and show safe team handoff instructions without committing `.env.keys`.

```bash
shk env key import
shk env key import --env production --stdin
shk env key import --key DOTENV_PRIVATE_KEY_STAGING --force
shk env key list
shk env key delete --env staging
shk env key delete --all
shk env key export --env production --instructions
```

`import` stores one `DOTENV_PRIVATE_KEY*` value in the native `shk` OS credential store for the current project. Without `--stdin`, it prompts for the key without echoing input. With `--stdin`, it can read from a password manager CLI:

```bash
op read "op://Project/prod/DOTENV_PRIVATE_KEY_PRODUCTION" \
  | shk env key import --env production --stdin
```

`list` prints only native key names indexed for the current project, never key material. `delete` removes stored native keys and requires an explicit target: `--all`, `--key <DOTENV_PRIVATE_KEY*>`, or `--env <name>`. Keys created by older versions that are not indexed can still be removed with an exact `--key` or `--env` target.

`export --instructions` intentionally does not print raw key material. It prints the key name, whether a key is already present on this machine, and a recommended local handoff flow: store the key in a team password manager, share vault access with the teammate, and have the recipient run `shk env key import`.

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

There is intentionally no raw-key export under `shk env dotenvx` because printing or writing raw private keys defeats the purpose of moving `.env.keys` into the OS credential store. Use `shk env key export --instructions` for safe handoff guidance that does not print key material.

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

In pre-hook mode, `shk` also runs an action guard before content scanning. It blocks sensitive file access, environment dump commands, destructive filesystem operations, direct database mutation commands, privilege or system changes, external transfer commands, and package manager operations when they are visible in the hook payload. Tune this with `[action_guard]` in `shk.toml`; `--audit` remains non-blocking.

## `shk ci init github`

Generate a GitHub Actions workflow that installs `shk` from the bundled cargo-dist installer and runs `shk scan` on every pull request and push to `main`.

```bash
shk ci init github
shk ci init github --dry-run
shk ci init github --mode audit
shk ci init github --fail-on critical
shk ci init github --shk-version v0.3.1
shk ci init github --output .github/workflows/security.yml --force
```

Options:

| Option | Behavior |
|--------|----------|
| `--mode <blocking|audit>` | `blocking` (default) fails the workflow when findings meet `--fail-on`. `audit` always exits `0` and is intended for non-blocking adoption. |
| `--fail-on <severity>` | Severity threshold for blocking mode. Valid values: `info`, `low`, `medium`, `high` (default), `critical`. Ignored under `--mode audit` (a warning is printed). |
| `--path <path>` | Path passed to `shk scan`. Defaults to `.`. |
| `--repo <owner/name>` | GitHub repository hosting `shk` releases. Defaults to `Kazuki-tam/security-harness-kit`. |
| `--shk-version <version>` | Release version to install. Accepts `latest` (default) or a SemVer-ish tag such as `v0.3.0`. |
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
