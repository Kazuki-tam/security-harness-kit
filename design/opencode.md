# OpenCode integration (design review, pre-implementation)

Internal design for `shk hooks install-ai --tool opencode`. Public docs will
live in `docs/commands.md` once implemented. This file is out of the public
wording check.

## Status

Design review of the initial proposal, verified against OpenCode sources
(`anomalyco/opencode`, tag `v1.19.0` released 2026-10-11, and branch `dev`).
Nothing is implemented yet. Section 9 lists the PoC gates that must pass
before the implementation PR.

## 1. Facts established from OpenCode sources

These change the original proposal, so they come first.

### 1.1 Two plugin APIs, two install channels, both live

| | V1 (`opencode-ai` 1.19.0) | V2 (`@opencode/cli` 2.0.29) |
|---|---|---|
| Channel | GitHub releases, `brew install opencode`, `npm i -g opencode-ai`, docs at `opencode.ai/docs` | `curl -fsSL https://opencode.ai/v2/install \| bash`, `brew install anomalyco/tap/opencode-v2`, AUR `opencode-beta`, `ghcr.io/anomalyco/opencode:2.x`, docs at `opencode.ai/v2/docs`; built from `dev`, published near-daily (2.0.29 on 2026-10-14) |
| Package | `@opencode-ai/plugin` 1.19.0 | `@opencode/plugin` 2.0.29 |
| Entry | module exports `async ({ client, project, directory, worktree, $ }) => Hooks` | `export default Plugin.define({ id, setup(ctx) })` |
| Config key | `plugin: [...]` | `plugins: [...]` |
| Pre-tool hook | `"tool.execute.before"(input: {tool, sessionID, callID}, output: {args})` | `ctx.tool.hook("execute.before", (event: {tool, sessionID, agent, messageID, id, input}))` |
| Post-tool hook | `"tool.execute.after"(input: {tool, sessionID, callID, args}, output: {title, output, metadata})` | `ctx.tool.hook("execute.after", event)` with `event.result` (completed) or `event.error` |
| Prompt hook | `"chat.message"(input, output: {message, parts})` | `ctx.session.hook("prompt", event)`; `event.prompt.text` is mutable, **no rejection API** |
| Permission hook | `"permission.ask"(input, output: {status})` | `ctx.permission.hook("evaluate", event)`; `event.effect` mutable |

Neither runtime runs the other's implementation:

- V2 (`packages/core/src/plugin/module.ts`) decodes the default export as
  `{ id, setup }` or `{ id, effect }`; a V1 function export fails with
  "Plugin must export a default definition with an id and an effect or setup
  function."
- V1 (`packages/opencode/src/plugin/shared.ts`, `readV1Plugin`) requires
  `server()` on an object export; a V2-only `{ id, setup }` object throws
  `must default export an object with server()`. The V1 loader then only
  logs the error — the session-error publish is commented out — so a V2-only
  file on a 1.x install is a **silent fail-open**.

Both runtimes accept one object carrying `id`, `setup()` and `server()`; V2
ignores `server()`, V1 (>= 1.18.29) ignores `setup()`. The dual-export shape
is documented by OpenCode and is the only way one managed file works on both
channels. `Plugin.define` is `return plugin` (identity), so no import from
`@opencode/plugin` is needed to produce a valid V2 definition.

### 1.2a V2 runtime facts (verified on `dev`, `packages/core/src`)

- `ctx.tool.hook("execute.before")`: a rejected callback is wrapped into
  `Tool.Error` and fails that call alone; the tool does not run and the model
  sees the message (`plugin/src/promise/adapter.ts`, `core/src/tool.ts`).
  This is the documented block primitive. `event.input` is mutable (pre-tool
  rewrite is possible).
- `execute.after` and `session.hook("prompt")` callbacks are adapted with
  `Effect.promise`: a rejection is a **defect**, not a typed failure. shk must
  never throw in those hooks. Prompt blocking in V2 is text rewrite only.
- MCP tools are added to the same registry via `tools.transform(editor.add)`
  (`core/src/tool/mcp.ts`) and the code-mode `execute` tool calls
  `beforeExecute` per inner tool, so every execution path hits the hook.
- The hook service is a location node (`makeLocationNode`): hooks registered
  by a plugin instance fire only for that location, so `ctx.location.directory`
  is the scan root.
- Local discovery admits direct `.js`/`.ts` files under `.opencode/plugins/`
  (`core/src/plugin/source-directory.ts`); "legacy auto-discovery still
  admits standalone server sources".

### 1.2 Hook mechanics (verified in `packages/opencode/src`)

- `Plugin.trigger` awaits every registered hook inline, sequentially. There is
  **no timeout** and **no error catch** around hooks. shk must impose its own
  timeout.
- A rejection from `tool.execute.before` propagates out of the AI SDK tool's
  `execute`, the processor records a `tool-error` part, and the model receives
  the error message as the tool result. The tool never ran. This is the block
  primitive.
- The same wrapper is used for registry tools (`bash`, `read`, `write`,
  `edit`, `glob`, `grep`, `webfetch`, `task`, ...), for MCP tools (keyed by the
  sanitized `server_tool` name), for the MCP resource tools, and for the
  subtask path. Subagent sessions resolve tools through the same function, so
  their calls are hooked too.
- `tool.execute.after` receives the output object that is returned to the AI
  SDK. Assigning `output.output` changes what the model sees. Output
  replacement (masking) is therefore possible, unlike Windsurf/Antigravity.
- `chat.message` fires inside `createUserMessage` **before** the message and
  parts are validated and persisted. A rejection aborts admission; the prompt
  is not stored. The TUI will see a request failure (UX to be confirmed in
  the PoC). `output.parts` is mutable, so text can also be rewritten.
- Plugin instances are per project directory (`InstanceState`). `directory`
  and `worktree` passed at load time are the correct scan roots.
- Hooks run inside the OpenCode server process (Bun). Many tool calls run
  concurrently (parallel tool calls, subagents); each hook invocation is
  independent.

### 1.3 Discovery, config, skills

- Local plugins are auto-discovered from `.opencode/plugins/` (project) and
  `~/.config/opencode/plugins/` (global). `.opencode/plugin/` (singular) also
  works. **No `opencode.json` edit is required.** OpenCode also
  background-installs `@opencode-ai/plugin` into each `.opencode` directory
  and writes a `.gitignore` there (PoC gate 10 checks it does not ignore
  `plugins/`).
- `opencode.json` / `opencode.jsonc` (project root, walks up to the git
  root) and `~/.config/opencode/opencode.json`. JSONC is accepted, which
  matters for `shk mcp audit`.
- `permission` config supports `read`/`edit`/`bash`/`webfetch`/... with glob
  rules and `allow|ask|deny`; the default already denies `read` of `*.env`
  except `*.env.example`.
- Skills are read from `.opencode/skills/`, `.claude/skills/`, and
  `.agents/skills/` (project), and `~/.config/opencode/skills/`,
  `~/.claude/skills/`, `~/.agents/skills/` (global). The existing
  `.agents/skills/shk/SKILL.md` destination already covers OpenCode. No new
  skill path is needed.

## 2. Review of the original proposal

| Proposal item | Verdict | Change |
|---|---|---|
| Generate a thin JS file; all decisions stay in Rust | Keep | Protocol formalized in section 4. |
| File at `.opencode/plugins/shk.js` | Keep, rename | `.opencode/plugins/shk-security.js`, matching the Copilot/Grok whole-file ownership model. |
| Throw when exit code is 2 | Keep | Also throw on timeout, spawn failure, and malformed stdout in blocking mode (section 5). |
| Throw when shk is missing | Keep, with mitigation | The OpenCode desktop app and GUI launches do not inherit the shell `PATH`. Add binary resolution fallbacks and an init-time warning (section 5.2). |
| Single plugin API | **Gap** | Both channels are live and incompatible. Target V2 as the primary implementation and keep a V1 `server()` compat layer in the same file (section 3.2). |
| No timeout handling | **Gap** | OpenCode has none; 30 s self-imposed, then kill and deny. |
| Deny reason content | **Gap** | The thrown message is persisted in the session DB and shown to the model. Reasons must stay metadata-only (rule ids, counts), never echo payload text. |
| Tamper/drift detection | **Gap** | The managed file is executable code committed to the repo. `shk doctor` must detect drift from the embedded template (section 6.3). |
| Skill under `.opencode/skills` | Not needed | OpenCode reads `.agents/skills`. `SkillTool::Opencode` becomes an alias of the Codex/Cursor destination. |
| Open question: subagent and MCP coverage | Answered | Covered by the shared wrapper (1.2). PoC gates 3 and 4 confirm at runtime. |
| Open question: post-hook masking | Answered | Possible via `output.output`; scheduled as Phase 2. |
| Open question: prompt blocking | Answered with caveat | V1: rejection works pre-persist. V2: no rejection API, text rewrite only. |

## 3. Managed artifact

### 3.1 Location and ownership

| Install | Path |
|---|---|
| project | `.opencode/plugins/shk-security.js` |
| `--global` | `~/.config/opencode/plugins/shk-security.js` |

The file is wholly owned by shk (same model as `.github/hooks/shk-security.json`
and `.grok/hooks/shk-security.json`): install writes it atomically, re-install
overwrites it, remove deletes it. Nothing is merged. A file at that path
without the managed header is never overwritten or deleted; install reports
it and exits non-zero.

Both install scopes write the identical file: the project root is known at
runtime (`directory`), so no embedded path or environment variable is needed.
`AiTool::project_dir_env` returns `None`.

### 3.2 Template rules

The template is embedded with `include_str!` from
`crates/shk-cli/src/hooks/opencode_plugin.js` and rendered with a small
configuration block substituted at install time.

- Plain ESM JavaScript. No TypeScript, no imports from `@opencode-ai/plugin`
  or `@opencode/plugin` (those packages are installed asynchronously by
  OpenCode and may be missing). Only `node:` built-ins, which Bun provides.
- Dual export, V2 primary:

  ```js
  // shk-managed: generated by `shk hooks install-ai --tool opencode`; do not edit.
  // shk-template: 1  (used by `shk doctor` to detect drift)
  const CONFIG = { audit: false, logBlocked: true, timeoutMs: 30000 };
  const run = (directory, event, payload) => { /* spawn shk, parse, decide */ };
  export default {
    id: "shk",
    async setup(ctx) {                                   // V2 runtime (primary)
      const dir = ctx.location.directory;
      await ctx.tool.hook("execute.before", (e) => run(dir, "pre", { tool: e.tool, input: e.input, sessionID: e.sessionID }));
      await ctx.tool.hook("execute.after", (e) => run(dir, "post", ...));     // never throws
      await ctx.session.hook("prompt", (e) => run(dir, "prompt", ...));       // rewrites e.prompt.text, never throws
    },
    async server({ directory, client }) {                // V1 compat (1.18.29+)
      return { "tool.execute.before": ..., "tool.execute.after": ..., "chat.message": ... };
    },
  };
  ```

  Both halves share `run`; the V1 half is ~40 lines of adapter code. V2 is
  the primary target because new development and the daily release train
  are on that channel; `server()` exists so a 1.x install never fails open
  silently (1.2a). Dropping `server()` later is a template-version bump.
- Detection string for `doctor` and the desktop app: the file contains
  `--hook-mode opencode`, consistent with how Copilot/Grok/Windsurf managed
  entries are recognized.
- No `eval`, no network, no file writes. The payload is never logged. The
  file must be short enough to review in a PR diff (target < 200 lines).

## 4. Plugin ↔ shk protocol

The plugin normalizes OpenCode's hook arguments into the envelope shk already
understands (`hook_event_name`, `tool_name`, `tool_input`, `cwd`), so the Rust
side needs only key additions, not a new parser.

| Event | Command | stdin |
|---|---|---|
| pre-tool | `shk scan <directory> --hook-mode opencode [--audit\|--log-blocked]` | `{"hook_event_name":"PreToolUse","tool_name":<tool>,"tool_input":<args>,"session_id":...,"call_id":...,"cwd":<directory>}` |
| post-tool | same + `--post` | `{"hook_event_name":"PostToolUse","tool_name":...,"tool_input":<args>,"tool_output":{"title":...,"output":...}}` (metadata omitted) |
| prompt | same + `--fail-on medium` | `{"hook_event_name":"UserPromptSubmit","prompt":<text parts joined>,"session_id":...,"cwd":...}` |

Rust-side key coverage (verified against `ai_hooks.rs` / `action_guard.rs`):

- `read`/`write`/`edit` use `filePath` → already in `PATH_KEYS` and
  `TARGET_PATH_KEYS`; `read` scans the file body from disk before the model
  sees it.
- `bash` uses `command` → already a command key for the action guard and a
  pre text key.
- `write.content`, `webfetch.url`, `task.prompt` → already pre text keys.
- New: `OPENCODE_PRE_EXTRA_TEXT_KEYS = ["tool_input", "oldString", "newString"]`
  (deep-scan arbitrary MCP arguments, like Grok's `toolInput`).
- New: `OPENCODE_POST_TEXT_KEYS = ["tool_output", "output", "title"]`.
- `access_kind_for_path` sniffs `read`/`write`/`edit` words; OpenCode tool
  names satisfy it.
- `cwd` is plugin-controlled here (not model-controlled), but it is still only
  used for action-guard policy roots; the scan root is the explicit path
  argument.

Stdout contract (`hook_output.rs`, `AiTool::Opencode`), reusing the
`decision_json` shape shared with Antigravity/Grok:

| Outcome | exit | stdout |
|---|---|---|
| allow | 0 | `{"decision":"allow"}` (+ `"reason"` for audit notes) |
| deny (pre) | 2 | `{"decision":"deny","reason":"<metadata-only>"}` + reason on stderr |
| block (prompt) | 2 | `{"decision":"block","reason":"..."}` |
| post | 0 | `{"decision":"allow"}`; Phase 2 adds `"masked_output"` |

Payload cap: the plugin truncates `tool_input`/`tool_output` strings to keep
stdin under 4 MiB and sets `"truncated": true`; shk's `MAX_HOOK_TEXT_BYTES`
(2 MiB) bounds the scan.

## 5. Failure policy and process handling

### 5.1 Decision table

| Condition | pre-tool (blocking) | pre-tool `--audit`, post-tool |
|---|---|---|
| exit 0, valid JSON | allow (apply `masked_output` in Phase 2) | allow |
| exit 2 | throw `Error("shk: " + reason)` | allow, log |
| other exit / malformed stdout | throw (fail-closed) | allow, log |
| spawn `ENOENT` | throw with install hint | allow, log once |
| timeout (30 s) | kill, throw | kill, allow, log |

This matches the repository policy already documented for the other tools
(pre hooks fail closed, audit and post hooks fail open) in
[hook-exit-code-policy]. The thrown message is what the model and the
session history see, so it carries only shk's metadata reason.

### 5.2 Binary resolution

Order: `SHK_BIN` env (absolute path) → `shk` on the process `PATH` →
well-known locations (`~/.local/bin`, `~/.cargo/bin`, `/opt/homebrew/bin`,
`/usr/local/bin`; `shk.exe` via `PATHEXT` on Windows). Resolved once at load,
re-resolved after `ENOENT`. At load time, if nothing resolves, the plugin
logs a warning through `client.app.log` (V1) so the user sees the problem
before the first blocked call. The GUI-launched desktop app is the motivating
case.

### 5.3 Spawn rules

`child_process.spawn(bin, args, { cwd: directory, shell: false, windowsHide: true, stdio: ["pipe","pipe","pipe"] })`.
Arguments are fixed strings plus `directory`; tool arguments travel only on
stdin. Concurrency is unbounded (one short-lived process per hook, as with
every other tool's hooks).

### 5.4 Prompt hook

- V2 (primary): rewrite `event.prompt.text` to the block notice. There is no
  rejection API and a rejection is a defect (1.2a), so the hook never throws.
  The rewritten notice becomes the persisted user input; the original text
  is never stored.
- V1: scan the joined text parts. On block, replace every text part with the
  block notice, then throw (the rejection aborts admission pre-persist).
  PoC gate 5 decides whether the resulting TUI error is acceptable or whether
  rewrite-only (matching V2) is the better UX.

### 5.5 V2 hook rules

- `execute.before` is the only hook that may reject; the adapter wraps the
  error in `Tool.Error`. Use a plain `Error` with the metadata-only reason.
- `execute.after` and `prompt` callbacks must resolve; wrap the body in
  try/catch and log through `ctx.app`/`console.error`.
- File attachments (`data:` URIs in `file` parts) are not scanned in Phase 1;
  tracked as Phase 2.

## 6. Rust-side changes

Mirrors the Grok integration (commit `4b7d22a`, 29 files), plus the template
and its test.

| Area | Change |
|---|---|
| `args.rs` | `AiTool::Opencode` (`"opencode"`, `project_dir_env = None`), `SkillToolArg::Opencode`. |
| `shk-integrations/ai_hooks.rs` | `AiHookTool::Opencode`, `<opencode-hook>` label, the two key sets in section 4, unit tests for `read`/`bash`/`edit`/MCP/post payloads. |
| `hooks/ai.rs` | `ai_config_relative_path` / global path, `apply_opencode` (render template, header check, atomic write), `remove_opencode_scan_hooks` (delete only when header present), `ConfigureAiOptions.scan_hooks_opencode`, tool lists. |
| `hook_output.rs` | `AiTool::Opencode` arms (section 4 stdout table). |
| `commands/scan.rs` | stderr reason emission for `Opencode`; default exit 2 already applies. |
| `doctor.rs` | path in `has_managed_ai_hooks`; drift check (6.3). |
| `desktop_api.rs` | `scan_hooks_opencode`, status row, `has_managed_hook_marker` for `--hook-mode opencode`, recommended-fix text. |
| `commands/init.rs` | prompt choice "OpenCode"; include in the `--yes` default set (consistent with the other tools; the file is inert where OpenCode is not used). |
| `commands/skills.rs` | `SkillTool::Opencode` → `.agents/skills/shk/SKILL.md` (global `~/.agents/skills/`), collapsing with Codex/Cursor. |
| `mcp_audit.rs` | Phase 2: `("opencode", "opencode.json" \| "opencode.jsonc", Format::JsonOpencode)` reading the `mcp` key (`type: local` → `command[]`, `environment`; `type: remote` → `url`, `headers`). Needs a JSONC-tolerant parse; `serde_json` alone is not enough. |
| Desktop app | `types.ts`, `setup/plan.ts`, `ProjectSetupPanel.tsx`, i18n `en`/`ja`, tests. |
| Docs | `docs/commands.md` (install-ai table, hook-mode list, skills table), `docs/installation.md` (uninstall tables), `README.md`, `crates/shk-cli/src/skills/shk.md` and its four copies, `AGENTS.md` tool list. |

### 6.1 Install / remove behavior

- `shk hooks install-ai --tool opencode [--global] [--audit] [--log-blocked] [--dry-run]`.
  Non-dry-run requires `shk.toml` (existing rule). Summary line:
  `<path>: wrote managed OpenCode plugin (template=1, audit=…, logBlocked=…)`.
- Idempotent: re-running rewrites the same bytes.
- Remove: deletes the file; refuses when the header is absent.
- `safety::ensure_write_path_within` guards the write as for other tools.

### 6.2 Tests

- Unit tests in `ai_hooks.rs` and `hook_output.rs` as for Grok.
- Smoke tests: install idempotency, header refusal, `--hook-mode opencode`
  deny/allow/prompt through the CLI.
- **Contract test for the JS template**: a smoke test that runs the generated
  plugin under `node` (ESM, Node >= 22) with a fake V2 context
  (`{ location: { directory }, tool: { hook }, session: { hook }, app }`)
  that captures the registered callbacks, invokes `execute.before` with a
  fixture path containing a synthetic secret, and asserts the rejection; then
  an allow case; then the same two cases through `server()` with a fake V1
  input (`{ directory, worktree, client: { app: { log } } }`). Skips when `node` is not on
  `PATH` locally; required in CI (the desktop jobs already provision Node).
  This is the only automated protection for the JS half.

### 6.3 Doctor drift check

`shk doctor` renders the expected file from the embedded template using the
options recorded in the file's `CONFIG` block and compares bytes. Mismatch →
advisory warning "managed OpenCode plugin differs from template (modified or
stale); rerun `shk hooks install-ai --tool opencode`" (`--strict` fails).
This is the tamper/staleness control for a committed, executable artifact.
Later, a check of `opencode --version` major against the template's supported
API versions can be added without changing the file format.

## 7. What is intentionally not in Phase 1

- `tool.execute.after` output replacement (`masked_output`) — Phase 2, after
  PoC gate 6 confirms the model sees the mutated output.
- Prompt attachment scanning — Phase 2.
- `shk mcp audit` client for `opencode.json(c)` — Phase 2 (JSONC parser).
- `--apply-deny` equivalent (merge recommended `permission` rules into
  `opencode.json(c)`) — later; editing JSONC while preserving comments is
  non-trivial, so the first version would print guidance like Antigravity.
- `permission.ask` / `permission.hook("evaluate")` as a second enforcement
  layer — not needed while `tool.execute.before` covers every tool.
- A per-tool skip list — not in Phase 1; uniform coverage matches
  Grok/Antigravity. Add only if PoC gate 7 shows unacceptable overhead.

## 8. Open decisions

1. V2 primary + V1 `server()` compat in one file (recommended) vs V2-only.
   V2-only is simpler but fails open silently on every 1.x install (1.2a),
   and 1.x is still the default `brew install opencode` / `opencode.ai/docs`
   channel.
2. Prompt block UX in V1: throw (hard stop, TUI error) vs rewrite-only. Decide
   from PoC gate 5.
3. Include `opencode` in the `shk init --yes` default tool set (recommended
   for consistency; the file is inert without OpenCode).
4. JSONC dependency for `mcp audit` (Phase 2).

## 9. PoC gates (all must pass before the implementation PR)

Run with the hand-written template at `.opencode/plugins/shk-security.js` in
a throwaway project with `shk.toml` and the `fixtures/` secrets. Gates 1–8
and 10–12 run on V2 (`@opencode/cli` 2.0.x via `opencode.ai/v2/install`);
gate 9 covers the V1 compat half.

1. OpenCode 2.0.x loads the plugin (`opencode plugin list`); a `read` of a
   fixture with a synthetic secret yields a tool error carrying shk's reason,
   and the file content does not appear in the persisted session parts.
2. `bash` with `cat .env` is denied by the action guard.
3. An MCP tool call is hooked under its `server_tool` name and its arguments
   are scanned.
4. A `task` subagent's own tool calls are hooked.
5. Prompt hook: on V2 the rewritten text is what gets persisted and sent; on
   V1 record the TUI behavior of the rejection and choose throw vs rewrite.
6. Mutating `event.result.output` (V2) / `output.output` (V1) in the after
   hook changes the text in the model's next request.
7. Hook overhead: p50 < 100 ms per call with a warm binary; record p95.
8. Desktop app launch: `shk` resolution works via fallbacks, or the load-time
   warning is visible.
9. OpenCode `1.19.x` loads the same file through `server()` (listed in
   `/status`) and gates 1–3 pass; a V2-only variant of the file is confirmed
   to load silently with no hooks (documents why `server()` stays).
10. The `.opencode/.gitignore` written by OpenCode does not ignore `plugins/`.
11. Windows: `shk.exe` resolution and spawn without a shell.
12. Slash commands (`command.execute.before`) still pass through
    `chat.message`, or document the gap.
