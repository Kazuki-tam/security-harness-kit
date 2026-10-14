//! Parse AI tool stdin JSON payloads (MVP heuristic; spec §7.9).

use crate::hook_payload::decode_encoded_arguments;
use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::Value;
use std::borrow::Cow;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Fail threshold embedded in managed user-prompt hook install commands.
pub const USER_PROMPT_HOOK_FAIL_ON: &str = "medium";

const PATH_KEYS: &[&str] = &[
    "path",
    "file_path",
    "filePath",
    "target_file",
    "targetPath",
    "uri",
    "fileName",
];
const ANTIGRAVITY_PATH_KEYS: &[&str] = &[
    "AbsolutePath",
    "TargetFile",
    "SearchPath",
    "DirectoryPath",
    "SearchDirectory",
];
// Non-Antigravity hooks still accept legacy `*path` payload heuristics. Keep
// known metadata keys out of file reads so hook logs/transcripts are not scanned
// as if they were the current tool input.
const METADATA_PATH_KEYS: &[&str] = &[
    "artifactDirectoryPath",
    "transcriptPath",
    "workspacePath",
    "workspacePaths",
];
const MAX_HOOK_TEXT_BYTES: usize = 4096 * 512;
// Bytes of file body that applying pre-hook edits may search and rewrite.
// Well under a second of work, far below the installed hook timeouts.
const MAX_EDIT_WORK_BYTES: usize = 64 * MAX_HOOK_TEXT_BYTES;
const PRE_TEXT_KEYS: &[&str] = &[
    "prompt", "text", "content", "command", "stdin", "args", "url",
];
// Replace-style edit arguments as (old, new) key pairs. Pre hooks apply each
// edit to the target file body read via PATH_KEYS and scan the edited body, so
// inserted text keeps the file's inline `shk-ignore` context and removed text
// no longer blocks. When the target is not read (outside the repo, binary, or
// missing) or `old` is not found, only the new text is scanned. Edits inherit
// the nearest enclosing path key, so nested lists work.
// - Claude Code Edit, MultiEdit `edits[]`; Windsurf `edits[]`: old_string, new_string
// - Copilot CLI edit: old_str, new_str
// - Copilot in VS Code replaceString, multiReplaceString `replacements[]`;
//   OpenCode edit (`replaceAll`): oldString, newString
// - Filesystem MCP server edit_file `edits[]`: oldText, newText
const EDIT_PAIR_KEYS: &[(&str, &str)] = &[
    ("old_string", "new_string"),
    ("old_str", "new_str"),
    ("oldString", "newString"),
    ("oldText", "newText"),
];
// Inserted text without an `old` counterpart. The target file body is read via
// PATH_KEYS, which suppresses the large-string fallback, so these must be named.
// - Claude Code NotebookEdit: new_source
// - Copilot CLI create: file_text
// - Copilot in VS Code editNotebook: newCode
// Codex `apply_patch` sends the patch as `command`, already in PRE_TEXT_KEYS.
const PRE_EDIT_TEXT_KEYS: &[&str] = &["new_source", "file_text", "newCode"];
const CODEX_POST_TEXT_KEYS: &[&str] = &[
    "stdout",
    "stderr",
    "output",
    "result",
    "content",
    "text",
    "body",
    "tool_response",
];
const CLAUDE_POST_TEXT_KEYS: &[&str] = &[
    "stdout", "stderr", "content", "response", "text", "body", "data", "result", "message",
    "messages", "items", "value",
];
// Cursor afterShellExecution payload: { command, output, duration, sandbox };
// afterMCPExecution payload: { tool_name, tool_input, result_json, duration }.
const CURSOR_POST_TEXT_KEYS: &[&str] = &[
    "content",
    "text",
    "command",
    "shell_command",
    "args",
    "output",
    "result_json",
    "tool_input",
];
// Antigravity PreToolUse payload: { toolCall: { name, args: {...} }, ... } with
// PascalCase argument names (run_command, write_to_file, read_url_content, ...).
// These extend the shared PRE_TEXT_KEYS; both sets are scanned for Antigravity.
const ANTIGRAVITY_PRE_EXTRA_TEXT_KEYS: &[&str] = &[
    "CommandLine",
    "CodeContent",
    "TargetContent",
    "ReplacementContent",
    "Url",
    "Prompt",
    "Query",
    "query",
    "domain",
    "Pattern",
    "Action",
    "Target",
    "Reason",
    "Recipient",
    "Description",
    "Includes",
    "Excludes",
    "Extensions",
    "ImagePaths",
    "Input",
    "Message",
    "system_prompt",
    "description",
    "question",
    "options",
];
// Antigravity PostToolUse payload carries no tool output: only `error` plus
// metadata, so only error text is scannable.
const ANTIGRAVITY_POST_TEXT_KEYS: &[&str] = &["error", "output", "result", "content", "text"];
// GitHub Copilot PostToolUse payload carries the tool result under
// `toolResult.textResultForLlm` (camelCase) / `tool_result.text_result_for_llm`
// (VS Code-compatible snake_case). PostToolUseFailure carries `error`.
const COPILOT_POST_TEXT_KEYS: &[&str] = &[
    "textResultForLlm",
    "text_result_for_llm",
    "output",
    "result",
    "content",
    "text",
    "stdout",
    "stderr",
    "error",
];
// Windsurf (Cascade) wraps event data under `tool_info`:
// - pre_run_command / post_run_command: { command_line, cwd }
// - pre_mcp_tool_use: { mcp_server_name, mcp_tool_name, mcp_tool_arguments }
// - pre_user_prompt: { user_prompt }
// - pre_read_code / pre_write_code: { file_path, edits[] } (file body read via PATH_KEYS)
// Write edits[] are covered by EDIT_PAIR_KEYS.
const WINDSURF_PRE_EXTRA_TEXT_KEYS: &[&str] =
    &["command_line", "user_prompt", "mcp_tool_arguments"];
// post_mcp_tool_use carries the tool output under `mcp_result`; post_run_command
// only carries `command_line` (Cascade omits stdout from the post payload).
const WINDSURF_POST_TEXT_KEYS: &[&str] = &[
    "mcp_result",
    "command_line",
    "output",
    "result",
    "content",
    "text",
];
// Scan every argument value, including arbitrary MCP schemas. Keep this
// scoped to the input envelope so session metadata is not treated as input.
const GROK_PRE_EXTRA_TEXT_KEYS: &[&str] = &["toolInput", "tool_input"];
// PostToolUse output is `toolResult` (not Claude's `tool_response`).
const GROK_POST_TEXT_KEYS: &[&str] = &[
    "toolResult",
    "tool_result",
    "stdout",
    "stderr",
    "output",
    "result",
    "content",
    "text",
    "error",
    "command",
];

// OpenCode's managed plugin normalizes tool arguments under `tool_input`,
// scanned as an argument envelope so every argument is covered, including
// arbitrary MCP arguments. Edit's `oldString`/`newString` pair is applied to
// the file named by `filePath` (resolved through PATH_KEYS) instead.
const OPENCODE_PRE_ENVELOPE_KEYS: &[&str] = &["tool_input"];
// The post payload carries `{ title, output }` under `tool_output`.
const OPENCODE_POST_TEXT_KEYS: &[&str] = &["tool_output", "output", "title"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AiHookTool {
    Antigravity,
    ClaudeCode,
    Codex,
    Copilot,
    Cursor,
    Grok,
    Opencode,
    Windsurf,
}

impl AiHookTool {
    pub fn kebab_str(self) -> &'static str {
        match self {
            Self::Antigravity => "antigravity",
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
            Self::Copilot => "copilot",
            Self::Cursor => "cursor",
            Self::Grok => "grok",
            Self::Opencode => "opencode",
            Self::Windsurf => "windsurf",
        }
    }

    pub fn virtual_path_label(self) -> &'static str {
        match self {
            Self::Antigravity => "<antigravity-hook>",
            Self::ClaudeCode => "<claude-hook>",
            Self::Codex => "<codex-hook>",
            Self::Copilot => "<copilot-hook>",
            Self::Cursor => "<cursor-hook>",
            Self::Grok => "<grok-hook>",
            Self::Opencode => "<opencode-hook>",
            Self::Windsurf => "<windsurf-hook>",
        }
    }
}

/// Extracts the user prompt from a `UserPromptSubmit` JSON payload.
///
/// Recognizes the top-level `prompt` field used by most tools, and falls back
/// to Cascade's (Windsurf) nested `tool_info.user_prompt`.
/// Returns `None` when neither field is present or the payload is not valid JSON.
pub fn extract_user_prompt(stdin: &str) -> Option<Cow<'_, str>> {
    #[derive(Deserialize)]
    struct ToolInfo<'a> {
        #[serde(borrow)]
        user_prompt: Option<Cow<'a, str>>,
    }
    #[derive(Deserialize)]
    struct UserPromptPayload<'a> {
        #[serde(borrow)]
        prompt: Option<Cow<'a, str>>,
        #[serde(borrow, rename = "userPrompt")]
        user_prompt_camel: Option<Cow<'a, str>>,
        #[serde(borrow)]
        user_prompt: Option<Cow<'a, str>>,
        #[serde(borrow)]
        tool_info: Option<ToolInfo<'a>>,
    }

    let payload = serde_json::from_str::<UserPromptPayload<'_>>(stdin).ok()?;
    payload
        .prompt
        .or(payload.user_prompt_camel)
        .or(payload.user_prompt)
        .or_else(|| payload.tool_info.and_then(|info| info.user_prompt))
}

/// Text extracted from a hook payload for scanning.
#[derive(Debug)]
pub struct HookBody {
    /// Display path for findings: the referenced file when the payload names
    /// exactly one, otherwise the tool's virtual label.
    pub display: String,
    pub body: String,
    /// Payload strings were left unscanned because the text budget ran out.
    /// Blocking hooks must not allow such a payload.
    pub truncated: bool,
}

/// Returns display path (posix-ish relative to repo) + body content to scan.
pub fn stdin_to_hook_body(
    tool: AiHookTool,
    post: bool,
    stdin: &str,
    cwd: &Path,
    repo_root: &Path,
) -> Result<(String, String)> {
    hook_body_from_stdin(tool, post, stdin, cwd, repo_root).map(|hook| (hook.display, hook.body))
}

pub fn hook_body_from_stdin(
    tool: AiHookTool,
    post: bool,
    stdin: &str,
    cwd: &Path,
    repo_root: &Path,
) -> Result<HookBody> {
    let raw: Value = serde_json::from_str(stdin).context("hook stdin must be valid JSON")?;
    // Pre hooks look inside JSON-encoded argument envelopes (Copilot CLI
    // `toolArgs`) so paths, edits, and text keys there are found. Post hooks
    // keep the raw payload.
    let mut envelope_keys = Vec::new();
    let decoded = (!post).then(|| {
        let mut decoded = raw.clone();
        envelope_keys = decode_encoded_arguments(&mut decoded);
        decoded
    });
    let v = decoded.as_ref().unwrap_or(&raw);
    if !post {
        for key in pre_envelope_keys(tool) {
            if !envelope_keys.contains(key) {
                envelope_keys.push(key);
            }
        }
    }

    // Post payloads describe edits that already ran; the file body is current.
    let mut edits = Vec::new();
    if !post {
        collect_text_edits(tool, v, None, &mut edits);
    }

    // Referenced files are scanned whole (with pre-hook edits applied) and do
    // not spend the payload budget.
    let files = read_files_from_candidates(tool, v, cwd, repo_root, &mut edits)?;

    let mut texts = HookTexts::default();
    if let Some(files) = &files {
        // A payload string equal to a file body (e.g. Cursor's `content`)
        // is already covered by the file scan.
        texts.seen.extend(files.contents.iter().map(String::as_str));
    }
    text_priority_chunks(v, post, tool, &mut texts);
    for edit in edits.iter().filter(|edit| !edit.applied) {
        texts.push(edit.new);
    }
    // An envelope is the tool's whole argument list. Scan every value in it,
    // so one matching key (or a file read) cannot hide the rest the way it
    // disables the fallback below.
    for key in &envelope_keys {
        if let Some(envelope) = v.get(*key) {
            push_envelope_strings(envelope, &mut texts);
        }
    }

    // The fallback reads the raw payload: an encoded envelope is one long
    // string that keeps its key names, so it clears the size cut more often
    // than any of its decoded values.
    if texts.blobs.is_empty() && files.is_none() {
        collect_large_strings(&raw, &mut texts, 96);
    }

    let parts: Vec<&str> = files
        .as_ref()
        .map(|files| files.body.as_str())
        .into_iter()
        .chain(texts.blobs.iter().copied())
        .collect();
    let body = if parts.is_empty() {
        "{}".into()
    } else {
        parts.join("\n---\n")
    };
    let truncated = texts.truncated;

    Ok(HookBody {
        display: files.map_or_else(|| tool.virtual_path_label().to_string(), |f| f.display),
        body,
        truncated,
    })
}

/// Argument envelopes that are scanned in full in pre hooks even when sent as
/// an object (stringified envelopes are found by `decode_encoded_arguments`).
fn pre_envelope_keys(tool: AiHookTool) -> &'static [&'static str] {
    match tool {
        AiHookTool::Opencode => OPENCODE_PRE_ENVELOPE_KEYS,
        _ => &[],
    }
}

/// Payload strings collected for scanning. Each distinct string is charged
/// once against `MAX_HOOK_TEXT_BYTES` (the same string is often reachable
/// through several keys).
#[derive(Default)]
struct HookTexts<'a> {
    blobs: Vec<&'a str>,
    seen: HashSet<&'a str>,
    used: usize,
    truncated: bool,
}

impl<'a> HookTexts<'a> {
    fn push(&mut self, s: &'a str) {
        if s.trim().is_empty() || !self.seen.insert(s) {
            return;
        }
        // Whether a payload overflows depends only on the total size of its
        // distinct strings, never on the order the keys are visited in.
        if self.used + s.len() > MAX_HOOK_TEXT_BYTES {
            self.truncated = true;
            return;
        }
        self.used += s.len();
        self.blobs.push(s);
    }
}

/// Files referenced by a hook payload, read from disk.
struct ReferencedFiles {
    /// Repo-relative path of the file, or the tool's virtual label when the
    /// payload names several files.
    display: String,
    /// Every file with a `// ---- <path>` header, ready to scan.
    body: String,
    /// The decoded file contents, to recognize payload strings that repeat them.
    contents: Vec<String>,
}

fn rel_from_repo(repo_root: &Path, abs: &Path) -> String {
    abs.strip_prefix(repo_root)
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .unwrap_or_else(|_| abs.to_string_lossy().replace('\\', "/"))
}

/// A replace-style edit found in a pre-hook payload.
struct TextEdit<'a> {
    /// Nearest enclosing file-path argument, as written in the payload.
    path: Option<&'a str>,
    old: &'a str,
    new: &'a str,
    replace_all: bool,
    applied: bool,
}

/// Collects replace-style edits in payload order (arrays keep their order, so
/// MultiEdit `edits[]` apply sequentially). Each edit targets the file-body
/// path key on its own object or the nearest ancestor. An object with several
/// distinct path values is ambiguous: its edits target no file, so their new
/// text is scanned on its own instead of under another file's suppressions.
fn collect_text_edits<'a>(
    tool: AiHookTool,
    v: &'a Value,
    inherited_path: Option<&'a str>,
    out: &mut Vec<TextEdit<'a>>,
) {
    match v {
        Value::Object(map) => {
            let own_paths: HashSet<&str> = map
                .iter()
                .filter(|(key, _)| is_file_body_path_key(tool, key))
                .filter_map(|(_, val)| val.as_str())
                .collect();
            let path = match own_paths.len() {
                0 => inherited_path,
                1 => own_paths.into_iter().next(),
                _ => None,
            };
            for (old_key, new_key) in EDIT_PAIR_KEYS {
                if let (Some(old), Some(new)) = (
                    map.get(*old_key).and_then(Value::as_str),
                    map.get(*new_key).and_then(Value::as_str),
                ) {
                    out.push(TextEdit {
                        path,
                        old,
                        new,
                        replace_all: ["replace_all", "replaceAll"]
                            .iter()
                            .any(|key| map.get(*key).and_then(Value::as_bool) == Some(true)),
                        applied: false,
                    });
                }
            }
            for val in map.values() {
                collect_text_edits(tool, val, path, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_text_edits(tool, item, inherited_path, out);
            }
        }
        _ => {}
    }
}

/// Applies the edits that target `abs` in order, marking each one applied.
/// An edit whose `old` text is empty or missing is left for standalone scanning,
/// as is one that would grow the body past `original_len + MAX_HOOK_TEXT_BYTES`
/// (a `replace_all` of a short `old` can otherwise multiply the body until
/// the hook times out, and a timed-out hook does not block). For the same
/// reason, edits stop being applied once searching and rewriting the body has
/// touched `MAX_EDIT_WORK_BYTES`: each edit costs a pass over the whole body, so
/// a long edit list on a large file would otherwise run past the hook timeout.
fn apply_text_edits(
    text: &mut String,
    abs: &Path,
    edits: &mut [TextEdit<'_>],
    targets: &[Option<PathBuf>],
) {
    let max_len = text.len().saturating_add(MAX_HOOK_TEXT_BYTES);
    let mut work = 0usize;
    for (edit, target) in edits.iter_mut().zip(targets) {
        if target.as_deref() != Some(abs) || edit.old.is_empty() {
            continue;
        }
        // One pass to search, one more to rewrite.
        work = work.saturating_add(text.len().saturating_mul(2));
        if work > MAX_EDIT_WORK_BYTES {
            break;
        }
        let count = if edit.replace_all {
            text.matches(edit.old).count()
        } else {
            usize::from(text.contains(edit.old))
        };
        let growth = edit.new.len().saturating_sub(edit.old.len());
        if count == 0 || text.len().saturating_add(count.saturating_mul(growth)) > max_len {
            continue;
        }
        *text = if edit.replace_all {
            text.replace(edit.old, edit.new)
        } else {
            text.replacen(edit.old, edit.new, 1)
        };
        edit.applied = true;
    }
}

fn read_files_from_candidates(
    tool: AiHookTool,
    v: &Value,
    cwd: &Path,
    repo_root: &Path,
    edits: &mut [TextEdit<'_>],
) -> Result<Option<ReferencedFiles>> {
    let mut texts: Vec<String> = Vec::new();
    let mut contents: Vec<String> = Vec::new();
    let mut label: Option<String> = None;
    let mut seen: HashSet<PathBuf> = HashSet::new();
    let repo_root = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let targets: Vec<Option<PathBuf>> = edits
        .iter()
        .map(|edit| {
            edit.path
                .and_then(|path| fs::canonicalize(resolve_path(path, cwd)).ok())
        })
        .collect();

    for cand in candidate_path_strings(tool, v) {
        let p = resolve_path(&cand, cwd);
        let p = fs::canonicalize(&p).ok();
        if let Some(abs) = p
            && abs.is_file()
            && abs.starts_with(&repo_root)
            && seen.insert(abs.clone())
        {
            let bytes =
                fs::read(&abs).with_context(|| format!("read scanned file {}", abs.display()))?;
            // Match the ordinary scanner's default NUL-in-head heuristic.
            // Do not skip by extension: text disguised as an image still needs
            // scanning. Lossy decoding preserves ASCII secrets in legacy text
            // and binary formats without NUL bytes, without a UTF-8 error.
            if bytes.iter().take(8192).any(|byte| *byte == 0) {
                continue;
            }
            let mut t = String::from_utf8_lossy(&bytes).into_owned();
            apply_text_edits(&mut t, &abs, edits, &targets);
            let rel = rel_from_repo(&repo_root, &abs);
            // The label drives path-scoped policy (allowlist rows, rule path
            // filters) for the whole body, so only a single-file body may use
            // the file's path. Several files get the tool's virtual label.
            match &label {
                None => label = Some(rel.clone()),
                Some(first) if *first != rel => {
                    label = Some(tool.virtual_path_label().to_string());
                }
                Some(_) => {}
            }
            texts.push(format!("// ---- {rel}\n{t}"));
            contents.push(t);
        }
    }

    Ok(if texts.is_empty() {
        None
    } else {
        Some(ReferencedFiles {
            display: label.unwrap_or_else(|| "<file>".into()),
            body: texts.join("\n"),
            contents,
        })
    })
}

fn resolve_path(s: &str, cwd: &Path) -> PathBuf {
    let p = Path::new(s);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        cwd.join(p)
    }
}

fn candidate_path_strings(tool: AiHookTool, v: &Value) -> Vec<String> {
    let mut out = Vec::new();
    scan_path_keys(tool, v, &mut out);
    out.sort_by_key(|s| std::cmp::Reverse(s.len()));
    out.dedup();
    out
}

fn scan_path_keys(tool: AiHookTool, v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(map) => {
            for (k, val) in map {
                if is_file_body_path_key(tool, k)
                    && let Some(s) = val.as_str()
                {
                    out.push(s.to_string());
                }
                scan_path_keys(tool, val, out);
            }
        }
        Value::Array(a) => {
            for i in a {
                scan_path_keys(tool, i, out);
            }
        }
        _ => {}
    }
}

fn is_file_body_path_key(tool: AiHookTool, key: &str) -> bool {
    if tool == AiHookTool::Antigravity {
        // Antigravity install uses matcher `.*`, so file-body reads must be an
        // allowlist of documented tool argument keys. Unknown metadata such as
        // future `sessionLogPath` / `cachePath` fields should not cause an
        // unrelated tool call to scan prior conversation artifacts.
        return ANTIGRAVITY_PATH_KEYS.iter().any(|pk| pk == &key);
    }

    !METADATA_PATH_KEYS.iter().any(|pk| pk == &key)
        && (PATH_KEYS.iter().any(|pk| pk == &key) || key.to_ascii_lowercase().ends_with("path"))
}

fn text_priority_chunks<'a>(v: &'a Value, post: bool, tool: AiHookTool, texts: &mut HookTexts<'a>) {
    for keys in priority_text_key_sets(post, tool) {
        grab_strings_for_keys_deep(v, keys, texts);
    }
}

fn priority_text_key_sets(post: bool, tool: AiHookTool) -> &'static [&'static [&'static str]] {
    if !post {
        return match tool {
            AiHookTool::Antigravity => &[PRE_TEXT_KEYS, ANTIGRAVITY_PRE_EXTRA_TEXT_KEYS],
            AiHookTool::Grok => &[PRE_TEXT_KEYS, GROK_PRE_EXTRA_TEXT_KEYS],
            AiHookTool::Windsurf => &[PRE_TEXT_KEYS, WINDSURF_PRE_EXTRA_TEXT_KEYS],
            AiHookTool::ClaudeCode
            | AiHookTool::Codex
            | AiHookTool::Copilot
            | AiHookTool::Cursor
            | AiHookTool::Opencode => &[PRE_TEXT_KEYS, PRE_EDIT_TEXT_KEYS],
        };
    }

    match tool {
        AiHookTool::Antigravity => &[ANTIGRAVITY_POST_TEXT_KEYS],
        AiHookTool::Codex => &[CODEX_POST_TEXT_KEYS],
        AiHookTool::ClaudeCode => &[CLAUDE_POST_TEXT_KEYS],
        AiHookTool::Copilot => &[COPILOT_POST_TEXT_KEYS],
        AiHookTool::Cursor => &[CURSOR_POST_TEXT_KEYS],
        AiHookTool::Grok => &[GROK_POST_TEXT_KEYS],
        AiHookTool::Opencode => &[OPENCODE_POST_TEXT_KEYS],
        AiHookTool::Windsurf => &[WINDSURF_POST_TEXT_KEYS],
    }
}

fn grab_strings_for_keys_deep<'a>(v: &'a Value, keys: &[&str], acc: &mut HookTexts<'a>) {
    match v {
        Value::Object(map) => {
            for (k, val) in map {
                if keys.iter().any(|x| x == &k.as_str()) {
                    push_strings_from_value(val, acc);
                }
                grab_strings_for_keys_deep(val, keys, acc);
            }
        }
        Value::Array(a) => {
            for i in a {
                grab_strings_for_keys_deep(i, keys, acc);
            }
        }
        _ => {}
    }
}

fn push_strings_from_value<'a>(v: &'a Value, acc: &mut HookTexts<'a>) {
    match v {
        Value::String(s) => acc.push(s),
        Value::Array(items) => {
            for x in items {
                push_strings_from_value(x, acc);
            }
        }
        Value::Object(map) => {
            for val in map.values() {
                push_strings_from_value(val, acc);
            }
        }
        _ => {}
    }
}

/// Pushes every string in an argument envelope except edit-pair text:
/// applied edits are already in the edited file body (keeping its inline
/// suppressions), and unapplied ones push their new text separately.
fn push_envelope_strings<'a>(v: &'a Value, acc: &mut HookTexts<'a>) {
    match v {
        Value::String(s) => acc.push(s),
        Value::Array(items) => {
            for item in items {
                push_envelope_strings(item, acc);
            }
        }
        Value::Object(map) => {
            // Only a complete string pair is an edit (see collect_text_edits);
            // a lone or non-string `new_str` is ordinary argument text.
            let is_edit_pair = |old: &str, new: &str| {
                map.get(old).is_some_and(Value::is_string)
                    && map.get(new).is_some_and(Value::is_string)
            };
            for (key, val) in map {
                let edit_text = EDIT_PAIR_KEYS
                    .iter()
                    .any(|(old, new)| (key == old || key == new) && is_edit_pair(old, new));
                if !edit_text {
                    push_envelope_strings(val, acc);
                }
            }
        }
        _ => {}
    }
}

fn collect_large_strings<'a>(v: &'a Value, acc: &mut HookTexts<'a>, min_len: usize) {
    match v {
        Value::String(s) if s.len() >= min_len => acc.push(s),
        Value::Object(map) => {
            for val in map.values() {
                collect_large_strings(val, acc, min_len);
            }
        }
        Value::Array(a) => {
            for i in a {
                collect_large_strings(i, acc, min_len);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hook_payload::copilot_cli_payload;
    use tempfile::tempdir;

    #[test]
    fn ai_hook_tool_labels_are_stable() {
        assert_eq!(AiHookTool::ClaudeCode.kebab_str(), "claude-code");
        assert_eq!(AiHookTool::Codex.kebab_str(), "codex");
        assert_eq!(AiHookTool::Copilot.kebab_str(), "copilot");
        assert_eq!(AiHookTool::Cursor.kebab_str(), "cursor");
        assert_eq!(AiHookTool::Antigravity.kebab_str(), "antigravity");

        assert_eq!(AiHookTool::ClaudeCode.virtual_path_label(), "<claude-hook>");
        assert_eq!(AiHookTool::Codex.virtual_path_label(), "<codex-hook>");
        assert_eq!(AiHookTool::Copilot.virtual_path_label(), "<copilot-hook>");
        assert_eq!(AiHookTool::Cursor.virtual_path_label(), "<cursor-hook>");
        assert_eq!(
            AiHookTool::Antigravity.virtual_path_label(),
            "<antigravity-hook>"
        );
        assert_eq!(AiHookTool::Grok.kebab_str(), "grok");
        assert_eq!(AiHookTool::Grok.virtual_path_label(), "<grok-hook>");
        assert_eq!(AiHookTool::Windsurf.kebab_str(), "windsurf");
        assert_eq!(AiHookTool::Windsurf.virtual_path_label(), "<windsurf-hook>");
        assert_eq!(AiHookTool::Opencode.kebab_str(), "opencode");
        assert_eq!(AiHookTool::Opencode.virtual_path_label(), "<opencode-hook>");
    }

    #[test]
    fn opencode_pre_extracts_bash_edit_and_mcp_arguments() {
        let dir = tempdir().unwrap();
        let bash = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "bash",
            "tool_input": { "command": "echo opencode-command-marker", "timeout": 1000 },
            "cwd": dir.path()
        })
        .to_string();
        let (_disp, body) =
            stdin_to_hook_body(AiHookTool::Opencode, false, &bash, dir.path(), dir.path()).unwrap();
        assert!(body.contains("opencode-command-marker"), "{body}");

        let edit = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "edit",
            "tool_input": {
                "filePath": "/nonexistent/file.txt",
                "oldString": "opencode-old-marker",
                "newString": "opencode-new-marker"
            }
        })
        .to_string();
        let (_disp, body) =
            stdin_to_hook_body(AiHookTool::Opencode, false, &edit, dir.path(), dir.path()).unwrap();
        // The target is missing, so only the inserted text is scanned.
        assert!(!body.contains("opencode-old-marker"), "{body}");
        assert!(body.contains("opencode-new-marker"), "{body}");

        let mcp = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "github_create_issue",
            "tool_input": { "fields": { "nested": { "body": "opencode-mcp-marker" } } }
        })
        .to_string();
        let (_disp, body) =
            stdin_to_hook_body(AiHookTool::Opencode, false, &mcp, dir.path(), dir.path()).unwrap();
        assert!(body.contains("opencode-mcp-marker"), "{body}");
    }

    #[test]
    fn opencode_pre_edit_applies_to_the_file_and_scans_other_arguments() {
        let repo = repo_with_file("A=placeholder\nB=placeholder\n");
        let token = synthetic_github_token();
        let stdin = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "edit",
            "tool_input": {
                "filePath": "app.txt",
                "oldString": "placeholder",
                "newString": token,
                "replaceAll": true,
                "note": "opencode-extra-argument-marker"
            }
        });

        let (display, body) = pre_body(AiHookTool::Opencode, repo.path(), &stdin);

        assert_eq!(display, "app.txt");
        assert!(body.contains(&format!("A={token}\nB={token}\n")), "{body}");
        // Applied in place, not repeated by the envelope scan.
        assert_eq!(body.matches(&token).count(), 2, "{body}");
        assert!(!body.contains("placeholder"), "{body}");
        assert!(body.contains("opencode-extra-argument-marker"), "{body}");

        // Removing a value scans the edited file, not the removed text.
        let repo = repo_with_file(&format!("A={token}\n"));
        let stdin = serde_json::json!({
            "tool_name": "edit",
            "tool_input": { "filePath": "app.txt", "oldString": token, "newString": "${A}" }
        });
        let (_display, body) = pre_body(AiHookTool::Opencode, repo.path(), &stdin);
        assert!(!body.contains(&token), "{body}");
    }

    #[test]
    fn hook_body_reports_strings_left_out_by_the_text_budget() {
        let dir = tempdir().unwrap();
        let big = "a".repeat(MAX_HOOK_TEXT_BYTES + 1);
        // Keys sort alphabetically, so `zzz` is visited after the big field.
        let stdin = serde_json::json!({
            "tool_name": "mcp_tool",
            "tool_input": { "aaa": big, "zzz": "budget-tail-marker" }
        })
        .to_string();
        let hook =
            hook_body_from_stdin(AiHookTool::Opencode, false, &stdin, dir.path(), dir.path())
                .unwrap();
        assert!(hook.truncated);
        assert!(!hook.body.contains(&big));

        // One oversized string overflows on its own, whatever follows it, so
        // the same write is judged alike for every tool.
        for (tool, stdin) in [
            (
                AiHookTool::ClaudeCode,
                serde_json::json!({
                    "tool_name": "Write",
                    "tool_input": { "file_path": "/nonexistent/out.txt", "content": big }
                }),
            ),
            (
                AiHookTool::Opencode,
                serde_json::json!({
                    "tool_name": "write",
                    "tool_input": { "filePath": "/nonexistent/out.txt", "content": big }
                }),
            ),
        ] {
            let hook =
                hook_body_from_stdin(tool, false, &stdin.to_string(), dir.path(), dir.path())
                    .unwrap();
            assert!(hook.truncated, "{tool:?}");
        }

        // The same string reachable through two keys is charged once.
        let half = "b".repeat(MAX_HOOK_TEXT_BYTES / 2 + 1);
        let stdin = serde_json::json!({
            "tool_name": "write",
            "tool_input": { "content": half, "zzz": "dedup-tail-marker" }
        })
        .to_string();
        let hook =
            hook_body_from_stdin(AiHookTool::Opencode, false, &stdin, dir.path(), dir.path())
                .unwrap();
        assert!(!hook.truncated);
        assert!(hook.body.contains("dedup-tail-marker"));
    }

    #[test]
    fn referenced_file_does_not_spend_the_payload_budget() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("large.txt");
        std::fs::write(&file, "c".repeat(MAX_HOOK_TEXT_BYTES + 1)).unwrap();
        let stdin = serde_json::json!({
            "tool_name": "edit",
            "tool_input": { "filePath": file, "oldString": "c", "newString": "edit-arg-marker" }
        })
        .to_string();
        let hook =
            hook_body_from_stdin(AiHookTool::Opencode, false, &stdin, dir.path(), dir.path())
                .unwrap();
        assert!(!hook.truncated);
        assert!(hook.body.contains("edit-arg-marker"));

        // A payload that repeats the file body (Cursor `beforeReadFile`
        // sends it as `content`) is covered by the file scan.
        let body = std::fs::read_to_string(&file).unwrap();
        let stdin = serde_json::json!({ "file_path": file, "content": body }).to_string();
        let hook = hook_body_from_stdin(AiHookTool::Cursor, false, &stdin, dir.path(), dir.path())
            .unwrap();
        assert!(!hook.truncated);
        assert_eq!(hook.body.matches(&body).count(), 1);
    }

    #[test]
    fn opencode_pre_reads_file_body_for_read_tool() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("notes.txt");
        std::fs::write(&file, "opencode-file-body-marker\n").unwrap();
        let stdin = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "read",
            "tool_input": { "filePath": file, "offset": 0, "limit": 10 }
        })
        .to_string();
        let (disp, body) =
            stdin_to_hook_body(AiHookTool::Opencode, false, &stdin, dir.path(), dir.path())
                .unwrap();
        assert_eq!(disp, "notes.txt");
        assert!(body.contains("opencode-file-body-marker"), "{body}");
    }

    #[test]
    fn opencode_post_extracts_tool_output() {
        let dir = tempdir().unwrap();
        let stdin = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "bash",
            "tool_input": { "command": "cat secrets" },
            "tool_output": { "title": "Shell", "output": "opencode-output-marker" }
        })
        .to_string();
        let (_disp, body) =
            stdin_to_hook_body(AiHookTool::Opencode, true, &stdin, dir.path(), dir.path()).unwrap();
        assert!(body.contains("opencode-output-marker"), "{body}");
        assert!(
            !body.contains("cat secrets"),
            "post scans output only: {body}"
        );
    }

    #[test]
    fn grok_pre_extracts_tool_input_command_and_edit() {
        let dir = tempdir().unwrap();
        let stdin = serde_json::json!({
            "hookEventName": "pre_tool_use",
            "cwd": dir.path(),
            "toolName": "run_terminal_command",
            "toolInput": { "command": "echo grok-command-marker" }
        })
        .to_string();
        let (_disp, body) =
            stdin_to_hook_body(AiHookTool::Grok, false, &stdin, dir.path(), dir.path()).unwrap();
        assert!(body.contains("grok-command-marker"), "{body}");

        let edit = serde_json::json!({
            "hookEventName": "pre_tool_use",
            "toolName": "search_replace",
            "toolInput": { "new_string": "grok-edit-marker" }
        })
        .to_string();
        let (_disp, body) =
            stdin_to_hook_body(AiHookTool::Grok, false, &edit, dir.path(), dir.path()).unwrap();
        assert!(body.contains("grok-edit-marker"), "{body}");
    }

    #[test]
    fn grok_post_extracts_tool_result() {
        let dir = tempdir().unwrap();
        let stdin = serde_json::json!({
            "hookEventName": "post_tool_use",
            "toolName": "run_terminal_command",
            "toolResult": "grok-result-marker"
        })
        .to_string();
        let (_disp, body) =
            stdin_to_hook_body(AiHookTool::Grok, true, &stdin, dir.path(), dir.path()).unwrap();
        assert!(body.contains("grok-result-marker"), "{body}");
    }

    #[test]
    fn extract_user_prompt_reads_grok_prompt_aliases() {
        assert_eq!(
            extract_user_prompt(r#"{"hookEventName":"user_prompt_submit","prompt":"typed"}"#)
                .as_deref(),
            Some("typed")
        );
        assert_eq!(
            extract_user_prompt(r#"{"userPrompt":"camel"}"#).as_deref(),
            Some("camel")
        );
    }

    #[test]
    fn windsurf_pre_extracts_command_line_from_tool_info() {
        let stdin = serde_json::json!({
            "agent_action_name": "pre_run_command",
            "tool_info": {
                "command_line": "echo windsurf-command-marker",
                "cwd": "/workspace/project"
            }
        })
        .to_string();

        let (display, body) = stdin_to_hook_body(
            AiHookTool::Windsurf,
            false,
            &stdin,
            Path::new("."),
            Path::new("."),
        )
        .unwrap();

        assert_eq!(display, "<windsurf-hook>");
        assert!(body.contains("echo windsurf-command-marker"), "{body}");
    }

    #[test]
    fn windsurf_post_extracts_mcp_result() {
        let stdin = serde_json::json!({
            "agent_action_name": "post_mcp_tool_use",
            "tool_info": {
                "mcp_tool_name": "list_commits",
                "mcp_result": "windsurf-result-marker-text"
            }
        })
        .to_string();

        let (_display, body) = stdin_to_hook_body(
            AiHookTool::Windsurf,
            true,
            &stdin,
            Path::new("."),
            Path::new("."),
        )
        .unwrap();

        assert!(body.contains("windsurf-result-marker-text"), "{body}");
    }

    #[test]
    fn extract_user_prompt_reads_cascade_tool_info() {
        assert_eq!(
            extract_user_prompt(
                r#"{"agent_action_name":"pre_user_prompt","tool_info":{"user_prompt":"scan cascade"}}"#
            )
            .as_deref(),
            Some("scan cascade")
        );
        // Top-level prompt still takes priority over the nested form.
        assert_eq!(
            extract_user_prompt(r#"{"prompt":"top","tool_info":{"user_prompt":"nested"}}"#)
                .as_deref(),
            Some("top")
        );
    }

    #[test]
    fn antigravity_pre_extracts_pascal_case_tool_call_args() {
        let stdin = serde_json::json!({
            "toolCall": {
                "name": "run_command",
                "args": {
                    "CommandLine": "export TOKEN=sk-live-example",
                    "Cwd": "/workspace/project"
                }
            },
            "stepIdx": 3,
            "conversationId": "uuid"
        })
        .to_string();

        let (display, body) = stdin_to_hook_body(
            AiHookTool::Antigravity,
            false,
            &stdin,
            Path::new("."),
            Path::new("."),
        )
        .unwrap();

        assert_eq!(display, "<antigravity-hook>");
        assert!(body.contains("export TOKEN=sk-live-example"), "{body}");
    }

    #[test]
    fn antigravity_pre_extracts_write_to_file_content() {
        let stdin = serde_json::json!({
            "toolCall": {
                "name": "write_to_file",
                "args": {
                    "TargetFile": "/outside/of/repo/new.txt",
                    "CodeContent": "api_key = embedded-secret-value"
                }
            }
        })
        .to_string();

        let (_display, body) = stdin_to_hook_body(
            AiHookTool::Antigravity,
            false,
            &stdin,
            Path::new("."),
            Path::new("."),
        )
        .unwrap();

        assert!(body.contains("embedded-secret-value"), "{body}");
    }

    #[test]
    fn antigravity_pre_extracts_search_tool_arguments() {
        let stdin = serde_json::json!({
            "toolCall": {
                "name": "grep_search",
                "args": {
                    "SearchPath": "/outside/of/repo/src",
                    "Query": "needle-from-query",
                    "Includes": ["*.env"]
                }
            }
        })
        .to_string();

        let (_display, body) = stdin_to_hook_body(
            AiHookTool::Antigravity,
            false,
            &stdin,
            Path::new("."),
            Path::new("."),
        )
        .unwrap();

        assert!(body.contains("needle-from-query"), "{body}");
        assert!(body.contains("*.env"), "{body}");
    }

    #[test]
    fn antigravity_pre_extracts_lowercase_search_web_arguments() {
        let stdin = serde_json::json!({
            "toolCall": {
                "name": "search_web",
                "args": {
                    "query": "john@example.com", // shk-ignore pii.email
                    "domain": "example.com"
                }
            }
        })
        .to_string();

        let (_display, body) = stdin_to_hook_body(
            AiHookTool::Antigravity,
            false,
            &stdin,
            Path::new("."),
            Path::new("."),
        )
        .unwrap();

        assert!(body.contains("john@example.com"), "{body}"); // shk-ignore pii.email
        assert!(body.contains("example.com"), "{body}");
    }

    #[test]
    fn antigravity_pre_extracts_find_by_name_pattern() {
        let stdin = serde_json::json!({
            "toolCall": {
                "name": "find_by_name",
                "args": {
                    "SearchDirectory": "/outside/of/repo",
                    "Pattern": "*sensitive-name*.pem",
                    "Excludes": ["node_modules"]
                }
            }
        })
        .to_string();

        let (_display, body) = stdin_to_hook_body(
            AiHookTool::Antigravity,
            false,
            &stdin,
            Path::new("."),
            Path::new("."),
        )
        .unwrap();

        assert!(body.contains("*sensitive-name*.pem"), "{body}");
        assert!(body.contains("node_modules"), "{body}");
    }

    #[test]
    fn antigravity_pre_extracts_collaboration_tool_arguments() {
        let stdin = serde_json::json!({
            "toolCall": {
                "name": "invoke_subagent",
                "args": {
                    "Subagents": [{
                        "Prompt": "investigate secret handling",
                        "Role": "security-reviewer",
                        "Workspace": "/outside/of/repo"
                    }]
                }
            }
        })
        .to_string();

        let (_display, body) = stdin_to_hook_body(
            AiHookTool::Antigravity,
            false,
            &stdin,
            Path::new("."),
            Path::new("."),
        )
        .unwrap();

        assert!(body.contains("investigate secret handling"), "{body}");
        assert!(body.contains("security-reviewer"), "{body}");
    }

    #[test]
    fn antigravity_metadata_paths_are_not_scanned_as_files() {
        let repo = tempdir().expect("temp repo");
        let transcript = repo.path().join("transcript.jsonl");
        std::fs::write(&transcript, "previous-secret-value").expect("write transcript");
        let session_log = repo.path().join("session.log");
        std::fs::write(&session_log, "future-metadata-secret").expect("write session log");
        let stdin = serde_json::json!({
            "toolCall": {
                "name": "run_command",
                "args": {
                    "CommandLine": "echo safe-command"
                }
            },
            "transcriptPath": transcript,
            "sessionLogPath": session_log,
            "artifactDirectoryPath": repo.path().join("artifacts"),
            "workspacePaths": [repo.path()]
        })
        .to_string();

        let (display, body) = stdin_to_hook_body(
            AiHookTool::Antigravity,
            false,
            &stdin,
            repo.path(),
            repo.path(),
        )
        .unwrap();

        assert_eq!(display, "<antigravity-hook>");
        assert!(body.contains("echo safe-command"), "{body}");
        assert!(!body.contains("previous-secret-value"), "{body}");
        assert!(!body.contains("future-metadata-secret"), "{body}");
    }

    #[test]
    fn antigravity_post_extracts_error_text() {
        let stdin = serde_json::json!({
            "stepIdx": 5,
            "error": "exit status 1: leaked-value-in-error",
            "conversationId": "uuid"
        })
        .to_string();

        let (_display, body) = stdin_to_hook_body(
            AiHookTool::Antigravity,
            true,
            &stdin,
            Path::new("."),
            Path::new("."),
        )
        .unwrap();

        assert!(body.contains("leaked-value-in-error"), "{body}");
    }

    #[test]
    fn copilot_post_extracts_tool_result_text() {
        let stdin = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "bash",
            "tool_result": {
                "result_type": "success",
                "text_result_for_llm": "copilot-result-marker-text"
            }
        })
        .to_string();

        let (_display, body) = stdin_to_hook_body(
            AiHookTool::Copilot,
            true,
            &stdin,
            Path::new("."),
            Path::new("."),
        )
        .unwrap();

        assert!(body.contains("copilot-result-marker-text"), "{body}");
    }

    #[test]
    fn copilot_pre_extracts_tool_args_command() {
        let stdin = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "bash",
            "tool_input": {
                "command": "echo copilot-args-marker"
            }
        })
        .to_string();

        let (display, body) = stdin_to_hook_body(
            AiHookTool::Copilot,
            false,
            &stdin,
            Path::new("."),
            Path::new("."),
        )
        .unwrap();

        assert_eq!(display, "<copilot-hook>");
        assert!(body.contains("echo copilot-args-marker"), "{body}");
    }

    #[test]
    fn extract_user_prompt_returns_prompt_only_for_valid_payloads() {
        assert_eq!(
            extract_user_prompt(r#"{"prompt":"scan this"}"#).as_deref(),
            Some("scan this")
        );
        assert!(extract_user_prompt(r#"{"text":"scan this"}"#).is_none());
        assert!(extract_user_prompt("not json").is_none());
    }

    #[test]
    fn claude_post_extracts_short_value_fields() {
        let stdin = serde_json::json!({
            "tool_name": "mcp__demo__read",
            "tool_response": {
                "data": {
                    "value": "short-sensitive-token"
                }
            }
        })
        .to_string();

        let (_display, body) = stdin_to_hook_body(
            AiHookTool::ClaudeCode,
            true,
            &stdin,
            Path::new("."),
            Path::new("."),
        )
        .unwrap();

        assert!(body.contains("short-sensitive-token"), "{body}");
    }

    #[test]
    fn claude_post_extracts_nested_message_items() {
        let stdin = serde_json::json!({
            "tool_response": {
                "messages": [
                    {
                        "role": "tool",
                        "content": [
                            { "type": "text", "text": "nested tool result" }
                        ]
                    }
                ]
            }
        })
        .to_string();

        let (_display, body) = stdin_to_hook_body(
            AiHookTool::ClaudeCode,
            true,
            &stdin,
            Path::new("."),
            Path::new("."),
        )
        .unwrap();

        assert!(body.contains("nested tool result"), "{body}");
    }

    #[test]
    fn priority_chunks_are_deduplicated() {
        let stdin = serde_json::json!({
            "data": {
                "content": "same text",
                "items": ["same text"]
            }
        })
        .to_string();

        let (_display, body) = stdin_to_hook_body(
            AiHookTool::ClaudeCode,
            true,
            &stdin,
            Path::new("."),
            Path::new("."),
        )
        .unwrap();

        assert_eq!(body.matches("same text").count(), 1, "{body}");
    }

    #[test]
    fn pre_hooks_prefer_prompt_like_text_fields() {
        let stdin = serde_json::json!({
            "prompt": "primary prompt",
            "tool_input": {
                "command": "secondary command"
            }
        })
        .to_string();

        let (display, body) = stdin_to_hook_body(
            AiHookTool::Cursor,
            false,
            &stdin,
            Path::new("."),
            Path::new("."),
        )
        .unwrap();

        assert_eq!(display, "<cursor-hook>");
        assert!(body.contains("primary prompt"), "{body}");
        assert!(body.contains("secondary command"), "{body}");
    }

    #[test]
    fn codex_post_extracts_tool_response_payload() {
        let stdin = serde_json::json!({
            "tool_name": "Bash",
            "tool_response": {
                "stdout": "hello from bash output"
            }
        })
        .to_string();

        let (_display, body) = stdin_to_hook_body(
            AiHookTool::Codex,
            true,
            &stdin,
            Path::new("."),
            Path::new("."),
        )
        .unwrap();

        assert!(body.contains("hello from bash output"), "{body}");
    }

    #[test]
    fn post_hook_text_keys_are_tool_specific() {
        let stdin = serde_json::json!({
            "stdout": "codex output",
            "shell_command": "cursor command"
        })
        .to_string();

        let (_display, codex_body) = stdin_to_hook_body(
            AiHookTool::Codex,
            true,
            &stdin,
            Path::new("."),
            Path::new("."),
        )
        .unwrap();
        let (_display, cursor_body) = stdin_to_hook_body(
            AiHookTool::Cursor,
            true,
            &stdin,
            Path::new("."),
            Path::new("."),
        )
        .unwrap();

        assert!(codex_body.contains("codex output"), "{codex_body}");
        assert!(!codex_body.contains("cursor command"), "{codex_body}");
        assert!(cursor_body.contains("cursor command"), "{cursor_body}");
        assert!(!cursor_body.contains("codex output"), "{cursor_body}");
    }

    #[test]
    fn cursor_post_extracts_after_shell_and_mcp_payloads() {
        let shell_stdin = serde_json::json!({
            "command": "curl https://api.example.com",
            "output": "shell output with token",
            "duration": 1234,
            "sandbox": false
        })
        .to_string();
        let (_display, shell_body) = stdin_to_hook_body(
            AiHookTool::Cursor,
            true,
            &shell_stdin,
            Path::new("."),
            Path::new("."),
        )
        .unwrap();
        assert!(
            shell_body.contains("shell output with token"),
            "{shell_body}"
        );

        let mcp_stdin = serde_json::json!({
            "tool_name": "mcp_fetch",
            "tool_input": "{\"url\":\"https://example.com\"}",
            "result_json": "{\"body\":\"mcp result body\"}",
            "duration": 99
        })
        .to_string();
        let (_display, mcp_body) = stdin_to_hook_body(
            AiHookTool::Cursor,
            true,
            &mcp_stdin,
            Path::new("."),
            Path::new("."),
        )
        .unwrap();
        assert!(mcp_body.contains("mcp result body"), "{mcp_body}");
    }

    #[test]
    fn falls_back_to_large_strings_when_priority_keys_are_absent() {
        let large = "x".repeat(96);
        let stdin = serde_json::json!({
            "nested": {
                "unrecognized": large
            }
        })
        .to_string();

        let (_display, body) = stdin_to_hook_body(
            AiHookTool::Codex,
            false,
            &stdin,
            Path::new("."),
            Path::new("."),
        )
        .unwrap();

        assert!(body.contains(&"x".repeat(96)), "{body}");
    }

    #[test]
    fn empty_payload_body_defaults_to_empty_json_object() {
        let (_display, body) = stdin_to_hook_body(
            AiHookTool::Codex,
            false,
            "{}",
            Path::new("."),
            Path::new("."),
        )
        .unwrap();

        assert_eq!(body, "{}");
    }

    #[test]
    fn reads_candidate_files_inside_repo_and_uses_first_relative_label() {
        let repo = tempdir().expect("temp repo");
        std::fs::create_dir_all(repo.path().join("nested")).expect("create temp repo");
        std::fs::write(repo.path().join("nested/secret.txt"), "file body")
            .expect("write temp file");
        let stdin = serde_json::json!({
            "tool_input": {
                "file_path": "nested/secret.txt"
            }
        })
        .to_string();

        let (display, body) = stdin_to_hook_body(
            AiHookTool::ClaudeCode,
            false,
            &stdin,
            repo.path(),
            repo.path(),
        )
        .unwrap();

        assert_eq!(display, "nested/secret.txt");
        assert!(body.contains("// ---- nested/secret.txt"), "{body}");
        assert!(body.contains("file body"), "{body}");
    }

    /// Built at runtime so no token-shaped literal appears in source.
    fn synthetic_github_token() -> String {
        format!("{}_{}", "ghp", "a1B2c3D4".repeat(5))
    }

    /// Repo with an existing target file, so the file-body read suppresses
    /// the large-string fallback.
    fn repo_with_file(body: &str) -> tempfile::TempDir {
        let repo = tempdir().expect("temp repo");
        std::fs::write(repo.path().join("app.txt"), body).expect("write target");
        repo
    }

    fn pre_body(tool: AiHookTool, repo: &Path, stdin: &serde_json::Value) -> (String, String) {
        stdin_to_hook_body(tool, false, &stdin.to_string(), repo, repo).unwrap()
    }

    #[test]
    fn claude_pre_edit_scans_the_edited_file_body() {
        let repo = repo_with_file("keep-line\nold-edit-marker\n");
        let token = synthetic_github_token();
        let stdin = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Edit",
            "tool_input": {
                "file_path": "app.txt",
                "old_string": "old-edit-marker",
                "new_string": format!("token = {token}"),
            }
        });

        let (display, body) = pre_body(AiHookTool::ClaudeCode, repo.path(), &stdin);

        assert_eq!(display, "app.txt");
        assert!(
            body.contains(&format!("keep-line\ntoken = {token}\n")),
            "{body}"
        );
        assert!(!body.contains("old-edit-marker"), "{body}");
        // Applied in place, not repeated as a standalone blob.
        assert_eq!(body.matches(&token).count(), 1, "{body}");
    }

    #[test]
    fn pre_edit_keeps_inline_suppression_context_from_the_file() {
        let directive = "# shk-ignore-next-line secret.github_token";
        let repo = repo_with_file(&format!("{directive}\nTOKEN=placeholder\n"));
        let token = synthetic_github_token();
        let stdin = serde_json::json!({
            "tool_input": {
                "file_path": "app.txt",
                "old_string": "placeholder",
                "new_string": token
            }
        });

        let (_display, body) = pre_body(AiHookTool::ClaudeCode, repo.path(), &stdin);

        assert!(
            body.contains(&format!("{directive}\nTOKEN={token}\n")),
            "{body}"
        );
    }

    #[test]
    fn pre_edit_replace_all_and_first_match_semantics() {
        let repo = repo_with_file("x x\n");
        let first = serde_json::json!({
            "tool_input": { "file_path": "app.txt", "old_string": "x", "new_string": "y" }
        });
        let all = serde_json::json!({
            "tool_input": {
                "file_path": "app.txt",
                "old_string": "x",
                "new_string": "z",
                "replace_all": true
            }
        });

        let (_display, body) = pre_body(AiHookTool::ClaudeCode, repo.path(), &first);
        assert!(body.ends_with("y x\n"), "{body}");
        let (_display, body) = pre_body(AiHookTool::ClaudeCode, repo.path(), &all);
        assert!(body.ends_with("z z\n"), "{body}");
    }

    #[test]
    fn claude_pre_multi_edit_applies_edits_in_order() {
        let repo = repo_with_file("alpha\n");
        let token = synthetic_github_token();
        let stdin = serde_json::json!({
            "tool_name": "MultiEdit",
            "tool_input": {
                "file_path": "app.txt",
                "edits": [
                    { "old_string": "alpha", "new_string": "beta" },
                    { "old_string": "beta", "new_string": token }
                ]
            }
        });

        let (_display, body) = pre_body(AiHookTool::ClaudeCode, repo.path(), &stdin);

        assert!(body.ends_with(&format!("{token}\n")), "{body}");
        assert!(!body.contains("alpha") && !body.contains("beta"), "{body}");
    }

    #[test]
    fn pre_edit_falls_back_to_new_text_when_old_text_is_missing() {
        let repo = repo_with_file("clean body\n");
        let token = synthetic_github_token();
        let stdin = serde_json::json!({
            "tool_input": {
                "file_path": "app.txt",
                "old_string": "not-in-file",
                "new_string": token
            }
        });

        let (_display, body) = pre_body(AiHookTool::ClaudeCode, repo.path(), &stdin);

        assert!(body.contains("clean body"), "{body}");
        assert!(body.contains(&token), "{body}");
        assert!(!body.contains("not-in-file"), "{body}");
    }

    #[test]
    fn pre_edit_outside_repo_scans_new_text_only() {
        let repo = tempdir().expect("temp repo");
        let outside = tempdir().expect("outside dir");
        std::fs::write(outside.path().join("app.txt"), "old-edit-marker\n").expect("write");
        let token = synthetic_github_token();
        let stdin = serde_json::json!({
            "tool_input": {
                "file_path": outside.path().join("app.txt"),
                "old_string": "old-edit-marker",
                "new_string": token
            }
        });

        let (display, body) = pre_body(AiHookTool::ClaudeCode, repo.path(), &stdin);

        assert_eq!(display, "<claude-hook>");
        assert_eq!(body, token);
    }

    #[test]
    fn post_hooks_do_not_apply_edits() {
        let repo = repo_with_file("already-edited\n");
        let stdin = serde_json::json!({
            "tool_input": {
                "file_path": "app.txt",
                "old_string": "already-edited",
                "new_string": "post-edit-marker"
            }
        });

        let (_display, body) = stdin_to_hook_body(
            AiHookTool::ClaudeCode,
            true,
            &stdin.to_string(),
            repo.path(),
            repo.path(),
        )
        .unwrap();

        assert!(body.contains("already-edited"), "{body}");
        assert!(!body.contains("post-edit-marker"), "{body}");
    }

    #[test]
    fn replace_all_that_would_explode_the_body_scans_new_text_alone() {
        let file = "a".repeat(10_000);
        let repo = repo_with_file(&file);
        let token = synthetic_github_token();
        // 10k matches x ~1 KiB growth is far past the MAX_HOOK_TEXT_BYTES cap.
        let new = format!("{}{token}", "b".repeat(1024));
        let stdin = serde_json::json!({
            "tool_input": {
                "file_path": "app.txt",
                "old_string": "a",
                "new_string": new,
                "replace_all": true
            }
        });

        let (_display, body) = pre_body(AiHookTool::ClaudeCode, repo.path(), &stdin);

        assert_eq!(body, format!("// ---- app.txt\n{file}\n---\n{new}"));
    }

    #[test]
    fn edit_work_budget_leaves_later_edits_for_standalone_scanning() {
        // Each edit costs two passes over a 2 MiB body, so the budget covers
        // 32 edits; the rest are scanned as standalone new text.
        let markers: Vec<String> = (0..40).map(|i| format!("edit-marker-{i:02}")).collect();
        let file = format!(
            "{}\n{}\n",
            "a".repeat(MAX_HOOK_TEXT_BYTES),
            markers.join("\n")
        );
        let repo = repo_with_file(&file);
        let edits: Vec<_> = markers
            .iter()
            .map(|marker| serde_json::json!({ "old_string": marker, "new_string": format!("new-{marker}") }))
            .collect();
        let stdin = serde_json::json!({
            "tool_name": "MultiEdit",
            "tool_input": { "file_path": "app.txt", "edits": edits }
        });

        let (_display, body) = pre_body(AiHookTool::ClaudeCode, repo.path(), &stdin);

        let (file_part, standalone) = body.split_once("\n---\n").expect("standalone texts");
        assert!(
            file_part.contains("\nnew-edit-marker-00\n"),
            "first edit applied"
        );
        assert!(
            file_part.contains("\nedit-marker-39\n"),
            "last edit not applied"
        );
        assert!(standalone.contains("new-edit-marker-39"), "{standalone}");
        assert!(!standalone.contains("new-edit-marker-00"), "{standalone}");
    }

    #[test]
    fn edits_on_an_object_with_several_paths_target_no_file() {
        let repo = repo_with_file("placeholder\n");
        std::fs::write(repo.path().join("decoy.txt"), "placeholder\n").expect("write decoy");
        let token = synthetic_github_token();
        let stdin = serde_json::json!({
            "tool_input": {
                "file_path": "app.txt",
                "backup_path": "decoy.txt",
                "old_string": "placeholder",
                "new_string": token
            }
        });

        let (_display, body) = pre_body(AiHookTool::ClaudeCode, repo.path(), &stdin);

        assert_eq!(body.matches("placeholder").count(), 2, "{body}");
        assert!(body.ends_with(&format!("\n---\n{token}")), "{body}");
    }

    #[test]
    fn filesystem_mcp_edit_file_edits_are_applied() {
        let repo = repo_with_file("API=placeholder\n");
        let token = synthetic_github_token();
        let stdin = serde_json::json!({
            "tool_name": "mcp__filesystem__edit_file",
            "tool_input": {
                "path": "app.txt",
                "edits": [{ "oldText": "placeholder", "newText": token }],
                "dryRun": false
            }
        });

        let (display, body) = pre_body(AiHookTool::ClaudeCode, repo.path(), &stdin);

        assert_eq!(display, "app.txt");
        assert!(body.contains(&format!("API={token}\n")), "{body}");
    }

    #[test]
    fn claude_pre_notebook_edit_scans_new_source() {
        let repo = tempdir().expect("temp repo");
        std::fs::write(repo.path().join("nb.ipynb"), r#"{"cells":[]}"#).expect("write notebook");
        let token = synthetic_github_token();
        let stdin = serde_json::json!({
            "tool_name": "NotebookEdit",
            "tool_input": {
                "notebook_path": "nb.ipynb",
                "cell_id": "c1",
                "new_source": format!("TOKEN = '{token}'"),
                "edit_mode": "replace"
            }
        });

        let (display, body) = pre_body(AiHookTool::ClaudeCode, repo.path(), &stdin);

        assert_eq!(display, "nb.ipynb");
        assert!(body.contains(&token), "{body}");
    }

    #[test]
    fn copilot_pre_edit_covers_cli_and_vscode_argument_names() {
        let repo = repo_with_file("x\n");
        let token = synthetic_github_token();
        let payloads = [
            serde_json::json!({
                "tool_name": "Edit",
                "tool_input": { "path": "app.txt", "old_str": "x", "new_str": token }
            }),
            serde_json::json!({
                "tool_name": "Write",
                "tool_input": { "path": "app.txt", "file_text": token }
            }),
            serde_json::json!({
                "tool_name": "replace_string_in_file",
                "tool_input": { "filePath": "app.txt", "oldString": "x", "newString": token }
            }),
            serde_json::json!({
                "tool_name": "multi_replace_string_in_file",
                "tool_input": {
                    "replacements": [
                        { "filePath": "app.txt", "oldString": "x", "newString": token }
                    ]
                }
            }),
            serde_json::json!({
                "tool_name": "edit_notebook_file",
                "tool_input": { "filePath": "app.txt", "newCode": token }
            }),
        ];

        for stdin in &payloads {
            let (display, body) = pre_body(AiHookTool::Copilot, repo.path(), stdin);
            assert_eq!(display, "app.txt", "{stdin}");
            assert!(body.contains(&token), "{stdin}: {body}");
        }
    }

    #[test]
    fn multi_file_replacements_apply_to_their_own_files() {
        let repo = tempdir().expect("temp repo");
        std::fs::write(repo.path().join("a.txt"), "shared\n").expect("write a");
        std::fs::write(repo.path().join("b.txt"), "shared\n").expect("write b");
        let stdin = serde_json::json!({
            "tool_input": {
                "replacements": [
                    { "filePath": "a.txt", "oldString": "shared", "newString": "a-marker" },
                    { "filePath": "b.txt", "oldString": "shared", "newString": "b-marker" }
                ]
            }
        });

        let (_display, body) = pre_body(AiHookTool::Copilot, repo.path(), &stdin);

        assert!(body.contains("// ---- a.txt\na-marker\n"), "{body}");
        assert!(body.contains("// ---- b.txt\nb-marker\n"), "{body}");
        assert!(!body.contains("shared"), "{body}");
    }

    #[test]
    fn edit_scanning_applies_to_every_tool_with_a_file_read() {
        let repo = repo_with_file("placeholder\n");
        let stdin = serde_json::json!({
            "tool_input": {
                "file_path": "app.txt",
                "old_string": "placeholder",
                "new_string": "shared-edit-marker"
            }
        });

        for tool in [
            AiHookTool::ClaudeCode,
            AiHookTool::Codex,
            AiHookTool::Copilot,
            AiHookTool::Cursor,
            AiHookTool::Windsurf,
        ] {
            let (_display, body) = pre_body(tool, repo.path(), &stdin);
            assert!(body.contains("shared-edit-marker"), "{tool:?}: {body}");
        }
    }

    #[test]
    fn generic_argument_names_do_not_disable_the_large_string_fallback() {
        let token = synthetic_github_token();
        let notes = format!("{} {token}", "n".repeat(100));
        let stdin = serde_json::json!({
            "tool_name": "mcp__s__run",
            "tool_input": { "code": "1+1", "input": "x", "notes": notes }
        });

        let (_display, body) = pre_body(AiHookTool::ClaudeCode, Path::new("."), &stdin);

        assert!(body.contains(&token), "{body}");
    }

    #[test]
    fn argument_text_has_its_own_budget_next_to_a_large_file() {
        let repo = repo_with_file(&"a".repeat(MAX_HOOK_TEXT_BYTES + 1));
        let stdin = serde_json::json!({
            "tool_input": { "file_path": "app.txt", "content": "write-content-marker" }
        });

        let (_display, body) = pre_body(AiHookTool::ClaudeCode, repo.path(), &stdin);

        assert!(body.contains("write-content-marker"), "{body:.80}");
    }

    #[test]
    fn copilot_cli_short_stringified_command_is_scanned() {
        // Under the 96-byte fallback cut, so only decoding finds it.
        let token = synthetic_github_token();
        let stdin = copilot_cli_payload(
            "bash",
            serde_json::json!({ "command": format!("echo {token}") }),
        );
        assert!(stdin["toolArgs"].as_str().unwrap().len() < 96);

        let (_display, body) = pre_body(AiHookTool::Copilot, Path::new("."), &stdin);

        assert_eq!(body, format!("echo {token}"));
    }

    #[test]
    fn copilot_cli_stringified_edit_applies_to_the_target_file() {
        let repo = repo_with_file("API=placeholder\n");
        let token = synthetic_github_token();
        let stdin = copilot_cli_payload(
            "edit",
            serde_json::json!({ "path": "app.txt", "old_str": "placeholder", "new_str": token }),
        );

        let (display, body) = pre_body(AiHookTool::Copilot, repo.path(), &stdin);

        assert_eq!(display, "app.txt");
        assert!(body.contains(&format!("API={token}\n")), "{body}");
        assert!(!body.contains("placeholder"), "{body}");
    }

    #[test]
    fn copilot_cli_stringified_create_scans_file_text() {
        let token = synthetic_github_token();
        let stdin = copilot_cli_payload(
            "create",
            serde_json::json!({ "path": "new.txt", "file_text": token }),
        );

        let (_display, body) = pre_body(AiHookTool::Copilot, Path::new("."), &stdin);

        assert!(body.contains(&token), "{body}");
    }

    #[test]
    fn every_value_in_a_decoded_envelope_is_scanned() {
        // A matching text key (`url`) or a file read (`path`) disables the
        // large-string fallback, so the remaining values must still be scanned.
        let repo = repo_with_file("clean body\n");
        let token = synthetic_github_token();
        let fetch = copilot_cli_payload(
            "web_fetch",
            serde_json::json!({
                "url": "https://example.com",
                "headers": { "Authorization": format!("Bearer {token}") }
            }),
        );
        let mcp = copilot_cli_payload(
            "mcp_tool",
            serde_json::json!({ "path": "app.txt", "message": token }),
        );

        for stdin in [&fetch, &mcp] {
            let (_display, body) = pre_body(AiHookTool::Copilot, repo.path(), stdin);
            assert!(body.contains(&token), "{stdin}: {body}");
        }
    }

    #[test]
    fn decoded_envelope_scans_a_lone_edit_key() {
        let repo = repo_with_file("clean body\n");
        let token = synthetic_github_token();
        let stdin = copilot_cli_payload(
            "custom_tool",
            serde_json::json!({ "path": "app.txt", "new_str": token }),
        );

        let (_display, body) = pre_body(AiHookTool::Copilot, repo.path(), &stdin);

        assert!(body.contains(&token), "{body}");
    }

    #[test]
    fn decoded_envelope_scan_leaves_edit_text_to_the_edited_body() {
        let directive = "# shk-ignore-next-line secret.github_token";
        let repo = repo_with_file(&format!("{directive}\nTOKEN=placeholder\n"));
        let token = synthetic_github_token();
        let stdin = copilot_cli_payload(
            "edit",
            serde_json::json!({ "path": "app.txt", "old_str": "placeholder", "new_str": token }),
        );

        let (_display, body) = pre_body(AiHookTool::Copilot, repo.path(), &stdin);

        // Only inside the edited body, under the file's suppression comment.
        assert_eq!(body.matches(&token).count(), 1, "{body}");
        assert!(
            body.contains(&format!("{directive}\nTOKEN={token}\n")),
            "{body}"
        );
    }

    #[test]
    fn post_hooks_do_not_decode_argument_envelopes() {
        let repo = repo_with_file("post-file-body\n");
        let stdin = copilot_cli_payload("view", serde_json::json!({ "path": "app.txt" }));

        let (display, body) = stdin_to_hook_body(
            AiHookTool::Copilot,
            true,
            &stdin.to_string(),
            repo.path(),
            repo.path(),
        )
        .unwrap();

        assert_eq!(display, "<copilot-hook>");
        assert!(!body.contains("post-file-body"), "{body}");
    }

    #[test]
    fn several_referenced_files_use_the_virtual_label() {
        let repo = tempdir().expect("temp repo");
        std::fs::create_dir_all(repo.path().join("fixtures")).expect("create fixtures");
        std::fs::write(repo.path().join("fixtures/demo.txt"), "fixture body").expect("write");
        std::fs::write(repo.path().join("app.txt"), "app body").expect("write");
        let stdin = serde_json::json!({
            "tool_input": { "source_path": "app.txt", "destination_path": "fixtures/demo.txt" }
        })
        .to_string();

        let (display, body) = stdin_to_hook_body(
            AiHookTool::ClaudeCode,
            false,
            &stdin,
            repo.path(),
            repo.path(),
        )
        .unwrap();

        // A path allowlist for `fixtures/**` must not cover `app.txt`.
        assert_eq!(display, "<claude-hook>");
        assert!(
            body.contains("app body") && body.contains("fixture body"),
            "{body}"
        );

        // The same file named twice is still one file.
        let stdin = serde_json::json!({
            "tool_input": { "file_path": "app.txt", "target_path": "./app.txt" }
        })
        .to_string();
        let (display, _body) = stdin_to_hook_body(
            AiHookTool::ClaudeCode,
            false,
            &stdin,
            repo.path(),
            repo.path(),
        )
        .unwrap();
        assert_eq!(display, "app.txt");
    }

    #[test]
    fn ignores_candidate_files_outside_repo() {
        let repo = tempdir().expect("temp repo");
        let outside = tempdir().expect("outside temp dir");
        std::fs::write(outside.path().join("secret.txt"), "outside body")
            .expect("write outside file");
        let stdin = serde_json::json!({
            "tool_input": {
                "file_path": outside.path().join("secret.txt")
            },
            "prompt": "fallback prompt"
        })
        .to_string();

        let (display, body) = stdin_to_hook_body(
            AiHookTool::ClaudeCode,
            false,
            &stdin,
            repo.path(),
            repo.path(),
        )
        .unwrap();

        assert_eq!(display, "<claude-hook>");
        assert_eq!(body, "fallback prompt");
    }
}
