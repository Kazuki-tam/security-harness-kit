//! Parse AI tool stdin JSON payloads (MVP heuristic; spec §7.9).

use crate::hook_payload::{ARGUMENT_ENVELOPE_KEYS, decode_encoded_arguments};
use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::Value;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
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
    "agent_transcript_path",
    "artifactDirectoryPath",
    "transcriptPath",
    "transcript_path",
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
// Replace-style edit arguments as (old, new) key pairs. For local write tools
// (see `writes_local_file`), pre hooks apply each edit to the target file body read
// via PATH_KEYS and scan the edited body, so inserted text keeps the file's
// inline `shk-ignore` context and removed text no longer blocks. When the
// target is not read (outside the repo, binary, or missing) or `old` is not
// found, only the new text is scanned; any other tool's edits are scanned as
// payload text, old text included. Edits inherit the nearest enclosing path
// key, so nested lists work.
// - Claude Code Edit, MultiEdit `edits[]`; Windsurf `edits[]`; Grok Build
//   search_replace: old_string, new_string
// - Copilot CLI edit: old_str, new_str
// - Copilot in VS Code replaceString, multiReplaceString `replacements[]`;
//   OpenCode edit (`replaceAll`), multiedit `edits[]`: oldString, newString
// - Filesystem MCP server edit_file `edits[]`: oldText, newText
// - Antigravity replace_file_content, multi_replace_file_content
//   `ReplacementChunks[]` (`AllowMultiple`): TargetContent, ReplacementContent
const EDIT_PAIR_KEYS: &[(&str, &str)] = &[
    ("old_string", "new_string"),
    ("old_str", "new_str"),
    ("oldString", "newString"),
    ("oldText", "newText"),
    ("TargetContent", "ReplacementContent"),
];
// Whole text a local write tool (see `writes_local_file`) sends to the file
// named by the nearest path argument. It is scanned with that file (under its
// path) when the file is read.
// - Claude Code Write, OpenCode write, filesystem MCP write_file: content
// - Cursor beforeReadFile: content (the file body being read)
// - Claude Code NotebookEdit: new_source
// - Copilot CLI create: file_text
// - Copilot in VS Code editNotebook: newCode; insertEdit: code
// - Antigravity write_to_file: CodeContent
// Codex `apply_patch` sends the patch as `command`, already in PRE_TEXT_KEYS.
const FILE_TEXT_KEYS: &[&str] = &[
    "content",
    "new_source",
    "file_text",
    "newCode",
    "code",
    "CodeContent",
];
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
// Grok pre payloads carry every argument, including arbitrary MCP schemas,
// under the `toolInput` envelope (see ARGUMENT_ENVELOPE_KEYS).
//
// Grok PostToolUse output is `toolResult` (not Claude's `tool_response`).
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

// OpenCode's managed plugin normalizes tool arguments under the `tool_input`
// envelope (see ARGUMENT_ENVELOPE_KEYS); edit's `oldString`/`newString` pair is
// applied to the file named by `filePath` (resolved through PATH_KEYS).
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

/// Text extracted from a hook payload for scanning, split by the path label
/// each part is scanned under.
#[derive(Debug)]
pub struct HookBody {
    /// The referenced file when the payload names exactly one, otherwise the
    /// tool's virtual label. The CLI logs it when no finding names a segment.
    pub display: String,
    /// Each referenced file (with a local write tool's edits applied and the
    /// text it writes to the file) under its repo-relative path, then the
    /// remaining payload text under the tool's virtual label. Path-scoped
    /// policy therefore only covers text that belongs to that path. Never
    /// empty.
    pub segments: Vec<HookSegment>,
    /// Payload strings were left unscanned because the text budget ran out.
    /// Blocking hooks must not allow such a payload.
    pub truncated: bool,
}

/// Text scanned under one path label.
#[derive(Debug)]
pub struct HookSegment {
    pub label: String,
    /// A file segment starts with the file body, so finding line numbers are
    /// the file's own.
    pub text: String,
    /// Whether `label` is a referenced file rather than the virtual label.
    pub file: bool,
}

impl HookBody {
    /// Every segment joined into one text (for masking, which rewrites the
    /// payload as a whole).
    pub fn joined_text(&self) -> String {
        self.segments
            .iter()
            .map(|segment| {
                if segment.file {
                    format!("// ---- {}\n{}", segment.label, segment.text)
                } else {
                    segment.text.clone()
                }
            })
            .collect::<Vec<_>>()
            .join("\n---\n")
    }
}

/// Returns display path (posix-ish relative to repo) + body content to scan.
pub fn stdin_to_hook_body(
    tool: AiHookTool,
    post: bool,
    stdin: &str,
    cwd: &Path,
    repo_root: &Path,
) -> Result<(String, String)> {
    hook_body_from_stdin(tool, post, stdin, cwd, repo_root).map(|hook| {
        let body = hook.joined_text();
        (hook.display, body)
    })
}

pub fn hook_body_from_stdin(
    tool: AiHookTool,
    post: bool,
    stdin: &str,
    cwd: &Path,
    repo_root: &Path,
) -> Result<HookBody> {
    let mut v: Value = serde_json::from_str(stdin).context("hook stdin must be valid JSON")?;
    // Pre hooks look inside JSON-encoded argument envelopes (Copilot CLI
    // `toolArgs`) so paths, edits, and text keys there are found. Post hooks
    // keep the payload as sent.
    if !post {
        decode_encoded_arguments(&mut v);
    }
    let v = &v;

    // Post payloads describe writes that already ran; the file body is current.
    let mut writes = FileWrites::default();
    if !post {
        collect_file_writes(tool, v, None, &mut writes);
    }
    let local_write = writes_local_file(tool, v);

    // Referenced files are scanned whole (with pre-hook edits applied) and do
    // not spend the payload budget.
    let candidates = read_candidate_files(tool, v, cwd, repo_root)?;
    let file_target = |path: Option<&str>| {
        local_write
            .then(|| target_index(&candidates.files, path?, cwd))
            .flatten()
    };
    let edit_targets: Vec<_> = writes.edits.iter().map(|e| file_target(e.path)).collect();
    let text_targets: Vec<_> = writes.texts.iter().map(|t| file_target(t.path)).collect();
    let mut files = candidates.files;
    for (index, file) in files.iter_mut().enumerate() {
        apply_text_edits(&mut file.text, index, &mut writes.edits, &edit_targets);
    }

    let mut texts = HookTexts {
        // A post payload reports the output of the call that read the file
        // (e.g. Read's result), so with one file read it is scanned under that
        // file's path, like the file. Pre payload text goes to the virtual
        // label.
        payload_file: (post && files.len() == 1).then_some(0),
        ..HookTexts::default()
    };
    for (index, file) in files.iter().enumerate() {
        // The file body is scanned already; a string equal to it under the
        // same label (e.g. Cursor's `content`) adds nothing.
        texts.cover(Some(index), &file.text);
    }
    // Text written to a file that was read is scanned under that file's path,
    // like the file itself.
    for (text, target) in writes.texts.iter().zip(&text_targets) {
        texts.push_bound(*target, text.text);
    }
    for (edit, target) in writes.edits.iter().zip(&edit_targets) {
        if edit.applied {
            texts.bind(edit.new);
        } else {
            texts.push_bound(*target, edit.new);
            // Any edit but a local file edit (a remote document, an MCP API)
            // sends its old text to the tool too.
            if !(local_write && edit.file_edit) {
                texts.push(edit.old);
            }
        }
    }
    text_priority_chunks(v, post, tool, &candidates.read_paths, &mut texts);
    // An envelope is the tool's whole argument list. Scan every value in it,
    // so one matching key (or a file read) cannot hide the rest the way it
    // disables the fallback below.
    if !post {
        for key in ARGUMENT_ENVELOPE_KEYS {
            if let Some(envelope) = v.get(*key) {
                push_envelope_strings(tool, envelope, &candidates.read_paths, &mut texts);
            }
        }
    }

    if texts.blobs.is_empty() && files.is_empty() {
        collect_large_strings(v, &mut texts, 96);
    }

    let mut segments: Vec<HookSegment> = files
        .iter()
        .enumerate()
        .map(|(index, file)| {
            let mut text = file.text.clone();
            for blob in texts.blobs_for(Some(index)) {
                text.push_str("\n---\n");
                text.push_str(blob);
            }
            HookSegment {
                label: file.rel.clone(),
                text,
                file: true,
            }
        })
        .collect();
    let payload_text: Vec<&str> = texts.blobs_for(None).collect();
    if !payload_text.is_empty() || segments.is_empty() {
        segments.push(HookSegment {
            label: tool.virtual_path_label().to_string(),
            file: false,
            text: if payload_text.is_empty() {
                "{}".to_string()
            } else {
                payload_text.join("\n---\n")
            },
        });
    }

    Ok(HookBody {
        display: match files.as_slice() {
            [only] => only.rel.clone(),
            _ => tool.virtual_path_label().to_string(),
        },
        segments,
        truncated: texts.truncated,
    })
}

/// Payload strings collected for scanning, each with the file it is scanned
/// with (`None`: the payload segment under the tool's virtual label).
/// `payload_file` is where `push` places payload text.
/// Each distinct string is charged once against `MAX_HOOK_TEXT_BYTES` (the
/// same string is often reachable through several keys).
#[derive(Default)]
struct HookTexts<'a> {
    blobs: Vec<(Option<usize>, &'a str)>,
    placed: HashSet<(Option<usize>, &'a str)>,
    charged: HashSet<&'a str>,
    /// Payload strings (by address) already placed with a file; key scans
    /// that reach the same JSON value again skip it. An equal string under
    /// another key is a different value and is still scanned.
    bound: HashSet<usize>,
    payload_file: Option<usize>,
    used: usize,
    truncated: bool,
}

impl<'a> HookTexts<'a> {
    /// Text from the payload, scanned under the tool's virtual label (or the
    /// one file a post payload read).
    fn push(&mut self, s: &'a str) {
        if !self.bound.contains(&(s.as_ptr() as usize)) {
            self.place(self.payload_file, s);
        }
    }

    /// Text written to `file` (or, with no file read, to the payload segment).
    fn push_bound(&mut self, file: Option<usize>, s: &'a str) {
        self.bind(s);
        self.place(file, s);
    }

    /// Marks a payload value as handled elsewhere (e.g. applied edit text).
    fn bind(&mut self, s: &'a str) {
        self.bound.insert(s.as_ptr() as usize);
    }

    /// Text the scan already covers with `file`, free of charge.
    fn cover(&mut self, file: Option<usize>, s: &'a str) {
        self.placed.insert((file, s));
        self.charged.insert(s);
    }

    fn place(&mut self, file: Option<usize>, s: &'a str) {
        if s.trim().is_empty() || self.placed.contains(&(file, s)) {
            return;
        }
        // Whether a payload overflows depends only on the total size of its
        // distinct strings, never on the order the keys are visited in.
        if !self.charged.contains(s) {
            if self.used + s.len() > MAX_HOOK_TEXT_BYTES {
                self.truncated = true;
                return;
            }
            self.used += s.len();
            self.charged.insert(s);
        }
        self.placed.insert((file, s));
        self.blobs.push((file, s));
    }

    fn blobs_for(&self, file: Option<usize>) -> impl Iterator<Item = &'a str> + '_ {
        self.blobs
            .iter()
            .filter(move |(target, _)| *target == file)
            .map(|(_, s)| *s)
    }
}

/// A text file inside the repository named by a payload path argument.
struct CandidateFile {
    abs: PathBuf,
    rel: String,
    text: String,
}

/// Files read for a payload, and the payload path strings that named them.
struct CandidateFiles {
    files: Vec<CandidateFile>,
    read_paths: HashSet<String>,
}

fn rel_from_repo(repo_root: &Path, abs: &Path) -> String {
    abs.strip_prefix(repo_root)
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .unwrap_or_else(|_| abs.to_string_lossy().replace('\\', "/"))
}

/// Writes a pre-hook payload makes to files: replace-style edits and whole
/// new text, each with the nearest enclosing file-path argument.
#[derive(Default)]
struct FileWrites<'a> {
    edits: Vec<TextEdit<'a>>,
    texts: Vec<FileText<'a>>,
}

/// A replace-style edit found in a pre-hook payload.
struct TextEdit<'a> {
    /// Nearest enclosing file-path argument, as written in the payload.
    path: Option<&'a str>,
    /// The edit or an ancestor names a file path, even an ambiguous one: it
    /// edits a local file rather than a remote document.
    file_edit: bool,
    old: &'a str,
    new: &'a str,
    replace_all: bool,
    applied: bool,
}

/// Whole text a pre-hook payload writes to a file (FILE_TEXT_KEYS).
struct FileText<'a> {
    path: Option<&'a str>,
    text: &'a str,
}

/// The complete replace-style edit pairs on one payload object, as
/// `(old_key, new_key, old, new)`. Only a pair of strings is an edit; a lone
/// or non-string `new_str` is ordinary argument text.
fn edit_pairs(
    map: &serde_json::Map<String, Value>,
) -> impl Iterator<Item = (&'static str, &'static str, &str, &str)> {
    EDIT_PAIR_KEYS.iter().filter_map(|(old_key, new_key)| {
        let old = map.get(*old_key)?.as_str()?;
        let new = map.get(*new_key)?.as_str()?;
        Some((*old_key, *new_key, old, new))
    })
}

/// Collects edits and written text in payload order (arrays keep their order,
/// so MultiEdit `edits[]` apply sequentially). Each targets the file-body path
/// key on its own object or the nearest ancestor. An object with several
/// distinct path values is ambiguous: its writes target no file, so their text
/// is scanned on its own instead of under another file's suppressions.
fn collect_file_writes<'a>(
    tool: AiHookTool,
    v: &'a Value,
    inherited: Option<Option<&'a str>>,
    out: &mut FileWrites<'a>,
) {
    match v {
        Value::Object(map) => {
            let own_paths: HashSet<&str> = map
                .iter()
                .filter(|(key, _)| is_file_body_path_key(tool, key))
                .filter_map(|(_, val)| val.as_str())
                .collect();
            // `Some(None)`: a path is named but ambiguous. An inner path that
            // differs from an enclosing one is ambiguous too: tools such as
            // OpenCode `multiedit` write the top-level `filePath` whatever an
            // item says, so binding to the inner path could apply a write to
            // an allowlisted file it never touches.
            let own = (own_paths.len() == 1)
                .then(|| own_paths.iter().next().copied())
                .flatten();
            let named = match (inherited, own_paths.len()) {
                (inherited, 0) => inherited,
                (None, 1) => Some(own),
                (Some(Some(outer)), 1) if Some(outer) == own => Some(own),
                _ => Some(None),
            };
            let path = named.flatten();
            let replace_all = ["replace_all", "replaceAll", "AllowMultiple"]
                .iter()
                .any(|key| map.get(*key).and_then(Value::as_bool) == Some(true));
            for (_, _, old, new) in edit_pairs(map) {
                out.edits.push(TextEdit {
                    path,
                    file_edit: named.is_some(),
                    old,
                    new,
                    replace_all,
                    applied: false,
                });
            }
            if path.is_some() {
                for key in FILE_TEXT_KEYS {
                    if let Some(text) = map.get(*key).and_then(Value::as_str) {
                        out.texts.push(FileText { path, text });
                    }
                }
            }
            for val in map.values() {
                collect_file_writes(tool, val, named, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_file_writes(tool, item, inherited, out);
            }
        }
        _ => {}
    }
}

/// Index into `files` of the file `path` names, if it was read.
fn target_index(files: &[CandidateFile], path: &str, cwd: &Path) -> Option<usize> {
    let abs = fs::canonicalize(resolve_path(path, cwd)).ok()?;
    files.iter().position(|file| file.abs == abs)
}

/// Whether the payload comes from a tool that writes the local file its own
/// path argument names. Only such tools have their edits applied and their
/// written text scanned under the file's path; any other tool, such as an MCP
/// tool that sends a `path` and `content` to a remote service, keeps its text
/// under the virtual label, so a path allowlist cannot cover it. Names are
/// matched per editor because MCP tools can carry bare names (Cursor's
/// `beforeMCPExecution` sends the server's own tool name).
fn writes_local_file(tool: AiHookTool, v: &Value) -> bool {
    let field = |key: &str| v.get(key).and_then(Value::as_str);
    let is_one_of = |name: Option<&str>, names: &[&str]| name.is_some_and(|n| names.contains(&n));
    match tool {
        // Grok Build runs Claude Code and Cursor hook entries with its own
        // payload shape (`toolName`).
        AiHookTool::ClaudeCode | AiHookTool::Cursor
            if field("toolName") == Some("search_replace") =>
        {
            true
        }
        AiHookTool::ClaudeCode => is_one_of(
            field("tool_name"),
            &[
                "Write",
                "Edit",
                "MultiEdit",
                "NotebookEdit",
                "mcp__filesystem__edit_file",
                "mcp__filesystem__write_file",
            ],
        ),
        AiHookTool::Copilot => {
            let names = [
                // Copilot CLI
                "create",
                "edit",
                // Copilot in VS Code
                "create_file",
                "replace_string_in_file",
                "multi_replace_string_in_file",
                "insert_edit_into_file",
                "edit_notebook_file",
            ];
            is_one_of(field("toolName"), &names) || is_one_of(field("tool_name"), &names)
        }
        AiHookTool::Grok => field("toolName") == Some("search_replace"),
        AiHookTool::Opencode => is_one_of(field("tool_name"), &["write", "edit", "multiedit"]),
        AiHookTool::Antigravity => is_one_of(
            v.pointer("/toolCall/name").and_then(Value::as_str),
            &[
                "write_to_file",
                "replace_file_content",
                "multi_replace_file_content",
            ],
        ),
        AiHookTool::Windsurf => field("agent_action_name") == Some("pre_write_code"),
        // `beforeReadFile` is a read: binding ties its `content` (the file
        // body) to the file. MCP calls never count.
        AiHookTool::Cursor => field("hook_event_name") == Some("beforeReadFile"),
        // Codex edits go through `apply_patch`, whose patch is a `command`.
        AiHookTool::Codex => false,
    }
}

/// Applies the edits that target file `index` to its body in order, marking
/// each one applied. An edit whose `old` text is empty or missing is left for
/// standalone scanning, as is one that would grow the body past
/// `original_len + MAX_HOOK_TEXT_BYTES` (a `replace_all` of a short `old` can
/// otherwise multiply the body until the hook times out, and a timed-out hook
/// does not block). For the same reason, edits stop being applied once
/// searching and rewriting the body has touched `MAX_EDIT_WORK_BYTES`: each
/// edit costs a pass over the whole body, so a long edit list on a large file
/// would otherwise run past the hook timeout.
fn apply_text_edits(
    text: &mut String,
    index: usize,
    edits: &mut [TextEdit<'_>],
    targets: &[Option<usize>],
) {
    let max_len = text.len().saturating_add(MAX_HOOK_TEXT_BYTES);
    let mut work = 0usize;
    for (edit, target) in edits.iter_mut().zip(targets) {
        if *target != Some(index) || edit.old.is_empty() {
            continue;
        }
        // One pass to search, one more to rewrite.
        work = work.saturating_add(text.len().saturating_mul(2));
        if work > MAX_EDIT_WORK_BYTES {
            break;
        }
        let (mut old, mut new) = (Cow::Borrowed(edit.old), Cow::Borrowed(edit.new));
        let mut count = match_count(text, &old, edit.replace_all);
        if count == 0 && old.contains('\n') && !old.contains('\r') && text.contains("\r\n") {
            // Editors match `old` with line endings normalised; on a CRLF file
            // the edit lands with CRLF line endings.
            work = work.saturating_add(text.len());
            old = Cow::Owned(edit.old.replace('\n', "\r\n"));
            new = Cow::Owned(edit.new.replace('\n', "\r\n"));
            count = match_count(text, &old, edit.replace_all);
        }
        let growth = new.len().saturating_sub(old.len());
        if count == 0 || text.len().saturating_add(count.saturating_mul(growth)) > max_len {
            continue;
        }
        *text = if edit.replace_all {
            text.replace(old.as_ref(), &new)
        } else {
            text.replacen(old.as_ref(), &new, 1)
        };
        edit.applied = true;
    }
}

/// Occurrences `old` would replace: all of them, or at most the first.
fn match_count(text: &str, old: &str, replace_all: bool) -> usize {
    if replace_all {
        text.matches(old).count()
    } else {
        usize::from(text.contains(old))
    }
}

/// Reads every distinct text file inside the repository that a payload path
/// argument names.
fn read_candidate_files(
    tool: AiHookTool,
    v: &Value,
    cwd: &Path,
    repo_root: &Path,
) -> Result<CandidateFiles> {
    let mut files = Vec::new();
    let mut read_paths = HashSet::new();
    // Whether each file seen so far was read (binary files are skipped).
    let mut seen: HashMap<PathBuf, bool> = HashMap::new();
    let repo_root = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());

    for cand in candidate_path_strings(tool, v) {
        let p = resolve_path(&cand, cwd);
        let p = fs::canonicalize(&p).ok();
        if let Some(abs) = p
            && abs.is_file()
            && abs.starts_with(&repo_root)
        {
            if let Some(read) = seen.get(&abs) {
                if *read {
                    read_paths.insert(cand);
                }
                continue;
            }
            seen.insert(abs.clone(), false);
            let bytes =
                fs::read(&abs).with_context(|| format!("read scanned file {}", abs.display()))?;
            // Match the ordinary scanner's default NUL-in-head heuristic.
            // Do not skip by extension: text disguised as an image still needs
            // scanning. Lossy decoding preserves ASCII secrets in legacy text
            // and binary formats without NUL bytes, without a UTF-8 error.
            if bytes.iter().take(8192).any(|byte| *byte == 0) {
                continue;
            }
            seen.insert(abs.clone(), true);
            read_paths.insert(cand);
            files.push(CandidateFile {
                rel: rel_from_repo(&repo_root, &abs),
                text: String::from_utf8_lossy(&bytes).into_owned(),
                abs,
            });
        }
    }
    Ok(CandidateFiles { files, read_paths })
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

/// Pushes the strings under each tool's text keys. Pre hooks skip what the
/// envelope scan skips (edit pairs and read path values, handled elsewhere),
/// so a generic key such as `args` cannot rescan an edit's old text.
fn text_priority_chunks<'a>(
    v: &'a Value,
    post: bool,
    tool: AiHookTool,
    read_paths: &HashSet<String>,
    texts: &mut HookTexts<'a>,
) {
    let mut push = |val: &'a Value, texts: &mut HookTexts<'a>| {
        if post {
            push_strings_from_value(val, texts);
        } else {
            push_envelope_strings(tool, val, read_paths, texts);
        }
    };
    for keys in priority_text_key_sets(post, tool) {
        grab_strings_for_keys_deep(v, keys, &mut push, texts);
    }
}

fn priority_text_key_sets(post: bool, tool: AiHookTool) -> &'static [&'static [&'static str]] {
    if !post {
        return match tool {
            AiHookTool::Antigravity => &[PRE_TEXT_KEYS, ANTIGRAVITY_PRE_EXTRA_TEXT_KEYS],
            AiHookTool::Windsurf => &[PRE_TEXT_KEYS, WINDSURF_PRE_EXTRA_TEXT_KEYS],
            AiHookTool::ClaudeCode
            | AiHookTool::Codex
            | AiHookTool::Copilot
            | AiHookTool::Cursor
            | AiHookTool::Grok
            | AiHookTool::Opencode => &[PRE_TEXT_KEYS],
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

fn grab_strings_for_keys_deep<'a>(
    v: &'a Value,
    keys: &[&str],
    push: &mut impl FnMut(&'a Value, &mut HookTexts<'a>),
    acc: &mut HookTexts<'a>,
) {
    match v {
        Value::Object(map) => {
            for (k, val) in map {
                if keys.iter().any(|x| x == &k.as_str()) {
                    push(val, acc);
                }
                grab_strings_for_keys_deep(val, keys, push, acc);
            }
        }
        Value::Array(a) => {
            for i in a {
                grab_strings_for_keys_deep(i, keys, push, acc);
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

/// Pushes every string in an argument envelope except values handled
/// elsewhere: path arguments that named a file read for the scan, and
/// edit-pair text (applied edits are in the edited file body, keeping its
/// inline suppressions; unapplied ones push their text separately).
fn push_envelope_strings<'a>(
    tool: AiHookTool,
    v: &'a Value,
    read_paths: &HashSet<String>,
    acc: &mut HookTexts<'a>,
) {
    match v {
        Value::Object(map) => {
            let pair_keys: Vec<&str> = edit_pairs(map)
                .flat_map(|(old_key, new_key, _, _)| [old_key, new_key])
                .collect();
            for (key, val) in map {
                let read_path = is_file_body_path_key(tool, key)
                    && val.as_str().is_some_and(|path| read_paths.contains(path));
                if !read_path && !pair_keys.contains(&key.as_str()) {
                    push_envelope_strings(tool, val, read_paths, acc);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                push_envelope_strings(tool, item, read_paths, acc);
            }
        }
        Value::String(s) => acc.push(s),
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
        assert!(!hook.joined_text().contains(&big));

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
        assert!(hook.joined_text().contains("dedup-tail-marker"));
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
        assert!(hook.joined_text().contains("edit-arg-marker"));

        // A payload that repeats the file body (Cursor `beforeReadFile`
        // sends it as `content`) is covered by the file scan.
        let body = std::fs::read_to_string(&file).unwrap();
        let stdin = serde_json::json!({ "hook_event_name": "beforeReadFile", "file_path": file, "content": body }).to_string();
        let hook = hook_body_from_stdin(AiHookTool::Cursor, false, &stdin, dir.path(), dir.path())
            .unwrap();
        assert!(!hook.truncated);
        assert_eq!(hook.joined_text().matches(&body).count(), 1);
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
            "tool_name": "Edit",
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
            "tool_name": "Edit",
            "tool_input": { "file_path": "app.txt", "old_string": "x", "new_string": "y" }
        });
        let all = serde_json::json!({
            "tool_name": "Edit",
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
            "tool_name": "Edit",
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
            "tool_name": "Edit",
            "tool_input": {
                "file_path": outside.path().join("app.txt"),
                "old_string": "old-edit-marker",
                "new_string": token
            }
        });

        let (display, body) = pre_body(AiHookTool::ClaudeCode, repo.path(), &stdin);

        assert_eq!(display, "<claude-hook>");
        assert!(body.starts_with(&format!("{token}\n---\n")), "{body}");
        assert!(!body.contains("old-edit-marker"), "{body}");
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
            "tool_name": "Edit",
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
            "tool_name": "Edit",
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
            "tool_name": "multi_replace_string_in_file",
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
    fn object_argument_envelopes_are_scanned_next_to_a_file_read() {
        // Reading `app.txt` disables the large-string fallback, so every other
        // argument must come from the envelope scan.
        let repo = repo_with_file("clean body\n");
        let token = synthetic_github_token();
        let payloads = [
            (
                AiHookTool::ClaudeCode,
                serde_json::json!({
                    "tool_name": "mcp__notes__append",
                    "tool_input": { "path": "app.txt", "body": token }
                }),
            ),
            (
                AiHookTool::Copilot,
                serde_json::json!({
                    "tool_name": "insert_edit_into_file",
                    "tool_input": { "filePath": "app.txt", "code": token, "explanation": "x" }
                }),
            ),
            (
                AiHookTool::Grok,
                serde_json::json!({
                    "toolName": "custom",
                    "toolInput": { "file_path": "app.txt", "payload": { "nested": token } }
                }),
            ),
        ];

        for (tool, stdin) in &payloads {
            let (display, body) = pre_body(*tool, repo.path(), stdin);
            assert_eq!(display, "app.txt", "{tool:?}");
            assert!(body.contains(&token), "{tool:?}: {body}");
            assert!(
                !body.contains("---\napp.txt"),
                "paths are not scanned as text: {body}"
            );
        }
    }

    /// Text of the segment scanned under `label`.
    fn segment<'h>(hook: &'h HookBody, label: &str) -> &'h str {
        hook.segments
            .iter()
            .find(|segment| segment.label == label)
            .map(|segment| segment.text.as_str())
            .unwrap_or_else(|| panic!("no {label} segment in {hook:?}"))
    }

    fn pre_hook(tool: AiHookTool, repo: &Path, stdin: &serde_json::Value) -> HookBody {
        hook_body_from_stdin(tool, false, &stdin.to_string(), repo, repo).unwrap()
    }

    #[test]
    fn only_text_written_to_a_file_is_scanned_under_its_path() {
        let repo = repo_with_file("clean body\n");
        let token = synthetic_github_token();

        // An argument sent elsewhere is payload text, even next to a file read,
        // so a path allowlist for that file cannot cover it.
        let mcp = pre_hook(
            AiHookTool::ClaudeCode,
            repo.path(),
            &serde_json::json!({
                "tool_name": "mcp__notes__append",
                "tool_input": { "path": "app.txt", "body": token }
            }),
        );
        assert!(!segment(&mcp, "app.txt").contains(&token), "{mcp:?}");
        assert!(segment(&mcp, "<claude-hook>").contains(&token), "{mcp:?}");

        // Text written to the file is scanned with it, under its path.
        let write = pre_hook(
            AiHookTool::ClaudeCode,
            repo.path(),
            &serde_json::json!({
                "tool_name": "Write",
                "tool_input": { "file_path": "app.txt", "content": token, "note": token }
            }),
        );
        assert!(segment(&write, "app.txt").contains(&token), "{write:?}");
        // An equal string under another key is still payload text.
        assert!(
            segment(&write, "<claude-hook>").contains(&token),
            "{write:?}"
        );

        // Unread path values are ordinary argument text.
        let get = pre_hook(
            AiHookTool::ClaudeCode,
            repo.path(),
            &serde_json::json!({
                "tool_name": "mcp__http__get",
                "tool_input": { "method": "GET", "path": format!("/items?token={token}") }
            }),
        );
        assert!(segment(&get, "<claude-hook>").contains(&token), "{get:?}");
    }

    #[test]
    fn each_file_is_scanned_under_its_own_path() {
        let repo = tempdir().expect("temp repo");
        std::fs::write(repo.path().join("a.txt"), "shared\n").expect("write a");
        std::fs::write(repo.path().join("b.txt"), "shared\n").expect("write b");
        let hook = pre_hook(
            AiHookTool::Copilot,
            repo.path(),
            &serde_json::json!({
                "tool_name": "multi_replace_string_in_file",
                "tool_input": {
                    "replacements": [
                        { "filePath": "a.txt", "oldString": "shared", "newString": "a-marker" },
                        { "filePath": "b.txt", "oldString": "shared", "newString": "b-marker" }
                    ]
                }
            }),
        );

        assert_eq!(hook.display, "<copilot-hook>");
        assert_eq!(hook.segments.len(), 2, "{hook:?}");
        assert!(segment(&hook, "a.txt").contains("a-marker"), "{hook:?}");
        assert!(segment(&hook, "b.txt").contains("b-marker"), "{hook:?}");
    }

    #[test]
    fn only_local_write_tools_scan_their_text_under_the_file_path() {
        let repo = repo_with_file("API=placeholder\n");
        let token = synthetic_github_token();

        // An MCP tool naming a local path still sends its text elsewhere: no
        // edit is applied and nothing is scanned under the file's path.
        for tool_input in [
            serde_json::json!({ "owner": "o", "repo": "r", "path": "app.txt", "content": token }),
            serde_json::json!({ "attachment_path": "app.txt", "messages": [{ "content": token }] }),
            serde_json::json!({ "path": "app.txt", "old_string": "placeholder", "new_string": token }),
        ] {
            let hook = pre_hook(
                AiHookTool::ClaudeCode,
                repo.path(),
                &serde_json::json!({
                    "tool_name": "mcp__github__create_or_update_file",
                    "tool_input": tool_input
                }),
            );
            assert!(!segment(&hook, "app.txt").contains(&token), "{hook:?}");
            assert!(segment(&hook, "<claude-hook>").contains(&token), "{hook:?}");
        }

        // Local write tools of other editors keep their text with the file.
        let writes = [
            (
                AiHookTool::Copilot,
                serde_json::json!({
                    "tool_name": "insert_edit_into_file",
                    "tool_input": { "filePath": "app.txt", "code": token, "explanation": "x" }
                }),
            ),
            (
                AiHookTool::Antigravity,
                serde_json::json!({
                    "toolCall": {
                        "name": "write_to_file",
                        "args": { "TargetFile": "app.txt", "CodeContent": token }
                    }
                }),
            ),
            (
                AiHookTool::Antigravity,
                serde_json::json!({
                    "toolCall": {
                        "name": "replace_file_content",
                        "args": {
                            "TargetFile": "app.txt",
                            "ReplacementChunks": [
                                { "TargetContent": "placeholder", "ReplacementContent": token }
                            ]
                        }
                    }
                }),
            ),
        ];
        for (tool, stdin) in &writes {
            let hook = pre_hook(*tool, repo.path(), stdin);
            assert!(segment(&hook, "app.txt").contains(&token), "{hook:?}");
            assert!(
                !hook
                    .segments
                    .iter()
                    .any(|s| !s.file && s.text.contains(&token)),
                "{hook:?}"
            );
        }
    }

    #[test]
    fn local_write_tools_are_matched_per_editor() {
        let repo = repo_with_file("API=placeholder\n");
        let token = synthetic_github_token();
        let in_file = |tool: AiHookTool, stdin: serde_json::Value| {
            let hook = pre_hook(tool, repo.path(), &stdin);
            segment(&hook, "app.txt").contains(&token)
        };

        // Local writes keep their text with the file.
        assert!(in_file(
            AiHookTool::Grok,
            serde_json::json!({
                "toolName": "search_replace",
                "toolInput": { "file_path": "app.txt", "old_string": "placeholder", "new_string": token }
            })
        ));
        assert!(in_file(
            AiHookTool::ClaudeCode,
            serde_json::json!({
                "tool_name": "mcp__filesystem__write_file",
                "tool_input": { "path": "app.txt", "content": token }
            })
        ));
        assert!(in_file(
            AiHookTool::Opencode,
            serde_json::json!({
                "tool_name": "multiedit",
                "tool_input": {
                    "filePath": "app.txt",
                    "edits": [{ "oldString": "placeholder", "newString": token }]
                }
            })
        ));

        // A bare MCP tool name from Cursor or another server is not a local
        // write, whatever it is called.
        assert!(!in_file(
            AiHookTool::Cursor,
            serde_json::json!({
                "hook_event_name": "beforeMCPExecution",
                "tool_name": "write",
                "tool_input": { "path": "app.txt", "content": token }
            })
        ));
        assert!(!in_file(
            AiHookTool::ClaudeCode,
            serde_json::json!({
                "tool_name": "mcp__sandbox__edit_file",
                "tool_input": {
                    "path": "app.txt",
                    "edits": [{ "oldText": "placeholder", "newText": token }]
                }
            })
        ));
    }

    #[test]
    fn an_inner_path_that_differs_from_the_outer_one_targets_no_file() {
        let repo = repo_with_file("API=placeholder\n");
        std::fs::write(repo.path().join("plain.txt"), "other\n").expect("write plain");
        let token = synthetic_github_token();
        let hook = pre_hook(
            AiHookTool::Opencode,
            repo.path(),
            &serde_json::json!({
                "tool_name": "multiedit",
                "tool_input": {
                    "filePath": "plain.txt",
                    "edits": [
                        { "filePath": "app.txt", "oldString": "placeholder", "newString": token }
                    ]
                }
            }),
        );

        assert_eq!(segment(&hook, "app.txt"), "API=placeholder\n");
        assert!(
            segment(&hook, "<opencode-hook>").contains(&token),
            "{hook:?}"
        );
    }

    #[test]
    fn windsurf_and_copilot_vscode_writes_apply_to_the_file() {
        let token = synthetic_github_token();
        let cases = [
            (
                AiHookTool::Windsurf,
                serde_json::json!({
                    "agent_action_name": "pre_write_code",
                    "tool_info": {
                        "file_path": "app.txt",
                        "edits": [{ "old_string": "placeholder", "new_string": token }]
                    }
                }),
            ),
            (
                AiHookTool::Copilot,
                serde_json::json!({
                    "tool_name": "replace_string_in_file",
                    "tool_input": { "filePath": "app.txt", "oldString": "placeholder", "newString": token }
                }),
            ),
        ];
        for (tool, stdin) in &cases {
            let repo = repo_with_file("API=placeholder\n");
            let hook = pre_hook(*tool, repo.path(), stdin);
            assert_eq!(
                segment(&hook, "app.txt"),
                format!("API={token}\n"),
                "{tool:?}: {hook:?}"
            );
            assert_eq!(hook.segments.len(), 1, "{tool:?}: {hook:?}");
        }
    }

    #[test]
    fn post_output_of_a_single_file_read_is_scanned_under_its_path() {
        let repo = repo_with_file("API=placeholder\n");
        let hook = hook_body_from_stdin(
            AiHookTool::ClaudeCode,
            true,
            &serde_json::json!({
                "tool_name": "Read",
                "tool_input": { "file_path": "app.txt" },
                "tool_response": { "content": "1\tAPI=placeholder" }
            })
            .to_string(),
            repo.path(),
            repo.path(),
        )
        .unwrap();

        assert_eq!(hook.segments.len(), 1, "{hook:?}");
        assert!(
            segment(&hook, "app.txt").contains("1\tAPI=placeholder"),
            "{hook:?}"
        );
    }

    #[test]
    fn grok_edits_through_claude_compatible_hooks_are_local() {
        let token = synthetic_github_token();
        let repo = repo_with_file("API=placeholder\n");
        let hook = pre_hook(
            AiHookTool::ClaudeCode,
            repo.path(),
            &serde_json::json!({
                "toolName": "search_replace",
                "toolInput": { "file_path": "app.txt", "old_string": "placeholder", "new_string": token }
            }),
        );
        assert_eq!(
            segment(&hook, "app.txt"),
            format!("API={token}\n"),
            "{hook:?}"
        );
    }

    #[test]
    fn antigravity_replacements_are_applied_to_the_file() {
        let token = synthetic_github_token();
        let repo = repo_with_file(&format!("A={token}\nB=placeholder\n"));
        let hook = pre_hook(
            AiHookTool::Antigravity,
            repo.path(),
            &serde_json::json!({
                "toolCall": {
                    "name": "multi_replace_file_content",
                    "args": {
                        "TargetFile": "app.txt",
                        "ReplacementChunks": [
                            { "TargetContent": format!("A={token}"), "ReplacementContent": "A=${A}" }
                        ]
                    }
                }
            }),
        );

        // Removing the value scans the edited file, not the replaced text.
        assert!(!hook.joined_text().contains(&token), "{hook:?}");
        assert!(
            segment(&hook, "app.txt").starts_with("A=${A}\n"),
            "{hook:?}"
        );
    }

    #[test]
    fn file_segments_start_with_the_file_body() {
        let repo = repo_with_file("line one\nline two\n");
        let hook = pre_hook(
            AiHookTool::ClaudeCode,
            repo.path(),
            &serde_json::json!({ "tool_name": "Read", "tool_input": { "file_path": "app.txt" } }),
        );
        assert_eq!(segment(&hook, "app.txt"), "line one\nline two\n");
        assert!(hook.joined_text().starts_with("// ---- app.txt\nline one"));
    }

    #[test]
    fn a_remote_edit_scans_its_old_text_but_a_file_edit_does_not() {
        let token = synthetic_github_token();
        let repo = tempdir().expect("temp repo");
        let remote = pre_hook(
            AiHookTool::ClaudeCode,
            repo.path(),
            &serde_json::json!({
                "tool_name": "mcp__docs__replace",
                "tool_input": { "doc_id": "d1", "old_str": token, "new_str": "x" }
            }),
        );
        assert!(remote.joined_text().contains(&token), "{remote:?}");

        let outside = tempdir().expect("outside dir");
        let local = pre_hook(
            AiHookTool::ClaudeCode,
            repo.path(),
            &serde_json::json!({
                "tool_name": "Edit",
                "tool_input": {
                    "file_path": outside.path().join("missing.txt"),
                    "old_string": token,
                    "new_string": "x"
                }
            }),
        );
        assert!(!local.joined_text().contains(&token), "{local:?}");
    }

    #[test]
    fn grok_edit_that_removes_a_finding_scans_the_edited_file_only() {
        let token = synthetic_github_token();
        let repo = repo_with_file(&format!("A={token}\n"));
        let stdin = serde_json::json!({
            "toolName": "search_replace",
            "toolInput": { "file_path": "app.txt", "old_string": token, "new_string": "${A}" }
        });

        let (_display, body) = pre_body(AiHookTool::Grok, repo.path(), &stdin);

        assert!(!body.contains(&token), "{body}");
    }

    #[test]
    fn envelope_text_past_the_budget_marks_the_body_truncated() {
        let token = synthetic_github_token();
        let stdin = copilot_cli_payload(
            "bash",
            serde_json::json!({
                "command": "a".repeat(MAX_HOOK_TEXT_BYTES),
                "description": token
            }),
        );

        let hook = hook_body_from_stdin(
            AiHookTool::Copilot,
            false,
            &stdin.to_string(),
            Path::new("."),
            Path::new("."),
        )
        .unwrap();

        assert!(hook.truncated);
    }

    #[test]
    fn multi_line_edits_apply_to_crlf_files() {
        let token = synthetic_github_token();
        let repo = repo_with_file("A=1\r\nB=placeholder\r\n");
        let stdin = serde_json::json!({
            "tool_name": "Edit",
            "tool_input": {
                "file_path": "app.txt",
                "old_string": "A=1\nB=placeholder",
                "new_string": format!("A=1\nB={token}")
            }
        });

        let (_display, body) = pre_body(AiHookTool::ClaudeCode, repo.path(), &stdin);

        assert!(body.contains(&format!("A=1\r\nB={token}\r\n")), "{body:?}");
        assert_eq!(body.matches(&token).count(), 1, "{body:?}");

        // Removing a value across lines scans the edited file, not the old text.
        let repo = repo_with_file(&format!("A=1\r\nB={token}\r\n"));
        let stdin = serde_json::json!({
            "tool_name": "Edit",
            "tool_input": {
                "file_path": "app.txt",
                "old_string": format!("A=1\nB={token}"),
                "new_string": "A=1\nB=${B}"
            }
        });
        let (_display, body) = pre_body(AiHookTool::ClaudeCode, repo.path(), &stdin);
        assert!(!body.contains(&token), "{body:?}");
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
        assert!(!body.contains("outside body"), "{body}");
        // The unread path is ordinary argument text.
        assert!(body.starts_with("fallback prompt\n---\n"), "{body}");
    }
}
