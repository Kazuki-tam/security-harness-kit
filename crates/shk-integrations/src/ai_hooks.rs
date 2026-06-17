//! Parse AI tool stdin JSON payloads (MVP heuristic; spec §7.9).

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
    // Antigravity tool arguments use PascalCase (e.g. view_file / write_to_file).
    "AbsolutePath",
    "TargetFile",
    "SearchPath",
    "DirectoryPath",
    "SearchDirectory",
];
const METADATA_PATH_KEYS: &[&str] = &[
    "artifactDirectoryPath",
    "transcriptPath",
    "workspacePath",
    "workspacePaths",
];
const MAX_HOOK_TEXT_BYTES: usize = 4096 * 512;
const PRE_TEXT_KEYS: &[&str] = &[
    "prompt", "text", "content", "command", "stdin", "args", "url",
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
    "TargetContent",
    "ReplacementContent",
    "Url",
    "Prompt",
    "Query",
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
const WINDSURF_PRE_EXTRA_TEXT_KEYS: &[&str] = &[
    "command_line",
    "user_prompt",
    "mcp_tool_arguments",
    "new_string",
    "old_string",
];
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AiHookTool {
    Antigravity,
    ClaudeCode,
    Codex,
    Copilot,
    Cursor,
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
        #[serde(borrow)]
        tool_info: Option<ToolInfo<'a>>,
    }

    let payload = serde_json::from_str::<UserPromptPayload<'_>>(stdin).ok()?;
    payload
        .prompt
        .or_else(|| payload.tool_info.and_then(|info| info.user_prompt))
}

/// Returns display path (posix-ish relative to repo) + body content to scan.
pub fn stdin_to_hook_body(
    tool: AiHookTool,
    post: bool,
    stdin: &str,
    cwd: &Path,
    repo_root: &Path,
) -> Result<(String, String)> {
    let v: Value = serde_json::from_str(stdin).context("hook stdin must be valid JSON")?;
    let mut blobs: Vec<String> = Vec::new();
    let mut display: Option<String> = None;

    if let Some((rel, txt)) = read_files_from_candidates(&v, cwd, repo_root)? {
        display = Some(rel);
        blobs.push(txt);
    }

    text_priority_chunks(&v, post, tool, &mut blobs);

    if blobs.is_empty() {
        collect_large_strings(&v, &mut blobs, 96, MAX_HOOK_TEXT_BYTES);
    }
    dedup_blobs(&mut blobs);

    let body = if blobs.is_empty() {
        "{}".into()
    } else {
        blobs.join("\n---\n")
    };

    let disp = display.unwrap_or_else(|| tool.virtual_path_label().to_string());

    Ok((disp, body))
}

fn dedup_blobs(blobs: &mut Vec<String>) {
    let mut seen = HashSet::new();
    blobs.retain(|s| seen.insert(s.clone()));
}

fn rel_from_repo(repo_root: &Path, abs: &Path) -> String {
    abs.strip_prefix(repo_root)
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .unwrap_or_else(|_| abs.to_string_lossy().replace('\\', "/"))
}

fn read_files_from_candidates(
    v: &Value,
    cwd: &Path,
    repo_root: &Path,
) -> Result<Option<(String, String)>> {
    let mut texts: Vec<String> = Vec::new();
    let mut first_rel: Option<String> = None;
    let repo_root = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());

    for cand in candidate_path_strings(v) {
        let p = resolve_path(&cand, cwd);
        let p = fs::canonicalize(&p).ok();
        if let Some(abs) = p
            && abs.is_file()
            && abs.starts_with(&repo_root)
        {
            let rel = rel_from_repo(&repo_root, &abs);
            if first_rel.is_none() {
                first_rel = Some(rel.clone());
            }
            let t = fs::read_to_string(&abs)
                .with_context(|| format!("read scanned file {}", abs.display()))?;
            texts.push(format!("// ---- {rel}\n{t}"));
        }
    }

    Ok(if texts.is_empty() {
        None
    } else {
        Some((
            first_rel.unwrap_or_else(|| "<file>".into()),
            texts.join("\n"),
        ))
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

fn candidate_path_strings(v: &Value) -> Vec<String> {
    let mut out = Vec::new();
    scan_path_keys(v, &mut out);
    out.sort_by_key(|s| std::cmp::Reverse(s.len()));
    out.dedup();
    out
}

fn scan_path_keys(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(map) => {
            for (k, val) in map {
                if !METADATA_PATH_KEYS.iter().any(|pk| pk == k)
                    && (PATH_KEYS.iter().any(|pk| pk == k)
                        || k.to_ascii_lowercase().ends_with("path"))
                    && let Some(s) = val.as_str()
                {
                    out.push(s.to_string());
                }
                scan_path_keys(val, out);
            }
        }
        Value::Array(a) => {
            for i in a {
                scan_path_keys(i, out);
            }
        }
        _ => {}
    }
}

fn text_priority_chunks(v: &Value, post: bool, tool: AiHookTool, blobs: &mut Vec<String>) {
    for keys in priority_text_key_sets(post, tool) {
        grab_strings_for_keys_deep(v, keys, blobs);
    }
}

fn priority_text_key_sets(post: bool, tool: AiHookTool) -> &'static [&'static [&'static str]] {
    if !post {
        return match tool {
            AiHookTool::Antigravity => &[PRE_TEXT_KEYS, ANTIGRAVITY_PRE_EXTRA_TEXT_KEYS],
            AiHookTool::Windsurf => &[PRE_TEXT_KEYS, WINDSURF_PRE_EXTRA_TEXT_KEYS],
            _ => &[PRE_TEXT_KEYS],
        };
    }

    match tool {
        AiHookTool::Antigravity => &[ANTIGRAVITY_POST_TEXT_KEYS],
        AiHookTool::Codex => &[CODEX_POST_TEXT_KEYS],
        AiHookTool::ClaudeCode => &[CLAUDE_POST_TEXT_KEYS],
        AiHookTool::Copilot => &[COPILOT_POST_TEXT_KEYS],
        AiHookTool::Cursor => &[CURSOR_POST_TEXT_KEYS],
        AiHookTool::Windsurf => &[WINDSURF_POST_TEXT_KEYS],
    }
}

fn grab_strings_for_keys_deep(v: &Value, keys: &[&str], acc: &mut Vec<String>) {
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

fn push_strings_from_value(v: &Value, acc: &mut Vec<String>) {
    match v {
        Value::String(s) => push_hook_text(s, acc, MAX_HOOK_TEXT_BYTES),
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

fn push_hook_text(s: &str, acc: &mut Vec<String>, max_total_bytes: usize) {
    if !s.trim().is_empty() && acc_chars_len(acc) < max_total_bytes {
        acc.push(s.to_string());
    }
}

fn collect_large_strings(v: &Value, acc: &mut Vec<String>, min_len: usize, max_total_bytes: usize) {
    match v {
        Value::String(s) if s.len() >= min_len && acc_chars_len(acc) < max_total_bytes => {
            push_hook_text(s, acc, max_total_bytes);
        }
        Value::Object(map) => {
            for (_k, val) in map {
                collect_large_strings(val, acc, min_len, max_total_bytes);
            }
        }
        Value::Array(a) => {
            for i in a {
                collect_large_strings(i, acc, min_len, max_total_bytes);
            }
        }
        _ => {}
    }
}

fn acc_chars_len(acc: &[String]) -> usize {
    acc.iter().map(|s| s.len()).sum()
}

#[cfg(test)]
mod tests {
    use super::*;
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
        assert_eq!(AiHookTool::Windsurf.kebab_str(), "windsurf");
        assert_eq!(AiHookTool::Windsurf.virtual_path_label(), "<windsurf-hook>");
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
        let stdin = serde_json::json!({
            "toolCall": {
                "name": "run_command",
                "args": {
                    "CommandLine": "echo safe-command"
                }
            },
            "transcriptPath": transcript,
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
