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
const CURSOR_POST_TEXT_KEYS: &[&str] = &["content", "text", "command", "shell_command", "args"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AiHookTool {
    ClaudeCode,
    Codex,
    Cursor,
}

impl AiHookTool {
    pub fn kebab_str(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
            Self::Cursor => "cursor",
        }
    }

    pub fn virtual_path_label(self) -> &'static str {
        match self {
            Self::ClaudeCode => "<claude-hook>",
            Self::Codex => "<codex-hook>",
            Self::Cursor => "<cursor-hook>",
        }
    }
}

/// Extracts the `prompt` field from a `UserPromptSubmit` JSON payload.
/// Returns `None` when the field is absent or the payload is not valid JSON.
pub fn extract_user_prompt(stdin: &str) -> Option<Cow<'_, str>> {
    #[derive(Deserialize)]
    struct UserPromptPayload<'a> {
        #[serde(borrow)]
        prompt: Option<Cow<'a, str>>,
    }

    serde_json::from_str::<UserPromptPayload<'_>>(stdin)
        .ok()?
        .prompt
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
                if (PATH_KEYS.iter().any(|pk| pk == k) || k.to_ascii_lowercase().ends_with("path"))
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
    grab_strings_for_keys_deep(v, priority_text_keys(post, tool), blobs);
}

fn priority_text_keys(post: bool, tool: AiHookTool) -> &'static [&'static str] {
    if !post {
        return PRE_TEXT_KEYS;
    }

    match tool {
        AiHookTool::Codex => CODEX_POST_TEXT_KEYS,
        AiHookTool::ClaudeCode => CLAUDE_POST_TEXT_KEYS,
        AiHookTool::Cursor => CURSOR_POST_TEXT_KEYS,
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
        assert_eq!(AiHookTool::Cursor.kebab_str(), "cursor");

        assert_eq!(AiHookTool::ClaudeCode.virtual_path_label(), "<claude-hook>");
        assert_eq!(AiHookTool::Codex.virtual_path_label(), "<codex-hook>");
        assert_eq!(AiHookTool::Cursor.virtual_path_label(), "<cursor-hook>");
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
