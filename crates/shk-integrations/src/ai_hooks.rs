//! Parse AI tool stdin JSON payloads (MVP heuristic; spec §7.9).

use anyhow::{Context, Result};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

const PATH_KEYS: &[&str] = &[
    "path",
    "file_path",
    "filePath",
    "target_file",
    "targetPath",
    "uri",
    "fileName",
];

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
        collect_large_strings(&v, &mut blobs, 96, 4096 * 512);
    }

    let body = if blobs.is_empty() {
        "{}".into()
    } else {
        blobs.join("\n---\n")
    };

    let disp = display.unwrap_or_else(|| tool.virtual_path_label().to_string());

    Ok((disp, body))
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

    for cand in candidate_path_strings(v) {
        let p = resolve_path(&cand, cwd);
        let p = fs::canonicalize(&p).ok();
        if let Some(abs) = p
            && abs.is_file()
        {
            let rel = rel_from_repo(repo_root, &abs);
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
    let priority: &[&str] = if post {
        match tool {
            AiHookTool::Codex => &[
                "stdout", "stderr", "output", "result", "content", "text", "body",
            ],
            AiHookTool::ClaudeCode => &["stdout", "stderr", "content", "response", "text", "body"],
            AiHookTool::Cursor => &["content", "text", "command", "shell_command", "args"],
        }
    } else {
        &[
            "prompt", "text", "content", "command", "stdin", "args", "url",
        ]
    };

    grab_strings_for_keys_deep(v, priority, blobs);
}

fn grab_strings_for_keys_deep(v: &Value, keys: &[&str], acc: &mut Vec<String>) {
    match v {
        Value::Object(map) => {
            for (k, val) in map {
                if keys.iter().any(|x| x == &k.as_str()) {
                    push_string_leaf(val, acc);
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

fn push_string_leaf(v: &Value, acc: &mut Vec<String>) {
    match v {
        Value::String(s) if s.len() > 48 => acc.push(s.clone()),
        Value::Array(items) => {
            for x in items {
                if let Some(s) = x.as_str() {
                    acc.push(s.to_string());
                }
            }
        }
        _ => {}
    }
}

fn collect_large_strings(v: &Value, acc: &mut Vec<String>, min_len: usize, max_total_bytes: usize) {
    match v {
        Value::String(s) if s.len() >= min_len && acc_chars_len(acc) < max_total_bytes => {
            acc.push(s.clone());
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
