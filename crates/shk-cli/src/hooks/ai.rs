use crate::args::AiTool;
use anyhow::{Context, Result};
use regex::Regex;
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Timeout (seconds) embedded in Cursor / Codex hook command payloads (CLI JSON / TOML).
const HOOK_CLI_TIMEOUT_SEC: u64 = 30;

fn home_or_error() -> Result<PathBuf> {
    dirs::home_dir().ok_or_else(|| anyhow::anyhow!("unable to resolve user home directory"))
}

fn ai_config_relative_path(tool: AiTool) -> &'static str {
    match tool {
        AiTool::ClaudeCode => ".claude/settings.json",
        AiTool::Cursor => ".cursor/hooks.json",
        AiTool::Codex => ".codex/config.toml",
    }
}

fn resolve_ai_config_path(tool: AiTool, cwd: &Path, global: bool) -> Result<PathBuf> {
    let rel = ai_config_relative_path(tool);
    Ok(if global {
        home_or_error()?.join(rel)
    } else {
        cwd.join(rel)
    })
}

fn hook_scan_cli_command(tool: AiTool, audit: bool, post: bool) -> String {
    hook_scan_cli_command_with_fail_on(tool, audit, post, None)
}

fn hook_scan_cli_command_with_fail_on(
    tool: AiTool,
    audit: bool,
    post: bool,
    fail_on: Option<&str>,
) -> String {
    let suf_audit = if audit { " --audit" } else { "" };
    let suf_post = if post { " --post" } else { "" };
    let suf_fail_on = fail_on
        .map(|severity| format!(" --fail-on {severity}"))
        .unwrap_or_default();
    format!(
        "shk scan --hook-mode {}{}{}{}",
        tool.kebab_str(),
        suf_audit,
        suf_post,
        suf_fail_on,
    )
}

pub fn install_ai(
    cwd: &Path,
    maybe_tool: Option<AiTool>,
    audit: bool,
    dry_run: bool,
    global: bool,
    fail_closed: bool,
    apply_deny: bool,
) -> Result<()> {
    let tools = if let Some(t) = maybe_tool {
        vec![t]
    } else {
        vec![AiTool::ClaudeCode, AiTool::Codex, AiTool::Cursor]
    };

    println!("shk hooks install-ai (global={global}, audit={audit}, dry-run={dry_run})");
    let cwd = fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());

    for t in tools {
        let path = resolve_ai_config_path(t, &cwd, global)?;
        let summary = match t {
            AiTool::ClaudeCode => apply_claude(&path, audit, dry_run, apply_deny)?,
            AiTool::Cursor => apply_cursor(&path, audit, dry_run, fail_closed)?,
            AiTool::Codex => apply_codex(&path, audit, dry_run)?,
        };
        println!("{}: {}", path.display(), summary.trim_end_matches('\n'));
    }
    Ok(())
}

fn save_json_formatted(path: &Path, v: &Value, dry_run: bool) -> Result<()> {
    let text = serde_json::to_string_pretty(v)? + "\n";
    if dry_run {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::write(path, text).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn load_json(path: &Path) -> Result<Value> {
    let s = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&s).with_context(|| format!("parse JSON {}", path.display()))
}

fn is_managed_claude_block(block: &Value) -> bool {
    block.get("_shk_managed") == Some(&json!(true))
}

fn push_managed_claude(root: &mut Value, key: &str, block: Value) -> Result<()> {
    let hooks = root
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("Claude settings root must be a JSON object"))?;
    let arr_val = hooks.entry("hooks").or_insert_with(|| json!({}));
    let hooks_obj = arr_val
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("hooks must be an object"))?;
    let list_key = hooks_obj.entry(key).or_insert_with(|| json!([]));
    let arr = list_key
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("{key} hook list must be an array"))?;
    arr.retain(|b| !is_managed_claude_block(b));
    arr.push(block);
    Ok(())
}

fn merge_claude_permissions_deny(root: &mut Value) -> Result<usize> {
    let obj = root
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("Claude settings root must be a JSON object"))?;
    let permissions = obj.entry("permissions").or_insert_with(|| json!({}));
    let permissions_obj = permissions
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("permissions must be an object"))?;
    let deny = permissions_obj.entry("deny").or_insert_with(|| json!([]));
    let deny_arr = deny
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("permissions.deny must be an array"))?;

    let mut added = 0;
    for entry in shk_integrations::claude_recommended_deny_entries() {
        if !deny_arr
            .iter()
            .any(|existing| existing.as_str() == Some(entry))
        {
            deny_arr.push(json!(entry));
            added += 1;
        }
    }
    Ok(added)
}

fn apply_claude(path: &Path, audit: bool, dry_run: bool, apply_deny: bool) -> Result<String> {
    let pre = hook_scan_cli_command(AiTool::ClaudeCode, audit, false);
    let post = hook_scan_cli_command(AiTool::ClaudeCode, audit, true);
    let user_prompt =
        hook_scan_cli_command_with_fail_on(AiTool::ClaudeCode, audit, false, Some("medium"));

    let mut root = if path.is_file() {
        load_json(path)?
    } else {
        json!({})
    };

    let pre_block = json!({
        "_shk_managed": true,
        "matcher": "Read|Write|Bash|WebFetch|mcp__.*",
        "hooks": [{ "type": "command", "command": pre }]
    });
    let post_block = json!({
        "_shk_managed": true,
        "matcher": "WebFetch|WebSearch|Bash|mcp__.*|Skill|Agent",
        "hooks": [{ "type": "command", "command": post }]
    });
    let user_prompt_block = json!({
        "_shk_managed": true,
        "hooks": [{ "type": "command", "command": user_prompt }]
    });

    push_managed_claude(&mut root, "UserPromptSubmit", user_prompt_block)?;
    push_managed_claude(&mut root, "PreToolUse", pre_block)?;
    push_managed_claude(&mut root, "PostToolUse", post_block)?;
    let deny_added = if apply_deny {
        merge_claude_permissions_deny(&mut root)?
    } else {
        0
    };

    save_json_formatted(path, &root, dry_run)?;
    Ok(if dry_run {
        format!(
            "dry-run: would write managed UserPromptSubmit/PreToolUse/PostToolUse blocks (audit={audit}, applyDeny={apply_deny}, denyAdded={deny_added})"
        )
    } else {
        format!(
            "wrote managed blocks (audit={audit}, applyDeny={apply_deny}, denyAdded={deny_added})"
        )
    })
}

fn is_managed_cursor_entry(entry: &Value) -> bool {
    entry.get("_shk_managed") == Some(&json!(true))
}

fn apply_cursor(path: &Path, audit: bool, dry_run: bool, fail_closed: bool) -> Result<String> {
    const KEYS: &[&str] = &[
        "beforeReadFile",
        "beforeShellExecution",
        "beforeMCPExecution",
        "beforeSubmitPrompt",
    ];

    let cmd = hook_scan_cli_command(AiTool::Cursor, audit, false);
    let entry = json!({
        "command": cmd,
        "timeout": HOOK_CLI_TIMEOUT_SEC,
        "failClosed": fail_closed,
        "_shk_managed": true
    });

    let mut root = if path.is_file() {
        load_json(path)?
    } else {
        json!({
            "version": 1,
            "hooks": {}
        })
    };

    let root_obj = root
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("Cursor hooks root must be an object"))?;
    root_obj.entry("version").or_insert(json!(1));
    let hooks = root_obj
        .entry("hooks")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("hooks must be an object"))?;

    for k in KEYS {
        let arr_val = hooks.entry((*k).to_string()).or_insert_with(|| json!([]));
        let arr = arr_val
            .as_array_mut()
            .ok_or_else(|| anyhow::anyhow!("{k} hook list must be an array"))?;
        arr.retain(|e| !is_managed_cursor_entry(e));
        arr.push(entry.clone());
    }

    save_json_formatted(path, &root, dry_run)?;
    Ok(if dry_run {
        format!(
            "dry-run: would write managed before* hooks (audit={audit}, failClosed={fail_closed})"
        )
    } else {
        format!("wrote managed before* hooks (audit={audit}, failClosed={fail_closed})")
    })
}

fn codex_managed_block(audit_pre: bool, audit_post: bool) -> String {
    let pre = hook_scan_cli_command(AiTool::Codex, audit_pre, false);
    let post = hook_scan_cli_command(AiTool::Codex, audit_post, true);
    format!(
        "# shk-managed-start
[[hooks.PreToolUse]]
matcher = \".*\"
timeout = {HOOK_CLI_TIMEOUT_SEC}

[[hooks.PreToolUse.hooks]]
type = \"command\"
command = \"{pre}\"
statusMessage = \"shk: scanning for secrets...\"

[[hooks.PermissionRequest]]
matcher = \".*\"
timeout = {HOOK_CLI_TIMEOUT_SEC}

[[hooks.PermissionRequest.hooks]]
type = \"command\"
command = \"{pre}\"
statusMessage = \"shk: checking approval request...\"

[[hooks.PostToolUse]]
matcher = \".*\"
timeout = {HOOK_CLI_TIMEOUT_SEC}

[[hooks.PostToolUse.hooks]]
type = \"command\"
command = \"{post}\"
statusMessage = \"shk: scanning tool output...\"
# shk-managed-end
"
    )
}

fn codex_managed_block_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?s)# shk-managed-start.*?# shk-managed-end\s*")
            .expect("valid codex managed-block regex")
    })
}

fn ensure_codex_features_prefix(content: &str) -> String {
    let trimmed = content.trim_start();
    if trimmed.contains("codex_hooks") {
        content.to_string()
    } else {
        format!("[features]\ncodex_hooks = true\n\n{}", content.trim_start())
    }
}

fn apply_codex(path: &Path, audit: bool, dry_run: bool) -> Result<String> {
    let block = codex_managed_block(audit, audit);
    let re = codex_managed_block_regex();

    let prev = if path.is_file() {
        Some(fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?)
    } else {
        None
    };

    let new_body = if let Some(mut s) = prev {
        let replaced = if re.is_match(&s) {
            re.replace(&s, format!("{block}\n")).to_string()
        } else {
            if !s.trim().is_empty() && !s.ends_with('\n') {
                s.push('\n');
            }
            if !s.ends_with('\n') {
                s.push('\n');
            }
            format!("{s}{block}\n")
        };
        ensure_codex_features_prefix(&replaced)
    } else {
        ensure_codex_features_prefix(&(block.clone() + "\n"))
    };

    if dry_run {
        return Ok(format!(
            "dry-run: would write codex_hooks + managed block len={}",
            new_body.lines().count()
        ));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::write(path, &new_body).with_context(|| format!("write {}", path.display()))?;
    Ok("wrote .codex/config.toml hooks block".into())
}
