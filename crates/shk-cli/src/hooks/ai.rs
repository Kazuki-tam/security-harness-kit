use crate::args::AiTool;
use anyhow::{Context, Result};
use regex::Regex;
use serde_json::{Value, json};
use shk_integrations::{
    CONFIG_REL_PATH, HOOKS_FEATURE_KEY, LEGACY_HOOKS_FEATURE_KEY, RECOMMENDED_APPROVAL_POLICY,
    RECOMMENDED_SANDBOX_MODE, RISKY_APPROVAL_POLICY, RISKY_SANDBOX_MODE, USER_PROMPT_HOOK_FAIL_ON,
    normalize_claude_deny_entry,
};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Timeout (seconds) embedded in Cursor / Codex hook command payloads (CLI JSON / TOML).
const HOOK_CLI_TIMEOUT_SEC: u64 = 30;
const CODEX_GIT_ROOT_ARG: &str = r#""$(git rev-parse --show-toplevel)""#;

#[derive(Clone, Copy, Debug)]
pub struct InstallAiOptions {
    pub audit: bool,
    pub log_blocked: bool,
    pub dry_run: bool,
    pub global: bool,
    pub fail_closed: bool,
    pub apply_deny: bool,
    pub apply_sandbox: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct ConfigureAiOptions {
    pub audit: bool,
    pub log_blocked: bool,
    pub dry_run: bool,
    pub global: bool,
    pub fail_closed: bool,
    pub scan_hooks_claude_code: bool,
    pub scan_hooks_cursor: bool,
    pub scan_hooks_codex: bool,
    pub scan_hooks_copilot: bool,
    pub scan_hooks_antigravity: bool,
    pub scan_hooks_windsurf: bool,
    pub claude_deny: bool,
    pub claude_sandbox: bool,
    pub codex_sandbox: bool,
}

fn scan_hooks_enabled_for(opts: &ConfigureAiOptions, tool: AiTool) -> bool {
    match tool {
        AiTool::ClaudeCode => opts.scan_hooks_claude_code,
        AiTool::Cursor => opts.scan_hooks_cursor,
        AiTool::Codex => opts.scan_hooks_codex,
        AiTool::Copilot => opts.scan_hooks_copilot,
        AiTool::Antigravity => opts.scan_hooks_antigravity,
        AiTool::Windsurf => opts.scan_hooks_windsurf,
    }
}

fn home_or_error() -> Result<PathBuf> {
    dirs::home_dir().ok_or_else(|| anyhow::anyhow!("unable to resolve user home directory"))
}

fn ai_config_relative_path(tool: AiTool) -> &'static str {
    match tool {
        AiTool::ClaudeCode => ".claude/settings.json",
        AiTool::Cursor => ".cursor/hooks.json",
        AiTool::Codex => CONFIG_REL_PATH,
        AiTool::Copilot => ".github/hooks/shk-security.json",
        AiTool::Antigravity => ".agents/hooks.json",
        AiTool::Windsurf => ".windsurf/hooks.json",
    }
}

/// Home-relative config path for `--global` installs. Antigravity's
/// user-level customization directory is `~/.gemini/config/`, not a
/// dot-directory mirroring the project layout. Windsurf reads
/// user-level hooks from `~/.codeium/windsurf/hooks.json`.
fn ai_config_global_relative_path(tool: AiTool) -> &'static str {
    match tool {
        AiTool::Antigravity => ".gemini/config/hooks.json",
        AiTool::Copilot => ".copilot/hooks/shk-security.json",
        AiTool::Windsurf => ".codeium/windsurf/hooks.json",
        _ => ai_config_relative_path(tool),
    }
}

pub(crate) fn resolve_ai_config_path(tool: AiTool, cwd: &Path, global: bool) -> Result<PathBuf> {
    Ok(if global {
        home_or_error()?.join(ai_config_global_relative_path(tool))
    } else {
        cwd.join(ai_config_relative_path(tool))
    })
}

fn hook_scan_cli_command(tool: AiTool, audit: bool, log_blocked: bool, post: bool) -> String {
    hook_scan_cli_command_with_root_arg(tool, audit, log_blocked, post, None, None)
}

fn user_prompt_hook_scan_command(
    tool: AiTool,
    audit: bool,
    log_blocked: bool,
    root_arg: Option<&str>,
) -> String {
    hook_scan_cli_command_with_root_arg(
        tool,
        audit,
        log_blocked,
        false,
        Some(USER_PROMPT_HOOK_FAIL_ON),
        root_arg,
    )
}

fn hook_scan_cli_command_with_root_arg(
    tool: AiTool,
    audit: bool,
    log_blocked: bool,
    post: bool,
    fail_on: Option<&str>,
    root_arg: Option<&str>,
) -> String {
    let suf_audit = if audit { " --audit" } else { "" };
    let suf_log_blocked = if log_blocked && !audit {
        " --log-blocked"
    } else {
        ""
    };
    let suf_post = if post { " --post" } else { "" };
    let suf_fail_on = fail_on
        .map(|severity| format!(" --fail-on {severity}"))
        .unwrap_or_default();
    let path_arg = root_arg.map(|arg| format!(" {arg}")).unwrap_or_default();
    format!(
        "shk scan{} --hook-mode {}{}{}{}{}",
        path_arg,
        tool.kebab_str(),
        suf_audit,
        suf_log_blocked,
        suf_post,
        suf_fail_on,
    )
}

pub fn install_ai(cwd: &Path, maybe_tool: Option<AiTool>, opts: InstallAiOptions) -> Result<()> {
    let summaries = install_ai_with_summaries(cwd, maybe_tool, opts)?;
    for summary in summaries {
        println!("{summary}");
    }
    Ok(())
}

pub fn install_ai_with_summaries(
    cwd: &Path,
    maybe_tool: Option<AiTool>,
    opts: InstallAiOptions,
) -> Result<Vec<String>> {
    let tools = if let Some(t) = maybe_tool {
        vec![t]
    } else {
        vec![
            AiTool::ClaudeCode,
            AiTool::Codex,
            AiTool::Cursor,
            AiTool::Copilot,
            AiTool::Antigravity,
            AiTool::Windsurf,
        ]
    };

    println!(
        "shk hooks install-ai (global={}, audit={}, log-blocked={}, dry-run={}, apply-sandbox={})",
        opts.global, opts.audit, opts.log_blocked, opts.dry_run, opts.apply_sandbox
    );
    let cwd = fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
    let mut summaries = Vec::new();

    for t in tools {
        let path = resolve_ai_config_path(t, &cwd, opts.global)?;
        let summary = apply_tool(&path, t, opts, !opts.global)?;
        summaries.push(format!("{}: {}", path.display(), summary.trim()));
    }
    Ok(summaries)
}

pub fn configure_ai_with_summaries(cwd: &Path, opts: ConfigureAiOptions) -> Result<Vec<String>> {
    let cwd = fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
    let mut summaries = Vec::new();
    let install_opts = InstallAiOptions {
        audit: opts.audit,
        log_blocked: opts.log_blocked,
        dry_run: opts.dry_run,
        global: opts.global,
        fail_closed: opts.fail_closed,
        apply_deny: false,
        apply_sandbox: false,
    };

    for tool in [
        AiTool::ClaudeCode,
        AiTool::Codex,
        AiTool::Cursor,
        AiTool::Copilot,
        AiTool::Antigravity,
        AiTool::Windsurf,
    ] {
        let path = resolve_ai_config_path(tool, &cwd, opts.global)?;
        if scan_hooks_enabled_for(&opts, tool) {
            let summary = apply_tool(&path, tool, install_opts, !opts.global)?;
            summaries.push(format!("{}: {}", path.display(), summary.trim()));
        } else if path.is_file() {
            summaries.push(format!(
                "{}: {}",
                path.display(),
                remove_scan_hooks_for_tool(&path, tool, opts.dry_run)?.trim()
            ));
        }
    }

    let claude_path = resolve_ai_config_path(AiTool::ClaudeCode, &cwd, opts.global)?;
    if opts.claude_deny || opts.claude_sandbox || claude_path.is_file() {
        let claude_summary = configure_claude_safety(
            &claude_path,
            opts.dry_run,
            opts.claude_deny,
            opts.claude_sandbox,
            !opts.global,
        )?;
        summaries.push(format!(
            "{}: {}",
            claude_path.display(),
            claude_summary.trim()
        ));
    }

    let codex_path = resolve_ai_config_path(AiTool::Codex, &cwd, opts.global)?;
    if opts.codex_sandbox || codex_path.is_file() {
        let codex_summary = configure_codex_sandbox(&codex_path, opts.dry_run, opts.codex_sandbox)?;
        summaries.push(format!(
            "{}: {}",
            codex_path.display(),
            codex_summary.trim()
        ));
    }

    Ok(summaries)
}

fn apply_tool(
    path: &Path,
    tool: AiTool,
    opts: InstallAiOptions,
    restrict_sandbox_reads_to_project: bool,
) -> Result<String> {
    match tool {
        AiTool::ClaudeCode => apply_claude(
            path,
            opts.audit,
            opts.log_blocked,
            opts.dry_run,
            opts.apply_deny,
            opts.apply_sandbox,
            restrict_sandbox_reads_to_project,
        ),
        AiTool::Cursor => apply_cursor(
            path,
            opts.audit,
            opts.log_blocked,
            opts.dry_run,
            opts.fail_closed || opts.apply_sandbox,
        ),
        AiTool::Codex => apply_codex(
            path,
            opts.audit,
            opts.log_blocked,
            opts.dry_run,
            opts.apply_sandbox,
            !opts.global,
        ),
        AiTool::Copilot => apply_copilot(path, opts.audit, opts.log_blocked, opts.dry_run),
        AiTool::Antigravity => apply_antigravity(
            path,
            opts.audit,
            opts.log_blocked,
            opts.dry_run,
            opts.apply_deny,
        ),
        AiTool::Windsurf => apply_windsurf(path, opts.audit, opts.log_blocked, opts.dry_run),
    }
}

fn remove_scan_hooks_for_tool(path: &Path, tool: AiTool, dry_run: bool) -> Result<String> {
    match tool {
        AiTool::ClaudeCode => remove_claude_scan_hooks(path, dry_run),
        AiTool::Cursor => remove_cursor_scan_hooks(path, dry_run),
        AiTool::Codex => remove_codex_scan_hooks(path, dry_run),
        AiTool::Copilot => remove_copilot_scan_hooks(path, dry_run),
        AiTool::Antigravity => remove_antigravity_scan_hooks(path, dry_run),
        AiTool::Windsurf => remove_windsurf_scan_hooks(path, dry_run),
    }
}

fn save_json_formatted(path: &Path, v: &Value, dry_run: bool) -> Result<()> {
    let text = serde_json::to_string_pretty(v)? + "\n";
    if dry_run {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    crate::fs_atomic::write_atomic(path, text.as_bytes())?;
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

fn remove_managed_claude(root: &mut Value, key: &str) -> Result<usize> {
    let Some(hooks_obj) = root.get_mut("hooks").and_then(Value::as_object_mut) else {
        return Ok(0);
    };
    let Some(arr) = hooks_obj.get_mut(key).and_then(Value::as_array_mut) else {
        return Ok(0);
    };
    let before = arr.len();
    arr.retain(|b| !is_managed_claude_block(b));
    Ok(before - arr.len())
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

    let existing_exact: HashSet<String> = deny_arr
        .iter()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect();
    let existing_normalized: HashSet<String> = existing_exact
        .iter()
        .map(|entry| normalize_claude_deny_entry(entry))
        .collect();

    let mut added = 0;
    let mut installed_exact = existing_exact;
    for entry in shk_integrations::claude_recommended_deny_entries() {
        if !installed_exact.contains(entry)
            && !existing_normalized.contains(&normalize_claude_deny_entry(entry))
        {
            deny_arr.push(json!(entry));
            installed_exact.insert(entry.to_string());
            added += 1;
        }
    }
    Ok(added)
}

fn remove_claude_permissions_deny(root: &mut Value) -> Result<usize> {
    let Some(deny_arr) = root
        .pointer_mut("/permissions/deny")
        .and_then(Value::as_array_mut)
    else {
        return Ok(0);
    };
    let recommended: HashSet<&'static str> = shk_integrations::claude_recommended_deny_entries()
        .iter()
        .copied()
        .collect();
    let before = deny_arr.len();
    deny_arr.retain(|entry| {
        entry
            .as_str()
            .map(|entry| !recommended.contains(entry))
            .unwrap_or(true)
    });
    Ok(before - deny_arr.len())
}

fn merge_claude_sandbox(root: &mut Value, restrict_reads_to_project: bool) -> Result<()> {
    let obj = root
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("Claude settings root must be a JSON object"))?;
    let sandbox = obj.entry("sandbox").or_insert_with(|| json!({}));
    let sandbox_obj = sandbox
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("sandbox must be an object"))?;
    sandbox_obj.insert("enabled".into(), json!(true));
    sandbox_obj.insert("failIfUnavailable".into(), json!(true));
    sandbox_obj.insert("autoAllowBashIfSandboxed".into(), json!(true));
    sandbox_obj.insert("allowUnsandboxedCommands".into(), json!(false));

    if restrict_reads_to_project {
        let filesystem = sandbox_obj.entry("filesystem").or_insert_with(|| json!({}));
        let filesystem_obj = filesystem
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("sandbox.filesystem must be an object"))?;
        merge_json_string_array(filesystem_obj, "denyRead", &["~/"]);
        merge_json_string_array(filesystem_obj, "allowRead", &["."]);
    }
    Ok(())
}

fn remove_claude_sandbox(root: &mut Value) -> usize {
    let Some(obj) = root.as_object_mut() else {
        return 0;
    };
    let Some(sandbox) = obj.get_mut("sandbox").and_then(Value::as_object_mut) else {
        return 0;
    };
    let mut removed = 0;
    for key in [
        "enabled",
        "failIfUnavailable",
        "autoAllowBashIfSandboxed",
        "allowUnsandboxedCommands",
    ] {
        if sandbox.remove(key).is_some() {
            removed += 1;
        }
    }
    if let Some(filesystem) = sandbox.get_mut("filesystem").and_then(Value::as_object_mut) {
        removed += remove_json_string_array_item(filesystem, "denyRead", "~/");
        removed += remove_json_string_array_item(filesystem, "allowRead", ".");
        if filesystem.is_empty() {
            sandbox.remove("filesystem");
        }
    }
    if sandbox.is_empty() {
        obj.remove("sandbox");
    }
    removed
}

fn merge_json_string_array(
    obj: &mut serde_json::Map<String, Value>,
    key: &str,
    recommended: &[&str],
) {
    let arr = obj.entry(key).or_insert_with(|| json!([]));
    if !arr.is_array() {
        *arr = json!([]);
    }
    let arr = arr.as_array_mut().expect("array initialized above");
    for item in recommended {
        if !arr.iter().any(|existing| existing.as_str() == Some(*item)) {
            arr.push(json!(item));
        }
    }
}

#[allow(dead_code)]
fn remove_json_string_array_item(
    obj: &mut serde_json::Map<String, Value>,
    key: &str,
    item: &str,
) -> usize {
    let Some(arr) = obj.get_mut(key).and_then(Value::as_array_mut) else {
        return 0;
    };
    let before = arr.len();
    arr.retain(|existing| existing.as_str() != Some(item));
    let removed = before - arr.len();
    if arr.is_empty() {
        obj.remove(key);
    }
    removed
}

fn apply_claude(
    path: &Path,
    audit: bool,
    log_blocked: bool,
    dry_run: bool,
    apply_deny: bool,
    apply_sandbox: bool,
    restrict_sandbox_reads_to_project: bool,
) -> Result<String> {
    let pre = hook_scan_cli_command(AiTool::ClaudeCode, audit, log_blocked, false);
    let post = hook_scan_cli_command(AiTool::ClaudeCode, audit, log_blocked, true);
    let user_prompt = user_prompt_hook_scan_command(AiTool::ClaudeCode, audit, log_blocked, None);

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
    if apply_sandbox {
        merge_claude_sandbox(&mut root, restrict_sandbox_reads_to_project)?;
    }

    save_json_formatted(path, &root, dry_run)?;
    Ok(if dry_run {
        format!(
            "dry-run: would write managed UserPromptSubmit/PreToolUse/PostToolUse blocks (audit={audit}, logBlocked={log_blocked}, applyDeny={apply_deny}, applySandbox={apply_sandbox}, denyAdded={deny_added})"
        )
    } else {
        format!(
            "wrote managed blocks (audit={audit}, logBlocked={log_blocked}, applyDeny={apply_deny}, applySandbox={apply_sandbox}, denyAdded={deny_added})"
        )
    })
}

#[allow(dead_code)]
fn remove_claude_scan_hooks(path: &Path, dry_run: bool) -> Result<String> {
    if !path.is_file() {
        return Ok("no Claude settings file".to_string());
    }
    let mut root = load_json(path)?;
    let removed = remove_managed_claude(&mut root, "UserPromptSubmit")?
        + remove_managed_claude(&mut root, "PreToolUse")?
        + remove_managed_claude(&mut root, "PostToolUse")?;
    save_json_formatted(path, &root, dry_run)?;
    Ok(if dry_run {
        format!("dry-run: would remove {removed} managed Claude hook block(s)")
    } else {
        format!("removed {removed} managed Claude hook block(s)")
    })
}

fn configure_claude_safety(
    path: &Path,
    dry_run: bool,
    enable_deny: bool,
    enable_sandbox: bool,
    restrict_sandbox_reads_to_project: bool,
) -> Result<String> {
    if !enable_deny && !enable_sandbox && !path.is_file() {
        return Ok("no Claude settings file".to_string());
    }
    let mut root = if path.is_file() {
        load_json(path)?
    } else {
        json!({})
    };

    let deny_count = if enable_deny {
        merge_claude_permissions_deny(&mut root)?
    } else {
        remove_claude_permissions_deny(&mut root)?
    };
    let sandbox_changed = if enable_sandbox {
        merge_claude_sandbox(&mut root, restrict_sandbox_reads_to_project)?;
        1
    } else {
        remove_claude_sandbox(&mut root)
    };

    if path.is_file() || enable_deny || enable_sandbox {
        save_json_formatted(path, &root, dry_run)?;
    }
    Ok(if dry_run {
        format!(
            "dry-run: would sync Claude safety (denyEnabled={enable_deny}, sandboxEnabled={enable_sandbox}, denyAdded={deny_count}, sandboxChanged={sandbox_changed})"
        )
    } else {
        format!(
            "synced Claude safety (denyEnabled={enable_deny}, sandboxEnabled={enable_sandbox}, denyAdded={deny_count}, sandboxChanged={sandbox_changed})"
        )
    })
}

fn is_managed_cursor_entry(entry: &Value) -> bool {
    entry.get("_shk_managed") == Some(&json!(true))
}

fn apply_cursor(
    path: &Path,
    audit: bool,
    log_blocked: bool,
    dry_run: bool,
    fail_closed: bool,
) -> Result<String> {
    const PRE_KEYS: &[&str] = &[
        "beforeReadFile",
        "beforeShellExecution",
        "beforeMCPExecution",
    ];
    // Observational events: Cursor ignores hook responses here, matching shk's
    // non-blocking `--post` semantics (always exit 0).
    const POST_KEYS: &[&str] = &["afterShellExecution", "afterMCPExecution"];

    let cmd = hook_scan_cli_command(AiTool::Cursor, audit, log_blocked, false);
    let post_cmd = hook_scan_cli_command(AiTool::Cursor, audit, log_blocked, true);
    let prompt_cmd = user_prompt_hook_scan_command(AiTool::Cursor, audit, log_blocked, None);
    let entry = json!({
        "command": cmd,
        "timeout": HOOK_CLI_TIMEOUT_SEC,
        "failClosed": fail_closed,
        "_shk_managed": true
    });
    let post_entry = json!({
        "command": post_cmd,
        "timeout": HOOK_CLI_TIMEOUT_SEC,
        "_shk_managed": true
    });
    let prompt_entry = json!({
        "command": prompt_cmd,
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

    let managed: &[(&[&str], &Value)] = &[
        (PRE_KEYS, &entry),
        (POST_KEYS, &post_entry),
        (&["beforeSubmitPrompt"], &prompt_entry),
    ];
    for (keys, managed_entry) in managed {
        for k in *keys {
            let arr_val = hooks.entry((*k).to_string()).or_insert_with(|| json!([]));
            let arr = arr_val
                .as_array_mut()
                .ok_or_else(|| anyhow::anyhow!("{k} hook list must be an array"))?;
            arr.retain(|e| !is_managed_cursor_entry(e));
            arr.push((*managed_entry).clone());
        }
    }

    save_json_formatted(path, &root, dry_run)?;
    Ok(if dry_run {
        format!(
            "dry-run: would write managed before*/after* hooks (audit={audit}, logBlocked={log_blocked}, failClosed={fail_closed})"
        )
    } else {
        format!(
            "wrote managed before*/after* hooks (audit={audit}, logBlocked={log_blocked}, failClosed={fail_closed})"
        )
    })
}

#[allow(dead_code)]
fn remove_cursor_scan_hooks(path: &Path, dry_run: bool) -> Result<String> {
    const KEYS: &[&str] = &[
        "beforeReadFile",
        "beforeShellExecution",
        "beforeMCPExecution",
        "afterShellExecution",
        "afterMCPExecution",
        "beforeSubmitPrompt",
    ];
    if !path.is_file() {
        return Ok("no Cursor hooks file".to_string());
    }
    let mut root = load_json(path)?;
    let hooks = root
        .get_mut("hooks")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| anyhow::anyhow!("hooks must be an object"))?;
    let mut removed = 0;
    for key in KEYS {
        if let Some(arr) = hooks.get_mut(*key).and_then(Value::as_array_mut) {
            let before = arr.len();
            arr.retain(|e| !is_managed_cursor_entry(e));
            removed += before - arr.len();
        }
    }
    save_json_formatted(path, &root, dry_run)?;
    Ok(if dry_run {
        format!("dry-run: would remove {removed} managed Cursor hook entry(s)")
    } else {
        format!("removed {removed} managed Cursor hook entry(s)")
    })
}

fn is_managed_copilot_entry(entry: &Value) -> bool {
    entry
        .get("_shk_managed")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || ["command", "bash", "powershell"].iter().any(|key| {
            entry
                .get(*key)
                .and_then(Value::as_str)
                .is_some_and(|cmd| cmd.contains("shk scan") && cmd.contains("--hook-mode copilot"))
        })
}

fn copilot_command_entry(command: String) -> Value {
    json!({
        "type": "command",
        "command": command,
        "cwd": ".",
        "timeoutSec": HOOK_CLI_TIMEOUT_SEC
    })
}

fn apply_copilot(path: &Path, audit: bool, log_blocked: bool, dry_run: bool) -> Result<String> {
    const PRE_KEYS: &[&str] = &["preToolUse", "PermissionRequest"];
    const POST_KEYS: &[&str] = &["postToolUse", "postToolUseFailure"];

    let pre = copilot_command_entry(hook_scan_cli_command(
        AiTool::Copilot,
        audit,
        log_blocked,
        false,
    ));
    let post = copilot_command_entry(hook_scan_cli_command(
        AiTool::Copilot,
        audit,
        log_blocked,
        true,
    ));
    let prompt = copilot_command_entry(user_prompt_hook_scan_command(
        AiTool::Copilot,
        audit,
        log_blocked,
        None,
    ));

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
        .ok_or_else(|| anyhow::anyhow!("Copilot hooks root must be a JSON object"))?;
    root_obj.entry("version").or_insert(json!(1));
    let hooks = root_obj
        .entry("hooks")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("hooks must be an object"))?;

    for (keys, entry) in [
        (PRE_KEYS, &pre),
        (POST_KEYS, &post),
        (&["UserPromptSubmit"][..], &prompt),
    ] {
        for key in keys {
            let arr_val = hooks.entry((*key).to_string()).or_insert_with(|| json!([]));
            let arr = arr_val
                .as_array_mut()
                .ok_or_else(|| anyhow::anyhow!("{key} hook list must be an array"))?;
            arr.retain(|existing| !is_managed_copilot_entry(existing));
            arr.push(entry.clone());
        }
    }

    save_json_formatted(path, &root, dry_run)?;
    Ok(if dry_run {
        format!(
            "dry-run: would write managed preToolUse/permissionRequest/postToolUse/userPromptSubmitted hooks (audit={audit}, logBlocked={log_blocked})"
        )
    } else {
        format!(
            "wrote managed preToolUse/permissionRequest/postToolUse/userPromptSubmitted hooks (audit={audit}, logBlocked={log_blocked})"
        )
    })
}

#[allow(dead_code)]
fn remove_copilot_scan_hooks(path: &Path, dry_run: bool) -> Result<String> {
    const KEYS: &[&str] = &[
        "preToolUse",
        "permissionRequest",
        "PermissionRequest",
        "postToolUse",
        "postToolUseFailure",
        "userPromptSubmitted",
        "UserPromptSubmit",
    ];
    if !path.is_file() {
        return Ok("no Copilot hooks file".to_string());
    }
    let mut root = load_json(path)?;
    let hooks = root
        .get_mut("hooks")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| anyhow::anyhow!("hooks must be an object"))?;
    let mut removed = 0;
    for key in KEYS {
        if let Some(arr) = hooks.get_mut(*key).and_then(Value::as_array_mut) {
            let before = arr.len();
            arr.retain(|entry| !is_managed_copilot_entry(entry));
            removed += before - arr.len();
        }
    }
    save_json_formatted(path, &root, dry_run)?;
    Ok(if dry_run {
        format!("dry-run: would remove {removed} managed Copilot hook entry(s)")
    } else {
        format!("removed {removed} managed Copilot hook entry(s)")
    })
}

/// Top-level key shk owns inside Antigravity's `hooks.json`
/// (the file maps hook names to event configurations).
const ANTIGRAVITY_HOOK_NAME: &str = "shk-security";
/// Tools whose proposed calls carry scannable content or run commands.
const ANTIGRAVITY_PRE_MATCHER: &str = "run_command|view_file|write_to_file|replace_file_content|multi_replace_file_content|read_url_content|search_web";

fn apply_antigravity(
    path: &Path,
    audit: bool,
    log_blocked: bool,
    dry_run: bool,
    apply_deny: bool,
) -> Result<String> {
    let pre = hook_scan_cli_command(AiTool::Antigravity, audit, log_blocked, false);

    let mut root = if path.is_file() {
        load_json(path)?
    } else {
        json!({})
    };
    let root_obj = root
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("Antigravity hooks.json root must be a JSON object"))?;

    // Antigravity PostToolUse payloads carry no tool output (only stepIdx/error),
    // so only a blocking PreToolUse hook is installed.
    root_obj.insert(
        ANTIGRAVITY_HOOK_NAME.to_string(),
        json!({
            "PreToolUse": [{
                "_shk_managed": true,
                "matcher": ANTIGRAVITY_PRE_MATCHER,
                "hooks": [{
                    "type": "command",
                    "command": pre,
                    "timeout": HOOK_CLI_TIMEOUT_SEC
                }]
            }]
        }),
    );

    save_json_formatted(path, &root, dry_run)?;

    if apply_deny {
        // Antigravity's Allow/Ask/Deny permission lists live in its settings UI
        // and internal per-project config; there is no documented project file
        // shk could merge into, so print copy-paste guidance instead.
        print_antigravity_deny_guidance();
    }

    Ok(if dry_run {
        format!(
            "dry-run: would write managed `{ANTIGRAVITY_HOOK_NAME}` PreToolUse hook (audit={audit}, logBlocked={log_blocked})"
        )
    } else {
        format!(
            "wrote managed `{ANTIGRAVITY_HOOK_NAME}` PreToolUse hook (audit={audit}, logBlocked={log_blocked})"
        )
    })
}

fn print_antigravity_deny_guidance() {
    println!(
        "Antigravity permissions cannot be written programmatically (managed in the Antigravity settings UI)."
    );
    println!(
        "Recommended Deny list entries - add them via Antigravity settings > Permissions (Deny > Ask > Allow precedence):"
    );
    for entry in shk_integrations::antigravity_recommended_deny_entries() {
        println!("  {entry}");
    }
}

#[allow(dead_code)]
fn remove_antigravity_scan_hooks(path: &Path, dry_run: bool) -> Result<String> {
    if !path.is_file() {
        return Ok("no Antigravity hooks file".to_string());
    }
    let mut root = load_json(path)?;
    let removed = root
        .as_object_mut()
        .map(|obj| usize::from(obj.remove(ANTIGRAVITY_HOOK_NAME).is_some()))
        .unwrap_or(0);
    save_json_formatted(path, &root, dry_run)?;
    Ok(if dry_run {
        format!("dry-run: would remove {removed} managed Antigravity hook entry(s)")
    } else {
        format!("removed {removed} managed Antigravity hook entry(s)")
    })
}

/// Cascade (Windsurf) hook events shk owns inside `hooks.json`.
/// Blocking pre-hooks scan inbound content (reads, writes, commands, MCP args);
/// observational post-hooks (always exit 0) scan tool output. Cascade runs each
/// command via `bash -c` with the workspace root as the working directory, so
/// `shk scan` (no path) is correct.
const WINDSURF_PRE_KEYS: &[&str] = &[
    "pre_read_code",
    "pre_write_code",
    "pre_run_command",
    "pre_mcp_tool_use",
];
const WINDSURF_POST_KEYS: &[&str] = &["post_run_command", "post_mcp_tool_use"];
const WINDSURF_PROMPT_KEY: &str = "pre_user_prompt";

/// Cascade ignores extra config keys, so managed entries are identified by the
/// `shk scan ... --hook-mode windsurf` command string (no `_shk_managed` marker
/// is injected, keeping the file schema-clean).
fn is_managed_windsurf_entry(entry: &Value) -> bool {
    ["command", "powershell"].iter().any(|key| {
        entry
            .get(*key)
            .and_then(Value::as_str)
            .is_some_and(|cmd| cmd.contains("shk scan") && cmd.contains("--hook-mode windsurf"))
    })
}

fn windsurf_command_entry(command: String) -> Value {
    json!({
        "command": command,
        "show_output": true
    })
}

fn apply_windsurf(path: &Path, audit: bool, log_blocked: bool, dry_run: bool) -> Result<String> {
    let pre = windsurf_command_entry(hook_scan_cli_command(
        AiTool::Windsurf,
        audit,
        log_blocked,
        false,
    ));
    let post = windsurf_command_entry(hook_scan_cli_command(
        AiTool::Windsurf,
        audit,
        log_blocked,
        true,
    ));
    let prompt = windsurf_command_entry(user_prompt_hook_scan_command(
        AiTool::Windsurf,
        audit,
        log_blocked,
        None,
    ));

    let mut root = if path.is_file() {
        load_json(path)?
    } else {
        json!({ "hooks": {} })
    };

    let root_obj = root
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("Windsurf hooks.json root must be a JSON object"))?;
    let hooks = root_obj
        .entry("hooks")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("hooks must be an object"))?;

    for (keys, entry) in [
        (WINDSURF_PRE_KEYS, &pre),
        (WINDSURF_POST_KEYS, &post),
        (&[WINDSURF_PROMPT_KEY][..], &prompt),
    ] {
        for key in keys {
            let arr_val = hooks.entry((*key).to_string()).or_insert_with(|| json!([]));
            let arr = arr_val
                .as_array_mut()
                .ok_or_else(|| anyhow::anyhow!("{key} hook list must be an array"))?;
            arr.retain(|existing| !is_managed_windsurf_entry(existing));
            arr.push(entry.clone());
        }
    }

    save_json_formatted(path, &root, dry_run)?;
    Ok(if dry_run {
        format!(
            "dry-run: would write managed pre_*/post_* Cascade hooks (audit={audit}, logBlocked={log_blocked})"
        )
    } else {
        format!(
            "wrote managed pre_*/post_* Cascade hooks (audit={audit}, logBlocked={log_blocked})"
        )
    })
}

#[allow(dead_code)]
fn remove_windsurf_scan_hooks(path: &Path, dry_run: bool) -> Result<String> {
    if !path.is_file() {
        return Ok("no Windsurf hooks file".to_string());
    }
    let mut root = load_json(path)?;
    let mut removed = 0;
    if let Some(hooks) = root.get_mut("hooks").and_then(Value::as_object_mut) {
        for arr in hooks.values_mut().filter_map(Value::as_array_mut) {
            let before = arr.len();
            arr.retain(|entry| !is_managed_windsurf_entry(entry));
            removed += before - arr.len();
        }
    }
    save_json_formatted(path, &root, dry_run)?;
    Ok(if dry_run {
        format!("dry-run: would remove {removed} managed Windsurf hook entry(s)")
    } else {
        format!("removed {removed} managed Windsurf hook entry(s)")
    })
}

fn codex_root_arg(use_git_root_path: bool) -> Option<&'static str> {
    use_git_root_path.then_some(CODEX_GIT_ROOT_ARG)
}

fn codex_hook_command(
    audit: bool,
    log_blocked: bool,
    post: bool,
    use_git_root_path: bool,
    fail_on: Option<&str>,
) -> String {
    hook_scan_cli_command_with_root_arg(
        AiTool::Codex,
        audit,
        log_blocked,
        post,
        fail_on,
        codex_root_arg(use_git_root_path),
    )
}

fn codex_inline_hook(
    event: &str,
    command: &str,
    status_message: &str,
    include_matcher: bool,
) -> String {
    let matcher = if include_matcher {
        "matcher = \".*\"\n"
    } else {
        ""
    };
    format!(
        "[[hooks.{event}]]
{matcher}\
timeout = {HOOK_CLI_TIMEOUT_SEC}

[[hooks.{event}.hooks]]
type = \"command\"
command = '{command}'
statusMessage = \"{status_message}\"
"
    )
}

fn codex_managed_block(
    audit_pre: bool,
    log_blocked: bool,
    audit_post: bool,
    use_git_root_path: bool,
) -> String {
    let root_arg = codex_root_arg(use_git_root_path);
    let pre = codex_hook_command(audit_pre, log_blocked, false, use_git_root_path, None);
    let user_prompt =
        user_prompt_hook_scan_command(AiTool::Codex, audit_pre, log_blocked, root_arg);
    let post = codex_hook_command(audit_post, log_blocked, true, use_git_root_path, None);
    let hooks = [
        (
            "PreToolUse",
            pre.as_str(),
            "shk: scanning for secrets...",
            true,
        ),
        (
            "PermissionRequest",
            pre.as_str(),
            "shk: checking approval request...",
            true,
        ),
        (
            "UserPromptSubmit",
            user_prompt.as_str(),
            "shk: scanning submitted prompt...",
            false,
        ),
        (
            "PostToolUse",
            post.as_str(),
            "shk: scanning tool output...",
            true,
        ),
    ];
    let body = hooks
        .into_iter()
        .map(|(event, command, status_message, include_matcher)| {
            codex_inline_hook(event, command, status_message, include_matcher)
        })
        .collect::<String>();
    format!("# shk-managed-start\n{body}# shk-managed-end\n")
}

fn codex_managed_block_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?s)# shk-managed-start.*?# shk-managed-end\s*")
            .expect("valid codex managed-block regex")
    })
}

fn ensure_codex_features_prefix(content: &str) -> String {
    let mut lines: Vec<String> = content.lines().map(ToOwned::to_owned).collect();

    if let Some(features_idx) = lines.iter().position(|line| line.trim() == "[features]") {
        let section_end = lines
            .iter()
            .enumerate()
            .skip(features_idx + 1)
            .find(|(_, line)| line.trim_start().starts_with('['))
            .map(|(idx, _)| idx)
            .unwrap_or(lines.len());

        let mut hooks_idx = None;
        let mut legacy_idxs = Vec::new();
        for (idx, line) in lines
            .iter()
            .enumerate()
            .take(section_end)
            .skip(features_idx + 1)
        {
            let Some((key, _)) = line.trim().split_once('=') else {
                continue;
            };
            match key.trim() {
                HOOKS_FEATURE_KEY => hooks_idx = Some(idx),
                LEGACY_HOOKS_FEATURE_KEY => legacy_idxs.push(idx),
                _ => {}
            }
        }

        let canonical_idx = hooks_idx.or_else(|| {
            if legacy_idxs.is_empty() {
                None
            } else {
                Some(legacy_idxs.remove(0))
            }
        });
        if let Some(idx) = canonical_idx {
            lines[idx] = format!("{HOOKS_FEATURE_KEY} = true");
        } else {
            lines.insert(section_end, format!("{HOOKS_FEATURE_KEY} = true"));
        }
        for idx in legacy_idxs.into_iter().rev() {
            lines.remove(idx);
        }
        return finish_text_lines(lines, content.ends_with('\n'));
    }

    let insert_at = lines
        .iter()
        .position(|line| line.trim_start().starts_with('['))
        .unwrap_or(lines.len());
    let block = [
        "[features]".to_string(),
        format!("{HOOKS_FEATURE_KEY} = true"),
    ];
    if insert_at == 0 {
        lines.splice(0..0, block);
        lines.insert(2, String::new());
    } else if insert_at == lines.len() {
        if !lines.is_empty() && !lines.last().is_some_and(|line| line.is_empty()) {
            lines.push(String::new());
        }
        lines.extend(block);
    } else {
        if !lines[insert_at - 1].is_empty() {
            lines.insert(insert_at, String::new());
        }
        lines.splice(insert_at..insert_at, block);
        lines.insert(insert_at + 2, String::new());
    }
    finish_text_lines(lines, true)
}

fn finish_text_lines(lines: Vec<String>, trailing_newline: bool) -> String {
    let mut output = lines.join("\n");
    if trailing_newline && !output.ends_with('\n') {
        output.push('\n');
    }
    output
}

fn apply_codex(
    path: &Path,
    audit: bool,
    log_blocked: bool,
    dry_run: bool,
    apply_sandbox: bool,
    use_git_root_path: bool,
) -> Result<String> {
    let block = codex_managed_block(audit, log_blocked, audit, use_git_root_path);
    let re = codex_managed_block_regex();

    let prev = if path.is_file() {
        Some(fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?)
    } else {
        None
    };

    let mut new_body = if let Some(mut s) = prev {
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
    if apply_sandbox {
        new_body = ensure_codex_sandbox_settings(&new_body);
    }

    if dry_run {
        return Ok(format!(
            "dry-run: would write hooks feature + managed block len={} (applySandbox={apply_sandbox})",
            new_body.lines().count(),
        ));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    crate::fs_atomic::write_atomic(path, new_body.as_bytes())?;
    Ok(format!(
        "wrote .codex/config.toml hooks block (applySandbox={apply_sandbox})"
    ))
}

#[allow(dead_code)]
fn remove_codex_scan_hooks(path: &Path, dry_run: bool) -> Result<String> {
    if !path.is_file() {
        return Ok("no Codex config file".to_string());
    }
    let existing = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let re = codex_managed_block_regex();
    let updated = re.replace(&existing, "").to_string();
    if !dry_run && updated != existing {
        crate::fs_atomic::write_atomic(path, updated.as_bytes())?;
    }
    Ok(if dry_run {
        "dry-run: would remove Codex managed hook block".to_string()
    } else {
        "removed Codex managed hook block".to_string()
    })
}

fn configure_codex_sandbox(path: &Path, dry_run: bool, enabled: bool) -> Result<String> {
    if !path.is_file() && !enabled {
        return Ok("no Codex sandbox settings to remove".to_string());
    }
    let existing = if path.is_file() {
        fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?
    } else {
        String::new()
    };
    let updated = if enabled {
        ensure_codex_sandbox_settings(&existing)
    } else {
        remove_codex_sandbox_settings(&existing)
    };
    if !dry_run && updated != existing {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
        crate::fs_atomic::write_atomic(path, updated.as_bytes())?;
    }
    Ok(if dry_run {
        format!("dry-run: would configure Codex sandbox (enabled={enabled})")
    } else {
        format!("configured Codex sandbox (enabled={enabled})")
    })
}

fn ensure_codex_sandbox_settings(content: &str) -> String {
    let content = ensure_top_level_string_setting(
        content,
        "sandbox_mode",
        RECOMMENDED_SANDBOX_MODE,
        &[RISKY_SANDBOX_MODE],
    );
    ensure_top_level_string_setting(
        &content,
        "approval_policy",
        RECOMMENDED_APPROVAL_POLICY,
        &[RISKY_APPROVAL_POLICY],
    )
}

#[allow(dead_code)]
fn remove_codex_sandbox_settings(content: &str) -> String {
    let content =
        remove_top_level_string_setting(content, "sandbox_mode", &[RECOMMENDED_SANDBOX_MODE]);
    remove_top_level_string_setting(&content, "approval_policy", &[RECOMMENDED_APPROVAL_POLICY])
}

fn ensure_top_level_string_setting(
    content: &str,
    key: &str,
    desired: &str,
    replace_values: &[&str],
) -> String {
    let mut lines: Vec<String> = content.lines().map(ToOwned::to_owned).collect();
    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            break;
        }
        let Some((raw_key, raw_value)) = trimmed.split_once('=') else {
            continue;
        };
        if raw_key.trim() != key {
            continue;
        }
        let current = parse_toml_string_value(raw_value).unwrap_or_else(|| raw_value.trim());
        if current == desired || !replace_values.contains(&current) {
            return content.to_string();
        }
        lines[idx] = format!(r#"{key} = "{desired}""#);
        return lines.join("\n") + if content.ends_with('\n') { "\n" } else { "" };
    }

    format!(r#"{key} = "{desired}""#) + "\n" + content.trim_start()
}

fn remove_top_level_string_setting(content: &str, key: &str, removable_values: &[&str]) -> String {
    let mut lines: Vec<String> = content.lines().map(ToOwned::to_owned).collect();
    for idx in 0..lines.len() {
        let trimmed = lines[idx].trim();
        if trimmed.starts_with('[') {
            break;
        }
        let Some((raw_key, raw_value)) = trimmed.split_once('=') else {
            continue;
        };
        if raw_key.trim() != key {
            continue;
        }
        let current = parse_toml_string_value(raw_value).unwrap_or_else(|| raw_value.trim());
        if removable_values.contains(&current) {
            lines.remove(idx);
        }
        break;
    }
    let mut output = lines.join("\n");
    if !output.is_empty() {
        output.push('\n');
    }
    output
}

fn parse_toml_string_value(raw: &str) -> Option<&str> {
    let value = raw.trim();
    let rest = value.strip_prefix('"')?;
    let end = rest.find('"')?;
    let trailing = rest[end + 1..].trim();
    if trailing.is_empty() || trailing.starts_with('#') {
        Some(&rest[..end])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_managed_entries_are_replaced_on_rerun() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hooks.json");

        apply_cursor(&path, false, false, false, false).unwrap();
        apply_cursor(&path, false, false, false, true).unwrap();

        let root: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        for key in [
            "beforeReadFile",
            "beforeShellExecution",
            "beforeMCPExecution",
            "beforeSubmitPrompt",
        ] {
            let hooks = root["hooks"][key].as_array().unwrap();
            assert_eq!(hooks.len(), 1, "{key} should not duplicate: {hooks:?}");
            assert_eq!(hooks[0]["failClosed"], true);
        }
        for key in ["afterShellExecution", "afterMCPExecution"] {
            let hooks = root["hooks"][key].as_array().unwrap();
            assert_eq!(hooks.len(), 1, "{key} should not duplicate: {hooks:?}");
            let cmd = hooks[0]["command"].as_str().unwrap_or_default();
            assert!(cmd.contains("--post"), "{key} should scan as post: {cmd}");
            assert!(
                hooks[0].get("failClosed").is_none(),
                "after* hooks are observational and should not set failClosed: {hooks:?}"
            );
        }
        let prompt_cmd = root["hooks"]["beforeSubmitPrompt"][0]["command"]
            .as_str()
            .unwrap_or_default();
        assert!(
            prompt_cmd.contains(&format!("--fail-on {USER_PROMPT_HOOK_FAIL_ON}")),
            "beforeSubmitPrompt should block medium PII: {prompt_cmd}"
        );
        let read_cmd = root["hooks"]["beforeReadFile"][0]["command"]
            .as_str()
            .unwrap_or_default();
        assert!(
            !read_cmd.contains(&format!("--fail-on {USER_PROMPT_HOOK_FAIL_ON}")),
            "beforeReadFile should keep default high threshold: {read_cmd}"
        );
    }

    #[test]
    fn hook_scan_cli_command_includes_log_blocked_when_enabled() {
        let cmd = hook_scan_cli_command(AiTool::Cursor, false, true, false);
        assert!(cmd.contains("--log-blocked"), "{cmd}");
        assert!(!cmd.contains("--audit"), "{cmd}");
    }

    #[test]
    fn hook_scan_cli_command_omits_log_blocked_in_audit_mode() {
        let cmd = hook_scan_cli_command(AiTool::Cursor, true, true, false);
        assert!(cmd.contains("--audit"), "{cmd}");
        assert!(!cmd.contains("--log-blocked"), "{cmd}");
    }

    #[test]
    fn hook_scan_cli_command_includes_log_blocked_for_all_tools() {
        for tool in [
            AiTool::ClaudeCode,
            AiTool::Codex,
            AiTool::Cursor,
            AiTool::Antigravity,
        ] {
            let cmd = hook_scan_cli_command(tool, false, true, false);
            assert!(cmd.contains("--log-blocked"), "{cmd}");
        }
    }

    #[test]
    fn antigravity_managed_hook_is_replaced_on_rerun() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hooks.json");
        fs::write(
            &path,
            serde_json::to_string_pretty(&json!({
                "my-linter-hook": {
                    "PostToolUse": [{ "matcher": "run_command", "hooks": [{ "command": "./lint.sh" }] }]
                }
            }))
            .unwrap(),
        )
        .unwrap();

        apply_antigravity(&path, false, false, false, false).unwrap();
        apply_antigravity(&path, true, false, false, false).unwrap();

        let root: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert!(
            root.get("my-linter-hook").is_some(),
            "existing user hooks must be preserved: {root}"
        );
        let pre = root[ANTIGRAVITY_HOOK_NAME]["PreToolUse"]
            .as_array()
            .unwrap();
        assert_eq!(pre.len(), 1, "{pre:?}");
        assert_eq!(pre[0]["_shk_managed"], true);
        assert_eq!(pre[0]["matcher"], ANTIGRAVITY_PRE_MATCHER);
        let cmd = pre[0]["hooks"][0]["command"].as_str().unwrap();
        assert!(
            cmd.contains("shk scan --hook-mode antigravity --audit"),
            "{cmd}"
        );
        assert!(
            root[ANTIGRAVITY_HOOK_NAME].get("PostToolUse").is_none(),
            "Antigravity post payloads carry no tool output, so no post hook: {root}"
        );
    }

    #[test]
    fn windsurf_managed_hooks_are_replaced_on_rerun() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hooks.json");
        // Pre-existing user hook in a managed event array must survive re-runs.
        fs::write(
            &path,
            serde_json::to_string_pretty(&json!({
                "hooks": {
                    "pre_run_command": [
                        { "command": "./lint.sh", "show_output": false }
                    ]
                }
            }))
            .unwrap(),
        )
        .unwrap();

        apply_windsurf(&path, false, false, false).unwrap();
        apply_windsurf(&path, true, false, false).unwrap();

        let root: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();

        let pre_run = root["hooks"]["pre_run_command"].as_array().unwrap();
        assert!(
            pre_run.iter().any(|e| e["command"] == "./lint.sh"),
            "user hook must be preserved: {pre_run:?}"
        );
        assert_eq!(
            pre_run
                .iter()
                .filter(|e| is_managed_windsurf_entry(e))
                .count(),
            1,
            "managed hook should not duplicate: {pre_run:?}"
        );

        for key in WINDSURF_PRE_KEYS {
            let arr = root["hooks"][*key].as_array().unwrap();
            let managed = arr.iter().find(|e| is_managed_windsurf_entry(e)).unwrap();
            let cmd = managed["command"].as_str().unwrap();
            assert!(!cmd.contains("--post"), "{key} is a pre hook: {cmd}");
            assert!(cmd.contains("--audit"), "second run sets audit: {cmd}");
            assert_eq!(managed["show_output"], true, "{key}");
        }
        for key in WINDSURF_POST_KEYS {
            let cmd = root["hooks"][*key][0]["command"].as_str().unwrap();
            assert!(cmd.contains("--post"), "{key} scans as post: {cmd}");
        }
        let prompt_cmd = root["hooks"][WINDSURF_PROMPT_KEY][0]["command"]
            .as_str()
            .unwrap();
        assert!(
            prompt_cmd.contains(&format!("--fail-on {USER_PROMPT_HOOK_FAIL_ON}")),
            "pre_user_prompt should block medium PII: {prompt_cmd}"
        );
    }

    #[test]
    fn windsurf_dry_run_does_not_write_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hooks.json");

        let summary = apply_windsurf(&path, false, false, true).unwrap();

        assert!(summary.starts_with("dry-run:"), "{summary}");
        assert!(!path.exists(), "dry-run must not create the hooks file");
    }

    #[test]
    fn windsurf_remove_deletes_only_managed_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hooks.json");
        fs::write(
            &path,
            serde_json::to_string_pretty(&json!({
                "hooks": {
                    "pre_run_command": [
                        { "command": "./lint.sh", "show_output": false }
                    ]
                }
            }))
            .unwrap(),
        )
        .unwrap();
        apply_windsurf(&path, false, false, false).unwrap();

        let summary = remove_windsurf_scan_hooks(&path, false).unwrap();
        assert!(summary.contains("removed"), "{summary}");

        let root: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        for arr in root["hooks"].as_object().unwrap().values() {
            assert!(
                !arr.as_array()
                    .unwrap()
                    .iter()
                    .any(is_managed_windsurf_entry),
                "managed entries should be gone: {root}"
            );
        }
        // Non-managed user hook survives.
        assert!(
            root["hooks"]["pre_run_command"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["command"] == "./lint.sh"),
            "user hook must be preserved: {root}"
        );
    }

    #[test]
    fn windsurf_remove_without_file_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.json");
        let summary = remove_windsurf_scan_hooks(&path, false).unwrap();
        assert!(summary.contains("no Windsurf hooks file"), "{summary}");
    }

    #[test]
    fn antigravity_remove_deletes_only_managed_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hooks.json");
        apply_antigravity(&path, false, false, false, false).unwrap();

        let summary = remove_antigravity_scan_hooks(&path, false).unwrap();
        assert!(summary.contains("removed 1"), "{summary}");
        let root: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert!(root.get(ANTIGRAVITY_HOOK_NAME).is_none(), "{root}");
    }

    #[test]
    fn codex_project_hook_command_uses_git_root_path() {
        let cmd = codex_hook_command(false, false, false, true, None);

        assert!(
            cmd.contains(r#"shk scan "$(git rev-parse --show-toplevel)" --hook-mode codex"#),
            "{cmd}"
        );
    }

    #[test]
    fn codex_global_hook_command_uses_session_cwd() {
        let cmd = codex_hook_command(false, false, false, false, None);

        assert_eq!(cmd, "shk scan --hook-mode codex");
    }

    #[test]
    fn codex_user_prompt_hook_command_uses_medium_threshold() {
        let cmd =
            user_prompt_hook_scan_command(AiTool::Codex, false, false, Some(CODEX_GIT_ROOT_ARG));

        assert!(
            cmd.contains(&format!("--fail-on {USER_PROMPT_HOOK_FAIL_ON}")),
            "UserPromptSubmit should block medium PII: {cmd}"
        );
    }

    #[test]
    fn claude_user_prompt_hook_command_uses_medium_threshold() {
        let cmd = user_prompt_hook_scan_command(AiTool::ClaudeCode, false, false, None);

        assert!(
            cmd.contains(&format!("--fail-on {USER_PROMPT_HOOK_FAIL_ON}")),
            "UserPromptSubmit should block medium PII: {cmd}"
        );
    }

    #[test]
    fn codex_managed_block_is_replaced_on_rerun() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        apply_codex(&path, false, false, false, false, true).unwrap();
        apply_codex(&path, true, false, false, false, true).unwrap();

        let body = fs::read_to_string(path).unwrap();
        assert_eq!(body.matches("# shk-managed-start").count(), 1, "{body}");
        assert_eq!(body.matches("[[hooks.PreToolUse]]").count(), 1, "{body}");
        assert_eq!(
            body.matches("[[hooks.PermissionRequest]]").count(),
            1,
            "{body}"
        );
        assert_eq!(
            body.matches("[[hooks.UserPromptSubmit]]").count(),
            1,
            "{body}"
        );
        assert_eq!(body.matches("[[hooks.PostToolUse]]").count(), 1, "{body}");
        assert!(
            body.contains(
                r#"shk scan "$(git rev-parse --show-toplevel)" --hook-mode codex --audit"#
            ),
            "{body}"
        );
        assert!(body.contains("command = '"), "{body}");
        let prompt_section = codex_managed_hook_section(&body, "UserPromptSubmit", "PostToolUse");
        assert!(
            prompt_section.contains(&format!("--fail-on {USER_PROMPT_HOOK_FAIL_ON}")),
            "UserPromptSubmit should use medium threshold: {prompt_section}"
        );
        let pre_section = codex_managed_hook_section(&body, "PreToolUse", "PermissionRequest");
        assert!(
            !pre_section.contains(&format!("--fail-on {USER_PROMPT_HOOK_FAIL_ON}")),
            "PreToolUse should keep default high threshold: {pre_section}"
        );
    }

    fn codex_managed_hook_section<'a>(body: &'a str, event: &str, next_event: &str) -> &'a str {
        let start = format!("[[hooks.{event}]]");
        let end = format!("[[hooks.{next_event}]]");
        body.split(&start)
            .nth(1)
            .and_then(|section| section.split(&end).next())
            .unwrap_or("")
    }

    #[test]
    fn claude_sandbox_settings_merge_without_duplicate_paths() {
        let mut root = json!({
            "sandbox": {
                "filesystem": {
                    "denyRead": ["~/.aws/credentials"],
                    "allowRead": ["."]
                }
            }
        });

        merge_claude_sandbox(&mut root, true).unwrap();
        merge_claude_sandbox(&mut root, true).unwrap();

        assert_eq!(root["sandbox"]["enabled"], true);
        assert_eq!(root["sandbox"]["failIfUnavailable"], true);
        assert_eq!(root["sandbox"]["allowUnsandboxedCommands"], false);
        let deny_read = root["sandbox"]["filesystem"]["denyRead"]
            .as_array()
            .unwrap();
        assert_eq!(
            deny_read.iter().filter(|v| *v == "~/").count(),
            1,
            "{deny_read:?}"
        );
        let allow_read = root["sandbox"]["filesystem"]["allowRead"]
            .as_array()
            .unwrap();
        assert_eq!(
            allow_read.iter().filter(|v| *v == ".").count(),
            1,
            "{allow_read:?}"
        );
    }

    #[test]
    fn claude_global_sandbox_settings_do_not_add_project_relative_read_allow() {
        let mut root = json!({});

        merge_claude_sandbox(&mut root, false).unwrap();

        assert_eq!(root["sandbox"]["enabled"], true);
        assert_eq!(root["sandbox"]["failIfUnavailable"], true);
        assert_eq!(root["sandbox"]["allowUnsandboxedCommands"], false);
        assert!(
            root["sandbox"].get("filesystem").is_none(),
            "global settings should not add `allowRead = [\".\"]` because it resolves under ~/.claude: {root}"
        );
    }

    #[test]
    fn codex_sandbox_settings_replace_risky_values() {
        let body = ensure_codex_sandbox_settings(
            r#"
sandbox_mode = "danger-full-access" # existing risky setting
approval_policy = "never"

[features]
hooks = true
"#,
        );

        assert!(
            body.contains(r#"sandbox_mode = "workspace-write""#),
            "{body}"
        );
        assert!(body.contains(r#"approval_policy = "on-request""#), "{body}");
        assert!(!body.contains("danger-full-access"), "{body}");
    }

    #[test]
    fn codex_sandbox_settings_preserve_stricter_values() {
        let body = ensure_codex_sandbox_settings(
            r#"
sandbox_mode = "read-only"
approval_policy = "untrusted"
"#,
        );

        assert!(body.contains(r#"sandbox_mode = "read-only""#), "{body}");
        assert!(body.contains(r#"approval_policy = "untrusted""#), "{body}");
    }

    #[test]
    fn codex_features_do_not_capture_top_level_settings() {
        let body = ensure_codex_features_prefix(
            r#"model = "gpt-5"
sandbox_mode = "workspace-write"

[profiles.default]
approval_policy = "on-request"
"#,
        );

        assert!(body.starts_with("model = \"gpt-5\"\n"), "{body}");
        assert!(
            body.contains("sandbox_mode = \"workspace-write\"\n\n[features]\nhooks = true\n\n[profiles.default]"),
            "{body}"
        );
    }

    #[test]
    fn codex_features_upgrade_legacy_feature_name() {
        let body = ensure_codex_features_prefix(
            r#"[features]
codex_hooks = true
other = false
"#,
        );

        assert!(
            body.contains("[features]\nhooks = true\nother = false"),
            "{body}"
        );
        assert!(!body.contains("codex_hooks"), "{body}");
    }

    #[test]
    fn codex_features_remove_legacy_alias_when_canonical_key_exists() {
        let body = ensure_codex_features_prefix(
            r#"[features]
hooks = false
codex_hooks = true
other = false
"#,
        );

        assert!(
            body.contains("[features]\nhooks = true\nother = false"),
            "{body}"
        );
        assert!(!body.contains("codex_hooks"), "{body}");
    }

    #[test]
    fn codex_sandbox_settings_ignore_profile_scoped_values() {
        let body = ensure_codex_sandbox_settings(
            r#"
[profiles.dev]
sandbox_mode = "danger-full-access"
"#,
        );

        assert!(
            body.starts_with(r#"approval_policy = "on-request""#),
            "{body}"
        );
        assert!(
            body.contains(r#"sandbox_mode = "workspace-write""#),
            "{body}"
        );
        assert!(body.contains("[profiles.dev]"), "{body}");
    }

    #[test]
    fn configure_ai_selection_syncs_only_selected_claude_settings() {
        let dir = tempfile::tempdir().unwrap();
        let settings_dir = dir.path().join(".claude");
        fs::create_dir_all(&settings_dir).unwrap();
        let settings_path = settings_dir.join("settings.json");
        fs::write(
            &settings_path,
            serde_json::to_string_pretty(&json!({
                "hooks": {
                    "PreToolUse": [{
                        "_shk_managed": true,
                        "matcher": "Read",
                        "hooks": [{ "type": "command", "command": "shk scan --hook-mode claude-code" }]
                    }],
                    "PostToolUse": [{
                        "matcher": "Bash",
                        "hooks": [{ "type": "command", "command": "echo keep-me" }]
                    }]
                },
                "permissions": {
                    "deny": ["Bash(rm -rf *)"]
                }
            }))
            .unwrap(),
        )
        .unwrap();

        configure_ai_with_summaries(
            dir.path(),
            ConfigureAiOptions {
                audit: false,
                log_blocked: false,
                dry_run: false,
                global: false,
                fail_closed: false,
                scan_hooks_claude_code: false,
                scan_hooks_cursor: false,
                scan_hooks_codex: false,
                scan_hooks_copilot: false,
                scan_hooks_antigravity: false,
                scan_hooks_windsurf: false,
                claude_deny: false,
                claude_sandbox: true,
                codex_sandbox: false,
            },
        )
        .unwrap();

        let root: Value =
            serde_json::from_str(&fs::read_to_string(settings_path).unwrap()).unwrap();
        assert_eq!(root["hooks"]["PreToolUse"].as_array().unwrap().len(), 0);
        assert_eq!(root["hooks"]["PostToolUse"].as_array().unwrap().len(), 1);
        assert_eq!(root["permissions"]["deny"][0], "Bash(rm -rf *)");
        assert_eq!(root["sandbox"]["enabled"], true);
    }
}
