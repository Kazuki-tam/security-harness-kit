use crate::args::AiTool;
use anyhow::{Context, Result};
use regex::Regex;
use serde_json::{Value, json};
use shk_integrations::normalize_claude_deny_entry;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Timeout (seconds) embedded in Cursor / Codex hook command payloads (CLI JSON / TOML).
const HOOK_CLI_TIMEOUT_SEC: u64 = 30;

#[derive(Clone, Copy, Debug)]
pub struct InstallAiOptions {
    pub audit: bool,
    pub dry_run: bool,
    pub global: bool,
    pub fail_closed: bool,
    pub apply_deny: bool,
    pub apply_sandbox: bool,
}

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
        vec![AiTool::ClaudeCode, AiTool::Codex, AiTool::Cursor]
    };

    println!(
        "shk hooks install-ai (global={}, audit={}, dry-run={}, apply-sandbox={})",
        opts.global, opts.audit, opts.dry_run, opts.apply_sandbox
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
            opts.dry_run,
            opts.apply_deny,
            opts.apply_sandbox,
            restrict_sandbox_reads_to_project,
        ),
        AiTool::Cursor => apply_cursor(
            path,
            opts.audit,
            opts.dry_run,
            opts.fail_closed || opts.apply_sandbox,
        ),
        AiTool::Codex => apply_codex(path, opts.audit, opts.dry_run, opts.apply_sandbox),
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

fn apply_claude(
    path: &Path,
    audit: bool,
    dry_run: bool,
    apply_deny: bool,
    apply_sandbox: bool,
    restrict_sandbox_reads_to_project: bool,
) -> Result<String> {
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
    if apply_sandbox {
        merge_claude_sandbox(&mut root, restrict_sandbox_reads_to_project)?;
    }

    save_json_formatted(path, &root, dry_run)?;
    Ok(if dry_run {
        format!(
            "dry-run: would write managed UserPromptSubmit/PreToolUse/PostToolUse blocks (audit={audit}, applyDeny={apply_deny}, applySandbox={apply_sandbox}, denyAdded={deny_added})"
        )
    } else {
        format!(
            "wrote managed blocks (audit={audit}, applyDeny={apply_deny}, applySandbox={apply_sandbox}, denyAdded={deny_added})"
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

fn apply_codex(path: &Path, audit: bool, dry_run: bool, apply_sandbox: bool) -> Result<String> {
    let block = codex_managed_block(audit, audit);
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
            "dry-run: would write codex_hooks + managed block len={} (applySandbox={apply_sandbox})",
            new_body.lines().count(),
        ));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::write(path, &new_body).with_context(|| format!("write {}", path.display()))?;
    Ok(format!(
        "wrote .codex/config.toml hooks block (applySandbox={apply_sandbox})"
    ))
}

fn ensure_codex_sandbox_settings(content: &str) -> String {
    let content = ensure_top_level_string_setting(
        content,
        "sandbox_mode",
        "workspace-write",
        &["danger-full-access"],
    );
    ensure_top_level_string_setting(&content, "approval_policy", "on-request", &["never"])
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

        apply_cursor(&path, false, false, false).unwrap();
        apply_cursor(&path, false, false, true).unwrap();

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
    }

    #[test]
    fn codex_managed_block_is_replaced_on_rerun() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        apply_codex(&path, false, false, false).unwrap();
        apply_codex(&path, true, false, false).unwrap();

        let body = fs::read_to_string(path).unwrap();
        assert_eq!(body.matches("# shk-managed-start").count(), 1, "{body}");
        assert_eq!(body.matches("[[hooks.PreToolUse]]").count(), 1, "{body}");
        assert_eq!(
            body.matches("[[hooks.PermissionRequest]]").count(),
            1,
            "{body}"
        );
        assert_eq!(body.matches("[[hooks.PostToolUse]]").count(), 1, "{body}");
        assert!(
            body.contains("shk scan --hook-mode codex --audit"),
            "{body}"
        );
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
codex_hooks = true
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
}
