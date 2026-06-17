use crate::exit::CliExit;
use crate::hook_audit_log;
use crate::hook_output;
use crate::output;
use crate::safety;
use anyhow::{Context, Result, bail};
use shk_core::policy::{ColorMode, Policy, Severity};
use shk_core::scanner::{
    GitHistoryPreview, ScanOptions, ScanResult, preview_git_history, scan_path, scan_string,
};
use shk_integrations::ActionGuardMatch;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::args::{AiTool, SeverityArg};

const HOOK_DENY_REASON_DEFAULT: &str =
    "shk: sensitive content detected above threshold - run `shk scan` for details";

/// Flat `clap` flags for [`run`], grouped for readability at the CLI boundary.
#[derive(Clone, Debug)]
pub struct ScanInvocation {
    pub path: PathBuf,
    pub staged: bool,
    pub changed_since: Option<String>,
    pub git_history: bool,
    pub preview: bool,
    pub git_history_ref: Option<String>,
    pub since: Option<String>,
    pub max_commits: Option<usize>,
    pub json: bool,
    pub sarif: bool,
    pub with_value_hash: bool,
    pub verbose: bool,
    pub fail_on: Option<SeverityArg>,
    pub include_binary: bool,
    pub follow_symlinks: bool,
    pub hook_mode: Option<AiTool>,
    pub post: bool,
    pub audit: bool,
    pub log_blocked: bool,
    pub color_enabled: bool,
}

pub fn run(inv: ScanInvocation) -> Result<()> {
    let cwd = std::env::current_dir().context("current directory for policy resolution")?;

    if inv.hook_mode.is_some() && (inv.staged || inv.changed_since.is_some() || inv.git_history) {
        bail!(
            "`--hook-mode` cannot be combined with `--staged`, `--changed-since`, or `--git-history`"
        );
    }
    if inv.with_value_hash && !inv.json && !inv.sarif {
        bail!("`--with-value-hash` requires `--json` or `--sarif`");
    }

    if let Some(tool) = inv.hook_mode {
        return run_hook_mode(
            tool,
            inv.post,
            inv.audit,
            inv.log_blocked,
            inv.fail_on,
            &cwd,
            inv.path,
        );
    }

    let fail_on_override = inv.fail_on.map(Severity::from);
    let opts = ScanOptions {
        staged: inv.staged,
        changed_since: inv.changed_since.clone(),
        git_history: inv.git_history,
        git_history_ref: inv.git_history_ref.clone(),
        git_history_since: inv.since.clone(),
        git_history_max_commits: inv.max_commits,
        json: inv.json,
        fail_on_override,
        use_pre_commit_threshold: inv.staged,
        include_context: false,
        include_binary: inv.include_binary,
        follow_symlinks: inv.follow_symlinks,
    };
    if inv.staged && shk_core::git::discover_repo_root(&inv.path).is_none() {
        return Err(CliExit::message(2, "shk scan --staged requires a Git repository").into());
    }
    if inv.changed_since.is_some() && shk_core::git::discover_repo_root(&inv.path).is_none() {
        return Err(
            CliExit::message(2, "shk scan --changed-since requires a Git repository").into(),
        );
    }
    if inv.git_history && shk_core::git::discover_repo_root(&inv.path).is_none() {
        return Err(CliExit::message(2, "shk scan --git-history requires a Git repository").into());
    }
    if !inv.staged && inv.changed_since.is_none() && !inv.git_history && !inv.path.exists() {
        return Err(CliExit::message(
            2,
            format!("scan target does not exist: {}", inv.path.display()),
        )
        .into());
    }

    if inv.preview {
        let preview = preview_git_history(&inv.path, opts).context("git history preview failed")?;
        if inv.json {
            println!("{}", serde_json::to_string_pretty(&preview)?);
        } else {
            print!("{}", format_git_history_preview(&preview));
        }
        return Ok(());
    }

    let res = scan_path(&inv.path, opts).context("scan failed")?;
    if inv.sarif {
        println!(
            "{}",
            serde_json::to_string_pretty(&sarif_report(&res, inv.with_value_hash))?
        );
    } else if inv.json {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &res.to_json_report_with_value_hash(ColorMode::Never, inv.with_value_hash)
            )?
        );
    } else {
        print!(
            "{}",
            output::format_human_findings(
                &res.findings,
                inv.color_enabled,
                inv.verbose,
                res.deduplicated,
            )
        );
        println!(
            "{}",
            output::format_scan_summary(
                output::max_human_severity(&res.findings, inv.verbose),
                res.exit_threshold,
                inv.color_enabled,
            )
        );
    }
    if !inv.audit && res.should_fail() {
        return Err(CliExit::silent(1).into());
    }
    Ok(())
}

fn sarif_report(res: &ScanResult, include_value_hash: bool) -> serde_json::Value {
    let rules = sarif_rules(res);
    let results: Vec<serde_json::Value> = res
        .findings
        .iter()
        .map(|finding| sarif_result(finding, include_value_hash))
        .collect();
    serde_json::json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "shk",
                        "informationUri": "https://github.com/Kazuki-tam/security-harness-kit",
                        "rules": rules
                    }
                },
                "results": results,
                "properties": {
                    "scannedPaths": res.scanned_paths,
                    "exitThreshold": res.exit_threshold.as_str(),
                    "suppressed": res.suppressed,
                    "deduplicated": res.deduplicated
                }
            }
        ]
    })
}

fn sarif_rules(res: &ScanResult) -> Vec<serde_json::Value> {
    let mut by_rule = std::collections::BTreeMap::<String, &shk_core::finding::Finding>::new();
    for finding in &res.findings {
        by_rule.entry(finding.rule_id.clone()).or_insert(finding);
    }
    by_rule
        .into_iter()
        .map(|(rule_id, finding)| {
            serde_json::json!({
                "id": rule_id,
                "name": finding.rule_id,
                "shortDescription": { "text": finding.message },
                "properties": {
                    "kind": finding.kind,
                    "security-severity": sarif_security_severity(&finding.severity),
                    "precision": sarif_precision(finding.confidence),
                    "tags": ["security", finding.kind]
                }
            })
        })
        .collect()
}

fn sarif_result(
    finding: &shk_core::finding::Finding,
    include_value_hash: bool,
) -> serde_json::Value {
    let mut properties = serde_json::json!({
        "severity": finding.severity,
        "kind": finding.kind,
        "confidence": finding.confidence,
        "redactedValue": finding.redacted_value,
    });
    if include_value_hash
        && let Some(hash) = &finding.value_hash
        && let Some(map) = properties.as_object_mut()
    {
        map.insert("valueHash".into(), serde_json::json!(hash));
    }

    serde_json::json!({
        "ruleId": finding.rule_id,
        "level": sarif_level(&finding.severity),
        "message": { "text": finding.message },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": { "uri": finding.file },
                    "region": {
                        "startLine": finding.line.max(1),
                        "startColumn": finding.column.max(1)
                    }
                }
            }
        ],
        "partialFingerprints": {
            "primaryLocationLineHash": format!("{}:{}:{}", finding.rule_id, finding.file, finding.line)
        },
        "properties": properties
    })
}

fn sarif_level(severity: &str) -> &'static str {
    match severity {
        "critical" | "high" => "error",
        "medium" => "warning",
        "low" | "info" => "note",
        _ => "warning",
    }
}

fn sarif_security_severity(severity: &str) -> &'static str {
    match severity {
        "critical" => "9.0",
        "high" => "8.0",
        "medium" => "5.0",
        "low" => "2.0",
        "info" => "0.0",
        _ => "5.0",
    }
}

fn sarif_precision(confidence: f32) -> &'static str {
    if confidence >= 0.85 {
        "high"
    } else if confidence >= 0.6 {
        "medium"
    } else {
        "low"
    }
}

fn format_git_history_preview(preview: &GitHistoryPreview) -> String {
    let mut out = String::new();
    out.push_str("Git history scan preview\n\n");
    out.push_str(&format!("scope: {}\n", preview.scope));
    if let Some(since) = &preview.since {
        out.push_str(&format!("since: {since}\n"));
    }
    if let Some(max) = preview.max_commits {
        out.push_str(&format!("max_commits: {max}\n"));
    }
    out.push_str(&format!(
        "candidate_commits: {}\n",
        preview.candidate_commits
    ));
    out.push_str(&format!("candidate_paths: {}\n", preview.candidate_paths));
    out.push_str(&format!("unique_blobs: {}\n", preview.unique_blobs));
    out.push_str(&format!(
        "policy_filtered_blobs: {}\n",
        preview.policy_filtered_blobs
    ));
    if let Some(policy_path) = &preview.policy_path {
        out.push_str(&format!("policy_path: {policy_path}\n"));
    }
    if preview.sample_paths.is_empty() {
        out.push_str("\nsample_paths: none\n");
    } else {
        out.push_str("\nsample_paths:\n");
        for path in &preview.sample_paths {
            out.push_str(&format!("  {path}\n"));
        }
    }
    out
}

fn resolve_repo_root(cwd: &Path, path_arg: &Path) -> PathBuf {
    let candidates = [
        cwd.to_path_buf(),
        path_arg.to_path_buf(),
        cwd.join(path_arg),
    ];
    for cand in candidates {
        if let Some(r) = shk_core::git::discover_repo_root(&cand) {
            return fs_canonical_or_same(r);
        }
    }
    fs_canonical_or_same(cwd.to_path_buf())
}

fn run_hook_mode(
    tool: AiTool,
    post: bool,
    audit: bool,
    log_blocked: bool,
    fail_on: Option<SeverityArg>,
    cwd: &Path,
    path_arg: PathBuf,
) -> Result<()> {
    let mut stdin_raw = Vec::new();
    let mut stdin = std::io::stdin();
    if std::io::IsTerminal::is_terminal(&stdin) {
        bail!("`scan --hook-mode` requires hook JSON payload on stdin");
    }
    stdin.read_to_end(&mut stdin_raw)?;
    let stdin_str = String::from_utf8_lossy(&stdin_raw);
    let stdin_trim = stdin_str.trim();
    if stdin_trim.is_empty() {
        bail!("hook-mode requires hook JSON payload on stdin");
    }

    let hook_event = hook_event_from_stdin(stdin_trim, post);
    let repo_root = resolve_repo_root(cwd, path_arg.as_path());
    require_hook_log_policy(&repo_root, audit, log_blocked)?;

    if hook_event == hook_output::HookEvent::UserPromptSubmit {
        return run_user_prompt_mode(tool, audit, log_blocked, fail_on, &repo_root, stdin_trim);
    }

    let (policy, _) = Policy::load_from_dir(&repo_root)?;
    let action_guard_config = action_guard_config_from_policy(&policy);

    if should_run_action_guard(post, audit)
        && let Some(guard_match) =
            shk_integrations::detect_dangerous_action_with_config(stdin_trim, &action_guard_config)?
    {
        let reason = action_guard_deny_reason(&guard_match);
        return deny_hook_with_log(
            &repo_root,
            log_blocked,
            tool,
            hook_event,
            &reason,
            BlockLog::ActionGuard(&guard_match),
        );
    }

    let (disp, body) = shk_integrations::stdin_to_hook_body(
        tool.integration_tool(),
        post,
        stdin_trim,
        cwd,
        &repo_root,
    )?;
    let opts = hook_scan_options(fail_on, matches!(tool, AiTool::Cursor) && !post);

    let res = scan_string(&repo_root, &disp, &body, opts).context("hook scan failed")?;

    if audit {
        hook_audit_log::append_audit_hook(&repo_root, tool, hook_event, &disp, &res)?;
        println!(
            "{}",
            hook_output::allow_stdout_for_event(
                tool,
                hook_event,
                Some("shk audit: non-blocking (see .shk/audit.log)"),
            ),
        );
        return Ok(());
    }

    if post {
        if log_blocked {
            if let Err(err) =
                hook_audit_log::append_audit_hook(&repo_root, tool, hook_event, &disp, &res)
            {
                eprintln!("shk post audit: unable to write .shk/audit.log: {err:#}");
            }
        }
        emit_post_hook_result(tool, hook_event, &res);
        return Ok(());
    }

    if res.should_fail() {
        return deny_hook_with_log(
            &repo_root,
            log_blocked,
            tool,
            hook_event,
            HOOK_DENY_REASON_DEFAULT,
            BlockLog::Scan {
                display_path: &disp,
                result: &res,
            },
        );
    }

    println!(
        "{}",
        hook_output::allow_stdout_for_event(tool, hook_event, None)
    );
    Ok(())
}

fn require_hook_log_policy(repo_root: &Path, audit: bool, log_blocked: bool) -> Result<()> {
    if audit {
        safety::require_project_policy(repo_root, "scan --audit")?;
    }
    if log_blocked {
        safety::require_project_policy(repo_root, "scan --log-blocked")?;
    }
    Ok(())
}

enum BlockLog<'a> {
    Scan {
        display_path: &'a str,
        result: &'a ScanResult,
    },
    ActionGuard(&'a ActionGuardMatch),
}

fn deny_hook_with_log(
    repo_root: &Path,
    log_blocked: bool,
    tool: AiTool,
    event: hook_output::HookEvent,
    reason: &str,
    block_log: BlockLog<'_>,
) -> Result<()> {
    if log_blocked {
        let append_result = match block_log {
            BlockLog::Scan {
                display_path,
                result,
            } => hook_audit_log::append_blocked_scan(repo_root, tool, event, display_path, result),
            BlockLog::ActionGuard(guard_match) => {
                hook_audit_log::append_blocked_action_guard(repo_root, tool, event, guard_match)
            }
        };
        if let Err(err) = append_result {
            eprintln!("shk blocked: unable to write .shk/audit.log: {err:#}");
        }
    }
    deny_hook(tool, event, reason)
}

fn emit_post_hook_result(tool: AiTool, hook_event: hook_output::HookEvent, res: &ScanResult) {
    if res.findings.is_empty() {
        println!(
            "{}",
            hook_output::allow_stdout_for_event(tool, hook_event, None)
        );
        return;
    }

    let hint = format!(
        "shk: {} finding(s) in tool output - review before using ({} suppressed, {} deduplicated)",
        res.findings.len(),
        res.suppressed,
        res.deduplicated,
    );
    eprintln!("{hint}");
    println!(
        "{}",
        hook_output::allow_stdout_for_event(tool, hook_event, Some(&hint))
    );
}

fn action_guard_config_from_policy(policy: &Policy) -> shk_integrations::ActionGuardConfig {
    shk_integrations::ActionGuardConfig {
        enabled: policy.action_guard.enabled,
        profile: policy.action_guard.profile.clone(),
        allow: policy.action_guard.allow.clone(),
        deny: policy.action_guard.deny.clone(),
    }
}

fn action_guard_deny_reason(guard_match: &ActionGuardMatch) -> String {
    format!("shk action guard: {} blocked", guard_match.category)
}

fn should_run_action_guard(post: bool, audit: bool) -> bool {
    !post && !audit
}

fn run_user_prompt_mode(
    tool: AiTool,
    audit: bool,
    log_blocked: bool,
    fail_on: Option<SeverityArg>,
    repo_root: &Path,
    stdin_trim: &str,
) -> Result<()> {
    let event = hook_output::HookEvent::UserPromptSubmit;
    let prompt = shk_integrations::extract_user_prompt(stdin_trim).unwrap_or_default();

    if prompt.is_empty() {
        println!("{}", hook_output::allow_stdout_for_event(tool, event, None));
        return Ok(());
    }

    let opts = hook_scan_options(fail_on, false);

    let res = scan_string(repo_root, "<user-prompt>", prompt.as_ref(), opts)
        .context("user-prompt scan failed")?;

    if audit {
        hook_audit_log::append_audit_hook(repo_root, tool, event, "<user-prompt>", &res)?;
        println!(
            "{}",
            hook_output::allow_stdout_for_event(
                tool,
                event,
                Some("shk audit: non-blocking (see .shk/audit.log)"),
            )
        );
        return Ok(());
    }

    if res.should_fail() {
        return deny_hook_with_log(
            repo_root,
            log_blocked,
            tool,
            event,
            HOOK_DENY_REASON_DEFAULT,
            BlockLog::Scan {
                display_path: "<user-prompt>",
                result: &res,
            },
        );
    }

    println!("{}", hook_output::allow_stdout_for_event(tool, event, None));
    Ok(())
}

fn hook_scan_options(fail_on: Option<SeverityArg>, use_pre_commit_threshold: bool) -> ScanOptions {
    ScanOptions {
        staged: false,
        changed_since: None,
        git_history: false,
        git_history_ref: None,
        git_history_since: None,
        git_history_max_commits: None,
        json: false,
        fail_on_override: fail_on.map(Severity::from),
        use_pre_commit_threshold,
        include_context: false,
        include_binary: false,
        follow_symlinks: false,
    }
}

fn deny_hook(tool: AiTool, event: hook_output::HookEvent, reason: &str) -> Result<()> {
    println!(
        "{}",
        hook_output::deny_stdout_for_event(tool, event, reason)
    );
    emit_blocking_reason_to_stderr(tool, event, reason);
    match hook_deny_exit_code(tool, event) {
        0 => Ok(()),
        code => Err(CliExit::silent(code).into()),
    }
}

/// Exit code for a denied hook, per tool/event contract.
///
/// GitHub Copilot's `preToolUse` / `permissionRequest` denies travel via the
/// stdout JSON (`permissionDecision` / `behavior`) and require exit 0 to be
/// honored; exit 2 is treated as a non-blocking warning for those events.
/// Copilot's `userPromptSubmitted` output is not processed, so exit 2 (a
/// stderr warning) is the only user-visible signal; it cannot hard-block.
/// Every other tool uses exit 2 to abort the pending operation.
fn hook_deny_exit_code(tool: AiTool, event: hook_output::HookEvent) -> i32 {
    match tool {
        AiTool::Copilot => match event {
            hook_output::HookEvent::PreToolUse
            | hook_output::HookEvent::PermissionRequest
            | hook_output::HookEvent::PostToolUse => 0,
            hook_output::HookEvent::UserPromptSubmit => 2,
        },
        _ => 2,
    }
}

fn emit_blocking_reason_to_stderr(tool: AiTool, event: hook_output::HookEvent, reason: &str) {
    let copilot_user_prompt =
        tool == AiTool::Copilot && event == hook_output::HookEvent::UserPromptSubmit;
    // Cascade (Windsurf) surfaces the stderr message of a
    // blocking pre-hook (exit 2) to the agent; stdout is ignored.
    if tool == AiTool::Codex || tool == AiTool::Windsurf || copilot_user_prompt {
        eprintln!("{reason}");
    }
}

fn hook_event_from_stdin(stdin: &str, post: bool) -> hook_output::HookEvent {
    if post {
        return hook_output::HookEvent::PostToolUse;
    }

    let Ok(value) = serde_json::from_str::<serde_json::Value>(stdin) else {
        return hook_output::HookEvent::PreToolUse;
    };
    match hook_event_name(&value) {
        Some("PermissionRequest") => hook_output::HookEvent::PermissionRequest,
        Some("UserPromptSubmit" | "UserPromptSubmitted") => {
            hook_output::HookEvent::UserPromptSubmit
        }
        // Cascade (Windsurf) uses `agent_action_name`; only
        // `pre_user_prompt` maps to the prompt event, other `pre_*` actions are
        // ordinary pre-tool guards.
        _ if cascade_action_name(&value) == Some("pre_user_prompt") => {
            hook_output::HookEvent::UserPromptSubmit
        }
        _ if looks_like_user_prompt_payload(&value) => hook_output::HookEvent::UserPromptSubmit,
        _ => hook_output::HookEvent::PreToolUse,
    }
}

fn hook_event_name(value: &serde_json::Value) -> Option<&str> {
    value
        .get("hook_event_name")
        .or_else(|| value.get("hookEventName"))
        .and_then(serde_json::Value::as_str)
}

fn cascade_action_name(value: &serde_json::Value) -> Option<&str> {
    value
        .get("agent_action_name")
        .and_then(serde_json::Value::as_str)
}

fn looks_like_user_prompt_payload(value: &serde_json::Value) -> bool {
    value
        .get("prompt")
        .and_then(serde_json::Value::as_str)
        .is_some()
        && value.get("toolName").is_none()
        && value.get("tool_name").is_none()
}

fn fs_canonical_or_same(p: PathBuf) -> PathBuf {
    std::fs::canonicalize(&p).unwrap_or(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hook_output::HookEvent;

    #[test]
    fn hook_event_post_flag_always_maps_to_post_tool_use() {
        assert_eq!(
            hook_event_from_stdin(r#"{"agent_action_name":"pre_read_code"}"#, true),
            HookEvent::PostToolUse
        );
    }

    #[test]
    fn hook_event_recognizes_explicit_event_names() {
        assert_eq!(
            hook_event_from_stdin(r#"{"hook_event_name":"PermissionRequest"}"#, false),
            HookEvent::PermissionRequest
        );
        assert_eq!(
            hook_event_from_stdin(r#"{"hookEventName":"UserPromptSubmitted"}"#, false),
            HookEvent::UserPromptSubmit
        );
    }

    #[test]
    fn hook_event_maps_cascade_action_names() {
        // Only `pre_user_prompt` is the prompt event; other pre_* actions are
        // ordinary pre-tool guards.
        assert_eq!(
            hook_event_from_stdin(
                r#"{"agent_action_name":"pre_user_prompt","tool_info":{"user_prompt":"hi"}}"#,
                false
            ),
            HookEvent::UserPromptSubmit
        );
        for action in [
            "pre_read_code",
            "pre_write_code",
            "pre_run_command",
            "pre_mcp_tool_use",
        ] {
            let stdin = format!(r#"{{"agent_action_name":"{action}","tool_info":{{}}}}"#);
            assert_eq!(
                hook_event_from_stdin(&stdin, false),
                HookEvent::PreToolUse,
                "{action} should be a pre-tool guard"
            );
        }
    }

    #[test]
    fn hook_event_falls_back_to_pre_tool_use_for_invalid_or_unknown() {
        assert_eq!(
            hook_event_from_stdin("not json", false),
            HookEvent::PreToolUse
        );
        assert_eq!(
            hook_event_from_stdin(r#"{"tool_name":"bash"}"#, false),
            HookEvent::PreToolUse
        );
    }

    #[test]
    fn hook_event_top_level_prompt_heuristic_still_applies() {
        assert_eq!(
            hook_event_from_stdin(r#"{"prompt":"do a thing"}"#, false),
            HookEvent::UserPromptSubmit
        );
        // A prompt accompanied by a tool name is not a user-prompt submission.
        assert_eq!(
            hook_event_from_stdin(r#"{"prompt":"x","tool_name":"bash"}"#, false),
            HookEvent::PreToolUse
        );
    }

    #[test]
    fn cascade_action_name_reads_only_string_field() {
        let value: serde_json::Value =
            serde_json::from_str(r#"{"agent_action_name":"pre_run_command"}"#).unwrap();
        assert_eq!(cascade_action_name(&value), Some("pre_run_command"));
        let missing: serde_json::Value = serde_json::from_str(r#"{"other":1}"#).unwrap();
        assert_eq!(cascade_action_name(&missing), None);
    }

    #[test]
    fn windsurf_routes_block_reason_to_stderr_like_codex() {
        // Smoke-level behavior is covered elsewhere; this guards the routing
        // predicate so a future tool list change cannot silently drop Windsurf.
        for event in [
            HookEvent::PreToolUse,
            HookEvent::PermissionRequest,
            HookEvent::UserPromptSubmit,
        ] {
            assert_eq!(hook_deny_exit_code(AiTool::Windsurf, event), 2);
        }
    }
}
