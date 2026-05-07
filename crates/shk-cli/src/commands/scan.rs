use crate::audit_log;
use crate::exit::CliExit;
use crate::hook_output;
use crate::output;
use crate::safety;
use anyhow::{Context, Result, bail};
use shk_core::policy::{ColorMode, Policy, Severity};
use shk_core::scanner::{ScanOptions, scan_path, scan_string};
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::args::AiTool;

const HOOK_DENY_REASON_DEFAULT: &str =
    "shk: secrets detected above threshold — run `shk scan` for details";

/// Flat `clap` flags for [`run`], grouped for readability at the CLI boundary.
#[derive(Clone, Debug)]
pub struct ScanInvocation {
    pub path: PathBuf,
    pub staged: bool,
    pub json: bool,
    pub verbose: bool,
    pub fail_on: Option<String>,
    pub include_binary: bool,
    pub follow_symlinks: bool,
    pub hook_mode: Option<AiTool>,
    pub post: bool,
    pub audit: bool,
    pub color_enabled: bool,
}

pub fn run(inv: ScanInvocation) -> Result<()> {
    let cwd = std::env::current_dir().context("current directory for policy resolution")?;

    if inv.hook_mode.is_some() && inv.staged {
        bail!("`--hook-mode` cannot be combined with `--staged`");
    }

    if let Some(tool) = inv.hook_mode {
        return run_hook_mode(tool, inv.post, inv.audit, inv.fail_on, &cwd, inv.path);
    }

    let fail_on_override = parse_fail_on(inv.fail_on.as_deref())?;
    let opts = ScanOptions {
        staged: inv.staged,
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

    let res = scan_path(&inv.path, opts).context("scan failed")?;
    if inv.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&res.to_json_report(ColorMode::Never))?
        );
    } else {
        print!(
            "{}",
            output::format_human_findings(&res.findings, inv.color_enabled, inv.verbose)
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
    if res.should_fail() {
        return Err(CliExit::silent(1).into());
    }
    Ok(())
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
    fail_on: Option<String>,
    cwd: &Path,
    path_arg: PathBuf,
) -> Result<()> {
    let mut stdin_raw = Vec::new();
    std::io::stdin().read_to_end(&mut stdin_raw)?;
    let stdin_str = String::from_utf8_lossy(&stdin_raw);
    let stdin_trim = stdin_str.trim();
    if stdin_trim.is_empty() {
        bail!("hook-mode requires hook JSON payload on stdin");
    }

    let hook_event = hook_event_from_stdin(stdin_trim, post);
    let repo_root = resolve_repo_root(cwd, path_arg.as_path());
    if audit {
        safety::require_project_policy(&repo_root, "scan --audit")?;
    }

    let (policy, _) = Policy::load_from_dir(&repo_root)?;
    let action_guard_config = action_guard_config_from_policy(&policy);

    if should_run_action_guard(post, audit)
        && let Some(guard_match) =
            shk_integrations::detect_dangerous_action_with_config(stdin_trim, &action_guard_config)?
    {
        return deny_hook(tool, hook_event, &guard_match.reason);
    }

    let (disp, body) = shk_integrations::stdin_to_hook_body(
        tool.integration_tool(),
        post,
        stdin_trim,
        cwd,
        &repo_root,
    )?;
    let fail_on_override = parse_fail_on(fail_on.as_deref())?;

    let opts = ScanOptions {
        staged: false,
        json: false,
        fail_on_override,
        use_pre_commit_threshold: matches!(tool, AiTool::Cursor) && !post,
        include_context: false,
        include_binary: false,
        follow_symlinks: false,
    };

    let res = scan_string(&repo_root, &disp, &body, opts).context("hook scan failed")?;

    if audit {
        emit_audit_hook(&repo_root, tool, post, &disp, &res)?;
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
        if res.findings.is_empty() {
            println!(
                "{}",
                hook_output::allow_stdout_for_event(tool, hook_event, None)
            );
        } else {
            let hint = format!(
                "shk: {} finding(s) in tool output — review before using ({} suppressed)",
                res.findings.len(),
                res.suppressed,
            );
            eprintln!("{hint}");
            println!(
                "{}",
                hook_output::allow_stdout_for_event(tool, hook_event, Some(&hint))
            );
        }
        return Ok(());
    }

    if res.should_fail() {
        return deny_hook(tool, hook_event, HOOK_DENY_REASON_DEFAULT);
    }

    println!(
        "{}",
        hook_output::allow_stdout_for_event(tool, hook_event, None)
    );
    Ok(())
}

fn action_guard_config_from_policy(policy: &Policy) -> shk_integrations::ActionGuardConfig {
    shk_integrations::ActionGuardConfig {
        enabled: policy.action_guard.enabled,
        profile: policy.action_guard.profile.clone(),
        allow: policy.action_guard.allow.clone(),
        deny: policy.action_guard.deny.clone(),
    }
}

fn should_run_action_guard(post: bool, audit: bool) -> bool {
    !post && !audit
}

fn deny_hook(tool: AiTool, event: hook_output::HookEvent, reason: &str) -> Result<()> {
    println!(
        "{}",
        hook_output::deny_stdout_for_event(tool, event, reason)
    );
    Err(CliExit::silent(2).into())
}

fn hook_event_from_stdin(stdin: &str, post: bool) -> hook_output::HookEvent {
    if post {
        return hook_output::HookEvent::PostToolUse;
    }

    let Ok(value) = serde_json::from_str::<serde_json::Value>(stdin) else {
        return hook_output::HookEvent::PreToolUse;
    };
    match value
        .get("hook_event_name")
        .and_then(serde_json::Value::as_str)
    {
        Some("PermissionRequest") => hook_output::HookEvent::PermissionRequest,
        _ => hook_output::HookEvent::PreToolUse,
    }
}

fn emit_audit_hook(
    repo_root: &Path,
    tool: AiTool,
    post: bool,
    disp: &str,
    res: &shk_core::scanner::ScanResult,
) -> Result<()> {
    let max_sev = res.max_severity().map(|s| s.as_str());
    audit_log::append_line(
        repo_root,
        serde_json::json!({
            "tool": tool.kebab_str(),
            "hook": if post {"post"} else {"pre"},
            "display_path": disp,
            "finding_count": res.findings.len(),
            "suppressed": res.suppressed,
            "max_severity": max_sev,
        }),
    )?;
    eprintln!(
        "{}",
        hook_output::audit_note(res.findings.len(), res.suppressed, max_sev),
    );
    Ok(())
}

fn fs_canonical_or_same(p: PathBuf) -> PathBuf {
    std::fs::canonicalize(&p).unwrap_or(p)
}

fn parse_fail_on(raw: Option<&str>) -> Result<Option<Severity>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    Severity::parse(raw).map(Some).ok_or_else(|| {
        anyhow::anyhow!(
            "invalid --fail-on severity `{raw}` (expected: info, low, medium, high, critical)"
        )
    })
}
