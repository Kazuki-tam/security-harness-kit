use crate::audit_log;
use crate::hook_output;
use crate::output;
use crate::safety;
use anyhow::{Context, Result, bail};
use shk_core::policy::{ColorMode, Severity};
use shk_core::scanner::{ScanOptions, scan_path, scan_string};
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::args::AiTool;

/// Flat `clap` flags for [`run`], grouped for readability at the CLI boundary.
#[derive(Clone, Debug)]
pub struct ScanInvocation {
    pub path: PathBuf,
    pub staged: bool,
    pub json: bool,
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

    let fail_on_override = inv.fail_on.as_deref().and_then(Severity::parse);
    let opts = ScanOptions {
        staged: inv.staged,
        json: inv.json,
        fail_on_override,
        use_pre_commit_threshold: inv.staged,
        include_context: false,
        include_binary: inv.include_binary,
        follow_symlinks: inv.follow_symlinks,
    };
    let res = scan_path(&inv.path, opts).context("scan failed")?;
    if inv.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&res.to_json_report(ColorMode::Never))?
        );
    } else {
        print!(
            "{}",
            output::format_human_findings(&res.findings, inv.color_enabled)
        );
        println!(
            "{}",
            output::format_scan_summary(res.max_severity(), res.exit_threshold, inv.color_enabled,)
        );
    }
    if res.should_fail() {
        std::process::exit(1);
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

    let repo_root = resolve_repo_root(cwd, path_arg.as_path());
    if audit {
        safety::require_project_policy(&repo_root, "scan --audit")?;
    }

    let (disp, body) = shk_integrations::stdin_to_hook_body(
        tool.integration_tool(),
        post,
        stdin_trim,
        cwd,
        &repo_root,
    )?;
    let fail_on_override = fail_on.as_deref().and_then(Severity::parse);

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
            hook_output::allow_stdout(
                tool,
                post,
                Some("shk audit: non-blocking (see .shk/audit.log)"),
            ),
        );
        return Ok(());
    }

    if post {
        if res.findings.is_empty() {
            println!("{}", hook_output::allow_stdout(tool, post, None));
        } else {
            let hint = format!(
                "shk: {} finding(s) in tool output — review before using ({} suppressed)",
                res.findings.len(),
                res.suppressed,
            );
            eprintln!("{hint}");
            println!("{}", hook_output::allow_stdout(tool, post, Some(&hint)));
        }
        return Ok(());
    }

    if res.should_fail() {
        println!("{}", hook_output::deny_stdout(tool));
        std::process::exit(2);
    }

    println!("{}", hook_output::allow_stdout(tool, false, None));
    Ok(())
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
