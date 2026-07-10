//! Structured APIs for the desktop app (no stdout parsing).

use crate::args::{AiTool, AuditReasonArg};
pub use crate::commands::audit::AuditReport;
use crate::commands::audit::{self, AuditInvocation};
use crate::commands::skills::{SkillTool, SkillsInstallArgs};
use crate::doctor::{
    ClaudePermissionsStatus, CodexConfigStatus, EnvStatus, IgnoreStatus,
    collect_claude_permissions_status, collect_codex_config_status, collect_env_status,
    collect_ignore_status, fix_ignore_patterns, has_shk_pre_commit, ignore_fix_target_statuses,
};
use crate::hooks::{
    ConfigureAiOptions, InstallAiOptions, configure_ai_with_summaries, install_ai_with_summaries,
    install_pre_commit,
};
use crate::npm_hardening;
use crate::policy_cmd;
use crate::safety;
use crate::workflow_hardening;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use shk_core::git;
use shk_integrations::{MANAGED_MARKER_JSON, MANAGED_MARKER_SH};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Desktop setup installs blocking scan hooks that append metadata-only block entries.
const DESKTOP_AI_HOOK_LOG_BLOCKED: bool = true;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AiSafetyAppliedStatus {
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

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectStatus {
    pub path: String,
    pub policy: PolicyStatus,
    pub git: GitStatus,
    pub hooks: HooksStatus,
    pub doctor: DoctorStatus,
    pub ai_safety_applied: AiSafetyAppliedStatus,
    pub npm_hardening: NpmHardeningStatusDto,
    pub skills: Vec<SkillStatusDto>,
    pub ignore_fix_targets: Vec<IgnoreFixTargetDto>,
    pub recommended_fixes: Vec<RecommendedFixDto>,
    pub cli_installed: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyStatus {
    pub exists: bool,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GitStatus {
    pub is_repo: bool,
    pub root: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HooksStatus {
    pub pre_commit: PreCommitStatus,
    pub ai_tools: Vec<AiHookToolStatus>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreCommitStatus {
    pub installed: bool,
    pub hook_path: Option<String>,
    pub is_git_repo: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AiHookToolStatus {
    pub tool: String,
    pub config_path: String,
    pub installed: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DoctorStatus {
    pub git_pre_commit: bool,
    pub ai_managed_hooks: bool,
    pub ignore_ok: bool,
    pub missing_ignore_patterns: Vec<String>,
    pub claude_deny_ok: bool,
    pub claude_sandbox_ok: bool,
    pub codex_config_ok: bool,
    pub env_applicable: bool,
    pub env_ok: bool,
    pub npm_ok: bool,
    pub workflows_applicable: bool,
    pub workflows_ok: bool,
    pub issues: Vec<DoctorIssue>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DoctorIssue {
    pub id: String,
    pub severity: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NpmHardeningStatusDto {
    pub has_projects: bool,
    pub ok: bool,
    pub settings_ok: bool,
    pub package_count: usize,
    pub missing_lockfiles: Vec<String>,
    pub ignore_scripts_ok: bool,
    pub age_gates_ok: bool,
    pub dependency_bot_cooldown_ok: bool,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillStatusDto {
    pub label: String,
    pub path: Option<String>,
    pub installed: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IgnoreFixTargetDto {
    pub name: String,
    pub exists: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecommendedFixDto {
    pub id: String,
    pub severity: String,
    pub message: String,
    pub requires_policy: bool,
    pub default_selected: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionResult {
    pub success: bool,
    pub message: String,
    pub details: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloneRepositoryResult {
    pub path: String,
}

pub fn clone_repository(
    remote_url: &str,
    destination_parent: &str,
) -> Result<CloneRepositoryResult> {
    let remote_url = validate_git_remote_url(remote_url)?;
    let parent = resolve_clone_parent(destination_parent)?;
    let repository_name = repository_name_from_remote(remote_url)?;
    let destination = parent.join(repository_name);

    safety::ensure_writable_path_allowed(&destination)?;
    safety::ensure_write_path_within(&parent, &destination)?;
    if destination.exists() {
        anyhow::bail!(
            "clone destination already exists: {}",
            destination.display()
        );
    }

    let status = Command::new("git")
        .arg("clone")
        .arg("--")
        .arg(remote_url)
        .arg(&destination)
        .current_dir(&parent)
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("failed to start git; install Git and ensure it is available on PATH")?;

    if !status.success() {
        anyhow::bail!(
            "Git clone failed. Check the repository URL, network connection, and Git credentials"
        );
    }

    let path = fs::canonicalize(&destination).unwrap_or(destination);
    Ok(CloneRepositoryResult {
        path: path.display().to_string(),
    })
}

fn validate_git_remote_url(remote_url: &str) -> Result<&str> {
    let remote_url = remote_url.trim();
    if remote_url.is_empty() {
        anyhow::bail!("repository URL is empty");
    }
    if remote_url.starts_with('-')
        || remote_url.chars().any(char::is_whitespace)
        || remote_url.contains(['\0', '\n', '\r'])
        || remote_url.contains(['?', '#'])
    {
        anyhow::bail!("repository URL is invalid");
    }

    let has_allowed_scheme = ["https://", "ssh://"]
        .iter()
        .any(|scheme| remote_url.starts_with(scheme));
    let is_scp_style = remote_url
        .split_once(':')
        .is_some_and(|(host, path)| host.contains('@') && !path.is_empty());
    if !has_allowed_scheme && !is_scp_style {
        anyhow::bail!("use an HTTPS or SSH repository URL");
    }

    if let Some(authority) = remote_url
        .strip_prefix("https://")
        .and_then(|rest| rest.split('/').next())
        && authority.contains('@')
    {
        anyhow::bail!("repository URLs containing credentials are not allowed");
    }

    Ok(remote_url)
}

fn resolve_clone_parent(path: &str) -> Result<PathBuf> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        anyhow::bail!("clone destination is empty");
    }
    let parent = PathBuf::from(trimmed);
    if !parent.is_dir() {
        anyhow::bail!("clone destination is not a directory: {}", parent.display());
    }
    let parent = fs::canonicalize(&parent).unwrap_or(parent);
    if parent.parent().is_none() {
        anyhow::bail!("cloning directly into a filesystem root is not allowed");
    }
    Ok(parent)
}

fn repository_name_from_remote(remote_url: &str) -> Result<&str> {
    let without_slash = remote_url.trim_end_matches('/');
    let name = without_slash
        .rsplit(['/', ':'])
        .next()
        .unwrap_or_default()
        .strip_suffix(".git")
        .unwrap_or_else(|| without_slash.rsplit(['/', ':']).next().unwrap_or_default());

    if name.is_empty() || name == "." || name == ".." || Path::new(name).components().count() != 1 {
        anyhow::bail!("repository URL does not contain a valid repository name");
    }
    Ok(name)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallAiHooksOptions {
    pub audit: bool,
    #[serde(default = "default_desktop_log_blocked")]
    pub log_blocked: bool,
    pub dry_run: bool,
    pub global: bool,
    pub tool: Option<String>,
    pub fail_closed: bool,
    pub apply_deny: bool,
    pub apply_sandbox: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitPolicyOptions {
    pub strict: bool,
    pub force: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallSkillsOptions {
    pub tool: Option<String>,
    pub global: bool,
    pub dry_run: bool,
    pub force: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FixDoctorIgnoreOptions {
    pub targets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplyRecommendedFixesOptions {
    pub fix_ids: Vec<String>,
    pub ignore_targets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplyNpmHardeningOptions {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplyAiHookSettingsOptions {
    pub scan_hooks_claude_code: bool,
    pub scan_hooks_cursor: bool,
    pub scan_hooks_codex: bool,
    /// Defaults to false for payloads from older desktop frontends.
    #[serde(default)]
    pub scan_hooks_copilot: bool,
    /// Defaults to false for payloads from older desktop frontends.
    #[serde(default)]
    pub scan_hooks_antigravity: bool,
    /// Defaults to false for payloads from older desktop frontends.
    #[serde(default)]
    pub scan_hooks_windsurf: bool,
    #[serde(default = "default_cursor_fail_closed")]
    pub cursor_fail_closed: bool,
    pub claude_deny: bool,
    pub claude_sandbox: bool,
    pub codex_sandbox: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditReportOptions {
    #[serde(default = "default_audit_limit")]
    pub limit: usize,
    pub since: Option<String>,
    pub tool: Option<String>,
    pub reason: Option<String>,
    #[serde(default)]
    pub hide_paths: bool,
}

fn default_audit_limit() -> usize {
    10
}

fn default_desktop_log_blocked() -> bool {
    DESKTOP_AI_HOOK_LOG_BLOCKED
}

fn default_cursor_fail_closed() -> bool {
    true
}

fn desktop_default_install_ai_hooks_options() -> InstallAiHooksOptions {
    InstallAiHooksOptions {
        audit: false,
        log_blocked: DESKTOP_AI_HOOK_LOG_BLOCKED,
        dry_run: false,
        global: false,
        tool: None,
        fail_closed: true,
        apply_deny: false,
        apply_sandbox: false,
    }
}

fn desktop_configure_ai_options(options: &ApplyAiHookSettingsOptions) -> ConfigureAiOptions {
    ConfigureAiOptions {
        audit: false,
        log_blocked: DESKTOP_AI_HOOK_LOG_BLOCKED,
        dry_run: false,
        global: false,
        fail_closed: options.cursor_fail_closed,
        scan_hooks_claude_code: options.scan_hooks_claude_code,
        scan_hooks_cursor: options.scan_hooks_cursor,
        scan_hooks_codex: options.scan_hooks_codex,
        scan_hooks_copilot: options.scan_hooks_copilot,
        scan_hooks_antigravity: options.scan_hooks_antigravity,
        scan_hooks_windsurf: options.scan_hooks_windsurf,
        claude_deny: options.claude_deny,
        claude_sandbox: options.claude_sandbox,
        codex_sandbox: options.codex_sandbox,
    }
}

fn audit_invocation(
    root: &Path,
    options: &AuditReportOptions,
    tool: Option<AiTool>,
    reason: Option<AuditReasonArg>,
) -> AuditInvocation {
    AuditInvocation {
        path: root.to_path_buf(),
        json: true,
        since: options.since.clone(),
        tool,
        reason,
        limit: options.limit,
        hide_paths: options.hide_paths,
    }
}

struct ProjectCheckStatus {
    git_pre_commit: bool,
    ai_managed_hooks: bool,
    scan_hooks_claude_code: bool,
    scan_hooks_cursor: bool,
    scan_hooks_codex: bool,
    scan_hooks_copilot: bool,
    scan_hooks_antigravity: bool,
    scan_hooks_windsurf: bool,
    ignore: IgnoreStatus,
    claude: ClaudePermissionsStatus,
    codex: CodexConfigStatus,
    env: EnvStatus,
    npm: npm_hardening::NpmHardeningStatus,
    workflows: Vec<workflow_hardening::WorkflowFileStatus>,
}

pub fn project_status(path: &str) -> Result<ProjectStatus> {
    let root = resolve_project_root(path)?;
    Ok(build_project_status(&root))
}

pub fn audit_report(path: &str, options: AuditReportOptions) -> Result<AuditReport> {
    let root = resolve_project_root(path)?;
    let tool = options
        .tool
        .as_deref()
        .map(parse_ai_tool)
        .transpose()
        .context("invalid audit tool filter")?;
    let reason = options
        .reason
        .as_deref()
        .map(parse_audit_reason)
        .transpose()
        .context("invalid audit reason filter")?;
    audit::build_audit_report(&root, &audit_invocation(&root, &options, tool, reason))
}

pub fn init_policy(path: &str, options: InitPolicyOptions) -> Result<ActionResult> {
    let root = resolve_project_root(path)?;
    ensure_desktop_project_root_allowed(&root)?;
    let policy_path = root.join("shk.toml");
    if policy_path.exists() && !options.force {
        return Ok(ActionResult {
            success: false,
            message: format!("{} already exists", policy_path.display()),
            details: vec![],
        });
    }
    policy_cmd::init(&root, options.strict, options.force)?;
    Ok(ActionResult {
        success: true,
        message: format!("Created {}", policy_path.display()),
        details: vec![],
    })
}

pub fn install_pre_commit_hook(path: &str) -> Result<ActionResult> {
    let root = resolve_project_root(path)?;
    ensure_desktop_project_root_allowed(&root)?;
    let repo_root = git::discover_repo_root(&root).context("not a git repository")?;
    safety::require_project_policy(&repo_root, "hooks install")?;
    install_pre_commit(&repo_root)?;
    Ok(ActionResult {
        success: true,
        message: format!("Installed pre-commit hook under {}", repo_root.display()),
        details: vec![],
    })
}

pub fn install_ai_hooks(path: &str, options: InstallAiHooksOptions) -> Result<ActionResult> {
    let root = resolve_project_root(path)?;
    ensure_desktop_project_root_allowed(&root)?;
    if options.global {
        anyhow::bail!("desktop setup does not support global AI hook installation");
    }
    if !options.dry_run {
        safety::require_project_policy(&root, "hooks install-ai")?;
    }
    let tool = options.tool.as_deref().map(parse_ai_tool).transpose()?;
    let summaries = install_ai_with_summaries(
        &root,
        tool,
        InstallAiOptions {
            audit: options.audit,
            log_blocked: options.log_blocked,
            dry_run: options.dry_run,
            global: options.global,
            fail_closed: options.fail_closed,
            apply_deny: options.apply_deny,
            apply_sandbox: options.apply_sandbox,
        },
    )?;
    Ok(ActionResult {
        success: true,
        message: if options.dry_run {
            "AI hook preview ready".to_string()
        } else {
            "AI hooks installed".to_string()
        },
        details: summaries,
    })
}

pub fn apply_ai_hook_settings(
    path: &str,
    options: ApplyAiHookSettingsOptions,
) -> Result<ActionResult> {
    let root = resolve_project_root(path)?;
    ensure_desktop_project_root_allowed(&root)?;
    safety::require_project_policy(&root, "hooks install-ai")?;
    let before = ai_safety_applied_from(&collect_project_check_status(&root));
    let summaries = configure_ai_with_summaries(&root, desktop_configure_ai_options(&options))?;
    let after = ai_safety_applied_from(&collect_project_check_status(&root));
    let message = if ai_safety_applied_matches(&before, &after) {
        "No AI editor safety changes were required".to_string()
    } else if ai_safety_fully_disabled(&after) && ai_safety_any_enabled(&before) {
        "AI editor safety settings removed".to_string()
    } else {
        "AI editor settings applied".to_string()
    };
    Ok(ActionResult {
        success: true,
        message,
        details: summaries,
    })
}

fn ai_safety_applied_matches(a: &AiSafetyAppliedStatus, b: &AiSafetyAppliedStatus) -> bool {
    a.scan_hooks_claude_code == b.scan_hooks_claude_code
        && a.scan_hooks_cursor == b.scan_hooks_cursor
        && a.scan_hooks_codex == b.scan_hooks_codex
        && a.scan_hooks_copilot == b.scan_hooks_copilot
        && a.scan_hooks_antigravity == b.scan_hooks_antigravity
        && a.scan_hooks_windsurf == b.scan_hooks_windsurf
        && a.claude_deny == b.claude_deny
        && a.claude_sandbox == b.claude_sandbox
        && a.codex_sandbox == b.codex_sandbox
}

fn ai_safety_fully_disabled(status: &AiSafetyAppliedStatus) -> bool {
    !status.scan_hooks_claude_code
        && !status.scan_hooks_cursor
        && !status.scan_hooks_codex
        && !status.scan_hooks_copilot
        && !status.scan_hooks_antigravity
        && !status.scan_hooks_windsurf
        && !status.claude_deny
        && !status.claude_sandbox
        && !status.codex_sandbox
}

fn ai_safety_any_enabled(status: &AiSafetyAppliedStatus) -> bool {
    !ai_safety_fully_disabled(status)
}

fn current_ai_hook_settings_options(root: &Path) -> ApplyAiHookSettingsOptions {
    let applied = ai_safety_applied_from(&collect_project_check_status(root));
    ApplyAiHookSettingsOptions {
        scan_hooks_claude_code: applied.scan_hooks_claude_code,
        scan_hooks_cursor: applied.scan_hooks_cursor,
        scan_hooks_codex: applied.scan_hooks_codex,
        scan_hooks_copilot: applied.scan_hooks_copilot,
        scan_hooks_antigravity: applied.scan_hooks_antigravity,
        scan_hooks_windsurf: applied.scan_hooks_windsurf,
        cursor_fail_closed: true,
        claude_deny: applied.claude_deny,
        claude_sandbox: applied.claude_sandbox,
        codex_sandbox: applied.codex_sandbox,
    }
}

pub fn apply_recommended_fixes(
    path: &str,
    options: ApplyRecommendedFixesOptions,
) -> Result<ActionResult> {
    let root = resolve_project_root(path)?;
    ensure_desktop_project_root_allowed(&root)?;
    if options.fix_ids.is_empty() {
        anyhow::bail!("at least one recommended fix must be selected");
    }

    let policy_exists = root.join("shk.toml").is_file();
    validate_recommended_fixes(&options, policy_exists)?;
    let mut details = Vec::new();
    let mut applied = 0usize;

    for fix_id in &options.fix_ids {
        let result = apply_recommended_fix(&root, fix_id, policy_exists, &options)?;
        if !result.details.is_empty() || result.success {
            details.push(format!("[{}] {}", fix_id, result.message));
            details.extend(result.details.into_iter().map(|line| format!("  {line}")));
            applied += 1;
        }
    }

    Ok(ActionResult {
        success: true,
        message: if applied == 0 {
            "No changes were required for the selected fixes".to_string()
        } else {
            format!("Applied {applied} recommended fix(es)")
        },
        details,
    })
}

fn validate_recommended_fixes(
    options: &ApplyRecommendedFixesOptions,
    policy_exists: bool,
) -> Result<()> {
    for fix_id in &options.fix_ids {
        match fix_id.as_str() {
            "ignore" => {
                if !policy_exists {
                    anyhow::bail!("ignore fix requires shk.toml");
                }
                if options.ignore_targets.is_empty() {
                    anyhow::bail!("ignore fix requires at least one target");
                }
            }
            "git_pre_commit" => {
                if !policy_exists {
                    anyhow::bail!("pre-commit fix requires shk.toml");
                }
            }
            "ai_hooks" => {
                if !policy_exists {
                    anyhow::bail!("AI hook fix requires shk.toml");
                }
            }
            "ai_claude_deny" => {
                if !policy_exists {
                    anyhow::bail!("Claude deny fix requires shk.toml");
                }
            }
            "ai_claude_sandbox" => {
                if !policy_exists {
                    anyhow::bail!("Claude sandbox fix requires shk.toml");
                }
            }
            "ai_codex_sandbox" => {
                if !policy_exists {
                    anyhow::bail!("Codex sandbox fix requires shk.toml");
                }
            }
            "workflows" => {
                if !policy_exists {
                    anyhow::bail!("workflows fix requires shk.toml");
                }
            }
            "npm_hardening" => {}
            other => anyhow::bail!("unknown recommended fix id: {other}"),
        }
    }
    Ok(())
}

fn apply_recommended_fix(
    root: &Path,
    fix_id: &str,
    policy_exists: bool,
    options: &ApplyRecommendedFixesOptions,
) -> Result<ActionResult> {
    match fix_id {
        "ignore" => {
            if !policy_exists {
                anyhow::bail!("ignore fix requires shk.toml");
            }
            fix_doctor_ignore(
                &root.display().to_string(),
                FixDoctorIgnoreOptions {
                    targets: options.ignore_targets.clone(),
                },
            )
        }
        "git_pre_commit" => {
            if !policy_exists {
                anyhow::bail!("pre-commit fix requires shk.toml");
            }
            install_pre_commit_hook(&root.display().to_string())
        }
        "ai_hooks" => {
            if !policy_exists {
                anyhow::bail!("AI hook fix requires shk.toml");
            }
            install_ai_hooks(
                &root.display().to_string(),
                desktop_default_install_ai_hooks_options(),
            )
        }
        "ai_claude_deny" => {
            if !policy_exists {
                anyhow::bail!("Claude deny fix requires shk.toml");
            }
            let mut ai_options = current_ai_hook_settings_options(root);
            ai_options.claude_deny = true;
            apply_ai_hook_settings(&root.display().to_string(), ai_options)
        }
        "ai_claude_sandbox" => {
            if !policy_exists {
                anyhow::bail!("Claude sandbox fix requires shk.toml");
            }
            let mut ai_options = current_ai_hook_settings_options(root);
            ai_options.claude_sandbox = true;
            apply_ai_hook_settings(&root.display().to_string(), ai_options)
        }
        "ai_codex_sandbox" => {
            if !policy_exists {
                anyhow::bail!("Codex sandbox fix requires shk.toml");
            }
            let mut ai_options = current_ai_hook_settings_options(root);
            ai_options.codex_sandbox = true;
            apply_ai_hook_settings(&root.display().to_string(), ai_options)
        }
        "workflows" => {
            if !policy_exists {
                anyhow::bail!("workflows fix requires shk.toml");
            }
            fix_doctor_workflows(&root.display().to_string())
        }
        "npm_hardening" => apply_npm_hardening(
            &root.display().to_string(),
            ApplyNpmHardeningOptions { enabled: true },
        ),
        other => anyhow::bail!("unknown recommended fix id: {other}"),
    }
}

pub fn fix_doctor_ignore(path: &str, options: FixDoctorIgnoreOptions) -> Result<ActionResult> {
    let root = resolve_project_root(path)?;
    ensure_desktop_project_root_allowed(&root)?;
    if options.targets.is_empty() {
        anyhow::bail!("at least one ignore fix target is required");
    }
    let result = fix_ignore_patterns(&root, &options.targets)?;
    if result.already_ok {
        return Ok(ActionResult {
            success: true,
            message: "Required ignore patterns are already present".to_string(),
            details: vec![],
        });
    }
    let total_patterns = result
        .updates
        .iter()
        .map(|update| update.appended.len())
        .sum::<usize>();
    let mut details = Vec::new();
    for update in &result.updates {
        details.push(format!("{}:", update.relative_path));
        for pat in &update.appended {
            details.push(format!("  + {pat}"));
        }
    }
    Ok(ActionResult {
        success: true,
        message: format!(
            "Appended {total_patterns} pattern(s) across {} file(s)",
            result.updates.len()
        ),
        details,
    })
}

pub fn fix_doctor_workflows(path: &str) -> Result<ActionResult> {
    let root = resolve_project_root(path)?;
    ensure_desktop_project_root_allowed(&root)?;
    safety::require_project_policy(&root, "doctor workflows --fix")?;

    let fixes = workflow_hardening::fix_all(&root)?;
    let total: usize = fixes.iter().map(|f| f.fixed_steps).sum();
    let details = fixes
        .iter()
        .map(|f| {
            format!(
                "{}: hardened {} checkout step(s)",
                f.relative_path, f.fixed_steps
            )
        })
        .collect();

    Ok(ActionResult {
        success: true,
        message: if total == 0 {
            "All actions/checkout steps already set persist-credentials: false".to_string()
        } else {
            format!("Hardened {total} checkout step(s)")
        },
        details,
    })
}

pub fn apply_npm_hardening(path: &str, options: ApplyNpmHardeningOptions) -> Result<ActionResult> {
    let root = resolve_project_root(path)?;
    ensure_desktop_project_root_allowed(&root)?;
    let before = npm_hardening::status(&root);
    if !npm_hardening_desktop_applicable(&before) {
        return Ok(ActionResult {
            success: true,
            message: "No package-manager project detected at the selected folder".to_string(),
            details: vec![],
        });
    }
    for path in before.apply_paths() {
        safety::ensure_writable_path_allowed(path)?;
    }
    if options.enabled {
        npm_hardening::apply(&root)?;
    } else {
        npm_hardening::unapply(&root)?;
    }
    let after = npm_hardening::status(&root);
    let settings_ok = npm_hardening_settings_ok(&after);
    let remaining = npm_auto_recommendations(&after);
    Ok(ActionResult {
        success: if options.enabled {
            settings_ok
        } else {
            !settings_ok
        },
        message: if !options.enabled {
            "npm supply-chain hardening removed".to_string()
        } else if settings_ok {
            "npm supply-chain hardening applied".to_string()
        } else {
            "Applied partial npm hardening; review remaining items".to_string()
        },
        details: remaining,
    })
}

pub fn install_skills(path: &str, options: InstallSkillsOptions) -> Result<ActionResult> {
    let root = resolve_project_root(path)?;
    ensure_desktop_project_root_allowed(&root)?;
    if options.global {
        anyhow::bail!("desktop setup does not support global skill installation");
    }
    if !options.dry_run {
        safety::require_project_policy(&root, "skills install")?;
    }
    let tool = options.tool.as_deref().map(parse_skill_tool).transpose()?;
    let details = crate::commands::skills::install_for(
        &root,
        SkillsInstallArgs {
            tool,
            global: options.global,
            dry_run: options.dry_run,
            force: options.force,
        },
    )?;
    Ok(ActionResult {
        success: true,
        message: if options.dry_run {
            "Skills install preview ready".to_string()
        } else {
            "Skills installed".to_string()
        },
        details,
    })
}

fn is_shk_in_path() -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir_contains_shk_executable(&dir)))
        .unwrap_or(false)
}

fn dir_contains_shk_executable(dir: &Path) -> bool {
    is_executable_file(&dir.join("shk")) || {
        #[cfg(windows)]
        {
            is_executable_file(&dir.join("shk.exe"))
        }
        #[cfg(not(windows))]
        {
            false
        }
    }
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    fs::metadata(path)
        .map(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(windows)]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

fn resolve_project_root(path: &str) -> Result<PathBuf> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        anyhow::bail!("project path is empty");
    }
    let p = PathBuf::from(trimmed);
    if !p.is_dir() {
        anyhow::bail!("project path is not a directory: {}", p.display());
    }
    Ok(fs::canonicalize(&p).unwrap_or(p))
}

fn ensure_desktop_project_root_allowed(root: &Path) -> Result<()> {
    if root.parent().is_none() {
        anyhow::bail!("desktop setup refuses to modify filesystem roots");
    }

    if let Some(home) = std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
        .or_else(dirs::home_dir)
        .and_then(|home| fs::canonicalize(home).ok())
        && fs::canonicalize(root)
            .map(|canonical_root| canonical_root == home)
            .unwrap_or(false)
    {
        anyhow::bail!("desktop setup refuses to modify the home directory as a project");
    }

    Ok(())
}

fn build_project_status(root: &Path) -> ProjectStatus {
    let policy_path = root.join("shk.toml");
    let git_root = git::discover_repo_root(root);
    let policy_exists = policy_path.is_file();
    let checks = collect_project_check_status(root);
    let recommended_fixes = build_recommended_fixes(&checks, policy_exists, git_root.is_some());
    ProjectStatus {
        path: root.display().to_string(),
        policy: PolicyStatus {
            exists: policy_exists,
            path: policy_path
                .is_file()
                .then(|| policy_path.display().to_string()),
        },
        git: GitStatus {
            is_repo: git_root.is_some(),
            root: git_root.as_ref().map(|p| p.display().to_string()),
        },
        hooks: build_hooks_status(root, git_root.as_deref()),
        doctor: build_doctor_status_from(&checks),
        ai_safety_applied: ai_safety_applied_from(&checks),
        npm_hardening: build_npm_status_from(&checks.npm),
        skills: build_skills_status(root),
        ignore_fix_targets: ignore_fix_target_statuses(root)
            .into_iter()
            .map(|entry| IgnoreFixTargetDto {
                name: entry.name,
                exists: entry.exists,
            })
            .collect(),
        recommended_fixes,
        cli_installed: is_shk_in_path(),
    }
}

fn collect_project_check_status(root: &Path) -> ProjectCheckStatus {
    let ai_tools = ai_tool_statuses(root, false);
    let scan_hooks_for = |tool: &str| {
        ai_tools
            .iter()
            .find(|entry| entry.tool == tool)
            .is_some_and(|entry| entry.installed)
    };
    ProjectCheckStatus {
        git_pre_commit: has_shk_pre_commit(root),
        ai_managed_hooks: has_all_managed_ai_hooks(root),
        scan_hooks_claude_code: scan_hooks_for("claude-code"),
        scan_hooks_cursor: scan_hooks_for("cursor"),
        scan_hooks_codex: scan_hooks_for("codex"),
        scan_hooks_copilot: scan_hooks_for("copilot"),
        scan_hooks_antigravity: scan_hooks_for("antigravity"),
        scan_hooks_windsurf: scan_hooks_for("windsurf"),
        ignore: collect_ignore_status(root),
        claude: collect_claude_permissions_status(root),
        codex: collect_codex_config_status(root),
        env: collect_env_status(root),
        npm: npm_hardening::status(root),
        workflows: workflow_hardening::scan_workflows(root),
    }
}

fn has_all_managed_ai_hooks(root: &Path) -> bool {
    let statuses = ai_tool_statuses(root, false);
    !statuses.is_empty() && statuses.iter().all(|status| status.installed)
}

fn build_hooks_status(root: &Path, git_root: Option<&Path>) -> HooksStatus {
    let pre_commit_path = git_root.map(|r| r.join(".git/hooks/pre-commit"));
    let pre_commit_installed = has_shk_pre_commit(root);
    HooksStatus {
        pre_commit: PreCommitStatus {
            installed: pre_commit_installed,
            hook_path: pre_commit_path.map(|p| p.display().to_string()),
            is_git_repo: git_root.is_some(),
        },
        ai_tools: ai_tool_statuses(root, false),
    }
}

fn ai_tool_statuses(root: &Path, global: bool) -> Vec<AiHookToolStatus> {
    [
        AiTool::ClaudeCode,
        AiTool::Codex,
        AiTool::Cursor,
        AiTool::Copilot,
        AiTool::Antigravity,
        AiTool::Windsurf,
    ]
    .into_iter()
    .filter_map(|tool| {
        let config_path = resolve_ai_config_path(tool, root, global).ok()?;
        let installed = config_path.is_file()
            && fs::read_to_string(&config_path)
                .map(|s| has_managed_hook_marker(tool, &s))
                .unwrap_or(false);
        Some(AiHookToolStatus {
            tool: tool.kebab_str().to_string(),
            config_path: config_path.display().to_string(),
            installed,
        })
    })
    .collect()
}

fn has_managed_hook_marker(tool: AiTool, content: &str) -> bool {
    content.contains(MANAGED_MARKER_JSON)
        || content.contains(MANAGED_MARKER_SH)
        || ((tool == AiTool::Copilot || tool == AiTool::Windsurf)
            && content.contains("shk scan")
            && content.contains(&format!("--hook-mode {}", tool.kebab_str())))
}

fn resolve_ai_config_path(tool: AiTool, root: &Path, global: bool) -> Result<PathBuf> {
    crate::hooks::resolve_ai_config_path(tool, root, global)
}

fn build_recommended_fixes(
    checks: &ProjectCheckStatus,
    policy_exists: bool,
    is_git_repo: bool,
) -> Vec<RecommendedFixDto> {
    let mut fixes = Vec::new();
    if policy_exists
        && checks.ignore.load_error.is_none()
        && !checks.ignore.missing_patterns.is_empty()
    {
        fixes.push(RecommendedFixDto {
            id: "ignore".into(),
            severity: "warn".into(),
            message: format!(
                "Append {} missing ignore pattern(s) to selected ignore files",
                checks.ignore.missing_patterns.len()
            ),
            requires_policy: true,
            default_selected: true,
        });
    }
    if policy_exists && is_git_repo && !checks.git_pre_commit {
        fixes.push(RecommendedFixDto {
            id: "git_pre_commit".into(),
            severity: "warn".into(),
            message: "Install Git pre-commit hook (shk scan --staged)".into(),
            requires_policy: true,
            default_selected: true,
        });
    }
    if policy_exists && !checks.ai_managed_hooks {
        fixes.push(RecommendedFixDto {
            id: "ai_hooks".into(),
            severity: "warn".into(),
            message: "Install managed AI scan hooks for Cursor, Claude Code, Codex, Copilot, Antigravity, and Windsurf"
                .into(),
            requires_policy: true,
            default_selected: true,
        });
    }
    if policy_exists && checks.claude.settings_exists && !checks.claude.deny_ok {
        fixes.push(RecommendedFixDto {
            id: "ai_claude_deny".into(),
            severity: "warn".into(),
            message: "Merge recommended Claude Code permissions.deny entries".into(),
            requires_policy: true,
            default_selected: true,
        });
    }
    if policy_exists && checks.claude.settings_exists && !checks.claude.sandbox_ok {
        fixes.push(RecommendedFixDto {
            id: "ai_claude_sandbox".into(),
            severity: "warn".into(),
            message: "Enable Claude Code project sandbox settings".into(),
            requires_policy: true,
            default_selected: true,
        });
    }
    if policy_exists
        && checks.codex.config_exists
        && (!checks.codex.sandbox_ok || !checks.codex.approval_ok)
    {
        fixes.push(RecommendedFixDto {
            id: "ai_codex_sandbox".into(),
            severity: "warn".into(),
            message: "Harden Codex config (sandbox_mode, approval_policy)".into(),
            requires_policy: true,
            default_selected: true,
        });
    }
    if policy_exists && checks.workflows.iter().any(|s| !s.ok()) {
        let flagged = checks.workflows.iter().filter(|s| !s.ok()).count();
        fixes.push(RecommendedFixDto {
            id: "workflows".into(),
            severity: "warn".into(),
            message: format!(
                "Add persist-credentials: false to actions/checkout in {flagged} workflow file(s)"
            ),
            requires_policy: true,
            default_selected: true,
        });
    }
    if npm_hardening_desktop_applicable(&checks.npm) && !npm_hardening_settings_ok(&checks.npm) {
        fixes.push(RecommendedFixDto {
            id: "npm_hardening".into(),
            severity: "info".into(),
            message: "Apply npm/package-manager supply-chain hardening".into(),
            requires_policy: false,
            default_selected: true,
        });
    }
    fixes
}

fn build_doctor_status_from(checks: &ProjectCheckStatus) -> DoctorStatus {
    let codex_config_ok =
        !checks.codex.config_exists || (checks.codex.sandbox_ok && checks.codex.approval_ok);

    let mut issues = Vec::new();
    if !checks.git_pre_commit {
        issues.push(DoctorIssue {
            id: "git_pre_commit".into(),
            severity: "warn".into(),
            message: "Git pre-commit hook is not installed".into(),
        });
    }
    if !checks.ai_managed_hooks {
        issues.push(DoctorIssue {
            id: "ai_hooks".into(),
            severity: "warn".into(),
            message: "AI managed hooks not found — install via Setup".into(),
        });
    }
    if let Some(err) = &checks.ignore.load_error {
        issues.push(DoctorIssue {
            id: "ignore_policy".into(),
            severity: "warn".into(),
            message: format!("Unable to load policy for ignore check: {err}"),
        });
    }
    for pat in &checks.ignore.missing_patterns {
        issues.push(DoctorIssue {
            id: format!("ignore:{pat}"),
            severity: "warn".into(),
            message: format!("Missing ignore pattern: {pat}"),
        });
    }
    if checks.claude.settings_exists && !checks.claude.deny_ok {
        issues.push(DoctorIssue {
            id: "ai_claude_deny".into(),
            severity: "warn".into(),
            message: "Claude Code permissions.deny entries are incomplete".into(),
        });
    }
    if checks.claude.settings_exists && !checks.claude.sandbox_ok {
        issues.push(DoctorIssue {
            id: "ai_claude_sandbox".into(),
            severity: "warn".into(),
            message: "Claude Code sandbox settings are incomplete".into(),
        });
    }
    if checks.codex.config_exists && !codex_config_ok {
        issues.push(DoctorIssue {
            id: "ai_codex_sandbox".into(),
            severity: "warn".into(),
            message: "Codex config needs sandbox or hook hardening".into(),
        });
    }
    for file in &checks.env.plaintext_env_files {
        issues.push(DoctorIssue {
            id: format!("env:{file}"),
            severity: "warn".into(),
            message: format!("Plaintext env file detected: {file}"),
        });
    }
    for file in &checks.env.mixed_env_files {
        issues.push(DoctorIssue {
            id: format!("env_mixed:{file}"),
            severity: "warn".into(),
            message: format!("Encrypted env file contains plaintext values: {file}"),
        });
    }
    for rec in npm_auto_recommendations(&checks.npm) {
        issues.push(DoctorIssue {
            id: "npm_hardening".into(),
            severity: "warn".into(),
            message: rec,
        });
    }
    for status in &checks.workflows {
        let flagged = status.findings().count();
        if flagged > 0 {
            issues.push(DoctorIssue {
                id: format!("workflows:{}", status.relative_path),
                severity: "warn".into(),
                message: format!(
                    "{}: {flagged} actions/checkout step(s) missing persist-credentials: false",
                    status.relative_path
                ),
            });
        }
    }
    for rec in npm_manual_recommendations(&checks.npm) {
        issues.push(DoctorIssue {
            id: "npm_hardening".into(),
            severity: "info".into(),
            message: rec,
        });
    }

    DoctorStatus {
        git_pre_commit: checks.git_pre_commit,
        ai_managed_hooks: checks.ai_managed_hooks,
        ignore_ok: checks.ignore.load_error.is_none() && checks.ignore.missing_patterns.is_empty(),
        missing_ignore_patterns: checks.ignore.missing_patterns.clone(),
        claude_deny_ok: !checks.claude.settings_exists || checks.claude.deny_ok,
        claude_sandbox_ok: !checks.claude.settings_exists || checks.claude.sandbox_ok,
        codex_config_ok,
        env_applicable: checks.env.has_env_files,
        env_ok: checks.env.plaintext_env_files.is_empty() && checks.env.mixed_env_files.is_empty(),
        npm_ok: npm_doctor_ok(&checks.npm),
        workflows_applicable: !checks.workflows.is_empty(),
        workflows_ok: checks.workflows.iter().all(|s| s.ok()),
        issues,
    }
}

fn ai_safety_applied_from(checks: &ProjectCheckStatus) -> AiSafetyAppliedStatus {
    AiSafetyAppliedStatus {
        scan_hooks_claude_code: checks.scan_hooks_claude_code,
        scan_hooks_cursor: checks.scan_hooks_cursor,
        scan_hooks_codex: checks.scan_hooks_codex,
        scan_hooks_copilot: checks.scan_hooks_copilot,
        scan_hooks_antigravity: checks.scan_hooks_antigravity,
        scan_hooks_windsurf: checks.scan_hooks_windsurf,
        claude_deny: checks.claude.settings_exists && checks.claude.deny_ok,
        claude_sandbox: checks.claude.settings_exists && checks.claude.sandbox_ok,
        codex_sandbox: checks.codex.config_exists
            && checks.codex.sandbox_ok
            && checks.codex.approval_ok,
    }
}

fn build_npm_status_from(status: &npm_hardening::NpmHardeningStatus) -> NpmHardeningStatusDto {
    let applicable = npm_hardening_desktop_applicable(status);
    NpmHardeningStatusDto {
        has_projects: applicable,
        ok: status.ok(),
        settings_ok: npm_hardening_settings_ok(status),
        package_count: status.package_dirs.len(),
        missing_lockfiles: status
            .package_dirs_without_lockfile
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
        ignore_scripts_ok: status.package_scripts_ok(),
        age_gates_ok: status.age_gates_ok(),
        dependency_bot_cooldown_ok: status.dependency_bot_cooldown_ok(),
        recommendations: if applicable {
            npm_auto_recommendations(status)
        } else {
            vec![]
        },
    }
}

fn npm_hardening_desktop_applicable(status: &npm_hardening::NpmHardeningStatus) -> bool {
    status.has_npm_projects() && status.root_project
}

fn npm_hardening_settings_ok(status: &npm_hardening::NpmHardeningStatus) -> bool {
    !status.has_npm_projects() || (status.package_scripts_ok() && status.age_gates_ok())
}

fn npm_doctor_ok(status: &npm_hardening::NpmHardeningStatus) -> bool {
    if !status.has_npm_projects() {
        return true;
    }
    if npm_hardening_desktop_applicable(status) {
        npm_hardening_settings_ok(status)
    } else {
        status.ok()
    }
}

fn npm_auto_recommendations(status: &npm_hardening::NpmHardeningStatus) -> Vec<String> {
    if !status.has_npm_projects() {
        return vec![];
    }
    let mut recs = Vec::new();
    if !status.package_scripts_ok() {
        recs.push(format!(
            "Add ignore-scripts=true to {}",
            status.npmrc_path.display()
        ));
    }
    if !status.age_gates_ok() {
        recs.push("Configure package-manager release age gates".into());
    }
    recs
}

fn npm_manual_recommendations(status: &npm_hardening::NpmHardeningStatus) -> Vec<String> {
    if !status.has_npm_projects() {
        return vec![];
    }
    let mut recs = Vec::new();
    if !status.package_dirs_without_lockfile.is_empty() {
        recs.push("Commit lockfiles for package.json directories".into());
    }
    if !status.dependency_bot_cooldown_ok() {
        recs.push("Add Dependabot or Renovate cooldown (7 days)".into());
    }
    recs
}

fn build_skills_status(root: &Path) -> Vec<SkillStatusDto> {
    crate::commands::skills::status_entries_for(root)
        .into_iter()
        .map(|entry| SkillStatusDto {
            label: entry.label.to_string(),
            path: entry.path.map(|p| p.display().to_string()),
            installed: entry.installed,
        })
        .collect()
}

fn parse_ai_tool(value: &str) -> Result<AiTool> {
    match value {
        "claude-code" => Ok(AiTool::ClaudeCode),
        "codex" => Ok(AiTool::Codex),
        "copilot" => Ok(AiTool::Copilot),
        "cursor" => Ok(AiTool::Cursor),
        "antigravity" => Ok(AiTool::Antigravity),
        "windsurf" => Ok(AiTool::Windsurf),
        other => anyhow::bail!("unknown AI tool: {other}"),
    }
}

fn parse_audit_reason(value: &str) -> Result<AuditReasonArg> {
    match value {
        "blocked" => Ok(AuditReasonArg::Blocked),
        "finding-threshold" => Ok(AuditReasonArg::FindingThreshold),
        "action-guard" => Ok(AuditReasonArg::ActionGuard),
        other => anyhow::bail!("unknown audit reason filter: {other}"),
    }
}

fn parse_skill_tool(value: &str) -> Result<SkillTool> {
    match value {
        "claude-code" => Ok(SkillTool::ClaudeCode),
        "codex" => Ok(SkillTool::Codex),
        "copilot" => Ok(SkillTool::Copilot),
        "cursor" => Ok(SkillTool::Cursor),
        "antigravity" => Ok(SkillTool::Antigravity),
        "windsurf" => Ok(SkillTool::Windsurf),
        "all" => Ok(SkillTool::All),
        other => anyhow::bail!("unknown skill tool: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn clone_remote_validation_accepts_https_and_ssh() {
        assert_eq!(
            validate_git_remote_url("https://github.com/example/project.git").unwrap(),
            "https://github.com/example/project.git"
        );
        assert_eq!(
            validate_git_remote_url("git@github.com:example/project.git").unwrap(),
            "git@github.com:example/project.git"
        );
    }

    #[test]
    fn clone_remote_validation_rejects_local_and_option_urls() {
        for remote in [
            "",
            "--upload-pack=evil",
            "file:///tmp/repo.git",
            "../repo",
            "http://example.com/repo.git",
            "git://example.com/repo.git",
            "https://user:token@example.com/repo.git",
            "https://example.com/repo.git?token=secret",
        ] {
            assert!(validate_git_remote_url(remote).is_err(), "{remote}");
        }
    }

    #[test]
    fn clone_repository_name_is_derived_from_remote() {
        assert_eq!(
            repository_name_from_remote("https://github.com/example/project.git").unwrap(),
            "project"
        );
        assert_eq!(
            repository_name_from_remote("git@github.com:example/project").unwrap(),
            "project"
        );
    }

    #[test]
    fn clone_parent_must_be_an_existing_directory() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");
        assert!(resolve_clone_parent(missing.to_str().unwrap()).is_err());
        assert_eq!(
            resolve_clone_parent(dir.path().to_str().unwrap()).unwrap(),
            fs::canonicalize(dir.path()).unwrap()
        );
    }

    #[test]
    fn doctor_status_reports_mixed_encrypted_env_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join(".env"),
            "DOTENV_PUBLIC_KEY=pub\nTOKEN=encrypted:ciphertext\nDEBUG_TOKEN=plain\n",
        )
        .unwrap();

        let checks = collect_project_check_status(dir.path());
        let status = build_doctor_status_from(&checks);

        assert!(!status.env_ok);
        assert!(status.env_applicable);
        assert!(
            status
                .issues
                .iter()
                .any(|issue| issue.id == "env_mixed:.env"
                    && issue
                        .message
                        .contains("Encrypted env file contains plaintext values")),
            "{:?}",
            status.issues
        );
    }

    #[test]
    fn doctor_status_skips_env_check_when_no_env_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("README.md"), "demo\n").unwrap();

        let checks = collect_project_check_status(dir.path());
        let status = build_doctor_status_from(&checks);

        assert!(!status.env_applicable);
        assert!(status.env_ok);
        assert!(
            !status
                .issues
                .iter()
                .any(|issue| issue.id.starts_with("env:") || issue.id.starts_with("env_mixed:")),
            "{:?}",
            status.issues
        );
    }

    #[test]
    fn doctor_status_reports_ignore_policy_load_errors() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("shk.toml"), "[scan\nbroken = true\n").unwrap();

        let status = build_project_status(dir.path());

        assert!(!status.doctor.ignore_ok, "{status:?}");
        assert!(
            status
                .doctor
                .issues
                .iter()
                .any(|issue| issue.id == "ignore_policy"),
            "{:?}",
            status.doctor.issues
        );
    }

    #[test]
    fn desktop_ai_hooks_reject_global_install() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("shk.toml"), "").unwrap();

        let err = install_ai_hooks(
            dir.path().to_str().unwrap(),
            InstallAiHooksOptions {
                audit: false,
                log_blocked: false,
                dry_run: true,
                global: true,
                tool: Some("cursor".to_string()),
                fail_closed: false,
                apply_deny: true,
                apply_sandbox: true,
            },
        )
        .unwrap_err();

        assert!(err.to_string().contains("does not support global"), "{err}");
    }

    #[test]
    fn desktop_skills_reject_global_install() {
        let dir = tempfile::tempdir().unwrap();

        let err = install_skills(
            dir.path().to_str().unwrap(),
            InstallSkillsOptions {
                tool: None,
                global: true,
                dry_run: true,
                force: false,
            },
        )
        .unwrap_err();

        assert!(err.to_string().contains("does not support global"), "{err}");
    }

    #[test]
    fn desktop_skills_require_project_policy_for_install() {
        let dir = tempfile::tempdir().unwrap();

        let err = install_skills(
            dir.path().to_str().unwrap(),
            InstallSkillsOptions {
                tool: None,
                global: false,
                dry_run: false,
                force: true,
            },
        )
        .unwrap_err();

        assert!(
            err.to_string().contains("requires a project shk.toml"),
            "{err}"
        );
        assert!(!dir.path().join(".claude").exists());
        assert!(!dir.path().join(".agents").exists());
    }

    #[test]
    fn doctor_status_reports_and_fixes_workflow_checkout() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("shk.toml"), "").unwrap();
        let workflows = dir.path().join(".github/workflows");
        fs::create_dir_all(&workflows).unwrap();
        fs::write(
            workflows.join("ci.yml"),
            "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v6\n",
        )
        .unwrap();

        let before = build_project_status(dir.path());
        assert!(before.doctor.workflows_applicable, "{before:?}");
        assert!(!before.doctor.workflows_ok, "{before:?}");
        assert!(
            before
                .doctor
                .issues
                .iter()
                .any(|i| i.id == "workflows:.github/workflows/ci.yml"),
            "{:?}",
            before.doctor.issues
        );
        assert!(
            before.recommended_fixes.iter().any(|f| f.id == "workflows"),
            "{:?}",
            before.recommended_fixes
        );

        let result = fix_doctor_workflows(dir.path().to_str().unwrap()).unwrap();
        assert!(result.success, "{result:?}");

        let after = build_project_status(dir.path());
        assert!(after.doctor.workflows_ok, "{after:?}");
        assert!(
            !after.recommended_fixes.iter().any(|f| f.id == "workflows"),
            "{:?}",
            after.recommended_fixes
        );
        let contents = fs::read_to_string(workflows.join("ci.yml")).unwrap();
        assert!(
            contents.contains("persist-credentials: false"),
            "{contents}"
        );
    }

    #[test]
    fn doctor_status_skips_workflows_when_no_checkout() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("shk.toml"), "").unwrap();

        let status = build_project_status(dir.path());
        assert!(!status.doctor.workflows_applicable, "{status:?}");
        assert!(status.doctor.workflows_ok, "{status:?}");
    }

    #[test]
    fn desktop_fix_doctor_ignore_appends_missing_patterns() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("shk.toml"), "[doctor.ignore]\n").unwrap();

        let result = fix_doctor_ignore(
            dir.path().to_str().unwrap(),
            FixDoctorIgnoreOptions {
                targets: vec![".gitignore".to_string()],
            },
        )
        .unwrap();
        assert!(result.success, "{result:?}");
        assert!(!result.details.is_empty(), "{result:?}");

        let status = build_project_status(dir.path());
        assert!(status.doctor.ignore_ok);
        assert!(status.doctor.missing_ignore_patterns.is_empty());
    }

    #[test]
    fn desktop_fix_doctor_ignore_supports_selected_targets() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("shk.toml"), "[doctor.ignore]\n").unwrap();

        let result = fix_doctor_ignore(
            dir.path().to_str().unwrap(),
            FixDoctorIgnoreOptions {
                targets: vec![
                    ".cursorignore".to_string(),
                    ".cursorindexingignore".to_string(),
                ],
            },
        )
        .unwrap();
        assert!(result.success, "{result:?}");
        assert!(
            result.details.iter().any(|line| line == ".cursorignore:"),
            "{result:?}"
        );
        assert!(
            result
                .details
                .iter()
                .any(|line| line == ".cursorindexingignore:"),
            "{result:?}"
        );
        assert!(!dir.path().join(".gitignore").exists());

        let status = build_project_status(dir.path());
        assert!(status.doctor.ignore_ok);
        assert_eq!(status.ignore_fix_targets.len(), 10);
    }

    #[test]
    fn desktop_recommended_fixes_validate_before_mutating() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("shk.toml"), "[doctor.ignore]\n").unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"name":"demo","packageManager":"npm@10.0.0"}"#,
        )
        .unwrap();
        fs::write(dir.path().join("package-lock.json"), "{}").unwrap();

        let err = apply_recommended_fixes(
            dir.path().to_str().unwrap(),
            ApplyRecommendedFixesOptions {
                fix_ids: vec!["npm_hardening".to_string(), "ignore".to_string()],
                ignore_targets: vec![],
            },
        )
        .unwrap_err();

        assert!(err.to_string().contains("ignore fix requires"), "{err}");
        assert!(
            !dir.path().join(".npmrc").exists(),
            "prevalidation should prevent partial npm hardening writes"
        );
    }

    #[test]
    fn desktop_npm_hardening_marks_auto_settings_ready() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"name":"demo","packageManager":"npm@10.0.0"}"#,
        )
        .unwrap();
        fs::write(dir.path().join("package-lock.json"), "{}").unwrap();

        let result = apply_npm_hardening(
            dir.path().to_str().unwrap(),
            ApplyNpmHardeningOptions { enabled: true },
        )
        .unwrap();
        assert!(result.success, "{result:?}");
        assert_eq!(result.message, "npm supply-chain hardening applied");
        assert!(result.details.is_empty(), "{result:?}");

        let status = build_project_status(dir.path());
        assert!(status.npm_hardening.settings_ok, "{status:?}");
        assert!(!status.npm_hardening.ok, "{status:?}");
        assert!(
            status.npm_hardening.recommendations.is_empty(),
            "{status:?}"
        );
        assert!(status.doctor.npm_ok, "{status:?}");
        assert!(
            status
                .doctor
                .issues
                .iter()
                .any(|issue| issue.message.contains("Dependabot")
                    || issue.message.contains("Renovate")),
            "{status:?}"
        );
        assert!(
            !status
                .recommended_fixes
                .iter()
                .any(|fix| fix.id == "npm_hardening"),
            "{status:?}"
        );
    }

    #[test]
    fn desktop_npm_hardening_can_be_removed() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"name":"demo","packageManager":"pnpm@11.0.0"}"#,
        )
        .unwrap();

        apply_npm_hardening(
            dir.path().to_str().unwrap(),
            ApplyNpmHardeningOptions { enabled: true },
        )
        .unwrap();
        let result = apply_npm_hardening(
            dir.path().to_str().unwrap(),
            ApplyNpmHardeningOptions { enabled: false },
        )
        .unwrap();

        assert!(result.success, "{result:?}");
        let status = build_project_status(dir.path());
        assert!(!status.npm_hardening.settings_ok, "{status:?}");
        assert!(
            status
                .recommended_fixes
                .iter()
                .any(|fix| fix.id == "npm_hardening"),
            "{status:?}"
        );
    }

    #[test]
    fn desktop_npm_hardening_hides_nested_pnpm_from_repo_root() {
        let dir = tempfile::tempdir().unwrap();
        let app = dir.path().join("apps/web");
        fs::create_dir_all(&app).unwrap();
        fs::write(
            app.join("package.json"),
            r#"{"name":"web","packageManager":"pnpm@11.0.0"}"#,
        )
        .unwrap();
        fs::write(
            app.join("pnpm-workspace.yaml"),
            "onlyBuiltDependencies:\n  - esbuild\n",
        )
        .unwrap();

        let status = build_project_status(dir.path());
        assert!(!status.npm_hardening.has_projects, "{status:?}");
        assert!(!status.npm_hardening.settings_ok, "{status:?}");
        assert!(!status.npm_hardening.age_gates_ok, "{status:?}");
        assert!(
            status.npm_hardening.recommendations.is_empty(),
            "{status:?}"
        );
        assert!(
            !status
                .recommended_fixes
                .iter()
                .any(|fix| fix.id == "npm_hardening"),
            "{status:?}"
        );
    }

    #[test]
    fn desktop_claude_sandbox_is_recommended_and_applied() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("shk.toml"), "").unwrap();
        fs::create_dir_all(dir.path().join(".claude")).unwrap();
        fs::write(dir.path().join(".claude/settings.json"), "{}").unwrap();

        let before = build_project_status(dir.path());
        assert!(!before.doctor.claude_sandbox_ok, "{before:?}");
        assert!(
            before
                .recommended_fixes
                .iter()
                .any(|fix| fix.id == "ai_claude_sandbox"),
            "{before:?}"
        );

        let result = install_ai_hooks(
            dir.path().to_str().unwrap(),
            InstallAiHooksOptions {
                audit: false,
                log_blocked: false,
                dry_run: false,
                global: false,
                tool: Some("claude-code".to_string()),
                fail_closed: false,
                apply_deny: false,
                apply_sandbox: true,
            },
        )
        .unwrap();

        assert!(result.success, "{result:?}");
        let after = build_project_status(dir.path());
        assert!(after.doctor.claude_sandbox_ok, "{after:?}");
    }

    #[test]
    fn desktop_ai_hooks_are_recommended_when_only_one_tool_is_installed() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("shk.toml"), "").unwrap();
        fs::create_dir_all(dir.path().join(".claude")).unwrap();
        fs::write(
            dir.path().join(".claude/settings.json"),
            r#"{"hooks":{"PreToolUse":[{"_shk_managed":true}]}}"#,
        )
        .unwrap();

        let status = build_project_status(dir.path());
        assert!(!status.doctor.ai_managed_hooks, "{status:?}");
        assert!(
            status
                .recommended_fixes
                .iter()
                .any(|fix| fix.id == "ai_hooks"),
            "{status:?}"
        );
    }

    #[test]
    fn desktop_recommended_claude_deny_does_not_install_scan_hooks() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("shk.toml"), "").unwrap();
        fs::create_dir_all(dir.path().join(".claude")).unwrap();
        fs::write(dir.path().join(".claude/settings.json"), "{}").unwrap();

        let result = apply_recommended_fixes(
            dir.path().to_str().unwrap(),
            ApplyRecommendedFixesOptions {
                fix_ids: vec!["ai_claude_deny".to_string()],
                ignore_targets: vec![],
            },
        )
        .unwrap();

        assert!(result.success, "{result:?}");
        let settings = fs::read_to_string(dir.path().join(".claude/settings.json")).unwrap();
        assert!(settings.contains("\"permissions\""), "{settings}");
        assert!(!settings.contains("_shk_managed"), "{settings}");
    }

    #[test]
    fn desktop_recommended_claude_deny_preserves_existing_scan_hooks() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("shk.toml"), "").unwrap();
        fs::create_dir_all(dir.path().join(".claude")).unwrap();
        fs::write(
            dir.path().join(".claude/settings.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "hooks": {
                    "PreToolUse": [{
                        "_shk_managed": true,
                        "matcher": "Read",
                        "hooks": [{ "type": "command", "command": "shk scan --hook-mode claude-code" }]
                    }]
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let result = apply_recommended_fixes(
            dir.path().to_str().unwrap(),
            ApplyRecommendedFixesOptions {
                fix_ids: vec!["ai_claude_deny".to_string()],
                ignore_targets: vec![],
            },
        )
        .unwrap();

        assert!(result.success, "{result:?}");
        let settings = fs::read_to_string(dir.path().join(".claude/settings.json")).unwrap();
        assert!(settings.contains("\"permissions\""), "{settings}");
        assert!(
            settings.contains("shk scan --hook-mode claude-code"),
            "{settings}"
        );
    }

    #[test]
    fn desktop_ai_hook_settings_sync_to_selected_state() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("shk.toml"), "").unwrap();
        fs::create_dir_all(dir.path().join(".claude")).unwrap();
        fs::write(
            dir.path().join(".claude/settings.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "hooks": {
                    "PreToolUse": [{
                        "_shk_managed": true,
                        "matcher": "Read",
                        "hooks": [{ "type": "command", "command": "shk scan --hook-mode claude-code" }]
                    }]
                },
                "permissions": {
                    "deny": ["Bash(rm -rf *)"]
                },
                "sandbox": {
                    "enabled": true,
                    "failIfUnavailable": true,
                    "allowUnsandboxedCommands": false,
                    "filesystem": {
                        "denyRead": ["~/"],
                        "allowRead": ["."]
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let result = apply_ai_hook_settings(
            dir.path().to_str().unwrap(),
            ApplyAiHookSettingsOptions {
                scan_hooks_claude_code: false,
                scan_hooks_cursor: false,
                scan_hooks_antigravity: false,
                scan_hooks_windsurf: false,
                scan_hooks_codex: false,
                scan_hooks_copilot: false,
                cursor_fail_closed: true,
                claude_deny: false,
                claude_sandbox: false,
                codex_sandbox: false,
            },
        )
        .unwrap();
        assert_eq!(result.message, "AI editor safety settings removed");

        let settings = fs::read_to_string(dir.path().join(".claude/settings.json")).unwrap();
        assert!(
            !settings.contains("shk scan --hook-mode claude-code"),
            "{settings}"
        );
        assert!(settings.contains("Bash(rm -rf *)"), "{settings}");
        assert!(!settings.contains("allowUnsandboxedCommands"), "{settings}");
    }

    #[cfg(unix)]
    #[test]
    fn desktop_setup_rejects_filesystem_root() {
        let err = init_policy(
            "/",
            InitPolicyOptions {
                strict: false,
                force: false,
            },
        )
        .unwrap_err();

        assert!(err.to_string().contains("filesystem roots"), "{err}");
    }

    #[test]
    fn desktop_apply_ai_hook_settings_installs_log_blocked_scan_hooks() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("shk.toml"), "").unwrap();

        let result = apply_ai_hook_settings(
            dir.path().to_str().unwrap(),
            ApplyAiHookSettingsOptions {
                scan_hooks_claude_code: true,
                scan_hooks_cursor: false,
                scan_hooks_antigravity: false,
                scan_hooks_windsurf: false,
                scan_hooks_codex: false,
                scan_hooks_copilot: false,
                cursor_fail_closed: true,
                claude_deny: false,
                claude_sandbox: false,
                codex_sandbox: false,
            },
        )
        .unwrap();
        assert!(result.success, "{result:?}");

        let settings = fs::read_to_string(dir.path().join(".claude/settings.json")).unwrap();
        assert!(
            settings.contains("--log-blocked"),
            "desktop setup should install log-blocked hooks by default: {settings}"
        );
    }

    #[test]
    fn desktop_ai_managed_hooks_require_all_supported_tools() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".claude")).unwrap();
        fs::write(
            dir.path().join(".claude/settings.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "hooks": {
                    "PreToolUse": [{
                        "_shk_managed": true,
                        "hooks": [{ "type": "command", "command": "shk scan --hook-mode claude-code" }]
                    }]
                }
            }))
            .unwrap(),
        )
        .unwrap();
        fs::create_dir_all(dir.path().join(".cursor")).unwrap();
        fs::write(
            dir.path().join(".cursor/hooks.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "version": 1,
                "hooks": {
                    "beforeShellExecution": [{
                        "_shk_managed": true,
                        "command": "shk scan --hook-mode cursor"
                    }]
                }
            }))
            .unwrap(),
        )
        .unwrap();
        fs::create_dir_all(dir.path().join(".codex")).unwrap();
        fs::write(
            dir.path().join(".codex/config.toml"),
            "# shk-managed-start\n[[hooks.PreToolUse]]\ncommand = 'shk scan --hook-mode codex'\n# shk-managed-end\n",
        )
        .unwrap();
        fs::create_dir_all(dir.path().join(".agents")).unwrap();
        fs::write(
            dir.path().join(".agents/hooks.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "shk-security": {
                    "PreToolUse": [{
                        "_shk_managed": true,
                        "hooks": [{ "type": "command", "command": "shk scan --hook-mode antigravity" }]
                    }]
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let checks = collect_project_check_status(dir.path());

        assert!(!checks.ai_managed_hooks);
        assert!(!checks.scan_hooks_copilot);
        assert!(!checks.scan_hooks_windsurf);
    }

    #[test]
    fn desktop_apply_ai_hook_settings_installs_windsurf_toggle() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("shk.toml"), "").unwrap();

        let result = apply_ai_hook_settings(
            dir.path().to_str().unwrap(),
            ApplyAiHookSettingsOptions {
                scan_hooks_claude_code: false,
                scan_hooks_cursor: false,
                scan_hooks_antigravity: false,
                scan_hooks_windsurf: true,
                scan_hooks_codex: false,
                scan_hooks_copilot: false,
                cursor_fail_closed: true,
                claude_deny: false,
                claude_sandbox: false,
                codex_sandbox: false,
            },
        )
        .unwrap();
        assert!(result.success, "{result:?}");

        let hooks = fs::read_to_string(dir.path().join(".windsurf/hooks.json")).unwrap();
        assert!(hooks.contains("--hook-mode windsurf"), "{hooks}");
        assert!(hooks.contains("--log-blocked"), "{hooks}");
        assert!(hooks.contains("pre_write_code"), "{hooks}");

        let status = build_project_status(dir.path());
        assert!(status.ai_safety_applied.scan_hooks_windsurf);
        assert!(
            status
                .hooks
                .ai_tools
                .iter()
                .any(|tool| tool.tool == "windsurf" && tool.installed),
            "{:?}",
            status.hooks.ai_tools
        );
    }

    #[test]
    fn desktop_apply_ai_hook_settings_upgrades_legacy_hooks() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("shk.toml"), "").unwrap();
        fs::create_dir_all(dir.path().join(".claude")).unwrap();
        fs::write(
            dir.path().join(".claude/settings.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "hooks": {
                    "PreToolUse": [{
                        "_shk_managed": true,
                        "matcher": "Read",
                        "hooks": [{ "type": "command", "command": "shk scan --hook-mode claude-code" }]
                    }]
                }
            }))
            .unwrap(),
        )
        .unwrap();

        apply_ai_hook_settings(
            dir.path().to_str().unwrap(),
            ApplyAiHookSettingsOptions {
                scan_hooks_claude_code: true,
                scan_hooks_cursor: false,
                scan_hooks_antigravity: false,
                scan_hooks_windsurf: false,
                scan_hooks_codex: false,
                scan_hooks_copilot: false,
                cursor_fail_closed: true,
                claude_deny: false,
                claude_sandbox: false,
                codex_sandbox: false,
            },
        )
        .unwrap();

        let settings = fs::read_to_string(dir.path().join(".claude/settings.json")).unwrap();
        assert!(
            settings.contains("--log-blocked"),
            "legacy hooks should be upgraded to log-blocked: {settings}"
        );
    }

    #[test]
    fn desktop_default_install_ai_hooks_options_enable_log_blocked() {
        let opts = desktop_default_install_ai_hooks_options();
        assert!(opts.log_blocked);
        assert!(!opts.audit);
        assert!(opts.fail_closed);
    }

    #[test]
    fn desktop_configure_ai_options_enable_log_blocked() {
        let opts = desktop_configure_ai_options(&ApplyAiHookSettingsOptions {
            scan_hooks_claude_code: true,
            scan_hooks_cursor: false,
            scan_hooks_antigravity: false,
            scan_hooks_windsurf: true,
            scan_hooks_codex: false,
            scan_hooks_copilot: false,
            cursor_fail_closed: true,
            claude_deny: false,
            claude_sandbox: false,
            codex_sandbox: false,
        });
        assert!(opts.log_blocked);
        assert!(!opts.audit);
        assert!(opts.fail_closed);
        assert!(opts.scan_hooks_windsurf);
    }

    #[test]
    fn desktop_cursor_fail_closed_is_independent_from_codex_sandbox() {
        let opts = desktop_configure_ai_options(&ApplyAiHookSettingsOptions {
            scan_hooks_claude_code: false,
            scan_hooks_cursor: true,
            scan_hooks_antigravity: false,
            scan_hooks_windsurf: false,
            scan_hooks_codex: false,
            scan_hooks_copilot: false,
            cursor_fail_closed: true,
            claude_deny: false,
            claude_sandbox: false,
            codex_sandbox: false,
        });

        assert!(opts.scan_hooks_cursor);
        assert!(!opts.codex_sandbox);
        assert!(opts.fail_closed);
    }

    #[test]
    fn desktop_install_ai_hooks_options_default_log_blocked() {
        let opts: InstallAiHooksOptions = serde_json::from_str(
            r#"{
                "audit": false,
                "dryRun": false,
                "global": false,
                "failClosed": false,
                "applyDeny": false,
                "applySandbox": false
            }"#,
        )
        .unwrap();
        assert!(opts.log_blocked);
    }

    #[cfg(unix)]
    #[test]
    fn desktop_cli_detection_requires_executable_shk_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let shk = dir.path().join("shk");
        fs::write(&shk, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&shk, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(!dir_contains_shk_executable(dir.path()));

        fs::set_permissions(&shk, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(dir_contains_shk_executable(dir.path()));
    }

    #[test]
    fn desktop_audit_report_when_log_missing() {
        let dir = tempfile::tempdir().unwrap();
        let report = audit_report(
            dir.path().to_str().unwrap(),
            AuditReportOptions {
                limit: 10,
                since: None,
                tool: None,
                reason: None,
                hide_paths: false,
            },
        )
        .unwrap();

        assert!(!report.log_exists);
        assert_eq!(report.summary.total_entries, 0);
        assert_eq!(report.summary.blocked_events, 0);
    }

    #[test]
    fn desktop_audit_report_filters_blocked_reason() {
        use crate::audit_log;

        let dir = tempfile::tempdir().unwrap();
        audit_log::append_line(
            dir.path(),
            serde_json::json!({"event":"blocked","reason":"finding_threshold","tool":"cursor"}),
        )
        .unwrap();
        audit_log::append_line(
            dir.path(),
            serde_json::json!({"tool":"cursor","hook":"pre","finding_count":1}),
        )
        .unwrap();

        let report = audit_report(
            dir.path().to_str().unwrap(),
            AuditReportOptions {
                limit: 10,
                since: None,
                tool: None,
                reason: Some("blocked".to_string()),
                hide_paths: false,
            },
        )
        .unwrap();

        assert_eq!(report.summary.total_entries, 1);
        assert_eq!(report.summary.blocked_events, 1);
        assert_eq!(report.summary.hook_audit_events, 0);
    }

    #[test]
    fn desktop_audit_report_rejects_invalid_reason() {
        let dir = tempfile::tempdir().unwrap();
        let err = audit_report(
            dir.path().to_str().unwrap(),
            AuditReportOptions {
                limit: 10,
                since: None,
                tool: None,
                reason: Some("not-a-reason".to_string()),
                hide_paths: false,
            },
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("invalid audit reason filter"),
            "{err}"
        );
    }

    #[test]
    fn desktop_audit_report_hides_display_paths() {
        use crate::audit_log;

        let dir = tempfile::tempdir().unwrap();
        audit_log::append_line(
            dir.path(),
            serde_json::json!({
                "event":"blocked",
                "reason":"finding_threshold",
                "ts":"2026-05-23T02:31:00Z",
                "tool":"cursor",
                "display_path":"secret.txt",
            }),
        )
        .unwrap();

        let report = audit_report(
            dir.path().to_str().unwrap(),
            AuditReportOptions {
                limit: 10,
                since: None,
                tool: None,
                reason: None,
                hide_paths: true,
            },
        )
        .unwrap();

        assert!(report.recent[0].display_path.is_none());
    }

    #[test]
    fn desktop_audit_report_summarizes_blocked_events() {
        use crate::audit_log;

        let dir = tempfile::tempdir().unwrap();
        audit_log::append_line(
            dir.path(),
            serde_json::json!({
                "event": "blocked",
                "reason": "finding_threshold",
                "tool": "cursor",
                "hook": "pre",
                "max_severity": "high",
                "finding_count": 2,
            }),
        )
        .unwrap();
        audit_log::append_line(
            dir.path(),
            serde_json::json!({"tool":"cursor","hook":"pre","finding_count":1}),
        )
        .unwrap();

        let report = audit_report(
            dir.path().to_str().unwrap(),
            AuditReportOptions {
                limit: 5,
                since: None,
                tool: None,
                reason: None,
                hide_paths: false,
            },
        )
        .unwrap();

        assert!(report.log_exists);
        assert_eq!(report.summary.blocked_events, 1);
        assert_eq!(report.summary.hook_audit_events, 1);
        assert!(!report.recent.is_empty());
    }
}
