//! Structured APIs for the desktop app (no stdout parsing).

use crate::args::AiTool;
use crate::commands::skills::{SkillTool, SkillsInstallArgs};
use crate::doctor::{
    ClaudePermissionsStatus, CodexConfigStatus, EnvStatus, IgnoreStatus,
    collect_claude_permissions_status, collect_codex_config_status, collect_env_status,
    collect_ignore_status, fix_ignore_patterns, has_managed_ai_hooks, has_shk_pre_commit,
    ignore_fix_target_statuses,
};
use crate::hooks::{InstallAiOptions, install_ai_with_summaries, install_pre_commit};
use crate::npm_hardening;
use crate::policy_cmd;
use crate::safety;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use shk_core::git;
use shk_integrations::{MANAGED_MARKER_JSON, MANAGED_MARKER_SH};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectStatus {
    pub path: String,
    pub policy: PolicyStatus,
    pub git: GitStatus,
    pub hooks: HooksStatus,
    pub doctor: DoctorStatus,
    pub npm_hardening: NpmHardeningStatusDto,
    pub skills: Vec<SkillStatusDto>,
    pub ignore_fix_targets: Vec<IgnoreFixTargetDto>,
    pub recommended_fixes: Vec<RecommendedFixDto>,
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
    pub codex_config_ok: bool,
    pub env_ok: bool,
    pub npm_ok: bool,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallAiHooksOptions {
    pub audit: bool,
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

struct ProjectCheckStatus {
    git_pre_commit: bool,
    ai_managed_hooks: bool,
    ignore: IgnoreStatus,
    claude: ClaudePermissionsStatus,
    codex: CodexConfigStatus,
    env: EnvStatus,
    npm: npm_hardening::NpmHardeningStatus,
}

pub fn project_status(path: &str) -> Result<ProjectStatus> {
    let root = resolve_project_root(path)?;
    Ok(build_project_status(&root))
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
    let mut details = Vec::new();
    let mut applied = 0usize;

    for fix_id in &options.fix_ids {
        if fix_id == "ignore" && options.ignore_targets.is_empty() {
            anyhow::bail!("ignore fix requires at least one target");
        }
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
                InstallAiHooksOptions {
                    audit: false,
                    dry_run: false,
                    global: false,
                    tool: None,
                    fail_closed: false,
                    apply_deny: false,
                    apply_sandbox: false,
                },
            )
        }
        "ai_claude_deny" => {
            if !policy_exists {
                anyhow::bail!("Claude deny fix requires shk.toml");
            }
            install_ai_hooks(
                &root.display().to_string(),
                InstallAiHooksOptions {
                    audit: false,
                    dry_run: false,
                    global: false,
                    tool: Some("claude-code".to_string()),
                    fail_closed: false,
                    apply_deny: true,
                    apply_sandbox: false,
                },
            )
        }
        "ai_codex_sandbox" => {
            if !policy_exists {
                anyhow::bail!("Codex sandbox fix requires shk.toml");
            }
            install_ai_hooks(
                &root.display().to_string(),
                InstallAiHooksOptions {
                    audit: false,
                    dry_run: false,
                    global: false,
                    tool: Some("codex".to_string()),
                    fail_closed: false,
                    apply_deny: false,
                    apply_sandbox: true,
                },
            )
        }
        "npm_hardening" => apply_npm_hardening(&root.display().to_string()),
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

pub fn apply_npm_hardening(path: &str) -> Result<ActionResult> {
    let root = resolve_project_root(path)?;
    ensure_desktop_project_root_allowed(&root)?;
    let before = npm_hardening::status(&root);
    if !before.has_npm_projects() {
        return Ok(ActionResult {
            success: true,
            message: "No package.json detected".to_string(),
            details: vec![],
        });
    }
    for path in before.apply_paths() {
        safety::ensure_writable_path_allowed(path)?;
    }
    npm_hardening::apply(&root)?;
    let after = npm_hardening::status(&root);
    Ok(ActionResult {
        success: after.ok(),
        message: if after.ok() {
            "npm supply-chain hardening applied".to_string()
        } else {
            "Applied partial npm hardening; review remaining items".to_string()
        },
        details: npm_recommendations(&after),
    })
}

pub fn install_skills(path: &str, options: InstallSkillsOptions) -> Result<ActionResult> {
    let root = resolve_project_root(path)?;
    ensure_desktop_project_root_allowed(&root)?;
    if options.global {
        anyhow::bail!("desktop setup does not support global skill installation");
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
    }
}

fn collect_project_check_status(root: &Path) -> ProjectCheckStatus {
    ProjectCheckStatus {
        git_pre_commit: has_shk_pre_commit(root),
        ai_managed_hooks: has_managed_ai_hooks(root),
        ignore: collect_ignore_status(root),
        claude: collect_claude_permissions_status(root),
        codex: collect_codex_config_status(root),
        env: collect_env_status(root),
        npm: npm_hardening::status(root),
    }
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
    [AiTool::ClaudeCode, AiTool::Codex, AiTool::Cursor]
        .into_iter()
        .filter_map(|tool| {
            let config_path = resolve_ai_config_path(tool, root, global).ok()?;
            let installed = config_path.is_file()
                && fs::read_to_string(&config_path)
                    .map(|s| s.contains(MANAGED_MARKER_JSON) || s.contains(MANAGED_MARKER_SH))
                    .unwrap_or(false);
            Some(AiHookToolStatus {
                tool: tool.kebab_str().to_string(),
                config_path: config_path.display().to_string(),
                installed,
            })
        })
        .collect()
}

fn resolve_ai_config_path(tool: AiTool, root: &Path, global: bool) -> Result<PathBuf> {
    let rel = match tool {
        AiTool::ClaudeCode => ".claude/settings.json",
        AiTool::Cursor => ".cursor/hooks.json",
        AiTool::Codex => ".codex/config.toml",
    };
    Ok(if global {
        dirs::home_dir()
            .context("home directory not found")?
            .join(rel)
    } else {
        root.join(rel)
    })
}

fn build_recommended_fixes(
    checks: &ProjectCheckStatus,
    policy_exists: bool,
    is_git_repo: bool,
) -> Vec<RecommendedFixDto> {
    let mut fixes = Vec::new();
    if policy_exists && !checks.ignore.missing_patterns.is_empty() {
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
            message: "Install managed AI scan hooks for Cursor, Claude Code, and Codex".into(),
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
    if policy_exists
        && checks.codex.config_exists
        && (!checks.codex.sandbox_ok || !checks.codex.approval_ok || !checks.codex.hooks_enabled)
    {
        fixes.push(RecommendedFixDto {
            id: "ai_codex_sandbox".into(),
            severity: "warn".into(),
            message: "Harden Codex config (hooks, sandbox_mode, approval_policy)".into(),
            requires_policy: true,
            default_selected: true,
        });
    }
    if checks.npm.has_npm_projects() && !checks.npm.ok() {
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
    let codex_config_ok = !checks.codex.config_exists
        || (checks.codex.hooks_enabled && checks.codex.sandbox_ok && checks.codex.approval_ok);

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
    for rec in npm_recommendations(&checks.npm) {
        issues.push(DoctorIssue {
            id: "npm_hardening".into(),
            severity: "info".into(),
            message: rec,
        });
    }

    DoctorStatus {
        git_pre_commit: checks.git_pre_commit,
        ai_managed_hooks: checks.ai_managed_hooks,
        ignore_ok: checks.ignore.missing_patterns.is_empty(),
        missing_ignore_patterns: checks.ignore.missing_patterns.clone(),
        claude_deny_ok: !checks.claude.settings_exists || checks.claude.deny_ok,
        codex_config_ok,
        env_ok: checks.env.plaintext_env_files.is_empty() && checks.env.mixed_env_files.is_empty(),
        npm_ok: !checks.npm.has_npm_projects() || checks.npm.ok(),
        issues,
    }
}

fn build_npm_status_from(status: &npm_hardening::NpmHardeningStatus) -> NpmHardeningStatusDto {
    NpmHardeningStatusDto {
        has_projects: status.has_npm_projects(),
        ok: status.ok(),
        package_count: status.package_dirs.len(),
        missing_lockfiles: status
            .package_dirs_without_lockfile
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
        ignore_scripts_ok: status.package_scripts_ok(),
        age_gates_ok: status.age_gates_ok(),
        dependency_bot_cooldown_ok: status.dependency_bot_cooldown_ok(),
        recommendations: npm_recommendations(status),
    }
}

fn npm_recommendations(status: &npm_hardening::NpmHardeningStatus) -> Vec<String> {
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
        "cursor" => Ok(AiTool::Cursor),
        other => anyhow::bail!("unknown AI tool: {other}"),
    }
}

fn parse_skill_tool(value: &str) -> Result<SkillTool> {
    match value {
        "claude-code" => Ok(SkillTool::ClaudeCode),
        "codex" => Ok(SkillTool::Codex),
        "cursor" => Ok(SkillTool::Cursor),
        "all" => Ok(SkillTool::All),
        other => anyhow::bail!("unknown skill tool: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

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
    fn desktop_ai_hooks_reject_global_install() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("shk.toml"), "").unwrap();

        let err = install_ai_hooks(
            dir.path().to_str().unwrap(),
            InstallAiHooksOptions {
                audit: false,
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
}
