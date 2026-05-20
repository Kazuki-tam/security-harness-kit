//! Structured APIs for the desktop app (no stdout parsing).

use crate::args::AiTool;
use crate::commands::skills::{SkillTool, SkillsInstallArgs};
use crate::doctor::{
    collect_env_status, collect_ignore_status, fix_ignore_patterns, has_managed_ai_hooks,
    has_shk_pre_commit,
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

pub fn fix_doctor_ignore(path: &str) -> Result<ActionResult> {
    let root = resolve_project_root(path)?;
    ensure_desktop_project_root_allowed(&root)?;
    let result = fix_ignore_patterns(&root)?;
    if result.already_ok {
        return Ok(ActionResult {
            success: true,
            message: "Required ignore patterns are already present".to_string(),
            details: vec![],
        });
    }
    Ok(ActionResult {
        success: true,
        message: format!(
            "Appended {} pattern(s) to {}",
            result.appended.len(),
            result.gitignore_path.display()
        ),
        details: result
            .appended
            .iter()
            .map(|pat| format!("+ {pat}"))
            .collect(),
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
    ProjectStatus {
        path: root.display().to_string(),
        policy: PolicyStatus {
            exists: policy_path.is_file(),
            path: policy_path
                .is_file()
                .then(|| policy_path.display().to_string()),
        },
        git: GitStatus {
            is_repo: git_root.is_some(),
            root: git_root.as_ref().map(|p| p.display().to_string()),
        },
        hooks: build_hooks_status(root, git_root.as_deref()),
        doctor: build_doctor_status(root),
        npm_hardening: build_npm_status(root),
        skills: build_skills_status(root),
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

fn build_doctor_status(root: &Path) -> DoctorStatus {
    let git_pre_commit = has_shk_pre_commit(root);
    let ai_managed_hooks = has_managed_ai_hooks(root);
    let ignore = collect_ignore_status(root);
    let env = collect_env_status(root);
    let npm = npm_hardening::status(root);

    let mut issues = Vec::new();
    if !git_pre_commit {
        issues.push(DoctorIssue {
            id: "git_pre_commit".into(),
            severity: "warn".into(),
            message: "Git pre-commit hook is not installed".into(),
        });
    }
    if !ai_managed_hooks {
        issues.push(DoctorIssue {
            id: "ai_hooks".into(),
            severity: "warn".into(),
            message: "AI managed hooks not found — install via Setup".into(),
        });
    }
    for pat in &ignore.missing_patterns {
        issues.push(DoctorIssue {
            id: format!("ignore:{pat}"),
            severity: "warn".into(),
            message: format!("Missing ignore pattern: {pat}"),
        });
    }
    for file in &env.plaintext_env_files {
        issues.push(DoctorIssue {
            id: format!("env:{file}"),
            severity: "warn".into(),
            message: format!("Plaintext env file detected: {file}"),
        });
    }
    for file in &env.mixed_env_files {
        issues.push(DoctorIssue {
            id: format!("env_mixed:{file}"),
            severity: "warn".into(),
            message: format!("Encrypted env file contains plaintext values: {file}"),
        });
    }
    for rec in npm_recommendations(&npm) {
        issues.push(DoctorIssue {
            id: "npm_hardening".into(),
            severity: "info".into(),
            message: rec,
        });
    }

    DoctorStatus {
        git_pre_commit,
        ai_managed_hooks,
        ignore_ok: ignore.missing_patterns.is_empty(),
        missing_ignore_patterns: ignore.missing_patterns,
        env_ok: env.plaintext_env_files.is_empty() && env.mixed_env_files.is_empty(),
        npm_ok: !npm.has_npm_projects() || npm.ok(),
        issues,
    }
}

fn build_npm_status(root: &Path) -> NpmHardeningStatusDto {
    let status = npm_hardening::status(root);
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
        recommendations: npm_recommendations(&status),
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

        let status = build_doctor_status(dir.path());

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

        let result = fix_doctor_ignore(dir.path().to_str().unwrap()).unwrap();
        assert!(result.success, "{result:?}");
        assert!(!result.details.is_empty(), "{result:?}");

        let status = build_project_status(dir.path());
        assert!(status.doctor.ignore_ok);
        assert!(status.doctor.missing_ignore_patterns.is_empty());
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
