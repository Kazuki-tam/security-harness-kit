use shk_cli::desktop_api::{
    self, ActionResult, ApplyRecommendedFixesOptions, FixDoctorIgnoreOptions, InitPolicyOptions,
    InstallAiHooksOptions, InstallSkillsOptions, ProjectStatus,
};
use shk_core::ScanJsonReport;
use shk_core::policy::ColorMode;
use shk_core::scanner::{ScanOptions, scan_path as scan_target_path};
use std::path::Path;

#[derive(Debug, thiserror::Error)]
enum AppError {
    #[error("{0}")]
    Message(String),
}

impl serde::Serialize for AppError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

fn map_err(err: impl std::fmt::Display) -> AppError {
    AppError::Message(err.to_string())
}

#[tauri::command]
fn scan_path(path: String) -> Result<ScanJsonReport, AppError> {
    if path.trim().is_empty() {
        return Err(AppError::Message("scan path is empty".to_string()));
    }

    let opts = ScanOptions {
        staged: false,
        git_history: false,
        git_history_ref: None,
        git_history_since: None,
        git_history_max_commits: None,
        json: true,
        fail_on_override: None,
        use_pre_commit_threshold: false,
        include_context: false,
        include_binary: false,
        follow_symlinks: false,
    };

    let result = scan_target_path(Path::new(&path), opts).map_err(map_err)?;
    Ok(result.to_json_report(ColorMode::Never))
}

#[tauri::command]
fn project_status(path: String) -> Result<ProjectStatus, AppError> {
    desktop_api::project_status(&path).map_err(map_err)
}

#[tauri::command]
fn init_policy(path: String, options: InitPolicyOptions) -> Result<ActionResult, AppError> {
    desktop_api::init_policy(&path, options).map_err(map_err)
}

#[tauri::command]
fn install_pre_commit_hook(path: String) -> Result<ActionResult, AppError> {
    desktop_api::install_pre_commit_hook(&path).map_err(map_err)
}

#[tauri::command]
fn install_ai_hooks(
    path: String,
    options: InstallAiHooksOptions,
) -> Result<ActionResult, AppError> {
    desktop_api::install_ai_hooks(&path, options).map_err(map_err)
}

#[tauri::command]
fn fix_doctor_ignore(
    path: String,
    options: FixDoctorIgnoreOptions,
) -> Result<ActionResult, AppError> {
    desktop_api::fix_doctor_ignore(&path, options).map_err(map_err)
}

#[tauri::command]
fn apply_recommended_fixes(
    path: String,
    options: ApplyRecommendedFixesOptions,
) -> Result<ActionResult, AppError> {
    desktop_api::apply_recommended_fixes(&path, options).map_err(map_err)
}

#[tauri::command]
fn apply_npm_hardening(path: String) -> Result<ActionResult, AppError> {
    desktop_api::apply_npm_hardening(&path).map_err(map_err)
}

#[tauri::command]
fn install_skills(path: String, options: InstallSkillsOptions) -> Result<ActionResult, AppError> {
    desktop_api::install_skills(&path, options).map_err(map_err)
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            scan_path,
            project_status,
            init_policy,
            install_pre_commit_hook,
            install_ai_hooks,
            fix_doctor_ignore,
            apply_recommended_fixes,
            apply_npm_hardening,
            install_skills,
        ])
        .run(tauri::generate_context!())
        .expect("error while running shk desktop app");
}
