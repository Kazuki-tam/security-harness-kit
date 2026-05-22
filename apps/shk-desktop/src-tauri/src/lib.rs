use shk_cli::desktop_api::{
    self, ActionResult, ApplyAiHookSettingsOptions, ApplyNpmHardeningOptions,
    ApplyRecommendedFixesOptions, FixDoctorIgnoreOptions, InitPolicyOptions, InstallAiHooksOptions,
    InstallSkillsOptions, ProjectStatus,
};
use shk_core::ScanJsonReport;
use shk_core::policy::ColorMode;
use shk_core::scanner::{ScanOptions, scan_path as scan_target_path};
use std::path::Path;
use tauri::async_runtime::spawn_blocking;

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

async fn run_blocking<F, T>(task: F) -> Result<T, AppError>
where
    F: FnOnce() -> Result<T, AppError> + Send + 'static,
    T: Send + 'static,
{
    spawn_blocking(task)
        .await
        .map_err(|err| AppError::Message(format!("background task failed: {err}")))?
}

#[tauri::command]
async fn scan_path(path: String) -> Result<ScanJsonReport, AppError> {
    if path.trim().is_empty() {
        return Err(AppError::Message("scan path is empty".to_string()));
    }

    run_blocking(move || {
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
    })
    .await
}

#[tauri::command]
async fn project_status(path: String) -> Result<ProjectStatus, AppError> {
    run_blocking(move || desktop_api::project_status(&path).map_err(map_err)).await
}

#[tauri::command]
async fn init_policy(path: String, options: InitPolicyOptions) -> Result<ActionResult, AppError> {
    run_blocking(move || desktop_api::init_policy(&path, options).map_err(map_err)).await
}

#[tauri::command]
async fn install_pre_commit_hook(path: String) -> Result<ActionResult, AppError> {
    run_blocking(move || desktop_api::install_pre_commit_hook(&path).map_err(map_err)).await
}

#[tauri::command]
async fn install_ai_hooks(
    path: String,
    options: InstallAiHooksOptions,
) -> Result<ActionResult, AppError> {
    run_blocking(move || desktop_api::install_ai_hooks(&path, options).map_err(map_err)).await
}

#[tauri::command]
async fn apply_ai_hook_settings(
    path: String,
    options: ApplyAiHookSettingsOptions,
) -> Result<ActionResult, AppError> {
    run_blocking(move || desktop_api::apply_ai_hook_settings(&path, options).map_err(map_err)).await
}

#[tauri::command]
async fn fix_doctor_ignore(
    path: String,
    options: FixDoctorIgnoreOptions,
) -> Result<ActionResult, AppError> {
    run_blocking(move || desktop_api::fix_doctor_ignore(&path, options).map_err(map_err)).await
}

#[tauri::command]
async fn apply_recommended_fixes(
    path: String,
    options: ApplyRecommendedFixesOptions,
) -> Result<ActionResult, AppError> {
    run_blocking(move || desktop_api::apply_recommended_fixes(&path, options).map_err(map_err))
        .await
}

#[tauri::command]
async fn apply_npm_hardening(
    path: String,
    options: ApplyNpmHardeningOptions,
) -> Result<ActionResult, AppError> {
    run_blocking(move || desktop_api::apply_npm_hardening(&path, options).map_err(map_err)).await
}

#[tauri::command]
async fn install_skills(
    path: String,
    options: InstallSkillsOptions,
) -> Result<ActionResult, AppError> {
    run_blocking(move || desktop_api::install_skills(&path, options).map_err(map_err)).await
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
            apply_ai_hook_settings,
            fix_doctor_ignore,
            apply_recommended_fixes,
            apply_npm_hardening,
            install_skills,
        ])
        .run(tauri::generate_context!())
        .expect("error while running shk desktop app");
}
