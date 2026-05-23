use shk_cli::desktop_api::{
    self, ActionResult, ApplyAiHookSettingsOptions, ApplyNpmHardeningOptions,
    ApplyRecommendedFixesOptions, AuditReportOptions, FixDoctorIgnoreOptions, InitPolicyOptions,
    InstallAiHooksOptions, InstallSkillsOptions, ProjectStatus,
};
use shk_core::ScanJsonReport;
use shk_core::policy::ColorMode;
use shk_core::scanner::{ScanOptions, scan_path as scan_target_path};
use std::path::{Path, PathBuf};
use std::process::Command;
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

#[tauri::command]
async fn audit_report(
    path: String,
    options: AuditReportOptions,
) -> Result<desktop_api::AuditReport, AppError> {
    run_blocking(move || desktop_api::audit_report(&path, options).map_err(map_err)).await
}

#[derive(Debug, Clone, Copy)]
enum IdeKind {
    Cursor,
    Vscode,
    Antigravity,
}

impl IdeKind {
    fn parse(raw: &str) -> Result<Self, AppError> {
        match raw {
            "cursor" => Ok(Self::Cursor),
            "vscode" => Ok(Self::Vscode),
            "antigravity" => Ok(Self::Antigravity),
            other => Err(AppError::Message(format!("unsupported IDE: {other}"))),
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Self::Cursor => "Cursor",
            Self::Vscode => "VS Code",
            Self::Antigravity => "Antigravity",
        }
    }

    fn cli_command(self) -> &'static str {
        match self {
            Self::Cursor => "cursor",
            Self::Vscode => "code",
            Self::Antigravity => "antigravity",
        }
    }

    #[cfg(target_os = "macos")]
    fn mac_app_names(self) -> &'static [&'static str] {
        match self {
            Self::Cursor => &["Cursor"],
            Self::Vscode => &["Visual Studio Code", "Code"],
            Self::Antigravity => &["Antigravity", "Antigravity IDE", "Google Antigravity"],
        }
    }

    #[cfg(target_os = "windows")]
    fn windows_candidates(self) -> Vec<PathBuf> {
        let local = std::env::var("LOCALAPPDATA").ok();
        let program_files = std::env::var("ProgramFiles").ok();
        match self {
            Self::Cursor => {
                let mut paths = Vec::new();
                if let Some(local) = local {
                    paths.push(
                        PathBuf::from(local)
                            .join("Programs")
                            .join("cursor")
                            .join("Cursor.exe"),
                    );
                }
                paths
            }
            Self::Vscode => {
                let mut paths = Vec::new();
                if let Some(local) = local {
                    paths.push(
                        PathBuf::from(local)
                            .join("Programs")
                            .join("Microsoft VS Code")
                            .join("Code.exe"),
                    );
                }
                if let Some(program_files) = program_files {
                    paths.push(
                        PathBuf::from(program_files)
                            .join("Microsoft VS Code")
                            .join("Code.exe"),
                    );
                }
                paths
            }
            Self::Antigravity => {
                let mut paths = Vec::new();
                if let Some(local) = local {
                    paths.push(
                        PathBuf::from(local)
                            .join("Programs")
                            .join("Antigravity")
                            .join("Antigravity.exe"),
                    );
                }
                if let Some(program_files) = program_files {
                    paths.push(
                        PathBuf::from(program_files)
                            .join("Antigravity")
                            .join("Antigravity.exe"),
                    );
                }
                paths
            }
        }
    }
}

fn run_command(mut command: Command) -> Result<(), AppError> {
    let status = command
        .status()
        .map_err(|err| AppError::Message(format!("failed to launch editor: {err}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(AppError::Message(format!(
            "editor process exited with status {status}"
        )))
    }
}

fn editor_command(program: impl AsRef<std::ffi::OsStr>, path: &Path) -> Command {
    let mut command = Command::new(program);
    command
        .arg(path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    command
}

fn launch_with_cli(path: &Path, ide: IdeKind) -> Result<(), AppError> {
    run_command(editor_command(ide.cli_command(), path))
}

fn open_in_ide_path(path: &Path, ide: IdeKind) -> Result<(), AppError> {
    if !path.exists() {
        return Err(AppError::Message(format!(
            "path does not exist: {}",
            path.display()
        )));
    }

    let mut errors = Vec::new();

    #[cfg(target_os = "macos")]
    for app_name in ide.mac_app_names() {
        let mut command = Command::new("open");
        command.arg("-a").arg(app_name).arg(path);
        match command.status() {
            Ok(status) if status.success() => return Ok(()),
            Ok(status) => errors.push(format!("open -a {app_name} exited with {status}")),
            Err(err) => errors.push(format!("open -a {app_name} failed: {err}")),
        }
    }

    #[cfg(target_os = "windows")]
    for candidate in ide.windows_candidates() {
        if !candidate.is_file() {
            continue;
        }
        match run_command(editor_command(&candidate, path)) {
            Ok(()) => return Ok(()),
            Err(err) => errors.push(format!("{}: {err}", candidate.display())),
        }
    }

    match launch_with_cli(path, ide) {
        Ok(()) => return Ok(()),
        Err(err) => errors.push(err.to_string()),
    }

    Err(AppError::Message(format!(
        "could not open {} in {}. {}",
        path.display(),
        ide.display_name(),
        errors.join("; ")
    )))
}

#[tauri::command]
async fn open_in_ide(path: String, ide: String) -> Result<(), AppError> {
    let ide = IdeKind::parse(ide.trim())?;
    if path.trim().is_empty() {
        return Err(AppError::Message("path is empty".to_string()));
    }

    let path = PathBuf::from(path);
    run_blocking(move || open_in_ide_path(&path, ide)).await
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
            audit_report,
            open_in_ide,
        ])
        .run(tauri::generate_context!())
        .expect("error while running shk desktop app");
}
