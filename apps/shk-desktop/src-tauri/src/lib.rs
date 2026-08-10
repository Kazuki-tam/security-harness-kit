use shk_cli::desktop_api::{
    self, ActionResult, ApplyAiHookSettingsOptions, ApplyNpmHardeningOptions,
    ApplyRecommendedFixesOptions, AuditReportOptions, CloneRepositoryResult, DesktopMaskFileResult,
    FixDoctorIgnoreOptions, InitPolicyOptions, InstallAiHooksOptions, InstallSkillsOptions,
    ProjectStatus,
};
use shk_core::ScanJsonReport;
use shk_core::masker::MaskJsonOutput;
use shk_core::policy::ColorMode;
use shk_core::scanner::{ScanOptions, scan_path as scan_target_path};
mod blocked_watcher;
mod project_launcher;

use blocked_watcher::{BLOCKED_EVENT, BlockedWatcher};
use project_launcher::{ProjectAppKind, open_project_in_app_path};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;
use tauri::async_runtime::spawn_blocking;
use tauri::{Emitter, Manager};

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
    run_blocking(move || {
        let root = desktop_api::resolve_project_root(&path).map_err(map_err)?;
        // Defaults keep JSON context disabled: the desktop renders the
        // structured report directly and does not display neighboring source
        // lines, so rescanning and redacting context around every finding is
        // unnecessary.
        let opts = ScanOptions {
            // The desktop process working directory is unrelated to the
            // scanned project (e.g. `/` when launched from Finder), so the
            // project's shk.toml must be resolved from the scanned path
            // itself. Otherwise allowlist/exclude entries are ignored and
            // desktop results diverge from `shk scan` run in the project.
            policy_root: Some(root.clone()),
            ..ScanOptions::default()
        };

        let result = scan_target_path(&root, opts).map_err(map_err)?;
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

/// Replace the set of projects whose audit logs are tailed for live blocks.
///
/// `async` so Tauri keeps it off the main thread: registering a project stats
/// its log, which can block for seconds on an unresponsive network volume.
#[tauri::command]
async fn watch_blocked_projects(
    paths: Vec<String>,
    watcher: tauri::State<'_, BlockedWatcher>,
) -> Result<(), AppError> {
    watcher.set_watched(paths);
    Ok(())
}

#[tauri::command]
async fn clear_audit_log(path: String) -> Result<ActionResult, AppError> {
    run_blocking(move || desktop_api::clear_audit_log(&path).map_err(map_err)).await
}

#[tauri::command]
async fn clone_repository(
    remote_url: String,
    destination_parent: String,
) -> Result<CloneRepositoryResult, AppError> {
    run_blocking(move || {
        desktop_api::clone_repository(&remote_url, &destination_parent).map_err(map_err)
    })
    .await
}

#[tauri::command]
async fn mask_policy_status(
    project_path: Option<String>,
) -> Result<desktop_api::DesktopMaskPolicyStatus, AppError> {
    run_blocking(move || {
        let project_root = project_path
            .as_deref()
            .map(PathBuf::from)
            .filter(|path| !path.as_os_str().is_empty());
        desktop_api::mask_policy_status(project_root.as_deref()).map_err(map_err)
    })
    .await
}

#[tauri::command]
async fn mask_content(
    project_path: Option<String>,
    content: String,
) -> Result<MaskJsonOutput, AppError> {
    run_blocking(move || {
        let project_root = project_path
            .as_deref()
            .map(PathBuf::from)
            .filter(|path| !path.as_os_str().is_empty());
        desktop_api::mask_text_for_desktop(project_root.as_deref(), &content, "<input>")
            .map_err(map_err)
    })
    .await
}

#[tauri::command]
async fn mask_file(
    project_path: Option<String>,
    input_path: String,
    output_path: Option<String>,
) -> Result<DesktopMaskFileResult, AppError> {
    if input_path.trim().is_empty() {
        return Err(AppError::Message("input path is empty".to_string()));
    }

    run_blocking(move || {
        let project_root = project_path
            .as_deref()
            .map(PathBuf::from)
            .filter(|path| !path.as_os_str().is_empty());
        let input = PathBuf::from(&input_path);
        let output = output_path
            .as_deref()
            .map(PathBuf::from)
            .filter(|path| !path.as_os_str().is_empty());
        desktop_api::mask_file_for_desktop(project_root.as_deref(), &input, output.as_deref())
            .map_err(map_err)
    })
    .await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AiToolKind {
    ClaudeDesktop,
    ChatGptDesktop,
    Cursor,
    Vscode,
}

impl AiToolKind {
    fn parse(raw: &str) -> Result<Self, AppError> {
        match raw {
            "claude-desktop" => Ok(Self::ClaudeDesktop),
            "chatgpt-desktop" => Ok(Self::ChatGptDesktop),
            "cursor" => Ok(Self::Cursor),
            "vscode" => Ok(Self::Vscode),
            other => Err(AppError::Message(format!("unsupported AI tool: {other}"))),
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Self::ClaudeDesktop => "Claude Desktop",
            Self::ChatGptDesktop => "ChatGPT",
            Self::Cursor => "Cursor",
            Self::Vscode => "VS Code",
        }
    }

    fn cli_command(self) -> Option<&'static str> {
        match self {
            Self::ClaudeDesktop | Self::ChatGptDesktop => None,
            Self::Cursor => Some("cursor"),
            Self::Vscode => Some("code"),
        }
    }

    #[cfg(target_os = "macos")]
    fn mac_app_names(self) -> &'static [&'static str] {
        match self {
            Self::ClaudeDesktop => &["Claude"],
            Self::ChatGptDesktop => &["ChatGPT"],
            Self::Cursor => &["Cursor"],
            Self::Vscode => &["Visual Studio Code", "Code"],
        }
    }

    #[cfg(target_os = "windows")]
    fn windows_candidates(self) -> Vec<PathBuf> {
        let local = std::env::var("LOCALAPPDATA").ok();
        let program_files = std::env::var("ProgramFiles").ok();
        match self {
            Self::ClaudeDesktop => {
                let mut paths = Vec::new();
                if let Some(local) = local {
                    paths.push(
                        PathBuf::from(local)
                            .join("Programs")
                            .join("Claude")
                            .join("Claude.exe"),
                    );
                }
                paths
            }
            Self::ChatGptDesktop => {
                let mut paths = Vec::new();
                if let Some(local) = local {
                    paths.push(
                        PathBuf::from(local)
                            .join("Programs")
                            .join("ChatGPT")
                            .join("ChatGPT.exe"),
                    );
                }
                paths
            }
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
        }
    }
}

fn launch_ai_tool(tool: AiToolKind) -> Result<(), AppError> {
    let mut errors = Vec::new();

    #[cfg(target_os = "macos")]
    for app_name in tool.mac_app_names() {
        let status = Command::new("open")
            .arg("-a")
            .arg(app_name)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        match status {
            Ok(status) if status.success() => return Ok(()),
            Ok(status) => errors.push(format!("open -a {app_name} exited with {status}")),
            Err(err) => errors.push(format!("open -a {app_name} failed: {err}")),
        }
    }

    #[cfg(target_os = "windows")]
    for candidate in tool.windows_candidates() {
        if !candidate.is_file() {
            continue;
        }
        match Command::new(&candidate)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
        {
            Ok(status) if status.success() => return Ok(()),
            Ok(status) => errors.push(format!("{} exited with {status}", candidate.display())),
            Err(err) => errors.push(format!("{} failed: {err}", candidate.display())),
        }
    }

    if let Some(cli) = tool.cli_command() {
        match Command::new(cli)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
        {
            Ok(status) if status.success() => return Ok(()),
            Ok(status) => errors.push(format!("{cli} exited with {status}")),
            Err(err) => errors.push(format!("{cli} failed: {err}")),
        }
    }

    Err(AppError::Message(format!(
        "could not open {}. {}",
        tool.display_name(),
        errors.join("; ")
    )))
}

#[tauri::command]
async fn open_ai_tool(tool: String) -> Result<(), AppError> {
    let tool = AiToolKind::parse(tool.trim())?;
    run_blocking(move || launch_ai_tool(tool)).await
}

#[tauri::command]
async fn open_in_ide(path: String, ide: String) -> Result<(), AppError> {
    open_project_in_app(path, ide).await
}

#[tauri::command]
async fn open_project_in_app(path: String, app: String) -> Result<(), AppError> {
    let app = ProjectAppKind::parse(app.trim())?;
    if path.trim().is_empty() {
        return Err(AppError::Message("path is empty".to_string()));
    }

    let path = PathBuf::from(path);
    run_blocking(move || open_project_in_app_path(&path, app)).await
}

fn compile_time_updater_pubkey() -> Option<&'static str> {
    option_env!("TAURI_UPDATER_PUBKEY")
        .map(str::trim)
        .filter(|key| !key.is_empty())
}

fn updater_builder() -> tauri_plugin_updater::Builder {
    let builder = tauri_plugin_updater::Builder::new();
    match compile_time_updater_pubkey() {
        Some(pubkey) => builder.pubkey(pubkey),
        None => builder,
    }
}

/// Interval between audit-log polls. Blocks are human-paced, so this trades a
/// couple of seconds of latency for a dependency-free, cross-platform watcher.
const BLOCKED_POLL_INTERVAL: Duration = Duration::from_secs(2);

fn spawn_blocked_watcher(app: &tauri::AppHandle) {
    let app = app.clone();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(BLOCKED_POLL_INTERVAL);
            let events = app.state::<BlockedWatcher>().drain_new_events();
            if events.is_empty() {
                continue;
            }
            // A closed window (or a frontend that never listens) is not an
            // error worth surfacing; the next poll simply carries on.
            let _ = app.emit(BLOCKED_EVENT, events);
        }
    });
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_process::init())
        .plugin(updater_builder().build())
        .manage(BlockedWatcher::default())
        .setup(|app| {
            spawn_blocked_watcher(app.handle());
            Ok(())
        })
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
            watch_blocked_projects,
            clear_audit_log,
            clone_repository,
            open_in_ide,
            open_project_in_app,
            mask_policy_status,
            mask_content,
            mask_file,
            open_ai_tool,
        ])
        .run(tauri::generate_context!())
        .expect("error while running shk desktop app");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ai_tool_kind_parse_and_display() {
        assert_eq!(
            AiToolKind::parse("claude-desktop").unwrap(),
            AiToolKind::ClaudeDesktop
        );
        assert_eq!(
            AiToolKind::parse("chatgpt-desktop").unwrap(),
            AiToolKind::ChatGptDesktop
        );
        assert_eq!(AiToolKind::parse("cursor").unwrap(), AiToolKind::Cursor);
        assert!(AiToolKind::parse("codex").is_err());
        assert_eq!(AiToolKind::ClaudeDesktop.display_name(), "Claude Desktop");
    }

    #[test]
    fn app_error_serializes_to_string() {
        let err = AppError::Message("scan path is empty".into());
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("scan path is empty"));
    }
}
