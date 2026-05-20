use std::path::Path;

use shk_core::ScanJsonReport;
use shk_core::policy::ColorMode;
use shk_core::scanner::{ScanOptions, scan_path as scan_target_path};

#[derive(Debug, thiserror::Error)]
enum AppError {
    #[error("{0}")]
    Scan(String),
}

impl serde::Serialize for AppError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[tauri::command]
fn scan_path(path: String) -> Result<ScanJsonReport, AppError> {
    if path.trim().is_empty() {
        return Err(AppError::Scan("scan path is empty".to_string()));
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

    let result = scan_target_path(Path::new(&path), opts)
        .map_err(|err| AppError::Scan(format!("scan failed: {err:#}")))?;
    Ok(result.to_json_report(ColorMode::Never))
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![scan_path])
        .run(tauri::generate_context!())
        .expect("error while running shk desktop app");
}
