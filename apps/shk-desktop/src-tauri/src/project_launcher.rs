use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::AppError;

const QUERY_VALUE_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'/')
    .add(b'\\')
    .add(b':');

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdeKind {
    Cursor,
    Vscode,
    Antigravity,
}

impl IdeKind {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProjectAppKind {
    Cursor,
    Vscode,
    Antigravity,
    ClaudeDesktop,
    ChatGptDesktop,
}

impl ProjectAppKind {
    pub(crate) fn parse(raw: &str) -> Result<Self, AppError> {
        match raw {
            "cursor" => Ok(Self::Cursor),
            "vscode" => Ok(Self::Vscode),
            "antigravity" => Ok(Self::Antigravity),
            "claude-desktop" => Ok(Self::ClaudeDesktop),
            "chatgpt-desktop" => Ok(Self::ChatGptDesktop),
            other => Err(AppError::Message(format!("unsupported app: {other}"))),
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Self::Cursor => IdeKind::Cursor.display_name(),
            Self::Vscode => IdeKind::Vscode.display_name(),
            Self::Antigravity => IdeKind::Antigravity.display_name(),
            Self::ClaudeDesktop => "Claude Desktop",
            Self::ChatGptDesktop => "ChatGPT",
        }
    }

    fn as_ide_kind(self) -> Option<IdeKind> {
        match self {
            Self::Cursor => Some(IdeKind::Cursor),
            Self::Vscode => Some(IdeKind::Vscode),
            Self::Antigravity => Some(IdeKind::Antigravity),
            Self::ClaudeDesktop | Self::ChatGptDesktop => None,
        }
    }

    fn build_deep_link(self, path: &Path) -> Result<String, AppError> {
        let absolute = canonical_project_path(path)?;
        let encoded = encode_query_value(absolute.to_string_lossy().as_ref());
        let url = match self {
            Self::ClaudeDesktop => format!("claude://code/new?folder={encoded}"),
            Self::ChatGptDesktop => format!("codex://new?path={encoded}"),
            Self::Cursor | Self::Vscode | Self::Antigravity => {
                return Err(AppError::Message(format!(
                    "{} does not use deep links",
                    self.display_name()
                )));
            }
        };
        Ok(url)
    }
}

fn encode_query_value(value: &str) -> String {
    utf8_percent_encode(value, QUERY_VALUE_ENCODE_SET).to_string()
}

fn canonical_project_path(path: &Path) -> Result<PathBuf, AppError> {
    if !path.exists() {
        return Err(AppError::Message(format!(
            "path does not exist: {}",
            path.display()
        )));
    }

    path.canonicalize().map_err(|err| {
        AppError::Message(format!("failed to resolve path {}: {err}", path.display()))
    })
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
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn launch_with_cli(path: &Path, ide: IdeKind) -> Result<(), AppError> {
    run_command(editor_command(ide.cli_command(), path))
}

pub(crate) fn open_in_ide_path(path: &Path, ide: IdeKind) -> Result<(), AppError> {
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

fn open_url_scheme(url: &str) -> Result<(), AppError> {
    let mut errors = Vec::new();

    #[cfg(target_os = "macos")]
    {
        match Command::new("open")
            .arg(url)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
        {
            Ok(status) if status.success() => return Ok(()),
            Ok(status) => errors.push(format!("open exited with {status}")),
            Err(err) => errors.push(format!("open failed: {err}")),
        }
    }

    #[cfg(target_os = "windows")]
    {
        match Command::new("cmd")
            .args(["/C", "start", "", url])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
        {
            Ok(status) if status.success() => return Ok(()),
            Ok(status) => errors.push(format!("start exited with {status}")),
            Err(err) => errors.push(format!("start failed: {err}")),
        }
    }

    #[cfg(target_os = "linux")]
    {
        match Command::new("xdg-open")
            .arg(url)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
        {
            Ok(status) if status.success() => return Ok(()),
            Ok(status) => errors.push(format!("xdg-open exited with {status}")),
            Err(err) => errors.push(format!("xdg-open failed: {err}")),
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        let _ = url;
    }

    Err(AppError::Message(format!(
        "could not open URL scheme. {}",
        errors.join("; ")
    )))
}

pub(crate) fn open_project_in_app_path(path: &Path, app: ProjectAppKind) -> Result<(), AppError> {
    if let Some(ide) = app.as_ide_kind() {
        return open_in_ide_path(path, ide);
    }

    let url = app.build_deep_link(path)?;
    open_url_scheme(&url).map_err(|err| {
        AppError::Message(format!(
            "could not open {} in {}. {err}",
            path.display(),
            app.display_name()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_app_kind_parse_and_display() {
        assert_eq!(
            ProjectAppKind::parse("claude-desktop").unwrap(),
            ProjectAppKind::ClaudeDesktop
        );
        assert_eq!(
            ProjectAppKind::parse("chatgpt-desktop").unwrap(),
            ProjectAppKind::ChatGptDesktop
        );
        assert_eq!(
            ProjectAppKind::parse("cursor").unwrap(),
            ProjectAppKind::Cursor
        );
        assert!(ProjectAppKind::parse("emacs").is_err());
        assert_eq!(
            ProjectAppKind::ClaudeDesktop.display_name(),
            "Claude Desktop"
        );
    }

    #[test]
    fn project_app_kind_parses_editor_ids() {
        assert_eq!(ProjectAppKind::parse("vscode").unwrap(), ProjectAppKind::Vscode);
        assert_eq!(
            ProjectAppKind::parse("antigravity").unwrap(),
            ProjectAppKind::Antigravity
        );
    }

    #[test]
    fn build_claude_desktop_deep_link_encodes_path() {
        let dir = tempfile::tempdir().unwrap();
        let url = ProjectAppKind::ClaudeDesktop
            .build_deep_link(dir.path())
            .unwrap();
        let expected = encode_query_value(
            dir.path()
                .canonicalize()
                .unwrap()
                .to_string_lossy()
                .as_ref(),
        );
        assert_eq!(url, format!("claude://code/new?folder={expected}"));
    }

    #[test]
    fn build_chatgpt_desktop_deep_link_encodes_path() {
        let dir = tempfile::tempdir().unwrap();
        let url = ProjectAppKind::ChatGptDesktop
            .build_deep_link(dir.path())
            .unwrap();
        let expected = encode_query_value(
            dir.path()
                .canonicalize()
                .unwrap()
                .to_string_lossy()
                .as_ref(),
        );
        assert_eq!(url, format!("codex://new?path={expected}"));
    }

    #[test]
    fn build_deep_link_requires_existing_path() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");
        let err = ProjectAppKind::ClaudeDesktop
            .build_deep_link(&missing)
            .unwrap_err();
        assert!(err.to_string().contains("path does not exist"));
    }

    #[test]
    fn encode_query_value_escapes_spaces_and_symbols() {
        assert_eq!(
            encode_query_value("/Users/me/My Project/repo"),
            "%2FUsers%2Fme%2FMy%20Project%2Frepo"
        );
        assert_eq!(encode_query_value("日本語"), "%E6%97%A5%E6%9C%AC%E8%AA%9E");
    }

    #[test]
    fn open_project_in_app_path_requires_existing_path() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");
        let err = open_project_in_app_path(&missing, ProjectAppKind::ClaudeDesktop).unwrap_err();
        assert!(err.to_string().contains("path does not exist"));
    }

    #[test]
    fn open_in_ide_path_requires_existing_path() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.txt");
        let err = open_in_ide_path(&missing, IdeKind::Cursor).unwrap_err();
        assert!(err.to_string().contains("path does not exist"));
    }

    #[test]
    fn editor_command_passes_path_to_program() {
        let path = Path::new("/tmp/example-project");
        let command = editor_command("cursor", path);

        assert_eq!(command.get_program(), "cursor");
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            vec![path.as_os_str()]
        );
    }
}
