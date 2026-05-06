use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

const POLICY_FILE: &str = "shk.toml";

const PROTECTED_HOME_PATHS: &[&str] = &[
    ".bash_profile",
    ".bashrc",
    ".cargo/credentials",
    ".cargo/credentials.toml",
    ".config/fish/config.fish",
    ".config/git/config",
    ".curlrc",
    ".gitconfig",
    ".gitignore",
    ".netrc",
    ".npmrc",
    ".profile",
    ".pypirc",
    ".ssh/authorized_keys",
    ".ssh/config",
    ".ssh/known_hosts",
    ".wgetrc",
    ".zprofile",
    ".zshenv",
    ".zshrc",
];

pub fn require_project_policy(root: &Path, action: &str) -> Result<PathBuf> {
    let policy_path = root.join(POLICY_FILE);
    if policy_path.is_file() {
        return Ok(policy_path);
    }

    bail!("{action} requires a project {POLICY_FILE}; run `shk init` from the project root first");
}

pub fn ensure_writable_path_allowed(path: &Path) -> Result<()> {
    if is_sensitive_env_file(path) {
        bail!("refusing to write sensitive env file `{}`", path.display());
    }

    let Some(rel) = path_relative_to_home(path)? else {
        return Ok(());
    };
    let rel = rel.to_string_lossy().replace('\\', "/");
    if PROTECTED_HOME_PATHS.iter().any(|p| *p == rel) {
        bail!(
            "refusing to write protected home configuration file `{}`",
            path.display()
        );
    }
    Ok(())
}

fn is_sensitive_env_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    name == ".env" || name.starts_with(".env.")
}

fn path_relative_to_home(path: &Path) -> Result<Option<PathBuf>> {
    let Some(home) = dirs::home_dir() else {
        return Ok(None);
    };
    let home = canonicalize_existing_or_parent(&home)?;
    let path = expand_home(path, &home);
    let abs = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .context("current directory for safety check")?
            .join(path)
    };
    let abs = canonicalize_existing_or_parent(&abs)?;
    Ok(abs.strip_prefix(&home).ok().map(Path::to_path_buf))
}

fn expand_home(path: &Path, home: &Path) -> PathBuf {
    let raw = path.to_string_lossy();
    if raw == "~" {
        return home.to_path_buf();
    }
    if let Some(rest) = raw.strip_prefix("~/") {
        return home.join(rest);
    }
    path.to_path_buf()
}

fn canonicalize_existing_or_parent(path: &Path) -> Result<PathBuf> {
    if path.exists() {
        return std::fs::canonicalize(path)
            .with_context(|| format!("canonicalize {}", path.display()));
    }

    let Some(parent) = path.parent() else {
        return Ok(path.to_path_buf());
    };
    let parent = if parent.as_os_str().is_empty() {
        std::env::current_dir().context("current directory for safety check")?
    } else if parent.exists() {
        std::fs::canonicalize(parent)
            .with_context(|| format!("canonicalize {}", parent.display()))?
    } else {
        canonicalize_existing_or_parent(parent)?
    };

    Ok(path
        .file_name()
        .map(|name| parent.join(name))
        .unwrap_or(parent))
}
