use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

const POLICY_FILE: &str = "shk.toml";

const PROTECTED_HOME_PATHS: &[&str] = &[
    ".aws/credentials",
    ".aws/config",
    ".bash_profile",
    ".bashrc",
    ".cargo/credentials",
    ".cargo/credentials.toml",
    ".config/fish/config.fish",
    ".config/gcloud/credentials.db",
    ".config/gcloud/application_default_credentials.json",
    ".config/git/config",
    ".curlrc",
    ".docker/config.json",
    ".gitconfig",
    ".gitignore",
    ".gnupg/secring.gpg",
    ".gnupg/trustdb.gpg",
    ".kube/config",
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
    let Some(home) = home_dir() else {
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

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
        .or_else(dirs::home_dir)
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn require_project_policy_returns_existing_policy_path() {
        let root = tempdir().expect("temp dir");
        std::fs::write(root.path().join(POLICY_FILE), "").expect("write policy");

        let path = require_project_policy(root.path(), "scan").expect("policy exists");

        assert_eq!(
            path.file_name().and_then(|name| name.to_str()),
            Some(POLICY_FILE)
        );
    }

    #[test]
    fn require_project_policy_errors_when_missing() {
        let root = tempdir().expect("temp dir");

        let err =
            require_project_policy(root.path(), "mask").expect_err("missing policy should fail");

        assert!(err.to_string().contains("mask requires a project shk.toml"));
    }

    #[test]
    fn ensure_writable_path_allowed_rejects_env_files() {
        for path in [Path::new(".env"), Path::new("nested/.env.local")] {
            let err = ensure_writable_path_allowed(path).expect_err("env files are sensitive");

            assert!(
                err.to_string()
                    .contains("refusing to write sensitive env file")
            );
        }
    }

    #[test]
    fn ensure_writable_path_allowed_accepts_regular_project_file() {
        ensure_writable_path_allowed(Path::new("src/main.rs")).expect("regular file is allowed");
    }

    #[test]
    fn expand_home_handles_bare_and_prefixed_home_paths() {
        let home = Path::new("/tmp/example-home");

        assert_eq!(expand_home(Path::new("~"), home), home);
        assert_eq!(
            expand_home(Path::new("~/project/file.txt"), home),
            home.join("project/file.txt")
        );
        assert_eq!(
            expand_home(Path::new("relative/file.txt"), home),
            PathBuf::from("relative/file.txt")
        );
    }

    #[test]
    fn canonicalize_existing_or_parent_preserves_missing_leaf() {
        let root = tempdir().expect("temp dir");
        let nested = root.path().join("existing");
        std::fs::create_dir_all(&nested).expect("create parent");

        let path = canonicalize_existing_or_parent(&nested.join("missing.txt"))
            .expect("canonicalize missing leaf");

        assert!(path.ends_with("existing/missing.txt"));
    }
}
