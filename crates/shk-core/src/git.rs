use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn is_inside_git_work_tree(cwd: &Path) -> bool {
    Command::new("git")
        .args(["rev-parse", "--is-inside-work-tree"])
        .current_dir(cwd)
        .output()
        .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "true")
        .unwrap_or(false)
}

/// Staged file paths relative to repo root, normalized with `/`.
pub fn staged_files(repo_root: &Path) -> Result<Vec<PathBuf>> {
    let out = Command::new("git")
        .args([
            "diff",
            "--cached",
            "--name-only",
            "--diff-filter=ACMR",
            "-z",
        ])
        .current_dir(repo_root)
        .output()
        .context("failed to run git")?;
    if !out.status.success() {
        bail!("git diff --cached failed");
    }
    let mut paths = Vec::new();
    for chunk in out.stdout.split(|&b| b == 0) {
        if chunk.is_empty() {
            continue;
        }
        let s = std::str::from_utf8(chunk).context("git path utf-8")?;
        paths.push(PathBuf::from(s));
    }
    Ok(paths)
}

pub fn staged_file_bytes(repo_root: &Path, rel_path: &Path) -> Result<Vec<u8>> {
    let spec = format!(":{}", rel_path.to_string_lossy().replace('\\', "/"));
    let out = Command::new("git")
        .args(["show", &spec])
        .current_dir(repo_root)
        .output()
        .with_context(|| format!("failed to read staged blob {}", rel_path.display()))?;
    if !out.status.success() {
        bail!("git show failed for staged blob {}", rel_path.display());
    }
    Ok(out.stdout)
}

pub fn discover_repo_root(start: &Path) -> Option<PathBuf> {
    let start = if start.is_absolute() {
        start.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(start)
    };
    let mut cur = std::fs::canonicalize(&start).unwrap_or(start);
    loop {
        if cur.join(".git").exists() {
            return Some(cur);
        }
        if !cur.pop() {
            return None;
        }
    }
}
