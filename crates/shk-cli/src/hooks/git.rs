use anyhow::{bail, Context, Result};
use std::fs;
use std::io::Write;
use std::path::Path;

const MANAGED_START: &str = "# shk-managed-start\n";
const MANAGED_END: &str = "# shk-managed-end\n";
const HOOK_BODY: &str = "shk scan --staged\n";

pub fn install_pre_commit(repo_root: &Path) -> Result<()> {
    let repo_root = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let hooks_dir = repo_root.join(".git").join("hooks");
    if !hooks_dir.exists() {
        bail!(
            "{} does not exist; not a git repository?",
            hooks_dir.display()
        );
    }
    let hook_path = hooks_dir.join("pre-commit");
    let block = format!("{MANAGED_START}{HOOK_BODY}{MANAGED_END}");
    if hook_path.exists() {
        let existing = fs::read_to_string(&hook_path)
            .with_context(|| format!("read {}", hook_path.display()))?;
        if existing.contains("shk-managed-start") && existing.contains("shk scan --staged") {
            return Ok(());
        }
        let mut f = fs::OpenOptions::new().append(true).open(&hook_path)?;
        if !existing.ends_with('\n') {
            writeln!(f)?;
        }
        f.write_all(block.as_bytes())?;
        return Ok(());
    }
    let mut script = String::new();
    script.push_str("#!/bin/sh\n");
    script.push_str(&block);
    fs::write(&hook_path, script)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&hook_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&hook_path, perms)?;
    }
    Ok(())
}
