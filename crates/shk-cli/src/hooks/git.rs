use anyhow::{Context, Result, bail};
use std::fs;
use std::io::Write;
use std::path::Path;

const MANAGED_START: &str = "# shk-managed-start\n";
const MANAGED_END: &str = "# shk-managed-end\n";
const HOOK_BODY: &str = r#"if command -v shk >/dev/null 2>&1; then
  shk scan --staged
elif command -v cargo >/dev/null 2>&1 && [ -f Cargo.toml ]; then
  cargo run -q -p shk-cli --bin shk -- scan --staged
else
  echo "shk pre-commit hook requires 'shk' in PATH or Cargo in a source checkout." >&2
  exit 127
fi
"#;

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
        let meta = fs::metadata(&hook_path)
            .with_context(|| format!("metadata {}", hook_path.display()))?;
        if !meta.is_file() {
            bail!("{} exists but is not a regular file", hook_path.display());
        }
        let existing = fs::read_to_string(&hook_path)
            .with_context(|| format!("read {}", hook_path.display()))?;
        if existing.contains(MANAGED_START) && existing.contains(MANAGED_END) {
            let updated = replace_managed_block(&existing, &block);
            if updated != existing {
                fs::write(&hook_path, updated)?;
            }
            ensure_executable(&hook_path)?;
            return Ok(());
        }
        let mut f = fs::OpenOptions::new().append(true).open(&hook_path)?;
        if !existing.ends_with('\n') {
            writeln!(f)?;
        }
        f.write_all(block.as_bytes())?;
        ensure_executable(&hook_path)?;
        return Ok(());
    }
    let mut script = String::new();
    script.push_str("#!/bin/sh\n");
    script.push_str(&block);
    fs::write(&hook_path, script)?;
    ensure_executable(&hook_path)?;
    Ok(())
}

fn replace_managed_block(existing: &str, block: &str) -> String {
    let Some(start) = existing.find(MANAGED_START) else {
        return existing.to_owned();
    };
    let Some(end_rel) = existing[start..].find(MANAGED_END) else {
        return existing.to_owned();
    };
    let end = start + end_rel + MANAGED_END.len();
    let mut updated = String::with_capacity(existing.len() + block.len());
    updated.push_str(&existing[..start]);
    updated.push_str(block);
    updated.push_str(&existing[end..]);
    updated
}

#[cfg(unix)]
fn ensure_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    let mode = perms.mode();
    if mode & 0o111 == 0 {
        let execute_bits_for_readers = (mode & 0o444) >> 2;
        perms.set_mode(mode | execute_bits_for_readers);
        fs::set_permissions(path, perms)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_executable(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_block_is_upgraded_in_place() {
        let existing = "#!/bin/sh\n\
# existing user hook\n\
# shk-managed-start\n\
shk scan --staged\n\
# shk-managed-end\n";
        let block = format!("{MANAGED_START}{HOOK_BODY}{MANAGED_END}");

        let updated = replace_managed_block(existing, &block);

        assert!(updated.contains("# existing user hook"));
        assert!(updated.contains("command -v shk"));
        assert!(updated.contains("cargo run -q -p shk-cli --bin shk -- scan --staged"));
        assert!(!updated.contains("\nshk scan --staged\n# shk-managed-end"));
    }
}
