use crate::safety;
use anyhow::{Context, Result, bail};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const MANAGED_START: &str = "# shk-managed-start\n";
const MANAGED_END: &str = "# shk-managed-end\n";
// `|| exit $?` keeps a failing scan fatal when user content follows the block.
const HOOK_BODY: &str = r#"if command -v shk >/dev/null 2>&1; then
  shk scan --staged || exit $?
elif command -v cargo >/dev/null 2>&1 && [ -f Cargo.toml ]; then
  cargo run -q -p shk-cli --bin shk -- scan --staged || exit $?
else
  echo "shk pre-commit hook requires 'shk' in PATH or Cargo in a source checkout." >&2
  exit 127
fi
"#;

/// Directory git runs hooks from for the work tree at `repo_root`. Honours
/// `core.hooksPath` and work trees whose `.git` is a file (linked worktrees,
/// submodules, `--separate-git-dir`). Falls back to `<repo_root>/.git/hooks`
/// when git is unavailable or does not report `repo_root` as its work tree.
pub fn effective_hooks_dir(repo_root: &Path) -> PathBuf {
    git_hooks_dir(repo_root).unwrap_or_else(|| repo_root.join(".git").join("hooks"))
}

/// Path of the pre-commit hook git would run for the work tree at `repo_root`.
pub fn pre_commit_hook_path(repo_root: &Path) -> PathBuf {
    effective_hooks_dir(repo_root).join("pre-commit")
}

fn git_hooks_dir(repo_root: &Path) -> Option<PathBuf> {
    let out = Command::new("git")
        .args(["rev-parse", "--show-toplevel", "--git-path", "hooks"])
        .current_dir(repo_root)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8(out.stdout).ok()?;
    let mut lines = stdout.lines();
    let toplevel = lines.next()?;
    let hooks = lines.next().filter(|line| !line.is_empty())?;
    // An unusable `.git` entry makes git walk up to an enclosing repository,
    // whose hooks directory is not this work tree's.
    let canonical = |path: &Path| fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if canonical(Path::new(toplevel)) != canonical(repo_root) {
        return None;
    }
    // Relative output is relative to the directory git ran in.
    Some(repo_root.join(hooks))
}

/// True when the hook git would run for `repo_root` invokes
/// `shk scan --staged` on a line that is not commented out and, on Unix, the
/// hook file is executable (git skips hooks that are not).
pub fn has_shk_pre_commit(repo_root: &Path) -> bool {
    let hook_path = pre_commit_hook_path(repo_root);
    let Ok(meta) = fs::metadata(&hook_path) else {
        return false;
    };
    if !meta.is_file() || !is_executable(&meta) {
        return false;
    }
    fs::read_to_string(&hook_path)
        .unwrap_or_default()
        .lines()
        .any(|line| !line.trim_start().starts_with('#') && line.contains("shk scan --staged"))
}

#[cfg(unix)]
fn is_executable(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_meta: &fs::Metadata) -> bool {
    true
}

/// True when the last command of `prefix` (the hook content before the managed
/// block) is an unconditional top-level `exit` or `exec <command>`, so the
/// shell never reaches the block.
fn ends_unconditionally(prefix: &str) -> bool {
    let Some(last) = prefix.lines().rfind(|line| {
        let trimmed = line.trim();
        !trimmed.is_empty() && !trimmed.starts_with('#')
    }) else {
        return false;
    };
    // Indented lines belong to a compound command or function body.
    if last.starts_with(char::is_whitespace) {
        return false;
    }
    let mut words = last.trim_end().trim_end_matches(';').split_whitespace();
    match words.next() {
        Some("exit") => true,
        // `exec` with only redirections (`exec 2>&1`) keeps the shell running.
        Some("exec") => words.next().is_some_and(|word| {
            !word.starts_with(|c: char| c == '<' || c == '>' || c.is_ascii_digit())
        }),
        _ => false,
    }
}

fn warn_if_block_unreachable(hook_path: &Path, prefix: &str) {
    if ends_unconditionally(prefix) {
        eprintln!(
            "warning: {} ends with an unconditional `exit`/`exec` before the shk-managed block, \
             so `shk scan --staged` never runs; move that line below the block.",
            hook_path.display()
        );
    }
}

pub fn install_pre_commit(repo_root: &Path) -> Result<()> {
    let repo_root = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let hooks_dir = effective_hooks_dir(&repo_root);
    if !hooks_dir.exists() {
        bail!(
            "{} does not exist; not a git repository?",
            hooks_dir.display()
        );
    }
    if hooks_dir != repo_root.join(".git").join("hooks") {
        eprintln!(
            "note: using the effective Git hooks directory {}",
            hooks_dir.display()
        );
    }
    let hook_path = hooks_dir.join("pre-commit");
    // `core.hooksPath` and linked worktrees can place the hooks directory
    // outside the work tree; the managed root is then that directory itself.
    let write_base = if hooks_dir.starts_with(&repo_root) {
        repo_root.as_path()
    } else {
        hooks_dir.as_path()
    };
    safety::ensure_write_path_within(write_base, &hook_path)?;
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
            if let Some(start) = existing.find(MANAGED_START) {
                warn_if_block_unreachable(&hook_path, &existing[..start]);
            }
            let updated = replace_managed_block(&existing, &block);
            if updated != existing {
                crate::fs_atomic::write_atomic(&hook_path, updated.as_bytes())?;
            }
            ensure_executable(&hook_path)?;
            return Ok(());
        }
        if !is_sh_compatible_hook(&existing) {
            bail!(
                "{} has a non-POSIX-shell shebang ({}); refusing to append shell code. \
                 Invoke `shk scan --staged` from your existing hook instead.",
                hook_path.display(),
                existing.lines().next().unwrap_or("").trim()
            );
        }
        warn_if_block_unreachable(&hook_path, &existing);
        let needs_newline = !existing.ends_with('\n');
        let mut updated = existing;
        if needs_newline {
            updated.push('\n');
        }
        updated.push_str(&block);
        crate::fs_atomic::write_atomic(&hook_path, updated.as_bytes())?;
        ensure_executable(&hook_path)?;
        return Ok(());
    }
    let mut script = String::new();
    script.push_str("#!/bin/sh\n");
    script.push_str(&block);
    crate::fs_atomic::write_atomic(&hook_path, script.as_bytes())?;
    ensure_executable(&hook_path)?;
    Ok(())
}

/// A hook without a shebang is executed via sh by git, so it is sh-compatible.
/// A hook with a shebang is only safe to append POSIX shell code to when the
/// interpreter is a Bourne-style shell (sh/bash/dash/ksh/zsh).
fn is_sh_compatible_hook(existing: &str) -> bool {
    let first = existing.lines().next().unwrap_or("").trim();
    let Some(shebang) = first.strip_prefix("#!") else {
        return true;
    };
    let mut parts = shebang.split_whitespace();
    let interpreter = match parts.next() {
        Some(cmd) if cmd.ends_with("/env") => parts.next().unwrap_or(""),
        Some(cmd) => cmd.rsplit('/').next().unwrap_or(cmd),
        None => return true,
    };
    matches!(interpreter, "sh" | "bash" | "dash" | "ksh" | "zsh")
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
    fn sh_compatible_hook_detection() {
        assert!(is_sh_compatible_hook("#!/bin/sh\necho hi\n"));
        assert!(is_sh_compatible_hook("#!/bin/bash\necho hi\n"));
        assert!(is_sh_compatible_hook("#!/usr/bin/env bash\necho hi\n"));
        assert!(is_sh_compatible_hook("#!/usr/bin/env zsh\n"));
        assert!(is_sh_compatible_hook("echo no shebang\n"));
        assert!(is_sh_compatible_hook(""));

        assert!(!is_sh_compatible_hook("#!/usr/bin/env python3\nprint(1)\n"));
        assert!(!is_sh_compatible_hook("#!/usr/bin/python\n"));
        assert!(!is_sh_compatible_hook("#!/usr/bin/env node\n"));
        assert!(!is_sh_compatible_hook("#!/usr/bin/perl -w\n"));
    }

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

    fn git(dir: &Path, args: &[&str]) {
        let out = std::process::Command::new("git")
            .args(args)
            .current_dir(dir)
            .output()
            .expect("run git");
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// A repository-shaped directory git itself does not recognise, so the
    /// `.git/hooks` fallback is exercised.
    fn fake_repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".git/hooks")).unwrap();
        dir
    }

    #[cfg(unix)]
    fn make_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn failing_scan_fails_the_hook_even_when_content_follows_the_block() {
        let repo = fake_repo();
        install_pre_commit(repo.path()).unwrap();
        let hook = repo.path().join(".git/hooks/pre-commit");
        let mut body = fs::read_to_string(&hook).unwrap();
        body.push_str("echo after\nexit 0\n");
        fs::write(&hook, body).unwrap();

        let bin = repo.path().join("bin");
        fs::create_dir(&bin).unwrap();
        fs::write(bin.join("shk"), "#!/bin/sh\nexit 1\n").unwrap();
        make_executable(&bin.join("shk"));

        let out = std::process::Command::new("/bin/sh")
            .arg(&hook)
            .env("PATH", &bin)
            .current_dir(repo.path())
            .output()
            .unwrap();

        assert_eq!(out.status.code(), Some(1), "{out:?}");
        assert!(!String::from_utf8_lossy(&out.stdout).contains("after"));
    }

    #[test]
    fn old_managed_block_is_upgraded_to_propagate_failure() {
        let repo = fake_repo();
        let hook = repo.path().join(".git/hooks/pre-commit");
        fs::write(
            &hook,
            "#!/bin/sh\n# shk-managed-start\nif command -v shk >/dev/null 2>&1; then\n  shk scan --staged\nfi\n# shk-managed-end\necho user-tail\n",
        )
        .unwrap();

        install_pre_commit(repo.path()).unwrap();

        let body = fs::read_to_string(&hook).unwrap();
        assert!(body.contains("  shk scan --staged || exit $?\n"), "{body}");
        assert!(
            body.contains("-- scan --staged || exit $?\n"),
            "cargo branch must propagate too: {body}"
        );
        assert!(
            body.ends_with("# shk-managed-end\necho user-tail\n"),
            "{body}"
        );
        assert_eq!(body.matches(MANAGED_START).count(), 1, "{body}");
    }

    #[test]
    fn unconditional_exit_or_exec_before_the_block_is_detected() {
        assert!(ends_unconditionally("#!/bin/sh\nrun-lint\nexit 0\n"));
        assert!(ends_unconditionally(
            "#!/bin/sh\nexit\n\n# trailing comment\n"
        ));
        assert!(ends_unconditionally(
            "#!/bin/sh\nexec lefthook run pre-commit\n"
        ));
        assert!(ends_unconditionally("exit $status;\n"));

        assert!(!ends_unconditionally("#!/bin/sh\n"));
        assert!(!ends_unconditionally("#!/bin/sh\nrun-lint || exit 1\n"));
        assert!(!ends_unconditionally(
            "#!/bin/sh\nif x; then\n  exit 1\nfi\n"
        ));
        assert!(!ends_unconditionally("f() {\n  exit 1\n}\n"));
        assert!(!ends_unconditionally("#!/bin/sh\nexec 2>&1\n"));
        assert!(!ends_unconditionally("#!/bin/sh\nexec >/dev/null\n"));
        assert!(!ends_unconditionally("#!/bin/sh\nexit_code=0\n"));
    }

    #[test]
    fn install_and_detection_follow_core_hooks_path() {
        let repo = tempfile::tempdir().unwrap();
        git(repo.path(), &["init", "-q"]);
        git(repo.path(), &["config", "core.hooksPath", ".githooks"]);
        fs::create_dir(repo.path().join(".githooks")).unwrap();
        assert!(!has_shk_pre_commit(repo.path()));

        install_pre_commit(repo.path()).unwrap();

        let hook = repo.path().join(".githooks/pre-commit");
        assert!(hook.is_file(), "hook must land in core.hooksPath");
        assert!(!repo.path().join(".git/hooks/pre-commit").exists());
        assert!(has_shk_pre_commit(repo.path()));
    }

    #[test]
    fn detection_ignores_default_hook_when_core_hooks_path_points_elsewhere() {
        let repo = tempfile::tempdir().unwrap();
        git(repo.path(), &["init", "-q"]);
        install_pre_commit(repo.path()).unwrap();
        assert!(has_shk_pre_commit(repo.path()));

        git(repo.path(), &["config", "core.hooksPath", ".githooks"]);

        assert!(!has_shk_pre_commit(repo.path()));
    }

    #[test]
    fn install_and_detection_work_when_dot_git_is_a_file() {
        let base = tempfile::tempdir().unwrap();
        let work = base.path().join("work");
        let git_dir = base.path().join("separate.git");
        fs::create_dir(&work).unwrap();
        git(
            &work,
            &[
                "init",
                "-q",
                "--separate-git-dir",
                git_dir.to_str().unwrap(),
            ],
        );
        assert!(work.join(".git").is_file());
        fs::create_dir_all(git_dir.join("hooks")).unwrap();

        install_pre_commit(&work).unwrap();

        assert!(git_dir.join("hooks/pre-commit").is_file());
        assert!(has_shk_pre_commit(&work));
    }

    #[test]
    fn detection_ignores_a_commented_out_shk_line() {
        let repo = fake_repo();
        let hook = repo.path().join(".git/hooks/pre-commit");
        fs::write(&hook, "#!/bin/sh\n# shk scan --staged\n").unwrap();
        #[cfg(unix)]
        make_executable(&hook);

        assert!(!has_shk_pre_commit(repo.path()));

        fs::write(&hook, "#!/bin/sh\nshk scan --staged\n").unwrap();
        #[cfg(unix)]
        make_executable(&hook);
        assert!(has_shk_pre_commit(repo.path()));
    }

    #[cfg(unix)]
    #[test]
    fn detection_requires_the_executable_bit() {
        use std::os::unix::fs::PermissionsExt;

        let repo = fake_repo();
        let hook = repo.path().join(".git/hooks/pre-commit");
        fs::write(&hook, "#!/bin/sh\nshk scan --staged\n").unwrap();
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o644)).unwrap();

        assert!(!has_shk_pre_commit(repo.path()));
    }
}
