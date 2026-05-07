use std::path::PathBuf;
use std::process::Command;

fn shk_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_shk"))
}

#[test]
fn scan_basic_fixture() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("fixtures/basic");
    let out = Command::new(shk_bin())
        .args([
            "scan",
            &root.display().to_string(),
            "--json",
            "--fail-on",
            "critical",
        ])
        .output()
        .expect("run shk");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    let findings = v["findings"].as_array().expect("findings array");
    assert!(
        findings
            .iter()
            .any(|f| f["rule_id"] == "secret.openai_api_key"),
        "expected openai rule hit: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn mask_stdin_fixture() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("fixtures/pii.txt");
    let data = std::fs::read_to_string(&fixture).unwrap();
    let out = Command::new(shk_bin())
        .args(["mask", "--json"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            use std::io::Write;
            c.stdin.as_mut().unwrap().write_all(data.as_bytes())?;
            c.wait_with_output()
        })
        .expect("mask");
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(!v["findings"].as_array().unwrap().is_empty());
}

#[test]
fn mask_partial_redaction_json_preserves_edges() {
    use std::io::Write;

    // not real credential: synthetic detector fixture value only
    let secret = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";
    let out = Command::new(shk_bin())
        .args(["mask", "--json", "--redaction", "partial"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            c.stdin
                .as_mut()
                .unwrap()
                .write_all(format!("token={secret}\n").as_bytes())?;
            c.wait_with_output()
        })
        .expect("partial mask");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let masked = v["masked_content"].as_str().unwrap_or_default();
    assert!(masked.contains("sk-p[REDACTED]6789"), "{masked}");
    assert!(!masked.contains(secret), "{masked}");
}

#[test]
fn mask_binary_stdin_passes_through() {
    use std::io::Write;

    let data = b"abc\0def".to_vec();
    let out = Command::new(shk_bin())
        .args(["mask"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            c.stdin.as_mut().unwrap().write_all(&data)?;
            c.wait_with_output()
        })
        .expect("mask binary");
    assert!(out.status.success());
    assert_eq!(out.stdout, data);
}

#[test]
fn mask_hook_mode_cursor_returns_masked_content() {
    use std::io::Write;

    // not real credential: synthetic detector fixture value only
    let secret = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";
    let stdin = serde_json::to_string(&serde_json::json!({
        "prompt": format!("please inspect this token: {secret}")
    }))
    .unwrap();
    let out = Command::new(shk_bin())
        .args(["mask", "--hook-mode", "cursor"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            c.stdin.as_mut().unwrap().write_all(stdin.as_bytes())?;
            c.wait_with_output()
        })
        .expect("mask hook");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["permission"], "allow");
    let masked = v["masked_content"].as_str().unwrap_or_default();
    assert!(masked.contains("[REDACTED_LINE]"), "{masked}");
    assert!(!masked.contains(secret), "{masked}");
}

#[test]
fn mask_hook_mode_clean_payload_does_not_echo_content() {
    use std::io::Write;

    let clean = "ordinary project note without sensitive values";
    let stdin = serde_json::to_string(&serde_json::json!({
        "prompt": clean
    }))
    .unwrap();
    let out = Command::new(shk_bin())
        .args(["mask", "--hook-mode", "cursor"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            c.stdin.as_mut().unwrap().write_all(stdin.as_bytes())?;
            c.wait_with_output()
        })
        .expect("mask hook");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["permission"], "allow");
    assert!(v.get("masked_content").is_none(), "{v}");
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains(clean),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn scan_json_reports_suppressed_field() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("fixtures/basic");
    let out = Command::new(shk_bin())
        .args([
            "scan",
            &root.display().to_string(),
            "--json",
            "--fail-on",
            "critical",
        ])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v.get("suppressed").is_some(), "{v}");
}

#[test]
fn scan_human_output_hides_skip_details_by_default() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("blob.dat"), b"abc\0def").unwrap();

    let out = Command::new(shk_bin())
        .args([
            "scan",
            &dir.path().display().to_string(),
            "--fail-on",
            "critical",
        ])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("0 findings"), "{stdout}");
    assert!(
        stdout.contains("Skipped 1 files; use --verbose to show details."),
        "{stdout}"
    );
    assert!(!stdout.contains("scan.binary_skipped"), "{stdout}");
}

#[test]
fn scan_verbose_human_output_shows_skip_details() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("blob.dat"), b"abc\0def").unwrap();

    let out = Command::new(shk_bin())
        .args([
            "scan",
            &dir.path().display().to_string(),
            "--fail-on",
            "critical",
            "--verbose",
        ])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("1 findings"), "{stdout}");
    assert!(stdout.contains("scan.binary_skipped"), "{stdout}");
}

#[test]
fn scan_detects_custom_rule_from_policy() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("shk.toml"),
        r#"
[rules]
internal_terms = true

[[custom_rules]]
id = "internal.project_codename"
pattern = "ProjectNebula|社外秘"
severity = "high"
kind = "internal"
message = "Internal confidential term detected"
"#,
    )
    .unwrap();
    std::fs::write(dir.path().join("notes.txt"), "launch ProjectNebula\n").unwrap();

    let out = Command::new(shk_bin())
        .args(["scan", ".", "--json", "--fail-on", "critical"])
        .current_dir(dir.path())
        .output()
        .expect("scan custom");

    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let findings = v["findings"].as_array().unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f["rule_id"] == "internal.project_codename"),
        "{v}"
    );
    assert!(!String::from_utf8_lossy(&out.stdout).contains("ProjectNebula"));
}

#[test]
fn scan_target_uses_current_dir_policy() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("src")).unwrap();
    std::fs::write(
        dir.path().join("shk.toml"),
        r#"
[rules]
internal_terms = true

[[custom_rules]]
id = "internal.project_codename"
pattern = "ProjectNebula"
severity = "high"
kind = "internal"
"#,
    )
    .unwrap();
    std::fs::write(dir.path().join("src/notes.txt"), "launch ProjectNebula\n").unwrap();

    let out = Command::new(shk_bin())
        .args(["scan", "src", "--json", "--fail-on", "critical"])
        .current_dir(dir.path())
        .output()
        .expect("scan target");

    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["rule_id"] == "internal.project_codename"),
        "{v}"
    );
}

#[test]
fn scan_rejects_invalid_fail_on() {
    let out = Command::new(shk_bin())
        .args(["scan", ".", "--fail-on", "critcal"])
        .output()
        .expect("scan invalid fail-on");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("invalid --fail-on severity"), "{stderr}");
}

#[test]
fn scan_staged_outside_git_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(shk_bin())
        .args(["scan", "--staged"])
        .current_dir(dir.path())
        .output()
        .expect("scan staged outside git");
    assert_eq!(
        out.status.code(),
        Some(2),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("shk scan --staged requires a Git repository"),
        "{stderr}"
    );
}

#[test]
fn scan_staged_reads_index_not_worktree() {
    let dir = tempfile::tempdir().unwrap();
    let init = Command::new("git")
        .args(["init"])
        .current_dir(dir.path())
        .output()
        .expect("git init");
    assert!(
        init.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );
    let path = dir.path().join("secret.txt");
    std::fs::write(
        &path,
        // not real credential: synthetic detector fixture value only
        "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789\n",
    )
    .unwrap();
    Command::new("git")
        .args(["add", "secret.txt"])
        .current_dir(dir.path())
        .output()
        .expect("git add");
    std::fs::write(&path, "clean worktree\n").unwrap();

    let out = Command::new(shk_bin())
        .args(["scan", "--staged", "--json"])
        .current_dir(dir.path())
        .output()
        .expect("scan staged");

    assert_eq!(
        out.status.code(),
        Some(1),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["rule_id"] == "secret.openai_api_key"),
        "{v}"
    );
}

#[test]
fn scan_staged_works_from_repo_subdirectory() {
    let dir = tempfile::tempdir().unwrap();
    let init = Command::new("git")
        .args(["init"])
        .current_dir(dir.path())
        .output()
        .expect("git init");
    assert!(
        init.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );
    std::fs::create_dir(dir.path().join("src")).unwrap();
    std::fs::write(
        dir.path().join("src/secret.txt"),
        // not real credential: synthetic detector fixture value only
        "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789\n",
    )
    .unwrap();
    Command::new("git")
        .args(["add", "src/secret.txt"])
        .current_dir(dir.path())
        .output()
        .expect("git add");

    let out = Command::new(shk_bin())
        .args(["scan", "--staged", "--json"])
        .current_dir(dir.path().join("src"))
        .output()
        .expect("scan staged from subdir");

    assert_eq!(
        out.status.code(),
        Some(1),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn hooks_install_ai_dry_run_cursor() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let out = Command::new(shk_bin())
        .args(["hooks", "install-ai", "--tool", "cursor", "--dry-run"])
        .current_dir(&root)
        .output()
        .expect("install-ai");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.replace('\\', "/").contains(".cursor/hooks.json"), "{s}");
}

#[test]
fn hook_mode_cursor_blocks_with_exit_2() {
    use std::io::Write;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let fixture = std::fs::canonicalize(root.join("fixtures/basic/insecure-sample.txt")).unwrap();
    let stdin = serde_json::to_string(&serde_json::json!({
        "file_path": fixture.to_str().unwrap(),
    }))
    .unwrap();
    let out = Command::new(shk_bin())
        .args(["scan", ".", "--hook-mode", "cursor"])
        .current_dir(&root)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            c.stdin.as_mut().unwrap().write_all(stdin.as_bytes())?;
            c.wait_with_output()
        })
        .expect("hook scan");
    assert_eq!(
        out.status.code(),
        Some(2),
        "stdout={}",
        String::from_utf8_lossy(&out.stdout)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("deny"), "{s}");
}

#[test]
fn hook_mode_ignores_file_paths_outside_repo_root() {
    use std::io::Write;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let outside = tempfile::NamedTempFile::new().unwrap();
    // not real credential: synthetic detector fixture value only
    std::fs::write(
        outside.path(),
        "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789\n",
    )
    .unwrap();
    let stdin = serde_json::to_string(&serde_json::json!({
        "file_path": outside.path().to_str().unwrap(),
    }))
    .unwrap();
    let out = Command::new(shk_bin())
        .args(["scan", ".", "--hook-mode", "cursor"])
        .current_dir(&root)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            c.stdin.as_mut().unwrap().write_all(stdin.as_bytes())?;
            c.wait_with_output()
        })
        .expect("hook scan");
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(stdout["permission"], "allow");
}

#[test]
fn hook_mode_audit_creates_audit_log_in_isolated_tmp() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    std::fs::write(repo.join("shk.toml"), "").unwrap();
    let fpath = repo.join("x.txt");
    // not real credential: synthetic detector fixture value only
    std::fs::write(
        &fpath,
        "// not real credential: synthetic detector fixture value only\nconst demo = \"sk-proj-abcdefghijklmnopqrstuvwxyz0123456789\";",
    )
    .unwrap();
    let stdin = serde_json::to_string(&serde_json::json!({
        "file_path": fpath.to_str().unwrap(),
    }))
    .unwrap();
    let out = Command::new(shk_bin())
        .args(["scan", ".", "--hook-mode", "cursor", "--audit"])
        .current_dir(repo)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            c.stdin.as_mut().unwrap().write_all(stdin.as_bytes())?;
            c.wait_with_output()
        })
        .expect("audit hook");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        repo.join(".shk/audit.log").is_file(),
        "missing audit log {:?}",
        repo.join(".shk")
    );
    let stdout: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(stdout["permission"], "allow");
    assert!(
        stdout["user_message"]
            .as_str()
            .unwrap_or_default()
            .contains("shk audit: non-blocking"),
        "{stdout}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("shk audit: findings=1"), "{stderr}");
}

#[test]
fn hook_mode_post_warns_but_exits_0() {
    use std::io::Write;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let secret = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";
    let stdin = serde_json::to_string(&serde_json::json!({
        "content": format!("tool returned token {secret}"),
    }))
    .unwrap();
    let out = Command::new(shk_bin())
        .args(["scan", ".", "--hook-mode", "cursor", "--post"])
        .current_dir(&root)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            c.stdin.as_mut().unwrap().write_all(stdin.as_bytes())?;
            c.wait_with_output()
        })
        .expect("post hook");
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(stdout["permission"], "allow");
    let msg = stdout["user_message"].as_str().unwrap_or_default();
    assert!(msg.contains("finding(s) in tool output"), "{msg}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("finding(s) in tool output"), "{stderr}");
}

#[test]
fn init_creates_project_policy() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(shk_bin())
        .args(["init"])
        .current_dir(dir.path())
        .output()
        .expect("init");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(dir.path().join("shk.toml").is_file());
}

#[test]
fn mask_output_requires_project_policy() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.txt");
    let output = dir.path().join("output.txt");
    std::fs::write(&input, "hello@example.com\n").unwrap();
    let out = Command::new(shk_bin())
        .args([
            "mask",
            input.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ])
        .current_dir(dir.path())
        .output()
        .expect("mask output");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("requires a project shk.toml"), "{stderr}");
    assert!(!output.exists());
}

#[test]
fn mask_output_refuses_protected_home_config() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let input = project.path().join("input.txt");
    let zshrc = home.path().join(".zshrc");
    std::fs::write(project.path().join("shk.toml"), "").unwrap();
    std::fs::write(&input, "hello@example.com\n").unwrap();
    std::fs::write(&zshrc, "original\n").unwrap();

    let out = Command::new(shk_bin())
        .args([
            "mask",
            input.to_str().unwrap(),
            "--output",
            zshrc.to_str().unwrap(),
        ])
        .env("HOME", home.path())
        .current_dir(project.path())
        .output()
        .expect("mask protected output");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("protected home configuration"), "{stderr}");
    assert_eq!(std::fs::read_to_string(&zshrc).unwrap(), "original\n");
}

#[test]
fn mask_output_refuses_tilde_home_config() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let input = project.path().join("input.txt");
    let zshrc = home.path().join(".zshrc");
    std::fs::write(project.path().join("shk.toml"), "").unwrap();
    std::fs::write(&input, "hello@example.com\n").unwrap();
    std::fs::write(&zshrc, "original\n").unwrap();

    let out = Command::new(shk_bin())
        .args(["mask", input.to_str().unwrap(), "--output", "~/.zshrc"])
        .env("HOME", home.path())
        .current_dir(project.path())
        .output()
        .expect("mask tilde protected output");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("protected home configuration"), "{stderr}");
    assert_eq!(std::fs::read_to_string(&zshrc).unwrap(), "original\n");
}

#[test]
fn mask_output_refuses_env_files() {
    let project = tempfile::tempdir().unwrap();
    let input = project.path().join("input.txt");
    let dotenv = project.path().join(".env");
    let dotenv_local = project.path().join(".env.local");
    std::fs::write(project.path().join("shk.toml"), "").unwrap();
    std::fs::write(&input, "hello@example.com\n").unwrap();
    std::fs::write(&dotenv, "SECRET=original\n").unwrap();

    for output in [&dotenv, &dotenv_local] {
        let out = Command::new(shk_bin())
            .args([
                "mask",
                input.to_str().unwrap(),
                "--output",
                output.to_str().unwrap(),
            ])
            .current_dir(project.path())
            .output()
            .expect("mask env output");
        assert!(!out.status.success());
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("sensitive env file"), "{stderr}");
    }
    assert_eq!(
        std::fs::read_to_string(&dotenv).unwrap(),
        "SECRET=original\n"
    );
    assert!(!dotenv_local.exists());
}

#[test]
fn hooks_install_requires_project_policy() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".git")).unwrap();
    let out = Command::new(shk_bin())
        .args(["hooks", "install"])
        .current_dir(dir.path())
        .output()
        .expect("hooks install");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("requires a project shk.toml"), "{stderr}");
    assert!(!dir.path().join(".git/hooks/pre-commit").exists());
}

#[cfg(unix)]
#[test]
fn hooks_install_makes_existing_pre_commit_executable() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let init = Command::new("git")
        .args(["init"])
        .current_dir(dir.path())
        .output()
        .expect("git init");
    assert!(
        init.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );
    std::fs::write(dir.path().join("shk.toml"), "").unwrap();
    std::fs::create_dir_all(dir.path().join(".git/hooks")).unwrap();
    let hook = dir.path().join(".git/hooks/pre-commit");
    std::fs::write(&hook, "#!/bin/sh\necho existing\n").unwrap();
    let mut perms = std::fs::metadata(&hook).unwrap().permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(&hook, perms).unwrap();

    let out = Command::new(shk_bin())
        .args(["hooks", "install"])
        .current_dir(dir.path())
        .output()
        .expect("hooks install");

    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mode = std::fs::metadata(&hook).unwrap().permissions().mode();
    assert_ne!(mode & 0o111, 0, "mode={mode:o}");
    assert_eq!(mode & 0o077, 0, "mode={mode:o}");
}

#[test]
fn doctor_env_reports_findings_without_values() {
    let dir = tempfile::tempdir().unwrap();
    let secret = "abcdefghijklmnop";
    std::fs::write(dir.path().join(".env"), format!("api_key={secret}\n")).unwrap();
    let out = Command::new(shk_bin())
        .args(["doctor", "env", dir.path().to_str().unwrap()])
        .output()
        .expect("doctor env");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(".env (1 finding(s))"), "{stdout}");
    assert!(!stdout.contains(secret), "{stdout}");
}

#[test]
fn doctor_version_reports_update_available_from_env() {
    let out = Command::new(shk_bin())
        .args(["doctor", "version"])
        .env("SHK_UPDATE_CHECK_LATEST_TAG", "v0.1.1")
        .env_remove("SHK_UPDATE_CHECK_URL")
        .output()
        .expect("doctor version");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("version: update available"), "{stdout}");
    assert!(stdout.contains("current: 0.1.0"), "{stdout}");
    assert!(stdout.contains("latest:  v0.1.1"), "{stdout}");
}

#[test]
fn doctor_version_json_reports_current_status_from_env() {
    let out = Command::new(shk_bin())
        .args(["doctor", "--json", "version"])
        .env("SHK_UPDATE_CHECK_LATEST_TAG", "v0.1.0")
        .env_remove("SHK_UPDATE_CHECK_URL")
        .output()
        .expect("doctor version json");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["current"], "0.1.0");
    assert_eq!(v["latest"], "v0.1.0");
    assert_eq!(v["status"], "current");
    assert_eq!(v["update_available"], false);
}

#[test]
fn doctor_env_dotenvx_flags_private_key_artifacts() {
    let dir = tempfile::tempdir().unwrap();
    let private_key = "DOTENV_PRIVATE_KEY=dotenvx-secret-demo-value";
    std::fs::write(dir.path().join(".env.keys"), private_key).unwrap();
    std::fs::write(dir.path().join(".env.vault"), "DOTENV_VAULT=encrypted").unwrap();
    let out = Command::new(shk_bin())
        .args(["doctor", "env", dir.path().to_str().unwrap(), "--dotenvx"])
        .output()
        .expect("doctor env dotenvx");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(".env.keys (private key material"),
        "{stdout}"
    );
    assert!(
        stdout.contains("warning: .env.keys should be stored outside"),
        "{stdout}"
    );
    assert!(!stdout.contains("dotenvx-secret-demo-value"), "{stdout}");
}

#[test]
fn doctor_env_dotenvx_accepts_vault_without_keys() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".env.vault"), "DOTENV_VAULT=encrypted").unwrap();
    let out = Command::new(shk_bin())
        .args(["doctor", "env", dir.path().to_str().unwrap(), "--dotenvx"])
        .output()
        .expect("doctor env dotenvx");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(".env.vault (encrypted vault"), "{stdout}");
    assert!(
        stdout.contains("ok: encrypted vault present without local .env.keys"),
        "{stdout}"
    );
}

#[test]
fn doctor_ignore_fix_adds_extended_recommended_patterns() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("shk.toml"), "").unwrap();
    std::fs::write(dir.path().join(".gitignore"), "node_modules/\n").unwrap();
    let out = Command::new(shk_bin())
        .args(["doctor", "ignore", dir.path().to_str().unwrap(), "--fix"])
        .output()
        .expect("doctor ignore fix");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let body = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
    assert!(body.contains("*.p12"), "{body}");
    assert!(body.contains("*.mobileprovision"), "{body}");
    assert!(body.contains("*.log"), "{body}");
}

#[test]
fn doctor_ignore_reports_missing_claude_read_denies() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".claude")).unwrap();
    std::fs::write(
        dir.path().join(".claude/settings.json"),
        r#"{"permissions":{"deny":["Read(./.env)"]}}"#,
    )
    .unwrap();
    let out = Command::new(shk_bin())
        .args(["doctor", "ignore", dir.path().to_str().unwrap()])
        .output()
        .expect("doctor ignore");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("claude permissions: missing recommended Read deny entries"),
        "{stdout}"
    );
    assert!(stdout.contains("Read(./secrets/**)"), "{stdout}");
}

#[test]
fn doctor_ignore_accepts_claude_read_denies() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".claude")).unwrap();
    std::fs::write(
        dir.path().join(".claude/settings.json"),
        r#"{"permissions":{"deny":["Read(./.env)","Read(./.env.*)","Read(./secrets/**)","Read(./credentials/**)"]}}"#,
    )
    .unwrap();
    let out = Command::new(shk_bin())
        .args(["doctor", "ignore", dir.path().to_str().unwrap()])
        .output()
        .expect("doctor ignore");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("claude permissions: OK (sensitive reads denied)"),
        "{stdout}"
    );
}

#[test]
fn doctor_ignore_reports_codex_risky_config() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".codex")).unwrap();
    std::fs::write(
        dir.path().join(".codex/config.toml"),
        r#"
sandbox_mode = "danger-full-access"
approval_policy = "never"
"#,
    )
    .unwrap();
    let out = Command::new(shk_bin())
        .args(["doctor", "ignore", dir.path().to_str().unwrap()])
        .output()
        .expect("doctor ignore");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("codex config: hooks feature not enabled"),
        "{stdout}"
    );
    assert!(
        stdout.contains("codex config: warning sandbox_mode=danger-full-access"),
        "{stdout}"
    );
    assert!(
        stdout.contains("codex config: warning approval_policy=never"),
        "{stdout}"
    );
}

#[test]
fn doctor_ignore_reports_codex_conservative_config() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".codex")).unwrap();
    std::fs::write(
        dir.path().join(".codex/config.toml"),
        r#"
sandbox_mode = "workspace-write"
approval_policy = "on-request"

[features]
codex_hooks = true
"#,
    )
    .unwrap();
    let out = Command::new(shk_bin())
        .args(["doctor", "ignore", dir.path().to_str().unwrap()])
        .output()
        .expect("doctor ignore");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("codex config: hooks feature enabled"),
        "{stdout}"
    );
    assert!(
        stdout.contains("codex config: sandbox_mode=workspace-write"),
        "{stdout}"
    );
    assert!(
        stdout.contains("codex config: approval_policy=on-request"),
        "{stdout}"
    );
}
