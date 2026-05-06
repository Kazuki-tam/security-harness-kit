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
fn hook_mode_audit_creates_audit_log_in_isolated_tmp() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
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
