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
    assert!(s.contains(".cursor/hooks.json"), "{s}");
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
    std::fs::write(
        &fpath,
        r#"const demo = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";"#,
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
