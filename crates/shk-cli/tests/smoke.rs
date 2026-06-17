use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use shk_integrations::USER_PROMPT_HOOK_FAIL_ON;

fn codex_managed_hook_section<'a>(body: &'a str, event: &str, next_event: &str) -> &'a str {
    let start = format!("[[hooks.{event}]]");
    let end = format!("[[hooks.{next_event}]]");
    body.split(&start)
        .nth(1)
        .and_then(|section| section.split(&end).next())
        .unwrap_or("")
}

fn shk_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_shk"))
}

fn synthetic_openai_key(seed: char) -> String {
    format!("sk-proj-{seed}bcdefghijklmnopqrstuvwxyz0123456789")
}

fn init_git_repo(dir: &Path) {
    let init = Command::new("git")
        .args(["init"])
        .current_dir(dir)
        .output()
        .expect("git init");
    assert!(
        init.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );
}

fn git_commit_all(dir: &Path, message: &str) {
    let add = Command::new("git")
        .args(["add", "-A"])
        .current_dir(dir)
        .output()
        .expect("git add");
    assert!(
        add.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&add.stdout),
        String::from_utf8_lossy(&add.stderr)
    );

    let commit = Command::new("git")
        .args([
            "-c",
            "user.name=shk test",
            "-c",
            "user.email=shk@example.invalid",
            "commit",
            "-m",
            message,
        ])
        .current_dir(dir)
        .output()
        .expect("git commit");
    assert!(
        commit.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&commit.stdout),
        String::from_utf8_lossy(&commit.stderr)
    );
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
    assert!(
        findings.iter().all(|f| f.get("value_hash").is_none()),
        "value_hash should be opt-in: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn scan_sarif_outputs_code_scanning_shape() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("fixtures/basic");
    let out = Command::new(shk_bin())
        .args([
            "scan",
            &root.display().to_string(),
            "--sarif",
            "--fail-on",
            "critical",
        ])
        .output()
        .expect("run shk sarif");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("sarif json");
    assert_eq!(v["version"], "2.1.0");
    let results = v["runs"][0]["results"].as_array().expect("sarif results");
    assert!(
        results
            .iter()
            .any(|r| r["ruleId"] == "secret.openai_api_key"),
        "expected openai rule hit: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        results
            .iter()
            .all(|r| r["properties"].get("valueHash").is_none()),
        "valueHash should be opt-in: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn scan_with_value_hash_requires_machine_output() {
    let out = Command::new(shk_bin())
        .args(["scan", ".", "--with-value-hash"])
        .output()
        .expect("run scan with invalid value hash mode");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("`--with-value-hash` requires `--json` or `--sarif`"),
        "{stderr}"
    );
}

#[test]
fn scan_changed_since_limits_scan_to_changed_files() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_git_repo(tmp.path());
    std::fs::write(tmp.path().join("old.txt"), synthetic_openai_key('a')).expect("write old");
    git_commit_all(tmp.path(), "initial");

    std::fs::write(tmp.path().join("new.txt"), synthetic_openai_key('b')).expect("write new");
    git_commit_all(tmp.path(), "add new");

    let out = Command::new(shk_bin())
        .args([
            "scan",
            ".",
            "--changed-since",
            "HEAD~1",
            "--json",
            "--fail-on",
            "critical",
        ])
        .current_dir(tmp.path())
        .output()
        .expect("run changed-since scan");
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    let scanned = v["scanned_paths"].as_array().expect("scanned paths");
    assert_eq!(scanned, &vec![serde_json::json!("new.txt")]);
}

#[test]
fn scan_changed_since_allows_missing_path_as_repo_hint() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_git_repo(tmp.path());
    std::fs::write(tmp.path().join("README.md"), "clean\n").expect("write readme");
    git_commit_all(tmp.path(), "initial");

    let out = Command::new(shk_bin())
        .args([
            "scan",
            "does-not-exist",
            "--changed-since",
            "HEAD",
            "--json",
            "--fail-on",
            "critical",
        ])
        .current_dir(tmp.path())
        .output()
        .expect("run changed-since from missing path");
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert!(v["scanned_paths"].as_array().unwrap().is_empty(), "{v}");
}

#[cfg(unix)]
#[test]
fn scan_changed_since_does_not_follow_symlinks_by_default() {
    let tmp = tempfile::tempdir().expect("tempdir");
    init_git_repo(tmp.path());
    std::fs::write(tmp.path().join("README.md"), "clean\n").expect("write readme");
    git_commit_all(tmp.path(), "initial");

    let outside = tmp.path().with_extension("outside-secret");
    std::fs::write(&outside, synthetic_openai_key('d')).expect("write outside secret");
    std::os::unix::fs::symlink(&outside, tmp.path().join("linked.txt")).expect("symlink");
    git_commit_all(tmp.path(), "add symlink");

    let out = Command::new(shk_bin())
        .args([
            "scan",
            ".",
            "--changed-since",
            "HEAD~1",
            "--json",
            "--fail-on",
            "high",
        ])
        .current_dir(tmp.path())
        .output()
        .expect("run changed-since scan");
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert!(
        v["findings"].as_array().unwrap().is_empty(),
        "symlink target should not be scanned by default: {v}"
    );
    assert!(
        v["scanned_paths"].as_array().unwrap().is_empty(),
        "symlink should not be reported as scanned when follow_symlinks=false: {v}"
    );
}

#[test]
fn allowlist_suggest_prints_safe_toml_from_scan_json() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let secret = synthetic_openai_key('c');
    std::fs::write(tmp.path().join("demo.env"), format!("TOKEN={secret}\n")).expect("write demo");
    let report = tmp.path().join("report.json");
    let scan = Command::new(shk_bin())
        .args([
            "scan",
            ".",
            "--json",
            "--with-value-hash",
            "--fail-on",
            "critical",
        ])
        .current_dir(tmp.path())
        .output()
        .expect("run scan json");
    assert!(
        scan.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&scan.stderr)
    );
    std::fs::write(&report, &scan.stdout).expect("write report");

    let out = Command::new(shk_bin())
        .args([
            "allowlist",
            "suggest",
            "--from",
            &report.display().to_string(),
            "--value-hash",
            "--reason",
            "Intentional fixture",
        ])
        .output()
        .expect("run allowlist suggest");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("[[allowlist]]"), "{stdout}");
    assert!(stdout.contains("path = \"demo.env\""), "{stdout}");
    assert!(stdout.contains("value_hash = \"sha256-hmac:"), "{stdout}");
    assert!(!stdout.contains(&secret), "{stdout}");
}

#[test]
fn scan_json_reports_ai_context_findings() {
    let tmp = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        tmp.path().join("prompt.md"),
        "safe prefix \u{E0000} hidden tag\n",
    )
    .expect("write prompt");

    let out = Command::new(shk_bin())
        .args(["scan", ".", "--json", "--fail-on", "critical"])
        .current_dir(tmp.path())
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
        findings.iter().any(|f| {
            f["rule_id"] == "ai_context.unicode_tag_chars"
                && f["kind"] == "ai-context"
                && f["severity"] == "high"
                && f["redacted_value"] == "[REDACTED]"
        }),
        "expected ai-context rule hit: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn hook_audit_mode_logs_findings_but_exits_zero() {
    use std::io::Write;

    let tmp = tempfile::tempdir().expect("tempdir");
    std::fs::write(tmp.path().join("shk.toml"), "").expect("write policy");
    let secret = synthetic_openai_key('z');
    let secret_path = tmp.path().join("secret.txt");
    std::fs::write(
        &secret_path,
        format!("// not real credential: synthetic detector fixture value only\ntoken={secret}\n"),
    )
    .expect("write secret");
    let stdin = serde_json::to_string(&serde_json::json!({
        "file_path": secret_path.to_str().unwrap(),
    }))
    .expect("hook payload");

    let out = Command::new(shk_bin())
        .args(["scan", ".", "--hook-mode", "cursor", "--audit"])
        .current_dir(tmp.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child.stdin.as_mut().unwrap().write_all(stdin.as_bytes())?;
            child.wait_with_output()
        })
        .expect("run shk audit scan");
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout: serde_json::Value = serde_json::from_slice(&out.stdout).expect("hook json");
    assert_eq!(stdout["permission"], "allow");

    let audit_log = std::fs::read_to_string(tmp.path().join(".shk/audit.log")).expect("audit log");
    let entry: serde_json::Value =
        serde_json::from_str(audit_log.lines().next().expect("audit entry")).expect("audit json");
    assert!(entry["finding_count"].as_u64().unwrap_or(0) > 0, "{entry}");
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
    assert!(
        v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f.get("value_hash").is_none()),
        "mask JSON should not expose value hashes: {v}"
    );
}

#[test]
fn mask_min_severity_filters_lower_risk_findings() {
    use std::io::Write;

    let out = Command::new(shk_bin())
        .args(["mask", "--json", "--min-severity", "high"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            c.stdin
                .as_mut()
                .unwrap()
                .write_all(b"contact hello@example.com\n")?;
            c.wait_with_output()
        })
        .expect("mask with high min severity");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["masked_content"], "contact hello@example.com\n");
    assert!(v["findings"].as_array().unwrap().is_empty(), "{v}");
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
fn mask_docx_requires_output() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("report.docx");
    let secret = synthetic_openai_key('a');
    create_minimal_docx(&input, &secret);

    let out = Command::new(shk_bin())
        .args(["mask", input.to_str().unwrap()])
        .current_dir(dir.path())
        .output()
        .expect("mask docx without output");

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Office document masking requires --output"),
        "{stderr}"
    );
}

#[test]
fn mask_docx_writes_redacted_output() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("shk.toml"), "").unwrap();
    let input = dir.path().join("report.docx");
    let output = dir.path().join("report.redacted.docx");
    let secret = synthetic_openai_key('a');
    create_minimal_docx(&input, &format!("token={secret}"));

    let out = Command::new(shk_bin())
        .args([
            "mask",
            input.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
            "--json",
        ])
        .current_dir(dir.path())
        .output()
        .expect("mask docx");

    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["masked_content"], "[DOCUMENT_WRITTEN]");
    assert!(!v["findings"].as_array().unwrap().is_empty());

    let redacted = read_docx_document_xml(&output);
    assert!(redacted.contains("[REDACTED]"), "{redacted}");
    assert!(!redacted.contains(&secret), "{redacted}");

    let original = read_docx_document_xml(&input);
    assert!(original.contains(&secret), "{original}");
}

#[test]
fn mask_xlsx_writes_redacted_output() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("shk.toml"), "").unwrap();
    let input = dir.path().join("workbook.xlsx");
    let output = dir.path().join("workbook.redacted.xlsx");
    let shared_secret = synthetic_openai_key('a');
    let inline_secret = synthetic_openai_key('b');
    create_minimal_xlsx(&input, &shared_secret, &inline_secret);

    let out = Command::new(shk_bin())
        .args([
            "mask",
            input.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
            "--json",
        ])
        .current_dir(dir.path())
        .output()
        .expect("mask xlsx");

    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["masked_content"], "[DOCUMENT_WRITTEN]");
    assert!(v["findings"].as_array().unwrap().len() >= 2, "{v}");

    let shared = read_zip_entry(&output, "xl/sharedStrings.xml");
    let sheet = read_zip_entry(&output, "xl/worksheets/sheet1.xml");
    assert!(shared.contains("[REDACTED]"), "{shared}");
    assert!(sheet.contains("[REDACTED]"), "{sheet}");
    assert!(!shared.contains(&shared_secret), "{shared}");
    assert!(!sheet.contains(&inline_secret), "{sheet}");
}

#[test]
fn mask_pptx_writes_redacted_output() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("shk.toml"), "").unwrap();
    let input = dir.path().join("slides.pptx");
    let output = dir.path().join("slides.redacted.pptx");
    let secret = synthetic_openai_key('a');
    create_minimal_pptx(&input, &secret);

    let out = Command::new(shk_bin())
        .args([
            "mask",
            input.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
            "--json",
        ])
        .current_dir(dir.path())
        .output()
        .expect("mask pptx");

    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["masked_content"], "[DOCUMENT_WRITTEN]");
    assert!(!v["findings"].as_array().unwrap().is_empty());

    let slide = read_zip_entry(&output, "ppt/slides/slide1.xml");
    assert!(slide.contains("[REDACTED]"), "{slide}");
    assert!(!slide.contains(&secret), "{slide}");
}

fn deflated_zip_options() -> zip::write::FileOptions<'static, ()> {
    zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated)
}

fn create_minimal_docx(path: &Path, text: &str) {
    let file = std::fs::File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(file);

    zip.start_file("[Content_Types].xml", deflated_zip_options())
        .unwrap();
    zip.write_all(
        br#"<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#,
    )
    .unwrap();

    zip.start_file("word/document.xml", deflated_zip_options())
        .unwrap();
    write!(
        zip,
        r#"<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>"#
    )
    .unwrap();
    zip.finish().unwrap();
}

fn create_minimal_xlsx(path: &Path, shared_text: &str, inline_text: &str) {
    let file = std::fs::File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(file);

    zip.start_file("[Content_Types].xml", deflated_zip_options())
        .unwrap();
    zip.write_all(br#"<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>"#).unwrap();

    zip.start_file("xl/workbook.xml", deflated_zip_options())
        .unwrap();
    zip.write_all(br#"<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/></sheets></workbook>"#).unwrap();

    zip.start_file("xl/sharedStrings.xml", deflated_zip_options())
        .unwrap();
    write!(
        zip,
        r#"<?xml version="1.0" encoding="UTF-8"?><sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><si><t>{shared_text}</t></si></sst>"#
    )
    .unwrap();

    zip.start_file("xl/worksheets/sheet1.xml", deflated_zip_options())
        .unwrap();
    write!(
        zip,
        r#"<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>{inline_text}</t></is></c></row></sheetData></worksheet>"#
    )
    .unwrap();
    zip.finish().unwrap();
}

fn create_minimal_pptx(path: &Path, text: &str) {
    let file = std::fs::File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(file);

    zip.start_file("[Content_Types].xml", deflated_zip_options())
        .unwrap();
    zip.write_all(br#"<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>"#).unwrap();

    zip.start_file("ppt/presentation.xml", deflated_zip_options())
        .unwrap();
    zip.write_all(br#"<?xml version="1.0" encoding="UTF-8"?><p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:sldIdLst/></p:presentation>"#).unwrap();

    zip.start_file("ppt/slides/slide1.xml", deflated_zip_options())
        .unwrap();
    write!(
        zip,
        r#"<?xml version="1.0" encoding="UTF-8"?><p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>{text}</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>"#
    )
    .unwrap();
    zip.finish().unwrap();
}

fn read_docx_document_xml(path: &Path) -> String {
    read_zip_entry(path, "word/document.xml")
}

fn read_zip_entry(path: &Path, name: &str) -> String {
    let file = std::fs::File::open(path).unwrap();
    let mut zip = zip::ZipArchive::new(file).unwrap();
    let mut entry = zip.by_name(name).unwrap();
    let mut body = String::new();
    use std::io::Read;
    entry.read_to_string(&mut body).unwrap();
    body
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
    assert!(masked.contains("[REDACTED]"), "{masked}");
    assert!(masked.contains("please inspect this token:"), "{masked}");
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
fn ci_init_github_dry_run_prints_workflow() {
    let out = Command::new(shk_bin())
        .args(["ci", "init", "github", "--dry-run"])
        .output()
        .expect("ci init github dry-run");

    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Generated by shk"), "{stdout}");
    assert!(stdout.contains("gh release download"), "{stdout}");
    assert!(
        stdout.contains(concat!("release download v", env!("CARGO_PKG_VERSION"))),
        "{stdout}"
    );
    assert!(stdout.contains("sha256sum -c"), "{stdout}");
    assert!(
        stdout.contains("shk scan . --json --fail-on high"),
        "{stdout}"
    );
}

#[test]
fn ci_init_github_writes_workflow_and_refuses_overwrite() {
    let tmp = tempfile::tempdir().expect("tempdir");

    let out = Command::new(shk_bin())
        .args(["ci", "init", "github"])
        .current_dir(tmp.path())
        .output()
        .expect("ci init github");

    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let workflow_path = tmp.path().join(".github/workflows/shk.yml");
    let workflow = std::fs::read_to_string(&workflow_path).expect("workflow");
    assert!(workflow.contains("shk scan . --json --fail-on high"));
    assert!(workflow.contains("permissions:\n  contents: read"));
    assert!(workflow.contains("cancel-in-progress: true"));

    let out = Command::new(shk_bin())
        .args(["ci", "init", "github"])
        .current_dir(tmp.path())
        .output()
        .expect("ci init github overwrite");

    assert!(!out.status.success(), "overwrite should fail");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("use --force to overwrite"),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn doctor_workflows_reports_and_fixes_missing_persist_credentials() {
    let tmp = tempfile::tempdir().expect("tempdir");
    std::fs::write(tmp.path().join("shk.toml"), "").expect("write policy");
    let workflows_dir = tmp.path().join(".github/workflows");
    std::fs::create_dir_all(&workflows_dir).expect("create workflows dir");
    let workflow_path = workflows_dir.join("ci.yml");
    std::fs::write(
        &workflow_path,
        "name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v6\n        with:\n          fetch-depth: 0\n",
    )
    .expect("write workflow");

    let report = Command::new(shk_bin())
        .args(["doctor", "workflows"])
        .current_dir(tmp.path())
        .output()
        .expect("doctor workflows");
    assert!(report.status.success(), "doctor workflows should exit 0");
    let stdout = String::from_utf8_lossy(&report.stdout);
    assert!(stdout.contains(".github/workflows/ci.yml:7"), "{stdout}");

    let fixed = Command::new(shk_bin())
        .args(["doctor", "workflows", "--fix"])
        .current_dir(tmp.path())
        .output()
        .expect("doctor workflows --fix");
    assert!(
        fixed.status.success(),
        "doctor workflows --fix should exit 0"
    );

    let contents = std::fs::read_to_string(&workflow_path).expect("read workflow");
    assert!(
        contents.contains(
            "        with:\n          persist-credentials: false\n          fetch-depth: 0"
        ),
        "{contents}"
    );

    let recheck = Command::new(shk_bin())
        .args(["doctor", "workflows"])
        .current_dir(tmp.path())
        .output()
        .expect("doctor workflows recheck");
    assert!(
        String::from_utf8_lossy(&recheck.stdout).contains("workflows: OK"),
        "stdout={}",
        String::from_utf8_lossy(&recheck.stdout)
    );
}

#[test]
fn doctor_workflows_fix_requires_project_policy() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let workflows_dir = tmp.path().join(".github/workflows");
    std::fs::create_dir_all(&workflows_dir).expect("create workflows dir");
    std::fs::write(
        workflows_dir.join("ci.yml"),
        "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v6\n",
    )
    .expect("write workflow");

    let out = Command::new(shk_bin())
        .args(["doctor", "workflows", "--fix"])
        .current_dir(tmp.path())
        .output()
        .expect("doctor workflows --fix without policy");

    assert!(!out.status.success(), "should fail without shk.toml");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("requires a project shk.toml"),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn ci_init_github_rejects_invalid_fail_on_at_clap_layer() {
    let out = Command::new(shk_bin())
        .args(["ci", "init", "github", "--dry-run", "--fail-on", "bogus"])
        .output()
        .expect("ci init github invalid fail-on");

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("invalid value 'bogus'"), "stderr={stderr}");
}

#[test]
fn ci_init_github_rejects_unsafe_shk_version() {
    let out = Command::new(shk_bin())
        .args([
            "ci",
            "init",
            "github",
            "--dry-run",
            "--shk-version",
            "; rm -rf /",
        ])
        .output()
        .expect("ci init github unsafe shk-version");

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("invalid --shk-version"), "stderr={stderr}");
}

#[test]
fn ci_init_github_warns_when_audit_combined_with_fail_on() {
    let out = Command::new(shk_bin())
        .args([
            "ci",
            "init",
            "github",
            "--dry-run",
            "--mode",
            "audit",
            "--fail-on",
            "critical",
        ])
        .output()
        .expect("ci init github audit warn");

    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stdout.contains("shk scan . --json --audit"), "{stdout}");
    assert!(!stdout.contains("--fail-on"), "{stdout}");
    assert!(
        stderr.contains("--fail-on is ignored when --mode audit"),
        "stderr={stderr}"
    );
}

#[test]
fn mask_hook_mode_claude_post_returns_replacement_output() {
    use std::io::Write;

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    // not real credential: synthetic detector fixture value only
    let secret = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";
    let stdin = serde_json::to_string(&serde_json::json!({
        "tool_name": "mcp__demo__read",
        "tool_response": {
            "data": {
                "value": secret
            }
        }
    }))
    .unwrap();
    let out = Command::new(shk_bin())
        .args(["mask", "--hook-mode", "claude-code", "--post"])
        .current_dir(&root)
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
    // PostToolUse schema: masked replacement is delivered via the
    // decision:block shape (permissionDecision is PreToolUse-only).
    assert_eq!(v["decision"], "block");
    let hook_output = &v["hookSpecificOutput"];
    assert_eq!(hook_output["hookEventName"], "PostToolUse");
    assert!(hook_output.get("permissionDecision").is_none(), "{v}");
    let replacement = v["reason"].as_str().unwrap_or_default();
    assert!(replacement.contains("[REDACTED]"), "{replacement}");
    assert!(replacement.contains("tool output:"), "{replacement}");
    assert!(!replacement.contains(secret), "{replacement}");
}

#[test]
fn scan_json_reports_suppressed_and_deduplicated_fields() {
    let dir = tempfile::tempdir().unwrap();
    let secret = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";
    std::fs::write(dir.path().join("dupe.txt"), format!("{secret}\n{secret}\n")).unwrap();
    let out = Command::new(shk_bin())
        .args([
            "scan",
            &dir.path().display().to_string(),
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
    assert_eq!(v["deduplicated"], 1, "{v}");
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
fn project_root_flag_resolves_policy_from_subdirectory() {
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

    // Run from the subdirectory; --project-root must pull in the root shk.toml.
    let out = Command::new(shk_bin())
        .args([
            "--project-root",
            &dir.path().display().to_string(),
            "scan",
            "src",
            "--json",
            "--fail-on",
            "critical",
        ])
        .current_dir(dir.path().join("src"))
        .output()
        .expect("scan with project root");

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
fn scan_includes_hidden_files_but_not_git_dir() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".env"), "GREETING=hello\n").unwrap();
    std::fs::write(dir.path().join("dev.env"), "GREETING=hello\n").unwrap();
    // A stray .git directory must not be descended into even though hidden
    // files are now included.
    std::fs::create_dir(dir.path().join(".git")).unwrap();
    std::fs::write(dir.path().join(".git/config"), "[core]\n").unwrap();

    let out = Command::new(shk_bin())
        .args(["scan", ".", "--json", "--fail-on", "critical"])
        .current_dir(dir.path())
        .output()
        .expect("scan hidden files");

    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let scanned: Vec<&str> = v["scanned_paths"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|p| p.as_str())
        .collect();
    assert!(scanned.iter().any(|p| p.ends_with(".env")), "{v}");
    assert!(scanned.iter().any(|p| p.ends_with("dev.env")), "{v}");
    assert!(!scanned.iter().any(|p| p.contains(".git/")), "{v}");
}

#[test]
fn project_root_flag_rejects_missing_directory() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("does-not-exist");
    let out = Command::new(shk_bin())
        .args([
            "--project-root",
            &missing.display().to_string(),
            "scan",
            ".",
        ])
        .current_dir(dir.path())
        .output()
        .expect("scan with missing project root");

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--project-root"), "{stderr}");
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
    assert!(stderr.contains("invalid value 'critcal'"), "{stderr}");
    assert!(
        stderr.contains("[possible values: info, low, medium, high, critical]"),
        "{stderr}"
    );
}

#[test]
fn scan_missing_target_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("does-not-exist.txt");
    let out = Command::new(shk_bin())
        .args(["scan", missing.to_str().unwrap(), "--json"])
        .current_dir(dir.path())
        .output()
        .expect("scan missing target");
    assert_eq!(
        out.status.code(),
        Some(2),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("scan target does not exist"), "{stderr}");
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
fn scan_staged_respects_policy_exclude() {
    let dir = tempfile::tempdir().unwrap();
    init_git_repo(dir.path());
    std::fs::write(
        dir.path().join("shk.toml"),
        "[scan]\nexclude = [\"vendor/**\"]\n",
    )
    .unwrap();
    std::fs::create_dir(dir.path().join("vendor")).unwrap();
    let secret = synthetic_openai_key('d');
    std::fs::write(dir.path().join("vendor/secret.txt"), format!("{secret}\n")).unwrap();
    let add = Command::new("git")
        .args(["add", "vendor/secret.txt"])
        .current_dir(dir.path())
        .output()
        .expect("git add");
    assert!(
        add.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&add.stdout),
        String::from_utf8_lossy(&add.stderr)
    );

    let out = Command::new(shk_bin())
        .args(["scan", "--staged", "--json"])
        .current_dir(dir.path())
        .output()
        .expect("scan staged");

    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v["scanned_paths"].as_array().unwrap().is_empty(), "{v}");
    assert!(v["findings"].as_array().unwrap().is_empty(), "{v}");
}

#[test]
fn scan_staged_skips_submodule_gitlink_entries() {
    let dir = tempfile::tempdir().unwrap();
    init_git_repo(dir.path());

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
    // Stage a gitlink (submodule bump) without needing a real submodule. The
    // referenced commit does not exist in this repository's object database,
    // mirroring how submodule commits are unreadable from the superproject.
    let stage_gitlink = Command::new("git")
        .args([
            "update-index",
            "--add",
            "--cacheinfo",
            "160000,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,vendor/submodule",
        ])
        .current_dir(dir.path())
        .output()
        .expect("git update-index");
    assert!(
        stage_gitlink.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&stage_gitlink.stdout),
        String::from_utf8_lossy(&stage_gitlink.stderr)
    );

    let out = Command::new(shk_bin())
        .args(["scan", "--staged", "--json"])
        .current_dir(dir.path())
        .output()
        .expect("scan staged");

    // Exit 1 (finding) — not exit 2 from a failed `git show :vendor/submodule`.
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
    assert!(
        !v["scanned_paths"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p.as_str().unwrap_or_default() == "vendor/submodule"),
        "{v}"
    );
}

#[test]
fn scan_git_history_detects_removed_secret() {
    let dir = tempfile::tempdir().unwrap();
    init_git_repo(dir.path());

    std::fs::write(
        dir.path().join("secret.txt"),
        // not real credential: synthetic detector fixture value only
        "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789\n",
    )
    .unwrap();
    git_commit_all(dir.path(), "add secret fixture");

    std::fs::remove_file(dir.path().join("secret.txt")).unwrap();
    git_commit_all(dir.path(), "remove secret fixture");

    let out = Command::new(shk_bin())
        .args(["scan", "--git-history", "--json"])
        .current_dir(dir.path())
        .output()
        .expect("scan git history");

    assert_eq!(
        out.status.code(),
        Some(1),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let findings = v["findings"].as_array().unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f["rule_id"] == "secret.openai_api_key"
                && f["file"]
                    .as_str()
                    .unwrap_or_default()
                    .ends_with(":secret.txt")),
        "{v}"
    );
    assert!(
        v["scanned_paths"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p.as_str().unwrap_or_default().ends_with(":secret.txt")),
        "{v}"
    );
}

#[test]
fn scan_git_history_handles_large_candidate_sets_without_deadlock() {
    let dir = tempfile::tempdir().unwrap();
    init_git_repo(dir.path());

    // Enough candidate paths that the cat-file --batch-check queries and
    // responses both exceed a typical 64KB OS pipe buffer; a sequential
    // write-all-then-read implementation deadlocks here.
    for i in 0..2500 {
        std::fs::write(
            dir.path().join(format!("file-{i:04}.txt")),
            format!("plain content {i}\n"),
        )
        .unwrap();
    }
    git_commit_all(dir.path(), "add many files");

    let out = Command::new(shk_bin())
        .args(["scan", "--git-history", "--json"])
        .current_dir(dir.path())
        .output()
        .expect("scan git history");

    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["scanned_paths"].as_array().unwrap().len(), 2500, "{v}");
}

#[test]
fn scan_git_history_scans_duplicate_blob_once() {
    let dir = tempfile::tempdir().unwrap();
    init_git_repo(dir.path());

    let secret = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";
    std::fs::write(dir.path().join("a.txt"), format!("{secret}\n")).unwrap();
    std::fs::write(dir.path().join("b.txt"), format!("{secret}\n")).unwrap();
    git_commit_all(dir.path(), "add duplicate blob fixture");

    let out = Command::new(shk_bin())
        .args(["scan", "--git-history", "--json", "--fail-on", "critical"])
        .current_dir(dir.path())
        .output()
        .expect("scan git history");

    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let findings = v["findings"].as_array().unwrap();
    assert_eq!(
        findings
            .iter()
            .filter(|f| f["rule_id"] == "secret.openai_api_key")
            .count(),
        1,
        "{v}"
    );
}

#[test]
fn scan_git_history_labels_binary_skip_with_commit_path() {
    let dir = tempfile::tempdir().unwrap();
    init_git_repo(dir.path());
    std::fs::write(dir.path().join("blob.dat"), b"abc\0def").unwrap();
    git_commit_all(dir.path(), "add binary fixture");

    let out = Command::new(shk_bin())
        .args(["scan", "--git-history", "--json", "--fail-on", "critical"])
        .current_dir(dir.path())
        .output()
        .expect("scan git history");

    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let findings = v["findings"].as_array().unwrap();
    let file = findings
        .iter()
        .find(|f| f["rule_id"] == "scan.binary_skipped")
        .and_then(|f| f["file"].as_str())
        .unwrap_or_default();
    assert!(file.contains(':'), "{v}");
    assert!(file.ends_with(":blob.dat"), "{v}");
}

#[test]
fn scan_git_history_outside_git_exits_2() {
    let dir = tempfile::tempdir().unwrap();

    let out = Command::new(shk_bin())
        .args(["scan", "--git-history"])
        .current_dir(dir.path())
        .output()
        .expect("scan git history outside git");

    assert_eq!(
        out.status.code(),
        Some(2),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("shk scan --git-history requires a Git repository"),
        "{stderr}"
    );
}

#[test]
fn scan_git_history_respects_policy_exclude() {
    let dir = tempfile::tempdir().unwrap();
    init_git_repo(dir.path());
    std::fs::write(
        dir.path().join("shk.toml"),
        "[scan]\nexclude = [\"ignored/**\"]\n",
    )
    .unwrap();
    std::fs::create_dir(dir.path().join("ignored")).unwrap();
    std::fs::create_dir(dir.path().join("kept")).unwrap();
    let secret = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";
    std::fs::write(dir.path().join("ignored/secret.txt"), format!("{secret}\n")).unwrap();
    std::fs::write(dir.path().join("kept/clean.txt"), "nothing sensitive\n").unwrap();
    git_commit_all(dir.path(), "add excluded history fixture");

    let out = Command::new(shk_bin())
        .args(["scan", "--git-history", "--json", "--fail-on", "critical"])
        .current_dir(dir.path())
        .output()
        .expect("scan git history");

    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v["findings"].as_array().unwrap().is_empty(), "{v}");
    assert!(
        !v["scanned_paths"].as_array().unwrap().iter().any(|p| p
            .as_str()
            .unwrap_or_default()
            .ends_with(":ignored/secret.txt")),
        "{v}"
    );
}

#[test]
fn scan_git_history_works_from_repo_subdirectory() {
    let dir = tempfile::tempdir().unwrap();
    init_git_repo(dir.path());
    std::fs::create_dir(dir.path().join("src")).unwrap();
    std::fs::write(
        dir.path().join("src/secret.txt"),
        // not real credential: synthetic detector fixture value only
        "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789\n",
    )
    .unwrap();
    git_commit_all(dir.path(), "add nested history fixture");

    let out = Command::new(shk_bin())
        .args(["scan", "--git-history", "--json"])
        .current_dir(dir.path().join("src"))
        .output()
        .expect("scan git history from subdir");

    assert_eq!(
        out.status.code(),
        Some(1),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        v["findings"].as_array().unwrap().iter().any(|f| f["file"]
            .as_str()
            .unwrap_or_default()
            .ends_with(":src/secret.txt")),
        "{v}"
    );
}

#[test]
fn scan_git_history_handles_hex_looking_paths() {
    let dir = tempfile::tempdir().unwrap();
    init_git_repo(dir.path());
    let hex_path = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    std::fs::write(
        dir.path().join(hex_path),
        // not real credential: synthetic detector fixture value only
        "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789\n",
    )
    .unwrap();
    git_commit_all(dir.path(), "add hex-looking path fixture");

    let out = Command::new(shk_bin())
        .args(["scan", "--git-history", "--json"])
        .current_dir(dir.path())
        .output()
        .expect("scan git history");

    assert_eq!(
        out.status.code(),
        Some(1),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        v["findings"].as_array().unwrap().iter().any(|f| f["file"]
            .as_str()
            .unwrap_or_default()
            .ends_with(&format!(":{hex_path}"))),
        "{v}"
    );
}

#[test]
fn scan_git_history_preview_json_reports_candidate_counts() {
    let dir = tempfile::tempdir().unwrap();
    init_git_repo(dir.path());
    std::fs::write(
        dir.path().join("secret.txt"),
        // not real credential: synthetic detector fixture value only
        "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789\n",
    )
    .unwrap();
    git_commit_all(dir.path(), "add preview fixture");

    let out = Command::new(shk_bin())
        .args(["scan", "--git-history", "--preview", "--json"])
        .current_dir(dir.path())
        .output()
        .expect("preview git history");

    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["mode"], "git-history-preview");
    assert_eq!(v["scope"], "--all");
    assert!(
        v["candidate_commits"].as_u64().unwrap_or_default() >= 1,
        "{v}"
    );
    assert!(
        v["candidate_paths"].as_u64().unwrap_or_default() >= 1,
        "{v}"
    );
    assert!(v["unique_blobs"].as_u64().unwrap_or_default() >= 1, "{v}");
    assert!(
        v["sample_paths"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p.as_str().unwrap_or_default().ends_with(":secret.txt")),
        "{v}"
    );
    assert!(
        v.get("findings").is_none(),
        "preview should not emit scan findings: {v}"
    );
}

#[test]
fn scan_git_history_ref_limits_scanned_commits() {
    let dir = tempfile::tempdir().unwrap();
    init_git_repo(dir.path());
    let path = dir.path().join("secret.txt");
    std::fs::write(
        &path,
        // not real credential: synthetic detector fixture value only
        "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789\n",
    )
    .unwrap();
    git_commit_all(dir.path(), "add old secret fixture");
    std::fs::write(&path, "clean now\n").unwrap();
    git_commit_all(dir.path(), "remove old secret fixture");

    let all = Command::new(shk_bin())
        .args(["scan", "--git-history", "--json"])
        .current_dir(dir.path())
        .output()
        .expect("scan all history");
    assert_eq!(
        all.status.code(),
        Some(1),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&all.stdout),
        String::from_utf8_lossy(&all.stderr)
    );

    let latest_only = Command::new(shk_bin())
        .args([
            "scan",
            "--git-history",
            "--ref",
            "HEAD~1..HEAD",
            "--json",
            "--fail-on",
            "critical",
        ])
        .current_dir(dir.path())
        .output()
        .expect("scan latest history range");
    assert!(
        latest_only.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&latest_only.stdout),
        String::from_utf8_lossy(&latest_only.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&latest_only.stdout).unwrap();
    assert!(
        !v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["rule_id"] == "secret.openai_api_key"),
        "{v}"
    );
}

#[test]
fn scan_git_history_rejects_since_that_looks_like_option() {
    let dir = tempfile::tempdir().unwrap();
    init_git_repo(dir.path());
    std::fs::write(dir.path().join("clean.txt"), "nothing sensitive\n").unwrap();
    git_commit_all(dir.path(), "add clean fixture");

    let out = Command::new(shk_bin())
        .args(["scan", "--git-history", "--preview", "--since=-bad"])
        .current_dir(dir.path())
        .output()
        .expect("scan git history invalid since");

    assert!(
        !out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--since must be a Git date expression"),
        "{stderr}"
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
fn hooks_install_ai_claude_apply_deny_merges_without_duplicates() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("shk.toml"), "").unwrap();
    std::fs::create_dir(dir.path().join(".claude")).unwrap();
    std::fs::write(
        dir.path().join(".claude/settings.json"),
        r#"{"permissions":{"deny":["Read(.env)","Bash(custom:*)"]}}"#,
    )
    .unwrap();

    for _ in 0..2 {
        let out = Command::new(shk_bin())
            .args([
                "hooks",
                "install-ai",
                "--tool",
                "claude-code",
                "--apply-deny",
            ])
            .current_dir(dir.path())
            .output()
            .expect("install-ai apply deny");
        assert!(
            out.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let settings: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.path().join(".claude/settings.json")).unwrap(),
    )
    .unwrap();
    let deny = settings["permissions"]["deny"].as_array().unwrap();
    assert!(
        deny.iter().any(|v| v == "Bash(custom:*)"),
        "existing deny entry should be preserved: {deny:?}"
    );
    assert_eq!(
        deny.iter().filter(|v| *v == "Read(.env)").count(),
        1,
        "managed deny entries should not duplicate: {deny:?}"
    );
    assert!(
        deny.iter().any(|v| v == "Bash(psql:*)"),
        "database guard deny should be installed: {deny:?}"
    );
    let prompt_hooks = settings["hooks"]["UserPromptSubmit"].as_array().unwrap();
    assert_eq!(
        prompt_hooks.len(),
        1,
        "managed prompt hook should be deduplicated: {prompt_hooks:?}"
    );
    assert_eq!(prompt_hooks[0]["_shk_managed"], true);
    assert!(
        prompt_hooks[0]["hooks"][0]["command"]
            .as_str()
            .unwrap_or_default()
            .contains(&format!("--fail-on {USER_PROMPT_HOOK_FAIL_ON}")),
        "prompt hook should use medium threshold: {prompt_hooks:?}"
    );
    let pre_hooks = settings["hooks"]["PreToolUse"].as_array().unwrap();
    assert_eq!(pre_hooks[0]["matcher"], "Read|Write|Bash|WebFetch|mcp__.*");
    let post_hooks = settings["hooks"]["PostToolUse"].as_array().unwrap();
    assert_eq!(
        post_hooks[0]["matcher"],
        "WebFetch|WebSearch|Bash|mcp__.*|Skill|Agent"
    );
}

#[test]
fn hooks_install_ai_claude_apply_deny_accepts_equivalent_entries() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("shk.toml"), "").unwrap();
    std::fs::create_dir(dir.path().join(".claude")).unwrap();
    std::fs::write(
        dir.path().join(".claude/settings.json"),
        r#"{"permissions":{"deny":["Read(./.env)","Bash(cat ./.env:*)"]}}"#,
    )
    .unwrap();

    let out = Command::new(shk_bin())
        .args([
            "hooks",
            "install-ai",
            "--tool",
            "claude-code",
            "--apply-deny",
        ])
        .current_dir(dir.path())
        .output()
        .expect("install-ai apply deny");
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let settings: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.path().join(".claude/settings.json")).unwrap(),
    )
    .unwrap();
    let deny = settings["permissions"]["deny"].as_array().unwrap();
    assert_eq!(
        deny.iter().filter(|v| *v == "Read(./.env)").count(),
        1,
        "existing equivalent deny entry should be preserved: {deny:?}"
    );
    assert!(
        !deny.iter().any(|v| v == "Read(.env)"),
        "equivalent deny entries should not be duplicated: {deny:?}"
    );
    assert!(
        !deny.iter().any(|v| v == "Bash(cat .env:*)"),
        "equivalent bash deny entries should not be duplicated: {deny:?}"
    );
}

#[test]
fn hooks_install_ai_codex_is_idempotent() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let dir = tempfile::tempdir_in(&root).unwrap();
    std::fs::write(dir.path().join("shk.toml"), "").unwrap();

    for _ in 0..2 {
        let out = Command::new(shk_bin())
            .args(["hooks", "install-ai", "--tool", "codex"])
            .current_dir(dir.path())
            .output()
            .expect("install-ai");
        assert!(
            out.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let codex = std::fs::read_to_string(dir.path().join(".codex/config.toml")).unwrap();
    assert_eq!(codex.matches("# shk-managed-start").count(), 1, "{codex}");
    assert_eq!(codex.matches("[[hooks.PreToolUse]]").count(), 1, "{codex}");
    assert_eq!(
        codex.matches("[[hooks.PermissionRequest]]").count(),
        1,
        "{codex}"
    );
    assert_eq!(
        codex.matches("[[hooks.UserPromptSubmit]]").count(),
        1,
        "{codex}"
    );
    assert_eq!(codex.matches("[[hooks.PostToolUse]]").count(), 1, "{codex}");
}

#[test]
fn hooks_install_ai_apply_sandbox_hardens_codex() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let dir = tempfile::tempdir_in(&root).unwrap();
    std::fs::write(dir.path().join("shk.toml"), "").unwrap();
    std::fs::create_dir(dir.path().join(".codex")).unwrap();
    std::fs::write(
        dir.path().join(".codex/config.toml"),
        r#"sandbox_mode = "danger-full-access"
approval_policy = "never"
"#,
    )
    .unwrap();

    let out = Command::new(shk_bin())
        .args(["hooks", "install-ai", "--tool", "codex", "--apply-sandbox"])
        .current_dir(dir.path())
        .output()
        .expect("install-ai apply sandbox");
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let codex = std::fs::read_to_string(dir.path().join(".codex/config.toml")).unwrap();
    assert!(
        codex.contains(r#"sandbox_mode = "workspace-write""#),
        "{codex}"
    );
    assert!(
        codex.contains(r#"approval_policy = "on-request""#),
        "{codex}"
    );
}

#[test]
fn hooks_install_ai_codex_includes_permission_request() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("shk.toml"), "").unwrap();

    let out = Command::new(shk_bin())
        .args(["hooks", "install-ai", "--tool", "codex"])
        .current_dir(dir.path())
        .output()
        .expect("install-ai codex");
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let body = std::fs::read_to_string(dir.path().join(".codex/config.toml")).unwrap();
    assert!(body.contains("hooks = true"), "{body}");
    assert!(!body.contains("codex_hooks = true"), "{body}");
    assert!(body.contains("[[hooks.PreToolUse]]"), "{body}");
    assert!(body.contains("[[hooks.PermissionRequest]]"), "{body}");
    assert!(body.contains("[[hooks.UserPromptSubmit]]"), "{body}");
    assert!(body.contains("[[hooks.PostToolUse]]"), "{body}");
    assert!(
        body.contains(r#"shk scan "$(git rev-parse --show-toplevel)" --hook-mode codex"#),
        "{body}"
    );
    let prompt_section = codex_managed_hook_section(&body, "UserPromptSubmit", "PostToolUse");
    assert!(
        prompt_section.contains(&format!("--fail-on {USER_PROMPT_HOOK_FAIL_ON}")),
        "UserPromptSubmit hook should use medium threshold: {prompt_section}"
    );
    let pre_section = codex_managed_hook_section(&body, "PreToolUse", "PermissionRequest");
    assert!(
        !pre_section.contains(&format!("--fail-on {USER_PROMPT_HOOK_FAIL_ON}")),
        "PreToolUse hook should keep default high threshold: {pre_section}"
    );
}

#[test]
fn hook_mode_cursor_blocks_with_exit_2() {
    use std::io::Write;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let dir = tempfile::tempdir_in(&root).unwrap();
    let fixture = dir.path().join("hook-secret.txt");
    // not real credential: synthetic detector fixture value only
    std::fs::write(&fixture, "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789\n").unwrap();
    let fixture = std::fs::canonicalize(fixture).unwrap();
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
fn hooks_install_ai_antigravity_writes_managed_pre_and_post_hooks() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("shk.toml"), "").unwrap();
    std::fs::create_dir_all(dir.path().join(".agents")).unwrap();
    std::fs::write(
        dir.path().join(".agents/hooks.json"),
        r#"{"my-linter":{"PostToolUse":[{"matcher":"run_command","hooks":[{"command":"./lint.sh"}]}]}}"#,
    )
    .unwrap();

    for _ in 0..2 {
        let out = Command::new(shk_bin())
            .args([
                "hooks",
                "install-ai",
                "--tool",
                "antigravity",
                "--log-blocked",
            ])
            .current_dir(dir.path())
            .output()
            .expect("install-ai antigravity");
        assert!(
            out.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let hooks: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.path().join(".agents/hooks.json")).unwrap(),
    )
    .unwrap();
    assert!(
        hooks.get("my-linter").is_some(),
        "user hooks must be preserved: {hooks}"
    );
    let pre = hooks["shk-security"]["PreToolUse"].as_array().unwrap();
    assert_eq!(pre.len(), 1, "managed hook should not duplicate: {pre:?}");
    assert_eq!(pre[0]["_shk_managed"], true);
    assert_eq!(pre[0]["matcher"], ".*");
    assert!(
        pre[0]["hooks"][0]["command"]
            .as_str()
            .unwrap_or_default()
            .contains("shk scan --hook-mode antigravity"),
        "{pre:?}"
    );
    assert!(
        pre[0]["hooks"][0]["command"]
            .as_str()
            .unwrap_or_default()
            .contains("--log-blocked"),
        "{pre:?}"
    );
    assert!(
        !pre[0]["hooks"][0]["command"]
            .as_str()
            .unwrap_or_default()
            .contains("--post"),
        "{pre:?}"
    );
    let post = hooks["shk-security"]["PostToolUse"].as_array().unwrap();
    assert_eq!(
        post.len(),
        1,
        "managed post hook should not duplicate: {post:?}"
    );
    assert_eq!(post[0]["_shk_managed"], true);
    assert_eq!(post[0]["matcher"], pre[0]["matcher"]);
    let post_cmd = post[0]["hooks"][0]["command"].as_str().unwrap_or_default();
    assert!(
        post_cmd.contains("shk scan --hook-mode antigravity")
            && post_cmd.contains("--log-blocked")
            && post_cmd.contains("--post"),
        "{post:?}"
    );
}

#[test]
fn hooks_install_ai_antigravity_apply_deny_prints_permission_guidance() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("shk.toml"), "").unwrap();

    let out = Command::new(shk_bin())
        .args([
            "hooks",
            "install-ai",
            "--tool",
            "antigravity",
            "--apply-deny",
        ])
        .current_dir(dir.path())
        .output()
        .expect("install-ai antigravity apply-deny");
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Recommended Deny list entries"), "{stdout}");
    assert!(stdout.contains("command(rm -rf)"), "{stdout}");
    assert!(stdout.contains("read_file(**/.env)"), "{stdout}");

    let hooks =
        std::fs::read_to_string(dir.path().join(".agents/hooks.json")).expect("hooks written");
    assert!(
        !hooks.contains("command(rm -rf)"),
        "deny guidance must not be written into hooks.json: {hooks}"
    );
}

#[test]
fn hook_mode_antigravity_blocks_dangerous_command_line() {
    use std::io::Write;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let stdin = serde_json::to_string(&serde_json::json!({
        "toolCall": {
            "name": "run_command",
            "args": { "CommandLine": "rm -rf /", "Cwd": "/workspace" }
        },
        "stepIdx": 1
    }))
    .unwrap();
    let out = Command::new(shk_bin())
        .args(["scan", ".", "--hook-mode", "antigravity"])
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
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(stdout["decision"], "deny", "{stdout}");
    assert!(
        stdout["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("destructive_filesystem"),
        "{stdout}"
    );
}

#[test]
fn hook_mode_antigravity_allows_clean_command() {
    use std::io::Write;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let stdin = serde_json::to_string(&serde_json::json!({
        "toolCall": {
            "name": "run_command",
            "args": { "CommandLine": "echo ok", "Cwd": "/workspace" }
        },
        "stepIdx": 1
    }))
    .unwrap();
    let out = Command::new(shk_bin())
        .args(["scan", ".", "--hook-mode", "antigravity"])
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
    assert_eq!(stdout["decision"], "allow", "{stdout}");
}

#[test]
fn skills_install_antigravity_project_uses_agents_dir() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(shk_bin())
        .args(["skills", "install", "--tool", "antigravity"])
        .current_dir(dir.path())
        .output()
        .expect("skills install antigravity");
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(dir.path().join(".agents/skills/shk/SKILL.md").is_file());
}

#[test]
fn hooks_install_ai_copilot_writes_github_hooks_file() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("shk.toml"), "").unwrap();
    std::fs::create_dir_all(dir.path().join(".github/hooks")).unwrap();
    std::fs::write(
        dir.path().join(".github/hooks/shk-security.json"),
        r#"{"version":1,"hooks":{"preToolUse":[{"type":"command","command":"./lint.sh"}]}}"#,
    )
    .unwrap();

    for _ in 0..2 {
        let out = Command::new(shk_bin())
            .args(["hooks", "install-ai", "--tool", "copilot"])
            .current_dir(dir.path())
            .output()
            .expect("install-ai copilot");
        assert!(
            out.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let hooks: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.path().join(".github/hooks/shk-security.json")).unwrap(),
    )
    .unwrap();
    let pre = hooks["hooks"]["preToolUse"].as_array().unwrap();
    assert_eq!(
        pre.iter()
            .filter(|entry| entry["command"]
                .as_str()
                .unwrap_or_default()
                .contains("--hook-mode copilot"))
            .count(),
        1,
        "managed hook should not duplicate: {pre:?}"
    );
    assert!(
        pre.iter()
            .any(|entry| entry["command"].as_str().unwrap_or_default() == "./lint.sh"),
        "user hooks must be preserved: {hooks}"
    );
    assert!(
        hooks["hooks"]["PermissionRequest"].is_array(),
        "permissionRequest should use PascalCase payloads: {hooks}"
    );
    assert!(
        hooks["hooks"]["UserPromptSubmit"].is_array(),
        "prompt hook should use PascalCase payloads: {hooks}"
    );
}

#[test]
fn hook_mode_copilot_pre_tool_deny_exits_zero_with_permission_decision() {
    use std::io::Write;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let stdin = serde_json::to_string(&serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "bash",
        "tool_input": {
            "command": "psql -c \"DROP TABLE users\""
        }
    }))
    .unwrap();
    let out = Command::new(shk_bin())
        .args(["scan", ".", "--hook-mode", "copilot"])
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
        "Copilot preToolUse denies must use stdout JSON with exit 0: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(stdout["permissionDecision"], "deny", "{stdout}");
    assert!(
        stdout["permissionDecisionReason"]
            .as_str()
            .unwrap_or_default()
            .contains("action guard"),
        "{stdout}"
    );
}

#[test]
fn hook_mode_codex_permission_request_uses_decision_shape() {
    use std::io::Write;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let stdin = serde_json::to_string(&serde_json::json!({
        "hook_event_name": "PermissionRequest",
        "tool_name": "Bash",
        "tool_input": {
            "command": "psql -c \"DROP TABLE users\""
        }
    }))
    .unwrap();
    let out = Command::new(shk_bin())
        .args(["scan", ".", "--hook-mode", "codex"])
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
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        stdout["hookSpecificOutput"]["hookEventName"],
        "PermissionRequest"
    );
    assert_eq!(stdout["hookSpecificOutput"]["decision"]["behavior"], "deny");
    assert!(
        stdout["hookSpecificOutput"]["decision"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("direct_db_mutation"),
        "{stdout}"
    );
}

#[test]
fn hook_mode_codex_permission_request_clean_does_not_auto_allow() {
    use std::io::Write;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let stdin = serde_json::to_string(&serde_json::json!({
        "hook_event_name": "PermissionRequest",
        "tool_name": "Bash",
        "tool_input": {
            "command": "echo ok"
        }
    }))
    .unwrap();
    let out = Command::new(shk_bin())
        .args(["scan", ".", "--hook-mode", "codex"])
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
    assert_eq!(stdout, serde_json::json!({}));
}

#[test]
fn hook_mode_claude_blocks_db_mutation_action() {
    use std::io::Write;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let stdin = serde_json::to_string(&serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {
            "command": "psql -c \"DROP TABLE users\""
        }
    }))
    .unwrap();
    let out = Command::new(shk_bin())
        .args(["scan", ".", "--hook-mode", "claude-code"])
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
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("direct_db_mutation"), "{stdout}");
}

#[test]
fn hook_mode_claude_allows_db_select_action() {
    use std::io::Write;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let stdin = serde_json::to_string(&serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {
            "command": "psql -c \"SELECT 1\""
        }
    }))
    .unwrap();
    let out = Command::new(shk_bin())
        .args(["scan", ".", "--hook-mode", "claude-code"])
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
}

#[test]
fn hook_mode_claude_user_prompt_blocks_medium_pii() {
    use std::io::Write;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let stdin = serde_json::to_string(&serde_json::json!({
        "hook_event_name": "UserPromptSubmit",
        "prompt": "Please use customer email admin@example.com in the demo"
    }))
    .unwrap();
    let out = Command::new(shk_bin())
        .args(["scan", "--hook-mode", "claude-code", "--fail-on", "medium"])
        .current_dir(&root)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            c.stdin.as_mut().unwrap().write_all(stdin.as_bytes())?;
            c.wait_with_output()
        })
        .expect("prompt hook scan");
    assert_eq!(
        out.status.code(),
        Some(2),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        stdout["hookSpecificOutput"]["hookEventName"],
        "UserPromptSubmit"
    );
    assert_eq!(stdout["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn hook_mode_codex_user_prompt_blocks_medium_pii() {
    use std::io::Write;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let stdin = serde_json::to_string(&serde_json::json!({
        "hook_event_name": "UserPromptSubmit",
        "prompt": "Please use customer email admin@example.com in the demo"
    }))
    .unwrap();
    let out = Command::new(shk_bin())
        .args(["scan", ".", "--hook-mode", "codex", "--fail-on", "medium"])
        .current_dir(&root)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            c.stdin.as_mut().unwrap().write_all(stdin.as_bytes())?;
            c.wait_with_output()
        })
        .expect("prompt hook scan");
    assert_eq!(
        out.status.code(),
        Some(2),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(stdout["decision"], "block");
    assert!(
        stdout["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("sensitive content detected"),
        "{stdout}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("sensitive content detected"),
        "Codex exit 2 requires a blocking reason on stderr: {stderr}"
    );
}

#[test]
fn hook_mode_action_guard_respects_project_policy() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("shk.toml"),
        r#"[action_guard]
enabled = true
allow = ["Bash(psql:*)"]
"#,
    )
    .unwrap();
    let stdin = serde_json::to_string(&serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {
            "command": "psql -c \"DROP TABLE users\""
        }
    }))
    .unwrap();
    let out = Command::new(shk_bin())
        .args(["scan", ".", "--hook-mode", "claude-code"])
        .current_dir(dir.path())
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
fn hook_mode_log_blocked_writes_metadata_on_block() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    std::fs::write(repo.join("shk.toml"), "").unwrap();
    let fpath = repo.join("x.txt");
    let secret = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";
    std::fs::write(
        &fpath,
        format!("// not real credential: synthetic detector fixture value only\nconst demo = \"{secret}\";"),
    )
    .unwrap();
    let stdin = serde_json::to_string(&serde_json::json!({
        "file_path": fpath.to_str().unwrap(),
    }))
    .unwrap();
    let out = Command::new(shk_bin())
        .args(["scan", ".", "--hook-mode", "cursor", "--log-blocked"])
        .current_dir(repo)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            c.stdin.as_mut().unwrap().write_all(stdin.as_bytes())?;
            c.wait_with_output()
        })
        .expect("log-blocked hook");
    assert_eq!(
        out.status.code(),
        Some(2),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let log_path = repo.join(".shk/audit.log");
    assert!(
        log_path.is_file(),
        "missing audit log {:?}",
        repo.join(".shk")
    );
    let log = std::fs::read_to_string(log_path).unwrap();
    assert!(
        !log.contains(secret),
        "audit log must not contain raw secret: {log}"
    );
    let entry: serde_json::Value = serde_json::from_str(log.lines().next().unwrap()).unwrap();
    assert_eq!(entry["event"], "blocked");
    assert_eq!(entry["reason"], "finding_threshold");
    assert_eq!(entry["tool"], "cursor");
    assert_eq!(entry["hook"], "pre");
    assert!(entry["finding_count"].as_u64().unwrap_or(0) >= 1);
    assert!(!entry["rule_ids"].as_array().unwrap().is_empty());
    assert!(!entry["kinds"].as_array().unwrap().is_empty());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("shk blocked:"), "{stderr}");
}

#[test]
fn hook_mode_log_blocked_append_failure_still_blocks() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    std::fs::write(repo.join("shk.toml"), "").unwrap();
    std::fs::write(repo.join(".shk"), "not a directory").unwrap();
    let fpath = repo.join("x.txt");
    let secret = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";
    std::fs::write(
        &fpath,
        format!("// not real credential: synthetic detector fixture value only\nconst demo = \"{secret}\";"),
    )
    .unwrap();
    let stdin = serde_json::to_string(&serde_json::json!({
        "file_path": fpath.to_str().unwrap(),
    }))
    .unwrap();
    let out = Command::new(shk_bin())
        .args(["scan", ".", "--hook-mode", "cursor", "--log-blocked"])
        .current_dir(repo)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            c.stdin.as_mut().unwrap().write_all(stdin.as_bytes())?;
            c.wait_with_output()
        })
        .expect("log-blocked hook with unwritable log");

    assert_eq!(
        out.status.code(),
        Some(2),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(stdout["permission"], "deny");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unable to write .shk/audit.log"),
        "{stderr}"
    );
}

#[test]
fn hook_mode_log_blocked_action_guard_writes_category_only() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    std::fs::write(repo.join("shk.toml"), "").unwrap();
    let stdin = serde_json::to_string(&serde_json::json!({
        "hook_event_name": "PermissionRequest",
        "tool_name": "Bash",
        "tool_input": {
            "command": "psql -c \"DROP TABLE users\""
        }
    }))
    .unwrap();
    let out = Command::new(shk_bin())
        .args(["scan", ".", "--hook-mode", "codex", "--log-blocked"])
        .current_dir(repo)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            c.stdin.as_mut().unwrap().write_all(stdin.as_bytes())?;
            c.wait_with_output()
        })
        .expect("log-blocked action guard");
    assert_eq!(
        out.status.code(),
        Some(2),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let log = std::fs::read_to_string(repo.join(".shk/audit.log")).unwrap();
    assert!(
        !log.contains("DROP TABLE"),
        "audit log must not contain command text: {log}"
    );
    let entry: serde_json::Value = serde_json::from_str(log.lines().next().unwrap()).unwrap();
    assert_eq!(entry["event"], "blocked");
    assert_eq!(entry["reason"], "action_guard");
    assert_eq!(entry["action_category"], "direct_db_mutation");
    assert_eq!(entry["tool"], "codex");
    assert_eq!(entry["hook"], "pre");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("direct_db_mutation"), "{stdout}");
    assert!(!stdout.contains("DROP TABLE"), "{stdout}");
}

#[test]
fn hooks_install_ai_log_blocked_injects_flag() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let dir = tempfile::tempdir_in(&root).unwrap();
    std::fs::write(dir.path().join("shk.toml"), "").unwrap();
    let out = Command::new(shk_bin())
        .args(["hooks", "install-ai", "--tool", "cursor", "--log-blocked"])
        .current_dir(dir.path())
        .output()
        .expect("hooks install-ai log-blocked");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let hooks = std::fs::read_to_string(dir.path().join(".cursor/hooks.json")).unwrap();
    assert!(hooks.contains("--log-blocked"), "{hooks}");
    assert!(!hooks.contains("--audit"), "{hooks}");
    let hooks_json: serde_json::Value = serde_json::from_str(&hooks).unwrap();
    let prompt_cmd = hooks_json["hooks"]["beforeSubmitPrompt"][0]["command"]
        .as_str()
        .unwrap_or_default();
    assert!(
        prompt_cmd.contains(&format!("--fail-on {USER_PROMPT_HOOK_FAIL_ON}")),
        "beforeSubmitPrompt should use medium threshold: {prompt_cmd}"
    );
    let read_cmd = hooks_json["hooks"]["beforeReadFile"][0]["command"]
        .as_str()
        .unwrap_or_default();
    assert!(
        !read_cmd.contains(&format!("--fail-on {USER_PROMPT_HOOK_FAIL_ON}")),
        "beforeReadFile should keep default high threshold: {read_cmd}"
    );
}

#[test]
fn hook_mode_block_without_log_blocked_skips_audit_log() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    std::fs::write(repo.join("shk.toml"), "").unwrap();
    let fpath = repo.join("x.txt");
    let secret = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";
    std::fs::write(
        &fpath,
        format!("// not real credential: synthetic detector fixture value only\nconst demo = \"{secret}\";"),
    )
    .unwrap();
    let stdin = serde_json::to_string(&serde_json::json!({
        "file_path": fpath.to_str().unwrap(),
    }))
    .unwrap();
    let out = Command::new(shk_bin())
        .args(["scan", ".", "--hook-mode", "cursor"])
        .current_dir(repo)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            c.stdin.as_mut().unwrap().write_all(stdin.as_bytes())?;
            c.wait_with_output()
        })
        .expect("blocking hook without log");
    assert_eq!(out.status.code(), Some(2));
    assert!(
        !repo.join(".shk/audit.log").exists(),
        "blocking without --log-blocked must not create audit log"
    );
}

#[test]
fn hook_mode_log_blocked_requires_policy() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    let fpath = repo.join("x.txt");
    std::fs::write(&fpath, "hello\n").unwrap();
    let stdin = serde_json::to_string(&serde_json::json!({
        "file_path": fpath.to_str().unwrap(),
    }))
    .unwrap();
    let out = Command::new(shk_bin())
        .args(["scan", ".", "--hook-mode", "cursor", "--log-blocked"])
        .current_dir(repo)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            c.stdin.as_mut().unwrap().write_all(stdin.as_bytes())?;
            c.wait_with_output()
        })
        .expect("log-blocked without policy");
    assert!(
        !out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("shk.toml"), "{stderr}");
}

#[test]
fn hook_mode_log_blocked_user_prompt_writes_log() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    std::fs::write(repo.join("shk.toml"), "").unwrap();
    let stdin = serde_json::to_string(&serde_json::json!({
        "hook_event_name": "UserPromptSubmit",
        "prompt": "Please use customer email admin@example.com in the demo"
    }))
    .unwrap();
    let out = Command::new(shk_bin())
        .args([
            "scan",
            ".",
            "--hook-mode",
            "claude-code",
            "--fail-on",
            "medium",
            "--log-blocked",
        ])
        .current_dir(repo)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            c.stdin.as_mut().unwrap().write_all(stdin.as_bytes())?;
            c.wait_with_output()
        })
        .expect("log-blocked user prompt");
    assert_eq!(out.status.code(), Some(2));
    let log = std::fs::read_to_string(repo.join(".shk/audit.log")).unwrap();
    let entry: serde_json::Value = serde_json::from_str(log.lines().next().unwrap()).unwrap();
    assert_eq!(entry["event"], "blocked");
    assert_eq!(entry["hook"], "user-prompt");
    assert_eq!(entry["display_path"], "<user-prompt>");
    assert!(!log.contains("admin@example.com"), "{log}");
}

#[test]
fn hook_mode_log_blocked_appends_multiple_entries() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    std::fs::write(repo.join("shk.toml"), "").unwrap();
    let fpath = repo.join("x.txt");
    let secret = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";
    std::fs::write(
        &fpath,
        format!("// not real credential: synthetic detector fixture value only\nconst demo = \"{secret}\";"),
    )
    .unwrap();
    let stdin = serde_json::to_string(&serde_json::json!({
        "file_path": fpath.to_str().unwrap(),
    }))
    .unwrap();

    for _ in 0..2 {
        let out = Command::new(shk_bin())
            .args(["scan", ".", "--hook-mode", "cursor", "--log-blocked"])
            .current_dir(repo)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut c| {
                c.stdin.as_mut().unwrap().write_all(stdin.as_bytes())?;
                c.wait_with_output()
            })
            .expect("repeat log-blocked hook");
        assert_eq!(out.status.code(), Some(2));
    }

    let log = std::fs::read_to_string(repo.join(".shk/audit.log")).unwrap();
    let lines: Vec<_> = log.lines().collect();
    assert_eq!(lines.len(), 2);
}

#[test]
fn hooks_install_ai_claude_log_blocked_injects_flag() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let dir = tempfile::tempdir_in(&root).unwrap();
    std::fs::write(dir.path().join("shk.toml"), "").unwrap();
    let out = Command::new(shk_bin())
        .args([
            "hooks",
            "install-ai",
            "--tool",
            "claude-code",
            "--log-blocked",
        ])
        .current_dir(dir.path())
        .output()
        .expect("hooks install-ai claude log-blocked");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let settings = std::fs::read_to_string(dir.path().join(".claude/settings.json")).unwrap();
    assert!(settings.contains("--log-blocked"), "{settings}");
}

#[test]
fn hooks_install_ai_codex_log_blocked_injects_flag() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let dir = tempfile::tempdir_in(&root).unwrap();
    std::fs::write(dir.path().join("shk.toml"), "").unwrap();
    let out = Command::new(shk_bin())
        .args(["hooks", "install-ai", "--tool", "codex", "--log-blocked"])
        .current_dir(dir.path())
        .output()
        .expect("hooks install-ai codex log-blocked");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let codex = std::fs::read_to_string(dir.path().join(".codex/config.toml")).unwrap();
    assert!(codex.contains("--log-blocked"), "{codex}");
}

#[test]
fn audit_reports_empty_log_helpfully() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(shk_bin())
        .args(["audit"])
        .current_dir(dir.path())
        .output()
        .expect("audit empty");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("No audit log found"), "{stdout}");
}

#[test]
fn audit_json_reports_blocked_metadata() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    std::fs::write(repo.join("shk.toml"), "").unwrap();
    let fpath = repo.join("x.txt");
    let secret = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";
    std::fs::write(
        &fpath,
        format!("// not real credential: synthetic detector fixture value only\nconst demo = \"{secret}\";"),
    )
    .unwrap();
    let stdin = serde_json::to_string(&serde_json::json!({
        "file_path": fpath.to_str().unwrap(),
    }))
    .unwrap();
    let block = Command::new(shk_bin())
        .args(["scan", ".", "--hook-mode", "cursor", "--log-blocked"])
        .current_dir(repo)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            c.stdin.as_mut().unwrap().write_all(stdin.as_bytes())?;
            c.wait_with_output()
        })
        .expect("log-blocked hook");
    assert_eq!(block.status.code(), Some(2));

    let out = Command::new(shk_bin())
        .args(["audit", "--json", "--reason", "finding-threshold"])
        .current_dir(repo)
        .output()
        .expect("audit json");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["summary"]["blocked_events"], 1);
    assert!(!report["by_rule"].as_array().unwrap().is_empty());
    assert!(
        !out.stdout
            .windows(secret.len())
            .any(|w| w == secret.as_bytes())
    );
}

#[test]
fn audit_from_git_subdir_reads_repo_root_log() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    init_git_repo(repo);
    std::fs::write(repo.join("shk.toml"), "").unwrap();
    std::fs::create_dir(repo.join("nested")).unwrap();
    let fpath = repo.join("x.txt");
    let secret = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";
    std::fs::write(
        &fpath,
        format!("// not real credential: synthetic detector fixture value only\nconst demo = \"{secret}\";"),
    )
    .unwrap();
    let stdin = serde_json::to_string(&serde_json::json!({
        "file_path": fpath.to_str().unwrap(),
    }))
    .unwrap();
    let block = Command::new(shk_bin())
        .args(["scan", ".", "--hook-mode", "cursor", "--log-blocked"])
        .current_dir(repo.join("nested"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            c.stdin.as_mut().unwrap().write_all(stdin.as_bytes())?;
            c.wait_with_output()
        })
        .expect("log-blocked hook from subdir");
    assert_eq!(block.status.code(), Some(2));
    assert!(repo.join(".shk/audit.log").is_file());

    let out = Command::new(shk_bin())
        .args(["audit", "--json"])
        .current_dir(repo.join("nested"))
        .output()
        .expect("audit from subdir");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["summary"]["blocked_events"], 1);
    let expected_log = std::fs::canonicalize(repo)
        .unwrap()
        .join(".shk/audit.log")
        .display()
        .to_string();
    assert_eq!(
        report["log_path"].as_str().unwrap_or_default(),
        expected_log,
    );
}

#[test]
fn audit_human_shows_recent_blocked_event() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    std::fs::write(repo.join("shk.toml"), "").unwrap();
    let stdin = serde_json::to_string(&serde_json::json!({
        "hook_event_name": "PermissionRequest",
        "tool_name": "Bash",
        "tool_input": {
            "command": "psql -c \"DROP TABLE users\""
        }
    }))
    .unwrap();
    Command::new(shk_bin())
        .args(["scan", ".", "--hook-mode", "codex", "--log-blocked"])
        .current_dir(repo)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            c.stdin.as_mut().unwrap().write_all(stdin.as_bytes())?;
            c.wait_with_output()
        })
        .expect("log-blocked guard");

    let out = Command::new(shk_bin())
        .args(["audit", "--reason", "action-guard"])
        .current_dir(repo)
        .output()
        .expect("audit human");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Recent events"), "{stdout}");
    assert!(stdout.contains("direct_db_mutation"), "{stdout}");
    assert!(!stdout.contains("DROP TABLE"), "{stdout}");
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
fn hook_mode_antigravity_post_log_blocked_writes_audit_and_empty_stdout() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("shk.toml"), "").unwrap();
    let stdin = serde_json::to_string(&serde_json::json!({
        "stepIdx": 5,
        "error": "tool failed while handling john@example.com",
        "conversationId": "ec33ebf9-0cba-4100-8142-c61503f6c587"
    }))
    .unwrap();

    let out = Command::new(shk_bin())
        .args([
            "scan",
            ".",
            "--hook-mode",
            "antigravity",
            "--log-blocked",
            "--post",
        ])
        .current_dir(dir.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            c.stdin.as_mut().unwrap().write_all(stdin.as_bytes())?;
            c.wait_with_output()
        })
        .expect("antigravity post hook");

    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(stdout, serde_json::json!({}));

    let log = std::fs::read_to_string(dir.path().join(".shk/audit.log")).unwrap();
    assert!(log.contains(r#""tool":"antigravity""#), "{log}");
    assert!(log.contains(r#""hook":"post""#), "{log}");
    assert!(!log.contains("john@example.com"), "{log}");
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
fn init_strict_with_piped_stdin_keeps_policy_only_behavior() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(shk_bin())
        .args(["init", "--strict"])
        .current_dir(dir.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child.stdin.as_mut().unwrap().write_all(b"")?;
            child.wait_with_output()
        })
        .expect("init --strict with piped stdin");
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let policy = std::fs::read_to_string(dir.path().join("shk.toml")).unwrap();
    assert!(policy.contains("default_fail_on = \"medium\""), "{policy}");
    assert!(!dir.path().join(".codex/config.toml").exists());
    assert!(!dir.path().join(".agents/skills/shk/SKILL.md").exists());
}

#[test]
fn init_interactive_retries_invalid_tool_input() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(shk_bin())
        .args(["init", "--no-ai-hooks", "--no-skills"])
        .current_dir(dir.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child.stdin.as_mut().unwrap().write_all(b"\n\n9\n2\n")?;
            child.wait_with_output()
        })
        .expect("init retries invalid tool");
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.starts_with("shk init"), "{stdout}");
    assert!(stdout.contains("  2) Codex"), "{stdout}");
    assert!(stdout.contains("Invalid choice `9`"), "{stdout}");
    assert!(dir.path().join("shk.toml").is_file());
}

#[test]
fn init_yes_sets_up_selected_ai_tool_and_skill() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(shk_bin())
        .args([
            "init",
            "--yes",
            "--tool",
            "codex",
            "--audit",
            "--no-git-hook",
        ])
        .current_dir(dir.path())
        .output()
        .expect("init --yes");
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(dir.path().join("shk.toml").is_file());
    let codex_config = std::fs::read_to_string(dir.path().join(".codex/config.toml")).unwrap();
    assert!(codex_config.contains("hooks = true"), "{codex_config}");
    assert!(
        !codex_config.contains("codex_hooks = true"),
        "{codex_config}"
    );
    assert!(
        codex_config
            .contains(r#"shk scan "$(git rev-parse --show-toplevel)" --hook-mode codex --audit"#),
        "{codex_config}"
    );
    assert!(dir.path().join(".agents/skills/shk/SKILL.md").is_file());
    assert!(!dir.path().join(".claude/skills/shk/SKILL.md").exists());
}

#[test]
fn init_yes_applies_npm_hardening_when_package_json_exists() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("package.json"), r#"{"name":"demo"}"#).unwrap();
    std::fs::write(
        dir.path().join(".npmrc"),
        "registry=https://registry.npmjs.org/\nignore-scripts=false\nmin-release-age=1\n",
    )
    .unwrap();

    let out = Command::new(shk_bin())
        .args([
            "init",
            "--yes",
            "--no-git-hook",
            "--no-ai-hooks",
            "--no-skills",
        ])
        .current_dir(dir.path())
        .output()
        .expect("init --yes npm");
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let npmrc = std::fs::read_to_string(dir.path().join(".npmrc")).unwrap();
    assert!(
        npmrc.contains("registry=https://registry.npmjs.org/"),
        "{npmrc}"
    );
    assert!(npmrc.contains("ignore-scripts=true\n"), "{npmrc}");
    assert!(npmrc.contains("min-release-age=7\n"), "{npmrc}");
    assert_eq!(npmrc.matches("ignore-scripts=").count(), 1, "{npmrc}");
    assert_eq!(npmrc.matches("min-release-age=").count(), 1, "{npmrc}");
}

#[test]
fn init_yes_can_skip_npm_hardening() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("package.json"), r#"{"name":"demo"}"#).unwrap();

    let out = Command::new(shk_bin())
        .args([
            "init",
            "--yes",
            "--no-git-hook",
            "--no-ai-hooks",
            "--no-skills",
            "--no-npm-hardening",
        ])
        .current_dir(dir.path())
        .output()
        .expect("init --yes --no-npm-hardening");
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Skipped npm supply-chain hardening"),
        "{stdout}"
    );
    assert!(!dir.path().join(".npmrc").exists());
}

#[test]
fn init_no_npm_hardening_is_quiet_without_package_json() {
    let dir = tempfile::tempdir().unwrap();

    let out = Command::new(shk_bin())
        .args([
            "init",
            "--yes",
            "--no-git-hook",
            "--no-ai-hooks",
            "--no-skills",
            "--no-npm-hardening",
        ])
        .current_dir(dir.path())
        .output()
        .expect("init --yes --no-npm-hardening without package.json");
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("Skipped npm supply-chain hardening"),
        "{stdout}"
    );
    assert!(!dir.path().join(".npmrc").exists());
}

#[test]
fn init_yes_applies_package_manager_specific_age_gates() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("package.json"),
        r#"{"packageManager":"pnpm@10.0.0"}"#,
    )
    .unwrap();
    std::fs::write(
        dir.path().join("pnpm-lock.yaml"),
        "lockfileVersion: '9.0'\n",
    )
    .unwrap();

    let out = Command::new(shk_bin())
        .args([
            "init",
            "--yes",
            "--no-git-hook",
            "--no-ai-hooks",
            "--no-skills",
        ])
        .current_dir(dir.path())
        .output()
        .expect("init --yes pnpm");
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let npmrc = std::fs::read_to_string(dir.path().join(".npmrc")).unwrap();
    assert!(npmrc.contains("ignore-scripts=true"), "{npmrc}");
    assert!(!npmrc.contains("min-release-age=7"), "{npmrc}");
    let pnpm_workspace = std::fs::read_to_string(dir.path().join("pnpm-workspace.yaml")).unwrap();
    assert!(
        pnpm_workspace.contains("packages:\n  - \".\""),
        "{pnpm_workspace}"
    );
    assert!(
        pnpm_workspace.contains("minimumReleaseAge: 10080"),
        "{pnpm_workspace}"
    );

    let yarn_dir = tempfile::tempdir().unwrap();
    std::fs::write(
        yarn_dir.path().join("package.json"),
        r#"{"packageManager":"yarn@4.0.0"}"#,
    )
    .unwrap();
    std::fs::write(yarn_dir.path().join("yarn.lock"), "").unwrap();
    let out = Command::new(shk_bin())
        .args([
            "init",
            "--yes",
            "--no-git-hook",
            "--no-ai-hooks",
            "--no-skills",
        ])
        .current_dir(yarn_dir.path())
        .output()
        .expect("init --yes yarn");
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let yarnrc = std::fs::read_to_string(yarn_dir.path().join(".yarnrc.yml")).unwrap();
    assert!(yarnrc.contains("npmMinimalAgeGate: 10080"), "{yarnrc}");

    let bun_dir = tempfile::tempdir().unwrap();
    std::fs::write(
        bun_dir.path().join("package.json"),
        r#"{"packageManager":"bun@1.2.0"}"#,
    )
    .unwrap();
    std::fs::write(bun_dir.path().join("bun.lock"), "").unwrap();
    let out = Command::new(shk_bin())
        .args([
            "init",
            "--yes",
            "--no-git-hook",
            "--no-ai-hooks",
            "--no-skills",
        ])
        .current_dir(bun_dir.path())
        .output()
        .expect("init --yes bun");
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let bunfig = std::fs::read_to_string(bun_dir.path().join("bunfig.toml")).unwrap();
    assert!(bunfig.contains("minimumReleaseAge = 604800"), "{bunfig}");
}

#[test]
fn init_yes_places_npmrc_in_nested_package_project() {
    let dir = tempfile::tempdir().unwrap();
    let app = dir.path().join("apps/shk-desktop");
    std::fs::create_dir_all(&app).unwrap();
    std::fs::write(
        app.join("package.json"),
        r#"{"name":"shk-desktop","packageManager":"pnpm@11.1.3"}"#,
    )
    .unwrap();
    std::fs::write(app.join("pnpm-lock.yaml"), "lockfileVersion: '9.0'\n").unwrap();
    std::fs::write(
        app.join(".npmrc"),
        "registry=https://registry.npmjs.org/\nignore-scripts=false\n",
    )
    .unwrap();

    let out = Command::new(shk_bin())
        .args([
            "init",
            "--yes",
            "--no-git-hook",
            "--no-ai-hooks",
            "--no-skills",
        ])
        .current_dir(dir.path())
        .output()
        .expect("init --yes nested pnpm");
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(!dir.path().join(".npmrc").exists());
    let npmrc = std::fs::read_to_string(app.join(".npmrc")).unwrap();
    assert!(
        npmrc.contains("registry=https://registry.npmjs.org/"),
        "{npmrc}"
    );
    assert!(npmrc.contains("ignore-scripts=true\n"), "{npmrc}");
    assert!(!npmrc.contains("min-release-age=7"), "{npmrc}");
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
    let secret = "aB3dE5gH7jK9mN2pQ4rS";
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
fn doctor_env_skips_dotenvx_encrypted_files() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(".env.local"),
        r#"
        DOTENV_PUBLIC_KEY_LOCAL="dotenvx-public-key"
        DATABASE_URL="encrypted:BE9f1wzB2Rf6Sg=="
        API_TOKEN='encrypted:BNwGvFpc2vRW4Q=='
        "#,
    )
    .unwrap();
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
    assert!(
        stdout.contains("env: no plaintext .env / .env.*"),
        "{stdout}"
    );
    assert!(!stdout.contains("plaintext env files detected"), "{stdout}");
    assert!(!stdout.contains(".env.local ("), "{stdout}");
}

#[test]
fn doctor_env_skips_shk_encrypted_files() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(".env.local"),
        r#"
DOTENV_PUBLIC_KEY_LOCAL="03f98bf6e00bce6fdb933bc47738d671dffb75a916fa8c89854bdfa3483902632f"
DATABASE_URL="encrypted:BE9f1wzB2Rf6Sg=="
"#,
    )
    .unwrap();
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
    assert!(
        stdout.contains("env: no plaintext .env / .env.*"),
        "{stdout}"
    );
    assert!(!stdout.contains("plaintext env files detected"), "{stdout}");
    assert!(!stdout.contains(".env.local ("), "{stdout}");
}

#[test]
fn doctor_env_warns_when_encrypted_file_contains_plaintext_values() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(".env.local"),
        r#"
        DOTENV_PUBLIC_KEY_LOCAL="dotenvx-public-key"
        DATABASE_URL="encrypted:BE9f1wzB2Rf6Sg=="
        API_TOKEN=plaintext-token
        "#,
    )
    .unwrap();
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
    assert!(
        stdout.contains("encrypted env files contain plaintext values"),
        "{stdout}"
    );
    assert!(
        stdout.contains(".env.local (1 plaintext key(s): API_TOKEN)"),
        "{stdout}"
    );
    assert!(
        stdout.contains("shk env encrypt <file> --in-place"),
        "{stdout}"
    );
    assert!(!stdout.contains("plaintext env files detected"), "{stdout}");
    assert!(!stdout.contains("plaintext-token"), "{stdout}");
}

#[test]
fn doctor_version_reports_update_available_from_env() {
    let current = env!("CARGO_PKG_VERSION");
    let mut parts = current
        .split('.')
        .map(|part| part.parse::<u64>().unwrap())
        .collect::<Vec<_>>();
    parts[2] += 1;
    let next_patch = format!("v{}.{}.{}", parts[0], parts[1], parts[2]);
    let out = Command::new(shk_bin())
        .args(["doctor", "version"])
        .env("SHK_UPDATE_CHECK_LATEST_TAG", &next_patch)
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
    assert!(stdout.contains(&format!("current: {current}")), "{stdout}");
    assert!(
        stdout.contains(&format!("latest:  {next_patch}")),
        "{stdout}"
    );
}

#[test]
fn doctor_version_json_reports_current_status_from_env() {
    let current = env!("CARGO_PKG_VERSION");
    let latest = format!("v{current}");
    let out = Command::new(shk_bin())
        .args(["doctor", "--json", "version"])
        .env("SHK_UPDATE_CHECK_LATEST_TAG", &latest)
        .env_remove("SHK_UPDATE_CHECK_URL")
        .output()
        .expect("doctor version json");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["current"], current);
    assert_eq!(v["latest"], latest);
    assert_eq!(v["status"], "current");
    assert_eq!(v["update_available"], false);
}

#[test]
fn completions_bash_generates_script() {
    let out = Command::new(shk_bin())
        .args(["completions", "bash"])
        .output()
        .expect("completions bash");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("_shk()"), "{stdout}");
    assert!(stdout.contains("complete -F _shk"), "{stdout}");
}

#[test]
fn status_reports_update_available_from_env() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("shk.toml"),
        "[thresholds]\nscan_fail_on = \"high\"\n",
    )
    .unwrap();
    let current = env!("CARGO_PKG_VERSION");
    let mut parts = current
        .split('.')
        .map(|part| part.parse::<u64>().unwrap())
        .collect::<Vec<_>>();
    parts[2] += 1;
    let next_patch = format!("v{}.{}.{}", parts[0], parts[1], parts[2]);
    let out = Command::new(shk_bin())
        .arg("status")
        .current_dir(dir.path())
        .env("SHK_UPDATE_CHECK_LATEST_TAG", &next_patch)
        .env_remove("SHK_UPDATE_CHECK_URL")
        .output()
        .expect("status");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("status:"), "{stdout}");
    assert!(stdout.contains("shk.toml"), "{stdout}");
    assert!(stdout.contains("update available"), "{stdout}");
    assert!(
        stdout.contains(&format!("{current} -> {next_patch}")),
        "{stdout}"
    );
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
fn env_dotenvx_help_is_registered() {
    let out = Command::new(shk_bin())
        .args(["env", "dotenvx", "--help"])
        .output()
        .expect("env dotenvx help");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("import-keys"), "{stdout}");
    assert!(stdout.contains("run"), "{stdout}");
    assert!(!stdout.contains("export"), "{stdout}");
}

#[test]
fn env_encrypt_help_documents_in_place() {
    let out = Command::new(shk_bin())
        .args(["env", "encrypt", "--help"])
        .output()
        .expect("env encrypt help");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--output"), "{stdout}");
    assert!(stdout.contains("--in-place"), "{stdout}");
    assert!(stdout.contains("--remove-source"), "{stdout}");
}

#[test]
fn env_decrypt_help_hides_encrypt_only_options() {
    let out = Command::new(shk_bin())
        .args(["env", "decrypt", "--help"])
        .output()
        .expect("env decrypt help");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--output"), "{stdout}");
    assert!(stdout.contains("--force"), "{stdout}");
    assert!(!stdout.contains("--in-place"), "{stdout}");
    assert!(!stdout.contains("--remove-source"), "{stdout}");
}

#[test]
fn env_run_help_is_registered() {
    let out = Command::new(shk_bin())
        .args(["env", "run", "--help"])
        .output()
        .expect("env run help");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--file"), "{stdout}");
    assert!(stdout.contains("--env"), "{stdout}");
    assert!(stdout.contains("--key"), "{stdout}");
}

#[test]
fn env_run_reports_missing_key_with_migration_hint() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(".env"),
        r#"
DOTENV_PUBLIC_KEY="03f98bf6e00bce6fdb933bc47738d671dffb75a916fa8c89854bdfa3483902632f"
DATABASE_URL="encrypted:BE9f1wzB2Rf6Sg=="
"#,
    )
    .unwrap();
    let out = Command::new(shk_bin())
        .current_dir(dir.path())
        .args(["env", "run", "--", "sh", "-c", "true"])
        .output()
        .expect("env run");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("shk env encrypt"), "{stderr}");
    assert!(stderr.contains("shk env dotenvx import-keys"), "{stderr}");
}

#[test]
fn env_key_help_is_registered_without_raw_export() {
    let out = Command::new(shk_bin())
        .args(["env", "key", "--help"])
        .output()
        .expect("env key help");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("import"), "{stdout}");
    assert!(stdout.contains("list"), "{stdout}");
    assert!(stdout.contains("delete"), "{stdout}");
    assert!(stdout.contains("export"), "{stdout}");

    let out = Command::new(shk_bin())
        .args(["env", "key", "delete"])
        .output()
        .expect("env key delete");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--all"), "{stderr}");
    assert!(stderr.contains("--key"), "{stderr}");
    assert!(stderr.contains("--env"), "{stderr}");

    let out = Command::new(shk_bin())
        .args(["env", "key", "export", "--help"])
        .output()
        .expect("env key export help");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--instructions"), "{stdout}");
    assert!(!stdout.contains("--print"), "{stdout}");
}

#[test]
fn env_dotenvx_delete_requires_explicit_target() {
    let out = Command::new(shk_bin())
        .args(["env", "dotenvx", "delete"])
        .output()
        .expect("env dotenvx delete");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--all"), "{stderr}");
    assert!(stderr.contains("--key"), "{stderr}");
    assert!(stderr.contains("--env"), "{stderr}");
}

#[test]
fn scan_detects_dotenvx_private_key_without_value() {
    let dir = tempfile::tempdir().unwrap();
    let secret = "dotenvx-secret-demo-value";
    std::fs::write(dir.path().join("shk.toml"), "[scan]\nexclude = []\n").unwrap();
    std::fs::write(
        dir.path().join(".env.keys"),
        format!("DOTENV_PRIVATE_KEY_PRODUCTION={secret}\n"),
    )
    .unwrap();
    let out = Command::new(shk_bin())
        .args([
            "scan",
            dir.path().join(".env.keys").to_str().unwrap(),
            "--json",
            "--fail-on",
            "critical",
        ])
        .output()
        .expect("scan dotenvx key");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains(secret), "{stdout}");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let findings = v["findings"].as_array().unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f["rule_id"] == "secret.dotenvx_private_key"),
        "{v}"
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
fn doctor_ignore_fix_accepts_equivalent_existing_patterns() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("shk.toml"), "").unwrap();
    let original = [
        ".env*",
        "!.env.example",
        "secrets/",
        "credentials/",
        "*.pem",
        "*.key",
        "*.p12",
        "*.mobileprovision",
        "*.log",
        "",
    ]
    .join("\n");
    std::fs::write(dir.path().join(".gitignore"), &original).unwrap();
    let out = Command::new(shk_bin())
        .args(["doctor", "ignore", dir.path().to_str().unwrap(), "--fix"])
        .output()
        .expect("doctor ignore fix");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("ignore: OK (required patterns present in ignore files)"),
        "{stdout}"
    );
    let body = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
    assert_eq!(body, original);
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
        stdout.contains("claude permissions: missing recommended action deny entries"),
        "{stdout}"
    );
    assert!(stdout.contains("Write(.env)"), "{stdout}");
}

#[test]
fn doctor_ignore_accepts_claude_read_denies() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".claude")).unwrap();
    let deny = shk_integrations::claude_recommended_deny_entries();
    std::fs::write(
        dir.path().join(".claude/settings.json"),
        serde_json::json!({"permissions":{"deny": deny}}).to_string(),
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
        stdout.contains("claude permissions: OK (recommended action deny entries present)"),
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
        stdout.contains("codex config: hooks feature enabled"),
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
fn doctor_ignore_reports_codex_risky_default_permissions() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".codex")).unwrap();
    std::fs::write(
        dir.path().join(".codex/config.toml"),
        r#"
default_permissions = ":danger-full-access"
approval_policy = "on-request"
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
        stdout.contains("codex config: warning default_permissions=:danger-full-access"),
        "{stdout}"
    );
}

#[test]
fn doctor_ignore_reports_codex_hooks_disabled() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".codex")).unwrap();
    std::fs::write(
        dir.path().join(".codex/config.toml"),
        r#"[features]
hooks = false
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
        stdout.contains("codex config: hooks feature disabled (`features.hooks = false`)"),
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
hooks = true
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

#[test]
fn doctor_reports_missing_npm_hardening_for_package_json_project() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("shk.toml"), "").unwrap();
    std::fs::write(dir.path().join("package.json"), r#"{"name":"demo"}"#).unwrap();
    std::fs::write(dir.path().join(".npmrc"), "ignore-scripts=false\n").unwrap();

    let out = Command::new(shk_bin())
        .args(["doctor"])
        .current_dir(dir.path())
        .output()
        .expect("doctor");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("npm hardening: package.json detected"),
        "{stdout}"
    );
    assert!(stdout.contains("ignore-scripts=true"), "{stdout}");
    assert!(stdout.contains("min-release-age=7"), "{stdout}");
    assert!(stdout.contains("lockfile missing"), "{stdout}");
    assert!(stdout.contains("minimumReleaseAge"), "{stdout}");
    assert!(stdout.contains(".npmrc"), "{stdout}");
    assert!(stdout.contains("days"), "{stdout}");
}

#[test]
fn doctor_accepts_npm_hardening_for_nested_package_json_project() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("packages/web")).unwrap();
    std::fs::write(dir.path().join("shk.toml"), "").unwrap();
    std::fs::write(
        dir.path().join("packages/web/package.json"),
        r#"{"name":"web"}"#,
    )
    .unwrap();
    std::fs::write(dir.path().join("package-lock.json"), "{}").unwrap();
    std::fs::write(
        dir.path().join("renovate.json"),
        r#"{"packageRules":[{"matchManagers":["npm"],"minimumReleaseAge":"7 days"}]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.path().join(".npmrc"),
        "ignore-scripts=true\nmin-release-age=7\n",
    )
    .unwrap();

    let out = Command::new(shk_bin())
        .args(["doctor"])
        .current_dir(dir.path())
        .output()
        .expect("doctor");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("npm hardening: OK"), "{stdout}");
}

#[test]
fn doctor_accepts_dependabot_npm_cooldown() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(".github")).unwrap();
    std::fs::write(dir.path().join("shk.toml"), "").unwrap();
    std::fs::write(dir.path().join("package.json"), r#"{"name":"demo"}"#).unwrap();
    std::fs::write(dir.path().join("package-lock.json"), "{}").unwrap();
    std::fs::write(
        dir.path().join(".npmrc"),
        "ignore-scripts=true\nmin-release-age=7\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join(".github/dependabot.yml"),
        r#"
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    cooldown:
      default-days: 7
"#,
    )
    .unwrap();

    let out = Command::new(shk_bin())
        .args(["doctor"])
        .current_dir(dir.path())
        .output()
        .expect("doctor");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("npm hardening: OK"), "{stdout}");
}

#[test]
fn skills_install_all_writes_project_skill_files() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(shk_bin())
        .args(["skills", "install"])
        .current_dir(dir.path())
        .output()
        .expect("skills install");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let claude_skill = dir.path().join(".claude/skills/shk/SKILL.md");
    let agents_skill = dir.path().join(".agents/skills/shk/SKILL.md");
    assert!(claude_skill.exists(), "missing {}", claude_skill.display());
    assert!(agents_skill.exists(), "missing {}", agents_skill.display());

    let body = std::fs::read_to_string(agents_skill).unwrap();
    assert!(body.contains("name: shk"), "{body}");
    assert!(body.contains("shk scan"), "{body}");
}

#[test]
fn skills_install_all_preflights_existing_destinations() {
    let dir = tempfile::tempdir().unwrap();
    let agents_skill = dir.path().join(".agents/skills/shk/SKILL.md");
    std::fs::create_dir_all(agents_skill.parent().unwrap()).unwrap();
    std::fs::write(&agents_skill, "existing").unwrap();

    let out = Command::new(shk_bin())
        .args(["skills", "install"])
        .current_dir(dir.path())
        .output()
        .expect("skills install");
    assert!(
        !out.status.success(),
        "stdout={}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("already exists"), "{stderr}");
    assert!(
        !dir.path().join(".claude/skills/shk/SKILL.md").exists(),
        "claude skill should not be partially written"
    );
}

#[test]
fn skills_install_replaces_legacy_claude_skill_file() {
    let dir = tempfile::tempdir().unwrap();
    let legacy = dir.path().join(".claude/skills/shk.md");
    std::fs::create_dir_all(legacy.parent().unwrap()).unwrap();
    std::fs::write(&legacy, "old flat-file skill").unwrap();

    let dry = Command::new(shk_bin())
        .args(["skills", "install", "--tool", "claude-code", "--dry-run"])
        .current_dir(dir.path())
        .output()
        .expect("skills install --dry-run");
    assert!(
        dry.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&dry.stderr)
    );
    let dry_stdout = String::from_utf8_lossy(&dry.stdout);
    assert!(dry_stdout.contains("would remove legacy"), "{dry_stdout}");
    assert!(legacy.is_file(), "dry-run must not remove the legacy file");

    let out = Command::new(shk_bin())
        .args(["skills", "install", "--tool", "claude-code"])
        .current_dir(dir.path())
        .output()
        .expect("skills install");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Removed legacy"), "{stdout}");
    assert!(dir.path().join(".claude/skills/shk/SKILL.md").is_file());
    assert!(!legacy.exists(), "legacy flat file should be removed");
}

#[test]
fn hooks_install_ai_windsurf_writes_cascade_hooks_and_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("shk.toml"), "").unwrap();
    std::fs::create_dir_all(dir.path().join(".windsurf")).unwrap();
    // Pre-existing user hook in a managed event array must be preserved.
    std::fs::write(
        dir.path().join(".windsurf/hooks.json"),
        r#"{"hooks":{"pre_run_command":[{"command":"./my-check.sh","show_output":false}]}}"#,
    )
    .unwrap();

    for _ in 0..2 {
        let out = Command::new(shk_bin())
            .args(["hooks", "install-ai", "--tool", "windsurf"])
            .current_dir(dir.path())
            .output()
            .expect("install-ai windsurf");
        assert!(
            out.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let hooks: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.path().join(".windsurf/hooks.json")).unwrap(),
    )
    .unwrap();

    let pre_run = hooks["hooks"]["pre_run_command"].as_array().unwrap();
    assert!(
        pre_run.iter().any(|e| e["command"] == "./my-check.sh"),
        "user hook must be preserved: {pre_run:?}"
    );
    let managed: Vec<_> = pre_run
        .iter()
        .filter(|e| {
            e["command"]
                .as_str()
                .unwrap_or_default()
                .contains("--hook-mode windsurf")
        })
        .collect();
    assert_eq!(
        managed.len(),
        1,
        "managed hook should not duplicate: {pre_run:?}"
    );

    for key in ["pre_read_code", "pre_write_code", "pre_mcp_tool_use"] {
        let arr = hooks["hooks"][key].as_array().unwrap();
        assert_eq!(arr.len(), 1, "{key}: {arr:?}");
        let cmd = arr[0]["command"].as_str().unwrap();
        assert_eq!(cmd, "shk scan --hook-mode windsurf", "{key}");
        assert_eq!(arr[0]["show_output"], true, "{key}");
    }
    for key in ["post_run_command", "post_mcp_tool_use"] {
        let cmd = hooks["hooks"][key][0]["command"].as_str().unwrap();
        assert!(cmd.contains("--post"), "{key} should scan as post: {cmd}");
    }
    let prompt_cmd = hooks["hooks"]["pre_user_prompt"][0]["command"]
        .as_str()
        .unwrap();
    assert!(
        prompt_cmd.contains(&format!("--fail-on {USER_PROMPT_HOOK_FAIL_ON}")),
        "pre_user_prompt should block medium PII: {prompt_cmd}"
    );
}

#[test]
fn hook_mode_windsurf_blocks_with_exit_2_and_stderr() {
    use std::io::Write;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let dir = tempfile::tempdir_in(&root).unwrap();
    // Neutral filename so the action guard (path-based) does not intercept and
    // the content-scan path is exercised instead.
    let fixture = dir.path().join("hook-fixture.txt");
    // not real credential: synthetic detector fixture value only
    std::fs::write(&fixture, "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789\n").unwrap();
    let fixture = std::fs::canonicalize(fixture).unwrap();
    // Cascade payload shape: agent_action_name + nested tool_info.
    let stdin = serde_json::to_string(&serde_json::json!({
        "agent_action_name": "pre_read_code",
        "tool_info": { "file_path": fixture.to_str().unwrap() },
    }))
    .unwrap();
    let out = Command::new(shk_bin())
        .args(["scan", ".", "--hook-mode", "windsurf"])
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
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // Cascade reads the block reason from stderr, not stdout JSON.
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("sensitive content detected"), "stderr={err}");
}

#[test]
fn hook_mode_windsurf_user_prompt_blocks_secret_prompt() {
    use std::io::Write;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    // Cascade nests the prompt under tool_info.user_prompt with agent_action_name.
    let stdin = serde_json::to_string(&serde_json::json!({
        "agent_action_name": "pre_user_prompt",
        "tool_info": {
            // not a real credential: synthetic detector fixture value only
            "user_prompt": "use this key sk-proj-abcdefghijklmnopqrstuvwxyz0123456789 please",
        },
    }))
    .unwrap();
    let out = Command::new(shk_bin())
        .args(["scan", ".", "--hook-mode", "windsurf"])
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
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("sensitive content detected"), "stderr={err}");
}

#[test]
fn hook_mode_windsurf_allows_clean_prompt() {
    use std::io::Write;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let stdin = serde_json::to_string(&serde_json::json!({
        "agent_action_name": "pre_user_prompt",
        "tool_info": { "user_prompt": "please refactor this helper function" },
    }))
    .unwrap();
    let out = Command::new(shk_bin())
        .args(["scan", ".", "--hook-mode", "windsurf"])
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
        Some(0),
        "clean prompt should pass: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn skills_install_windsurf_uses_windsurf_skills_dir() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(shk_bin())
        .args(["skills", "install", "--tool", "windsurf"])
        .current_dir(dir.path())
        .output()
        .expect("skills install windsurf");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        dir.path().join(".windsurf/skills/shk/SKILL.md").is_file(),
        "windsurf skill should be written to .windsurf/skills/shk/SKILL.md"
    );
}
