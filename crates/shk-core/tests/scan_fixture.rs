use shk_core::policy::{Policy, Severity};
use shk_core::scanner::{ScanOptions, scan_path};
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

fn default_scan_options() -> ScanOptions {
    ScanOptions {
        staged: false,
        json: false,
        fail_on_override: Some(Severity::Critical),
        use_pre_commit_threshold: false,
        include_context: true,
        include_binary: false,
        follow_symlinks: false,
    }
}

fn scan_fixture(relative: &str) -> shk_core::scanner::ScanResult {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../fixtures/{relative}"));
    let root = std::fs::canonicalize(&root).unwrap();
    scan_path(&root, default_scan_options()).expect("scan fixture")
}

fn finding_ids(result: &shk_core::scanner::ScanResult) -> BTreeSet<&str> {
    result.findings.iter().map(|f| f.rule_id.as_str()).collect()
}

fn has_finding(result: &shk_core::scanner::ScanResult, rule_id: &str, file: &str) -> bool {
    result
        .findings
        .iter()
        .any(|f| f.rule_id == rule_id && f.file == file)
}

fn has_rule(result: &shk_core::scanner::ScanResult, rule_id: &str) -> bool {
    result.findings.iter().any(|f| f.rule_id == rule_id)
}

fn write_policy(root: &std::path::Path, body: &str) {
    fs::write(root.join("shk.toml"), body).unwrap();
}

#[test]
fn scan_basic_fixture_dir() {
    let res = scan_fixture("basic");
    assert!(
        has_rule(&res, "secret.openai_api_key"),
        "findings={:?}",
        res.findings
    );
}

#[test]
fn pii_detection_fixtures_cover_expected_rules() {
    let res = scan_fixture("pii/en");
    let ids = finding_ids(&res);

    for expected in [
        "pii.email",
        "pii.credit_card",
        "pii.ipv4",
        "pii.ipv6",
        "pii.en.phone",
        "pii.en.ein",
        "pii.en.postal_code",
        "pii.en.passport",
        "pii.en.name",
        "pii.en.address",
        "pii.en.ssn",
    ] {
        assert!(
            ids.contains(expected),
            "missing {expected}: {:?}",
            res.findings
        );
    }

    let res = scan_fixture("pii/ja");
    let ids = finding_ids(&res);
    for expected in [
        "pii.ja.phone",
        "pii.ja.postal_code",
        "pii.ja.passport",
        "pii.ja.my_number",
        "pii.ja.corporate_number",
        "pii.ja.drivers_license",
        "pii.ja.bank_account",
        "pii.ja.health_insurance",
        "pii.ja.name",
    ] {
        assert!(
            ids.contains(expected),
            "missing {expected}: {:?}",
            res.findings
        );
    }

    let res = scan_fixture("pii/mixed");
    let ids = finding_ids(&res);
    for expected in ["pii.email", "pii.en.phone", "pii.ja.phone", "pii.ja.name"] {
        assert!(
            ids.contains(expected),
            "missing {expected}: {:?}",
            res.findings
        );
    }
}

#[test]
fn pii_false_positive_fixture_stays_clean() {
    let res = scan_fixture("pii/false_positives");
    assert!(
        res.findings.iter().all(|f| f.kind != "pii"),
        "unexpected PII findings: {:?}",
        res.findings
    );
}

#[test]
fn secret_provider_fixtures_cover_expected_rules() {
    let res = scan_fixture("secrets");
    let ids = finding_ids(&res);

    for expected in [
        "secret.anthropic_api_key",
        "secret.google_api_key",
        "secret.github_token",
        "secret.slack_token",
        "secret.stripe_api_key",
        "secret.database_url",
        "secret.jwt",
        "secret.bearer_token",
    ] {
        assert!(
            ids.contains(expected),
            "missing {expected}: {:?}",
            res.findings
        );
    }
    assert!(
        !ids.contains("secret.openai_api_key"),
        "provider fixtures should not be classified as OpenAI keys: {:?}",
        res.findings
    );
}

#[test]
fn scan_reports_large_file_skips() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(
        dir.path(),
        r#"[scan]
max_file_size_bytes = 8
"#,
    );
    let file = dir.path().join("large.txt");
    // not real credential: synthetic detector fixture value only
    fs::write(&file, "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789").unwrap();

    let res = scan_path(&file, default_scan_options()).expect("scan large file");
    assert!(
        has_finding(&res, "scan.file_too_large", "large.txt"),
        "{:?}",
        res.findings
    );
}

#[test]
fn scan_reports_binary_skips() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("image.dat");
    fs::write(&file, b"\x89PNG\0secret-ish").unwrap();

    let res = scan_path(&file, default_scan_options()).expect("scan binary file");
    assert!(
        has_finding(&res, "scan.binary_skipped", "image.dat"),
        "{:?}",
        res.findings
    );
}

#[cfg(unix)]
#[test]
fn scan_reports_unreadable_file_skips() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("unreadable.txt");
    fs::write(&file, "nothing sensitive").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o000)).unwrap();

    let res = scan_path(&file, default_scan_options()).expect("scan unreadable file");
    assert!(
        has_finding(&res, "scan.file_read_error", "unreadable.txt"),
        "{:?}",
        res.findings
    );
    assert!(
        res.findings
            .iter()
            .any(|f| f.message.starts_with("Skipped: could not read file")),
        "{:?}",
        res.findings
    );
}

#[test]
fn scan_default_policy_excludes_static_media_assets() {
    let dir = tempfile::tempdir().unwrap();
    for name in ["favicon.svg", "photo.avif", "clip.mp4", "sound.mp3"] {
        let file = dir.path().join(name);
        // not real credential: synthetic detector fixture value only
        fs::write(&file, "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789").unwrap();
    }

    let res = scan_path(dir.path(), default_scan_options()).expect("scan media files");
    assert!(res.findings.is_empty(), "{:?}", res.findings);
}

#[test]
fn scan_handles_crlf_line_numbers() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("crlf.txt");
    fs::write(
        &file,
        // not real credential: synthetic detector fixture value only
        "first line\r\nsk-proj-abcdefghijklmnopqrstuvwxyz0123456789\r\n",
    )
    .unwrap();

    let res = scan_path(&file, default_scan_options()).expect("scan crlf file");
    let hit = res
        .findings
        .iter()
        .find(|f| f.rule_id == "secret.openai_api_key")
        .expect("openai key finding");
    assert_eq!(hit.line, 2, "{:?}", res.findings);
}

#[test]
fn scan_handles_unicode_paths() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("秘密.txt");
    // not real credential: synthetic detector fixture value only
    fs::write(&file, "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789").unwrap();

    let res = scan_path(&file, default_scan_options()).expect("scan unicode file");
    assert!(
        has_finding(&res, "secret.openai_api_key", "秘密.txt"),
        "{:?}",
        res.findings
    );
}

#[test]
fn scan_respects_gitignore_files() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join(".git")).unwrap();
    fs::write(dir.path().join(".gitignore"), "ignored.txt\n").unwrap();
    fs::write(
        dir.path().join("ignored.txt"),
        // not real credential: synthetic detector fixture value only
        "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789",
    )
    .unwrap();
    fs::write(dir.path().join("clean.txt"), "nothing sensitive").unwrap();

    let res = scan_path(dir.path(), default_scan_options()).expect("scan ignored project");
    assert!(
        !res.scanned_paths.iter().any(|p| p == "ignored.txt"),
        "{:?}",
        res.scanned_paths
    );
    assert!(
        !has_rule(&res, "secret.openai_api_key"),
        "{:?}",
        res.findings
    );
}

#[test]
fn scan_one_file_via_rules() {
    let p =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/basic/insecure-sample.txt");
    let p = std::fs::canonicalize(&p).unwrap();
    let policy = Policy::default();
    let text = std::fs::read_to_string(&p).unwrap();
    let ms = shk_rules::scan_content(&text, "insecure-sample.txt", &policy.rule_engine_config());
    assert!(
        ms.iter().any(|m| m.rule_id == "secret.openai_api_key"),
        "{ms:?}"
    );
}
