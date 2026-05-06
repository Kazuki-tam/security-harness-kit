use shk_core::policy::{Policy, Severity};
use shk_core::scanner::{ScanOptions, scan_path};
use std::collections::BTreeSet;
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

#[test]
fn scan_basic_fixture_dir() {
    let res = scan_fixture("basic");
    assert!(
        res.findings
            .iter()
            .any(|f| f.rule_id == "secret.openai_api_key"),
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
