use shk_core::policy::{Policy, Severity};
use shk_core::scanner::{ScanOptions, scan_path};
use std::path::PathBuf;

#[test]
fn scan_basic_fixture_dir() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/basic");
    let root = std::fs::canonicalize(&root).unwrap();
    let opts = ScanOptions {
        staged: false,
        json: false,
        fail_on_override: Some(Severity::Critical),
        use_pre_commit_threshold: false,
        include_context: true,
        include_binary: false,
        follow_symlinks: false,
    };
    let res = scan_path(&root, opts).expect("scan");
    assert!(
        res.findings
            .iter()
            .any(|f| f.rule_id == "secret.openai_api_key"),
        "findings={:?}",
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
