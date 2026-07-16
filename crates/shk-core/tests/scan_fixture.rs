use shk_core::policy::{Policy, Severity};
use shk_core::scanner::{ScanOptions, scan_path};
use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

fn default_scan_options() -> ScanOptions {
    ScanOptions {
        fail_on_override: Some(Severity::Critical),
        include_context: true,
        ..ScanOptions::default()
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
        "pii.ja.address",
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
fn env_fixture_detects_sensitive_assignments_and_skips_placeholders() {
    let res = scan_fixture("env");
    assert!(
        has_finding(&res, "env.sensitive_assignment", "sample.env"),
        "missing env assignment finding: {:?}",
        res.findings
    );
    assert!(
        !has_finding(&res, "env.sensitive_assignment", "placeholders.env"),
        "placeholder values must stay clean: {:?}",
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

#[test]
fn scan_detects_docx_content() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("report.docx");
    let secret = synthetic_openai_key('a');
    create_minimal_docx(&file, &secret);

    let res = scan_path(&file, default_scan_options()).expect("scan docx");

    assert!(
        has_finding(
            &res,
            "secret.openai_api_key",
            "report.docx:word/document.xml"
        ),
        "{:?}",
        res.findings
    );
    assert!(
        !has_finding(&res, "scan.binary_skipped", "report.docx"),
        "{:?}",
        res.findings
    );
}

#[test]
fn scan_allows_office_entry_path_suppression() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(
        dir.path(),
        r#"[[allowlist]]
rule_id = "secret.openai_api_key"
path = "report.docx:word/document.xml"
reason = "fixture"
"#,
    );
    let file = dir.path().join("report.docx");
    let secret = synthetic_openai_key('a');
    create_minimal_docx(&file, &secret);

    let res = scan_path(&file, default_scan_options()).expect("scan docx");

    assert!(
        !has_rule(&res, "secret.openai_api_key"),
        "{:?}",
        res.findings
    );
    assert_eq!(res.suppressed, 1, "{:?}", res.findings);
}

#[test]
fn scan_detects_xlsx_content_split_across_rich_text() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("workbook.xlsx");
    let secret = synthetic_openai_key('a');
    let (left, right) = secret.split_at(9);
    create_minimal_xlsx(
        &file,
        &format!("{left}</t><r><t>{right}</t></r><t>"),
        "clean",
    );

    let res = scan_path(&file, default_scan_options()).expect("scan xlsx");

    assert!(
        has_finding(
            &res,
            "secret.openai_api_key",
            "workbook.xlsx:xl/sharedStrings.xml"
        ),
        "{:?}",
        res.findings
    );
}

#[test]
fn scan_detects_pptx_content() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("slides.pptx");
    let secret = synthetic_openai_key('a');
    create_minimal_pptx(&file, &secret);

    let res = scan_path(&file, default_scan_options()).expect("scan pptx");

    assert!(
        has_finding(
            &res,
            "secret.openai_api_key",
            "slides.pptx:ppt/slides/slide1.xml"
        ),
        "{:?}",
        res.findings
    );
}

#[test]
fn scan_detects_pdf_text_layer_secret_and_pii() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("report.pdf");
    let secret = synthetic_openai_key('a');
    create_minimal_pdf(&file, &format!("token {secret} contact alice@example.com"));

    let res = scan_path(&file, default_scan_options()).expect("scan pdf");

    assert!(
        has_finding(&res, "secret.openai_api_key", "report.pdf"),
        "{:?}",
        res.findings
    );
    assert!(
        has_finding(&res, "pii.email", "report.pdf"),
        "{:?}",
        res.findings
    );
    assert!(
        !has_finding(&res, "scan.binary_skipped", "report.pdf"),
        "{:?}",
        res.findings
    );
}

#[test]
fn scan_reports_pdf_without_extractable_text() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("empty.pdf");
    create_minimal_pdf(&file, "");

    let res = scan_path(&file, default_scan_options()).expect("scan empty pdf");

    assert!(
        has_finding(&res, "scan.document_text_empty", "empty.pdf"),
        "{:?}",
        res.findings
    );
    assert!(
        !has_finding(&res, "scan.binary_skipped", "empty.pdf"),
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

fn synthetic_openai_key(seed: char) -> String {
    format!("sk-proj-{seed}bcdefghijklmnopqrstuvwxyz0123456789")
}

fn deflated_zip_options() -> zip::write::FileOptions<'static, ()> {
    zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated)
}

fn create_minimal_docx(path: &Path, text: &str) {
    let file = fs::File::create(path).unwrap();
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
    let file = fs::File::create(path).unwrap();
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
    let file = fs::File::create(path).unwrap();
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

fn create_minimal_pdf(path: &Path, text: &str) {
    let escaped = pdf_string_escape(text);
    let stream = format!("BT /F1 12 Tf 72 720 Td ({escaped}) Tj ET\n");
    let objects = [
        "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_string(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>".to_string(),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_string(),
        format!("<< /Length {} >>\nstream\n{stream}endstream", stream.len()),
    ];

    let mut body = String::from("%PDF-1.4\n");
    let mut offsets = Vec::new();
    for (idx, object) in objects.iter().enumerate() {
        offsets.push(body.len());
        body.push_str(&format!("{} 0 obj\n{object}\nendobj\n", idx + 1));
    }

    let xref_offset = body.len();
    body.push_str("xref\n0 6\n0000000000 65535 f \n");
    for offset in offsets {
        body.push_str(&format!("{offset:010} 00000 n \n"));
    }
    body.push_str(&format!(
        "trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n"
    ));

    fs::write(path, body).unwrap();
}

fn pdf_string_escape(text: &str) -> String {
    text.replace('\\', r"\\")
        .replace('(', r"\(")
        .replace(')', r"\)")
}
