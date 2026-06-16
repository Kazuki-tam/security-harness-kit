use anyhow::{Context, Result, bail};
use shk_core::finding::{Finding, ScanJsonReport};
use std::collections::BTreeSet;
use std::io::Read;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct SuggestArgs {
    pub from: PathBuf,
    pub value_hash: bool,
    pub reason: Option<String>,
    pub expires: Option<String>,
}

pub fn suggest(args: SuggestArgs) -> Result<()> {
    let input = read_input(&args.from)?;
    let report: ScanJsonReport =
        serde_json::from_str(&input).context("parse scan JSON report from --from")?;
    let allowlist_candidates: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| is_allowlist_candidate(finding))
        .collect();
    if args.value_hash
        && !allowlist_candidates.is_empty()
        && allowlist_candidates
            .iter()
            .any(|finding| finding.value_hash.is_none())
    {
        bail!(
            "report does not contain value_hash metadata; rerun `shk scan --json --with-value-hash`"
        );
    }
    let suggestions = suggestions_from_findings(
        &report.findings,
        args.value_hash,
        args.reason.as_deref(),
        args.expires.as_deref(),
    );

    if suggestions.is_empty() {
        println!("# No allowlist suggestions.");
        return Ok(());
    }

    println!(
        "# Review before adding to shk.toml. Entries suppress future findings; raw secret values are not included."
    );
    if args.value_hash {
        println!(
            "# value_hash entries are deterministic fingerprints; treat this output as sensitive when values may be low entropy."
        );
    }
    for entry in suggestions {
        println!("\n{entry}");
    }
    Ok(())
}

fn read_input(path: &PathBuf) -> Result<String> {
    if path == &PathBuf::from("-") {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("read scan JSON report from stdin")?;
        if buf.trim().is_empty() {
            bail!("stdin is empty");
        }
        return Ok(buf);
    }
    std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))
}

fn suggestions_from_findings(
    findings: &[Finding],
    value_hash: bool,
    reason: Option<&str>,
    expires: Option<&str>,
) -> Vec<String> {
    let mut seen = BTreeSet::<String>::new();
    for finding in findings {
        if !is_allowlist_candidate(finding) {
            continue;
        }
        let rendered = render_entry(finding, value_hash, reason, expires);
        seen.insert(rendered);
    }
    seen.into_iter().collect()
}

fn render_entry(
    finding: &Finding,
    value_hash: bool,
    reason: Option<&str>,
    expires: Option<&str>,
) -> String {
    let mut out = String::new();
    out.push_str("[[allowlist]]\n");
    out.push_str(&format!(
        "rule_id = \"{}\"\n",
        toml_escape(&finding.rule_id)
    ));
    out.push_str(&format!("path = \"{}\"\n", toml_escape(&finding.file)));
    if value_hash && let Some(hash) = &finding.value_hash {
        out.push_str(&format!("value_hash = \"{}\"\n", toml_escape(hash)));
    }
    out.push_str(&format!(
        "reason = \"{}\"\n",
        toml_escape(reason.unwrap_or("TODO: explain why this finding is safe"))
    ));
    if let Some(exp) = expires {
        out.push_str(&format!("expires = \"{}\"\n", toml_escape(exp)));
    }
    out
}

fn is_allowlist_candidate(finding: &Finding) -> bool {
    finding.severity != "info"
        && finding.kind != "ignore"
        && !finding.rule_id.starts_with("scan.")
        && !finding.rule_id.starts_with("policy.")
}

fn toml_escape(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggests_path_allowlist_without_raw_value() {
        let finding = Finding {
            rule_id: "secret.generic_api_key".into(),
            severity: "high".into(),
            kind: "secret".into(),
            file: "fixtures/demo.env".into(),
            line: 3,
            column: 1,
            message: "Possible API key detected".into(),
            redacted_value: "[REDACTED]".into(),
            value_hash: Some("sha256-hmac:abc".into()),
            confidence: 0.9,
            context_before: vec![],
            context_after: vec![],
        };

        let suggestions =
            suggestions_from_findings(&[finding], false, Some("Intentional fixture"), None);

        assert_eq!(suggestions.len(), 1);
        assert!(suggestions[0].contains("rule_id = \"secret.generic_api_key\""));
        assert!(suggestions[0].contains("path = \"fixtures/demo.env\""));
        assert!(!suggestions[0].contains("value_hash"));
        assert!(!suggestions[0].contains("Possible API key"));
    }

    #[test]
    fn can_include_value_hash() {
        let finding = Finding {
            rule_id: "pii.email".into(),
            severity: "medium".into(),
            kind: "pii".into(),
            file: "README.md".into(),
            line: 1,
            column: 1,
            message: "Email address detected".into(),
            redacted_value: "[REDACTED]".into(),
            value_hash: Some("sha256-hmac:def".into()),
            confidence: 0.8,
            context_before: vec![],
            context_after: vec![],
        };

        let suggestions =
            suggestions_from_findings(&[finding], true, Some("Public address"), Some("2026-12-31"));

        assert!(suggestions[0].contains("value_hash = \"sha256-hmac:def\""));
        assert!(suggestions[0].contains("expires = \"2026-12-31\""));
    }

    #[test]
    fn value_hash_request_requires_hash_metadata() {
        let report = ScanJsonReport {
            version: 1,
            scanned_paths: vec!["demo.env".into()],
            findings: vec![Finding {
                rule_id: "secret.generic_api_key".into(),
                severity: "high".into(),
                kind: "secret".into(),
                file: "demo.env".into(),
                line: 1,
                column: 1,
                message: "Possible API key detected".into(),
                redacted_value: "[REDACTED]".into(),
                value_hash: None,
                confidence: 0.9,
                context_before: vec![],
                context_after: vec![],
            }],
            summary: shk_core::finding::ScanSummary {
                total: 1,
                by_severity: std::collections::BTreeMap::new(),
            },
            exit_threshold: "high".into(),
            policy_path: None,
            suppressed: 0,
            deduplicated: 0,
            color_mode: "never".into(),
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.json");
        std::fs::write(&path, serde_json::to_string(&report).unwrap()).unwrap();

        let err = suggest(SuggestArgs {
            from: path,
            value_hash: true,
            reason: None,
            expires: None,
        })
        .unwrap_err()
        .to_string();

        assert!(
            err.contains("rerun `shk scan --json --with-value-hash`"),
            "{err}"
        );
    }

    #[test]
    fn value_hash_request_requires_hash_metadata_on_allowlist_candidates() {
        let report = ScanJsonReport {
            version: 1,
            scanned_paths: vec!["demo.env".into()],
            findings: vec![
                Finding {
                    rule_id: "scan.binary_skipped".into(),
                    severity: "info".into(),
                    kind: "ignore".into(),
                    file: "image.png".into(),
                    line: 1,
                    column: 1,
                    message: "Skipped binary file".into(),
                    redacted_value: "[REDACTED]".into(),
                    value_hash: Some("sha256-hmac:noncandidate".into()),
                    confidence: 1.0,
                    context_before: vec![],
                    context_after: vec![],
                },
                Finding {
                    rule_id: "secret.generic_api_key".into(),
                    severity: "high".into(),
                    kind: "secret".into(),
                    file: "demo.env".into(),
                    line: 1,
                    column: 1,
                    message: "Possible API key detected".into(),
                    redacted_value: "[REDACTED]".into(),
                    value_hash: None,
                    confidence: 0.9,
                    context_before: vec![],
                    context_after: vec![],
                },
            ],
            summary: shk_core::finding::ScanSummary {
                total: 2,
                by_severity: std::collections::BTreeMap::new(),
            },
            exit_threshold: "high".into(),
            policy_path: None,
            suppressed: 0,
            deduplicated: 0,
            color_mode: "never".into(),
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.json");
        std::fs::write(&path, serde_json::to_string(&report).unwrap()).unwrap();

        let err = suggest(SuggestArgs {
            from: path,
            value_hash: true,
            reason: None,
            expires: None,
        })
        .unwrap_err()
        .to_string();

        assert!(
            err.contains("rerun `shk scan --json --with-value-hash`"),
            "{err}"
        );
    }

    #[test]
    fn skips_policy_and_ignore_findings() {
        let findings = vec![
            Finding {
                rule_id: "policy.allowlist_expired".into(),
                severity: "low".into(),
                kind: "ignore".into(),
                file: "shk.toml".into(),
                line: 1,
                column: 1,
                message: "Expired allowlist entry".into(),
                redacted_value: "[REDACTED]".into(),
                value_hash: None,
                confidence: 1.0,
                context_before: vec![],
                context_after: vec![],
            },
            Finding {
                rule_id: "scan.binary_skipped".into(),
                severity: "info".into(),
                kind: "ignore".into(),
                file: "image.png".into(),
                line: 1,
                column: 1,
                message: "Skipped binary file".into(),
                redacted_value: "[REDACTED]".into(),
                value_hash: None,
                confidence: 1.0,
                context_before: vec![],
                context_after: vec![],
            },
        ];

        let suggestions = suggestions_from_findings(&findings, false, None, None);

        assert!(suggestions.is_empty(), "{suggestions:?}");
    }

    #[test]
    fn toml_escape_handles_control_characters() {
        assert_eq!(toml_escape("a\u{0001}\u{0008}\u{000c}z"), "a\\u0001\\b\\fz");
    }
}
