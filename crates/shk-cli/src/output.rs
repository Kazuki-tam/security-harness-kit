use shk_core::finding::Finding;
use shk_core::policy::Severity;

pub fn format_human_findings(
    findings: &[Finding],
    color: bool,
    verbose: bool,
    deduplicated: u64,
) -> String {
    let mut s = String::new();
    let hidden_skips = if verbose {
        0
    } else {
        findings.iter().filter(|f| is_skip_finding(f)).count()
    };
    let visible_count = findings.len() - hidden_skips;

    s.push_str(&format!("{visible_count} findings\n\n"));
    for f in findings {
        if !verbose && is_skip_finding(f) {
            continue;
        }
        let sev = format_severity_label(&f.severity, color);
        let line = format!(
            "{sev}  {}  {}:{}    {}",
            f.rule_id, f.file, f.line, f.message
        );
        s.push_str(&line);
        s.push('\n');
    }
    if hidden_skips > 0 {
        s.push_str(&format!(
            "\nSkipped {hidden_skips} files; use --verbose to show details.\n"
        ));
    }
    if deduplicated > 0 {
        s.push_str(&format!(
            "\nDeduplicated {deduplicated} repeated finding(s).\n"
        ));
    }
    s
}

pub fn max_human_severity(findings: &[Finding], verbose: bool) -> Option<Severity> {
    findings
        .iter()
        .filter(|f| verbose || !is_skip_finding(f))
        .filter_map(|f| Severity::parse(&f.severity))
        .max()
}

fn is_skip_finding(f: &Finding) -> bool {
    matches!(
        f.rule_id.as_str(),
        "scan.binary_skipped" | "scan.file_read_error" | "scan.file_too_large"
    )
}

fn abbrev_sev(sev: &str) -> String {
    let u = sev.to_ascii_uppercase();
    match u.as_str() {
        "CRITICAL" => "CRIT".into(),
        "HIGH" => "HIGH".into(),
        "MEDIUM" => "MED ".into(),
        "LOW" => "LOW ".into(),
        "INFO" => "INFO".into(),
        _ => format!("{u:4}"),
    }
}

pub fn format_scan_summary(max: Option<Severity>, threshold: Severity, color: bool) -> String {
    let msg = match max {
        None => "No findings.".to_string(),
        Some(m) if !m.meets_threshold(threshold) => format!(
            "Highest severity: {} (below threshold {}).",
            m.as_str(),
            threshold.as_str()
        ),
        Some(m) => format!(
            "Failed: findings at or above {} (max {}).",
            threshold.as_str(),
            m.as_str()
        ),
    };
    if color {
        colorize_summary(&msg, max)
    } else {
        msg
    }
}

fn format_severity_label(severity: &str, color: bool) -> String {
    let label = abbrev_sev(severity);
    if color {
        colorize_severity_label(&label, severity)
    } else {
        label
    }
}

fn colorize_summary(msg: &str, severity: Option<Severity>) -> String {
    let code = match severity {
        Some(sev) => severity_color_code(sev),
        None => "32",
    };
    ansi(code, msg)
}

fn colorize_severity_label(label: &str, severity: &str) -> String {
    match Severity::parse(severity) {
        Some(sev) => ansi(severity_color_code(sev), label),
        None => ansi("1", label),
    }
}

fn ansi(code: &str, text: &str) -> String {
    format!("\x1b[{code}m{text}\x1b[0m")
}

fn severity_color_code(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "1;31",
        Severity::High => "31",
        Severity::Medium => "33",
        Severity::Low => "34",
        Severity::Info => "36",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(severity: &str) -> Finding {
        Finding {
            rule_id: "demo.rule".into(),
            severity: severity.into(),
            kind: "secret".into(),
            file: "demo.txt".into(),
            line: 7,
            column: 1,
            message: "demo finding".into(),
            redacted_value: "[REDACTED]".into(),
            confidence: 0.9,
            context_before: vec![],
            context_after: vec![],
        }
    }

    fn skip_finding(rule_id: &str) -> Finding {
        Finding {
            rule_id: rule_id.into(),
            severity: "info".into(),
            kind: "ignore".into(),
            file: "demo.txt".into(),
            line: 1,
            column: 1,
            message: "Skipped: demo".into(),
            redacted_value: "[REDACTED]".into(),
            confidence: 1.0,
            context_before: vec![],
            context_after: vec![],
        }
    }

    #[test]
    fn colorizes_human_finding_severity_labels_by_level() {
        let findings = vec![
            finding("critical"),
            finding("high"),
            finding("medium"),
            finding("low"),
            finding("info"),
        ];

        let out = format_human_findings(&findings, true, false, 0);

        assert!(out.contains("\x1b[1;31mCRIT\x1b[0m"));
        assert!(out.contains("\x1b[31mHIGH\x1b[0m"));
        assert!(out.contains("\x1b[33mMED \x1b[0m"));
        assert!(out.contains("\x1b[34mLOW \x1b[0m"));
        assert!(out.contains("\x1b[36mINFO\x1b[0m"));
    }

    #[test]
    fn leaves_human_finding_severity_labels_plain_without_color() {
        let out = format_human_findings(&[finding("high")], false, false, 0);

        assert!(out.contains("HIGH  demo.rule  demo.txt:7"));
        assert!(!out.contains("\x1b["));
    }

    #[test]
    fn colorizes_scan_summary_by_max_severity() {
        let out = format_scan_summary(Some(Severity::High), Severity::High, true);

        assert_eq!(
            out,
            "\x1b[31mFailed: findings at or above high (max high).\x1b[0m"
        );
    }

    #[test]
    fn colorizes_empty_scan_summary_as_success() {
        let out = format_scan_summary(None, Severity::High, true);

        assert_eq!(out, "\x1b[32mNo findings.\x1b[0m");
    }

    #[test]
    fn human_findings_report_deduplicated_count() {
        let out = format_human_findings(&[finding("high")], false, false, 2);

        assert!(out.contains("Deduplicated 2 repeated finding(s)."));
    }

    #[test]
    fn human_findings_hide_file_read_error_skips_unless_verbose() {
        let skipped = skip_finding("scan.file_read_error");
        let quiet = format_human_findings(std::slice::from_ref(&skipped), false, false, 0);

        assert!(quiet.contains("0 findings"));
        assert!(quiet.contains("Skipped 1 files; use --verbose to show details."));
        assert!(!quiet.contains("scan.file_read_error"));
        assert_eq!(
            max_human_severity(std::slice::from_ref(&skipped), false),
            None
        );

        let verbose = format_human_findings(&[skipped], false, true, 0);
        assert!(verbose.contains("scan.file_read_error"));
        assert_eq!(
            max_human_severity(&[skip_finding("scan.file_read_error")], true),
            Some(Severity::Info)
        );
    }
}
