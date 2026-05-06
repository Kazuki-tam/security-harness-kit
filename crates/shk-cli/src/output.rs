use shk_core::finding::Finding;
use shk_core::policy::Severity;

pub fn format_human_findings(findings: &[Finding], color: bool) -> String {
    let mut s = String::new();
    s.push_str(&format!("{} findings\n\n", findings.len()));
    for f in findings {
        let sev = abbrev_sev(&f.severity);
        let line = if color {
            format!(
                "\x1b[1m{sev}\x1b[0m  {}  {}:{}    {}",
                f.rule_id, f.file, f.line, f.message
            )
        } else {
            format!(
                "{sev}  {}  {}:{}    {}",
                f.rule_id, f.file, f.line, f.message
            )
        };
        s.push_str(&line);
        s.push('\n');
    }
    s
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
        format!("\x1b[36m{msg}\x1b[0m")
    } else {
        msg
    }
}
