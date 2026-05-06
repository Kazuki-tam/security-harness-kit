use crate::policy::Severity;
use serde::Serialize;
use shk_rules::{Kind, RuleEngineConfig, redact_line_for_display};

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: String,
    pub kind: String,
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub message: String,
    pub redacted_value: String,
    pub confidence: f32,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub context_before: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub context_after: Vec<String>,
}

impl Finding {
    pub fn from_rule_match(
        file: &str,
        m: &shk_rules::RuleMatch,
        include_context: bool,
        content: &str,
        rule_cfg: &RuleEngineConfig,
    ) -> Self {
        let (ctx_before, ctx_after) = if include_context {
            context_lines(content, m.line, 1)
        } else {
            (vec![], vec![])
        };
        Self {
            rule_id: m.rule_id.to_string(),
            severity: Severity::from(m.severity).as_str().to_string(),
            kind: kind_str(m.kind).to_string(),
            file: file.to_string(),
            line: m.line,
            column: m.column,
            message: m.message.to_string(),
            redacted_value: "[REDACTED]".into(),
            confidence: m.confidence,
            context_before: sanitize_context(ctx_before, rule_cfg),
            context_after: sanitize_context(ctx_after, rule_cfg),
        }
    }
}

fn kind_str(k: Kind) -> &'static str {
    match k {
        Kind::Secret => "secret",
        Kind::Pii => "pii",
        Kind::Env => "env",
        Kind::AiContext => "ai-context",
        Kind::Ignore => "ignore",
        Kind::Git => "git",
    }
}

fn context_lines(content: &str, line_1based: usize, n: usize) -> (Vec<String>, Vec<String>) {
    let lines: Vec<&str> = content.lines().collect();
    if lines.is_empty() || line_1based == 0 {
        return (vec![], vec![]);
    }
    let idx = line_1based
        .saturating_sub(1)
        .min(lines.len().saturating_sub(1));
    let start = idx.saturating_sub(n);
    let before: Vec<String> = lines[start..idx].iter().map(|s| (*s).to_string()).collect();
    let end = (idx + 1 + n).min(lines.len());
    let after: Vec<String> = if idx + 1 < lines.len() {
        lines[idx + 1..end]
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    } else {
        vec![]
    };
    (before, after)
}

fn sanitize_context(lines: Vec<String>, cfg: &RuleEngineConfig) -> Vec<String> {
    lines
        .into_iter()
        .map(|l| redact_line_for_display(&l, cfg))
        .collect()
}

#[derive(Debug, Serialize)]
pub struct ScanJsonReport {
    pub version: u32,
    pub scanned_paths: Vec<String>,
    pub findings: Vec<Finding>,
    pub summary: ScanSummary,
    pub exit_threshold: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_path: Option<String>,
    pub suppressed: u64,
    pub color_mode: String,
}

#[derive(Debug, Serialize)]
pub struct ScanSummary {
    pub total: usize,
    pub by_severity: std::collections::BTreeMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use shk_rules::RuleEngineConfig;

    #[test]
    fn context_never_leaks_raw_email() {
        let cfg = RuleEngineConfig::default();
        // not real credential or personal data: synthetic detector fixture value only
        let content = "line0 ok\nline1 user@secret.com\nline2 tail\n";
        let m = shk_rules::scan_content(content, "x.txt", &cfg)
            .into_iter()
            .find(|x| x.rule_id == "pii.email")
            .expect("email match");
        let f = Finding::from_rule_match("x.txt", &m, true, content, &cfg);
        let blob = format!("{:?}{:?}", f.context_before, f.context_after);
        assert!(!blob.contains("secret.com"));
    }
}
