use crate::custom_rules::{CompiledCustomRule, CustomMatch};
use crate::policy::Severity;
use serde::ser::{SerializeSeq, SerializeStruct};
use serde::{Deserialize, Serialize};
use shk_rules::{Kind, RuleEngineConfig, redact_line_for_display};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: String,
    pub kind: String,
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub message: String,
    pub redacted_value: String,
    #[serde(skip_serializing, default)]
    pub value_hash: Option<String>,
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
        Self::from_rule_match_with_custom_context(file, m, include_context, content, rule_cfg, &[])
    }

    pub(crate) fn from_rule_match_with_custom_context(
        file: &str,
        m: &shk_rules::RuleMatch,
        include_context: bool,
        content: &str,
        rule_cfg: &RuleEngineConfig,
        custom_rules: &[CompiledCustomRule],
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
            value_hash: Some(crate::suppression::compute_value_hmac(
                m.rule_id,
                &m.matched_text,
            )),
            confidence: m.confidence,
            context_before: sanitize_context(ctx_before, rule_cfg, custom_rules),
            context_after: sanitize_context(ctx_after, rule_cfg, custom_rules),
        }
    }

    pub(crate) fn from_custom_match(
        file: &str,
        m: &CustomMatch,
        include_context: bool,
        content: &str,
        rule_cfg: &RuleEngineConfig,
        custom_rules: &[CompiledCustomRule],
    ) -> Self {
        let (ctx_before, ctx_after) = if include_context {
            context_lines(content, m.line, 1)
        } else {
            (vec![], vec![])
        };
        Self {
            rule_id: m.rule_id.clone(),
            severity: m.severity.as_str().to_string(),
            kind: m.kind.clone(),
            file: file.to_string(),
            line: m.line,
            column: m.column,
            message: m.message.clone(),
            redacted_value: "[REDACTED]".into(),
            value_hash: Some(crate::suppression::compute_value_hmac(
                &m.rule_id,
                &m.matched_text,
            )),
            confidence: m.confidence,
            context_before: sanitize_context(ctx_before, rule_cfg, custom_rules),
            context_after: sanitize_context(ctx_after, rule_cfg, custom_rules),
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

fn sanitize_context(
    lines: Vec<String>,
    cfg: &RuleEngineConfig,
    custom_rules: &[CompiledCustomRule],
) -> Vec<String> {
    lines
        .into_iter()
        .map(|l| {
            let redacted = redact_line_for_display(&l, cfg);
            crate::custom_rules::redact_line_for_display(&redacted, custom_rules)
        })
        .collect()
}

#[derive(Debug, Deserialize)]
pub struct ScanJsonReport {
    pub version: u32,
    pub scanned_paths: Vec<String>,
    pub findings: Vec<Finding>,
    pub summary: ScanSummary,
    pub exit_threshold: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_path: Option<String>,
    pub suppressed: u64,
    pub deduplicated: u64,
    pub color_mode: String,
}

impl Serialize for ScanJsonReport {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut len = 8;
        if self.policy_path.is_some() {
            len += 1;
        }
        let mut state = serializer.serialize_struct("ScanJsonReport", len)?;
        state.serialize_field("version", &self.version)?;
        state.serialize_field("scanned_paths", &self.scanned_paths)?;
        state.serialize_field("findings", &ReportFindings(&self.findings))?;
        state.serialize_field("summary", &self.summary)?;
        state.serialize_field("exit_threshold", &self.exit_threshold)?;
        if let Some(policy_path) = &self.policy_path {
            state.serialize_field("policy_path", policy_path)?;
        }
        state.serialize_field("suppressed", &self.suppressed)?;
        state.serialize_field("deduplicated", &self.deduplicated)?;
        state.serialize_field("color_mode", &self.color_mode)?;
        state.end()
    }
}

struct ReportFindings<'a>(&'a [Finding]);

impl Serialize for ReportFindings<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for finding in self.0 {
            seq.serialize_element(&ReportFinding(finding))?;
        }
        seq.end()
    }
}

struct ReportFinding<'a>(&'a Finding);

impl Serialize for ReportFinding<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let finding = self.0;
        let mut len = 9;
        if finding.value_hash.is_some() {
            len += 1;
        }
        if !finding.context_before.is_empty() {
            len += 1;
        }
        if !finding.context_after.is_empty() {
            len += 1;
        }
        let mut state = serializer.serialize_struct("Finding", len)?;
        state.serialize_field("rule_id", &finding.rule_id)?;
        state.serialize_field("severity", &finding.severity)?;
        state.serialize_field("kind", &finding.kind)?;
        state.serialize_field("file", &finding.file)?;
        state.serialize_field("line", &finding.line)?;
        state.serialize_field("column", &finding.column)?;
        state.serialize_field("message", &finding.message)?;
        state.serialize_field("redacted_value", &finding.redacted_value)?;
        if let Some(value_hash) = &finding.value_hash {
            state.serialize_field("value_hash", value_hash)?;
        }
        state.serialize_field("confidence", &finding.confidence)?;
        if !finding.context_before.is_empty() {
            state.serialize_field("context_before", &finding.context_before)?;
        }
        if !finding.context_after.is_empty() {
            state.serialize_field("context_after", &finding.context_after)?;
        }
        state.end()
    }
}

#[derive(Debug, Serialize, Deserialize)]
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
