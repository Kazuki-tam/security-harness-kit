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
        let guard = include_context.then(|| {
            let mut guard = ContextGuard::for_content(content);
            guard.add_match(content, m.line, m.column, &m.matched_text);
            guard
        });
        Self::from_rule_match_with_custom_context(file, m, guard.as_ref(), content, rule_cfg, &[])
    }

    /// `context` is `None` when context lines are not wanted; otherwise it
    /// names the parts of `content` that must be redacted in them.
    pub(crate) fn from_rule_match_with_custom_context(
        file: &str,
        m: &shk_rules::RuleMatch,
        context: Option<&ContextGuard>,
        content: &str,
        rule_cfg: &RuleEngineConfig,
        custom_rules: &[CompiledCustomRule],
    ) -> Self {
        let (context_before, context_after) =
            sanitized_context(content, m.line, context, rule_cfg, custom_rules);
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
            context_before,
            context_after,
        }
    }

    pub(crate) fn from_custom_match(
        file: &str,
        m: &CustomMatch,
        context: Option<&ContextGuard>,
        content: &str,
        rule_cfg: &RuleEngineConfig,
        custom_rules: &[CompiledCustomRule],
    ) -> Self {
        let (context_before, context_after) =
            sanitized_context(content, m.line, context, rule_cfg, custom_rules);
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
            context_before,
            context_after,
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

/// Parts of a scanned text that must not appear in context lines even though
/// no rule matches them on their own line: private key blocks (only the
/// header line matches a rule) and every match that spans several lines.
/// Context lines are otherwise redacted one line at a time, which cannot see
/// either.
#[derive(Debug, Default)]
pub(crate) struct ContextGuard {
    /// Byte ranges of the scanned text; unsorted and possibly overlapping.
    ranges: Vec<(usize, usize)>,
}

impl ContextGuard {
    pub(crate) fn for_content(content: &str) -> Self {
        Self {
            ranges: shk_rules::private_key_block_ranges(content)
                .into_iter()
                .map(|range| (range.start, range.end))
                .collect(),
        }
    }

    /// Register a match reported at 1-based `line` / `column` (in chars).
    /// Single-line matches are left to the per-line redaction.
    pub(crate) fn add_match(
        &mut self,
        content: &str,
        line: usize,
        column: usize,
        matched_text: &str,
    ) {
        if !matched_text.contains('\n') || line == 0 || column == 0 {
            return;
        }
        let Some((line_start, line_text)) = lines_with_offsets(content).nth(line - 1) else {
            return;
        };
        let column_offset = line_text
            .char_indices()
            .nth(column - 1)
            .map_or(line_text.len(), |(offset, _)| offset);
        let start = line_start + column_offset;
        if content[start..].starts_with(matched_text) {
            self.ranges.push((start, start + matched_text.len()));
        }
    }

    /// Replace the guarded parts of the line at `line_start` with the
    /// redaction placeholder.
    fn redact_line(&self, line_start: usize, line: &str) -> String {
        let line_end = line_start + line.len();
        let mut spans: Vec<(usize, usize)> = self
            .ranges
            .iter()
            .filter_map(|&(start, end)| {
                let start = start.max(line_start);
                let end = end.min(line_end);
                (start < end).then(|| (start - line_start, end - line_start))
            })
            .collect();
        if spans.is_empty() {
            return line.to_string();
        }
        spans.sort_unstable();
        let mut out = String::with_capacity(line.len());
        let mut cursor = 0;
        let mut placeholder_written = false;
        for (start, end) in spans {
            if placeholder_written && start <= cursor {
                // Overlaps or touches the previous span: one placeholder.
                cursor = cursor.max(end);
                continue;
            }
            out.push_str(&line[cursor..start]);
            out.push_str("[REDACTED]");
            cursor = end;
            placeholder_written = true;
        }
        out.push_str(&line[cursor..]);
        out
    }
}

/// Lines of `content` as `str::lines` yields them, with their byte offset.
fn lines_with_offsets(content: &str) -> impl Iterator<Item = (usize, &str)> {
    let mut offset = 0;
    content.split_inclusive('\n').map(move |raw| {
        let start = offset;
        offset += raw.len();
        let line = raw.strip_suffix('\n').unwrap_or(raw);
        (start, line.strip_suffix('\r').unwrap_or(line))
    })
}

type ContextLines<'a> = Vec<(usize, &'a str)>;

fn context_lines(
    content: &str,
    line_1based: usize,
    n: usize,
) -> (ContextLines<'_>, ContextLines<'_>) {
    let lines: ContextLines<'_> = lines_with_offsets(content).collect();
    if lines.is_empty() || line_1based == 0 {
        return (vec![], vec![]);
    }
    let idx = line_1based
        .saturating_sub(1)
        .min(lines.len().saturating_sub(1));
    let start = idx.saturating_sub(n);
    let before = lines[start..idx].to_vec();
    let end = (idx + 1 + n).min(lines.len());
    let after = if idx + 1 < lines.len() {
        lines[idx + 1..end].to_vec()
    } else {
        vec![]
    };
    (before, after)
}

fn sanitized_context(
    content: &str,
    line_1based: usize,
    guard: Option<&ContextGuard>,
    cfg: &RuleEngineConfig,
    custom_rules: &[CompiledCustomRule],
) -> (Vec<String>, Vec<String>) {
    let Some(guard) = guard else {
        return (vec![], vec![]);
    };
    let (before, after) = context_lines(content, line_1based, 1);
    let sanitize = |lines: ContextLines<'_>| -> Vec<String> {
        lines
            .into_iter()
            .map(|(line_start, line)| {
                let guarded = guard.redact_line(line_start, line);
                let redacted = redact_line_for_display(&guarded, cfg);
                crate::custom_rules::redact_line_for_display(&redacted, custom_rules)
            })
            .collect()
    };
    (sanitize(before), sanitize(after))
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

    #[test]
    fn context_never_leaks_private_key_block_body() {
        let cfg = RuleEngineConfig::default();
        let dashes = "-".repeat(5);
        let label = ["RSA", "PRIVATE", "KEY"].join(" ");
        let body = "Q1w2".repeat(12);
        let footer = format!("{dashes}END {label}{dashes}");
        // not real credential or personal data: synthetic detector fixture value only
        let content =
            format!("{dashes}BEGIN {label}{dashes}\n{body}\n{footer}\nowner user@example.com\n");
        let matches = shk_rules::scan_content(&content, "x.txt", &cfg);
        let header = matches
            .iter()
            .find(|m| m.rule_id == "secret.private_key_block")
            .expect("private key header match");
        let f = Finding::from_rule_match("x.txt", header, true, &content, &cfg);
        assert_eq!(f.context_after.len(), 1);
        assert!(!f.context_after[0].contains(&body), "{:?}", f.context_after);

        let email = matches
            .iter()
            .find(|m| m.rule_id == "pii.email")
            .expect("email match");
        let f = Finding::from_rule_match("x.txt", email, true, &content, &cfg);
        assert_eq!(f.context_before, vec!["[REDACTED]".to_string()]);
    }
}
