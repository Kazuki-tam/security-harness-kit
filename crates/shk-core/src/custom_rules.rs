use crate::policy::{CustomRule, Severity};
use anyhow::{Context, Result, bail};
use regex::{Regex, RegexBuilder};

#[derive(Debug, Clone)]
pub(crate) struct CompiledCustomRule {
    pub(crate) id: String,
    pub(crate) severity: Severity,
    pub(crate) kind: String,
    pub(crate) re: Regex,
    pub(crate) message: String,
    pub(crate) confidence: f32,
}

#[derive(Debug, Clone)]
pub(crate) struct CustomMatch {
    pub(crate) rule_id: String,
    pub(crate) severity: Severity,
    pub(crate) kind: String,
    pub(crate) line: usize,
    pub(crate) column: usize,
    pub(crate) message: String,
    pub(crate) confidence: f32,
    pub(crate) matched_text: String,
}

pub(crate) fn compile(rules: &[CustomRule]) -> Result<Vec<CompiledCustomRule>> {
    rules
        .iter()
        .filter(|rule| rule.enabled)
        .map(compile_one)
        .collect()
}

fn compile_one(rule: &CustomRule) -> Result<CompiledCustomRule> {
    let id = rule.id.trim();
    if id.is_empty() {
        bail!("custom rule id must not be empty");
    }
    if rule.pattern.trim().is_empty() {
        bail!("custom rule `{id}` pattern must not be empty");
    }
    let severity = Severity::parse(&rule.severity)
        .with_context(|| format!("invalid severity for custom rule `{id}`"))?;
    let re = RegexBuilder::new(&rule.pattern)
        .case_insensitive(rule.case_insensitive)
        .build()
        .with_context(|| format!("compile custom rule `{id}`"))?;
    if re.is_match("") {
        bail!("custom rule `{id}` pattern must not match empty text");
    }

    let kind = rule.kind.trim();
    let confidence = rule
        .confidence
        .filter(|c| c.is_finite())
        .unwrap_or(1.0)
        .clamp(0.0, 1.0);

    Ok(CompiledCustomRule {
        id: id.to_string(),
        severity,
        kind: if kind.is_empty() {
            "internal".into()
        } else {
            kind.to_string()
        },
        re,
        message: rule
            .message
            .as_deref()
            .map(str::trim)
            .filter(|message| !message.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| "Custom sensitive term detected".into()),
        confidence,
    })
}

fn line_col(content: &str, byte_idx: usize) -> (usize, usize) {
    let prefix = &content[..byte_idx.min(content.len())];
    let line = prefix.bytes().filter(|&b| b == b'\n').count() + 1;
    let last_nl = prefix.rfind('\n').map(|i| i + 1).unwrap_or(0);
    let col = content[last_nl..byte_idx.min(content.len())]
        .chars()
        .count()
        + 1;
    (line, col)
}

pub(crate) fn scan_content(content: &str, rules: &[CompiledCustomRule]) -> Vec<CustomMatch> {
    let mut out = Vec::new();
    for rule in rules {
        for m in rule.re.find_iter(content) {
            let (line, column) = line_col(content, m.start());
            out.push(CustomMatch {
                rule_id: rule.id.clone(),
                severity: rule.severity,
                kind: rule.kind.clone(),
                line,
                column,
                message: rule.message.clone(),
                confidence: rule.confidence,
                matched_text: m.as_str().to_string(),
            });
        }
    }
    out
}

pub(crate) fn redact_line_for_display(line: &str, rules: &[CompiledCustomRule]) -> String {
    let mut s = line.to_string();
    for rule in rules {
        s = rule.re.replace_all(&s, "[REDACTED]").to_string();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn custom_rule(pattern: &str) -> CustomRule {
        CustomRule {
            id: "internal.demo".into(),
            pattern: pattern.into(),
            severity: "high".into(),
            kind: "internal".into(),
            message: None,
            confidence: None,
            case_insensitive: false,
            enabled: true,
        }
    }

    #[test]
    fn rejects_empty_matching_patterns() {
        let err = compile(&[custom_rule(".*")]).unwrap_err();
        assert!(
            err.to_string().contains("must not match empty text"),
            "{err:#}"
        );
    }

    #[test]
    fn trims_rule_metadata_and_clamps_confidence() {
        let mut rule = custom_rule("ProjectNebula");
        rule.id = " internal.demo ".into();
        rule.kind = " internal ".into();
        rule.message = Some(" Demo message ".into());
        rule.confidence = Some(2.0);

        let compiled = compile(&[rule]).unwrap();

        assert_eq!(compiled[0].id, "internal.demo");
        assert_eq!(compiled[0].kind, "internal");
        assert_eq!(compiled[0].message, "Demo message");
        assert_eq!(compiled[0].confidence, 1.0);
    }
}
