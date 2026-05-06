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

pub(crate) fn compile_for_policy(
    rules: &[CustomRule],
    include_internal_terms: bool,
) -> Result<Vec<CompiledCustomRule>> {
    rules
        .iter()
        .filter(|rule| rule.enabled)
        .filter(|rule| include_internal_terms || !is_internal_rule(rule))
        .map(compile_one)
        .collect()
}

fn normalized_kind(kind: &str) -> &str {
    let kind = kind.trim();
    if kind.is_empty() { "internal" } else { kind }
}

fn is_internal_rule(rule: &CustomRule) -> bool {
    normalized_kind(&rule.kind).eq_ignore_ascii_case("internal")
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

    let kind = normalized_kind(&rule.kind);
    let confidence = rule
        .confidence
        .filter(|c| c.is_finite())
        .unwrap_or(1.0)
        .clamp(0.0, 1.0);

    Ok(CompiledCustomRule {
        id: id.to_string(),
        severity,
        kind: kind.to_string(),
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
        let err = compile_for_policy(&[custom_rule(".*")], true).unwrap_err();
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

        let compiled = compile_for_policy(&[rule], true).unwrap();

        assert_eq!(compiled[0].id, "internal.demo");
        assert_eq!(compiled[0].kind, "internal");
        assert_eq!(compiled[0].message, "Demo message");
        assert_eq!(compiled[0].confidence, 1.0);
    }

    #[test]
    fn policy_compile_excludes_internal_rules_by_default() {
        let internal = custom_rule("ProjectNebula");
        let mut non_internal = custom_rule("CLIENT-[0-9]+");
        non_internal.id = "custom.client_id".into();
        non_internal.kind = "project".into();

        let compiled = compile_for_policy(&[internal, non_internal], false).unwrap();

        assert_eq!(compiled.len(), 1);
        assert_eq!(compiled[0].id, "custom.client_id");
    }

    #[test]
    fn policy_compile_treats_blank_kind_as_internal() {
        let mut rule = custom_rule("ProjectNebula");
        rule.kind.clear();

        let disabled = compile_for_policy(&[rule.clone()], false).unwrap();
        let enabled = compile_for_policy(&[rule], true).unwrap();

        assert!(disabled.is_empty());
        assert_eq!(enabled[0].kind, "internal");
    }
}
