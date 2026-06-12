use crate::custom_rules;
use crate::policy::{Policy, Severity};
use anyhow::{Result, bail};
use serde::Serialize;
use shk_rules::{RuleEngineConfig, scan_content};
use zeroize::Zeroize;

#[derive(Debug, Serialize)]
pub struct MaskJsonOutput {
    pub masked_content: String,
    pub findings: Vec<crate::finding::Finding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaskRedaction {
    FullLine,
    Match,
    Partial {
        preserve_prefix: usize,
        preserve_suffix: usize,
    },
}

/// Mask content line-by-line while preserving original line boundaries.
pub fn mask_text(
    content: &str,
    cfg: &RuleEngineConfig,
    rel_path: &str,
    redaction: MaskRedaction,
) -> (String, Vec<crate::finding::Finding>) {
    mask_text_with_custom(content, cfg, &[], rel_path, redaction, Severity::Info)
}

fn mask_text_with_custom(
    content: &str,
    cfg: &RuleEngineConfig,
    custom: &[custom_rules::CompiledCustomRule],
    rel_path: &str,
    redaction: MaskRedaction,
    min_severity: Severity,
) -> (String, Vec<crate::finding::Finding>) {
    let mut findings = Vec::new();
    let mut out = String::with_capacity(content.len());
    // Preserve each line's original terminator (LF vs CRLF) so masking never
    // rewrites line endings on lines without findings.
    for (i, raw_line) in content.split_inclusive('\n').enumerate() {
        let (line, ending) = if let Some(stripped) = raw_line.strip_suffix("\r\n") {
            (stripped, "\r\n")
        } else if let Some(stripped) = raw_line.strip_suffix('\n') {
            (stripped, "\n")
        } else {
            (raw_line, "")
        };
        let mut ms = scan_content(line, rel_path, cfg);
        ms.retain(|m| Severity::from(m.severity).meets_threshold(min_severity));
        let mut custom_ms = custom_rules::scan_content(line, custom);
        custom_ms.retain(|m| m.severity.meets_threshold(min_severity));
        for m in &mut ms {
            m.line = i + 1;
        }
        for m in &mut custom_ms {
            m.line = i + 1;
        }
        if ms.is_empty() && custom_ms.is_empty() {
            out.push_str(line);
        } else {
            for m in &ms {
                findings.push(
                    crate::finding::Finding::from_rule_match_with_custom_context(
                        rel_path, m, false, line, cfg, custom,
                    ),
                );
            }
            for m in &custom_ms {
                findings.push(crate::finding::Finding::from_custom_match(
                    rel_path, m, false, line, cfg, custom,
                ));
            }
            let values = ms
                .iter()
                .map(|m| m.matched_text.clone())
                .chain(custom_ms.iter().map(|m| m.matched_text.clone()))
                .collect();
            match redaction {
                MaskRedaction::FullLine => out.push_str("[REDACTED_LINE]"),
                MaskRedaction::Match => out.push_str(&mask_line_match(line, values)),
                MaskRedaction::Partial {
                    preserve_prefix,
                    preserve_suffix,
                } => out.push_str(&mask_line_partial(
                    line,
                    values,
                    preserve_prefix,
                    preserve_suffix,
                )),
            }
            for m in &mut ms {
                m.matched_text.zeroize();
            }
            for m in &mut custom_ms {
                m.matched_text.zeroize();
            }
        }
        out.push_str(ending);
    }
    (out, findings)
}

fn mask_line_partial(
    line: &str,
    matches: Vec<String>,
    preserve_prefix: usize,
    preserve_suffix: usize,
) -> String {
    mask_line_values(line, matches, |value| {
        partial_value(value, preserve_prefix, preserve_suffix)
    })
}

fn mask_line_match(line: &str, matches: Vec<String>) -> String {
    mask_line_values(line, matches, |_| "[REDACTED]".into())
}

fn mask_line_values(
    line: &str,
    matches: Vec<String>,
    mut replacement_for: impl FnMut(&str) -> String,
) -> String {
    let mut values = matches;
    values.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    values.dedup();

    let mut ranges: Vec<(usize, usize, String)> = Vec::new();
    for value in &values {
        if value.is_empty() {
            continue;
        }
        for (start, _) in line.match_indices(value) {
            let end = start + value.len();
            if ranges.iter().any(|(s, e, _)| start < *e && *s < end) {
                continue;
            }
            ranges.push((start, end, replacement_for(value)));
        }
    }
    for value in &mut values {
        value.zeroize();
    }
    ranges.sort_by_key(|(start, _, _)| *start);

    let mut masked = String::with_capacity(line.len());
    let mut cursor = 0;
    for (start, end, replacement) in ranges {
        masked.push_str(&line[cursor..start]);
        masked.push_str(&replacement);
        cursor = end;
    }
    masked.push_str(&line[cursor..]);
    masked
}

fn partial_value(value: &str, preserve_prefix: usize, preserve_suffix: usize) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= preserve_prefix + preserve_suffix {
        return "[REDACTED]".into();
    }

    let prefix: String = chars.iter().take(preserve_prefix).collect();
    let suffix: String = chars
        .iter()
        .skip(chars.len().saturating_sub(preserve_suffix))
        .collect();
    format!("{prefix}[REDACTED]{suffix}")
}

pub fn mask_from_policy(
    content: &str,
    policy: &Policy,
    rel_path: &str,
) -> Result<(String, Vec<crate::finding::Finding>)> {
    if !policy.mask.mode.eq_ignore_ascii_case("strict") {
        bail!(
            "unsupported mask.mode `{}` (supported: strict)",
            policy.mask.mode
        );
    }
    let min_severity = policy.mask_min_severity()?;
    let cfg = policy.rule_engine_config();
    let custom = custom_rules::compile_for_policy(&policy.custom_rules, cfg.internal_terms)?;
    let redaction = match policy.mask.redaction.to_ascii_lowercase().as_str() {
        "full" => MaskRedaction::FullLine,
        "match" => MaskRedaction::Match,
        "partial" => MaskRedaction::Partial {
            preserve_prefix: policy.mask.preserve_prefix,
            preserve_suffix: policy.mask.preserve_suffix,
        },
        other => bail!("unsupported mask.redaction `{other}` (supported: full, match, partial)"),
    };
    Ok(mask_text_with_custom(
        content,
        &cfg,
        &custom,
        rel_path,
        redaction,
        min_severity,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_leaves_clean_lines() {
        let cfg = RuleEngineConfig::default();
        let (out, hits) = mask_text(
            // not real credential: synthetic detector fixture value only
            "ok line\nsk-proj-abcdefghijklmnopqrstuvwxyz0123456789\n",
            &cfg,
            "x.txt",
            MaskRedaction::FullLine,
        );
        assert!(out.contains("ok line"));
        assert!(out.contains("[REDACTED_LINE]"));
        assert!(!hits.is_empty());
    }

    #[test]
    fn mask_preserves_crlf_line_endings() {
        let cfg = RuleEngineConfig::default();
        let (out, hits) = mask_text(
            // not real credential: synthetic detector fixture value only
            "clean one\r\nsk-proj-abcdefghijklmnopqrstuvwxyz0123456789\r\nclean two\r\n",
            &cfg,
            "x.txt",
            MaskRedaction::FullLine,
        );
        assert_eq!(out, "clean one\r\n[REDACTED_LINE]\r\nclean two\r\n");
        assert!(!hits.is_empty());
    }

    #[test]
    fn mask_preserves_missing_trailing_newline() {
        let cfg = RuleEngineConfig::default();
        let (out, _) = mask_text("no newline at end", &cfg, "x.txt", MaskRedaction::FullLine);
        assert_eq!(out, "no newline at end");
    }

    #[test]
    fn partial_mask_preserves_edges() {
        let cfg = RuleEngineConfig::default();
        let (out, hits) = mask_text(
            // not real credential: synthetic detector fixture value only
            "token sk-proj-abcdefghijklmnopqrstuvwxyz0123456789\n",
            &cfg,
            "x.txt",
            MaskRedaction::Partial {
                preserve_prefix: 4,
                preserve_suffix: 4,
            },
        );
        assert!(!hits.is_empty());
        assert!(out.contains("sk-p[REDACTED]6789"), "{out}");
        assert!(!out.contains("abcdefghijklmnopqrstuvwxyz012345"), "{out}");
    }

    #[test]
    fn match_mask_replaces_only_detected_value() {
        let cfg = RuleEngineConfig::default();
        let (out, hits) = mask_text(
            // not real credential: synthetic detector fixture value only
            "token sk-proj-abcdefghijklmnopqrstuvwxyz0123456789 stays\n",
            &cfg,
            "x.txt",
            MaskRedaction::Match,
        );
        assert!(!hits.is_empty());
        assert_eq!(out, "token [REDACTED] stays\n");
    }

    #[test]
    fn match_mask_does_not_remask_replacement_text() {
        let out = mask_line_match(
            "token secret REDACTED",
            vec!["secret".into(), "REDACTED".into()],
        );
        assert_eq!(out, "token [REDACTED] [REDACTED]");
    }

    #[test]
    fn partial_mask_prefers_longer_overlapping_matches() {
        let out = mask_line_partial(
            "token sk-proj-abcdefghijklmnopqrstuvwxyz0123456789",
            vec![
                "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789".into(),
                "sk-p".into(),
            ],
            4,
            4,
        );
        assert_eq!(out, "token sk-p[REDACTED]6789");
    }

    #[test]
    fn mask_findings_keep_original_line_numbers() {
        let cfg = RuleEngineConfig::default();
        let (_out, hits) = mask_text(
            // not real credential: synthetic detector fixture value only
            "clean\nsk-proj-abcdefghijklmnopqrstuvwxyz0123456789\n",
            &cfg,
            "x.txt",
            MaskRedaction::FullLine,
        );
        let hit = hits
            .iter()
            .find(|f| f.rule_id == "secret.openai_api_key")
            .expect("openai finding");
        assert_eq!(hit.line, 2, "{hits:?}");
    }

    #[test]
    fn mask_from_policy_rejects_unsupported_mode() {
        let mut policy = Policy::default();
        policy.mask.mode = "passthrough".into();
        let err = mask_from_policy("hello@example.com\n", &policy, "<stdin>").unwrap_err();
        assert!(err.to_string().contains("unsupported mask.mode"), "{err:#}");
    }

    #[test]
    fn mask_from_policy_rejects_unsupported_redaction() {
        let mut policy = Policy::default();
        policy.mask.redaction = "line".into();
        let err = mask_from_policy("hello@example.com\n", &policy, "<stdin>").unwrap_err();
        assert!(
            err.to_string().contains("unsupported mask.redaction"),
            "{err:#}"
        );
    }

    #[test]
    fn mask_from_policy_rejects_unsupported_min_severity() {
        let mut policy = Policy::default();
        policy.mask.min_severity = "severe".into();
        let err = mask_from_policy("hello@example.com\n", &policy, "<stdin>").unwrap_err();
        assert!(
            err.to_string().contains("unsupported mask.min_severity"),
            "{err:#}"
        );
    }

    #[test]
    fn mask_from_policy_masks_medium_and_above_by_default() {
        let policy = Policy::default();
        let (out, findings) = mask_from_policy(
            // not real credential: synthetic detector fixture value only
            "contact hello@example.com\ntoken sk-proj-abcdefghijklmnopqrstuvwxyz0123456789\n",
            &policy,
            "<stdin>",
        )
        .unwrap();

        assert!(out.contains("contact [REDACTED]"), "{out}");
        assert!(out.contains("token [REDACTED]"), "{out}");
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "secret.openai_api_key"),
            "{findings:?}"
        );
        assert!(
            findings.iter().any(|f| f.rule_id == "pii.email"),
            "{findings:?}"
        );
    }

    #[test]
    fn mask_from_policy_can_raise_min_severity() {
        let mut policy = Policy::default();
        policy.mask.min_severity = "high".into();

        let (out, findings) = mask_from_policy("contact hello@example.com\n", &policy, "<stdin>")
            .expect("mask with high threshold");

        assert_eq!(out, "contact hello@example.com\n");
        assert!(
            !findings.iter().any(|f| f.rule_id == "pii.email"),
            "{findings:?}"
        );
    }

    #[test]
    fn mask_from_policy_applies_custom_rules() {
        let mut policy = Policy::default();
        policy.rules.internal_terms = true;
        policy.custom_rules.push(crate::policy::CustomRule {
            id: "internal.project_codename".into(),
            pattern: "ProjectNebula".into(),
            severity: "high".into(),
            kind: "internal".into(),
            message: Some("Internal confidential term detected".into()),
            confidence: None,
            case_insensitive: false,
            enabled: true,
        });

        let (out, findings) =
            mask_from_policy("codename ProjectNebula\n", &policy, "<stdin>").unwrap();

        assert_eq!(out, "codename [REDACTED]\n");
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "internal.project_codename"),
            "{findings:?}"
        );
    }

    #[test]
    fn mask_from_policy_skips_internal_custom_rules_by_default() {
        let mut policy = Policy::default();
        policy.custom_rules.push(crate::policy::CustomRule {
            id: "internal.project_codename".into(),
            pattern: "ProjectNebula".into(),
            severity: "high".into(),
            kind: "internal".into(),
            message: None,
            confidence: None,
            case_insensitive: false,
            enabled: true,
        });

        let (out, findings) =
            mask_from_policy("codename ProjectNebula\n", &policy, "<stdin>").unwrap();

        assert_eq!(out, "codename ProjectNebula\n");
        assert!(findings.is_empty(), "{findings:?}");
    }
}
