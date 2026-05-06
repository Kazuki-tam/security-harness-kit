use crate::policy::Policy;
use anyhow::Result;
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
    Partial {
        preserve_prefix: usize,
        preserve_suffix: usize,
    },
}

/// Line-oriented masking: lines containing matches become `[REDACTED_LINE]` (MVP, streaming-friendly).
pub fn mask_text(
    content: &str,
    cfg: &RuleEngineConfig,
    rel_path: &str,
    redaction: MaskRedaction,
) -> (String, Vec<crate::finding::Finding>) {
    let mut findings = Vec::new();
    let ends_with_newline = content.ends_with('\n');
    let mut out = String::with_capacity(content.len());
    for (i, line) in content.lines().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let mut ms = scan_content(line, rel_path, cfg);
        if ms.is_empty() {
            out.push_str(line);
        } else {
            for m in &ms {
                findings.push(crate::finding::Finding::from_rule_match(
                    rel_path, m, false, line, cfg,
                ));
            }
            match redaction {
                MaskRedaction::FullLine => out.push_str("[REDACTED_LINE]"),
                MaskRedaction::Partial {
                    preserve_prefix,
                    preserve_suffix,
                } => out.push_str(&mask_line_partial(
                    line,
                    &ms,
                    preserve_prefix,
                    preserve_suffix,
                )),
            }
            for m in &mut ms {
                m.matched_text.zeroize();
            }
        }
    }
    if ends_with_newline {
        out.push('\n');
    }
    (out, findings)
}

fn mask_line_partial(
    line: &str,
    matches: &[shk_rules::RuleMatch],
    preserve_prefix: usize,
    preserve_suffix: usize,
) -> String {
    let mut masked = line.to_string();
    let mut values: Vec<String> = matches.iter().map(|m| m.matched_text.clone()).collect();
    values.sort_by_key(|v| std::cmp::Reverse(v.len()));
    values.dedup();

    for value in values {
        let replacement = partial_value(&value, preserve_prefix, preserve_suffix);
        masked = masked.replace(&value, &replacement);
    }
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
    let cfg = policy.rule_engine_config();
    let redaction = if policy.mask.redaction.eq_ignore_ascii_case("partial") {
        MaskRedaction::Partial {
            preserve_prefix: policy.mask.preserve_prefix,
            preserve_suffix: policy.mask.preserve_suffix,
        }
    } else {
        MaskRedaction::FullLine
    };
    Ok(mask_text(content, &cfg, rel_path, redaction))
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
}
