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
    // A leading byte order mark is kept in the output but must not sit in
    // front of the first line, where it hides the line from anchored rules.
    let content = match content.strip_prefix(BYTE_ORDER_MARK) {
        Some(rest) => {
            out.push(BYTE_ORDER_MARK);
            rest
        }
        None => content,
    };
    // Rules run per line, so only the header line of a private key block
    // matches. The body and footer are masked through these block ranges.
    let key_blocks = if cfg.secrets {
        shk_rules::private_key_block_ranges(content)
    } else {
        Vec::new()
    };
    let mut line_start = 0;
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
        let block_spans = spans_within_line(&key_blocks, line_start, line.len());
        line_start += raw_line.len();
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
        if ms.is_empty() && custom_ms.is_empty() && block_spans.is_empty() {
            out.push_str(line);
        } else {
            for m in &ms {
                findings.push(
                    crate::finding::Finding::from_rule_match_with_custom_context(
                        rel_path, m, None, line, cfg, custom,
                    ),
                );
            }
            for m in &custom_ms {
                findings.push(crate::finding::Finding::from_custom_match(
                    rel_path, m, None, line, cfg, custom,
                ));
            }
            let values = ms
                .iter()
                .map(|m| m.matched_text.clone())
                .chain(custom_ms.iter().map(|m| m.matched_text.clone()))
                .collect();
            match redaction {
                MaskRedaction::FullLine => out.push_str("[REDACTED_LINE]"),
                MaskRedaction::Match => {
                    out.push_str(&mask_line_values(line, values, &block_spans, |_| {
                        "[REDACTED]".into()
                    }))
                }
                MaskRedaction::Partial {
                    preserve_prefix,
                    preserve_suffix,
                } => out.push_str(&mask_line_values(line, values, &block_spans, |value| {
                    partial_value(value, preserve_prefix, preserve_suffix)
                })),
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

const BYTE_ORDER_MARK: char = '\u{feff}';

/// Parts of `ranges` (byte offsets into the whole content) that fall inside
/// the line starting at `line_start`, as offsets into that line.
fn spans_within_line(
    ranges: &[std::ops::Range<usize>],
    line_start: usize,
    line_len: usize,
) -> Vec<(usize, usize)> {
    let line_end = line_start + line_len;
    ranges
        .iter()
        .filter_map(|range| {
            let start = range.start.max(line_start);
            let end = range.end.min(line_end);
            (start < end).then(|| (start - line_start, end - line_start))
        })
        .collect()
}

#[cfg(test)]
fn mask_line_partial(
    line: &str,
    matches: Vec<String>,
    preserve_prefix: usize,
    preserve_suffix: usize,
) -> String {
    mask_line_values(line, matches, &[], |value| {
        partial_value(value, preserve_prefix, preserve_suffix)
    })
}

#[cfg(test)]
fn mask_line_match(line: &str, matches: Vec<String>) -> String {
    mask_line_values(line, matches, &[], |_| "[REDACTED]".into())
}

/// Replace every occurrence of the matched values in `line`. Overlapping
/// occurrences are merged into one span, so the tail of a partially
/// overlapping match is never left behind. `forced_spans` are always replaced
/// with the full placeholder, whatever `replacement_for` would preserve.
fn mask_line_values(
    line: &str,
    matches: Vec<String>,
    forced_spans: &[(usize, usize)],
    mut replacement_for: impl FnMut(&str) -> String,
) -> String {
    let mut values = matches;
    values.sort();
    values.dedup();

    let mut spans: Vec<(usize, usize, bool)> = forced_spans
        .iter()
        .map(|&(start, end)| (start, end, true))
        .collect();
    for value in &values {
        if value.is_empty() {
            continue;
        }
        for (start, _) in line.match_indices(value.as_str()) {
            spans.push((start, start + value.len(), false));
        }
    }
    for value in &mut values {
        value.zeroize();
    }
    spans.sort_by_key(|&(start, end, _)| (start, std::cmp::Reverse(end)));

    let mut merged: Vec<(usize, usize, bool)> = Vec::with_capacity(spans.len());
    for (start, end, forced) in spans {
        match merged.last_mut() {
            Some(last) if start < last.1 => {
                last.1 = last.1.max(end);
                last.2 |= forced;
            }
            _ => merged.push((start, end, forced)),
        }
    }

    let mut masked = String::with_capacity(line.len());
    let mut cursor = 0;
    for (start, end, forced) in merged {
        masked.push_str(&line[cursor..start]);
        if forced {
            masked.push_str("[REDACTED]");
        } else {
            masked.push_str(&replacement_for(&line[start..end]));
        }
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

    /// Synthetic PEM-shaped block assembled at runtime; the body is not key
    /// material.
    fn synthetic_key_block(label: &str, eol: &str, terminated: bool) -> (String, Vec<String>) {
        let dashes = "-".repeat(5);
        let body: Vec<String> = ["Q1w2", "E3r4", "T5y6"]
            .iter()
            .map(|seed| seed.repeat(12))
            .collect();
        let mut block = format!("{dashes}BEGIN {label}{dashes}{eol}");
        for line in &body {
            block.push_str(line);
            block.push_str(eol);
        }
        if terminated {
            block.push_str(&format!("{dashes}END {label}{dashes}{eol}"));
        }
        (block, body)
    }

    const KEY_BLOCK_LABELS: &[&str] = &[
        "PRIVATE KEY",
        "RSA PRIVATE KEY",
        "EC PRIVATE KEY",
        "DSA PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
        "OPENSSH PRIVATE KEY",
        "PGP PRIVATE KEY BLOCK",
    ];

    #[test]
    fn match_mask_redacts_whole_private_key_block() {
        let cfg = RuleEngineConfig::default();
        for label in KEY_BLOCK_LABELS {
            let (block, body) = synthetic_key_block(label, "\n", true);
            let content = format!("before\n{block}after\n");
            let (out, hits) = mask_text(&content, &cfg, "x.txt", MaskRedaction::Match);
            assert!(!hits.is_empty(), "{label}");
            for line in &body {
                assert!(!out.contains(line.as_str()), "{label}: body leaked");
            }
            assert!(!out.contains("END "), "{label}: footer kept: {out}");
            assert!(out.starts_with("before\n"), "{label}: {out}");
            assert!(out.ends_with("after\n"), "{label}: {out}");
            assert_eq!(out.lines().count(), content.lines().count(), "{label}");
        }
    }

    #[test]
    fn full_line_mask_redacts_every_private_key_block_line() {
        let cfg = RuleEngineConfig::default();
        let (block, _) = synthetic_key_block("RSA PRIVATE KEY", "\r\n", true);
        let content = format!("before\r\n{block}after\r\n");
        let (out, _) = mask_text(&content, &cfg, "x.txt", MaskRedaction::FullLine);
        let expected = format!("before\r\n{}after\r\n", "[REDACTED_LINE]\r\n".repeat(5));
        assert_eq!(out, expected);
    }

    #[test]
    fn partial_mask_does_not_preserve_private_key_block_edges() {
        let cfg = RuleEngineConfig::default();
        let (block, body) = synthetic_key_block("EC PRIVATE KEY", "\n", true);
        let (out, _) = mask_text(
            &block,
            &cfg,
            "x.txt",
            MaskRedaction::Partial {
                preserve_prefix: 4,
                preserve_suffix: 4,
            },
        );
        for line in &body {
            assert!(!out.contains(&line[..4]), "{out}");
        }
    }

    #[test]
    fn unterminated_private_key_block_body_is_masked() {
        let cfg = RuleEngineConfig::default();
        let (block, body) = synthetic_key_block("OPENSSH PRIVATE KEY", "\n", false);
        let content = format!("before\n{block}");
        let (out, _) = mask_text(&content, &cfg, "x.txt", MaskRedaction::Match);
        for line in &body {
            assert!(!out.contains(line.as_str()), "{out}");
        }
        assert!(out.starts_with("before\n"), "{out}");
        assert_eq!(out.lines().count(), content.lines().count(), "{out}");

        // Text after the armor body is not part of the key.
        let content = format!("before\n{block}trailing words\n");
        let (out, _) = mask_text(&content, &cfg, "x.txt", MaskRedaction::Match);
        for line in &body {
            assert!(!out.contains(line.as_str()), "{out}");
        }
        assert!(out.ends_with("trailing words\n"), "{out}");
    }

    #[test]
    fn private_key_header_quoted_in_code_does_not_mask_following_code() {
        let cfg = RuleEngineConfig::default();
        let (header, _) = synthetic_key_block("RSA PRIVATE KEY", "\n", false);
        let header = header.lines().next().unwrap();
        let code = "fn main() {\n    let total = add(1, 2);\n}\n";
        let content = format!("const HEADER: &str = \"{header}\";\n{code}");
        for redaction in [MaskRedaction::Match, MaskRedaction::FullLine] {
            let (out, hits) = mask_text(&content, &cfg, "x.rs", redaction);
            assert!(!hits.is_empty());
            assert!(out.ends_with(code), "{out}");
        }
    }

    #[test]
    fn private_key_header_inside_a_sentence_does_not_mask_following_prose() {
        let cfg = RuleEngineConfig::default();
        let (header, _) = synthetic_key_block("PRIVATE KEY", "\n", false);
        let header = header.lines().next().unwrap();
        let prose = "The next paragraph explains rotation.\nIt has two lines.\n";
        let content = format!("Key files start with {header} on line one.\n{prose}");
        let (out, _) = mask_text(&content, &cfg, "notes.md", MaskRedaction::Match);
        assert!(out.starts_with("Key files start with "), "{out}");
        assert!(out.ends_with(prose), "{out}");
    }

    #[test]
    fn private_key_block_is_left_alone_when_secret_rules_are_off() {
        let cfg = RuleEngineConfig {
            secrets: false,
            ..RuleEngineConfig::default()
        };
        let (block, _) = synthetic_key_block("RSA PRIVATE KEY", "\n", true);
        let (out, hits) = mask_text(&block, &cfg, "x.txt", MaskRedaction::Match);
        assert_eq!(out, block);
        assert!(hits.is_empty(), "{hits:?}");
    }

    #[test]
    fn match_mask_merges_partially_overlapping_values() {
        let out = mask_line_match("xxabcdefyy", vec!["abcd".into(), "cdef".into()]);
        assert_eq!(out, "xx[REDACTED]yy");
    }

    #[test]
    fn partial_mask_merges_partially_overlapping_values() {
        let out = mask_line_partial(
            "xx0123456789abcdefyy",
            vec!["0123456789ab".into(), "89abcdef".into()],
            2,
            2,
        );
        assert_eq!(out, "xx01[REDACTED]efyy");
    }

    #[test]
    fn mask_keeps_leading_bom_and_still_masks_first_line() {
        let policy = Policy::default();
        let name = ["API", "TOKEN"].join("_");
        let content = format!("\u{feff}{name}=abcdefghijklmnop1234\nplain\n");
        let (out, hits) = mask_from_policy(&content, &policy, ".env").unwrap();
        assert!(!hits.is_empty());
        assert!(out.starts_with('\u{feff}'), "{out:?}");
        assert!(!out.contains("abcdefghijklmnop1234"), "{out}");
        assert!(out.ends_with("plain\n"), "{out}");
    }
}
