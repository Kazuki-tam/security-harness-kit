use crate::policy::Policy;
use anyhow::Result;
use serde::Serialize;
use shk_rules::{RuleEngineConfig, scan_content};

#[derive(Debug, Serialize)]
pub struct MaskJsonOutput {
    pub masked_content: String,
    pub findings: Vec<crate::finding::Finding>,
}

/// Line-oriented masking: lines containing matches become `[REDACTED_LINE]` (MVP, streaming-friendly).
pub fn mask_text(
    content: &str,
    cfg: &RuleEngineConfig,
    rel_path: &str,
) -> (String, Vec<crate::finding::Finding>) {
    let mut findings = Vec::new();
    let ends_with_newline = content.ends_with('\n');
    let mut out = String::with_capacity(content.len());
    for (i, line) in content.lines().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let ms = scan_content(line, rel_path, cfg);
        if ms.is_empty() {
            out.push_str(line);
        } else {
            for m in &ms {
                findings.push(crate::finding::Finding::from_rule_match(
                    rel_path, m, false, line, cfg,
                ));
            }
            out.push_str("[REDACTED_LINE]");
        }
    }
    if ends_with_newline {
        out.push('\n');
    }
    (out, findings)
}

pub fn mask_from_policy(
    content: &str,
    policy: &Policy,
    rel_path: &str,
) -> Result<(String, Vec<crate::finding::Finding>)> {
    let cfg = policy.rule_engine_config();
    Ok(mask_text(content, &cfg, rel_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_leaves_clean_lines() {
        let cfg = RuleEngineConfig::default();
        let (out, hits) = mask_text(
            "ok line\nsk-proj-abcdefghijklmnopqrstuvwxyz0123456789\n",
            &cfg,
            "x.txt",
        );
        assert!(out.contains("ok line"));
        assert!(out.contains("[REDACTED_LINE]"));
        assert!(!hits.is_empty());
    }
}
