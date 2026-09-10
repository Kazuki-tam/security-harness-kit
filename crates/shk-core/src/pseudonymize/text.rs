use super::apply::{CellAction, MapCollector, apply_cell, replacement_text, resolve_rule_kind};
use super::derive::KeyMaterial;
use super::normalize::NormalizeSettings;
use super::table::{MetaColumn, PseudonymizeMeta};
use anyhow::{Context, Result};
use shk_rules::{RuleEngineConfig, scan_content};
use std::collections::BTreeMap;
use std::path::Path;

pub struct TextOptions {
    pub token_bits: u16,
    pub norm: String,
    pub settings: NormalizeSettings,
    pub rule_overrides: BTreeMap<String, String>,
    pub shk_version: String,
    pub key_namespace: String,
    pub dry_run: bool,
}

pub struct TextResult {
    pub output: String,
    pub meta: PseudonymizeMeta,
}

pub fn run_text(
    input: &str,
    material: Option<&KeyMaterial>,
    options: &TextOptions,
    mut map: Option<&mut MapCollector>,
) -> Result<TextResult> {
    if options.dry_run {
        return Ok(TextResult {
            output: String::new(),
            meta: text_meta(options, material, 0, BTreeMap::new(), BTreeMap::new(), true),
        });
    }
    let material = material.context("text mode requires key material unless --dry-run")?;
    let cfg = RuleEngineConfig {
        secrets: true,
        pii: true,
        pii_languages: vec!["en".into(), "ja".into()],
        env: false,
        internal_terms: false,
        ai_context: false,
    };
    let mut matches = scan_content(input, "input.txt", &cfg);
    matches.sort_by(|a, b| {
        b.column
            .cmp(&a.column)
            .then_with(|| b.matched_text.len().cmp(&a.matched_text.len()))
    });

    let mut out = input.to_string();
    let mut replaced: BTreeMap<String, u64> = BTreeMap::new();
    let mut unparsed: BTreeMap<String, u64> = BTreeMap::new();
    let mut used_spans: Vec<(usize, usize)> = Vec::new();

    for item in matches {
        let Some(span) = find_match_span(&out, item.line, item.column, &item.matched_text) else {
            continue;
        };
        if used_spans
            .iter()
            .any(|(start, end)| span.0 < *end && *start < span.1)
        {
            continue;
        }
        let replacement = if item.rule_id.starts_with("secret.") {
            "[REDACTED]".to_string()
        } else if let Some(kind) = resolve_rule_kind(item.rule_id, &options.rule_overrides)
            .map_err(|err| anyhow::anyhow!(err))?
        {
            let action = apply_cell(
                &kind,
                &item.matched_text,
                material,
                options.settings,
                options.token_bits,
                map.as_deref_mut(),
            )?;
            match &action {
                CellAction::Unparsed => {
                    *unparsed.entry(kind.as_config_value()).or_insert(0) += 1;
                }
                CellAction::Token(_) => {
                    *replaced.entry(kind.as_config_value()).or_insert(0) += 1;
                }
                CellAction::Keep => {}
            }
            replacement_text(&action, &item.matched_text)
        } else {
            "[REDACTED]".to_string()
        };
        out.replace_range(span.0..span.1, &replacement);
        used_spans.push((span.0, span.0 + replacement.len()));
    }

    Ok(TextResult {
        output: out,
        meta: text_meta(options, Some(material), 1, replaced, unparsed, false),
    })
}

pub fn run_office_text(
    input: &Path,
    output: Option<&Path>,
    material: Option<&KeyMaterial>,
    options: &TextOptions,
    mut map: Option<&mut MapCollector>,
    max_file_size_bytes: u64,
) -> Result<TextResult> {
    if options.dry_run {
        return Ok(TextResult {
            output: String::new(),
            meta: text_meta(options, material, 0, BTreeMap::new(), BTreeMap::new(), true),
        });
    }
    let material = material.context("text mode requires key material unless --dry-run")?;
    let output = output.context("Office text mode requires --output")?;
    let mut replaced: BTreeMap<String, u64> = BTreeMap::new();
    let mut unparsed: BTreeMap<String, u64> = BTreeMap::new();
    crate::document_masker::rewrite_ooxml_text_groups(
        input,
        output,
        max_file_size_bytes,
        |group| {
            let result = run_text(group, Some(material), options, map.as_deref_mut())?;
            for (kind, count) in result.meta.replaced {
                *replaced.entry(kind).or_insert(0) += count;
            }
            for (kind, count) in result.meta.unparsed {
                *unparsed.entry(kind).or_insert(0) += count;
            }
            Ok(result.output)
        },
    )?;
    Ok(TextResult {
        output: String::new(),
        meta: text_meta(options, Some(material), 1, replaced, unparsed, false),
    })
}

fn find_match_span(
    content: &str,
    line: usize,
    column: usize,
    matched: &str,
) -> Option<(usize, usize)> {
    let line_start = content
        .split_inclusive('\n')
        .take(line.saturating_sub(1))
        .map(|part| part.len())
        .sum::<usize>();
    let line_body = content.get(line_start..)?;
    let col = column.saturating_sub(1);
    let byte_col = line_body
        .chars()
        .take(col)
        .map(|ch| ch.len_utf8())
        .sum::<usize>();
    let start = line_start + byte_col;
    if content
        .get(start..)
        .is_some_and(|tail| tail.starts_with(matched))
    {
        return Some((start, start + matched.len()));
    }
    content[line_start..]
        .find(matched)
        .map(|rel| (line_start + rel, line_start + rel + matched.len()))
}

fn text_meta(
    options: &TextOptions,
    material: Option<&KeyMaterial>,
    rows_processed: u64,
    replaced: BTreeMap<String, u64>,
    unparsed: BTreeMap<String, u64>,
    dry_run: bool,
) -> PseudonymizeMeta {
    let columns = replaced
        .keys()
        .chain(unparsed.keys())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .map(|kind| MetaColumn {
            name: kind.clone(),
            kind: kind.clone(),
            source: super::columns::ColumnSource::Config,
            match_rate: None,
        })
        .collect();
    PseudonymizeMeta {
        shk_version: options.shk_version.clone(),
        mode: "text",
        norm: options.norm.clone(),
        token_bits: options.token_bits,
        key_fingerprint: material.map(KeyMaterial::fingerprint),
        key_namespace: options.key_namespace.clone(),
        columns,
        rows_processed,
        replaced,
        unparsed,
        map_created: false,
        dry_run,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pseudonymize::Kind;

    fn material() -> KeyMaterial {
        KeyMaterial::from_parts([0x21; 32], [0x43; 32])
    }

    fn options() -> TextOptions {
        TextOptions {
            token_bits: 64,
            norm: "v1".into(),
            settings: NormalizeSettings::default(),
            rule_overrides: BTreeMap::new(),
            shk_version: "0.6.4".into(),
            key_namespace: "test".into(),
            dry_run: false,
        }
    }

    #[test]
    fn text_mode_tokens_email_and_redacts_secrets() {
        let email = ["ada", "@", "example.com"].concat();
        let secret = format!("sk-proj-{}abcdefghijklmnopqrstuvwxyz0123456789", "z");
        let input = format!("contact {email} key {secret}");
        let result = run_text(&input, Some(&material()), &options(), None).unwrap();
        assert!(result.output.contains("email_"), "{}", result.output);
        assert!(result.output.contains("[REDACTED]"), "{}", result.output);
        assert!(!result.output.contains(&email), "{}", result.output);
        assert!(!result.output.contains(&secret), "{}", result.output);
        assert_eq!(result.meta.replaced.get("email"), Some(&1));
        assert_eq!(result.meta.mode, "text");
    }

    #[test]
    fn text_and_table_share_tokens_for_the_same_email() {
        let email = ["ada", "@", "example.com"].concat();
        let material = material();
        let from_text = run_text(&email, Some(&material), &options(), None)
            .unwrap()
            .output;
        let from_cell = replacement_text(
            &apply_cell(
                &Kind::Email,
                &email,
                &material,
                NormalizeSettings::default(),
                64,
                None,
            )
            .unwrap(),
            &email,
        );
        assert_eq!(from_text, from_cell);
    }
}
