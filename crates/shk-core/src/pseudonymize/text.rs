use super::apply::{CellAction, MapCollector, apply_cell, replacement_text, resolve_rule_kind};
use super::derive::KeyMaterial;
use super::kind::Kind;
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
    validate_options(options)?;
    if options.dry_run {
        return Ok(TextResult {
            output: String::new(),
            meta: text_meta(options, material, 0, BTreeMap::new(), BTreeMap::new(), true),
        });
    }
    let material = material.context("text mode requires key material unless --dry-run")?;
    let cfg = RuleEngineConfig {
        secrets: true,
        env: false,
        ai_context: false,
        ..RuleEngineConfig::default()
    };
    // Resolve every span against the original input before changing any offsets.
    let line_starts = line_starts(input);
    let mut matches: Vec<_> = scan_content(input, "input.txt", &cfg)
        .into_iter()
        .filter_map(|item| {
            find_match_span(
                input,
                &line_starts,
                item.line,
                item.column,
                &item.matched_text,
            )
            .map(|span| (span, item))
        })
        .collect();
    // Prefer secret redaction over overlapping PII, then the widest match.
    matches.sort_by_key(|(span, item)| {
        (
            !item.rule_id.starts_with("secret."),
            std::cmp::Reverse(span.1 - span.0),
            span.0,
        )
    });

    let mut replaced: BTreeMap<String, u64> = BTreeMap::new();
    let mut unparsed: BTreeMap<String, u64> = BTreeMap::new();
    // start -> end of every accepted span; accepted spans never overlap.
    let mut used_spans: BTreeMap<usize, usize> = BTreeMap::new();

    let mut edits = Vec::new();
    for (span, item) in matches {
        if overlaps(&used_spans, span) {
            continue;
        }
        let replacement = if item.rule_id.starts_with("secret.") {
            "[REDACTED]".to_string()
        } else if let Some(kind) = resolve_rule_kind(item.rule_id, &options.rule_overrides)
            .map_err(|err| anyhow::anyhow!(err))?
        {
            // Name rules match `氏名: 山田太郎` / `Name: Ada Lovelace` with the
            // label; keep the label in place and tokenize only the name so the
            // token equals the table-mode token for the same person.
            let (label, value) = if matches!(kind, Kind::Name) {
                split_name_label(&item.matched_text)
            } else {
                ("", item.matched_text.as_str())
            };
            let action = apply_cell(
                &kind,
                value,
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
            format!("{label}{}", replacement_text(&action, value))
        } else {
            "[REDACTED]".to_string()
        };
        edits.push((span, replacement));
        used_spans.insert(span.0, span.1);
    }

    // One forward pass: spans are disjoint, so the output is input with holes.
    edits.sort_by_key(|(span, _)| span.0);
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0;
    for ((start, end), replacement) in edits {
        out.push_str(&input[cursor..start]);
        out.push_str(&replacement);
        cursor = end;
    }
    out.push_str(&input[cursor..]);

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
    validate_options(options)?;
    if options.dry_run {
        crate::document_masker::validate_ooxml_text_document(input, max_file_size_bytes)?;
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

fn validate_options(options: &TextOptions) -> Result<()> {
    super::validate_norm(&options.norm).map_err(anyhow::Error::msg)?;
    super::validate_token_bits(options.token_bits).map_err(anyhow::Error::msg)?;
    for (rule_id, kind) in &options.rule_overrides {
        Kind::parse(kind)
            .map_err(|err| anyhow::anyhow!("[pseudonymize.rules] `{rule_id}`: {err}"))?;
    }
    Ok(())
}

/// Split a name-rule match into its label prefix (`氏名: `, `Name: `, `by `)
/// and the name itself. The label is whatever precedes the separator, or the
/// leading Japanese label word when no separator is present.
fn split_name_label(matched: &str) -> (&str, &str) {
    let name_start = match matched.find([':', '：', '#']) {
        Some(sep) => sep + matched[sep..].chars().next().map_or(1, char::len_utf8),
        None => ["氏名", "名前"]
            .iter()
            .find_map(|label| matched.starts_with(label).then_some(label.len()))
            .or_else(|| {
                // English labels without a separator are one word, then a space.
                matched.find(char::is_whitespace)
            })
            .unwrap_or(0),
    };
    let name_start = name_start
        + matched[name_start..]
            .chars()
            .take_while(|ch| ch.is_whitespace())
            .map(char::len_utf8)
            .sum::<usize>();
    matched.split_at(name_start)
}

/// Byte offset at which each 1-based line begins.
fn line_starts(content: &str) -> Vec<usize> {
    std::iter::once(0)
        .chain(content.match_indices('\n').map(|(idx, _)| idx + 1))
        .collect()
}

/// Accepted spans are disjoint and sorted by start, so only the last span
/// starting before `span.1` can reach into it.
fn overlaps(used: &BTreeMap<usize, usize>, span: (usize, usize)) -> bool {
    used.range(..span.1)
        .next_back()
        .is_some_and(|(_, end)| *end > span.0)
}

fn find_match_span(
    content: &str,
    line_starts: &[usize],
    line: usize,
    column: usize,
    matched: &str,
) -> Option<(usize, usize)> {
    let line_start = *line_starts.get(line.checked_sub(1)?)?;
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
    // Column and text disagree (a rule reporting a capture group, say): fall
    // back to locating the text within the same line rather than dropping it.
    let line_end = line_body.find('\n').unwrap_or(line_body.len());
    line_body[..line_end]
        .find(matched)
        .map(|offset| (line_start + offset, line_start + offset + matched.len()))
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
            source: super::columns::ColumnSource::Rule,
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
    use crate::pseudonymize::{ColumnSource, Kind};

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
    fn multiline_replacements_use_original_offsets() {
        let email = ["ada", "@", "example.com"].concat();
        let input = format!("{email}\nx {email}\n日本語 {email} {email}");
        let result = run_text(&input, Some(&material()), &options(), None).unwrap();
        assert!(!result.output.contains(&email));
        assert_eq!(result.meta.replaced.get("email"), Some(&4));
        assert_eq!(result.output.lines().count(), 3);
    }

    #[test]
    fn dry_run_rejects_invalid_contract_options() {
        let mut invalid = options();
        invalid.dry_run = true;
        invalid.token_bits = 63;
        assert!(run_text("plain", None, &invalid, None).is_err());

        invalid.token_bits = 64;
        invalid
            .rule_overrides
            .insert("pii.email".into(), "bogus".into());
        assert!(run_text("plain", None, &invalid, None).is_err());
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
    fn unparsed_phones_redacted_cards_and_rule_overrides() {
        let us_phone = ["555", "-", "123", "-", "4567"].concat();
        let card = ["4111", "1111", "1111", "1111"].join(" ");
        let input = format!("tel {us_phone} card {card}");
        let result = run_text(&input, Some(&material()), &options(), None).unwrap();
        assert!(result.output.contains("[UNPARSED]"), "{}", result.output);
        assert!(result.output.contains("[REDACTED]"), "{}", result.output);
        assert!(!result.output.contains("4111"), "{}", result.output);
        assert_eq!(result.meta.unparsed.get("phone"), Some(&1));
        assert_eq!(result.meta.columns[0].source, ColumnSource::Rule);

        let mut overridden = options();
        overridden
            .rule_overrides
            .insert("pii.credit_card".into(), "custom:card".into());
        let result = run_text(&card, Some(&material()), &overridden, None).unwrap();
        assert!(result.output.starts_with("card_"), "{}", result.output);
        assert_eq!(result.meta.replaced.get("custom:card"), Some(&1));

        overridden
            .rule_overrides
            .insert("pii.credit_card".into(), "custom:Bad".into());
        assert!(run_text(&card, Some(&material()), &overridden, None).is_err());
    }

    #[test]
    fn overlap_check_and_line_table_agree_with_linear_scan() {
        let mut used = BTreeMap::new();
        used.insert(10, 20);
        used.insert(30, 40);
        assert!(overlaps(&used, (15, 18)));
        assert!(overlaps(&used, (5, 11)));
        assert!(overlaps(&used, (19, 25)));
        assert!(!overlaps(&used, (20, 30)));
        assert!(!overlaps(&used, (0, 10)));
        assert!(!overlaps(&used, (40, 50)));
        let text = "ab\n日本\n\ncd";
        assert_eq!(line_starts(text), vec![0, 3, 10, 11]);
        let starts = line_starts(text);
        assert_eq!(find_match_span(text, &starts, 4, 1, "cd"), Some((11, 13)));
        assert_eq!(find_match_span(text, &starts, 2, 2, "本"), Some((6, 9)));
        assert_eq!(find_match_span(text, &starts, 9, 1, "x"), None);
        assert_eq!(find_match_span(text, &starts, 0, 1, "ab"), None);
        // Wrong column but same line: recovered; text on another line: not.
        assert_eq!(find_match_span(text, &starts, 4, 2, "cd"), Some((11, 13)));
        assert_eq!(find_match_span(text, &starts, 1, 1, "cd"), None);
    }

    #[test]
    fn name_labels_stay_and_only_the_name_is_tokenized() {
        let material = material();
        let ja = "氏名: 山田太郎";
        let en = "Name: Ada Lovelace";
        let result = run_text(&format!("{ja}\n{en}\n"), Some(&material), &options(), None).unwrap();
        let expected_ja = replacement_text(
            &apply_cell(
                &Kind::Name,
                "山田太郎",
                &material,
                NormalizeSettings::default(),
                64,
                None,
            )
            .unwrap(),
            "山田太郎",
        );
        assert!(
            result.output.starts_with(&format!("氏名: {expected_ja}\n")),
            "{}",
            result.output
        );
        assert!(result.output.contains("Name: name_"), "{}", result.output);
        assert!(!result.output.contains("Ada"), "{}", result.output);
        assert_eq!(result.meta.replaced.get("name"), Some(&2));
        assert_eq!(split_name_label("氏名　山田太郎"), ("氏名　", "山田太郎"));
        assert_eq!(split_name_label("by Ada Lovelace"), ("by ", "Ada Lovelace"));
        assert_eq!(split_name_label("山田太郎"), ("", "山田太郎"));
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
