use super::apply::{CellAction, MapCollector, apply_cell, replacement_text};
use super::columns::{
    ColumnOverrides, ColumnSource, ResolvedColumn, infer_header, resolve_columns,
};
use super::derive::KeyMaterial;
use super::normalize::NormalizeSettings;
use super::{INFER_MATCH_THRESHOLD, INFER_SAMPLE_ROWS, validate_norm, validate_token_bits};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::{Read, Write};

#[derive(Debug, Clone)]
pub struct TableOptions {
    pub delimiter: u8,
    pub no_header: bool,
    pub token_bits: u16,
    pub norm: String,
    pub settings: NormalizeSettings,
    pub config_columns: BTreeMap<String, String>,
    pub cli_columns: Option<ColumnOverrides>,
    pub dry_run: bool,
    pub crlf: bool,
    pub shk_version: String,
    pub key_namespace: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PseudonymizeMeta {
    pub shk_version: String,
    pub mode: &'static str,
    pub norm: String,
    pub token_bits: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_fingerprint: Option<String>,
    pub key_namespace: String,
    pub columns: Vec<MetaColumn>,
    pub rows_processed: u64,
    pub replaced: BTreeMap<String, u64>,
    pub unparsed: BTreeMap<String, u64>,
    pub map_created: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct MetaColumn {
    pub name: String,
    pub kind: String,
    pub source: ColumnSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_rate: Option<f64>,
}

pub type PseudonymizeJson = PseudonymizeMeta;

#[derive(Debug, Clone)]
pub struct TableResult {
    pub meta: PseudonymizeMeta,
    pub columns: Vec<ResolvedColumn>,
    pub has_header: bool,
}

pub fn delimiter_for_path(path: Option<&std::path::Path>) -> u8 {
    match path
        .and_then(|p| p.extension())
        .and_then(|ext| ext.to_str())
    {
        Some(ext) if ext.eq_ignore_ascii_case("tsv") => b'\t',
        _ => b',',
    }
}

pub fn run_table<R: Read, W: Write>(
    input: R,
    mut output: Option<W>,
    options: &TableOptions,
    material: Option<&KeyMaterial>,
    mut map: Option<&mut MapCollector>,
) -> Result<TableResult> {
    validate_norm(&options.norm).map_err(|err| anyhow::anyhow!(err))?;
    validate_token_bits(options.token_bits).map_err(|err| anyhow::anyhow!(err))?;
    if !options.dry_run && material.is_none() {
        bail!("pseudonymize requires key material unless --dry-run is set");
    }

    let mut reader = csv::ReaderBuilder::new()
        .delimiter(options.delimiter)
        .has_headers(false)
        .flexible(true)
        .from_reader(input);

    let mut records = reader.records();
    let Some(first) = records.next() else {
        let columns = Vec::new();
        return Ok(empty_result(options, columns, !options.no_header, material));
    };
    let first = first.context("read first CSV row")?;
    let first_row = record_to_row(&first);

    let has_header = if options.no_header {
        false
    } else {
        infer_header(&first_row, INFER_MATCH_THRESHOLD)
    };

    let (headers, mut pending_rows) = if has_header {
        (first_row, Vec::new())
    } else {
        let headers = (0..first_row.len()).map(|idx| idx.to_string()).collect();
        (headers, vec![first_row])
    };

    while pending_rows.len() < INFER_SAMPLE_ROWS {
        match records.next() {
            Some(row) => pending_rows.push(record_to_row(&row.context("read CSV row")?)),
            None => break,
        }
    }

    let columns = resolve_columns(
        &headers,
        &pending_rows,
        &options.config_columns,
        options.cli_columns.as_ref(),
    )
    .map_err(|err| anyhow::anyhow!(err))?;

    if options.dry_run {
        return Ok(TableResult {
            meta: meta_from_parts(
                options,
                "table",
                &columns,
                pending_rows.len() as u64,
                BTreeMap::new(),
                BTreeMap::new(),
                material,
                true,
            ),
            columns,
            has_header,
        });
    }

    let material = material.expect("checked above");
    let mut writer = csv::WriterBuilder::new()
        .delimiter(options.delimiter)
        .quote_style(csv::QuoteStyle::Necessary)
        .terminator(if options.crlf {
            csv::Terminator::CRLF
        } else {
            csv::Terminator::Any(b'\n')
        })
        .from_writer(output.take().expect("output required when not dry-run"));

    if has_header {
        writer.write_record(&headers).context("write CSV header")?;
    }

    let mut rows_processed = 0u64;
    let mut replaced: BTreeMap<String, u64> = BTreeMap::new();
    let mut unparsed: BTreeMap<String, u64> = BTreeMap::new();

    let mut process_row = |row: Vec<String>| -> Result<()> {
        let out = transform_row(
            row,
            &columns,
            material,
            options,
            &mut replaced,
            &mut unparsed,
            map.as_deref_mut(),
        )?;
        writer.write_record(&out).context("write CSV row")?;
        rows_processed += 1;
        Ok(())
    };

    for row in pending_rows {
        process_row(row)?;
    }
    for row in records {
        process_row(record_to_row(&row.context("read CSV row")?))?;
    }
    writer.flush().context("flush CSV output")?;

    Ok(TableResult {
        meta: meta_from_parts(
            options,
            "table",
            &columns,
            rows_processed,
            replaced,
            unparsed,
            Some(material),
            false,
        ),
        columns,
        has_header,
    })
}

fn transform_row(
    mut row: Vec<String>,
    columns: &[ResolvedColumn],
    material: &KeyMaterial,
    options: &TableOptions,
    replaced: &mut BTreeMap<String, u64>,
    unparsed: &mut BTreeMap<String, u64>,
    mut map: Option<&mut MapCollector>,
) -> Result<Vec<String>> {
    for column in columns {
        if column.index >= row.len() {
            continue;
        }
        let kind_key = column.kind.as_config_value();
        let action = apply_cell(
            &column.kind,
            &row[column.index],
            material,
            options.settings,
            options.token_bits,
            map.as_deref_mut(),
        )?;
        match &action {
            CellAction::Keep => {}
            CellAction::Unparsed => {
                *unparsed.entry(kind_key).or_insert(0) += 1;
                row[column.index] = replacement_text(&action, &row[column.index]);
            }
            CellAction::Token(_) => {
                *replaced.entry(kind_key).or_insert(0) += 1;
                row[column.index] = replacement_text(&action, &row[column.index]);
            }
        }
    }
    Ok(row)
}

fn record_to_row(record: &csv::StringRecord) -> Vec<String> {
    record
        .iter()
        .enumerate()
        .map(|(idx, field)| {
            if idx == 0 {
                field.trim_start_matches('\u{feff}').to_string()
            } else {
                field.to_string()
            }
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn meta_from_parts(
    options: &TableOptions,
    mode: &'static str,
    columns: &[ResolvedColumn],
    rows_processed: u64,
    replaced: BTreeMap<String, u64>,
    unparsed: BTreeMap<String, u64>,
    material: Option<&KeyMaterial>,
    dry_run: bool,
) -> PseudonymizeMeta {
    PseudonymizeMeta {
        shk_version: options.shk_version.clone(),
        mode,
        norm: options.norm.clone(),
        token_bits: options.token_bits,
        key_fingerprint: material.map(KeyMaterial::fingerprint),
        key_namespace: options.key_namespace.clone(),
        columns: columns
            .iter()
            .map(|column| MetaColumn {
                name: column.name.clone(),
                kind: column.kind.as_config_value(),
                source: column.source,
                match_rate: column.match_rate,
            })
            .collect(),
        rows_processed,
        replaced,
        unparsed,
        map_created: false,
        dry_run,
    }
}

fn empty_result(
    options: &TableOptions,
    columns: Vec<ResolvedColumn>,
    has_header: bool,
    material: Option<&KeyMaterial>,
) -> TableResult {
    TableResult {
        meta: meta_from_parts(
            options,
            "table",
            &columns,
            0,
            BTreeMap::new(),
            BTreeMap::new(),
            material,
            options.dry_run,
        ),
        columns,
        has_header,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pseudonymize::{Kind, UNPARSED, parse_columns_spec};

    fn options(cli: &str, dry_run: bool) -> TableOptions {
        TableOptions {
            delimiter: b',',
            no_header: false,
            token_bits: 64,
            norm: "v1".into(),
            settings: NormalizeSettings::default(),
            config_columns: BTreeMap::new(),
            cli_columns: Some(parse_columns_spec(cli).unwrap()),
            dry_run,
            crlf: false,
            shk_version: "0.6.4".into(),
            key_namespace: "test".into(),
        }
    }

    fn material() -> KeyMaterial {
        KeyMaterial::from_parts([0x33; 32], [0x44; 32])
    }

    fn csv_body() -> String {
        format!(
            "Email,Phone,Note\n{},{},keep\n",
            ["Ada", "@", "Example.COM"].concat(),
            ["090", "-", "1234", "-", "5678"].concat()
        )
    }

    #[test]
    fn table_is_deterministic_and_redacts_values() {
        let material = material();
        let opts = options("Email:email,Phone:phone", false);
        let mut first = Vec::new();
        let result = run_table(
            csv_body().as_bytes(),
            Some(&mut first),
            &opts,
            Some(&material),
            None,
        )
        .unwrap();
        let mut second = Vec::new();
        run_table(
            csv_body().as_bytes(),
            Some(&mut second),
            &opts,
            Some(&material),
            None,
        )
        .unwrap();
        assert_eq!(first, second);
        let text = String::from_utf8(first).unwrap();
        assert!(text.contains("email_"));
        assert!(text.contains("phone_"));
        assert!(text.contains("keep"));
        assert!(!text.contains("Example"));
        assert!(!text.contains("1234"));
        assert_eq!(result.meta.replaced.get("email"), Some(&1));
        assert_eq!(result.meta.rows_processed, 1);
        assert!(!result.meta.map_created);
    }

    #[test]
    fn dry_run_does_not_need_material() {
        let opts = options("Email:email", true);
        let result = run_table(
            csv_body().as_bytes(),
            None::<&mut Vec<u8>>,
            &opts,
            None,
            None,
        )
        .unwrap();
        assert!(result.meta.dry_run);
        assert_eq!(result.columns[0].kind, Kind::Email);
    }

    #[test]
    fn missing_and_unparsed_cells() {
        let material = material();
        let opts = options("Email:email,Phone:phone", false);
        let input = format!(
            "Email,Phone\n-,not-a-phone\n{},{}\n",
            ["ada", "@", "example.com"].concat(),
            ["090", "1234", "5678"].concat()
        );
        let mut out = Vec::new();
        let result = run_table(
            input.as_bytes(),
            Some(&mut out),
            &opts,
            Some(&material),
            None,
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("-"));
        assert!(text.contains(UNPARSED));
        assert_eq!(result.meta.unparsed.get("phone"), Some(&1));
        assert!(!text.contains("not-a-phone"));
    }

    #[test]
    fn name_columns_are_tokenized() {
        let material = material();
        let opts = options("Name:name", false);
        let input = "Name\nAda Lovelace\n";
        let mut out = Vec::new();
        let result = run_table(
            input.as_bytes(),
            Some(&mut out),
            &opts,
            Some(&material),
            None,
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("name_"), "{text}");
        assert!(!text.contains("Ada"), "{text}");
        assert_eq!(result.meta.replaced.get("name"), Some(&1));
    }
}
