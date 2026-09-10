use super::apply::{CellAction, MapCollector, apply_cell, replacement_text};
use super::columns::{infer_header, resolve_columns};
use super::derive::KeyMaterial;
use super::table::{TableOptions, TableResult, meta_from_parts};
use super::{INFER_MATCH_THRESHOLD, INFER_SAMPLE_ROWS};
use anyhow::{Context, Result, bail};
use quick_xml::Reader;
use quick_xml::events::{BytesStart, BytesText, Event};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Cursor, Read, Write};
use std::path::Path;
use zip::ZipArchive;
use zip::write::{FileOptions, ZipWriter};

pub fn run_xlsx(
    input: &Path,
    output: Option<&Path>,
    sheet: Option<&str>,
    options: &TableOptions,
    material: Option<&KeyMaterial>,
    mut map: Option<&mut MapCollector>,
) -> Result<TableResult> {
    let file = File::open(input).with_context(|| format!("open {}", input.display()))?;
    let mut archive = ZipArchive::new(file).context("read xlsx zip container")?;
    let workbook = read_zip_string(&mut archive, "xl/workbook.xml")?;
    let sheets = parse_workbook_sheets(&workbook)?;
    if sheets.is_empty() {
        bail!("xlsx workbook has no sheets");
    }
    let selected = select_sheet(&sheets, sheet)?;
    let rels = read_zip_string(&mut archive, "xl/_rels/workbook.xml.rels").unwrap_or_default();
    let sheet_path = resolve_sheet_path(&rels, &selected.rel_id)
        .unwrap_or_else(|| format!("xl/worksheets/sheet{}.xml", selected.index + 1));
    let shared = read_zip_string(&mut archive, "xl/sharedStrings.xml").unwrap_or_default();
    let shared_strings = parse_shared_strings(&shared);
    let sheet_xml =
        read_zip_string(&mut archive, &sheet_path).with_context(|| format!("read {sheet_path}"))?;
    let cells = parse_sheet_cells(&sheet_xml, &shared_strings)?;
    let grid = cells_to_grid(&cells);

    if grid.is_empty() {
        return Ok(empty_xlsx_result(options, material));
    }

    let first = grid[0].clone();
    let has_header = if options.no_header {
        false
    } else {
        infer_header(&first, INFER_MATCH_THRESHOLD)
    };
    let (headers, data_rows) = if has_header {
        (first, grid[1..].to_vec())
    } else {
        let headers = (0..first.len()).map(|idx| idx.to_string()).collect();
        (headers, grid)
    };
    let sample: Vec<Vec<String>> = data_rows.iter().take(INFER_SAMPLE_ROWS).cloned().collect();
    let columns = resolve_columns(
        &headers,
        &sample,
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
                data_rows.len() as u64,
                BTreeMap::new(),
                BTreeMap::new(),
                material,
                true,
            ),
            columns,
            has_header,
        });
    }
    let material = material.context("xlsx table mode requires key material unless --dry-run")?;
    let output = output.context("xlsx table mode requires --output")?;

    let mut replaced: BTreeMap<String, u64> = BTreeMap::new();
    let mut unparsed: BTreeMap<String, u64> = BTreeMap::new();
    let mut new_values: BTreeMap<(usize, usize), String> = BTreeMap::new();
    let data_offset = if has_header { 1 } else { 0 };
    for (row_idx, row) in data_rows.iter().enumerate() {
        for column in &columns {
            let Some(raw) = row.get(column.index) else {
                continue;
            };
            let action = apply_cell(
                &column.kind,
                raw,
                material,
                options.settings,
                options.token_bits,
                map.as_deref_mut(),
            )?;
            match &action {
                CellAction::Unparsed => {
                    *unparsed.entry(column.kind.as_config_value()).or_insert(0) += 1;
                }
                CellAction::Token(_) => {
                    *replaced.entry(column.kind.as_config_value()).or_insert(0) += 1;
                }
                CellAction::Keep => continue,
            }
            new_values.insert(
                (row_idx + data_offset, column.index),
                replacement_text(&action, raw),
            );
        }
    }

    let rewritten_sheet = rewrite_sheet_cells(&sheet_xml, &new_values)?;
    write_xlsx_copy(
        &mut archive,
        output,
        &sheet_path,
        rewritten_sheet.as_bytes(),
    )?;

    Ok(TableResult {
        meta: meta_from_parts(
            options,
            "table",
            &columns,
            data_rows.len() as u64,
            replaced,
            unparsed,
            Some(material),
            false,
        ),
        columns,
        has_header,
    })
}

struct SheetInfo {
    name: String,
    rel_id: String,
    index: usize,
}

fn select_sheet<'a>(sheets: &'a [SheetInfo], spec: Option<&str>) -> Result<&'a SheetInfo> {
    let Some(spec) = spec else {
        return Ok(&sheets[0]);
    };
    if let Ok(number) = spec.parse::<usize>() {
        let idx = number.saturating_sub(1);
        return sheets
            .get(idx)
            .ok_or_else(|| anyhow::anyhow!("sheet `{spec}` not found"));
    }
    sheets
        .iter()
        .find(|sheet| sheet.name == spec)
        .ok_or_else(|| anyhow::anyhow!("sheet `{spec}` not found"))
}

fn parse_workbook_sheets(xml: &str) -> Result<Vec<SheetInfo>> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut sheets = Vec::new();
    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Empty(tag) | Event::Start(tag) if local_name(tag.name().as_ref()) == "sheet" => {
                let name = attr(&tag, "name").unwrap_or_default();
                let rel_id = attr(&tag, "id")
                    .or_else(|| attr(&tag, "r:id"))
                    .unwrap_or_default();
                sheets.push(SheetInfo {
                    name,
                    rel_id,
                    index: sheets.len(),
                });
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Ok(sheets)
}

fn resolve_sheet_path(rels: &str, rel_id: &str) -> Option<String> {
    if rels.is_empty() || rel_id.is_empty() {
        return None;
    }
    let mut reader = Reader::from_str(rels);
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf).ok()? {
            Event::Empty(tag) | Event::Start(tag)
                if local_name(tag.name().as_ref()) == "Relationship" =>
            {
                if attr(&tag, "Id").as_deref() == Some(rel_id) {
                    let target = attr(&tag, "Target")?;
                    return Some(if target.starts_with("xl/") {
                        target
                    } else {
                        format!("xl/{target}")
                    });
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    None
}

fn parse_shared_strings(xml: &str) -> Vec<String> {
    if xml.is_empty() {
        return Vec::new();
    }
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_si = false;
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(tag)) if local_name(tag.name().as_ref()) == "si" => {
                in_si = true;
                current.clear();
            }
            Ok(Event::End(tag)) if local_name(tag.name().as_ref()) == "si" => {
                out.push(std::mem::take(&mut current));
                in_si = false;
            }
            Ok(Event::Text(text)) if in_si => {
                current.push_str(&decode_text(&text));
            }
            Ok(Event::CData(cdata)) if in_si => {
                current.push_str(cdata.as_ref());
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    out
}

fn parse_sheet_cells(xml: &str, shared: &[String]) -> Result<Vec<((usize, usize), String)>> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();
    let mut cells = Vec::new();
    let mut cell_ref = String::new();
    let mut cell_type = String::new();
    let mut text = String::new();
    let mut in_value = false;
    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(tag) | Event::Empty(tag) if local_name(tag.name().as_ref()) == "c" => {
                cell_ref = attr(&tag, "r").unwrap_or_default();
                cell_type = attr(&tag, "t").unwrap_or_default();
                text.clear();
                if matches!(reader.read_event_into(&mut buf), Ok(Event::Empty(_))) {
                    // handled below via next events
                }
            }
            Event::Start(tag) if matches!(local_name(tag.name().as_ref()), "v" | "t") => {
                in_value = true;
            }
            Event::End(tag) if matches!(local_name(tag.name().as_ref()), "v" | "t") => {
                in_value = false;
            }
            Event::Text(value) if in_value => {
                text.push_str(&decode_text(&value));
            }
            Event::End(tag) if local_name(tag.name().as_ref()) == "c" => {
                if let Some(coord) = parse_cell_ref(&cell_ref) {
                    let value = if cell_type == "s" {
                        text.parse::<usize>()
                            .ok()
                            .and_then(|idx| shared.get(idx).cloned())
                            .unwrap_or_default()
                    } else {
                        text.clone()
                    };
                    cells.push((coord, value));
                }
                cell_ref.clear();
                cell_type.clear();
                text.clear();
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Ok(cells)
}

fn cells_to_grid(cells: &[((usize, usize), String)]) -> Vec<Vec<String>> {
    let max_row = cells.iter().map(|((row, _), _)| *row).max().unwrap_or(0);
    let max_col = cells.iter().map(|((_, col), _)| *col).max().unwrap_or(0);
    let mut grid = vec![vec![String::new(); max_col + 1]; max_row + 1];
    for ((row, col), value) in cells {
        grid[*row][*col] = value.clone();
    }
    grid
}

fn rewrite_sheet_cells(
    xml: &str,
    replacements: &BTreeMap<(usize, usize), String>,
) -> Result<String> {
    if replacements.is_empty() {
        return Ok(xml.to_string());
    }
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut writer = quick_xml::Writer::new(Cursor::new(Vec::new()));
    let mut buf = Vec::new();
    let mut skip_depth = 0u32;
    let mut pending: Option<String> = None;
    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Eof => break,
            Event::Start(tag) if skip_depth == 0 && local_name(tag.name().as_ref()) == "c" => {
                let coord = attr(&tag, "r").and_then(|raw| parse_cell_ref(&raw));
                if let Some(coord) = coord
                    && let Some(value) = replacements.get(&coord)
                {
                    write_inline_cell(&mut writer, &tag, value)?;
                    pending = Some(value.clone());
                    skip_depth = 1;
                    continue;
                }
                writer.write_event(Event::Start(tag.into_owned()))?;
            }
            Event::Empty(tag) if skip_depth == 0 && local_name(tag.name().as_ref()) == "c" => {
                let coord = attr(&tag, "r").and_then(|raw| parse_cell_ref(&raw));
                if let Some(coord) = coord
                    && let Some(value) = replacements.get(&coord)
                {
                    write_inline_cell(&mut writer, &tag, value)?;
                    writer.write_event(Event::End(quick_xml::events::BytesEnd::new("c")))?;
                    continue;
                }
                writer.write_event(Event::Empty(tag.into_owned()))?;
            }
            Event::Start(_) if skip_depth > 0 => skip_depth += 1,
            Event::End(tag) if skip_depth > 0 => {
                skip_depth -= 1;
                if skip_depth == 0 {
                    writer.write_event(Event::End(quick_xml::events::BytesEnd::new("c")))?;
                    pending = None;
                }
                let _ = tag;
            }
            Event::Text(_) | Event::CData(_) | Event::Empty(_) if skip_depth > 0 => {}
            other if skip_depth == 0 => {
                writer.write_event(other.into_owned())?;
            }
            _ => {}
        }
        buf.clear();
    }
    let _ = pending;
    let bytes = writer.into_inner().into_inner();
    String::from_utf8(bytes).context("xlsx sheet rewrite is not UTF-8")
}

fn write_inline_cell(
    writer: &mut quick_xml::Writer<Cursor<Vec<u8>>>,
    original: &BytesStart<'_>,
    value: &str,
) -> Result<()> {
    let mut start = BytesStart::new("c");
    for attr in original.attributes().flatten() {
        if attr.key.as_ref() != "t" {
            start.push_attribute((attr.key.as_ref(), attr.value.as_ref()));
        }
    }
    start.push_attribute(("t", "inlineStr"));
    writer.write_event(Event::Start(start))?;
    writer.write_event(Event::Start(BytesStart::new("is")))?;
    writer.write_event(Event::Start(BytesStart::new("t")))?;
    writer.write_event(Event::Text(BytesText::new(value)))?;
    writer.write_event(Event::End(quick_xml::events::BytesEnd::new("t")))?;
    writer.write_event(Event::End(quick_xml::events::BytesEnd::new("is")))?;
    Ok(())
}

fn write_xlsx_copy(
    archive: &mut ZipArchive<File>,
    output: &Path,
    replace_name: &str,
    replacement: &[u8],
) -> Result<()> {
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let tmp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("create temp xlsx in {}", parent.display()))?;
    let mut writer = ZipWriter::new(tmp);
    for idx in 0..archive.len() {
        let mut entry = archive.by_index(idx)?;
        let name = entry.name().to_string();
        let options = FileOptions::<()>::default().compression_method(entry.compression());
        if entry.is_dir() {
            writer.add_directory(&name, options)?;
            continue;
        }
        writer.start_file(&name, options)?;
        if name == replace_name {
            writer.write_all(replacement)?;
        } else {
            std::io::copy(&mut entry, &mut writer)?;
        }
    }
    let tmp = writer.finish()?;
    crate::fs_atomic::persist_named_temp_file(tmp, output)
}

fn read_zip_string(archive: &mut ZipArchive<File>, name: &str) -> Result<String> {
    let mut entry = archive.by_name(name)?;
    let mut body = String::new();
    entry.read_to_string(&mut body)?;
    Ok(body)
}

fn parse_cell_ref(raw: &str) -> Option<(usize, usize)> {
    let split = raw.find(|ch: char| ch.is_ascii_digit())?;
    let (col_raw, row_raw) = raw.split_at(split);
    let mut col = 0usize;
    for byte in col_raw.bytes() {
        if !byte.is_ascii_alphabetic() {
            return None;
        }
        col = col * 26 + usize::from(byte.to_ascii_uppercase() - b'A' + 1);
    }
    let row = row_raw.parse::<usize>().ok()?;
    Some((row.saturating_sub(1), col.saturating_sub(1)))
}

fn attr(tag: &BytesStart<'_>, name: &str) -> Option<String> {
    tag.attributes()
        .flatten()
        .find(|attr| {
            let key = attr.key.as_ref();
            key == name || key.ends_with(&format!(":{name}"))
        })
        .map(|attr| attr.value.as_ref().to_string())
}

fn local_name(name: &str) -> &str {
    name.rsplit_once(':')
        .map(|(_, local)| local)
        .unwrap_or(name)
}

fn decode_text(text: &BytesText<'_>) -> String {
    quick_xml::escape::unescape(text.as_ref())
        .map(|cow| cow.into_owned())
        .unwrap_or_else(|_| text.as_ref().to_string())
}

fn empty_xlsx_result(options: &TableOptions, material: Option<&KeyMaterial>) -> TableResult {
    TableResult {
        meta: meta_from_parts(
            options,
            "table",
            &[],
            0,
            BTreeMap::new(),
            BTreeMap::new(),
            material,
            options.dry_run,
        ),
        columns: Vec::new(),
        has_header: !options.no_header,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pseudonymize::NormalizeSettings;
    use crate::pseudonymize::parse_columns_spec;
    use std::io::Write;
    use tempfile::tempdir;
    use zip::CompressionMethod;

    fn material() -> KeyMaterial {
        KeyMaterial::from_parts([0x77; 32], [0x88; 32])
    }

    fn options() -> TableOptions {
        TableOptions {
            delimiter: b',',
            no_header: false,
            token_bits: 64,
            norm: "v1".into(),
            settings: NormalizeSettings::default(),
            config_columns: BTreeMap::new(),
            cli_columns: Some(parse_columns_spec("Email:email").unwrap()),
            dry_run: false,
            crlf: false,
            shk_version: "0.6.4".into(),
            key_namespace: "test".into(),
        }
    }

    fn create_xlsx(path: &Path, header: &str, value: &str) {
        let file = File::create(path).unwrap();
        let mut zip = ZipWriter::new(file);
        let opts = FileOptions::<()>::default().compression_method(CompressionMethod::Deflated);
        zip.start_file("[Content_Types].xml", opts).unwrap();
        zip.write_all(b"<Types/>").unwrap();
        zip.start_file("xl/workbook.xml", opts).unwrap();
        zip.write_all(br#"<workbook xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Customers" sheetId="1" r:id="rId1"/></sheets></workbook>"#).unwrap();
        zip.start_file("xl/_rels/workbook.xml.rels", opts).unwrap();
        zip.write_all(br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Target="worksheets/sheet1.xml"/></Relationships>"#).unwrap();
        zip.start_file("xl/worksheets/sheet1.xml", opts).unwrap();
        write!(
            zip,
            r#"<worksheet><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>{header}</t></is></c></row><row r="2"><c r="A2" t="inlineStr"><is><t>{value}</t></is></c></row></sheetData></worksheet>"#
        )
        .unwrap();
        zip.finish().unwrap();
    }

    #[test]
    fn xlsx_table_replaces_target_cells_only() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("in.xlsx");
        let output = dir.path().join("out.xlsx");
        let email = ["ada", "@", "example.com"].concat();
        create_xlsx(&input, "Email", &email);
        let result = run_xlsx(
            &input,
            Some(&output),
            Some("Customers"),
            &options(),
            Some(&material()),
            None,
        )
        .unwrap();
        assert_eq!(result.meta.replaced.get("email"), Some(&1));
        let body = {
            let file = File::open(&output).unwrap();
            let mut zip = ZipArchive::new(file).unwrap();
            let mut entry = zip.by_name("xl/worksheets/sheet1.xml").unwrap();
            let mut s = String::new();
            entry.read_to_string(&mut s).unwrap();
            s
        };
        assert!(body.contains("email_"), "{body}");
        assert!(!body.contains(&email), "{body}");
        assert!(body.contains("Email"), "{body}");
    }
}
