use super::INFER_SAMPLE_ROWS;
use super::apply::{CellAction, MapCollector, apply_cell, replacement_text};
use super::columns::{infer_header, resolve_columns};
use super::derive::KeyMaterial;
use super::table::{TableOptions, TableResult, meta_from_parts};
use crate::document_masker::{
    copy_entry_bounded, decode_general_ref, decode_xml_text as decode_text, local_name,
    read_entry_bounded,
};
use anyhow::{Context, Result, bail};
use quick_xml::Reader;
use quick_xml::events::{BytesRef, BytesStart, BytesText, Event};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Cursor, Write};
use std::path::Path;
use zip::ZipArchive;
use zip::write::ZipWriter;

const MAX_ARCHIVE_EXPANDED_BYTES: u64 = 256 * 1024 * 1024;
const MAX_XML_BYTES: u64 = 64 * 1024 * 1024;
const MAX_GRID_CELLS: usize = 1_000_000;
const MAX_XLSX_ROWS: usize = 1_048_576;
const MAX_XLSX_COLS: usize = 16_384;

pub fn run_xlsx(
    input: &Path,
    output: Option<&Path>,
    sheet: Option<&str>,
    options: &TableOptions,
    material: Option<&KeyMaterial>,
    mut map: Option<&mut MapCollector>,
) -> Result<TableResult> {
    if !options.dry_run && material.is_none() {
        bail!("xlsx table mode requires key material unless --dry-run");
    }
    let file = File::open(input).with_context(|| format!("open {}", input.display()))?;
    let mut archive = ZipArchive::new(file).context("read xlsx zip container")?;
    crate::document_masker::ensure_archive_entry_limit(archive.len())?;
    let mut expanded_bytes = 0u64;
    for index in 0..archive.len() {
        expanded_bytes = expanded_bytes
            .checked_add(archive.by_index(index)?.size())
            .context("xlsx expanded size overflow")?;
        if expanded_bytes > MAX_ARCHIVE_EXPANDED_BYTES {
            bail!("xlsx expanded size exceeds 256 MiB limit");
        }
    }
    let workbook = read_zip_string(&mut archive, "xl/workbook.xml")?;
    let sheets = parse_workbook_sheets(&workbook)?;
    if sheets.is_empty() {
        bail!("xlsx workbook has no sheets");
    }
    let selected = select_sheet(&sheets, sheet)?;
    let rels = read_zip_string(&mut archive, "xl/_rels/workbook.xml.rels")?;
    let sheet_path = resolve_sheet_path(&rels, &selected.rel_id)
        .context("xlsx sheet relationship is missing or invalid")?;
    let worksheet_paths = sheets
        .iter()
        .map(|sheet| {
            resolve_sheet_path(&rels, &sheet.rel_id)
                .with_context(|| format!("xlsx sheet relationship is missing: {}", sheet.name))
        })
        .collect::<Result<BTreeSet<_>>>()?;
    let shared = if archive
        .file_names()
        .any(|name| name == "xl/sharedStrings.xml")
    {
        read_zip_string(&mut archive, "xl/sharedStrings.xml")?
    } else {
        String::new()
    };
    let shared_strings = parse_shared_strings(&shared)?;
    let sheet_xml =
        read_zip_string(&mut archive, &sheet_path).with_context(|| format!("read {sheet_path}"))?;
    let cells = parse_sheet_cells(&sheet_xml, &shared_strings)?;
    let mut grid = cells_to_grid(&cells)?;
    // Blank rows above the table (a common export layout) are not the header.
    let leading_blank = grid
        .iter()
        .take_while(|row| row.iter().all(String::is_empty))
        .count();
    grid.drain(..leading_blank);

    if grid.is_empty() {
        if !options.dry_run {
            let output = output.context("xlsx table mode requires --output")?;
            write_xlsx_copy(
                &mut archive,
                output,
                &sheet_path,
                sheet_xml.as_bytes(),
                &worksheet_paths,
            )?;
        }
        return Ok(empty_xlsx_result(options, material));
    }

    let has_header = if options.no_header {
        false
    } else {
        infer_header(&grid[0])
    };
    let headers = if has_header {
        grid.remove(0)
    } else {
        (0..grid[0].len()).map(|idx| idx.to_string()).collect()
    };
    let data_rows = grid;
    let sample_len = data_rows.len().min(INFER_SAMPLE_ROWS);
    let columns = resolve_columns(
        &headers,
        &data_rows[..sample_len],
        &options.config_columns,
        options.cli_columns.as_ref(),
    )
    .map_err(|err| anyhow::anyhow!(err))?;
    let data_offset = leading_blank + usize::from(has_header);
    let selected_columns: BTreeSet<usize> = columns.iter().map(|column| column.index).collect();
    if let Some((row, col)) = parse_formula_cells(&sheet_xml)?
        .into_iter()
        .find(|(row, col)| {
            *row >= data_offset
                && *row < data_offset + data_rows.len()
                && selected_columns.contains(col)
        })
    {
        bail!(
            "refusing to pseudonymize formula cell at row {}, column {}; select a value-only column",
            row + 1,
            col + 1
        );
    }

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
    let material = material.expect("checked above");
    let output = output.context("xlsx table mode requires --output")?;

    let mut replaced: BTreeMap<String, u64> = BTreeMap::new();
    let mut unparsed: BTreeMap<String, u64> = BTreeMap::new();
    let mut new_values: BTreeMap<(usize, usize), String> = BTreeMap::new();
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
        &worksheet_paths,
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
}

fn select_sheet<'a>(sheets: &'a [SheetInfo], spec: Option<&str>) -> Result<&'a SheetInfo> {
    let Some(spec) = spec else {
        return Ok(&sheets[0]);
    };
    if let Ok(number) = spec.parse::<usize>() {
        let idx = number.checked_sub(1).context("sheet numbers start at 1")?;
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
                let rel_id = attr(&tag, "id").unwrap_or_default();
                sheets.push(SheetInfo { name, rel_id });
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
                    if attr(&tag, "TargetMode")
                        .is_some_and(|mode| mode.eq_ignore_ascii_case("external"))
                    {
                        return None;
                    }
                    let target = attr(&tag, "Target")?;
                    return normalize_sheet_target(&target);
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    None
}

fn normalize_sheet_target(target: &str) -> Option<String> {
    if target.contains("://") || target.starts_with("//") || target.contains('\\') {
        return None;
    }
    let raw = if target.starts_with('/') {
        target.trim_start_matches('/').to_string()
    } else if target.starts_with("xl/") {
        target.to_string()
    } else {
        format!("xl/{target}")
    };
    let mut parts = Vec::new();
    for part in raw.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            value => parts.push(value),
        }
    }
    let path = parts.join("/");
    (!path.is_empty()).then_some(path)
}

fn parse_shared_strings(xml: &str) -> Result<Vec<String>> {
    if xml.is_empty() {
        return Ok(Vec::new());
    }
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_si = false;
    // <rPh> holds the phonetic guide Japanese Excel adds; it is not cell text.
    let mut in_phonetic = false;
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(tag)) if local_name(tag.name().as_ref()) == "si" => {
                in_si = true;
                current.clear();
            }
            Ok(Event::Empty(tag)) if local_name(tag.name().as_ref()) == "si" => {
                out.push(String::new());
            }
            Ok(Event::End(tag)) if local_name(tag.name().as_ref()) == "si" => {
                out.push(std::mem::take(&mut current));
                in_si = false;
            }
            Ok(Event::Start(tag)) if local_name(tag.name().as_ref()) == "rPh" => {
                in_phonetic = true;
            }
            Ok(Event::End(tag)) if local_name(tag.name().as_ref()) == "rPh" => {
                in_phonetic = false;
            }
            Ok(Event::Text(text)) if in_si && !in_phonetic => {
                current.push_str(&decode_text(&text)?);
            }
            Ok(Event::GeneralRef(reference)) if in_si && !in_phonetic => {
                current.push_str(&resolve_cell_ref_entity(&reference)?);
            }
            Ok(Event::CData(cdata)) if in_si && !in_phonetic => {
                current.push_str(cdata.as_ref());
            }
            Ok(Event::Eof) => break,
            Err(err) => return Err(err.into()),
            _ => {}
        }
        buf.clear();
    }
    Ok(out)
}

fn resolve_cell_ref_entity(reference: &BytesRef<'_>) -> Result<String> {
    decode_general_ref(reference)?
        .ok_or_else(|| anyhow::anyhow!("unsupported XML entity reference in worksheet"))
}

/// Tracks the coordinate of the cell being read. `<row r>` and `<c r>` are
/// optional in OOXML: without them a row follows the previous row and a cell
/// follows the previous cell.
#[derive(Default)]
struct CellCursor {
    row: Option<usize>,
    next_col: usize,
}

impl CellCursor {
    fn enter_row(&mut self, tag: &BytesStart<'_>) -> Result<()> {
        let explicit = attr(tag, "r")
            .map(|raw| {
                raw.parse::<usize>()
                    .ok()
                    .and_then(|n| n.checked_sub(1))
                    .filter(|row| *row < MAX_XLSX_ROWS)
                    .context("invalid xlsx row number")
            })
            .transpose()?;
        self.row = Some(explicit.unwrap_or_else(|| self.row.map_or(0, |row| row + 1)));
        self.next_col = 0;
        Ok(())
    }

    fn enter_cell(&mut self, tag: &BytesStart<'_>) -> Result<(usize, usize)> {
        let coord = match attr(tag, "r") {
            Some(raw) => parse_cell_ref(&raw).context("invalid xlsx cell reference")?,
            None => (self.row.context("xlsx cell outside a row")?, self.next_col),
        };
        self.row = Some(coord.0);
        self.next_col = coord.1 + 1;
        Ok(coord)
    }
}

fn parse_sheet_cells(xml: &str, shared: &[String]) -> Result<Vec<((usize, usize), String)>> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();
    let mut cells = Vec::new();
    let mut cursor = CellCursor::default();
    let mut coord = (0, 0);
    let mut cell_type = String::new();
    let mut text = String::new();
    let mut in_value = false;
    let mut in_phonetic = false;
    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(tag) | Event::Empty(tag) if local_name(tag.name().as_ref()) == "row" => {
                cursor.enter_row(&tag)?;
            }
            Event::Start(tag) | Event::Empty(tag) if local_name(tag.name().as_ref()) == "c" => {
                coord = cursor.enter_cell(&tag)?;
                cell_type = attr(&tag, "t").unwrap_or_default();
                text.clear();
                in_value = false;
            }
            Event::Start(tag) if local_name(tag.name().as_ref()) == "rPh" => in_phonetic = true,
            Event::End(tag) if local_name(tag.name().as_ref()) == "rPh" => in_phonetic = false,
            Event::Start(tag) if matches!(local_name(tag.name().as_ref()), "v" | "t") => {
                in_value = !in_phonetic;
            }
            Event::End(tag) if matches!(local_name(tag.name().as_ref()), "v" | "t") => {
                in_value = false;
            }
            Event::Text(value) if in_value => {
                text.push_str(&decode_text(&value)?);
            }
            Event::GeneralRef(reference) if in_value => {
                text.push_str(&resolve_cell_ref_entity(&reference)?);
            }
            Event::End(tag) if local_name(tag.name().as_ref()) == "c" => {
                let value = if cell_type == "s" {
                    if text.trim().is_empty() {
                        // `<c t="s"><v/></c>`: a shared cell with no index is empty.
                        String::new()
                    } else {
                        let index = text
                            .trim()
                            .parse::<usize>()
                            .context("invalid shared string index")?;
                        shared
                            .get(index)
                            .context("shared string index out of range")?
                            .clone()
                    }
                } else {
                    text.clone()
                };
                if !value.is_empty() {
                    cells.push((coord, value));
                }
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

fn parse_formula_cells(xml: &str) -> Result<BTreeSet<(usize, usize)>> {
    let mut reader = Reader::from_str(xml);
    let mut buf = Vec::new();
    let mut cursor = CellCursor::default();
    let mut current = None;
    let mut formulas = BTreeSet::new();
    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(tag) | Event::Empty(tag) if local_name(tag.name().as_ref()) == "row" => {
                cursor.enter_row(&tag)?;
            }
            Event::Start(tag) if local_name(tag.name().as_ref()) == "c" => {
                current = Some(cursor.enter_cell(&tag)?);
            }
            Event::Empty(tag) if local_name(tag.name().as_ref()) == "c" => {
                cursor.enter_cell(&tag)?;
                current = None;
            }
            Event::Start(tag) | Event::Empty(tag) if local_name(tag.name().as_ref()) == "f" => {
                if let Some(coord) = current {
                    formulas.insert(coord);
                }
            }
            Event::End(tag) if local_name(tag.name().as_ref()) == "c" => current = None,
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Ok(formulas)
}

fn cells_to_grid(cells: &[((usize, usize), String)]) -> Result<Vec<Vec<String>>> {
    if cells.is_empty() {
        return Ok(Vec::new());
    }
    let max_row = cells.iter().map(|((row, _), _)| *row).max().unwrap_or(0);
    let max_col = cells.iter().map(|((_, col), _)| *col).max().unwrap_or(0);
    if (max_row + 1)
        .checked_mul(max_col + 1)
        .is_none_or(|count| count > MAX_GRID_CELLS)
    {
        bail!("xlsx table exceeds the supported grid size ({MAX_GRID_CELLS} cells)");
    }
    let mut grid = vec![vec![String::new(); max_col + 1]; max_row + 1];
    for ((row, col), value) in cells {
        grid[*row][*col] = value.clone();
    }
    Ok(grid)
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
    let mut cursor = CellCursor::default();
    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Eof => break,
            Event::Start(tag) if skip_depth == 0 && local_name(tag.name().as_ref()) == "row" => {
                cursor.enter_row(&tag)?;
                writer.write_event(Event::Start(tag.into_owned()))?;
            }
            Event::Empty(tag) if skip_depth == 0 && local_name(tag.name().as_ref()) == "row" => {
                cursor.enter_row(&tag)?;
                writer.write_event(Event::Empty(tag.into_owned()))?;
            }
            Event::Empty(tag) if skip_depth == 0 && local_name(tag.name().as_ref()) == "c" => {
                // Empty cells carry no value and are never replaced; keep the cursor in step.
                cursor.enter_cell(&tag)?;
                writer.write_event(Event::Empty(tag.into_owned()))?;
            }
            Event::Start(tag) if skip_depth == 0 && local_name(tag.name().as_ref()) == "c" => {
                let coord = cursor.enter_cell(&tag)?;
                if let Some(value) = replacements.get(&coord) {
                    write_inline_cell(&mut writer, &tag, value)?;
                    skip_depth = 1;
                    continue;
                }
                writer.write_event(Event::Start(tag.into_owned()))?;
            }
            Event::Start(_) if skip_depth > 0 => skip_depth += 1,
            Event::End(_) if skip_depth > 0 => {
                skip_depth -= 1;
                if skip_depth == 0 {
                    writer.write_event(Event::End(quick_xml::events::BytesEnd::new("c")))?;
                }
            }
            // Everything else inside a replaced cell (old value, formula, rich text) is dropped.
            _ if skip_depth > 0 => {}
            other => writer.write_event(other.into_owned())?,
        }
        buf.clear();
    }
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
    worksheet_paths: &BTreeSet<String>,
) -> Result<()> {
    // Keep indices stable, but remove originals no longer referenced by any sheet.
    let mut used = BTreeSet::new();
    for idx in 0..archive.len() {
        let name = archive.by_index(idx)?.name().to_string();
        if worksheet_paths.contains(&name)
            || (name.starts_with("xl/worksheets/") && name.ends_with(".xml"))
        {
            if name == replace_name {
                collect_shared_indices(std::str::from_utf8(replacement)?, &mut used)?;
            } else {
                collect_shared_indices(&read_zip_string(archive, &name)?, &mut used)?;
            }
        }
    }
    let shared = if archive
        .file_names()
        .any(|name| name == "xl/sharedStrings.xml")
    {
        Some(prune_shared_strings(
            &read_zip_string(archive, "xl/sharedStrings.xml")?,
            &used,
        )?)
    } else {
        None
    };
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let tmp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("create temp xlsx in {}", parent.display()))?;
    if let Ok(metadata) = std::fs::metadata(output) {
        std::fs::set_permissions(tmp.path(), metadata.permissions())
            .with_context(|| format!("preserve output permissions for {}", output.display()))?;
    }
    let mut writer = ZipWriter::new(tmp);
    // Declared sizes were pre-checked, but only the bytes actually inflated
    // are trusted against the expanded-size cap.
    let mut actual_total = 0u64;
    for idx in 0..archive.len() {
        let mut entry = archive.by_index(idx)?;
        let name = entry.name().to_string();
        let options = crate::document_masker::entry_options(&entry);
        if entry.is_dir() {
            writer.add_directory(&name, options)?;
            continue;
        }
        writer.start_file(&name, options)?;
        let rewritten: Option<&[u8]> = if name == "xl/sharedStrings.xml" && shared.is_some() {
            shared.as_deref().map(str::as_bytes)
        } else if name == replace_name {
            Some(replacement)
        } else {
            None
        };
        match rewritten {
            Some(bytes) => {
                writer.write_all(bytes)?;
                actual_total = actual_total
                    .checked_add(bytes.len() as u64)
                    .context("xlsx expanded size overflow")?;
                if actual_total > MAX_ARCHIVE_EXPANDED_BYTES {
                    bail!("xlsx expanded output exceeds 256 MiB limit");
                }
            }
            None => copy_entry_bounded(
                &mut entry,
                &mut writer,
                &mut actual_total,
                MAX_ARCHIVE_EXPANDED_BYTES,
                &name,
            )?,
        }
    }
    let tmp = writer.finish()?;
    tmp.as_file()
        .sync_all()
        .with_context(|| format!("sync output workbook {}", output.display()))?;
    crate::fs_atomic::persist_named_temp_file(tmp, output)
}

fn collect_shared_indices(xml: &str, used: &mut BTreeSet<usize>) -> Result<()> {
    let mut reader = Reader::from_str(xml);
    let mut shared_cell = false;
    let mut value = false;
    loop {
        match reader.read_event()? {
            Event::Start(tag) if local_name(tag.name().as_ref()) == "c" => {
                shared_cell = attr(&tag, "t").as_deref() == Some("s");
            }
            Event::Start(tag) if local_name(tag.name().as_ref()) == "v" => value = true,
            Event::Text(text) if shared_cell && value => {
                used.insert(
                    decode_text(&text)?
                        .parse()
                        .context("invalid shared string index")?,
                );
            }
            Event::GeneralRef(_) if shared_cell && value => {
                bail!("invalid shared string index");
            }
            Event::End(tag) if local_name(tag.name().as_ref()) == "v" => value = false,
            Event::End(tag) if local_name(tag.name().as_ref()) == "c" => shared_cell = false,
            Event::Eof => break,
            _ => {}
        }
    }
    Ok(())
}

fn prune_shared_strings(xml: &str, used: &BTreeSet<usize>) -> Result<String> {
    let mut reader = Reader::from_str(xml);
    let mut writer = quick_xml::Writer::new(Vec::new());
    let mut index = 0;
    let mut skip_depth = 0;
    loop {
        let event = reader.read_event()?;
        match event {
            Event::Eof => break,
            Event::Start(tag) if skip_depth == 0 && local_name(tag.name().as_ref()) == "sst" => {
                let mut start = BytesStart::new("sst");
                for attr in tag.attributes().flatten() {
                    let name = local_name(attr.key.as_ref());
                    if name != "count" && name != "uniqueCount" {
                        start.push_attribute((attr.key.as_ref(), attr.value.as_ref()));
                    }
                }
                writer.write_event(Event::Start(start))?;
            }
            Event::Start(tag) if skip_depth == 0 && local_name(tag.name().as_ref()) == "si" => {
                if !used.contains(&index) {
                    writer.write_event(Event::Empty(tag.into_owned()))?;
                    skip_depth = 1;
                } else {
                    writer.write_event(Event::Start(tag.into_owned()))?;
                }
                index += 1;
            }
            Event::Empty(tag) if skip_depth == 0 && local_name(tag.name().as_ref()) == "si" => {
                writer.write_event(Event::Empty(tag.into_owned()))?;
                index += 1;
            }
            Event::Start(_) if skip_depth > 0 => skip_depth += 1,
            Event::End(_) if skip_depth > 0 => skip_depth -= 1,
            event if skip_depth == 0 => writer.write_event(event.into_owned())?,
            _ => {}
        }
    }
    String::from_utf8(writer.into_inner()).context("shared strings rewrite is not UTF-8")
}

fn read_zip_string(archive: &mut ZipArchive<File>, name: &str) -> Result<String> {
    let mut entry = archive.by_name(name)?;
    let bytes = read_entry_bounded(&mut entry, MAX_XML_BYTES, name)?;
    String::from_utf8(bytes).with_context(|| format!("xlsx entry {name} is not UTF-8"))
}

fn parse_cell_ref(raw: &str) -> Option<(usize, usize)> {
    let split = raw.find(|ch: char| ch.is_ascii_digit())?;
    let (col_raw, row_raw) = raw.split_at(split);
    let mut col = 0usize;
    for byte in col_raw.bytes() {
        if !byte.is_ascii_alphabetic() {
            return None;
        }
        col = col
            .checked_mul(26)?
            .checked_add(usize::from(byte.to_ascii_uppercase() - b'A' + 1))?;
    }
    let row = row_raw.parse::<usize>().ok()?;
    if row > MAX_XLSX_ROWS || col > MAX_XLSX_COLS {
        return None;
    }
    Some((row.checked_sub(1)?, col.checked_sub(1)?))
}

fn attr(tag: &BytesStart<'_>, name: &str) -> Option<String> {
    tag.attributes()
        .flatten()
        .find(|attr| local_name(attr.key.as_ref()) == name)
        .and_then(|attr| {
            quick_xml::escape::unescape(attr.value.as_ref())
                .ok()
                .map(|value| value.into_owned())
        })
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
    use std::io::{Read, Write};
    use tempfile::tempdir;
    use zip::CompressionMethod;
    use zip::write::FileOptions;

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

    const WORKBOOK: &str = r#"<workbook xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Customers" sheetId="1" r:id="rId1"/></sheets></workbook>"#;
    const RELS: &str = r#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Target="worksheets/sheet1.xml"/></Relationships>"#;

    /// Write an xlsx-shaped zip from raw entries; `dirs` adds directory entries.
    fn build_xlsx(path: &Path, entries: &[(&str, String)], dirs: &[&str]) {
        let file = File::create(path).unwrap();
        let mut zip = ZipWriter::new(file);
        let opts = FileOptions::<()>::default().compression_method(CompressionMethod::Deflated);
        for dir in dirs {
            zip.add_directory(*dir, opts).unwrap();
        }
        for (name, body) in entries {
            zip.start_file(*name, opts).unwrap();
            zip.write_all(body.as_bytes()).unwrap();
        }
        zip.finish().unwrap();
    }

    fn create_xlsx(path: &Path, header: &str, value: &str) {
        build_xlsx(
            path,
            &[
                ("[Content_Types].xml", "<Types/>".into()),
                ("xl/workbook.xml", WORKBOOK.into()),
                ("xl/_rels/workbook.xml.rels", RELS.into()),
                (
                    "xl/sharedStrings.xml",
                    format!("<sst><si><t>{value}</t></si></sst>"),
                ),
                (
                    "xl/worksheets/sheet1.xml",
                    format!(
                        r#"<worksheet><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>{header}</t></is></c></row><row r="2"><c r="A2" t="s"><v>0</v></c></row></sheetData></worksheet>"#
                    ),
                ),
            ],
            &[],
        );
    }

    fn sheet_xml(path: &Path, name: &str) -> String {
        let mut archive = ZipArchive::new(File::open(path).unwrap()).unwrap();
        read_zip_string(&mut archive, name).unwrap()
    }

    #[test]
    fn no_header_mode_counts_unparsed_missing_and_short_rows() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("raw.xlsx");
        let output = dir.path().join("out.xlsx");
        let email = ["ada", "@", "example.com"].concat();
        build_xlsx(
            &input,
            &[
                ("xl/workbook.xml", WORKBOOK.into()),
                (
                    "xl/_rels/workbook.xml.rels",
                    RELS.replace("worksheets/", "/xl/worksheets/"),
                ),
                (
                    "xl/worksheets/sheet1.xml",
                    format!(
                        r#"<worksheet><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>{email}</t></is></c><c r="B1" t="inlineStr"><is><t>garbage</t></is></c></row><row r="2"><c r="A2" t="inlineStr"><is><t>-</t></is></c><c r="B2" t="inlineStr"><is><t>NULL</t></is></c></row><row r="3"><c r="A3" t="inlineStr"><is><t>{email}</t></is></c></row></sheetData></worksheet>"#
                    ),
                ),
            ],
            &["xl/", "xl/worksheets/"],
        );
        let mut opts = options();
        opts.no_header = true;
        opts.cli_columns = Some(parse_columns_spec("0:email,1:phone").unwrap());
        let result = run_xlsx(&input, Some(&output), None, &opts, Some(&material()), None).unwrap();
        assert!(!result.has_header);
        assert_eq!(result.meta.rows_processed, 3);
        assert_eq!(result.meta.replaced.get("email"), Some(&2));
        assert_eq!(result.meta.unparsed.get("phone"), Some(&1));
        let sheet = sheet_xml(&output, "xl/worksheets/sheet1.xml");
        assert!(sheet.contains("[UNPARSED]") && sheet.contains(">-<") && sheet.contains("NULL"));
        assert!(!sheet.contains(&email), "{sheet}");
    }

    #[test]
    fn empty_sheet_copies_the_workbook_and_reports_no_rows() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("empty.xlsx");
        let output = dir.path().join("out.xlsx");
        build_xlsx(
            &input,
            &[
                ("xl/workbook.xml", WORKBOOK.into()),
                (
                    "xl/_rels/workbook.xml.rels",
                    RELS.replace("Target=\"", "Target=\"xl/"),
                ),
                (
                    "xl/worksheets/sheet1.xml",
                    "<worksheet><sheetData/></worksheet>".into(),
                ),
            ],
            &[],
        );
        let mut dry = options();
        dry.dry_run = true;
        let result = run_xlsx(&input, None, None, &dry, None, None).unwrap();
        assert_eq!(result.meta.rows_processed, 0);
        assert!(result.meta.dry_run);
        run_xlsx(
            &input,
            Some(&output),
            None,
            &options(),
            Some(&material()),
            None,
        )
        .unwrap();
        assert!(output.exists());
        assert!(run_xlsx(&input, Some(&output), None, &options(), None, None).is_err());
    }

    #[test]
    fn workbook_structure_errors_are_reported() {
        let dir = tempdir().unwrap();
        let no_sheets = dir.path().join("none.xlsx");
        build_xlsx(
            &no_sheets,
            &[
                ("xl/workbook.xml", "<workbook><sheets/></workbook>".into()),
                ("xl/_rels/workbook.xml.rels", RELS.into()),
            ],
            &[],
        );
        assert!(run_xlsx(&no_sheets, None, None, &options(), None, None).is_err());

        let bad_rel = dir.path().join("rel.xlsx");
        build_xlsx(
            &bad_rel,
            &[
                ("xl/workbook.xml", WORKBOOK.into()),
                ("xl/_rels/workbook.xml.rels", "<Relationships/>".into()),
            ],
            &[],
        );
        assert!(run_xlsx(&bad_rel, None, None, &options(), None, None).is_err());

        let ok = dir.path().join("ok.xlsx");
        create_xlsx(&ok, "Email", "x");
        for sheet in ["0", "2", "Missing"] {
            assert!(
                run_xlsx(&ok, None, Some(sheet), &options(), None, None).is_err(),
                "{sheet}"
            );
        }
        assert!(parse_cell_ref("A-1").is_none());
        assert!(parse_cell_ref("A").is_none());
        assert_eq!(
            resolve_sheet_path(
                r#"<Relationships><Relationship Id="rId1" Target="./worksheets/sheet1.xml"/></Relationships>"#,
                "rId1"
            )
            .as_deref(),
            Some("xl/worksheets/sheet1.xml")
        );
        assert!(resolve_sheet_path(
            r#"<Relationships><Relationship Id="rId1" Target="https://example.com/sheet.xml" TargetMode="External"/></Relationships>"#,
            "rId1"
        )
        .is_none());
        // Entity references are part of the cell text; malformed ones are errors.
        assert!(parse_shared_strings("<sst><si><t>bad &#xZZ; entity</t></si></sst>").is_err());
        assert_eq!(
            parse_shared_strings("<sst><si><t>R&amp;D &lt;x&gt;</t></si></sst>").unwrap(),
            vec!["R&D <x>"]
        );
        let cells = parse_sheet_cells(
            r#"<worksheet><sheetData><row><c r="A1" t="inlineStr"><is><t>a&amp;b</t></is></c></row></sheetData></worksheet>"#,
            &[],
        )
        .unwrap();
        assert_eq!(cells, vec![((0, 0), "a&b".into())]);
        assert_eq!(
            parse_shared_strings("<sst><si><t><![CDATA[cd]]></t></si></sst>").unwrap(),
            vec!["cd"]
        );
    }

    #[test]
    fn selected_formula_cells_are_rejected_without_rewriting_formulas() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("formula.xlsx");
        build_xlsx(
            &input,
            &[
                ("xl/workbook.xml", WORKBOOK.into()),
                ("xl/_rels/workbook.xml.rels", RELS.into()),
                (
                    "xl/worksheets/sheet1.xml",
                    format!(
                        r#"<worksheet><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>Email</t></is></c></row><row r="2"><c r="A2" t="str"><f>LOWER(B2)</f><v>{}</v></c></row></sheetData></worksheet>"#,
                        ["ada", "@", "example.com"].concat()
                    ),
                ),
            ],
            &[],
        );
        let mut dry = options();
        dry.dry_run = true;
        let err = run_xlsx(&input, None, None, &dry, None, None).unwrap_err();
        assert!(err.to_string().contains("formula cell"), "{err}");
    }

    #[test]
    fn escaped_cell_text_is_tokenized_as_the_real_value() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("amp.xlsx");
        let output = dir.path().join("out.xlsx");
        // The custom kind keeps the raw value, so the map original must be `R&D`.
        create_xlsx(&input, "Team", "R&amp;D");
        let mut opts = options();
        opts.cli_columns = Some(parse_columns_spec("Team:custom:team").unwrap());
        let mut collector = MapCollector::default();
        run_xlsx(
            &input,
            Some(&output),
            None,
            &opts,
            Some(&material()),
            Some(&mut collector),
        )
        .unwrap();
        let doc = collector.into_document("v1".into(), material().fingerprint());
        assert_eq!(doc.entries.len(), 1);
        assert_eq!(doc.entries[0].originals, vec!["R&D".to_string()]);
    }

    #[test]
    fn phonetic_runs_implicit_positions_and_blank_rows() {
        let email = ["ada", "@", "example.com"].concat();
        // Japanese Excel stores a furigana guide next to the text; it is not part of the value.
        assert_eq!(
            parse_shared_strings(
                r#"<sst><si><t>メールアドレス</t><rPh sb="0" eb="7"><t>メールアドレス</t></rPh><phoneticPr fontId="1"/></si></sst>"#
            )
            .unwrap(),
            vec!["メールアドレス"]
        );
        // Cells and rows without `r` follow their predecessors; `<v/>` is an empty shared cell.
        let cells = parse_sheet_cells(
            r#"<worksheet><sheetData><row/><row r="3"><c t="inlineStr"><is><t>a</t></is></c><c t="s"><v/></c><c t="inlineStr"><is><t>c</t></is></c></row><row><c r="B4" t="inlineStr"><is><t>d</t></is></c><c t="inlineStr"><is><t>e</t></is></c></row></sheetData></worksheet>"#,
            &[],
        )
        .unwrap();
        assert_eq!(
            cells,
            vec![
                ((2, 0), "a".into()),
                ((2, 2), "c".into()),
                ((3, 1), "d".into()),
                ((3, 2), "e".into()),
            ]
        );

        let dir = tempdir().unwrap();
        let input = dir.path().join("blank.xlsx");
        let output = dir.path().join("out.xlsx");
        build_xlsx(
            &input,
            &[
                ("xl/workbook.xml", WORKBOOK.into()),
                ("xl/_rels/workbook.xml.rels", RELS.into()),
                (
                    "xl/worksheets/sheet1.xml",
                    format!(
                        r#"<worksheet><sheetData><row r="1"/><row r="2"><c r="A2"/></row><row r="3"><c t="inlineStr"><is><t>Email</t></is></c></row><row r="4"><c t="inlineStr"><is><t>{email}</t></is></c></row></sheetData></worksheet>"#
                    ),
                ),
            ],
            &[],
        );
        let result = run_xlsx(
            &input,
            Some(&output),
            None,
            &options(),
            Some(&material()),
            None,
        )
        .unwrap();
        assert!(result.has_header);
        assert_eq!(result.meta.rows_processed, 1);
        assert_eq!(result.meta.replaced.get("email"), Some(&1));
        let sheet = sheet_xml(&output, "xl/worksheets/sheet1.xml");
        assert!(
            sheet.contains("<t>Email</t>") && sheet.contains("email_"),
            "{sheet}"
        );
        assert!(!sheet.contains(&email), "{sheet}");
    }

    #[test]
    fn shared_strings_used_by_other_sheets_survive_pruning() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("two.xlsx");
        let output = dir.path().join("out.xlsx");
        let email = ["ada", "@", "example.com"].concat();
        build_xlsx(
            &input,
            &[
                ("xl/workbook.xml", WORKBOOK.into()),
                ("xl/_rels/workbook.xml.rels", RELS.into()),
                ("xl/sharedStrings.xml", format!("<sst><si><t>{email}</t></si></sst>")),
                (
                    "xl/worksheets/sheet1.xml",
                    r#"<worksheet><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>Email</t></is></c></row><row r="2"><c r="A2" t="s"><v>0</v></c></row></sheetData></worksheet>"#.into(),
                ),
                (
                    "xl/worksheets/sheet2.xml",
                    r#"<worksheet><sheetData><row r="1"><c r="A1" t="s"><v>0</v></c></row></sheetData></worksheet>"#.into(),
                ),
            ],
            &[],
        );
        run_xlsx(
            &input,
            Some(&output),
            None,
            &options(),
            Some(&material()),
            None,
        )
        .unwrap();
        assert!(sheet_xml(&output, "xl/sharedStrings.xml").contains(&email));
        assert!(!sheet_xml(&output, "xl/worksheets/sheet1.xml").contains("<v>0</v>"));
    }

    #[test]
    fn shared_strings_on_relationship_resolved_custom_sheet_paths_survive() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("custom-path.xlsx");
        let output = dir.path().join("out.xlsx");
        let workbook = r#"<workbook xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Customers" sheetId="1" r:id="rId1"/><sheet name="Archive" sheetId="2" r:id="rId2"/></sheets></workbook>"#;
        let rels = r#"<Relationships><Relationship Id="rId1" Target="custom/active.xml"/><Relationship Id="rId2" Target="custom/archive.xml"/></Relationships>"#;
        let email = ["ada", "@", "example.com"].concat();
        let keep = "must survive";
        build_xlsx(
            &input,
            &[
                ("xl/workbook.xml", workbook.into()),
                ("xl/_rels/workbook.xml.rels", rels.into()),
                (
                    "xl/sharedStrings.xml",
                    format!(
                        r#"<sst count="2" uniqueCount="2"><si><t>{email}</t></si><si><t>{keep}</t></si></sst>"#
                    ),
                ),
                (
                    "xl/custom/active.xml",
                    r#"<worksheet><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>Email</t></is></c></row><row r="2"><c r="A2" t="s"><v>0</v></c></row></sheetData></worksheet>"#.into(),
                ),
                (
                    "xl/custom/archive.xml",
                    r#"<worksheet><sheetData><row r="1"><c r="A1" t="s"><v>1</v></c></row></sheetData></worksheet>"#.into(),
                ),
            ],
            &[],
        );
        run_xlsx(
            &input,
            Some(&output),
            None,
            &options(),
            Some(&material()),
            None,
        )
        .unwrap();
        let shared = sheet_xml(&output, "xl/sharedStrings.xml");
        assert!(shared.contains(keep), "{shared}");
        assert!(
            !shared.contains(" count=") && !shared.contains(" uniqueCount="),
            "{shared}"
        );
    }

    #[test]
    fn parses_shared_numeric_and_empty_cells_without_skipping_events() {
        let xml = r#"<worksheet><sheetData><row><c r="A1" t="s"><v>0</v></c><c r="B1"/><c r="C1"><v>42</v></c></row></sheetData></worksheet>"#;
        let cells = parse_sheet_cells(xml, &["Email".into()]).unwrap();
        assert_eq!(cells, vec![((0, 0), "Email".into()), ((0, 2), "42".into())]);
        assert!(parse_cell_ref("A0").is_none());
        assert!(parse_cell_ref("1").is_none());
        assert!(parse_cell_ref("ZZZZZZZZZZZZZZZZZZZZ1").is_none());
        assert!(cells_to_grid(&[((1_048_575, 16_383), "x".into())]).is_err());
        assert!(cells_to_grid(&[]).unwrap().is_empty());
    }

    #[test]
    fn shared_strings_pruning_preserves_indices_and_referenced_runs() {
        let xml = "<sst><si><t>unused original</t></si><si><r><t>kept</t></r></si><si/></sst>";
        let used = BTreeSet::from([1]);
        let clean = prune_shared_strings(xml, &used).unwrap();
        assert!(!clean.contains("unused original"));
        assert!(clean.contains("<r><t>kept</t></r>"));
        assert_eq!(parse_shared_strings(&clean).unwrap(), vec!["", "kept", ""]);
    }

    #[test]
    fn shared_string_original_is_removed_from_output_archive() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("shared.xlsx");
        let output = dir.path().join("out.xlsx");
        let email = ["ada", "@", "example.com"].concat();
        create_xlsx(&input, "Email", &email);
        run_xlsx(
            &input,
            Some(&output),
            None,
            &options(),
            Some(&material()),
            None,
        )
        .unwrap();
        let mut archive = ZipArchive::new(File::open(output).unwrap()).unwrap();
        assert!(
            !read_zip_string(&mut archive, "xl/sharedStrings.xml")
                .unwrap()
                .contains(&email)
        );
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
