use crate::finding::Finding;
use crate::fs_atomic::persist_named_temp_file;
use crate::masker;
use crate::policy::Policy;
use anyhow::{Context, Result, bail};
use quick_xml::escape::unescape;
use quick_xml::events::{BytesCData, BytesText, Event};
use quick_xml::{Reader, Writer};
use std::fs::File;
use std::io::{Cursor, Read, Write};
use std::path::Path;
use tempfile::NamedTempFile;
use zeroize::Zeroize;
use zip::write::FileOptions;
use zip::{ZipArchive, ZipWriter};

const MAX_OOXML_ENTRIES: usize = 10_000;
const MIN_OOXML_ENTRY_BYTES: u64 = 4 * 1024 * 1024;
const MAX_OOXML_ENTRY_BYTES: u64 = 32 * 1024 * 1024;
const MIN_OOXML_TOTAL_BYTES: u64 = 16 * 1024 * 1024;
const MAX_OOXML_TOTAL_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Clone, Copy)]
struct OoxmlReadLimits {
    entry_bytes: u64,
    total_bytes: u64,
}

fn ooxml_read_limits(max_file_size_bytes: u64) -> OoxmlReadLimits {
    OoxmlReadLimits {
        entry_bytes: max_file_size_bytes
            .saturating_mul(16)
            .clamp(MIN_OOXML_ENTRY_BYTES, MAX_OOXML_ENTRY_BYTES),
        total_bytes: max_file_size_bytes
            .saturating_mul(64)
            .clamp(MIN_OOXML_TOTAL_BYTES, MAX_OOXML_TOTAL_BYTES),
    }
}

#[derive(Debug)]
pub struct DocumentMaskResult {
    pub findings: Vec<Finding>,
}

pub struct DocumentTextEntry {
    pub entry_path: String,
    pub text: String,
}

impl DocumentTextEntry {
    fn new(entry_path: impl Into<String>, text: String) -> Self {
        Self {
            entry_path: entry_path.into(),
            text,
        }
    }
}

impl Drop for DocumentTextEntry {
    fn drop(&mut self) {
        self.text.zeroize();
    }
}

pub fn mask_docx(input: &Path, output: &Path, policy: &Policy) -> Result<DocumentMaskResult> {
    mask_ooxml(input, output, policy, OoxmlFormat::docx())
}

pub fn mask_xlsx(input: &Path, output: &Path, policy: &Policy) -> Result<DocumentMaskResult> {
    mask_ooxml(input, output, policy, OoxmlFormat::xlsx())
}

pub fn mask_pptx(input: &Path, output: &Path, policy: &Policy) -> Result<DocumentMaskResult> {
    mask_ooxml(input, output, policy, OoxmlFormat::pptx())
}

struct OoxmlFormat {
    label: &'static str,
    required_entry: &'static str,
    should_mask_entry: fn(&str) -> bool,
    text_group: TextGroupKind,
}

impl OoxmlFormat {
    fn docx() -> Self {
        Self {
            label: ".docx",
            required_entry: "word/document.xml",
            should_mask_entry: is_docx_mask_target,
            text_group: TextGroupKind::Docx,
        }
    }

    fn xlsx() -> Self {
        Self {
            label: ".xlsx",
            required_entry: "xl/workbook.xml",
            should_mask_entry: is_xlsx_mask_target,
            text_group: TextGroupKind::Xlsx,
        }
    }

    fn pptx() -> Self {
        Self {
            label: ".pptx",
            required_entry: "ppt/presentation.xml",
            should_mask_entry: is_pptx_mask_target,
            text_group: TextGroupKind::Pptx,
        }
    }

    fn from_path(path: &str) -> Option<Self> {
        let ext = Path::new(path).extension()?.to_str()?;
        if ext.eq_ignore_ascii_case("docx") {
            Some(Self::docx())
        } else if ext.eq_ignore_ascii_case("xlsx") {
            Some(Self::xlsx())
        } else if ext.eq_ignore_ascii_case("pptx") {
            Some(Self::pptx())
        } else {
            None
        }
    }
}

#[derive(Clone, Copy)]
enum TextGroupKind {
    Docx,
    Xlsx,
    Pptx,
}

fn mask_ooxml(
    input: &Path,
    output: &Path,
    policy: &Policy,
    format: OoxmlFormat,
) -> Result<DocumentMaskResult> {
    if paths_refer_to_same_target(input, output)? {
        bail!("--output must not be the same as input for Office document masking");
    }

    let input_file =
        File::open(input).with_context(|| format!("open input document {}", input.display()))?;
    let mut archive = ZipArchive::new(input_file)
        .with_context(|| format!("read {} zip container", format.label))?;
    if archive.by_name(format.required_entry).is_err() {
        bail!(
            "unsupported {}: missing {}",
            format.label,
            format.required_entry
        );
    }

    ensure_archive_entry_limit(archive.len())?;
    let limits = ooxml_read_limits(policy.scan.max_file_size_bytes);

    let output_parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let output_file = NamedTempFile::new_in(output_parent)
        .with_context(|| format!("create temporary output in {}", output_parent.display()))?;
    if let Ok(metadata) = std::fs::metadata(output) {
        std::fs::set_permissions(output_file.path(), metadata.permissions())
            .with_context(|| format!("preserve output permissions for {}", output.display()))?;
    }
    let mut writer = ZipWriter::new(output_file);
    let mut findings = Vec::new();
    let mut declared_total = 0u64;
    let mut actual_total = 0u64;

    for idx in 0..archive.len() {
        let mut entry = archive
            .by_index(idx)
            .with_context(|| format!("read zip entry {idx}"))?;
        let name = entry.name().to_string();
        let options = entry_options(&entry);

        declared_total = declared_total
            .checked_add(entry.size())
            .context("Office document expanded size overflow")?;
        if declared_total > limits.total_bytes {
            bail!(
                "Office document expanded size exceeds limit ({} bytes)",
                limits.total_bytes
            );
        }

        if entry.is_dir() {
            writer
                .add_directory(&name, options)
                .with_context(|| format!("write directory entry {name}"))?;
            continue;
        }

        writer
            .start_file(&name, options)
            .with_context(|| format!("write zip entry {name}"))?;

        if (format.should_mask_entry)(&name) {
            let remaining = limits.total_bytes.saturating_sub(actual_total);
            let mut bytes =
                read_entry_bounded(&mut entry, limits.entry_bytes.min(remaining), &name)?;
            actual_total = actual_total
                .checked_add(bytes.len() as u64)
                .context("Office document expanded size overflow")?;
            let rel_label = format!("{}:{name}", input.display());
            let mask_result = mask_xml_text(&bytes, policy, &rel_label, format.text_group)
                .with_context(|| format!("mask XML entry {name}"));
            bytes.zeroize();
            let (mut masked_xml, mut entry_findings) = mask_result?;
            let write_result = writer
                .write_all(&masked_xml)
                .with_context(|| format!("write masked XML entry {name}"));
            masked_xml.zeroize();
            write_result?;
            findings.append(&mut entry_findings);
        } else {
            copy_entry_bounded(
                &mut entry,
                &mut writer,
                &mut actual_total,
                limits.total_bytes,
                &name,
            )?;
        }
    }

    let output_file = writer
        .finish()
        .with_context(|| format!("finish output {} zip container", format.label))?;
    output_file
        .as_file()
        .sync_all()
        .with_context(|| format!("sync output document {}", output.display()))?;
    persist_named_temp_file(output_file, output)?;

    Ok(DocumentMaskResult { findings })
}

pub fn extract_ooxml_text_entries(
    scan_rel: &str,
    bytes: &[u8],
    max_file_size_bytes: u64,
) -> Result<Option<Vec<DocumentTextEntry>>> {
    let Some(format) = OoxmlFormat::from_path(scan_rel) else {
        return Ok(None);
    };

    let mut archive = ZipArchive::new(Cursor::new(bytes))
        .with_context(|| format!("read {} zip container", format.label))?;
    if archive.by_name(format.required_entry).is_err() {
        bail!(
            "unsupported {}: missing {}",
            format.label,
            format.required_entry
        );
    }

    ensure_archive_entry_limit(archive.len())?;
    let limits = ooxml_read_limits(max_file_size_bytes);

    let mut entries = Vec::new();
    let mut actual_total = 0u64;
    for idx in 0..archive.len() {
        let mut entry = archive
            .by_index(idx)
            .with_context(|| format!("read zip entry {idx}"))?;
        let name = entry.name().to_string();
        if entry.is_dir() || !(format.should_mask_entry)(&name) {
            continue;
        }

        let remaining = limits.total_bytes.saturating_sub(actual_total);
        let mut entry_bytes =
            read_entry_bounded(&mut entry, limits.entry_bytes.min(remaining), &name)?;
        actual_total = actual_total
            .checked_add(entry_bytes.len() as u64)
            .context("Office document expanded size overflow")?;
        let text_result = extract_xml_text(&entry_bytes, format.text_group)
            .with_context(|| format!("extract XML text from {name}"));
        entry_bytes.zeroize();
        let mut text = text_result?;
        if text.is_empty() {
            continue;
        }
        entries.push(DocumentTextEntry::new(name, std::mem::take(&mut text)));
    }

    Ok(Some(entries))
}

pub fn extract_document_text_entries(
    scan_rel: &str,
    bytes: &[u8],
    max_file_size_bytes: u64,
) -> Result<Option<Vec<DocumentTextEntry>>> {
    if let Some(entries) = extract_ooxml_text_entries(scan_rel, bytes, max_file_size_bytes)? {
        return Ok(Some(entries));
    }
    if is_pdf_path(scan_rel) {
        return extract_pdf_text_entry(bytes).map(Some);
    }
    Ok(None)
}

fn ensure_archive_entry_limit(entries: usize) -> Result<()> {
    if entries > MAX_OOXML_ENTRIES {
        bail!("Office document contains too many zip entries ({entries})");
    }
    Ok(())
}

fn read_entry_bounded(reader: &mut impl Read, limit: u64, name: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("read zip entry {name}"))?;
    if bytes.len() as u64 > limit {
        bytes.zeroize();
        bail!("Office zip entry {name} exceeds expanded size limit ({limit} bytes)");
    }
    Ok(bytes)
}

fn copy_entry_bounded<W: Write>(
    reader: &mut impl Read,
    writer: &mut W,
    actual_total: &mut u64,
    total_limit: u64,
    name: &str,
) -> Result<()> {
    let remaining = total_limit.saturating_sub(*actual_total);
    let copied = std::io::copy(&mut reader.take(remaining.saturating_add(1)), writer)
        .with_context(|| format!("copy zip entry {name}"))?;
    if copied > remaining {
        bail!("Office document expanded size exceeds limit ({total_limit} bytes)");
    }
    *actual_total = actual_total
        .checked_add(copied)
        .context("Office document expanded size overflow")?;
    Ok(())
}

fn is_pdf_path(path: &str) -> bool {
    Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("pdf"))
}

fn extract_pdf_text_entry(bytes: &[u8]) -> Result<Vec<DocumentTextEntry>> {
    // pdf-extract is known to panic on malformed PDFs; catch the unwind so a
    // single corrupt file degrades to a skipped finding instead of aborting
    // the whole (rayon-parallel) scan.
    let extracted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        pdf_extract::extract_text_from_mem(bytes)
    }))
    .map_err(|_| anyhow::anyhow!("PDF text extraction panicked (corrupt or unsupported PDF)"))?;
    let mut text = extracted.context("extract PDF text")?;
    if text.trim().is_empty() {
        text.zeroize();
        return Ok(Vec::new());
    }
    Ok(vec![DocumentTextEntry::new("", text)])
}

fn is_docx_mask_target(name: &str) -> bool {
    name == "word/document.xml"
}

fn is_xlsx_mask_target(name: &str) -> bool {
    name == "xl/sharedStrings.xml"
        || (name.starts_with("xl/worksheets/sheet") && name.ends_with(".xml"))
}

fn is_pptx_mask_target(name: &str) -> bool {
    (name.starts_with("ppt/slides/slide") && name.ends_with(".xml"))
        || (name.starts_with("ppt/notesSlides/notesSlide") && name.ends_with(".xml"))
        || (name.starts_with("ppt/comments/comment") && name.ends_with(".xml"))
}

fn paths_refer_to_same_target(input: &Path, output: &Path) -> Result<bool> {
    let input_abs = input
        .canonicalize()
        .with_context(|| format!("resolve input document {}", input.display()))?;

    let output_abs = if output.exists() {
        output
            .canonicalize()
            .with_context(|| format!("resolve output document {}", output.display()))?
    } else {
        let parent = output
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent_abs = parent
            .canonicalize()
            .with_context(|| format!("resolve output directory {}", parent.display()))?;
        let Some(file_name) = output.file_name() else {
            return Ok(false);
        };
        parent_abs.join(file_name)
    };

    Ok(input_abs == output_abs)
}

fn entry_options<R: Read>(entry: &zip::read::ZipFile<'_, R>) -> FileOptions<'static, ()> {
    let mut options = FileOptions::default().compression_method(entry.compression());
    if let Some(mod_time) = entry.last_modified() {
        options = options.last_modified_time(mod_time);
    }
    if let Some(mode) = entry.unix_mode() {
        options = options.unix_permissions(mode);
    }
    options
}

enum XmlItem {
    Event(Event<'static>),
    Text {
        is_cdata: bool,
        original: String,
        replacement: Option<String>,
    },
}

struct XmlMaskContext<'a> {
    policy: &'a Policy,
    rel_label: &'a str,
    findings: &'a mut Vec<Finding>,
}

fn decode_xml_text(text: &BytesText<'_>) -> Result<String> {
    let decoded = text.decode().context("decode XML text")?;
    Ok(unescape(decoded.as_ref())
        .context("unescape XML text")?
        .into_owned())
}

fn mask_xml_text(
    xml: &[u8],
    policy: &Policy,
    rel_label: &str,
    text_group: TextGroupKind,
) -> Result<(Vec<u8>, Vec<Finding>)> {
    let mut reader = Reader::from_reader(Cursor::new(xml));
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();
    let mut items = Vec::new();
    let mut findings = Vec::new();
    let mut group_depth: Option<usize> = None;
    let mut group_text_items = Vec::new();

    {
        let mut mask_context = XmlMaskContext {
            policy,
            rel_label,
            findings: &mut findings,
        };

        loop {
            match reader.read_event_into(&mut buf).context("read XML event")? {
                Event::Eof => break,
                Event::Start(start) => {
                    if let Some(depth) = group_depth.as_mut() {
                        *depth += 1;
                    } else if starts_text_group(start.name().as_ref(), text_group) {
                        group_depth = Some(1);
                        group_text_items.clear();
                    }
                    items.push(XmlItem::Event(Event::Start(start.into_owned())));
                }
                Event::End(end) => {
                    if let Some(depth) = group_depth {
                        if depth == 1 {
                            mask_text_items(&mut items, &group_text_items, &mut mask_context)?;
                            group_depth = None;
                            group_text_items.clear();
                        } else {
                            group_depth = Some(depth - 1);
                        }
                    }
                    items.push(XmlItem::Event(Event::End(end.into_owned())));
                }
                Event::Text(text) => {
                    let decoded = decode_xml_text(&text)?;
                    push_text_item(
                        &mut items,
                        decoded,
                        false,
                        group_depth,
                        &mut group_text_items,
                        &mut mask_context,
                    )?;
                }
                Event::CData(cdata) => {
                    let decoded = String::from_utf8_lossy(cdata.as_ref()).to_string();
                    push_text_item(
                        &mut items,
                        decoded,
                        true,
                        group_depth,
                        &mut group_text_items,
                        &mut mask_context,
                    )?;
                }
                event => items.push(XmlItem::Event(event.into_owned())),
            }
            buf.clear();
        }

        if !group_text_items.is_empty() {
            mask_text_items(&mut items, &group_text_items, &mut mask_context)?;
        }
    }

    let mut writer = Writer::new(Vec::with_capacity(xml.len()));
    for item in items {
        match item {
            XmlItem::Event(event) => writer.write_event(event).context("write XML event")?,
            XmlItem::Text {
                is_cdata,
                original,
                replacement,
            } => {
                let text = replacement.as_deref().unwrap_or(&original);
                if is_cdata {
                    writer
                        .write_event(Event::CData(BytesCData::new(text)))
                        .context("write masked XML CDATA")?;
                } else {
                    writer
                        .write_event(Event::Text(BytesText::new(text)))
                        .context("write masked XML text")?;
                }
            }
        }
    }

    Ok((writer.into_inner(), findings))
}

fn extract_xml_text(xml: &[u8], text_group: TextGroupKind) -> Result<String> {
    let mut reader = Reader::from_reader(Cursor::new(xml));
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();
    let mut out = String::new();
    let mut group_depth: Option<usize> = None;
    let mut group_text = String::new();

    loop {
        match reader.read_event_into(&mut buf).context("read XML event")? {
            Event::Eof => break,
            Event::Start(start) => {
                if let Some(depth) = group_depth.as_mut() {
                    *depth += 1;
                } else if starts_text_group(start.name().as_ref(), text_group) {
                    group_depth = Some(1);
                    group_text.clear();
                }
            }
            Event::End(_) => {
                if let Some(depth) = group_depth {
                    if depth == 1 {
                        out.push_str(&group_text);
                        out.push('\n');
                        group_depth = None;
                        group_text.zeroize();
                    } else {
                        group_depth = Some(depth - 1);
                    }
                }
            }
            Event::Text(text) => {
                let mut decoded = decode_xml_text(&text)?;
                if group_depth.is_some() {
                    group_text.push_str(&decoded);
                } else {
                    out.push_str(&decoded);
                    out.push('\n');
                }
                decoded.zeroize();
            }
            Event::CData(cdata) => {
                let mut decoded = String::from_utf8_lossy(cdata.as_ref()).to_string();
                if group_depth.is_some() {
                    group_text.push_str(&decoded);
                } else {
                    out.push_str(&decoded);
                    out.push('\n');
                }
                decoded.zeroize();
            }
            _ => {}
        }
        buf.clear();
    }

    if !group_text.is_empty() {
        out.push_str(&group_text);
        out.push('\n');
        group_text.zeroize();
    }
    Ok(out)
}

fn push_text_item(
    items: &mut Vec<XmlItem>,
    original: String,
    is_cdata: bool,
    group_depth: Option<usize>,
    group_text_items: &mut Vec<usize>,
    context: &mut XmlMaskContext<'_>,
) -> Result<()> {
    let idx = items.len();
    items.push(XmlItem::Text {
        is_cdata,
        original,
        replacement: None,
    });

    if group_depth.is_some() {
        group_text_items.push(idx);
    } else {
        mask_text_items(items, &[idx], context)?;
    }
    Ok(())
}

fn mask_text_items(
    items: &mut [XmlItem],
    text_item_indices: &[usize],
    context: &mut XmlMaskContext<'_>,
) -> Result<()> {
    if text_item_indices.is_empty() {
        return Ok(());
    }

    let mut combined = String::new();
    let mut original_lengths = Vec::with_capacity(text_item_indices.len());
    for idx in text_item_indices {
        let XmlItem::Text { original, .. } = &items[*idx] else {
            continue;
        };
        original_lengths.push(original.chars().count());
        combined.push_str(original);
    }

    let mask_result = masker::mask_from_policy(&combined, context.policy, context.rel_label);
    combined.zeroize();
    let (mut masked, mut text_findings) = mask_result?;
    let replacements = split_masked_text(&masked, &original_lengths);
    masked.zeroize();

    for (idx, replacement) in text_item_indices.iter().zip(replacements) {
        if let XmlItem::Text {
            original,
            replacement: target,
            ..
        } = &mut items[*idx]
        {
            original.zeroize();
            *target = Some(replacement);
        }
    }
    context.findings.append(&mut text_findings);
    Ok(())
}

fn split_masked_text(masked: &str, original_lengths: &[usize]) -> Vec<String> {
    let mut chars = masked.chars();
    let mut out = Vec::with_capacity(original_lengths.len());
    for (idx, len) in original_lengths.iter().enumerate() {
        if idx + 1 == original_lengths.len() {
            out.push(chars.by_ref().collect());
        } else {
            out.push(chars.by_ref().take(*len).collect());
        }
    }
    out
}

fn starts_text_group(name: &[u8], kind: TextGroupKind) -> bool {
    let local = local_name(name);
    match kind {
        TextGroupKind::Docx => local == b"p",
        TextGroupKind::Xlsx => local == b"si" || local == b"is",
        TextGroupKind::Pptx => local == b"p",
    }
}

fn local_name(name: &[u8]) -> &[u8] {
    name.iter()
        .position(|b| *b == b':')
        .map(|idx| &name[idx + 1..])
        .unwrap_or(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;
    use zip::ZipArchive;

    fn synthetic_openai_key(seed: char) -> String {
        format!("sk-proj-{seed}bcdefghijklmnopqrstuvwxyz0123456789")
    }

    #[test]
    fn masks_docx_document_xml_to_output_file() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("report.docx");
        let output = dir.path().join("report.redacted.docx");
        let secret = synthetic_openai_key('a');
        create_minimal_docx(&input, &format!("hello {secret}")).unwrap();

        let policy = Policy::default();
        let result = mask_docx(&input, &output, &policy).unwrap();

        assert!(!result.findings.is_empty());
        let body = read_docx_document_xml(&output).unwrap();
        assert!(body.contains("[REDACTED]"), "{body}");
        assert!(!body.contains(&secret), "{body}");

        let original = read_docx_document_xml(&input).unwrap();
        assert!(original.contains(&secret), "{original}");
    }

    #[test]
    fn masks_docx_secret_split_across_text_nodes() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("report.docx");
        let output = dir.path().join("report.redacted.docx");
        let secret = synthetic_openai_key('a');
        let (left, right) = secret.split_at(9);
        create_minimal_docx(&input, &format!("{left}</w:t></w:r><w:r><w:t>{right}")).unwrap();

        let policy = Policy::default();
        let result = mask_docx(&input, &output, &policy).unwrap();

        assert!(!result.findings.is_empty());
        let body = read_docx_document_xml(&output).unwrap();
        let text = xml_text_content(&body).unwrap();
        assert!(text.contains("[REDACTED]"), "{text}");
        assert!(!text.contains(&secret), "{text}");
    }

    #[test]
    fn rejects_same_input_and_output_before_writing() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("report.docx");
        let secret = synthetic_openai_key('a');
        create_minimal_docx(&input, &secret).unwrap();

        let policy = Policy::default();
        let err = mask_docx(&input, &dir.path().join("./report.docx"), &policy).unwrap_err();

        assert!(
            err.to_string()
                .contains("--output must not be the same as input"),
            "{err:?}"
        );
        let original = read_docx_document_xml(&input).unwrap();
        assert!(original.contains(&secret), "{original}");
    }

    #[test]
    fn masks_xlsx_shared_strings_and_inline_strings() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("workbook.xlsx");
        let output = dir.path().join("workbook.redacted.xlsx");
        let shared_secret = synthetic_openai_key('a');
        let inline_secret = synthetic_openai_key('b');
        create_minimal_xlsx(&input, &shared_secret, &inline_secret).unwrap();

        let policy = Policy::default();
        let result = mask_xlsx(&input, &output, &policy).unwrap();

        assert!(result.findings.len() >= 2, "{:?}", result.findings);
        let shared = read_zip_entry(&output, "xl/sharedStrings.xml").unwrap();
        let sheet = read_zip_entry(&output, "xl/worksheets/sheet1.xml").unwrap();
        assert!(shared.contains("[REDACTED]"), "{shared}");
        assert!(sheet.contains("[REDACTED]"), "{sheet}");
        assert!(!shared.contains(&shared_secret), "{shared}");
        assert!(!sheet.contains(&inline_secret), "{sheet}");
    }

    #[test]
    fn masks_xlsx_secret_split_across_rich_text_nodes() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("workbook.xlsx");
        let output = dir.path().join("workbook.redacted.xlsx");
        let shared_secret = synthetic_openai_key('a');
        let inline_secret = synthetic_openai_key('b');
        let (shared_left, shared_right) = shared_secret.split_at(9);
        let (inline_left, inline_right) = inline_secret.split_at(9);
        create_minimal_xlsx(
            &input,
            &format!("{shared_left}</t><r><t>{shared_right}</t></r><t>"),
            &format!("{inline_left}</t><r><t>{inline_right}</t></r><t>"),
        )
        .unwrap();

        let policy = Policy::default();
        let result = mask_xlsx(&input, &output, &policy).unwrap();

        assert!(result.findings.len() >= 2, "{:?}", result.findings);
        let shared =
            xml_text_content(&read_zip_entry(&output, "xl/sharedStrings.xml").unwrap()).unwrap();
        let sheet = xml_text_content(&read_zip_entry(&output, "xl/worksheets/sheet1.xml").unwrap())
            .unwrap();
        assert!(shared.contains("[REDACTED]"), "{shared}");
        assert!(sheet.contains("[REDACTED]"), "{sheet}");
        assert!(!shared.contains(&shared_secret), "{shared}");
        assert!(!sheet.contains(&inline_secret), "{sheet}");
    }

    #[test]
    fn masks_pptx_slide_text() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("slides.pptx");
        let output = dir.path().join("slides.redacted.pptx");
        let secret = synthetic_openai_key('a');
        create_minimal_pptx(&input, &secret).unwrap();

        let policy = Policy::default();
        let result = mask_pptx(&input, &output, &policy).unwrap();

        assert!(!result.findings.is_empty());
        let slide = read_zip_entry(&output, "ppt/slides/slide1.xml").unwrap();
        assert!(slide.contains("[REDACTED]"), "{slide}");
        assert!(!slide.contains(&secret), "{slide}");
    }

    #[test]
    fn masks_pptx_secret_split_across_text_nodes() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("slides.pptx");
        let output = dir.path().join("slides.redacted.pptx");
        let secret = synthetic_openai_key('a');
        let (left, right) = secret.split_at(9);
        create_minimal_pptx(&input, &format!("{left}</a:t></a:r><a:r><a:t>{right}")).unwrap();

        let policy = Policy::default();
        let result = mask_pptx(&input, &output, &policy).unwrap();

        assert!(!result.findings.is_empty());
        let slide = read_zip_entry(&output, "ppt/slides/slide1.xml").unwrap();
        let text = xml_text_content(&slide).unwrap();
        assert!(text.contains("[REDACTED]"), "{text}");
        assert!(!text.contains(&secret), "{text}");
    }

    fn deflated_zip_options() -> FileOptions<'static, ()> {
        FileOptions::default().compression_method(zip::CompressionMethod::Deflated)
    }

    fn create_minimal_docx(path: &Path, text: &str) -> Result<()> {
        let file = File::create(path)?;
        let mut zip = ZipWriter::new(file);

        zip.start_file("[Content_Types].xml", deflated_zip_options())?;
        zip.write_all(
            br#"<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#,
        )?;

        zip.start_file("word/document.xml", deflated_zip_options())?;
        write!(
            zip,
            r#"<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>"#
        )?;
        zip.finish()?;
        Ok(())
    }

    fn create_minimal_xlsx(path: &Path, shared_text: &str, inline_text: &str) -> Result<()> {
        let file = File::create(path)?;
        let mut zip = ZipWriter::new(file);

        zip.start_file("[Content_Types].xml", deflated_zip_options())?;
        zip.write_all(br#"<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>"#)?;

        zip.start_file("xl/workbook.xml", deflated_zip_options())?;
        zip.write_all(br#"<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/></sheets></workbook>"#)?;

        zip.start_file("xl/sharedStrings.xml", deflated_zip_options())?;
        write!(
            zip,
            r#"<?xml version="1.0" encoding="UTF-8"?><sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><si><t>{shared_text}</t></si></sst>"#
        )?;

        zip.start_file("xl/worksheets/sheet1.xml", deflated_zip_options())?;
        write!(
            zip,
            r#"<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>{inline_text}</t></is></c></row></sheetData></worksheet>"#
        )?;
        zip.finish()?;
        Ok(())
    }

    fn create_minimal_pptx(path: &Path, text: &str) -> Result<()> {
        let file = File::create(path)?;
        let mut zip = ZipWriter::new(file);

        zip.start_file("[Content_Types].xml", deflated_zip_options())?;
        zip.write_all(br#"<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>"#)?;

        zip.start_file("ppt/presentation.xml", deflated_zip_options())?;
        zip.write_all(br#"<?xml version="1.0" encoding="UTF-8"?><p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:sldIdLst/></p:presentation>"#)?;

        zip.start_file("ppt/slides/slide1.xml", deflated_zip_options())?;
        write!(
            zip,
            r#"<?xml version="1.0" encoding="UTF-8"?><p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>{text}</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>"#
        )?;
        zip.finish()?;
        Ok(())
    }

    fn read_docx_document_xml(path: &Path) -> Result<String> {
        read_zip_entry(path, "word/document.xml")
    }

    fn read_zip_entry(path: &Path, name: &str) -> Result<String> {
        let file = File::open(path)?;
        let mut zip = ZipArchive::new(file)?;
        let mut entry = zip.by_name(name)?;
        let mut body = String::new();
        entry.read_to_string(&mut body)?;
        Ok(body)
    }

    fn xml_text_content(xml: &str) -> Result<String> {
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(false);
        let mut buf = Vec::new();
        let mut out = String::new();

        loop {
            match reader.read_event_into(&mut buf)? {
                Event::Eof => break,
                Event::Text(text) => out.push_str(&decode_xml_text(&text)?),
                Event::CData(cdata) => out.push_str(&String::from_utf8_lossy(cdata.as_ref())),
                _ => {}
            }
            buf.clear();
        }

        Ok(out)
    }

    #[test]
    fn rejects_invalid_zip_archive() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("broken.docx");
        std::fs::write(&input, b"not-a-zip").unwrap();
        let output = dir.path().join("out.docx");
        let policy = Policy::default();
        let err = mask_docx(&input, &output, &policy).unwrap_err();
        assert!(
            err.to_string().contains("zip") || err.to_string().contains("archive"),
            "{err}"
        );
    }

    #[test]
    fn rejects_docx_missing_required_entry() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("empty.docx");
        let output = dir.path().join("out.docx");
        {
            let file = File::create(&input).unwrap();
            let mut zip = ZipWriter::new(file);
            zip.start_file("[Content_Types].xml", deflated_zip_options())
                .unwrap();
            zip.write_all(b"<Types/>").unwrap();
            zip.finish().unwrap();
        }
        let policy = Policy::default();
        let err = mask_docx(&input, &output, &policy).unwrap_err();
        assert!(err.to_string().contains("word/document.xml"), "{err}");
    }

    #[test]
    fn bounded_entry_read_rejects_expansion_past_limit() {
        let mut input = Cursor::new(b"12345");

        let err = read_entry_bounded(&mut input, 4, "word/document.xml").unwrap_err();

        assert!(err.to_string().contains("expanded size limit"), "{err}");
    }

    #[test]
    fn failed_mask_preserves_existing_output() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("invalid.docx");
        let output = dir.path().join("existing.docx");
        {
            let file = File::create(&input).unwrap();
            let mut zip = ZipWriter::new(file);
            zip.start_file("word/document.xml", deflated_zip_options())
                .unwrap();
            zip.write_all(b"<w:document><w:t>\xff</w:t></w:document>")
                .unwrap();
            zip.finish().unwrap();
        }
        std::fs::write(&output, b"existing-output").unwrap();

        let err = mask_docx(&input, &output, &Policy::default()).unwrap_err();

        assert!(err.to_string().contains("mask XML entry"), "{err}");
        assert_eq!(std::fs::read(&output).unwrap(), b"existing-output");
    }
}
