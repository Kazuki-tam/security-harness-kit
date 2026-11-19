use crate::args::{AiTool, PseudonymizeFormatArg, PseudonymizeModeArg, RedactionMode, SeverityArg};
use crate::exit::CliExit;
use crate::hook_output;
use crate::safety;
use anyhow::{Context, Result, bail};
use shk_core::finding::Finding;
use shk_core::masker::MaskJsonOutput;
use shk_core::policy::Policy;
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

#[derive(Clone, Debug)]
pub struct MaskInvocation {
    pub project_root: PathBuf,
    pub file: Option<PathBuf>,
    pub json: bool,
    pub output: Option<PathBuf>,
    pub redaction: Option<RedactionMode>,
    pub min_severity: Option<SeverityArg>,
    pub hook_mode: Option<AiTool>,
    pub post: bool,
    pub pseudonymize: bool,
    pub yes: bool,
    pub dry_run: bool,
    pub columns: Option<String>,
    pub no_header: bool,
    pub no_create_key: bool,
    pub mode: Option<PseudonymizeModeArg>,
    pub format: Option<PseudonymizeFormatArg>,
    pub sheet: Option<String>,
    pub map: Option<PathBuf>,
    pub check_remaining: bool,
}

pub fn run(inv: MaskInvocation) -> Result<()> {
    if inv.pseudonymize {
        return run_pseudonymize(inv);
    }
    if inv.yes
        || inv.dry_run
        || inv.columns.is_some()
        || inv.no_header
        || inv.no_create_key
        || inv.mode.is_some()
        || inv.format.is_some()
        || inv.sheet.is_some()
        || inv.map.is_some()
        || inv.check_remaining
    {
        return Err(CliExit::message(
            2,
            "`--yes`, `--dry-run`, `--columns`, `--no-header`, `--no-create-key`, `--mode`, `--format`, `--sheet`, `--map`, and `--check-remaining` require `--pseudonymize`",
        )
        .into());
    }
    if let Some(tool) = inv.hook_mode {
        if inv.file.is_some() || inv.output.is_some() || inv.json {
            bail!("`mask --hook-mode` cannot be combined with FILE, `--output`, or `--json`");
        }
        return run_hook_mode(
            &inv.project_root,
            tool,
            inv.post,
            inv.redaction,
            inv.min_severity,
        );
    }
    if inv.post {
        bail!("`mask --post` requires `--hook-mode <tool>`");
    }
    if let Some(outp) = inv.output.as_ref() {
        safety::require_project_policy(&inv.project_root, "mask --output")?;
        safety::ensure_writable_path_allowed(outp)?;
    }

    let (mut policy, _) = Policy::load_from_dir(&inv.project_root)?;
    apply_redaction_override(&mut policy, inv.redaction);
    apply_min_severity_override(&mut policy, inv.min_severity);

    if let Some((input, format)) = inv
        .file
        .as_ref()
        .and_then(|p| office_format(p).map(|format| (p, format)))
    {
        let outp = inv
            .output
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Office document masking requires --output"))?;
        let result = match format {
            OfficeFormat::Docx => shk_core::document_masker::mask_docx(input, outp, &policy)?,
            OfficeFormat::Xlsx => shk_core::document_masker::mask_xlsx(input, outp, &policy)?,
            OfficeFormat::Pptx => shk_core::document_masker::mask_pptx(input, outp, &policy)?,
        };
        if inv.json {
            let out = MaskJsonOutput {
                masked_content: "[DOCUMENT_WRITTEN]".into(),
                findings: result.findings,
            };
            println!("{}", serde_json::to_string_pretty(&out)?);
        } else {
            println!("Wrote masked document to {}", outp.display());
        }
        return Ok(());
    }

    let (rel_label, mut bytes) = read_mask_input(inv.file.as_ref())?;

    if is_binary_or_non_utf8(&bytes, policy.scan.binary_detection_bytes) {
        // Nothing is passed through unmasked: text that is not UTF-8 still
        // carries ASCII secrets, and one NUL byte must not switch masking off.
        let masked = mask_non_utf8(&bytes, &policy, &rel_label);
        bytes.zeroize();
        let (mut masked, mut findings) = masked?;
        findings.insert(0, non_utf8_input_finding(&rel_label));
        let result: Result<()> = if inv.json {
            let out = MaskJsonOutput {
                masked_content: String::from_utf8_lossy(&masked).into_owned(),
                findings,
            };
            serde_json::to_string_pretty(&out)
                .map(|json| println!("{json}"))
                .map_err(Into::into)
        } else {
            eprintln!(
                "shk mask: warning: input is not UTF-8 text; it was masked byte by byte, and text \
                 in other encodings is only recognised where it is ASCII"
            );
            io::stdout().write_all(&masked).map_err(Into::into)
        };
        let output_result: Result<()> = match inv.output {
            Some(outp) => crate::fs_atomic::write_atomic(&outp, &masked),
            None => Ok(()),
        };
        masked.zeroize();
        result?;
        output_result?;
        return Ok(());
    }

    let mut buf = String::from_utf8(std::mem::take(&mut bytes)).expect("checked above");
    let mask_result = shk_core::masker::mask_from_policy(&buf, &policy, &rel_label);
    buf.zeroize();
    let (masked, findings) = mask_result?;
    if inv.json {
        let out = MaskJsonOutput {
            masked_content: masked.clone(),
            findings,
        };
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        print!("{masked}");
    }
    if let Some(outp) = inv.output {
        crate::fs_atomic::write_atomic(&outp, masked.as_bytes())?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum OfficeFormat {
    Docx,
    Xlsx,
    Pptx,
}

fn office_format(path: &Path) -> Option<OfficeFormat> {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some(ext) if ext.eq_ignore_ascii_case("docx") => Some(OfficeFormat::Docx),
        Some(ext) if ext.eq_ignore_ascii_case("xlsx") => Some(OfficeFormat::Xlsx),
        Some(ext) if ext.eq_ignore_ascii_case("pptx") => Some(OfficeFormat::Pptx),
        _ => None,
    }
}

pub(crate) fn apply_redaction_override(policy: &mut Policy, redaction: Option<RedactionMode>) {
    if let Some(mode) = redaction {
        policy.mask.redaction = match mode {
            RedactionMode::Full => "full",
            RedactionMode::Match => "match",
            RedactionMode::Partial => "partial",
        }
        .into();
    }
}

fn run_pseudonymize(inv: MaskInvocation) -> Result<()> {
    if inv.hook_mode.is_some() {
        return Err(
            CliExit::message(2, "`--pseudonymize` cannot be combined with `--hook-mode`").into(),
        );
    }
    if inv.redaction.is_some() {
        return Err(
            CliExit::message(2, "`--pseudonymize` cannot be combined with `--redaction`").into(),
        );
    }
    if inv.min_severity.is_some() {
        return Err(CliExit::message(
            2,
            "`--pseudonymize` cannot be combined with `--min-severity`",
        )
        .into());
    }
    if inv.post {
        return Err(
            CliExit::message(2, "`--pseudonymize` cannot be combined with `--post`").into(),
        );
    }
    super::pseudonymize::mask(super::pseudonymize::MaskPseudonymizeArgs {
        project_root: inv.project_root,
        file: inv.file,
        json: inv.json,
        output: inv.output,
        yes: inv.yes,
        dry_run: inv.dry_run,
        columns: inv.columns,
        no_header: inv.no_header,
        no_create_key: inv.no_create_key,
        mode: inv.mode,
        format: inv.format,
        sheet: inv.sheet,
        map: inv.map,
        check_remaining: inv.check_remaining,
    })
}

pub(crate) fn apply_min_severity_override(policy: &mut Policy, min_severity: Option<SeverityArg>) {
    if let Some(severity) = min_severity {
        policy.mask.min_severity = severity.as_str().into();
    }
}

fn read_mask_input(file: Option<&PathBuf>) -> Result<(String, Vec<u8>)> {
    let mut bytes = Vec::new();
    let rel_label = if let Some(f) = file {
        let mut r = fs::File::open(f)?;
        r.read_to_end(&mut bytes)?;
        f.to_string_lossy().to_string()
    } else {
        let mut stdin = io::stdin();
        if stdin.is_terminal() {
            bail!(
                "`shk mask` requires FILE or stdin input; try `shk mask prompt.txt` or `shk mask < prompt.txt`"
            );
        }
        stdin.read_to_end(&mut bytes)?;
        "<stdin>".into()
    };
    Ok((rel_label, bytes))
}

fn run_hook_mode(
    cwd: &Path,
    tool: AiTool,
    post: bool,
    redaction: Option<RedactionMode>,
    min_severity: Option<SeverityArg>,
) -> Result<()> {
    let mut stdin_raw = Vec::new();
    let mut stdin = io::stdin();
    if stdin.is_terminal() {
        bail!("`mask --hook-mode` requires hook JSON payload on stdin");
    }
    stdin.read_to_end(&mut stdin_raw)?;
    let mut stdin_str = String::from_utf8_lossy(&stdin_raw).to_string();
    stdin_raw.zeroize();
    let stdin_trim = stdin_str.trim();
    if stdin_trim.is_empty() {
        stdin_str.zeroize();
        bail!("mask hook-mode requires hook JSON payload on stdin");
    }

    let repo_root = resolve_repo_root(cwd);
    let hook_body_result = shk_integrations::hook_body_from_stdin(
        tool.integration_tool(),
        post,
        stdin_trim,
        cwd,
        &repo_root,
    );
    stdin_str.zeroize();
    let mut segments = hook_body_result?.segments;
    let (mut policy, _) = Policy::load_from_dir(&repo_root)?;
    apply_redaction_override(&mut policy, redaction);
    apply_min_severity_override(&mut policy, min_severity);
    // Each segment is masked under its own path, like `scan --hook-mode`, so
    // path-dependent rules (e.g. env files) only apply to that file's text.
    let mask_results: Vec<_> = segments
        .iter()
        .map(|segment| {
            let path = if segment.file {
                crate::commands::scan::hook_policy_path(&repo_root, &segment.label)
            } else {
                segment.label.clone()
            };
            shk_core::masker::mask_from_policy(&segment.text, &policy, &path)
        })
        .collect();
    segments
        .iter_mut()
        .for_each(|segment| segment.text.zeroize());
    let mut masked_parts = Vec::with_capacity(mask_results.len());
    let mut findings = Vec::new();
    for result in mask_results {
        let (masked, found) = result.context("hook mask failed")?;
        masked_parts.push(masked);
        findings.extend(found);
    }
    let mut masked = masked_parts.join("\n---\n");
    masked_parts.iter_mut().for_each(Zeroize::zeroize);

    println!(
        "{}",
        hook_output::mask_stdout(
            tool,
            post,
            findings.len(),
            (!findings.is_empty()).then_some(masked.as_str()),
        )
    );
    masked.zeroize();
    Ok(())
}

fn resolve_repo_root(cwd: &Path) -> PathBuf {
    shk_core::git::discover_repo_root(cwd)
        .and_then(|p| std::fs::canonicalize(&p).ok().or(Some(p)))
        .unwrap_or_else(|| std::fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf()))
}

fn is_binary_or_non_utf8(bytes: &[u8], binary_detection_bytes: usize) -> bool {
    let take = binary_detection_bytes.min(bytes.len());
    bytes[..take].contains(&0) || std::str::from_utf8(bytes).is_err()
}

/// Masks input that is not UTF-8 text and returns it in its own encoding.
/// Input with nothing to mask comes back byte for byte.
///
/// UTF-16 with a byte order mark is decoded, masked and encoded again. Any
/// other input is masked byte by byte: ASCII bytes are read as themselves and
/// every other byte as a private-use character that no rule matches, so the
/// rules see the ASCII in the input and nothing else, and every byte outside
/// a redacted value comes back as it was, whatever the encoding (Latin-1,
/// Shift-JIS, a binary format).
fn mask_non_utf8(
    bytes: &[u8],
    policy: &Policy,
    rel_label: &str,
) -> Result<(Vec<u8>, Vec<Finding>)> {
    let utf16 = match bytes {
        // `FF FE 00 00` is the UTF-32LE mark.
        [0xff, 0xfe, 0x00, 0x00, ..] => None,
        [0xff, 0xfe, body @ ..] => Some((body, true)),
        [0xfe, 0xff, body @ ..] => Some((body, false)),
        _ => None,
    };
    let (mut text, encode): (String, Encoder) = match utf16 {
        Some((body, little_endian)) => {
            let pairs = body.chunks_exact(2);
            // An odd last byte is no code unit; it is kept as it is.
            let tail = pairs.remainder().to_vec();
            let units = pairs
                .map(|pair| {
                    let pair = [pair[0], pair[1]];
                    if little_endian {
                        u16::from_le_bytes(pair)
                    } else {
                        u16::from_be_bytes(pair)
                    }
                })
                .collect::<Vec<_>>();
            let mark = bytes[..2].to_vec();
            let encode = move |masked: &str| {
                let mut out = mark.clone();
                for unit in masked.encode_utf16() {
                    out.extend(if little_endian {
                        unit.to_le_bytes()
                    } else {
                        unit.to_be_bytes()
                    });
                }
                out.extend(&tail);
                out
            };
            (String::from_utf16_lossy(&units), Box::new(encode))
        }
        None => {
            let text = bytes.iter().map(|byte| opaque_char(*byte)).collect();
            let encode = |masked: &str| masked.chars().map(opaque_byte).collect();
            (text, Box::new(encode))
        }
    };
    let masked = shk_core::masker::mask_from_policy(&text, policy, rel_label);
    text.zeroize();
    let (mut masked, findings) = masked?;
    let out = if findings.is_empty() {
        // Decoding may not round-trip (a lone surrogate): with nothing
        // masked, nothing is rewritten.
        bytes.to_vec()
    } else {
        encode(&masked)
    };
    masked.zeroize();
    Ok((out, findings))
}

/// Turns masked text back into the encoding of the input.
type Encoder = Box<dyn Fn(&str) -> Vec<u8>>;

/// First of the 128 private-use characters that stand for the bytes
/// `0x80..=0xFF` while input is masked byte by byte.
const OPAQUE_BYTE_BASE: u32 = 0xE000;

/// The character a byte is masked as: itself for ASCII, otherwise a
/// private-use character. Those are not letters, digits, whitespace or
/// invisible formatting characters, so no rule matches one or treats it as
/// part of a word.
fn opaque_char(byte: u8) -> char {
    if byte.is_ascii() {
        char::from(byte)
    } else {
        char::from_u32(OPAQUE_BYTE_BASE + u32::from(byte)).unwrap_or(char::REPLACEMENT_CHARACTER)
    }
}

/// The byte a character of byte-wise masked text stands for. Redaction
/// markers are ASCII, so nothing else can occur.
fn opaque_byte(c: char) -> u8 {
    let code = u32::from(c);
    u8::try_from(code)
        .or_else(|_| u8::try_from(code.wrapping_sub(OPAQUE_BYTE_BASE)))
        .unwrap_or(b'?')
}

fn non_utf8_input_finding(file: &str) -> Finding {
    Finding {
        rule_id: "mask.non_utf8_input".into(),
        severity: "info".into(),
        kind: "ignore".into(),
        file: file.into(),
        line: 1,
        column: 1,
        message: "Input is not UTF-8 text: it was masked byte by byte, and text in other \
                  encodings is only recognised where it is ASCII"
            .into(),
        redacted_value: "[REDACTED]".into(),
        value_hash: None,
        confidence: 1.0,
        context_before: vec![],
        context_after: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn office_format_matches_extensions_case_insensitively() {
        assert!(matches!(
            office_format(Path::new("a.docx")),
            Some(OfficeFormat::Docx)
        ));
        assert!(matches!(
            office_format(Path::new("a.XLSX")),
            Some(OfficeFormat::Xlsx)
        ));
        assert!(matches!(
            office_format(Path::new("dir/a.PpTx")),
            Some(OfficeFormat::Pptx)
        ));
        assert!(office_format(Path::new("a.txt")).is_none());
        assert!(office_format(Path::new("docx")).is_none());
    }

    #[test]
    fn redaction_override_replaces_policy_value_only_when_set() {
        let mut policy = Policy::default();
        let original = policy.mask.redaction.clone();

        apply_redaction_override(&mut policy, None);
        assert_eq!(policy.mask.redaction, original);

        apply_redaction_override(&mut policy, Some(RedactionMode::Full));
        assert_eq!(policy.mask.redaction, "full");
        apply_redaction_override(&mut policy, Some(RedactionMode::Match));
        assert_eq!(policy.mask.redaction, "match");
        apply_redaction_override(&mut policy, Some(RedactionMode::Partial));
        assert_eq!(policy.mask.redaction, "partial");
    }

    #[test]
    fn min_severity_override_replaces_policy_value_only_when_set() {
        let mut policy = Policy::default();
        let original = policy.mask.min_severity.clone();

        apply_min_severity_override(&mut policy, None);
        assert_eq!(policy.mask.min_severity, original);

        apply_min_severity_override(&mut policy, Some(SeverityArg::High));
        assert_eq!(policy.mask.min_severity, SeverityArg::High.as_str());
    }

    #[test]
    fn binary_detection_finds_nul_within_window() {
        assert!(is_binary_or_non_utf8(b"ab\0cd", 8192));
        assert!(is_binary_or_non_utf8(&[0xff, 0xfe, b'a'], 8192));
        assert!(!is_binary_or_non_utf8("plain text\n".as_bytes(), 8192));
        assert!(!is_binary_or_non_utf8(b"", 8192));
    }

    #[test]
    fn binary_detection_ignores_nul_beyond_window() {
        // NUL is valid UTF-8, so a NUL past the detection window does not
        // flip the input to binary; it is masked as text.
        let bytes = b"abcd\0";
        assert!(!is_binary_or_non_utf8(bytes, 4));
        assert!(is_binary_or_non_utf8(bytes, 5));
    }

    #[test]
    fn non_utf8_input_is_masked_in_its_own_encoding() {
        let policy = Policy::default();
        // not real credential: synthetic detector fixture value only
        let key = concat!("sk-proj-", "abcdefghijklmnopqrstuvwxyz0123456789");
        let mask = |bytes: &[u8]| mask_non_utf8(bytes, &policy, "input").unwrap();
        let holds = |bytes: &[u8], needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);

        // Latin-1 text and a binary with a NUL: the value goes, every other
        // byte stays.
        for prefix in [&b"caf\xe9 "[..], &b"\0\x01\xff "[..]] {
            let input = [prefix, b"key=", key.as_bytes(), b" \xfctail\n"].concat();
            let (masked, findings) = mask(&input);
            assert!(!holds(&masked, key.as_bytes()));
            assert!(masked.starts_with(prefix) && masked.ends_with(b" \xfctail\n"));
            assert!(!findings.is_empty());
        }

        // UTF-16 keeps its byte order mark and encoding.
        for (bom, unit) in [
            ([0xff, 0xfe], u16::to_le_bytes as fn(u16) -> [u8; 2]),
            ([0xfe, 0xff], u16::to_be_bytes),
        ] {
            let encode = |text: &str| {
                let mut bytes = bom.to_vec();
                bytes.extend(text.encode_utf16().flat_map(unit));
                bytes
            };
            let (masked, findings) = mask(&encode(&format!("名前 key={key}\n")));
            assert_eq!(masked, encode("名前 key=[REDACTED]\n"));
            assert!(!findings.is_empty());
        }

        // Nothing to mask: the input comes back byte for byte, whatever
        // bytes it holds (0xAD would be a soft hyphen in Latin-1).
        let clean = b"abc\0def\xff".to_vec();
        assert_eq!(mask(&clean).0, clean);
        let every_byte: Vec<u8> = (0..=255u8).cycle().take(1024).collect();
        let (masked, findings) = mask(&every_byte);
        assert!(findings.is_empty(), "{findings:?}");
        assert_eq!(masked, every_byte);
        // Around a masked value too: EUC-JP kana next to a key.
        let kana = [b"\xa4\xad\xa5\xad key=", key.as_bytes(), b" \xa4\xad\n"].concat();
        let (masked, _) = mask(&kana);
        assert_eq!(masked, b"\xa4\xad\xa5\xad key=[REDACTED] \xa4\xad\n");
        // An odd last byte of UTF-16 input survives masking.
        let odd = [
            &[0xff, 0xfe][..],
            &"k".encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
            b"\x41",
        ]
        .concat();
        assert_eq!(mask(&odd).0, odd);
    }

    #[test]
    fn non_utf8_input_finding_says_how_the_input_was_masked() {
        let f = non_utf8_input_finding("data.bin");
        assert_eq!(f.rule_id, "mask.non_utf8_input");
        assert_eq!(f.file, "data.bin");
        assert_eq!(f.severity, "info");
        assert_eq!(f.kind, "ignore");
        assert_eq!(f.redacted_value, "[REDACTED]");
    }

    #[test]
    fn read_mask_input_reads_file_and_labels_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prompt.txt");
        fs::write(&path, "hello").unwrap();

        let (label, bytes) = read_mask_input(Some(&path)).unwrap();
        assert_eq!(label, path.to_string_lossy());
        assert_eq!(bytes, b"hello");
    }

    #[test]
    fn resolve_repo_root_falls_back_to_cwd_outside_git() {
        let dir = tempfile::tempdir().unwrap();
        let resolved = resolve_repo_root(dir.path());
        assert_eq!(resolved, std::fs::canonicalize(dir.path()).unwrap());
    }
}
