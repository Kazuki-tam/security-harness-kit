use crate::args::{AiTool, RedactionMode, SeverityArg};
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
}

pub fn run(inv: MaskInvocation) -> Result<()> {
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
        let findings = vec![binary_passthrough_finding(&rel_label)];
        let result: Result<()> = if inv.json {
            let out = MaskJsonOutput {
                masked_content: "[BINARY_PASSTHROUGH]".into(),
                findings,
            };
            match serde_json::to_string_pretty(&out) {
                Ok(s) => {
                    println!("{s}");
                    Ok(())
                }
                Err(e) => Err(e.into()),
            }
        } else {
            match io::stdout().write_all(&bytes) {
                Ok(()) => Ok(()),
                Err(e) => Err(e.into()),
            }
        };
        let output_result: Result<()> = if let Some(outp) = inv.output {
            match fs::write(&outp, &bytes) {
                Ok(()) => Ok(()),
                Err(e) => Err(e.into()),
            }
        } else {
            Ok(())
        };
        bytes.zeroize();
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
        fs::write(&outp, masked)?;
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
    let hook_body_result = shk_integrations::stdin_to_hook_body(
        tool.integration_tool(),
        post,
        stdin_trim,
        cwd,
        &repo_root,
    );
    stdin_str.zeroize();
    let (disp, mut body) = hook_body_result?;
    let (mut policy, _) = Policy::load_from_dir(&repo_root)?;
    apply_redaction_override(&mut policy, redaction);
    apply_min_severity_override(&mut policy, min_severity);
    let mask_result = shk_core::masker::mask_from_policy(&body, &policy, &disp);
    body.zeroize();
    let (mut masked, findings) = mask_result.context("hook mask failed")?;

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

fn binary_passthrough_finding(file: &str) -> Finding {
    Finding {
        rule_id: "mask.binary_passthrough".into(),
        severity: "info".into(),
        kind: "ignore".into(),
        file: file.into(),
        line: 1,
        column: 1,
        message: "Binary or non-UTF-8 input was passed through unchanged and not scanned".into(),
        redacted_value: "[REDACTED]".into(),
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
    fn binary_passthrough_finding_reports_unscanned_input() {
        let f = binary_passthrough_finding("data.bin");
        assert_eq!(f.rule_id, "mask.binary_passthrough");
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
