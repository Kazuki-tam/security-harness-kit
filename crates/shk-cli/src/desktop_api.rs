//! Structured APIs for the desktop app (no stdout parsing).

use crate::args::{
    AiTool, AuditReasonArg, EnvEncryptArgs, PseudonymizeFormatArg, PseudonymizeModeArg,
};
pub use crate::commands::audit::AuditReport;
use crate::commands::audit::{self, AuditInvocation};
use crate::commands::pseudonymize::{
    self, ColumnSelection, Decisions, InlineRequest, InputKind, Preview, PseudonymizeRequest,
    PseudonymizeSource, StoreOpener,
};
use crate::commands::skills::{SkillTool, SkillsInstallArgs};
use crate::doctor::{
    ClaudePermissionsStatus, CodexConfigStatus, EnvFileState, EnvFileStatus, IgnoreStatus,
    collect_claude_permissions_status, collect_codex_config_status, collect_env_file_statuses,
    collect_ignore_status, fix_ignore_patterns, has_shk_pre_commit, ignore_fix_target_statuses,
};
use crate::env_store::{is_secret_store_unavailable, open_pseudonymize_store};
use crate::hooks::{
    ConfigureAiOptions, InstallAiOptions, configure_ai_with_summaries, install_ai_with_summaries,
    install_pre_commit,
};
use crate::npm_hardening;
use crate::policy_cmd;
use crate::safety;
use crate::shk_executable;
use crate::workflow_hardening;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use shk_core::finding::Finding;
use shk_core::git;
use shk_core::masker::MaskJsonOutput;
use shk_core::policy::{Policy, SecretStoreBackend};
use shk_core::pseudonymize::{
    ColumnOverrides, ColumnSource, Kind, ResolvedColumn, TableResult, delimiter_for_path,
    list_sheets,
};
use shk_integrations::{MANAGED_MARKER_JSON, MANAGED_MARKER_SH};
use std::collections::{BTreeMap, HashSet};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use zeroize::{Zeroize, Zeroizing};

/// Desktop setup installs blocking scan hooks that append metadata-only block entries.
const DESKTOP_AI_HOOK_LOG_BLOCKED: bool = true;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AiSafetyAppliedStatus {
    pub scan_hooks_claude_code: bool,
    pub scan_hooks_cursor: bool,
    pub scan_hooks_codex: bool,
    pub scan_hooks_copilot: bool,
    pub scan_hooks_antigravity: bool,
    pub scan_hooks_windsurf: bool,
    pub claude_deny: bool,
    pub claude_sandbox: bool,
    pub codex_sandbox: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectStatus {
    pub path: String,
    pub policy: PolicyStatus,
    pub git: GitStatus,
    pub hooks: HooksStatus,
    pub doctor: DoctorStatus,
    pub ai_safety_applied: AiSafetyAppliedStatus,
    pub npm_hardening: NpmHardeningStatusDto,
    pub skills: Vec<SkillStatusDto>,
    /// Per-file env encryption report — key names and counts only, never values.
    pub env_files: Vec<EnvFileStatus>,
    pub ignore_fix_targets: Vec<IgnoreFixTargetDto>,
    pub recommended_fixes: Vec<RecommendedFixDto>,
    pub cli_installed: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyStatus {
    pub exists: bool,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GitStatus {
    pub is_repo: bool,
    pub root: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HooksStatus {
    pub pre_commit: PreCommitStatus,
    pub ai_tools: Vec<AiHookToolStatus>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreCommitStatus {
    pub installed: bool,
    pub hook_path: Option<String>,
    pub is_git_repo: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AiHookToolStatus {
    pub tool: String,
    pub config_path: String,
    pub installed: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DoctorStatus {
    pub git_pre_commit: bool,
    pub ai_managed_hooks: bool,
    pub ignore_ok: bool,
    pub missing_ignore_patterns: Vec<String>,
    pub claude_deny_ok: bool,
    pub claude_sandbox_ok: bool,
    pub codex_config_ok: bool,
    pub env_applicable: bool,
    pub env_ok: bool,
    pub npm_ok: bool,
    pub workflows_applicable: bool,
    pub workflows_ok: bool,
    pub issues: Vec<DoctorIssue>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DoctorIssue {
    pub id: String,
    pub severity: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NpmHardeningStatusDto {
    pub has_projects: bool,
    pub ok: bool,
    pub settings_ok: bool,
    pub package_count: usize,
    pub missing_lockfiles: Vec<String>,
    pub ignore_scripts_ok: bool,
    pub age_gates_ok: bool,
    pub dependency_bot_cooldown_ok: bool,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillStatusDto {
    pub label: String,
    pub path: Option<String>,
    pub installed: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IgnoreFixTargetDto {
    pub name: String,
    pub exists: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecommendedFixDto {
    pub id: String,
    pub severity: String,
    pub message: String,
    pub requires_policy: bool,
    pub default_selected: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionResult {
    pub success: bool,
    pub message: String,
    pub details: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloneRepositoryResult {
    pub path: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopMaskFileResult {
    pub masked_content: String,
    pub findings: Vec<Finding>,
    pub file_kind: String,
    pub source_label: String,
    pub output_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopMaskPolicyStatus {
    pub uses_project_policy: bool,
    pub policy_path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DesktopOfficeFormat {
    Docx,
    Xlsx,
    Pptx,
}

pub fn mask_text_for_desktop(
    project_root: Option<&Path>,
    content: &str,
    label: &str,
) -> Result<MaskJsonOutput> {
    if content.trim().is_empty() {
        anyhow::bail!("mask input is empty");
    }
    let policy = load_mask_policy(project_root)?;
    ensure_mask_content_size_allowed(content, policy.scan.max_file_size_bytes)?;
    let (masked_content, findings) = shk_core::masker::mask_from_policy(content, &policy, label)?;
    Ok(MaskJsonOutput {
        masked_content,
        findings,
    })
}

pub fn mask_policy_status(project_root: Option<&Path>) -> Result<DesktopMaskPolicyStatus> {
    let policy_path = if let Some(root) = project_root {
        let (_, path) = Policy::load_from_dir(root)?;
        path.map(|path| path.display().to_string())
    } else {
        None
    };
    Ok(DesktopMaskPolicyStatus {
        uses_project_policy: policy_path.is_some(),
        policy_path,
    })
}

pub fn mask_file_for_desktop(
    project_root: Option<&Path>,
    input_path: &Path,
    output_path: Option<&Path>,
) -> Result<DesktopMaskFileResult> {
    if !input_path.is_file() {
        anyhow::bail!("input file does not exist: {}", input_path.display());
    }

    let policy = load_mask_policy(project_root)?;
    let source_label = input_path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| input_path.display().to_string());

    ensure_input_file_size_allowed(input_path, policy.scan.max_file_size_bytes)?;

    if let Some(format) = desktop_office_format(input_path) {
        return mask_office_file_for_desktop(
            project_root,
            &policy,
            input_path,
            output_path,
            format,
            &source_label,
        );
    }

    if is_pdf_file(input_path) {
        return mask_pdf_file_for_desktop(&policy, input_path, output_path, &source_label);
    }

    let mut bytes = fs::read(input_path)?;
    let decoded = decode_desktop_text_file(&bytes, input_path, policy.scan.binary_detection_bytes);
    bytes.zeroize();
    let mut content = decoded?;
    let mask_result = shk_core::masker::mask_from_policy(&content, &policy, &source_label);
    content.zeroize();
    let (masked_content, findings) = mask_result?;

    let written_output = if let Some(outp) = output_path {
        ensure_mask_output_path_allowed(project_root, outp)?;
        crate::fs_atomic::write_atomic(outp, masked_content.as_bytes())?;
        Some(outp.display().to_string())
    } else {
        None
    };

    Ok(DesktopMaskFileResult {
        masked_content,
        findings,
        file_kind: "text".into(),
        source_label,
        output_path: written_output,
    })
}

fn ensure_mask_content_size_allowed(content: &str, max_bytes: u64) -> Result<()> {
    let size = content.len() as u64;
    if size > max_bytes {
        anyhow::bail!("mask input exceeds the configured size limit ({size} > {max_bytes} bytes)");
    }
    Ok(())
}

fn ensure_input_file_size_allowed(input_path: &Path, max_bytes: u64) -> Result<()> {
    let file_size = fs::metadata(input_path)?.len();
    if file_size > max_bytes {
        anyhow::bail!(
            "file exceeds the configured file size limit ({file_size} > {max_bytes} bytes)"
        );
    }
    Ok(())
}

fn ensure_mask_output_path_allowed(project_root: Option<&Path>, output_path: &Path) -> Result<()> {
    safety::ensure_writable_path_allowed(output_path)?;
    // When a project is selected, keep masked outputs inside that project tree.
    // Without a project, only protected-path checks apply so dialog-chosen save
    // locations outside the workspace remain available.
    if let Some(root) = project_root {
        safety::ensure_write_path_within(root, output_path)?;
    }
    Ok(())
}

fn load_mask_policy(project_root: Option<&Path>) -> Result<Policy> {
    if let Some(root) = project_root {
        let (policy, _) = Policy::load_from_dir(root)?;
        Ok(policy)
    } else {
        Ok(Policy::default())
    }
}

fn desktop_office_format(path: &Path) -> Option<DesktopOfficeFormat> {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some(ext) if ext.eq_ignore_ascii_case("docx") => Some(DesktopOfficeFormat::Docx),
        Some(ext) if ext.eq_ignore_ascii_case("xlsx") => Some(DesktopOfficeFormat::Xlsx),
        Some(ext) if ext.eq_ignore_ascii_case("pptx") => Some(DesktopOfficeFormat::Pptx),
        _ => None,
    }
}

fn is_pdf_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("pdf"))
}

fn mask_pdf_file_for_desktop(
    policy: &Policy,
    input_path: &Path,
    output_path: Option<&Path>,
    source_label: &str,
) -> Result<DesktopMaskFileResult> {
    if output_path.is_some() {
        anyhow::bail!("writing a masked PDF is not supported; copy the masked text output instead");
    }

    let file_size = fs::metadata(input_path)?.len();
    if file_size > policy.scan.max_file_size_bytes {
        anyhow::bail!(
            "PDF exceeds the configured file size limit ({} > {} bytes)",
            file_size,
            policy.scan.max_file_size_bytes
        );
    }

    let mut bytes = fs::read(input_path)?;
    let header_len = bytes.len().min(1024);
    if !bytes[..header_len]
        .windows(b"%PDF-".len())
        .any(|window| window == b"%PDF-")
    {
        bytes.zeroize();
        anyhow::bail!("file has a .pdf extension but no PDF header");
    }

    let extracted = shk_core::document_masker::extract_document_text_entries(
        source_label,
        &bytes,
        policy.scan.max_file_size_bytes,
    );
    bytes.zeroize();
    let entries =
        extracted?.ok_or_else(|| anyhow::anyhow!("unable to extract text from PDF document"))?;
    if entries.is_empty() {
        anyhow::bail!("PDF has no extractable text layer (scanned/image-only PDFs are scan-only)");
    }

    let mut combined = entries
        .iter()
        .map(|entry| entry.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");

    let mask_result = shk_core::masker::mask_from_policy(&combined, policy, source_label);
    combined.zeroize();
    let (masked_content, findings) = mask_result?;

    Ok(DesktopMaskFileResult {
        masked_content,
        findings,
        file_kind: "pdf".into(),
        source_label: source_label.into(),
        output_path: None,
    })
}

fn decode_desktop_text_file(
    bytes: &[u8],
    path: &Path,
    binary_detection_bytes: usize,
) -> Result<String> {
    if let Some(without_bom) = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]) {
        return String::from_utf8(without_bom.to_vec()).context("decode UTF-8 text file");
    }

    if let Some(without_bom) = bytes.strip_prefix(&[0xff, 0xfe]) {
        return decode_legacy_text(without_bom, encoding_rs::UTF_16LE, "UTF-16LE");
    }
    if let Some(without_bom) = bytes.strip_prefix(&[0xfe, 0xff]) {
        return decode_legacy_text(without_bom, encoding_rs::UTF_16BE, "UTF-16BE");
    }

    if let Ok(text) = std::str::from_utf8(bytes) {
        return Ok(text.to_owned());
    }

    let take = binary_detection_bytes.min(bytes.len());
    if bytes[..take].contains(&0) || !is_legacy_text_path(path) {
        anyhow::bail!(
            "binary or unsupported text encoding; use UTF-8, UTF-16 with BOM, or Shift_JIS"
        );
    }

    decode_legacy_text(bytes, encoding_rs::SHIFT_JIS, "Shift_JIS")
}

fn decode_legacy_text(
    bytes: &[u8],
    encoding: &'static encoding_rs::Encoding,
    encoding_name: &str,
) -> Result<String> {
    let (decoded, had_errors) = encoding.decode_without_bom_handling(bytes);
    if had_errors {
        anyhow::bail!("invalid {encoding_name} text");
    }
    Ok(decoded.into_owned())
}

fn is_legacy_text_path(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| {
            ["txt", "md", "json", "yaml", "yml", "csv", "log"]
                .iter()
                .any(|supported| ext.eq_ignore_ascii_case(supported))
        })
}

fn mask_office_file_for_desktop(
    project_root: Option<&Path>,
    policy: &Policy,
    input_path: &Path,
    output_path: Option<&Path>,
    format: DesktopOfficeFormat,
    source_label: &str,
) -> Result<DesktopMaskFileResult> {
    let mut bytes = fs::read(input_path)?;
    let extracted = shk_core::document_masker::extract_ooxml_text_entries(
        source_label,
        &bytes,
        policy.scan.max_file_size_bytes,
    );
    bytes.zeroize();
    let entries =
        extracted?.ok_or_else(|| anyhow::anyhow!("unable to extract text from Office document"))?;

    let mut combined = entries
        .iter()
        .map(|entry| entry.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");

    let mask_result = shk_core::masker::mask_from_policy(&combined, policy, source_label);
    combined.zeroize();
    let (masked_content, preview_findings) = mask_result?;
    let mut findings = preview_findings;

    let written_output = if let Some(outp) = output_path {
        ensure_mask_output_path_allowed(project_root, outp)?;
        let doc_result = match format {
            DesktopOfficeFormat::Docx => {
                shk_core::document_masker::mask_docx(input_path, outp, policy)?
            }
            DesktopOfficeFormat::Xlsx => {
                shk_core::document_masker::mask_xlsx(input_path, outp, policy)?
            }
            DesktopOfficeFormat::Pptx => {
                shk_core::document_masker::mask_pptx(input_path, outp, policy)?
            }
        };
        findings = doc_result.findings;
        Some(outp.display().to_string())
    } else {
        None
    };

    Ok(DesktopMaskFileResult {
        masked_content,
        findings,
        file_kind: "office".into(),
        source_label: source_label.into(),
        output_path: written_output,
    })
}

// ---------------------------------------------------------------------------
// Pseudonymize
// ---------------------------------------------------------------------------

/// Sample rows shown next to each column so a person can tell what it holds.
const PSEUDONYMIZE_PREVIEW_ROWS: usize = 3;
/// Cells are cut for display; the engine never sees the truncated copy.
const PSEUDONYMIZE_PREVIEW_CELL_CHARS: usize = 40;
const PSEUDONYMIZE_INLINE_LABEL: &str = "<pasted>";

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PseudonymizeColumnChoice {
    /// Column position from the plan. When every choice carries one, columns
    /// are addressed by position, so blank or repeated headers work too.
    #[serde(default)]
    pub index: Option<usize>,
    pub name: String,
    /// `email`, `phone`, `name`, `custom`, or `none` (leave the column as it is).
    pub kind: String,
    #[serde(default)]
    pub custom_label: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PseudonymizeInspectOptions {
    #[serde(default)]
    pub input_path: Option<String>,
    #[serde(default)]
    pub inline_text: Option<String>,
    /// `table` or `text`. Required for pasted content; files classify by extension.
    #[serde(default)]
    pub mode: Option<String>,
    /// `csv` or `tsv` for pasted tables or files without a table extension.
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub sheet: Option<String>,
    #[serde(default)]
    pub no_header: bool,
    /// The user's column choices, one per header. Empty means "suggest".
    #[serde(default)]
    pub columns: Vec<PseudonymizeColumnChoice>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PseudonymizeColumnPlan {
    pub index: usize,
    pub name: String,
    /// `email`, `phone`, `name`, `custom`, or `none`.
    pub kind: String,
    pub custom_label: Option<String>,
    /// `config`, `cli`, `inferred`, `rule`, or `none`.
    pub source: String,
    pub match_rate: Option<f64>,
    /// xlsx only: the column holds a formula cell, which a run would refuse.
    pub formula: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PseudonymizeTablePreview {
    pub has_header: bool,
    pub delimiter: String,
    pub headers: Vec<String>,
    pub sample_rows: Vec<Vec<String>>,
    pub row_count: u64,
    pub columns: Vec<PseudonymizeColumnPlan>,
    pub sheets: Vec<String>,
    pub selected_sheet: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PseudonymizeInspectResult {
    /// `table-csv`, `table-xlsx`, `text`, or `text-office`.
    pub input_kind: String,
    pub source_label: String,
    pub table: Option<PseudonymizeTablePreview>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PseudonymizeKeyStatus {
    pub exists: bool,
    pub backend: String,
    pub fingerprint: Option<String>,
    /// Set when the configured store cannot be reached on this machine.
    pub unavailable_reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PseudonymizeRunOptions {
    #[serde(flatten)]
    pub input: PseudonymizeInspectOptions,
    #[serde(default)]
    pub output_path: Option<String>,
    #[serde(default)]
    pub map_path: Option<String>,
    /// The user agreed to create the project key if none exists yet.
    #[serde(default)]
    pub create_key: bool,
    #[serde(default)]
    pub check_remaining: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PseudonymizeRunResult {
    pub mode: String,
    pub rows_processed: u64,
    pub replaced: BTreeMap<String, u64>,
    pub unparsed: BTreeMap<String, u64>,
    pub columns: Vec<PseudonymizeColumnPlan>,
    pub key_fingerprint: Option<String>,
    pub output_path: Option<String>,
    pub meta_path: Option<String>,
    pub map_path: Option<String>,
    /// The pseudonymized text for pasted content; files are written instead.
    pub inline_output: Option<String>,
    pub remaining_rule_ids: Vec<String>,
    pub remaining_check_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PseudonymizeRestoreResult {
    pub output_path: String,
    pub replacements: usize,
    pub ambiguous_tokens: usize,
}

enum PseudonymizeInput {
    File(PathBuf),
    Inline {
        text: Zeroizing<String>,
        mode: PseudonymizeModeArg,
    },
}

struct ParsedPseudonymizeInput {
    input: PseudonymizeInput,
    mode: Option<PseudonymizeModeArg>,
    format: Option<PseudonymizeFormatArg>,
    sheet: Option<String>,
    no_header: bool,
    columns: Option<ColumnOverrides>,
}

pub fn pseudonymize_inspect(
    project_root: &Path,
    options: PseudonymizeInspectOptions,
) -> Result<PseudonymizeInspectResult> {
    pseudonymize_inspect_inner(project_root, options).map_err(flatten_error)
}

fn pseudonymize_inspect_inner(
    project_root: &Path,
    options: PseudonymizeInspectOptions,
) -> Result<PseudonymizeInspectResult> {
    let root = require_pseudonymize_project(project_root)?;
    let parsed = parse_pseudonymize_input(options)?;
    let (source, source_label) = match parsed.input {
        PseudonymizeInput::File(path) => {
            let label = source_label_for(&path);
            (PseudonymizeSource::File(path), label)
        }
        PseudonymizeInput::Inline { text, .. } => (
            PseudonymizeSource::Buffer(inline_bytes(&root, text)?),
            PSEUDONYMIZE_INLINE_LABEL.to_string(),
        ),
    };
    let kind = pseudonymize::classify_input(source.path(), parsed.mode, parsed.format)?;
    let (sheets, sheet, selected_sheet) = if kind == InputKind::TableXlsx {
        let path = source.path().expect("xlsx input is a file");
        sheet_selection(path, parsed.sheet.as_deref())?
    } else {
        (Vec::new(), parsed.sheet.clone(), None)
    };
    let request = PseudonymizeRequest {
        project_root: root,
        source,
        output: None,
        dry_run: true,
        columns: parsed.columns.map(ColumnSelection::Resolved),
        no_header: parsed.no_header,
        mode: parsed.mode,
        format: parsed.format,
        sheet,
        map: None,
        check_remaining: false,
    };
    let table = match pseudonymize::preview(&request)? {
        Preview::Table(table) => {
            let delimiter = match (kind, parsed.format) {
                (InputKind::TableXlsx, _) | (_, Some(PseudonymizeFormatArg::Csv)) => ",",
                (_, Some(PseudonymizeFormatArg::Tsv)) => "\t",
                (_, None) if delimiter_for_path(request.source.path()) == b'\t' => "\t",
                (_, None) => ",",
            };
            Some(table_preview(&table, delimiter, sheets, selected_sheet))
        }
        Preview::Text => None,
    };
    Ok(PseudonymizeInspectResult {
        input_kind: input_kind_label(kind).to_string(),
        source_label,
        table,
    })
}

pub fn pseudonymize_key_status(project_root: &Path) -> Result<PseudonymizeKeyStatus> {
    pseudonymize_key_status_with(project_root, &open_pseudonymize_store)
}

pub(crate) fn pseudonymize_key_status_with(
    project_root: &Path,
    open_store: StoreOpener<'_>,
) -> Result<PseudonymizeKeyStatus> {
    pseudonymize_key_status_inner(project_root, open_store).map_err(flatten_error)
}

fn pseudonymize_key_status_inner(
    project_root: &Path,
    open_store: StoreOpener<'_>,
) -> Result<PseudonymizeKeyStatus> {
    let root = require_pseudonymize_project(project_root)?;
    let lookup = (|| {
        let (_policy, project, store, backend) = pseudonymize::open_context(&root, open_store)?;
        let material = pseudonymize::load_material(store.as_ref(), &project)?;
        Ok::<_, anyhow::Error>(PseudonymizeKeyStatus {
            exists: material.is_some(),
            backend: pseudonymize::backend_label(backend).to_string(),
            fingerprint: material.map(|material| material.fingerprint()),
            unavailable_reason: None,
        })
    })();
    match lookup {
        Ok(status) => Ok(status),
        Err(err) if is_secret_store_unavailable(&err) => {
            let (policy, _) = Policy::load_from_dir(&root)?;
            let backend = policy
                .env
                .secret_store
                .parse::<SecretStoreBackend>()
                .map(pseudonymize::backend_label)
                .unwrap_or("unknown");
            Ok(PseudonymizeKeyStatus {
                exists: false,
                backend: backend.to_string(),
                fingerprint: None,
                unavailable_reason: Some(format!("{err:#}")),
            })
        }
        Err(err) => Err(err),
    }
}

pub fn pseudonymize_run(
    project_root: &Path,
    options: PseudonymizeRunOptions,
) -> Result<PseudonymizeRunResult> {
    pseudonymize_run_with(project_root, options, &open_pseudonymize_store)
}

pub(crate) fn pseudonymize_run_with(
    project_root: &Path,
    options: PseudonymizeRunOptions,
    open_store: StoreOpener<'_>,
) -> Result<PseudonymizeRunResult> {
    pseudonymize_run_inner(project_root, options, open_store).map_err(flatten_error)
}

fn pseudonymize_run_inner(
    project_root: &Path,
    options: PseudonymizeRunOptions,
    open_store: StoreOpener<'_>,
) -> Result<PseudonymizeRunResult> {
    let root = require_pseudonymize_project(project_root)?;
    let parsed = parse_pseudonymize_input(options.input)?;
    // Positional choices are applied exactly; name-based ones leave the rest
    // to config and inference, and inference then fails closed.
    let decisions = Decisions {
        accept_inferred: false,
        create_key: options.create_key,
    };
    let kind = pseudonymize::classify_input(
        match &parsed.input {
            PseudonymizeInput::File(path) => Some(path.as_path()),
            PseudonymizeInput::Inline { .. } => None,
        },
        parsed.mode,
        parsed.format,
    )?;
    if matches!(kind, InputKind::TableCsv | InputKind::TableXlsx) && parsed.columns.is_none() {
        anyhow::bail!("choose what each column holds before pseudonymizing a table");
    }
    let output = non_blank(options.output_path.as_deref()).map(PathBuf::from);
    let map = non_blank(options.map_path.as_deref()).map(PathBuf::from);
    match parsed.input {
        PseudonymizeInput::File(path) => {
            let output = output
                .ok_or_else(|| anyhow::anyhow!("choose where to save the pseudonymized file"))?;
            // The engine applies the CLI's own guards: protected home paths,
            // regular-file and distinct-path checks, and the `.shk-map` suffix.
            // Unlike redaction, outputs are not confined to the project tree:
            // business exports usually live outside the repository and the
            // location came from a save dialog the user drove.
            let sheet = if kind == InputKind::TableXlsx {
                sheet_selection(&path, parsed.sheet.as_deref())?.1
            } else {
                parsed.sheet
            };
            let request = PseudonymizeRequest {
                project_root: root,
                source: PseudonymizeSource::File(path),
                output: Some(output),
                dry_run: false,
                columns: parsed.columns.map(ColumnSelection::Resolved),
                no_header: parsed.no_header,
                mode: parsed.mode,
                format: parsed.format,
                sheet,
                map,
                check_remaining: options.check_remaining,
            };
            let outcome = pseudonymize::mask_core(request, open_store, &decisions)?;
            let written = outcome
                .written
                .ok_or_else(|| anyhow::anyhow!("pseudonymize run finished without writing"))?;
            let (remaining_rule_ids, remaining_check_error) = match outcome.remaining {
                None => (Vec::new(), None),
                Some(Ok(ids)) => (ids, None),
                Some(Err(err)) => (Vec::new(), Some(format!("{err:#}"))),
            };
            Ok(PseudonymizeRunResult {
                mode: outcome.meta.mode.to_string(),
                rows_processed: outcome.meta.rows_processed,
                replaced: outcome.meta.replaced,
                unparsed: outcome.meta.unparsed,
                columns: outcome
                    .columns
                    .map(|columns| columns.iter().map(column_plan).collect())
                    .unwrap_or_default(),
                key_fingerprint: outcome.meta.key_fingerprint,
                output_path: Some(written.output.display().to_string()),
                meta_path: Some(written.meta.display().to_string()),
                map_path: written.map.map(|map| map.display().to_string()),
                inline_output: None,
                remaining_rule_ids,
                remaining_check_error,
            })
        }
        PseudonymizeInput::Inline { text, mode } => {
            if output.is_some() || map.is_some() || options.check_remaining {
                anyhow::bail!(
                    "pasted content is returned in place; output, restore map, and leftover checks apply to files only"
                );
            }
            let bytes = inline_bytes(&root, text)?;
            let outcome = pseudonymize::pseudonymize_inline(
                InlineRequest {
                    project_root: root,
                    bytes,
                    mode,
                    format: parsed.format,
                    columns: parsed.columns,
                    no_header: parsed.no_header,
                },
                open_store,
                &decisions,
            )?;
            Ok(PseudonymizeRunResult {
                mode: outcome.meta.mode.to_string(),
                rows_processed: outcome.meta.rows_processed,
                replaced: outcome.meta.replaced,
                unparsed: outcome.meta.unparsed,
                columns: outcome
                    .columns
                    .map(|columns| columns.iter().map(column_plan).collect())
                    .unwrap_or_default(),
                key_fingerprint: outcome.meta.key_fingerprint,
                output_path: None,
                meta_path: None,
                map_path: None,
                inline_output: Some(outcome.output.to_string()),
                remaining_rule_ids: Vec::new(),
                remaining_check_error: None,
            })
        }
    }
}

pub fn pseudonymize_restore(
    project_root: &Path,
    input_path: &Path,
    map_path: &Path,
    output_path: &Path,
) -> Result<PseudonymizeRestoreResult> {
    pseudonymize_restore_with(
        project_root,
        input_path,
        map_path,
        output_path,
        &open_pseudonymize_store,
    )
}

pub(crate) fn pseudonymize_restore_with(
    project_root: &Path,
    input_path: &Path,
    map_path: &Path,
    output_path: &Path,
    open_store: StoreOpener<'_>,
) -> Result<PseudonymizeRestoreResult> {
    let root = require_pseudonymize_project(project_root).map_err(flatten_error)?;
    let summary = pseudonymize::restore_with(
        &root,
        input_path.to_path_buf(),
        map_path.to_path_buf(),
        output_path.to_path_buf(),
        open_store,
    )?;
    Ok(PseudonymizeRestoreResult {
        output_path: summary.output.display().to_string(),
        replacements: summary.replacements,
        ambiguous_tokens: summary.ambiguous,
    })
}

/// Keys are per project, so every pseudonymize call needs a real project
/// with a policy file, unlike redaction which falls back to defaults.
fn require_pseudonymize_project(project_root: &Path) -> Result<PathBuf> {
    let root = resolve_project_root(&project_root.display().to_string())?;
    safety::require_project_policy(&root, "pseudonymize")?;
    Ok(root)
}

fn parse_pseudonymize_input(
    options: PseudonymizeInspectOptions,
) -> Result<ParsedPseudonymizeInput> {
    let mode = options
        .mode
        .as_deref()
        .map(parse_pseudonymize_mode)
        .transpose()?;
    let format = options
        .format
        .as_deref()
        .map(parse_pseudonymize_format)
        .transpose()?;
    let input = match (
        non_blank(options.input_path.as_deref()),
        options.inline_text,
    ) {
        (Some(path), None) => PseudonymizeInput::File(PathBuf::from(path)),
        (None, Some(text)) => {
            let text = Zeroizing::new(text);
            if text.trim().is_empty() {
                anyhow::bail!("pasted content is empty");
            }
            let mode =
                mode.ok_or_else(|| anyhow::anyhow!("pasted content needs a mode (table or text)"))?;
            PseudonymizeInput::Inline { text, mode }
        }
        (Some(_), Some(_)) => {
            anyhow::bail!("pass either a file path or pasted content, not both")
        }
        (None, None) => anyhow::bail!("pass a file path or pasted content"),
    };
    Ok(ParsedPseudonymizeInput {
        input,
        mode,
        format,
        sheet: non_blank(options.sheet.as_deref()).map(str::to_string),
        no_header: options.no_header,
        columns: column_overrides(&options.columns)?,
    })
}

fn inline_bytes(root: &Path, mut text: Zeroizing<String>) -> Result<Zeroizing<Vec<u8>>> {
    let (policy, _) = Policy::load_from_dir(root)?;
    ensure_mask_content_size_allowed(&text, policy.scan.max_file_size_bytes)?;
    // Move the buffer rather than copy it; the emptied String zeroizes nothing.
    Ok(Zeroizing::new(std::mem::take(&mut *text).into_bytes()))
}

/// Engine errors carry their cause in the chain; the app shows one string.
fn flatten_error(err: anyhow::Error) -> anyhow::Error {
    anyhow::anyhow!("{err:#}")
}

fn parse_pseudonymize_mode(raw: &str) -> Result<PseudonymizeModeArg> {
    match raw.trim() {
        "table" => Ok(PseudonymizeModeArg::Table),
        "text" => Ok(PseudonymizeModeArg::Text),
        other => anyhow::bail!("unknown pseudonymize mode `{other}` (expected table or text)"),
    }
}

fn parse_pseudonymize_format(raw: &str) -> Result<PseudonymizeFormatArg> {
    match raw.trim() {
        "csv" => Ok(PseudonymizeFormatArg::Csv),
        "tsv" => Ok(PseudonymizeFormatArg::Tsv),
        other => anyhow::bail!("unknown table format `{other}` (expected csv or tsv)"),
    }
}

/// Turn the user's per-column choices into an exact selection: named kinds
/// become entries and `none` becomes a skip, so neither `[pseudonymize.columns]`
/// nor inference can add a column the user did not pick.
fn column_overrides(choices: &[PseudonymizeColumnChoice]) -> Result<Option<ColumnOverrides>> {
    if choices.is_empty() {
        return Ok(None);
    }
    let by_position = choices.iter().all(|choice| choice.index.is_some());
    if !by_position && choices.iter().any(|choice| choice.index.is_some()) {
        anyhow::bail!("column choices must all carry a position, or none of them");
    }
    let mut overrides = ColumnOverrides::default();
    let mut seen = std::collections::BTreeSet::new();
    for choice in choices {
        let name = choice.name.trim();
        let label = if by_position {
            format!("column {}", choice.index.unwrap_or_default() + 1)
        } else {
            format!("column `{name}`")
        };
        let key = match choice.index {
            Some(index) => index.to_string(),
            // Headers match case-insensitively, so two names that fold to the
            // same key would silently override each other.
            None if name.is_empty() => anyhow::bail!("column choice has an empty name"),
            None => name.to_ascii_lowercase(),
        };
        if !seen.insert(key) {
            anyhow::bail!("{label} was chosen twice");
        }
        let kind = match choice.kind.trim() {
            "none" => None,
            "custom" => {
                let custom = choice
                    .custom_label
                    .as_deref()
                    .map(str::trim)
                    .unwrap_or_default();
                if custom.is_empty() {
                    anyhow::bail!("{label} needs a label for the custom kind");
                }
                Some(Kind::parse(&format!("custom:{custom}")))
            }
            other => Some(Kind::parse(other)),
        }
        .transpose()
        .map_err(|err| anyhow::anyhow!("{label}: {}", err.0))?;
        match (choice.index, kind) {
            (Some(index), kind) => overrides.positions.push((index, kind)),
            (None, Some(kind)) => overrides.entries.push((name.to_string(), kind)),
            (None, None) => overrides.skip.push(name.to_string()),
        }
    }
    Ok(Some(overrides))
}

/// Sheets for the picker, the selector to hand to the engine, and the name
/// that selector resolves to. The engine reads a numeric selector as a
/// position, so a sheet whose *name* looks like a number is sent by position.
fn sheet_selection(
    path: &Path,
    spec: Option<&str>,
) -> Result<(Vec<String>, Option<String>, Option<String>)> {
    let sheets = list_sheets(path)?;
    let selector = spec.map(|spec| match sheets.iter().position(|name| name == spec) {
        Some(index) => (index + 1).to_string(),
        None => spec.to_string(),
    });
    let selected = resolve_sheet_name(&sheets, selector.as_deref());
    Ok((sheets, selector, selected))
}

fn table_preview(
    result: &TableResult,
    delimiter: &str,
    sheets: Vec<String>,
    selected_sheet: Option<String>,
) -> PseudonymizeTablePreview {
    PseudonymizeTablePreview {
        has_header: result.has_header,
        delimiter: delimiter.to_string(),
        headers: result.headers.clone(),
        sample_rows: result
            .sample_rows
            .iter()
            .take(PSEUDONYMIZE_PREVIEW_ROWS)
            .map(|row| row.iter().map(|cell| truncate_cell(cell)).collect())
            .collect(),
        row_count: result.meta.rows_processed,
        columns: column_plans(&result.headers, &result.columns, &result.formula_columns),
        sheets,
        selected_sheet,
    }
}

/// One plan entry per header, so the UI can render unselected columns too.
fn column_plans(
    headers: &[String],
    resolved: &[ResolvedColumn],
    formula_columns: &[usize],
) -> Vec<PseudonymizeColumnPlan> {
    headers
        .iter()
        .enumerate()
        .map(|(index, name)| {
            let mut plan = resolved
                .iter()
                .find(|column| column.index == index)
                .map(column_plan)
                .unwrap_or_else(|| PseudonymizeColumnPlan {
                    index,
                    name: name.clone(),
                    kind: "none".to_string(),
                    custom_label: None,
                    source: "none".to_string(),
                    match_rate: None,
                    formula: false,
                });
            plan.formula = formula_columns.contains(&index);
            plan
        })
        .collect()
}

fn column_plan(column: &ResolvedColumn) -> PseudonymizeColumnPlan {
    let (kind, custom_label) = match &column.kind {
        Kind::Custom(label) => ("custom".to_string(), Some(label.clone())),
        other => (other.as_config_value(), None),
    };
    PseudonymizeColumnPlan {
        index: column.index,
        name: column.name.clone(),
        kind,
        custom_label,
        source: match column.source {
            ColumnSource::Config => "config",
            ColumnSource::Cli => "cli",
            ColumnSource::Inferred => "inferred",
            ColumnSource::Rule => "rule",
        }
        .to_string(),
        match_rate: column.match_rate,
        formula: false,
    }
}

fn input_kind_label(kind: InputKind) -> &'static str {
    match kind {
        InputKind::TableCsv => "table-csv",
        InputKind::TableXlsx => "table-xlsx",
        InputKind::TextPlain => "text",
        InputKind::TextOffice => "text-office",
    }
}

fn truncate_cell(cell: &str) -> String {
    let mut chars = cell.chars();
    let shown: String = chars
        .by_ref()
        .take(PSEUDONYMIZE_PREVIEW_CELL_CHARS)
        .collect();
    if chars.next().is_some() {
        format!("{shown}…")
    } else {
        shown
    }
}

/// Mirror `run_xlsx`'s selector: a number is a 1-based position, otherwise
/// an exact name; `None` means the first sheet.
fn resolve_sheet_name(sheets: &[String], spec: Option<&str>) -> Option<String> {
    let Some(spec) = spec else {
        return sheets.first().cloned();
    };
    match spec.parse::<usize>() {
        Ok(number) => number
            .checked_sub(1)
            .and_then(|index| sheets.get(index))
            .cloned(),
        Err(_) => sheets.iter().find(|sheet| sheet.as_str() == spec).cloned(),
    }
}

fn source_label_for(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| path.display().to_string())
}

fn non_blank(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

pub fn clone_repository(
    remote_url: &str,
    destination_parent: &str,
) -> Result<CloneRepositoryResult> {
    let remote_url = validate_git_remote_url(remote_url)?;
    let parent = resolve_clone_parent(destination_parent)?;
    let repository_name = repository_name_from_remote(remote_url)?;
    let destination = parent.join(repository_name);

    safety::ensure_writable_path_allowed(&destination)?;
    safety::ensure_write_path_within(&parent, &destination)?;
    if destination.exists() {
        anyhow::bail!(
            "clone destination already exists: {}",
            destination.display()
        );
    }

    let status = Command::new("git")
        .arg("clone")
        .arg("--")
        .arg(remote_url)
        .arg(&destination)
        .current_dir(&parent)
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("failed to start git; install Git and ensure it is available on PATH")?;

    if !status.success() {
        anyhow::bail!(
            "Git clone failed. Check the repository URL, network connection, and Git credentials"
        );
    }

    let path = fs::canonicalize(&destination).unwrap_or(destination);
    Ok(CloneRepositoryResult {
        path: path.display().to_string(),
    })
}

fn validate_git_remote_url(remote_url: &str) -> Result<&str> {
    let remote_url = remote_url.trim();
    if remote_url.is_empty() {
        anyhow::bail!("repository URL is empty");
    }
    if remote_url.starts_with('-')
        || remote_url.chars().any(char::is_whitespace)
        || remote_url.contains(['\0', '\n', '\r'])
        || remote_url.contains(['?', '#'])
    {
        anyhow::bail!("repository URL is invalid");
    }

    let has_allowed_scheme = ["https://", "ssh://"]
        .iter()
        .any(|scheme| remote_url.starts_with(scheme));
    let is_scp_style = remote_url
        .split_once(':')
        .is_some_and(|(host, path)| host.contains('@') && !path.is_empty());
    if !has_allowed_scheme && !is_scp_style {
        anyhow::bail!("use an HTTPS or SSH repository URL");
    }

    if let Some(authority) = remote_url
        .strip_prefix("https://")
        .and_then(|rest| rest.split('/').next())
        && authority.contains('@')
    {
        anyhow::bail!("repository URLs containing credentials are not allowed");
    }

    Ok(remote_url)
}

fn resolve_clone_parent(path: &str) -> Result<PathBuf> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        anyhow::bail!("clone destination is empty");
    }
    let parent = PathBuf::from(trimmed);
    if !parent.is_dir() {
        anyhow::bail!("clone destination is not a directory: {}", parent.display());
    }
    let parent = fs::canonicalize(&parent).unwrap_or(parent);
    if parent.parent().is_none() {
        anyhow::bail!("cloning directly into a filesystem root is not allowed");
    }
    Ok(parent)
}

fn repository_name_from_remote(remote_url: &str) -> Result<&str> {
    let without_slash = remote_url.trim_end_matches('/');
    let name = without_slash
        .rsplit(['/', ':'])
        .next()
        .unwrap_or_default()
        .strip_suffix(".git")
        .unwrap_or_else(|| without_slash.rsplit(['/', ':']).next().unwrap_or_default());

    if name.is_empty() || name == "." || name == ".." || Path::new(name).components().count() != 1 {
        anyhow::bail!("repository URL does not contain a valid repository name");
    }
    Ok(name)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallAiHooksOptions {
    pub audit: bool,
    #[serde(default = "default_desktop_log_blocked")]
    pub log_blocked: bool,
    pub dry_run: bool,
    pub global: bool,
    pub tool: Option<String>,
    pub fail_closed: bool,
    pub apply_deny: bool,
    pub apply_sandbox: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitPolicyOptions {
    pub strict: bool,
    pub force: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallSkillsOptions {
    pub tool: Option<String>,
    pub global: bool,
    pub dry_run: bool,
    pub force: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FixDoctorIgnoreOptions {
    pub targets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplyRecommendedFixesOptions {
    pub fix_ids: Vec<String>,
    pub ignore_targets: Vec<String>,
    /// Env files the env_encrypt fix should touch. `None` preserves the old
    /// desktop behavior of selecting every eligible file; `Some` is an
    /// explicit selection and must not be empty. Names are re-validated
    /// against the freshly collected statuses.
    #[serde(default)]
    pub env_targets: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplyNpmHardeningOptions {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplyAiHookSettingsOptions {
    pub scan_hooks_claude_code: bool,
    pub scan_hooks_cursor: bool,
    pub scan_hooks_codex: bool,
    /// Defaults to false for payloads from older desktop frontends.
    #[serde(default)]
    pub scan_hooks_copilot: bool,
    /// Defaults to false for payloads from older desktop frontends.
    #[serde(default)]
    pub scan_hooks_antigravity: bool,
    /// Defaults to false for payloads from older desktop frontends.
    #[serde(default)]
    pub scan_hooks_windsurf: bool,
    #[serde(default = "default_cursor_fail_closed")]
    pub cursor_fail_closed: bool,
    pub claude_deny: bool,
    pub claude_sandbox: bool,
    pub codex_sandbox: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditReportOptions {
    #[serde(default = "default_audit_limit")]
    pub limit: usize,
    pub since: Option<String>,
    pub tool: Option<String>,
    pub reason: Option<String>,
    #[serde(default)]
    pub hide_paths: bool,
}

fn default_audit_limit() -> usize {
    10
}

fn default_desktop_log_blocked() -> bool {
    DESKTOP_AI_HOOK_LOG_BLOCKED
}

fn default_cursor_fail_closed() -> bool {
    true
}

fn desktop_default_install_ai_hooks_options() -> InstallAiHooksOptions {
    InstallAiHooksOptions {
        audit: false,
        log_blocked: DESKTOP_AI_HOOK_LOG_BLOCKED,
        dry_run: false,
        global: false,
        tool: None,
        fail_closed: true,
        apply_deny: false,
        apply_sandbox: false,
    }
}

fn desktop_configure_ai_options(options: &ApplyAiHookSettingsOptions) -> ConfigureAiOptions {
    ConfigureAiOptions {
        audit: false,
        log_blocked: DESKTOP_AI_HOOK_LOG_BLOCKED,
        dry_run: false,
        global: false,
        fail_closed: options.cursor_fail_closed,
        scan_hooks_claude_code: options.scan_hooks_claude_code,
        scan_hooks_cursor: options.scan_hooks_cursor,
        scan_hooks_codex: options.scan_hooks_codex,
        scan_hooks_copilot: options.scan_hooks_copilot,
        scan_hooks_antigravity: options.scan_hooks_antigravity,
        scan_hooks_windsurf: options.scan_hooks_windsurf,
        claude_deny: options.claude_deny,
        claude_sandbox: options.claude_sandbox,
        codex_sandbox: options.codex_sandbox,
    }
}

fn audit_invocation(
    root: &Path,
    options: &AuditReportOptions,
    tool: Option<AiTool>,
    reason: Option<AuditReasonArg>,
) -> AuditInvocation {
    AuditInvocation {
        path: root.to_path_buf(),
        json: true,
        since: options.since.clone(),
        tool,
        reason,
        limit: options.limit,
        hide_paths: options.hide_paths,
    }
}

struct ProjectCheckStatus {
    git_pre_commit: bool,
    ai_managed_hooks: bool,
    scan_hooks_claude_code: bool,
    scan_hooks_cursor: bool,
    scan_hooks_codex: bool,
    scan_hooks_copilot: bool,
    scan_hooks_antigravity: bool,
    scan_hooks_windsurf: bool,
    ignore: IgnoreStatus,
    claude: ClaudePermissionsStatus,
    codex: CodexConfigStatus,
    env_files: Vec<EnvFileStatus>,
    npm: npm_hardening::NpmHardeningStatus,
    workflows: Vec<workflow_hardening::WorkflowFileStatus>,
}

pub fn project_status(path: &str) -> Result<ProjectStatus> {
    let root = resolve_project_root(path)?;
    Ok(build_project_status(&root))
}

pub fn audit_report(path: &str, options: AuditReportOptions) -> Result<AuditReport> {
    let root = resolve_project_root(path)?;
    let tool = options
        .tool
        .as_deref()
        .map(parse_ai_tool)
        .transpose()
        .context("invalid audit tool filter")?;
    let reason = options
        .reason
        .as_deref()
        .map(parse_audit_reason)
        .transpose()
        .context("invalid audit reason filter")?;
    audit::build_audit_report(&root, &audit_invocation(&root, &options, tool, reason))
}

pub fn clear_audit_log(path: &str) -> Result<ActionResult> {
    let root = resolve_project_root(path)?;
    ensure_desktop_project_root_allowed(&root)?;
    let removed = crate::audit_log::clear_log(&root)?;
    Ok(ActionResult {
        success: true,
        message: if removed == 0 {
            "No audit log files to clear".to_string()
        } else {
            format!("Cleared {removed} audit log file(s)")
        },
        details: vec![],
    })
}

pub fn init_policy(path: &str, options: InitPolicyOptions) -> Result<ActionResult> {
    let root = resolve_project_root(path)?;
    ensure_desktop_project_root_allowed(&root)?;
    let policy_path = root.join("shk.toml");
    if policy_path.exists() && !options.force {
        return Ok(ActionResult {
            success: false,
            message: format!("{} already exists", policy_path.display()),
            details: vec![],
        });
    }
    policy_cmd::init(&root, options.strict, options.force)?;
    Ok(ActionResult {
        success: true,
        message: format!("Created {}", policy_path.display()),
        details: vec![],
    })
}

pub fn install_pre_commit_hook(path: &str) -> Result<ActionResult> {
    let root = resolve_project_root(path)?;
    ensure_desktop_project_root_allowed(&root)?;
    let repo_root = git::discover_repo_root(&root).context("not a git repository")?;
    safety::require_project_policy(&repo_root, "hooks install")?;
    install_pre_commit(&repo_root)?;
    Ok(ActionResult {
        success: true,
        message: format!("Installed pre-commit hook under {}", repo_root.display()),
        details: vec![],
    })
}

pub fn install_ai_hooks(path: &str, options: InstallAiHooksOptions) -> Result<ActionResult> {
    let root = resolve_project_root(path)?;
    ensure_desktop_project_root_allowed(&root)?;
    if options.global {
        anyhow::bail!("desktop setup does not support global AI hook installation");
    }
    if !options.dry_run {
        safety::require_project_policy(&root, "hooks install-ai")?;
    }
    let tool = options.tool.as_deref().map(parse_ai_tool).transpose()?;
    let summaries = install_ai_with_summaries(
        &root,
        tool,
        InstallAiOptions {
            audit: options.audit,
            log_blocked: options.log_blocked,
            dry_run: options.dry_run,
            global: options.global,
            fail_closed: options.fail_closed,
            apply_deny: options.apply_deny,
            apply_sandbox: options.apply_sandbox,
        },
    )?;
    Ok(ActionResult {
        success: true,
        message: if options.dry_run {
            "AI hook preview ready".to_string()
        } else {
            "AI hooks installed".to_string()
        },
        details: summaries,
    })
}

pub fn apply_ai_hook_settings(
    path: &str,
    options: ApplyAiHookSettingsOptions,
) -> Result<ActionResult> {
    let root = resolve_project_root(path)?;
    ensure_desktop_project_root_allowed(&root)?;
    safety::require_project_policy(&root, "hooks install-ai")?;
    let before = ai_safety_applied_from(&collect_project_check_status(&root));
    let summaries = configure_ai_with_summaries(&root, desktop_configure_ai_options(&options))?;
    let after = ai_safety_applied_from(&collect_project_check_status(&root));
    let message = if ai_safety_applied_matches(&before, &after) {
        "No AI editor safety changes were required".to_string()
    } else if ai_safety_fully_disabled(&after) && ai_safety_any_enabled(&before) {
        "AI editor safety settings removed".to_string()
    } else {
        "AI editor settings applied".to_string()
    };
    Ok(ActionResult {
        success: true,
        message,
        details: summaries,
    })
}

fn ai_safety_applied_matches(a: &AiSafetyAppliedStatus, b: &AiSafetyAppliedStatus) -> bool {
    a.scan_hooks_claude_code == b.scan_hooks_claude_code
        && a.scan_hooks_cursor == b.scan_hooks_cursor
        && a.scan_hooks_codex == b.scan_hooks_codex
        && a.scan_hooks_copilot == b.scan_hooks_copilot
        && a.scan_hooks_antigravity == b.scan_hooks_antigravity
        && a.scan_hooks_windsurf == b.scan_hooks_windsurf
        && a.claude_deny == b.claude_deny
        && a.claude_sandbox == b.claude_sandbox
        && a.codex_sandbox == b.codex_sandbox
}

fn ai_safety_fully_disabled(status: &AiSafetyAppliedStatus) -> bool {
    !status.scan_hooks_claude_code
        && !status.scan_hooks_cursor
        && !status.scan_hooks_codex
        && !status.scan_hooks_copilot
        && !status.scan_hooks_antigravity
        && !status.scan_hooks_windsurf
        && !status.claude_deny
        && !status.claude_sandbox
        && !status.codex_sandbox
}

fn ai_safety_any_enabled(status: &AiSafetyAppliedStatus) -> bool {
    !ai_safety_fully_disabled(status)
}

fn current_ai_hook_settings_options(root: &Path) -> ApplyAiHookSettingsOptions {
    let applied = ai_safety_applied_from(&collect_project_check_status(root));
    ApplyAiHookSettingsOptions {
        scan_hooks_claude_code: applied.scan_hooks_claude_code,
        scan_hooks_cursor: applied.scan_hooks_cursor,
        scan_hooks_codex: applied.scan_hooks_codex,
        scan_hooks_copilot: applied.scan_hooks_copilot,
        scan_hooks_antigravity: applied.scan_hooks_antigravity,
        scan_hooks_windsurf: applied.scan_hooks_windsurf,
        cursor_fail_closed: true,
        claude_deny: applied.claude_deny,
        claude_sandbox: applied.claude_sandbox,
        codex_sandbox: applied.codex_sandbox,
    }
}

pub fn apply_recommended_fixes(
    path: &str,
    options: ApplyRecommendedFixesOptions,
) -> Result<ActionResult> {
    let root = resolve_project_root(path)?;
    ensure_desktop_project_root_allowed(&root)?;
    if options.fix_ids.is_empty() {
        anyhow::bail!("at least one recommended fix must be selected");
    }

    let policy_exists = root.join("shk.toml").is_file();
    validate_recommended_fixes(&options, policy_exists)?;
    let mut details = Vec::new();
    let mut applied = 0usize;

    for fix_id in &options.fix_ids {
        let result = apply_recommended_fix(&root, fix_id, policy_exists, &options)?;
        if !result.details.is_empty() || result.success {
            details.push(format!("[{}] {}", fix_id, result.message));
            details.extend(result.details.into_iter().map(|line| format!("  {line}")));
            applied += 1;
        }
    }

    Ok(ActionResult {
        success: true,
        message: if applied == 0 {
            "No changes were required for the selected fixes".to_string()
        } else {
            format!("Applied {applied} recommended fix(es)")
        },
        details,
    })
}

fn validate_recommended_fixes(
    options: &ApplyRecommendedFixesOptions,
    policy_exists: bool,
) -> Result<()> {
    for fix_id in &options.fix_ids {
        match fix_id.as_str() {
            "ignore" => {
                if !policy_exists {
                    anyhow::bail!("ignore fix requires shk.toml");
                }
                if options.ignore_targets.is_empty() {
                    anyhow::bail!("ignore fix requires at least one target");
                }
            }
            "git_pre_commit" => {
                if !policy_exists {
                    anyhow::bail!("pre-commit fix requires shk.toml");
                }
            }
            "ai_hooks" => {
                if !policy_exists {
                    anyhow::bail!("AI hook fix requires shk.toml");
                }
            }
            "ai_claude_deny" => {
                if !policy_exists {
                    anyhow::bail!("Claude deny fix requires shk.toml");
                }
            }
            "ai_claude_sandbox" => {
                if !policy_exists {
                    anyhow::bail!("Claude sandbox fix requires shk.toml");
                }
            }
            "ai_codex_sandbox" => {
                if !policy_exists {
                    anyhow::bail!("Codex sandbox fix requires shk.toml");
                }
            }
            "workflows" => {
                if !policy_exists {
                    anyhow::bail!("workflows fix requires shk.toml");
                }
            }
            "env_encrypt" => {
                if !policy_exists {
                    anyhow::bail!("env encrypt fix requires shk.toml");
                }
                if options.env_targets.as_ref().is_some_and(Vec::is_empty) {
                    anyhow::bail!("env encrypt fix requires at least one target");
                }
            }
            "npm_hardening" => {}
            other => anyhow::bail!("unknown recommended fix id: {other}"),
        }
    }
    Ok(())
}

fn apply_recommended_fix(
    root: &Path,
    fix_id: &str,
    policy_exists: bool,
    options: &ApplyRecommendedFixesOptions,
) -> Result<ActionResult> {
    match fix_id {
        "ignore" => {
            if !policy_exists {
                anyhow::bail!("ignore fix requires shk.toml");
            }
            fix_doctor_ignore(
                &root.display().to_string(),
                FixDoctorIgnoreOptions {
                    targets: options.ignore_targets.clone(),
                },
            )
        }
        "git_pre_commit" => {
            if !policy_exists {
                anyhow::bail!("pre-commit fix requires shk.toml");
            }
            install_pre_commit_hook(&root.display().to_string())
        }
        "ai_hooks" => {
            if !policy_exists {
                anyhow::bail!("AI hook fix requires shk.toml");
            }
            install_ai_hooks(
                &root.display().to_string(),
                desktop_default_install_ai_hooks_options(),
            )
        }
        "ai_claude_deny" => {
            if !policy_exists {
                anyhow::bail!("Claude deny fix requires shk.toml");
            }
            let mut ai_options = current_ai_hook_settings_options(root);
            ai_options.claude_deny = true;
            apply_ai_hook_settings(&root.display().to_string(), ai_options)
        }
        "ai_claude_sandbox" => {
            if !policy_exists {
                anyhow::bail!("Claude sandbox fix requires shk.toml");
            }
            let mut ai_options = current_ai_hook_settings_options(root);
            ai_options.claude_sandbox = true;
            apply_ai_hook_settings(&root.display().to_string(), ai_options)
        }
        "ai_codex_sandbox" => {
            if !policy_exists {
                anyhow::bail!("Codex sandbox fix requires shk.toml");
            }
            let mut ai_options = current_ai_hook_settings_options(root);
            ai_options.codex_sandbox = true;
            apply_ai_hook_settings(&root.display().to_string(), ai_options)
        }
        "workflows" => {
            if !policy_exists {
                anyhow::bail!("workflows fix requires shk.toml");
            }
            fix_doctor_workflows(&root.display().to_string())
        }
        "env_encrypt" => {
            if !policy_exists {
                anyhow::bail!("env encrypt fix requires shk.toml");
            }
            encrypt_env_files_in_place(root, options.env_targets.as_deref())
        }
        "npm_hardening" => apply_npm_hardening(
            &root.display().to_string(),
            ApplyNpmHardeningOptions { enabled: true },
        ),
        other => anyhow::bail!("unknown recommended fix id: {other}"),
    }
}

/// Encrypt plaintext/mixed env files at the project root in place.
/// Eligibility is recomputed server-side; `requested` (client-selected file
/// names) can only narrow that set, never extend it. Plaintext values never
/// leave the process — the private key goes to the configured secret store
/// and only ciphertext is written back.
fn encrypt_env_files_in_place(root: &Path, requested: Option<&[String]>) -> Result<ActionResult> {
    let eligible = env_encrypt_targets(&collect_env_file_statuses(root));
    let selected = select_env_encrypt_names(eligible, requested)?;
    let resolution = resolve_env_encrypt_target_paths(root, selected)?;
    if resolution.targets.is_empty() && resolution.skipped.is_empty() {
        return Ok(ActionResult {
            success: true,
            message: "No plaintext env files to encrypt".to_string(),
            details: vec![],
        });
    }
    let target_count = resolution.targets.len();
    let skipped_count = resolution.skipped.len();
    let mut details = resolution.skipped;
    let mut encrypted = 0usize;
    for target in &resolution.targets {
        let result = crate::commands::env::encrypt(
            root,
            EnvEncryptArgs {
                file: target.path.clone(),
                output: None,
                in_place: true,
                env: target.env.clone(),
                key: None,
                force: false,
                remove_source: false,
            },
        );
        match result {
            Ok(()) => {
                encrypted += 1;
                details.push(format!(
                    "Encrypted {} in place with the {} environment key",
                    target.name, target.env
                ));
            }
            // Keep going: one file refusing (e.g. ciphertext under a foreign
            // key) must not block encrypting the others.
            Err(err) => details.push(format!("Failed to encrypt {}: {err:#}", target.name)),
        }
    }
    if encrypted == 0 {
        anyhow::bail!("failed to encrypt env files: {}", details.join("; "));
    }
    Ok(ActionResult {
        success: true,
        message: if encrypted == target_count && skipped_count == 0 {
            format!("Encrypted {encrypted} env file(s) in place")
        } else {
            "Partially encrypted env files; review remaining items".to_string()
        },
        details,
    })
}

/// Narrow the freshly recomputed eligible set to the client's selection.
/// An omitted `requested` list from an older frontend means every eligible
/// file. An explicit list can only narrow that set. A requested name outside
/// the eligible set is a stale or forged client view — refuse rather than
/// guess.
fn select_env_encrypt_names(
    eligible: Vec<String>,
    requested: Option<&[String]>,
) -> Result<Vec<String>> {
    let Some(requested) = requested else {
        return Ok(eligible);
    };
    anyhow::ensure!(
        !requested.is_empty(),
        "env encrypt fix requires at least one target"
    );
    for name in requested {
        anyhow::ensure!(
            eligible.contains(name),
            "env file {name} is not eligible for encryption (missing, renamed, or already encrypted); refresh the project status and retry"
        );
    }
    // Iterate the recomputed list, not `requested`, so ordering is stable and
    // duplicate client entries collapse.
    Ok(eligible
        .into_iter()
        .filter(|name| requested.contains(name))
        .collect())
}

#[derive(Debug, Eq, PartialEq)]
struct EnvEncryptTarget {
    name: String,
    path: PathBuf,
    env: String,
}

#[derive(Debug, Eq, PartialEq)]
struct EnvEncryptResolution {
    targets: Vec<EnvEncryptTarget>,
    skipped: Vec<String>,
}

/// Follow dotenv's conventional file naming: `.env` and `.env.local` use the
/// default key, `.env.<environment>` uses that environment, and
/// `.env.<environment>.local` is the local override for the same environment.
fn env_label_for_dotenv_name(name: &str) -> Result<String> {
    if matches!(name, ".env" | ".env.local") {
        return Ok("default".to_string());
    }
    let suffix = name
        .strip_prefix(".env.")
        .ok_or_else(|| anyhow::anyhow!("unsupported env file name {name}"))?;
    let label = suffix.strip_suffix(".local").unwrap_or(suffix);
    anyhow::ensure!(
        !label.is_empty()
            && label
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_'),
        "cannot infer a safe environment key from {name}; encrypt it explicitly with `shk env encrypt --env <name>`"
    );
    Ok(label.to_ascii_lowercase())
}

/// Resolve report names back to the exact directory entries that were
/// inspected. Refuse ambiguous, symlinked, or unreadable targets before the
/// first file is mutated.
fn resolve_env_encrypt_target_paths(
    root: &Path,
    names: Vec<String>,
) -> Result<EnvEncryptResolution> {
    let entries = fs::read_dir(root)
        .with_context(|| format!("read env file directory {}", root.display()))?
        .collect::<std::io::Result<Vec<_>>>()?;
    let mut targets = Vec::with_capacity(names.len());
    let mut skipped = Vec::new();
    let mut seen_names = Vec::with_capacity(names.len());
    for name in names {
        anyhow::ensure!(
            !seen_names.contains(&name),
            "refusing to encrypt ambiguous env file name {name}"
        );
        seen_names.push(name.clone());
        let matches = entries
            .iter()
            .filter(|entry| entry.file_name().to_str() == Some(name.as_str()))
            .collect::<Vec<_>>();
        anyhow::ensure!(
            matches.len() == 1,
            "refusing to encrypt ambiguous env file name {name}"
        );
        let path = matches[0].path();
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("inspect env file {}", path.display()))?;
        anyhow::ensure!(
            metadata.file_type().is_file(),
            "refusing to encrypt non-regular env file {}",
            path.display()
        );
        fs::read_to_string(&path)
            .with_context(|| format!("read env file {} before encryption", path.display()))?;
        match env_label_for_dotenv_name(&name) {
            Ok(label) => targets.push(EnvEncryptTarget {
                name,
                path,
                env: label,
            }),
            Err(err) => skipped.push(format!("Skipped {name}: {err}")),
        }
    }
    Ok(EnvEncryptResolution { targets, skipped })
}

pub fn fix_doctor_ignore(path: &str, options: FixDoctorIgnoreOptions) -> Result<ActionResult> {
    let root = resolve_project_root(path)?;
    ensure_desktop_project_root_allowed(&root)?;
    if options.targets.is_empty() {
        anyhow::bail!("at least one ignore fix target is required");
    }
    let result = fix_ignore_patterns(&root, &options.targets)?;
    if result.already_ok {
        return Ok(ActionResult {
            success: true,
            message: "Required ignore patterns are already present".to_string(),
            details: vec![],
        });
    }
    let total_patterns = result
        .updates
        .iter()
        .map(|update| update.appended.len())
        .sum::<usize>();
    let mut details = Vec::new();
    for update in &result.updates {
        details.push(format!("{}:", update.relative_path));
        for pat in &update.appended {
            details.push(format!("  + {pat}"));
        }
    }
    Ok(ActionResult {
        success: true,
        message: format!(
            "Appended {total_patterns} pattern(s) across {} file(s)",
            result.updates.len()
        ),
        details,
    })
}

pub fn fix_doctor_workflows(path: &str) -> Result<ActionResult> {
    let root = resolve_project_root(path)?;
    ensure_desktop_project_root_allowed(&root)?;
    safety::require_project_policy(&root, "doctor workflows --fix")?;

    let fixes = workflow_hardening::fix_all(&root)?;
    let total: usize = fixes.iter().map(|f| f.fixed_steps).sum();
    let details = fixes
        .iter()
        .map(|f| {
            format!(
                "{}: hardened {} checkout step(s)",
                f.relative_path, f.fixed_steps
            )
        })
        .collect();

    Ok(ActionResult {
        success: true,
        message: if total == 0 {
            "All actions/checkout steps already set persist-credentials: false".to_string()
        } else {
            format!("Hardened {total} checkout step(s)")
        },
        details,
    })
}

pub fn apply_npm_hardening(path: &str, options: ApplyNpmHardeningOptions) -> Result<ActionResult> {
    let root = resolve_project_root(path)?;
    ensure_desktop_project_root_allowed(&root)?;
    let before = npm_hardening::status(&root);
    if !npm_hardening_desktop_applicable(&before) {
        return Ok(ActionResult {
            success: true,
            message: "No package-manager project detected at the selected folder".to_string(),
            details: vec![],
        });
    }
    for path in before.apply_paths() {
        safety::ensure_writable_path_allowed(path)?;
    }
    if options.enabled {
        npm_hardening::apply(&root)?;
    } else {
        npm_hardening::unapply(&root)?;
    }
    let after = npm_hardening::status(&root);
    let settings_ok = npm_hardening_settings_ok(&after);
    let remaining = npm_auto_recommendations(&after);
    Ok(ActionResult {
        success: if options.enabled {
            settings_ok
        } else {
            !settings_ok
        },
        message: if !options.enabled {
            "npm supply-chain hardening removed".to_string()
        } else if settings_ok {
            "npm supply-chain hardening applied".to_string()
        } else {
            "Applied partial npm hardening; review remaining items".to_string()
        },
        details: remaining,
    })
}

pub fn install_skills(path: &str, options: InstallSkillsOptions) -> Result<ActionResult> {
    let root = resolve_project_root(path)?;
    ensure_desktop_project_root_allowed(&root)?;
    if options.global {
        anyhow::bail!("desktop setup does not support global skill installation");
    }
    if !options.dry_run {
        safety::require_project_policy(&root, "skills install")?;
    }
    let tool = options.tool.as_deref().map(parse_skill_tool).transpose()?;
    let details = crate::commands::skills::install_for(
        &root,
        SkillsInstallArgs {
            tool,
            global: options.global,
            dry_run: options.dry_run,
            force: options.force,
        },
    )?;
    Ok(ActionResult {
        success: true,
        message: if options.dry_run {
            "Skills install preview ready".to_string()
        } else {
            "Skills installed".to_string()
        },
        details,
    })
}

fn is_shk_cli_installed() -> bool {
    !shk_executable::candidates_in_dirs(
        shk_executable_search_dirs(),
        std::env::var_os("PATHEXT").as_deref(),
    )
    .is_empty()
}

/// `PATH` entries first, then the install locations documented in
/// `docs/installation.md`.
///
/// A macOS app bundle launched from Finder inherits launchd's `PATH`, which
/// carries none of the shell-profile entries, so a CLI installed by the script
/// installer into `~/.cargo/bin` or by Homebrew is invisible to a plain `PATH`
/// lookup even though the user's shell finds it.
fn shk_executable_search_dirs() -> Vec<PathBuf> {
    let path = std::env::var_os("PATH");
    let cargo_home = std::env::var_os("CARGO_HOME")
        .filter(|cargo_home| !cargo_home.is_empty())
        .map(PathBuf::from);
    shk_search_dirs_from(path.as_deref(), cargo_home, desktop_home_dir())
}

fn shk_search_dirs_from(
    path: Option<&OsStr>,
    cargo_home: Option<PathBuf>,
    home: Option<PathBuf>,
) -> Vec<PathBuf> {
    let mut dirs: Vec<_> = path
        .map(std::env::split_paths)
        .into_iter()
        .flatten()
        .collect();
    // Script installer: `$CARGO_HOME/bin`, or `~/.cargo/bin` when unset.
    if let Some(cargo_home) = cargo_home {
        dirs.push(cargo_home.join("bin"));
    } else if let Some(home) = home {
        dirs.push(home.join(".cargo").join("bin"));
    }
    // Homebrew's Apple silicon prefix.
    #[cfg(target_os = "macos")]
    dirs.push(PathBuf::from("/opt/homebrew/bin"));
    // Intel Homebrew and npm's default global prefix both land here, and the
    // desktop app ships for Linux too, so this is not macOS-only.
    #[cfg(not(windows))]
    dirs.push(PathBuf::from("/usr/local/bin"));
    let mut seen = HashSet::new();
    dirs.retain(|dir| seen.insert(dir.clone()));
    dirs
}

fn desktop_home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
        .or_else(dirs::home_dir)
}

pub fn resolve_project_root(path: &str) -> Result<PathBuf> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        anyhow::bail!("project path is empty");
    }
    let p = PathBuf::from(trimmed);
    if !p.is_dir() {
        anyhow::bail!("project path is not a directory: {}", p.display());
    }
    Ok(fs::canonicalize(&p).unwrap_or(p))
}

fn ensure_desktop_project_root_allowed(root: &Path) -> Result<()> {
    if root.parent().is_none() {
        anyhow::bail!("desktop setup refuses to modify filesystem roots");
    }

    if let Some(home) = desktop_home_dir().and_then(|home| fs::canonicalize(home).ok())
        && fs::canonicalize(root)
            .map(|canonical_root| canonical_root == home)
            .unwrap_or(false)
    {
        anyhow::bail!("desktop setup refuses to modify the home directory as a project");
    }

    Ok(())
}

fn build_project_status(root: &Path) -> ProjectStatus {
    let policy_path = root.join("shk.toml");
    let git_root = git::discover_repo_root(root);
    let policy_exists = policy_path.is_file();
    let checks = collect_project_check_status(root);
    let recommended_fixes = build_recommended_fixes(&checks, policy_exists, git_root.is_some());
    ProjectStatus {
        path: root.display().to_string(),
        policy: PolicyStatus {
            exists: policy_exists,
            path: policy_path
                .is_file()
                .then(|| policy_path.display().to_string()),
        },
        git: GitStatus {
            is_repo: git_root.is_some(),
            root: git_root.as_ref().map(|p| p.display().to_string()),
        },
        hooks: build_hooks_status(root, git_root.as_deref()),
        doctor: build_doctor_status_from(&checks),
        ai_safety_applied: ai_safety_applied_from(&checks),
        npm_hardening: build_npm_status_from(&checks.npm),
        skills: build_skills_status(root),
        env_files: checks.env_files.clone(),
        ignore_fix_targets: ignore_fix_target_statuses(root)
            .into_iter()
            .map(|entry| IgnoreFixTargetDto {
                name: entry.name,
                exists: entry.exists,
            })
            .collect(),
        recommended_fixes,
        cli_installed: is_shk_cli_installed(),
    }
}

fn collect_project_check_status(root: &Path) -> ProjectCheckStatus {
    let ai_tools = ai_tool_statuses(root, false);
    let scan_hooks_for = |tool: &str| {
        ai_tools
            .iter()
            .find(|entry| entry.tool == tool)
            .is_some_and(|entry| entry.installed)
    };
    ProjectCheckStatus {
        git_pre_commit: has_shk_pre_commit(root),
        ai_managed_hooks: has_all_managed_ai_hooks(root),
        scan_hooks_claude_code: scan_hooks_for("claude-code"),
        scan_hooks_cursor: scan_hooks_for("cursor"),
        scan_hooks_codex: scan_hooks_for("codex"),
        scan_hooks_copilot: scan_hooks_for("copilot"),
        scan_hooks_antigravity: scan_hooks_for("antigravity"),
        scan_hooks_windsurf: scan_hooks_for("windsurf"),
        ignore: collect_ignore_status(root),
        claude: collect_claude_permissions_status(root),
        codex: collect_codex_config_status(root),
        env_files: collect_env_file_statuses(root),
        npm: npm_hardening::status(root),
        workflows: workflow_hardening::scan_workflows(root),
    }
}

/// Env files the in-place encrypt fix would touch (anything not fully encrypted).
fn env_encrypt_targets(files: &[EnvFileStatus]) -> Vec<String> {
    files
        .iter()
        .filter(|file| file.state != EnvFileState::Encrypted)
        .map(|file| file.name.clone())
        .collect()
}

fn has_all_managed_ai_hooks(root: &Path) -> bool {
    let statuses = ai_tool_statuses(root, false);
    !statuses.is_empty() && statuses.iter().all(|status| status.installed)
}

fn build_hooks_status(root: &Path, git_root: Option<&Path>) -> HooksStatus {
    let pre_commit_path = git_root.map(|r| r.join(".git/hooks/pre-commit"));
    let pre_commit_installed = has_shk_pre_commit(root);
    HooksStatus {
        pre_commit: PreCommitStatus {
            installed: pre_commit_installed,
            hook_path: pre_commit_path.map(|p| p.display().to_string()),
            is_git_repo: git_root.is_some(),
        },
        ai_tools: ai_tool_statuses(root, false),
    }
}

fn ai_tool_statuses(root: &Path, global: bool) -> Vec<AiHookToolStatus> {
    [
        AiTool::ClaudeCode,
        AiTool::Codex,
        AiTool::Cursor,
        AiTool::Copilot,
        AiTool::Antigravity,
        AiTool::Windsurf,
    ]
    .into_iter()
    .filter_map(|tool| {
        let config_path = resolve_ai_config_path(tool, root, global).ok()?;
        let installed = config_path.is_file()
            && fs::read_to_string(&config_path)
                .map(|s| has_managed_hook_marker(tool, &s))
                .unwrap_or(false);
        Some(AiHookToolStatus {
            tool: tool.kebab_str().to_string(),
            config_path: config_path.display().to_string(),
            installed,
        })
    })
    .collect()
}

fn has_managed_hook_marker(tool: AiTool, content: &str) -> bool {
    content.contains(MANAGED_MARKER_JSON)
        || content.contains(MANAGED_MARKER_SH)
        || ((tool == AiTool::Copilot || tool == AiTool::Windsurf)
            && content.contains("shk scan")
            && content.contains(&format!("--hook-mode {}", tool.kebab_str())))
}

fn resolve_ai_config_path(tool: AiTool, root: &Path, global: bool) -> Result<PathBuf> {
    crate::hooks::resolve_ai_config_path(tool, root, global)
}

fn build_recommended_fixes(
    checks: &ProjectCheckStatus,
    policy_exists: bool,
    is_git_repo: bool,
) -> Vec<RecommendedFixDto> {
    let mut fixes = Vec::new();
    if policy_exists
        && checks.ignore.load_error.is_none()
        && !checks.ignore.missing_patterns.is_empty()
    {
        fixes.push(RecommendedFixDto {
            id: "ignore".into(),
            severity: "warn".into(),
            message: format!(
                "Append {} missing ignore pattern(s) to selected ignore files",
                checks.ignore.missing_patterns.len()
            ),
            requires_policy: true,
            default_selected: true,
        });
    }
    if policy_exists && is_git_repo && !checks.git_pre_commit {
        fixes.push(RecommendedFixDto {
            id: "git_pre_commit".into(),
            severity: "warn".into(),
            message: "Install Git pre-commit hook (shk scan --staged)".into(),
            requires_policy: true,
            default_selected: true,
        });
    }
    if policy_exists && !checks.ai_managed_hooks {
        fixes.push(RecommendedFixDto {
            id: "ai_hooks".into(),
            severity: "warn".into(),
            message: "Install managed AI scan hooks for Cursor, Claude Code, Codex, Copilot, Antigravity, and Windsurf"
                .into(),
            requires_policy: true,
            default_selected: true,
        });
    }
    if policy_exists && checks.claude.settings_exists && !checks.claude.deny_ok {
        fixes.push(RecommendedFixDto {
            id: "ai_claude_deny".into(),
            severity: "warn".into(),
            message: "Merge recommended Claude Code permissions.deny entries".into(),
            requires_policy: true,
            default_selected: true,
        });
    }
    if policy_exists && checks.claude.settings_exists && !checks.claude.sandbox_ok {
        fixes.push(RecommendedFixDto {
            id: "ai_claude_sandbox".into(),
            severity: "warn".into(),
            message: "Enable Claude Code project sandbox settings".into(),
            requires_policy: true,
            default_selected: true,
        });
    }
    if policy_exists
        && checks.codex.config_exists
        && (!checks.codex.sandbox_ok || !checks.codex.approval_ok)
    {
        fixes.push(RecommendedFixDto {
            id: "ai_codex_sandbox".into(),
            severity: "warn".into(),
            message: "Harden Codex config (sandbox_mode, approval_policy)".into(),
            requires_policy: true,
            default_selected: true,
        });
    }
    if policy_exists && checks.workflows.iter().any(|s| !s.ok()) {
        let flagged = checks.workflows.iter().filter(|s| !s.ok()).count();
        fixes.push(RecommendedFixDto {
            id: "workflows".into(),
            severity: "warn".into(),
            message: format!(
                "Add persist-credentials: false to actions/checkout in {flagged} workflow file(s)"
            ),
            requires_policy: true,
            default_selected: true,
        });
    }
    let env_targets = env_encrypt_targets(&checks.env_files);
    if policy_exists && !env_targets.is_empty() {
        fixes.push(RecommendedFixDto {
            id: "env_encrypt".into(),
            severity: "warn".into(),
            message: format!(
                "Encrypt {} env file(s) in place with file-name-derived environment keys",
                env_targets.len()
            ),
            requires_policy: true,
            // Opt-in: encrypting .env changes the local dev workflow
            // (values must be read via `shk env run` / dotenvx afterwards).
            default_selected: false,
        });
    }
    if npm_hardening_desktop_applicable(&checks.npm) && !npm_hardening_settings_ok(&checks.npm) {
        fixes.push(RecommendedFixDto {
            id: "npm_hardening".into(),
            severity: "info".into(),
            message: "Apply npm/package-manager supply-chain hardening".into(),
            requires_policy: false,
            default_selected: true,
        });
    }
    fixes
}

fn build_doctor_status_from(checks: &ProjectCheckStatus) -> DoctorStatus {
    let codex_config_ok =
        !checks.codex.config_exists || (checks.codex.sandbox_ok && checks.codex.approval_ok);

    let mut issues = Vec::new();
    if !checks.git_pre_commit {
        issues.push(DoctorIssue {
            id: "git_pre_commit".into(),
            severity: "warn".into(),
            message: "Git pre-commit hook is not installed".into(),
        });
    }
    if !checks.ai_managed_hooks {
        issues.push(DoctorIssue {
            id: "ai_hooks".into(),
            severity: "warn".into(),
            message: "AI managed hooks not found — install via Setup".into(),
        });
    }
    if let Some(err) = &checks.ignore.load_error {
        issues.push(DoctorIssue {
            id: "ignore_policy".into(),
            severity: "warn".into(),
            message: format!("Unable to load policy for ignore check: {err}"),
        });
    }
    for pat in &checks.ignore.missing_patterns {
        issues.push(DoctorIssue {
            id: format!("ignore:{pat}"),
            severity: "warn".into(),
            message: format!("Missing ignore pattern: {pat}"),
        });
    }
    if checks.claude.settings_exists && !checks.claude.deny_ok {
        issues.push(DoctorIssue {
            id: "ai_claude_deny".into(),
            severity: "warn".into(),
            message: "Claude Code permissions.deny entries are incomplete".into(),
        });
    }
    if checks.claude.settings_exists && !checks.claude.sandbox_ok {
        issues.push(DoctorIssue {
            id: "ai_claude_sandbox".into(),
            severity: "warn".into(),
            message: "Claude Code sandbox settings are incomplete".into(),
        });
    }
    if checks.codex.config_exists && !codex_config_ok {
        issues.push(DoctorIssue {
            id: "ai_codex_sandbox".into(),
            severity: "warn".into(),
            message: "Codex config needs sandbox or hook hardening".into(),
        });
    }
    for file in &checks.env_files {
        match file.state {
            EnvFileState::Encrypted => {}
            EnvFileState::Plaintext => issues.push(DoctorIssue {
                id: format!("env:{}", file.name),
                severity: "warn".into(),
                message: format!("Plaintext env file detected: {}", file.name),
            }),
            EnvFileState::Mixed => issues.push(DoctorIssue {
                id: format!("env_mixed:{}", file.name),
                severity: "warn".into(),
                message: format!(
                    "Encrypted env file contains plaintext values: {}",
                    file.name
                ),
            }),
        }
    }
    for rec in npm_auto_recommendations(&checks.npm) {
        issues.push(DoctorIssue {
            id: "npm_hardening".into(),
            severity: "warn".into(),
            message: rec,
        });
    }
    for status in &checks.workflows {
        let flagged = status.findings().count();
        if flagged > 0 {
            issues.push(DoctorIssue {
                id: format!("workflows:{}", status.relative_path),
                severity: "warn".into(),
                message: format!(
                    "{}: {flagged} actions/checkout step(s) missing persist-credentials: false",
                    status.relative_path
                ),
            });
        }
    }
    for rec in npm_manual_recommendations(&checks.npm) {
        issues.push(DoctorIssue {
            id: "npm_hardening".into(),
            severity: "info".into(),
            message: rec,
        });
    }

    DoctorStatus {
        git_pre_commit: checks.git_pre_commit,
        ai_managed_hooks: checks.ai_managed_hooks,
        ignore_ok: checks.ignore.load_error.is_none() && checks.ignore.missing_patterns.is_empty(),
        missing_ignore_patterns: checks.ignore.missing_patterns.clone(),
        claude_deny_ok: !checks.claude.settings_exists || checks.claude.deny_ok,
        claude_sandbox_ok: !checks.claude.settings_exists || checks.claude.sandbox_ok,
        codex_config_ok,
        env_applicable: !checks.env_files.is_empty(),
        env_ok: env_encrypt_targets(&checks.env_files).is_empty(),
        npm_ok: npm_doctor_ok(&checks.npm),
        workflows_applicable: !checks.workflows.is_empty(),
        workflows_ok: checks.workflows.iter().all(|s| s.ok()),
        issues,
    }
}

fn ai_safety_applied_from(checks: &ProjectCheckStatus) -> AiSafetyAppliedStatus {
    AiSafetyAppliedStatus {
        scan_hooks_claude_code: checks.scan_hooks_claude_code,
        scan_hooks_cursor: checks.scan_hooks_cursor,
        scan_hooks_codex: checks.scan_hooks_codex,
        scan_hooks_copilot: checks.scan_hooks_copilot,
        scan_hooks_antigravity: checks.scan_hooks_antigravity,
        scan_hooks_windsurf: checks.scan_hooks_windsurf,
        claude_deny: checks.claude.settings_exists && checks.claude.deny_ok,
        claude_sandbox: checks.claude.settings_exists && checks.claude.sandbox_ok,
        codex_sandbox: checks.codex.config_exists
            && checks.codex.sandbox_ok
            && checks.codex.approval_ok,
    }
}

fn build_npm_status_from(status: &npm_hardening::NpmHardeningStatus) -> NpmHardeningStatusDto {
    let applicable = npm_hardening_desktop_applicable(status);
    NpmHardeningStatusDto {
        has_projects: applicable,
        ok: status.ok(),
        settings_ok: npm_hardening_settings_ok(status),
        package_count: status.package_dirs.len(),
        missing_lockfiles: status
            .package_dirs_without_lockfile
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
        ignore_scripts_ok: status.package_scripts_ok(),
        age_gates_ok: status.age_gates_ok(),
        dependency_bot_cooldown_ok: status.dependency_bot_cooldown_ok(),
        recommendations: if applicable {
            npm_auto_recommendations(status)
        } else {
            vec![]
        },
    }
}

fn npm_hardening_desktop_applicable(status: &npm_hardening::NpmHardeningStatus) -> bool {
    status.has_npm_projects() && status.root_project
}

fn npm_hardening_settings_ok(status: &npm_hardening::NpmHardeningStatus) -> bool {
    !status.has_npm_projects() || (status.package_scripts_ok() && status.age_gates_ok())
}

fn npm_doctor_ok(status: &npm_hardening::NpmHardeningStatus) -> bool {
    if !status.has_npm_projects() {
        return true;
    }
    if npm_hardening_desktop_applicable(status) {
        npm_hardening_settings_ok(status)
    } else {
        status.ok()
    }
}

fn npm_auto_recommendations(status: &npm_hardening::NpmHardeningStatus) -> Vec<String> {
    if !status.has_npm_projects() {
        return vec![];
    }
    let mut recs = Vec::new();
    if !status.package_scripts_ok() {
        recs.push(format!(
            "Add ignore-scripts=true to {}",
            status.npmrc_path.display()
        ));
    }
    if !status.age_gates_ok() {
        recs.push("Configure package-manager release age gates".into());
    }
    recs
}

fn npm_manual_recommendations(status: &npm_hardening::NpmHardeningStatus) -> Vec<String> {
    if !status.has_npm_projects() {
        return vec![];
    }
    let mut recs = Vec::new();
    if !status.package_dirs_without_lockfile.is_empty() {
        recs.push("Commit lockfiles for package.json directories".into());
    }
    if !status.dependency_bot_cooldown_ok() {
        recs.push("Add Dependabot or Renovate cooldown (7 days)".into());
    }
    recs
}

fn build_skills_status(root: &Path) -> Vec<SkillStatusDto> {
    crate::commands::skills::status_entries_for(root)
        .into_iter()
        .map(|entry| SkillStatusDto {
            label: entry.label.to_string(),
            path: entry.path.map(|p| p.display().to_string()),
            installed: entry.installed,
        })
        .collect()
}

fn parse_ai_tool(value: &str) -> Result<AiTool> {
    match value {
        "claude-code" => Ok(AiTool::ClaudeCode),
        "codex" => Ok(AiTool::Codex),
        "copilot" => Ok(AiTool::Copilot),
        "cursor" => Ok(AiTool::Cursor),
        "antigravity" => Ok(AiTool::Antigravity),
        "windsurf" => Ok(AiTool::Windsurf),
        other => anyhow::bail!("unknown AI tool: {other}"),
    }
}

fn parse_audit_reason(value: &str) -> Result<AuditReasonArg> {
    match value {
        "blocked" => Ok(AuditReasonArg::Blocked),
        "finding-threshold" => Ok(AuditReasonArg::FindingThreshold),
        "action-guard" => Ok(AuditReasonArg::ActionGuard),
        other => anyhow::bail!("unknown audit reason filter: {other}"),
    }
}

fn parse_skill_tool(value: &str) -> Result<SkillTool> {
    match value {
        "claude-code" => Ok(SkillTool::ClaudeCode),
        "codex" => Ok(SkillTool::Codex),
        "copilot" => Ok(SkillTool::Copilot),
        "cursor" => Ok(SkillTool::Cursor),
        "antigravity" => Ok(SkillTool::Antigravity),
        "windsurf" => Ok(SkillTool::Windsurf),
        "all" => Ok(SkillTool::All),
        other => anyhow::bail!("unknown skill tool: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn json_string_contains(value: &serde_json::Value, needle: &str) -> bool {
        match value {
            serde_json::Value::String(value) => value.contains(needle),
            serde_json::Value::Array(values) => values
                .iter()
                .any(|value| json_string_contains(value, needle)),
            serde_json::Value::Object(values) => values
                .values()
                .any(|value| json_string_contains(value, needle)),
            _ => false,
        }
    }

    #[cfg(unix)]
    fn write_shk_executable(dir: &Path) {
        use std::os::unix::fs::PermissionsExt;

        fs::create_dir_all(dir).unwrap();
        let bin = dir.join("shk");
        fs::write(&bin, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn shk_search_dirs_prefer_cargo_home_and_preserve_path_order() {
        let home = PathBuf::from("/home/tester");
        let cargo_home = PathBuf::from("/opt/cargo");
        let path = std::env::join_paths(["/usr/bin", "/custom/bin"]).unwrap();
        let dirs = shk_search_dirs_from(Some(&path), Some(cargo_home.clone()), Some(home.clone()));

        assert_eq!(
            &dirs[..3],
            [
                PathBuf::from("/usr/bin"),
                PathBuf::from("/custom/bin"),
                cargo_home.join("bin"),
            ]
        );
        assert!(!dirs.contains(&home.join(".cargo").join("bin")), "{dirs:?}");
    }

    #[test]
    fn shk_search_dirs_use_default_cargo_bin_only_when_cargo_home_is_missing() {
        let home = PathBuf::from("/home/tester");
        let dirs = shk_search_dirs_from(None, None, Some(home.clone()));
        assert_eq!(dirs.first(), Some(&home.join(".cargo").join("bin")));
    }

    #[test]
    fn shk_search_dirs_deduplicate_without_reordering() {
        let cargo_bin = PathBuf::from("/opt/cargo/bin");
        let path = std::env::join_paths(["/usr/bin", "/opt/cargo/bin", "/usr/bin"]).unwrap();
        let dirs = shk_search_dirs_from(Some(&path), Some(PathBuf::from("/opt/cargo")), None);

        assert_eq!(
            &dirs[..2],
            [PathBuf::from("/usr/bin"), cargo_bin],
            "{dirs:?}"
        );
        assert_eq!(
            dirs.iter()
                .filter(|dir| **dir == PathBuf::from("/usr/bin"))
                .count(),
            1
        );
    }

    #[test]
    fn shk_search_dirs_tolerate_missing_path_home_and_cargo_home() {
        let dirs = shk_search_dirs_from(None, None, None);
        #[cfg(target_os = "macos")]
        assert_eq!(
            dirs,
            [
                PathBuf::from("/opt/homebrew/bin"),
                PathBuf::from("/usr/local/bin")
            ]
        );
        // The desktop app ships for Linux, where npm's default global prefix
        // puts `shk` in /usr/local/bin and a launcher's PATH may not have it.
        #[cfg(all(not(target_os = "macos"), not(windows)))]
        assert_eq!(dirs, [PathBuf::from("/usr/local/bin")]);
        #[cfg(windows)]
        assert!(dirs.is_empty(), "{dirs:?}");
    }

    #[cfg(unix)]
    #[test]
    fn shk_is_detected_in_cargo_bin_when_path_is_stripped() {
        // A macOS app bundle launched from Finder gets launchd's PATH, so the
        // shell-profile entry for ~/.cargo/bin is absent.
        let home = tempfile::tempdir().unwrap();
        let cargo_bin = home.path().join(".cargo").join("bin");
        write_shk_executable(&cargo_bin);

        let path = std::env::join_paths(["/usr/bin"]).unwrap();
        let dirs = shk_search_dirs_from(Some(&path), None, Some(home.path().to_path_buf()));
        assert!(!shk_executable::candidates_in_dirs(dirs, None).is_empty());
    }

    #[test]
    fn resolve_project_root_canonicalizes_directories_and_rejects_other_paths() {
        let dir = tempfile::tempdir().unwrap();
        let resolved = resolve_project_root(&format!("  {}  ", dir.path().display())).unwrap();
        assert_eq!(resolved, fs::canonicalize(dir.path()).unwrap());

        let file = dir.path().join("project.txt");
        fs::write(&file, "not a directory").unwrap();
        assert!(
            resolve_project_root(&file.to_string_lossy())
                .unwrap_err()
                .to_string()
                .contains("not a directory")
        );
        assert!(resolve_project_root("  ").is_err());
    }

    #[test]
    fn desktop_mask_text_uses_default_policy_without_project() {
        let out =
            mask_text_for_desktop(None, "contact test.user@example.com\n", "<input>").unwrap(); // shk-ignore pii.email
        assert!(
            out.masked_content.contains("[REDACTED]"),
            "{}",
            out.masked_content
        );
        assert!(out.findings.iter().any(|f| f.rule_id == "pii.email"));
    }

    #[test]
    fn desktop_mask_policy_status_distinguishes_project_and_default_policy() {
        let dir = tempfile::tempdir().unwrap();

        let default_status = mask_policy_status(None).unwrap();
        assert!(!default_status.uses_project_policy);
        assert!(default_status.policy_path.is_none());

        let missing_status = mask_policy_status(Some(dir.path())).unwrap();
        assert!(!missing_status.uses_project_policy);
        assert!(missing_status.policy_path.is_none());

        fs::write(dir.path().join("shk.toml"), "").unwrap();
        let project_status = mask_policy_status(Some(dir.path())).unwrap();
        assert!(project_status.uses_project_policy);
        assert_eq!(
            project_status.policy_path.as_deref(),
            Some(dir.path().join("shk.toml").to_str().unwrap())
        );
    }

    #[test]
    fn desktop_mask_text_rejects_empty_input() {
        let err = mask_text_for_desktop(None, "   ", "<input>").unwrap_err();
        assert!(err.to_string().contains("empty"), "{err}");
    }

    #[test]
    fn desktop_mask_file_masks_utf8_text() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("prompt.txt");
        fs::write(&input, "contact test.user@example.com\n").unwrap(); // shk-ignore pii.email

        let out = mask_file_for_desktop(None, &input, None).unwrap();
        assert_eq!(out.file_kind, "text");
        assert!(out.masked_content.contains("[REDACTED]"));
        assert!(out.findings.iter().any(|f| f.rule_id == "pii.email"));
        assert!(out.output_path.is_none());
    }

    #[test]
    fn desktop_mask_file_masks_csv_as_text() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("contacts.csv");
        fs::write(&input, "name,email\nalice,test.user@example.com\n").unwrap(); // shk-ignore pii.email

        let out = mask_file_for_desktop(None, &input, None).unwrap();
        assert_eq!(out.file_kind, "text");
        assert!(out.masked_content.contains("[REDACTED]"));
        assert!(out.findings.iter().any(|f| f.rule_id == "pii.email"));
    }

    #[test]
    fn desktop_mask_file_masks_shift_jis_csv() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("contacts.csv");
        let (encoded, _, had_errors) =
            encoding_rs::SHIFT_JIS.encode("名前,メール\n山田,test.user@example.com\n"); // shk-ignore pii.email
        assert!(!had_errors);
        fs::write(&input, encoded.as_ref()).unwrap();

        let out = mask_file_for_desktop(None, &input, None).unwrap();
        assert_eq!(out.file_kind, "text");
        assert!(
            out.masked_content.contains("山田"),
            "{}",
            out.masked_content
        );
        assert!(out.masked_content.contains("[REDACTED]"));
        assert!(out.findings.iter().any(|f| f.rule_id == "pii.email"));
    }

    #[test]
    fn desktop_mask_file_masks_utf8_bom_csv() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("contacts.csv");
        let mut encoded = vec![0xef, 0xbb, 0xbf];
        encoded.extend_from_slice(b"name,email\nalice,test.user@example.com\n"); // shk-ignore pii.email
        fs::write(&input, encoded).unwrap();

        let out = mask_file_for_desktop(None, &input, None).unwrap();
        assert!(!out.masked_content.starts_with('\u{feff}'));
        assert!(out.masked_content.contains("[REDACTED]"));
        assert!(out.findings.iter().any(|f| f.rule_id == "pii.email"));
    }

    #[test]
    fn desktop_mask_file_masks_utf16le_csv() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("contacts.csv");
        let mut encoded = vec![0xff, 0xfe];
        // shk-ignore-next-line pii.email
        for unit in "名前,メール\n山田,test.user@example.com\n".encode_utf16() {
            encoded.extend_from_slice(&unit.to_le_bytes());
        }
        fs::write(&input, encoded).unwrap();

        let out = mask_file_for_desktop(None, &input, None).unwrap();
        assert_eq!(out.file_kind, "text");
        assert!(
            out.masked_content.contains("山田"),
            "{}",
            out.masked_content
        );
        assert!(out.masked_content.contains("[REDACTED]"));
        assert!(out.findings.iter().any(|f| f.rule_id == "pii.email"));
    }

    #[test]
    fn desktop_mask_file_masks_pdf_text_layer() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("report.pdf");
        create_minimal_pdf(&input, "contact test.user@example.com"); // shk-ignore pii.email

        let out = mask_file_for_desktop(None, &input, None).unwrap();
        assert_eq!(out.file_kind, "pdf");
        assert!(
            out.masked_content.contains("[REDACTED]"),
            "{}",
            out.masked_content
        );
        assert!(out.findings.iter().any(|f| f.rule_id == "pii.email"));
        assert!(out.output_path.is_none());
    }

    #[test]
    fn desktop_mask_file_rejects_pdf_without_text_layer() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("empty.pdf");
        create_minimal_pdf(&input, "");

        let err = mask_file_for_desktop(None, &input, None).unwrap_err();
        assert!(err.to_string().contains("no extractable text"), "{err}");
    }

    #[test]
    fn desktop_mask_text_rejects_content_over_configured_size_limit() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("shk.toml");
        fs::write(&policy_path, "[scan]\nmax_file_size_bytes = 8\n").unwrap();
        let err = mask_text_for_desktop(Some(dir.path()), "0123456789", "stdin").unwrap_err();
        assert!(err.to_string().contains("size limit"), "{err}");
    }

    #[test]
    fn desktop_mask_file_rejects_text_over_configured_size_limit() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        fs::create_dir_all(&project).unwrap();
        fs::write(
            project.join("shk.toml"),
            "[scan]\nmax_file_size_bytes = 8\n",
        )
        .unwrap();
        let input = project.join("large.txt");
        fs::write(&input, "012345678901234567890").unwrap();

        let err = mask_file_for_desktop(Some(&project), &input, None).unwrap_err();
        assert!(err.to_string().contains("file size limit"), "{err}");
    }

    #[test]
    fn desktop_mask_file_rejects_output_outside_project_root() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join("shk.toml"), "[scan]\n").unwrap();
        let input = project.join("input.txt");
        fs::write(&input, "contact test.user@example.com").unwrap(); // shk-ignore pii.email
        let output = dir.path().join("outside.txt");

        let err = mask_file_for_desktop(Some(&project), &input, Some(&output)).unwrap_err();
        assert!(err.to_string().contains("outside"), "{err}");
        assert!(!output.exists());
    }

    #[test]
    fn desktop_mask_file_rejects_pdf_output_path() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("report.pdf");
        let output = dir.path().join("masked.pdf");
        create_minimal_pdf(&input, "contact test.user@example.com"); // shk-ignore pii.email

        let err = mask_file_for_desktop(None, &input, Some(&output)).unwrap_err();
        assert!(err.to_string().contains("not supported"), "{err}");
        assert!(!output.exists());
    }

    #[test]
    fn desktop_mask_file_rejects_pdf_over_configured_size_limit() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("report.pdf");
        create_minimal_pdf(&input, "contact test.user@example.com"); // shk-ignore pii.email
        let mut policy = Policy::default();
        policy.scan.max_file_size_bytes = 16;

        let err = mask_pdf_file_for_desktop(&policy, &input, None, "report.pdf").unwrap_err();
        assert!(err.to_string().contains("file size limit"), "{err}");
    }

    #[test]
    fn desktop_mask_file_rejects_fake_pdf_extension() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("report.pdf");
        fs::write(&input, "contact test.user@example.com").unwrap(); // shk-ignore pii.email

        let err = mask_file_for_desktop(None, &input, None).unwrap_err();
        assert!(err.to_string().contains("no PDF header"), "{err}");
    }

    fn create_minimal_pdf(path: &std::path::Path, text: &str) {
        let escaped = text
            .replace('\\', r"\\")
            .replace('(', r"\(")
            .replace(')', r"\)");
        let stream = format!("BT /F1 12 Tf 72 720 Td ({escaped}) Tj ET\n");
        let objects = [
            "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_string(),
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>".to_string(),
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_string(),
            format!("<< /Length {} >>\nstream\n{stream}endstream", stream.len()),
        ];

        let mut body = String::from("%PDF-1.4\n");
        let mut offsets = Vec::new();
        for (idx, object) in objects.iter().enumerate() {
            offsets.push(body.len());
            body.push_str(&format!("{} 0 obj\n{object}\nendobj\n", idx + 1));
        }

        let xref_offset = body.len();
        body.push_str("xref\n0 6\n0000000000 65535 f \n");
        for offset in offsets {
            body.push_str(&format!("{offset:010} 00000 n \n"));
        }
        body.push_str(&format!(
            "trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n"
        ));

        fs::write(path, body).unwrap();
    }

    #[test]
    fn desktop_mask_file_rejects_binary_input() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("data.bin");
        fs::write(&input, [0, 1, 2, 3, 0xff]).unwrap();

        let err = mask_file_for_desktop(None, &input, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("binary or unsupported text encoding"),
            "{err}"
        );
    }

    #[test]
    fn desktop_mask_file_writes_text_output_when_requested() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("prompt.txt");
        let output = dir.path().join("masked.txt");
        fs::write(&input, "contact test.user@example.com\n").unwrap(); // shk-ignore pii.email

        let out = mask_file_for_desktop(None, &input, Some(&output)).unwrap();
        assert_eq!(out.output_path.as_deref(), Some(output.to_str().unwrap()));
        let written = fs::read_to_string(&output).unwrap();
        assert!(written.contains("[REDACTED]"), "{written}");
    }

    #[test]
    fn clone_remote_validation_accepts_https_and_ssh() {
        assert_eq!(
            validate_git_remote_url("https://github.com/example/project.git").unwrap(),
            "https://github.com/example/project.git"
        );
        assert_eq!(
            validate_git_remote_url("git@github.com:example/project.git").unwrap(), // shk-ignore pii.email
            "git@github.com:example/project.git" // shk-ignore pii.email
        );
    }

    #[test]
    fn clone_remote_validation_rejects_local_and_option_urls() {
        for remote in [
            "",
            "--upload-pack=evil",
            "file:///tmp/repo.git",
            "../repo",
            "http://example.com/repo.git",
            "git://example.com/repo.git",
            "https://user:token@example.com/repo.git", // shk-ignore pii.email
            "https://example.com/repo.git?token=secret",
        ] {
            assert!(validate_git_remote_url(remote).is_err(), "{remote}");
        }
    }

    #[test]
    fn clone_repository_name_is_derived_from_remote() {
        assert_eq!(
            repository_name_from_remote("https://github.com/example/project.git").unwrap(),
            "project"
        );
        assert_eq!(
            repository_name_from_remote("git@github.com:example/project").unwrap(), // shk-ignore pii.email
            "project"
        );
    }

    #[test]
    fn clone_parent_must_be_an_existing_directory() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");
        assert!(resolve_clone_parent(missing.to_str().unwrap()).is_err());
        assert_eq!(
            resolve_clone_parent(dir.path().to_str().unwrap()).unwrap(),
            fs::canonicalize(dir.path()).unwrap()
        );
    }

    #[test]
    fn doctor_status_reports_mixed_encrypted_env_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join(".env"),
            "DOTENV_PUBLIC_KEY=pub\nTOKEN=encrypted:ciphertext\nDEBUG_TOKEN=plain\n",
        )
        .unwrap();

        let checks = collect_project_check_status(dir.path());
        let status = build_doctor_status_from(&checks);

        assert!(!status.env_ok);
        assert!(status.env_applicable);
        assert!(
            status
                .issues
                .iter()
                .any(|issue| issue.id == "env_mixed:.env"
                    && issue
                        .message
                        .contains("Encrypted env file contains plaintext values")),
            "{:?}",
            status.issues
        );
    }

    #[test]
    fn project_status_reports_env_files_without_values() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join(".env"),
            "API_KEY=placeholder\nDB_URL=localhost\n",
        )
        .unwrap();
        fs::write(
            dir.path().join(".env.production"),
            "DOTENV_PUBLIC_KEY=pub\nTOKEN=encrypted:ciphertext\n",
        )
        .unwrap();

        let status = build_project_status(dir.path());
        assert_eq!(status.env_files.len(), 2);

        let plain = &status.env_files[0];
        assert_eq!(plain.name, ".env");
        assert_eq!(plain.state, EnvFileState::Plaintext);
        assert_eq!(plain.plaintext_keys, vec!["API_KEY", "DB_URL"]);

        let encrypted = &status.env_files[1];
        assert_eq!(encrypted.name, ".env.production");
        assert_eq!(encrypted.state, EnvFileState::Encrypted);
        assert!(encrypted.plaintext_keys.is_empty());
        assert_eq!(encrypted.encrypted_key_count, 1);

        let serialized = serde_json::to_string(&status.env_files).unwrap();
        assert!(
            !serialized.contains("placeholder") && !serialized.contains("localhost"),
            "env file reports must never carry values: {serialized}"
        );
        // Wire format contract with the desktop frontend.
        assert!(
            serialized.contains(r#""state":"plaintext""#),
            "{serialized}"
        );
        assert!(
            serialized.contains(r#""state":"encrypted""#),
            "{serialized}"
        );
        assert!(serialized.contains(r#""plaintextKeys""#), "{serialized}");
        assert!(
            serialized.contains(r#""encryptedKeyCount""#),
            "{serialized}"
        );
    }

    #[test]
    fn recommended_fixes_offer_opt_in_env_encrypt() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("shk.toml"), "\n").unwrap();
        fs::write(dir.path().join(".env"), "API_KEY=plain\n").unwrap();

        let checks = collect_project_check_status(dir.path());
        let fixes = build_recommended_fixes(&checks, true, false);
        let env_fix = fixes
            .iter()
            .find(|fix| fix.id == "env_encrypt")
            .expect("env_encrypt fix offered");
        assert!(env_fix.requires_policy);
        assert!(
            !env_fix.default_selected,
            "in-place encryption must stay opt-in"
        );

        // Without a policy the fix is not offered and apply is rejected.
        let no_policy_fixes = build_recommended_fixes(&checks, false, false);
        assert!(no_policy_fixes.iter().all(|fix| fix.id != "env_encrypt"));
        let err = validate_recommended_fixes(
            &ApplyRecommendedFixesOptions {
                fix_ids: vec!["env_encrypt".into()],
                ignore_targets: vec![],
                env_targets: Some(vec![]),
            },
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("requires shk.toml"));
    }

    #[test]
    fn env_encrypt_selection_distinguishes_legacy_and_explicit_empty_payloads() {
        let legacy: ApplyRecommendedFixesOptions = serde_json::from_value(serde_json::json!({
            "fixIds": ["env_encrypt"],
            "ignoreTargets": []
        }))
        .unwrap();
        assert_eq!(legacy.env_targets, None);

        let explicit: ApplyRecommendedFixesOptions = serde_json::from_value(serde_json::json!({
            "fixIds": ["env_encrypt"],
            "ignoreTargets": [],
            "envTargets": []
        }))
        .unwrap();
        assert_eq!(explicit.env_targets, Some(vec![]));

        let err = validate_recommended_fixes(&explicit, true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires at least one target"), "{err}");
    }

    #[test]
    fn recommended_fixes_skip_env_encrypt_when_fully_encrypted() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("shk.toml"), "\n").unwrap();
        fs::write(
            dir.path().join(".env"),
            "DOTENV_PUBLIC_KEY=pub\nTOKEN=encrypted:ciphertext\n",
        )
        .unwrap();

        let checks = collect_project_check_status(dir.path());
        let fixes = build_recommended_fixes(&checks, true, false);
        assert!(fixes.iter().all(|fix| fix.id != "env_encrypt"));
    }

    #[test]
    fn env_encrypt_infers_conventional_environment_names() {
        assert_eq!(env_label_for_dotenv_name(".env").unwrap(), "default");
        assert_eq!(env_label_for_dotenv_name(".env.local").unwrap(), "default");
        assert_eq!(
            env_label_for_dotenv_name(".env.production").unwrap(),
            "production"
        );
        assert_eq!(
            env_label_for_dotenv_name(".env.production.local").unwrap(),
            "production"
        );
        assert!(env_label_for_dotenv_name(".env.production.eu").is_err());
    }

    #[test]
    fn env_encrypt_skips_uninferrable_names_without_blocking_valid_targets() {
        let project = tempfile::tempdir().unwrap();
        fs::write(project.path().join(".env"), "API_KEY=plain\n").unwrap();
        fs::write(project.path().join(".env.pre-prod"), "API_KEY=plain\n").unwrap();

        let names = env_encrypt_targets(&collect_env_file_statuses(project.path()));
        let resolution = resolve_env_encrypt_target_paths(project.path(), names).unwrap();

        assert_eq!(resolution.targets.len(), 1);
        assert_eq!(resolution.targets[0].name, ".env");
        assert_eq!(resolution.targets[0].env, "default");
        assert_eq!(resolution.skipped.len(), 1);
        assert!(resolution.skipped[0].contains("Skipped .env.pre-prod"));
        assert!(resolution.skipped[0].contains("shk env encrypt --env <name>"));
    }

    #[test]
    fn env_encrypt_fails_when_every_plaintext_file_requires_manual_selection() {
        let project = tempfile::tempdir().unwrap();
        fs::write(project.path().join(".env.backup.2024"), "API_KEY=plain\n").unwrap();

        let err = encrypt_env_files_in_place(project.path(), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("Skipped .env.backup.2024"), "{err}");
        assert!(err.contains("shk env encrypt --env <name>"), "{err}");
    }

    #[test]
    fn select_env_encrypt_names_defaults_to_every_eligible_file_when_omitted() {
        let eligible = vec![".env".to_string(), ".env.production".to_string()];
        assert_eq!(
            select_env_encrypt_names(eligible.clone(), None).unwrap(),
            eligible
        );
    }

    #[test]
    fn select_env_encrypt_names_rejects_an_explicit_empty_selection() {
        let eligible = vec![".env".to_string()];
        let err = select_env_encrypt_names(eligible, Some(&[]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires at least one target"), "{err}");
    }

    #[test]
    fn select_env_encrypt_names_narrows_dedupes_and_keeps_server_order() {
        let eligible = vec![
            ".env".to_string(),
            ".env.ci".to_string(),
            ".env.production".to_string(),
        ];
        let requested = vec![
            ".env.production".to_string(),
            ".env".to_string(),
            ".env".to_string(),
        ];
        assert_eq!(
            select_env_encrypt_names(eligible, Some(&requested)).unwrap(),
            vec![".env".to_string(), ".env.production".to_string()]
        );
    }

    #[test]
    fn select_env_encrypt_names_rejects_ineligible_requests() {
        let eligible = vec![".env".to_string()];
        for stale in [".env.production", ".env.example", "../.env", ".env\u{ff}"] {
            let requested = [stale.to_string()];
            let err = select_env_encrypt_names(eligible.clone(), Some(&requested))
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("not eligible for encryption"),
                "{stale}: {err}"
            );
        }
    }

    #[test]
    fn env_encrypt_fix_rejects_stale_client_selection() {
        let project = tempfile::tempdir().unwrap();
        fs::write(project.path().join(".env"), "API_KEY=plain\n").unwrap();

        let requested = [".env.production".to_string()];
        let err = encrypt_env_files_in_place(project.path(), Some(&requested))
            .unwrap_err()
            .to_string();
        assert!(err.contains("not eligible for encryption"), "{err}");
        assert_eq!(
            fs::read_to_string(project.path().join(".env")).unwrap(),
            "API_KEY=plain\n",
            "nothing may be encrypted when the selection is stale"
        );
    }

    #[cfg(unix)]
    #[test]
    fn env_encrypt_fix_refuses_symlinked_files_before_writing() {
        use std::os::unix::fs::symlink;

        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let source = outside.path().join("shared.env");
        fs::write(&source, "API_KEY=plain\n").unwrap();
        symlink(&source, project.path().join(".env")).unwrap();

        let err = encrypt_env_files_in_place(project.path(), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("non-regular env file"), "{err}");
        assert_eq!(fs::read_to_string(&source).unwrap(), "API_KEY=plain\n");
        assert!(project.path().join(".env").is_symlink());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn env_encrypt_fix_refuses_lossy_filename_collisions() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let project = tempfile::tempdir().unwrap();
        let non_utf8 = OsString::from_vec(b".env.\xff".to_vec());
        fs::write(project.path().join(non_utf8), "FIRST=plain\n").unwrap();
        fs::write(project.path().join(".env.�"), "SECOND=plain\n").unwrap();

        let names = env_encrypt_targets(&collect_env_file_statuses(project.path()));
        let err = resolve_env_encrypt_target_paths(project.path(), names)
            .unwrap_err()
            .to_string();
        assert!(err.contains("ambiguous env file name"), "{err}");
        assert_eq!(
            fs::read_to_string(project.path().join(".env.�")).unwrap(),
            "SECOND=plain\n"
        );
    }

    #[test]
    fn doctor_status_skips_env_check_when_no_env_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("README.md"), "demo\n").unwrap();

        let checks = collect_project_check_status(dir.path());
        let status = build_doctor_status_from(&checks);

        assert!(!status.env_applicable);
        assert!(status.env_ok);
        assert!(
            !status
                .issues
                .iter()
                .any(|issue| issue.id.starts_with("env:") || issue.id.starts_with("env_mixed:")),
            "{:?}",
            status.issues
        );
    }

    #[test]
    fn doctor_status_reports_ignore_policy_load_errors() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("shk.toml"), "[scan\nbroken = true\n").unwrap();

        let status = build_project_status(dir.path());

        assert!(!status.doctor.ignore_ok, "{status:?}");
        assert!(
            status
                .doctor
                .issues
                .iter()
                .any(|issue| issue.id == "ignore_policy"),
            "{:?}",
            status.doctor.issues
        );
    }

    #[test]
    fn desktop_ai_hooks_reject_global_install() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("shk.toml"), "").unwrap();

        let err = install_ai_hooks(
            dir.path().to_str().unwrap(),
            InstallAiHooksOptions {
                audit: false,
                log_blocked: false,
                dry_run: true,
                global: true,
                tool: Some("cursor".to_string()),
                fail_closed: false,
                apply_deny: true,
                apply_sandbox: true,
            },
        )
        .unwrap_err();

        assert!(err.to_string().contains("does not support global"), "{err}");
    }

    #[test]
    fn desktop_skills_reject_global_install() {
        let dir = tempfile::tempdir().unwrap();

        let err = install_skills(
            dir.path().to_str().unwrap(),
            InstallSkillsOptions {
                tool: None,
                global: true,
                dry_run: true,
                force: false,
            },
        )
        .unwrap_err();

        assert!(err.to_string().contains("does not support global"), "{err}");
    }

    #[test]
    fn desktop_skills_require_project_policy_for_install() {
        let dir = tempfile::tempdir().unwrap();

        let err = install_skills(
            dir.path().to_str().unwrap(),
            InstallSkillsOptions {
                tool: None,
                global: false,
                dry_run: false,
                force: true,
            },
        )
        .unwrap_err();

        assert!(
            err.to_string().contains("requires a project shk.toml"),
            "{err}"
        );
        assert!(!dir.path().join(".claude").exists());
        assert!(!dir.path().join(".agents").exists());
    }

    #[test]
    fn doctor_status_reports_and_fixes_workflow_checkout() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("shk.toml"), "").unwrap();
        let workflows = dir.path().join(".github/workflows");
        fs::create_dir_all(&workflows).unwrap();
        fs::write(
            workflows.join("ci.yml"),
            "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v6\n",
        )
        .unwrap();

        let before = build_project_status(dir.path());
        assert!(before.doctor.workflows_applicable, "{before:?}");
        assert!(!before.doctor.workflows_ok, "{before:?}");
        assert!(
            before
                .doctor
                .issues
                .iter()
                .any(|i| i.id == "workflows:.github/workflows/ci.yml"),
            "{:?}",
            before.doctor.issues
        );
        assert!(
            before.recommended_fixes.iter().any(|f| f.id == "workflows"),
            "{:?}",
            before.recommended_fixes
        );

        let result = fix_doctor_workflows(dir.path().to_str().unwrap()).unwrap();
        assert!(result.success, "{result:?}");

        let after = build_project_status(dir.path());
        assert!(after.doctor.workflows_ok, "{after:?}");
        assert!(
            !after.recommended_fixes.iter().any(|f| f.id == "workflows"),
            "{:?}",
            after.recommended_fixes
        );
        let contents = fs::read_to_string(workflows.join("ci.yml")).unwrap();
        assert!(
            contents.contains("persist-credentials: false"),
            "{contents}"
        );
    }

    #[test]
    fn doctor_status_skips_workflows_when_no_checkout() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("shk.toml"), "").unwrap();

        let status = build_project_status(dir.path());
        assert!(!status.doctor.workflows_applicable, "{status:?}");
        assert!(status.doctor.workflows_ok, "{status:?}");
    }

    #[test]
    fn desktop_fix_doctor_ignore_appends_missing_patterns() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("shk.toml"), "[doctor.ignore]\n").unwrap();

        let result = fix_doctor_ignore(
            dir.path().to_str().unwrap(),
            FixDoctorIgnoreOptions {
                targets: vec![".gitignore".to_string()],
            },
        )
        .unwrap();
        assert!(result.success, "{result:?}");
        assert!(!result.details.is_empty(), "{result:?}");

        let status = build_project_status(dir.path());
        assert!(status.doctor.ignore_ok);
        assert!(status.doctor.missing_ignore_patterns.is_empty());
    }

    #[test]
    fn desktop_fix_doctor_ignore_supports_selected_targets() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("shk.toml"), "[doctor.ignore]\n").unwrap();

        let result = fix_doctor_ignore(
            dir.path().to_str().unwrap(),
            FixDoctorIgnoreOptions {
                targets: vec![
                    ".cursorignore".to_string(),
                    ".cursorindexingignore".to_string(),
                ],
            },
        )
        .unwrap();
        assert!(result.success, "{result:?}");
        assert!(
            result.details.iter().any(|line| line == ".cursorignore:"),
            "{result:?}"
        );
        assert!(
            result
                .details
                .iter()
                .any(|line| line == ".cursorindexingignore:"),
            "{result:?}"
        );
        assert!(!dir.path().join(".gitignore").exists());

        let status = build_project_status(dir.path());
        assert!(status.doctor.ignore_ok);
        assert_eq!(status.ignore_fix_targets.len(), 10);
    }

    #[test]
    fn desktop_recommended_fixes_validate_before_mutating() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("shk.toml"), "[doctor.ignore]\n").unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"name":"demo","packageManager":"npm@10.0.0"}"#,
        )
        .unwrap();
        fs::write(dir.path().join("package-lock.json"), "{}").unwrap();

        let err = apply_recommended_fixes(
            dir.path().to_str().unwrap(),
            ApplyRecommendedFixesOptions {
                fix_ids: vec!["npm_hardening".to_string(), "ignore".to_string()],
                ignore_targets: vec![],
                env_targets: None,
            },
        )
        .unwrap_err();

        assert!(err.to_string().contains("ignore fix requires"), "{err}");
        assert!(
            !dir.path().join(".npmrc").exists(),
            "prevalidation should prevent partial npm hardening writes"
        );
    }

    #[test]
    fn desktop_npm_hardening_marks_auto_settings_ready() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"name":"demo","packageManager":"npm@10.0.0"}"#,
        )
        .unwrap();
        fs::write(dir.path().join("package-lock.json"), "{}").unwrap();

        let result = apply_npm_hardening(
            dir.path().to_str().unwrap(),
            ApplyNpmHardeningOptions { enabled: true },
        )
        .unwrap();
        assert!(result.success, "{result:?}");
        assert_eq!(result.message, "npm supply-chain hardening applied");
        assert!(result.details.is_empty(), "{result:?}");

        let status = build_project_status(dir.path());
        assert!(status.npm_hardening.settings_ok, "{status:?}");
        assert!(!status.npm_hardening.ok, "{status:?}");
        assert!(
            status.npm_hardening.recommendations.is_empty(),
            "{status:?}"
        );
        assert!(status.doctor.npm_ok, "{status:?}");
        assert!(
            status
                .doctor
                .issues
                .iter()
                .any(|issue| issue.message.contains("Dependabot")
                    || issue.message.contains("Renovate")),
            "{status:?}"
        );
        assert!(
            !status
                .recommended_fixes
                .iter()
                .any(|fix| fix.id == "npm_hardening"),
            "{status:?}"
        );
    }

    #[test]
    fn desktop_npm_hardening_can_be_removed() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"name":"demo","packageManager":"pnpm@11.0.0"}"#,
        )
        .unwrap();

        apply_npm_hardening(
            dir.path().to_str().unwrap(),
            ApplyNpmHardeningOptions { enabled: true },
        )
        .unwrap();
        let result = apply_npm_hardening(
            dir.path().to_str().unwrap(),
            ApplyNpmHardeningOptions { enabled: false },
        )
        .unwrap();

        assert!(result.success, "{result:?}");
        let status = build_project_status(dir.path());
        assert!(!status.npm_hardening.settings_ok, "{status:?}");
        assert!(
            status
                .recommended_fixes
                .iter()
                .any(|fix| fix.id == "npm_hardening"),
            "{status:?}"
        );
    }

    #[test]
    fn desktop_npm_hardening_hides_nested_pnpm_from_repo_root() {
        let dir = tempfile::tempdir().unwrap();
        let app = dir.path().join("apps/web");
        fs::create_dir_all(&app).unwrap();
        fs::write(
            app.join("package.json"),
            r#"{"name":"web","packageManager":"pnpm@11.0.0"}"#,
        )
        .unwrap();
        fs::write(
            app.join("pnpm-workspace.yaml"),
            "onlyBuiltDependencies:\n  - esbuild\n",
        )
        .unwrap();

        let status = build_project_status(dir.path());
        assert!(!status.npm_hardening.has_projects, "{status:?}");
        assert!(!status.npm_hardening.settings_ok, "{status:?}");
        assert!(!status.npm_hardening.age_gates_ok, "{status:?}");
        assert!(
            status.npm_hardening.recommendations.is_empty(),
            "{status:?}"
        );
        assert!(
            !status
                .recommended_fixes
                .iter()
                .any(|fix| fix.id == "npm_hardening"),
            "{status:?}"
        );
    }

    #[test]
    fn desktop_claude_sandbox_is_recommended_and_applied() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("shk.toml"), "").unwrap();
        fs::create_dir_all(dir.path().join(".claude")).unwrap();
        fs::write(dir.path().join(".claude/settings.json"), "{}").unwrap();

        let before = build_project_status(dir.path());
        assert!(!before.doctor.claude_sandbox_ok, "{before:?}");
        assert!(
            before
                .recommended_fixes
                .iter()
                .any(|fix| fix.id == "ai_claude_sandbox"),
            "{before:?}"
        );

        let result = install_ai_hooks(
            dir.path().to_str().unwrap(),
            InstallAiHooksOptions {
                audit: false,
                log_blocked: false,
                dry_run: false,
                global: false,
                tool: Some("claude-code".to_string()),
                fail_closed: false,
                apply_deny: false,
                apply_sandbox: true,
            },
        )
        .unwrap();

        assert!(result.success, "{result:?}");
        let after = build_project_status(dir.path());
        assert!(after.doctor.claude_sandbox_ok, "{after:?}");
    }

    #[test]
    fn desktop_ai_hooks_are_recommended_when_only_one_tool_is_installed() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("shk.toml"), "").unwrap();
        fs::create_dir_all(dir.path().join(".claude")).unwrap();
        fs::write(
            dir.path().join(".claude/settings.json"),
            r#"{"hooks":{"PreToolUse":[{"_shk_managed":true}]}}"#,
        )
        .unwrap();

        let status = build_project_status(dir.path());
        assert!(!status.doctor.ai_managed_hooks, "{status:?}");
        assert!(
            status
                .recommended_fixes
                .iter()
                .any(|fix| fix.id == "ai_hooks"),
            "{status:?}"
        );
    }

    #[test]
    fn desktop_recommended_claude_deny_does_not_install_scan_hooks() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("shk.toml"), "").unwrap();
        fs::create_dir_all(dir.path().join(".claude")).unwrap();
        fs::write(dir.path().join(".claude/settings.json"), "{}").unwrap();

        let result = apply_recommended_fixes(
            dir.path().to_str().unwrap(),
            ApplyRecommendedFixesOptions {
                fix_ids: vec!["ai_claude_deny".to_string()],
                ignore_targets: vec![],
                env_targets: None,
            },
        )
        .unwrap();

        assert!(result.success, "{result:?}");
        let settings = fs::read_to_string(dir.path().join(".claude/settings.json")).unwrap();
        assert!(settings.contains("\"permissions\""), "{settings}");
        assert!(!settings.contains("_shk_managed"), "{settings}");
    }

    #[test]
    fn desktop_recommended_claude_deny_preserves_existing_scan_hooks() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("shk.toml"), "").unwrap();
        fs::create_dir_all(dir.path().join(".claude")).unwrap();
        fs::write(
            dir.path().join(".claude/settings.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "hooks": {
                    "PreToolUse": [{
                        "_shk_managed": true,
                        "matcher": "Read",
                        "hooks": [{ "type": "command", "command": "shk scan --hook-mode claude-code" }]
                    }]
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let result = apply_recommended_fixes(
            dir.path().to_str().unwrap(),
            ApplyRecommendedFixesOptions {
                fix_ids: vec!["ai_claude_deny".to_string()],
                ignore_targets: vec![],
                env_targets: None,
            },
        )
        .unwrap();

        assert!(result.success, "{result:?}");
        let settings = fs::read_to_string(dir.path().join(".claude/settings.json")).unwrap();
        assert!(settings.contains("\"permissions\""), "{settings}");
        assert!(settings.contains("--hook-mode claude-code"), "{settings}");
        let parsed: serde_json::Value = serde_json::from_str(&settings).unwrap();
        let canonical_root = fs::canonicalize(dir.path()).unwrap();
        assert!(
            json_string_contains(&parsed, "\"${CLAUDE_PROJECT_DIR:-.}\""),
            "portable project root arg missing: {settings}"
        );
        assert!(
            !json_string_contains(&parsed, &canonical_root.to_string_lossy()),
            "machine-local path must not leak into committed settings: {settings}"
        );
    }

    #[test]
    fn desktop_ai_hook_settings_sync_to_selected_state() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("shk.toml"), "").unwrap();
        fs::create_dir_all(dir.path().join(".claude")).unwrap();
        fs::write(
            dir.path().join(".claude/settings.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "hooks": {
                    "PreToolUse": [{
                        "_shk_managed": true,
                        "matcher": "Read",
                        "hooks": [{ "type": "command", "command": "shk scan --hook-mode claude-code" }]
                    }]
                },
                "permissions": {
                    "deny": ["Bash(rm -rf *)"]
                },
                "sandbox": {
                    "enabled": true,
                    "failIfUnavailable": true,
                    "allowUnsandboxedCommands": false,
                    "filesystem": {
                        "denyRead": ["~/"],
                        "allowRead": ["."]
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let result = apply_ai_hook_settings(
            dir.path().to_str().unwrap(),
            ApplyAiHookSettingsOptions {
                scan_hooks_claude_code: false,
                scan_hooks_cursor: false,
                scan_hooks_antigravity: false,
                scan_hooks_windsurf: false,
                scan_hooks_codex: false,
                scan_hooks_copilot: false,
                cursor_fail_closed: true,
                claude_deny: false,
                claude_sandbox: false,
                codex_sandbox: false,
            },
        )
        .unwrap();
        assert_eq!(result.message, "AI editor safety settings removed");

        let settings = fs::read_to_string(dir.path().join(".claude/settings.json")).unwrap();
        assert!(
            !settings.contains("shk scan --hook-mode claude-code"),
            "{settings}"
        );
        assert!(settings.contains("Bash(rm -rf *)"), "{settings}");
        assert!(!settings.contains("allowUnsandboxedCommands"), "{settings}");
    }

    #[cfg(unix)]
    #[test]
    fn desktop_setup_rejects_filesystem_root() {
        let err = init_policy(
            "/",
            InitPolicyOptions {
                strict: false,
                force: false,
            },
        )
        .unwrap_err();

        assert!(err.to_string().contains("filesystem roots"), "{err}");
    }

    #[test]
    fn desktop_apply_ai_hook_settings_installs_log_blocked_scan_hooks() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("shk.toml"), "").unwrap();

        let result = apply_ai_hook_settings(
            dir.path().to_str().unwrap(),
            ApplyAiHookSettingsOptions {
                scan_hooks_claude_code: true,
                scan_hooks_cursor: false,
                scan_hooks_antigravity: false,
                scan_hooks_windsurf: false,
                scan_hooks_codex: false,
                scan_hooks_copilot: false,
                cursor_fail_closed: true,
                claude_deny: false,
                claude_sandbox: false,
                codex_sandbox: false,
            },
        )
        .unwrap();
        assert!(result.success, "{result:?}");

        let settings = fs::read_to_string(dir.path().join(".claude/settings.json")).unwrap();
        assert!(
            settings.contains("--log-blocked"),
            "desktop setup should install log-blocked hooks by default: {settings}"
        );
    }

    #[test]
    fn desktop_ai_managed_hooks_require_all_supported_tools() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".claude")).unwrap();
        fs::write(
            dir.path().join(".claude/settings.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "hooks": {
                    "PreToolUse": [{
                        "_shk_managed": true,
                        "hooks": [{ "type": "command", "command": "shk scan --hook-mode claude-code" }]
                    }]
                }
            }))
            .unwrap(),
        )
        .unwrap();
        fs::create_dir_all(dir.path().join(".cursor")).unwrap();
        fs::write(
            dir.path().join(".cursor/hooks.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "version": 1,
                "hooks": {
                    "beforeShellExecution": [{
                        "_shk_managed": true,
                        "command": "shk scan --hook-mode cursor"
                    }]
                }
            }))
            .unwrap(),
        )
        .unwrap();
        fs::create_dir_all(dir.path().join(".codex")).unwrap();
        fs::write(
            dir.path().join(".codex/config.toml"),
            "# shk-managed-start\n[[hooks.PreToolUse]]\ncommand = 'shk scan --hook-mode codex'\n# shk-managed-end\n",
        )
        .unwrap();
        fs::create_dir_all(dir.path().join(".agents")).unwrap();
        fs::write(
            dir.path().join(".agents/hooks.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "shk-security": {
                    "PreToolUse": [{
                        "_shk_managed": true,
                        "hooks": [{ "type": "command", "command": "shk scan --hook-mode antigravity" }]
                    }]
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let checks = collect_project_check_status(dir.path());

        assert!(!checks.ai_managed_hooks);
        assert!(!checks.scan_hooks_copilot);
        assert!(!checks.scan_hooks_windsurf);
    }

    #[test]
    fn desktop_apply_ai_hook_settings_installs_windsurf_toggle() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("shk.toml"), "").unwrap();

        let result = apply_ai_hook_settings(
            dir.path().to_str().unwrap(),
            ApplyAiHookSettingsOptions {
                scan_hooks_claude_code: false,
                scan_hooks_cursor: false,
                scan_hooks_antigravity: false,
                scan_hooks_windsurf: true,
                scan_hooks_codex: false,
                scan_hooks_copilot: false,
                cursor_fail_closed: true,
                claude_deny: false,
                claude_sandbox: false,
                codex_sandbox: false,
            },
        )
        .unwrap();
        assert!(result.success, "{result:?}");

        let hooks = fs::read_to_string(dir.path().join(".windsurf/hooks.json")).unwrap();
        assert!(hooks.contains("--hook-mode windsurf"), "{hooks}");
        assert!(hooks.contains("--log-blocked"), "{hooks}");
        assert!(hooks.contains("pre_write_code"), "{hooks}");

        let status = build_project_status(dir.path());
        assert!(status.ai_safety_applied.scan_hooks_windsurf);
        assert!(
            status
                .hooks
                .ai_tools
                .iter()
                .any(|tool| tool.tool == "windsurf" && tool.installed),
            "{:?}",
            status.hooks.ai_tools
        );
    }

    #[test]
    fn desktop_apply_ai_hook_settings_upgrades_legacy_hooks() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("shk.toml"), "").unwrap();
        fs::create_dir_all(dir.path().join(".claude")).unwrap();
        fs::write(
            dir.path().join(".claude/settings.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "hooks": {
                    "PreToolUse": [{
                        "_shk_managed": true,
                        "matcher": "Read",
                        "hooks": [{ "type": "command", "command": "shk scan --hook-mode claude-code" }]
                    }]
                }
            }))
            .unwrap(),
        )
        .unwrap();

        apply_ai_hook_settings(
            dir.path().to_str().unwrap(),
            ApplyAiHookSettingsOptions {
                scan_hooks_claude_code: true,
                scan_hooks_cursor: false,
                scan_hooks_antigravity: false,
                scan_hooks_windsurf: false,
                scan_hooks_codex: false,
                scan_hooks_copilot: false,
                cursor_fail_closed: true,
                claude_deny: false,
                claude_sandbox: false,
                codex_sandbox: false,
            },
        )
        .unwrap();

        let settings = fs::read_to_string(dir.path().join(".claude/settings.json")).unwrap();
        assert!(
            settings.contains("--log-blocked"),
            "legacy hooks should be upgraded to log-blocked: {settings}"
        );
    }

    #[test]
    fn desktop_default_install_ai_hooks_options_enable_log_blocked() {
        let opts = desktop_default_install_ai_hooks_options();
        assert!(opts.log_blocked);
        assert!(!opts.audit);
        assert!(opts.fail_closed);
    }

    #[test]
    fn desktop_configure_ai_options_enable_log_blocked() {
        let opts = desktop_configure_ai_options(&ApplyAiHookSettingsOptions {
            scan_hooks_claude_code: true,
            scan_hooks_cursor: false,
            scan_hooks_antigravity: false,
            scan_hooks_windsurf: true,
            scan_hooks_codex: false,
            scan_hooks_copilot: false,
            cursor_fail_closed: true,
            claude_deny: false,
            claude_sandbox: false,
            codex_sandbox: false,
        });
        assert!(opts.log_blocked);
        assert!(!opts.audit);
        assert!(opts.fail_closed);
        assert!(opts.scan_hooks_windsurf);
    }

    #[test]
    fn desktop_cursor_fail_closed_is_independent_from_codex_sandbox() {
        let opts = desktop_configure_ai_options(&ApplyAiHookSettingsOptions {
            scan_hooks_claude_code: false,
            scan_hooks_cursor: true,
            scan_hooks_antigravity: false,
            scan_hooks_windsurf: false,
            scan_hooks_codex: false,
            scan_hooks_copilot: false,
            cursor_fail_closed: true,
            claude_deny: false,
            claude_sandbox: false,
            codex_sandbox: false,
        });

        assert!(opts.scan_hooks_cursor);
        assert!(!opts.codex_sandbox);
        assert!(opts.fail_closed);
    }

    #[test]
    fn desktop_install_ai_hooks_options_default_log_blocked() {
        let opts: InstallAiHooksOptions = serde_json::from_str(
            r#"{
                "audit": false,
                "dryRun": false,
                "global": false,
                "failClosed": false,
                "applyDeny": false,
                "applySandbox": false
            }"#,
        )
        .unwrap();
        assert!(opts.log_blocked);
    }

    #[cfg(unix)]
    #[test]
    fn desktop_cli_detection_requires_executable_shk_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let shk = dir.path().join("shk");
        fs::write(&shk, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&shk, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(shk_executable::candidates_in_dirs([dir.path()], None).is_empty());

        fs::set_permissions(&shk, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            shk_executable::candidates_in_dirs([dir.path()], None),
            [shk]
        );
    }

    #[test]
    fn desktop_audit_report_when_log_missing() {
        let dir = tempfile::tempdir().unwrap();
        let report = audit_report(
            dir.path().to_str().unwrap(),
            AuditReportOptions {
                limit: 10,
                since: None,
                tool: None,
                reason: None,
                hide_paths: false,
            },
        )
        .unwrap();

        assert!(!report.log_exists);
        assert_eq!(report.summary.total_entries, 0);
        assert_eq!(report.summary.blocked_events, 0);
    }

    #[test]
    fn desktop_audit_report_filters_blocked_reason() {
        use crate::audit_log;

        let dir = tempfile::tempdir().unwrap();
        audit_log::append_line(
            dir.path(),
            serde_json::json!({"event":"blocked","reason":"finding_threshold","tool":"cursor"}),
        )
        .unwrap();
        audit_log::append_line(
            dir.path(),
            serde_json::json!({"tool":"cursor","hook":"pre","finding_count":1}),
        )
        .unwrap();

        let report = audit_report(
            dir.path().to_str().unwrap(),
            AuditReportOptions {
                limit: 10,
                since: None,
                tool: None,
                reason: Some("blocked".to_string()),
                hide_paths: false,
            },
        )
        .unwrap();

        assert_eq!(report.summary.total_entries, 1);
        assert_eq!(report.summary.blocked_events, 1);
        assert_eq!(report.summary.hook_audit_events, 0);
    }

    #[test]
    fn desktop_audit_report_rejects_invalid_reason() {
        let dir = tempfile::tempdir().unwrap();
        let err = audit_report(
            dir.path().to_str().unwrap(),
            AuditReportOptions {
                limit: 10,
                since: None,
                tool: None,
                reason: Some("not-a-reason".to_string()),
                hide_paths: false,
            },
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("invalid audit reason filter"),
            "{err}"
        );
    }

    #[test]
    fn desktop_audit_report_hides_display_paths() {
        use crate::audit_log;

        let dir = tempfile::tempdir().unwrap();
        audit_log::append_line(
            dir.path(),
            serde_json::json!({
                "event":"blocked",
                "reason":"finding_threshold",
                "ts":"2026-05-23T02:31:00Z",
                "tool":"cursor",
                "display_path":"secret.txt",
            }),
        )
        .unwrap();

        let report = audit_report(
            dir.path().to_str().unwrap(),
            AuditReportOptions {
                limit: 10,
                since: None,
                tool: None,
                reason: None,
                hide_paths: true,
            },
        )
        .unwrap();

        assert!(report.recent[0].display_path.is_none());
    }

    #[test]
    fn desktop_audit_report_summarizes_blocked_events() {
        use crate::audit_log;

        let dir = tempfile::tempdir().unwrap();
        audit_log::append_line(
            dir.path(),
            serde_json::json!({
                "event": "blocked",
                "reason": "finding_threshold",
                "tool": "cursor",
                "hook": "pre",
                "max_severity": "high",
                "finding_count": 2,
            }),
        )
        .unwrap();
        audit_log::append_line(
            dir.path(),
            serde_json::json!({"tool":"cursor","hook":"pre","finding_count":1}),
        )
        .unwrap();

        let report = audit_report(
            dir.path().to_str().unwrap(),
            AuditReportOptions {
                limit: 5,
                since: None,
                tool: None,
                reason: None,
                hide_paths: false,
            },
        )
        .unwrap();

        assert!(report.log_exists);
        assert_eq!(report.summary.blocked_events, 1);
        assert_eq!(report.summary.hook_audit_events, 1);
        assert!(!report.recent.is_empty());
    }

    #[test]
    fn desktop_clear_audit_log_removes_entries() {
        use crate::audit_log;

        let dir = tempfile::tempdir().unwrap();
        audit_log::append_line(
            dir.path(),
            serde_json::json!({
                "event": "blocked",
                "reason": "finding_threshold",
                "tool": "cursor",
            }),
        )
        .unwrap();
        assert!(dir.path().join(".shk/audit.log").is_file());

        let result = clear_audit_log(dir.path().to_str().unwrap()).unwrap();
        assert!(result.success);
        assert!(!dir.path().join(".shk/audit.log").exists());

        let report = audit_report(
            dir.path().to_str().unwrap(),
            AuditReportOptions {
                limit: 10,
                since: None,
                tool: None,
                reason: None,
                hide_paths: false,
            },
        )
        .unwrap();
        assert!(!report.log_exists);
        assert_eq!(report.summary.blocked_events, 0);
    }

    mod pseudonymize_api {
        use super::*;
        use crate::commands::pseudonymize::NO_KEY_MESSAGE;
        use crate::commands::pseudonymize::test_support::{
            MemoryStore, create_docx, create_xlsx, opener,
        };
        use std::sync::Arc;

        fn email() -> String {
            ["ada", "@", "example.com"].concat()
        }

        fn project() -> tempfile::TempDir {
            let dir = tempfile::tempdir().unwrap();
            fs::write(dir.path().join("shk.toml"), "").unwrap();
            dir
        }

        fn file_options(path: &Path) -> PseudonymizeInspectOptions {
            PseudonymizeInspectOptions {
                input_path: Some(path.display().to_string()),
                ..PseudonymizeInspectOptions::default()
            }
        }

        fn inline_options(text: &str, mode: &str) -> PseudonymizeInspectOptions {
            PseudonymizeInspectOptions {
                inline_text: Some(text.to_string()),
                mode: Some(mode.to_string()),
                ..PseudonymizeInspectOptions::default()
            }
        }

        fn choice(name: &str, kind: &str) -> PseudonymizeColumnChoice {
            PseudonymizeColumnChoice {
                index: None,
                name: name.to_string(),
                kind: kind.to_string(),
                custom_label: None,
            }
        }

        fn at(index: usize, kind: &str) -> PseudonymizeColumnChoice {
            PseudonymizeColumnChoice {
                index: Some(index),
                name: String::new(),
                kind: kind.to_string(),
                custom_label: None,
            }
        }

        #[test]
        fn positional_choices_handle_blank_and_repeated_headers() {
            let dir = project();
            let root = dir.path();
            let store = Arc::new(MemoryStore::default());
            let open = opener(Arc::clone(&store));
            // A trailing comma and a repeated header, as exports often have.
            fs::write(
                root.join("export.csv"),
                format!("Email,Email,\n{},{},note\n", email(), email()),
            )
            .unwrap();
            let table = pseudonymize_inspect(root, file_options(&root.join("export.csv")))
                .unwrap()
                .table
                .unwrap();
            assert_eq!(
                table.headers,
                vec!["Email".to_string(), "Email".to_string(), "".to_string()]
            );
            assert_eq!(table.columns.len(), 3);
            assert!(table.columns.iter().all(|column| !column.formula));

            let mut run = run_options(
                file_options(&root.join("export.csv")),
                Some(&root.join("export.pseudo.csv")),
            );
            run.input.columns = vec![at(0, "email"), at(1, "none"), at(2, "name")];
            let result = pseudonymize_run_with(root, run, &open).unwrap();
            assert_eq!(result.columns.len(), 2);
            assert_eq!(result.replaced.get("email"), Some(&1));
            let pseudo = fs::read_to_string(root.join("export.pseudo.csv")).unwrap();
            assert!(pseudo.contains(&email()), "second column stays");
            assert!(pseudo.contains("name_"), "{pseudo}");

            // Positions are exact: config and inference never add a column.
            fs::write(
                root.join("shk.toml"),
                "[pseudonymize.columns]\nEmail = \"email\"\n",
            )
            .unwrap();
            let mut only_last = run_options(
                file_options(&root.join("export.csv")),
                Some(&root.join("last.csv")),
            );
            only_last.input.columns = vec![at(2, "name")];
            let result = pseudonymize_run_with(root, only_last, &open).unwrap();
            assert_eq!(result.columns.len(), 1);
            assert_eq!(result.columns[0].index, 2);
            assert!(!result.replaced.contains_key("email"));
            fs::write(root.join("shk.toml"), "").unwrap();

            let mut twice = run_options(
                file_options(&root.join("export.csv")),
                Some(&root.join("t.csv")),
            );
            twice.input.columns = vec![at(0, "email"), at(0, "none"), at(1, "none"), at(2, "none")];
            let err = pseudonymize_run_with(root, twice, &open).unwrap_err();
            assert!(
                err.to_string().contains("column 1 was chosen twice"),
                "{err}"
            );
            let mut mixed = run_options(
                file_options(&root.join("export.csv")),
                Some(&root.join("t.csv")),
            );
            mixed.input.columns = vec![at(0, "email"), choice("Email", "none")];
            assert!(pseudonymize_run_with(root, mixed, &open).is_err());
            let mut beyond = run_options(
                file_options(&root.join("export.csv")),
                Some(&root.join("t.csv")),
            );
            beyond.input.columns =
                vec![at(0, "none"), at(1, "none"), at(2, "none"), at(7, "email")];
            let err = pseudonymize_run_with(root, beyond, &open).unwrap_err();
            assert!(err.to_string().contains("position 8"), "{err}");
            assert!(!root.join("t.csv").exists());
        }

        #[test]
        fn numeric_sheet_names_are_sent_by_position() {
            let dir = project();
            let root = dir.path();
            let workbook = r#"<workbook xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Summary" sheetId="1" r:id="rId1"/><sheet name="2024" sheetId="2" r:id="rId2"/></sheets></workbook>"#;
            let rels = r#"<Relationships><Relationship Id="rId1" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Target="worksheets/sheet2.xml"/></Relationships>"#;
            let sheet = |header: &str| {
                format!(
                    r#"<worksheet><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>{header}</t></is></c></row><row r="2"><c r="A2" t="inlineStr"><is><t>{}</t></is></c></row></sheetData></worksheet>"#,
                    email()
                )
            };
            crate::commands::pseudonymize::test_support::build_xlsx(
                &root.join("book.xlsx"),
                &[
                    ("[Content_Types].xml", "<Types/>".into()),
                    ("xl/workbook.xml", workbook.into()),
                    ("xl/_rels/workbook.xml.rels", rels.into()),
                    ("xl/worksheets/sheet1.xml", sheet("Contact")),
                    ("xl/worksheets/sheet2.xml", sheet("Mail")),
                ],
            );
            let mut by_name = file_options(&root.join("book.xlsx"));
            by_name.sheet = Some("2024".into());
            let table = pseudonymize_inspect(root, by_name).unwrap().table.unwrap();
            assert_eq!(
                table.sheets,
                vec!["Summary".to_string(), "2024".to_string()]
            );
            assert_eq!(table.selected_sheet.as_deref(), Some("2024"));
            assert_eq!(table.headers, vec!["Mail".to_string()]);

            let (sheets, selector, selected) =
                sheet_selection(&root.join("book.xlsx"), Some("2024")).unwrap();
            assert_eq!(sheets.len(), 2);
            assert_eq!(selector.as_deref(), Some("2"));
            assert_eq!(selected.as_deref(), Some("2024"));
            let (_, selector, selected) =
                sheet_selection(&root.join("book.xlsx"), Some("Nope")).unwrap();
            assert_eq!(selector.as_deref(), Some("Nope"));
            assert!(selected.is_none());
        }

        fn run_options(
            input: PseudonymizeInspectOptions,
            output: Option<&Path>,
        ) -> PseudonymizeRunOptions {
            PseudonymizeRunOptions {
                input,
                output_path: output.map(|path| path.display().to_string()),
                map_path: None,
                create_key: true,
                check_remaining: false,
            }
        }

        #[test]
        fn inspect_describes_csv_columns_with_bounded_samples() {
            let dir = project();
            let root = dir.path();
            let long = "x".repeat(PSEUDONYMIZE_PREVIEW_CELL_CHARS + 5);
            let mut body = format!("Email,Note\n{},{long}\n", email());
            for _ in 0..5 {
                body.push_str(&format!("{},short\n", email()));
            }
            fs::write(root.join("orders.csv"), &body).unwrap();

            let result =
                pseudonymize_inspect(root, file_options(&root.join("orders.csv"))).unwrap();
            assert_eq!(result.input_kind, "table-csv");
            assert_eq!(result.source_label, "orders.csv");
            let table = result.table.unwrap();
            assert!(table.has_header);
            assert_eq!(table.delimiter, ",");
            assert_eq!(table.headers, vec!["Email".to_string(), "Note".to_string()]);
            assert_eq!(table.row_count, 6);
            assert_eq!(table.sample_rows.len(), PSEUDONYMIZE_PREVIEW_ROWS);
            assert!(table.sample_rows[0][1].ends_with('…'));
            assert_eq!(
                table.sample_rows[0][1].chars().count(),
                PSEUDONYMIZE_PREVIEW_CELL_CHARS + 1
            );
            assert_eq!(table.columns.len(), 2);
            assert_eq!(table.columns[0].kind, "email");
            assert_eq!(table.columns[0].source, "inferred");
            assert!(table.columns[0].match_rate.is_some());
            assert_eq!(table.columns[1].kind, "none");
            assert_eq!(table.columns[1].source, "none");
            assert!(table.sheets.is_empty());
            assert!(!root.join(".shk").exists(), "inspect writes nothing");

            // A re-plan with the user's choices applies exactly those.
            let mut options = file_options(&root.join("orders.csv"));
            options.columns = vec![
                choice("Email", "none"),
                PseudonymizeColumnChoice {
                    index: None,
                    name: "Note".into(),
                    kind: "custom".into(),
                    custom_label: Some("note".into()),
                },
            ];
            let table = pseudonymize_inspect(root, options).unwrap().table.unwrap();
            assert_eq!(table.columns[0].kind, "none");
            assert_eq!(table.columns[1].kind, "custom");
            assert_eq!(table.columns[1].custom_label.as_deref(), Some("note"));
            assert_eq!(table.columns[1].source, "cli");

            fs::write(
                root.join("rows.tsv"),
                format!("Email\tNote\n{}\tkeep\n", email()),
            )
            .unwrap();
            let table = pseudonymize_inspect(root, file_options(&root.join("rows.tsv")))
                .unwrap()
                .table
                .unwrap();
            assert_eq!(table.delimiter, "\t");
        }

        #[test]
        fn inspect_lists_xlsx_sheets_and_classifies_text_inputs() {
            let dir = project();
            let root = dir.path();
            create_xlsx(&root.join("book.xlsx"), "Email", &email());
            let result = pseudonymize_inspect(root, file_options(&root.join("book.xlsx"))).unwrap();
            assert_eq!(result.input_kind, "table-xlsx");
            let table = result.table.unwrap();
            assert_eq!(table.sheets, vec!["Customers".to_string()]);
            assert_eq!(table.selected_sheet.as_deref(), Some("Customers"));
            assert_eq!(table.headers, vec!["Email".to_string()]);
            assert_eq!(table.sample_rows, vec![vec![email()]]);

            let mut by_index = file_options(&root.join("book.xlsx"));
            by_index.sheet = Some("1".into());
            let table = pseudonymize_inspect(root, by_index).unwrap().table.unwrap();
            assert_eq!(table.selected_sheet.as_deref(), Some("Customers"));

            fs::write(root.join("notes.md"), format!("contact {}\n", email())).unwrap();
            let result = pseudonymize_inspect(root, file_options(&root.join("notes.md"))).unwrap();
            assert_eq!(result.input_kind, "text");
            assert!(result.table.is_none());

            create_docx(&root.join("memo.docx"), &email());
            let result = pseudonymize_inspect(root, file_options(&root.join("memo.docx"))).unwrap();
            assert_eq!(result.input_kind, "text-office");
            assert!(result.table.is_none());

            let mut text = file_options(&root.join("orders.csv"));
            fs::write(root.join("orders.csv"), "Email\n").unwrap();
            text.mode = Some("text".into());
            assert_eq!(pseudonymize_inspect(root, text).unwrap().input_kind, "text");
        }

        #[test]
        fn inspect_handles_pasted_content_and_rejects_bad_input() {
            let dir = project();
            let root = dir.path();
            let pasted = format!("Email\tMember\n{}\tm-1\n", email());
            let mut options = inline_options(&pasted, "table");
            options.format = Some("tsv".into());
            let result = pseudonymize_inspect(root, options).unwrap();
            assert_eq!(result.source_label, PSEUDONYMIZE_INLINE_LABEL);
            let table = result.table.unwrap();
            assert_eq!(table.delimiter, "\t");
            assert_eq!(
                table.headers,
                vec!["Email".to_string(), "Member".to_string()]
            );

            let text = pseudonymize_inspect(root, inline_options("hello", "text")).unwrap();
            assert!(text.table.is_none());

            let mut no_mode = inline_options("hello", "text");
            no_mode.mode = None;
            assert!(pseudonymize_inspect(root, no_mode).is_err());
            let mut both = inline_options("hello", "text");
            both.input_path = Some(root.join("x.csv").display().to_string());
            assert!(pseudonymize_inspect(root, both).is_err());
            assert!(pseudonymize_inspect(root, PseudonymizeInspectOptions::default()).is_err());
            assert!(pseudonymize_inspect(root, inline_options("   ", "text")).is_err());
            assert!(pseudonymize_inspect(root, inline_options("x", "tabular")).is_err());
            let mut bad_format = inline_options("x", "table");
            bad_format.format = Some("psv".into());
            assert!(pseudonymize_inspect(root, bad_format).is_err());

            let no_policy = tempfile::tempdir().unwrap();
            let err =
                pseudonymize_inspect(no_policy.path(), inline_options("x", "text")).unwrap_err();
            assert!(err.to_string().contains("shk.toml"), "{err}");
            assert!(
                pseudonymize_inspect(&root.join("missing"), inline_options("x", "text")).is_err()
            );

            let mut typo = file_options(&root.join("orders.csv"));
            fs::write(root.join("orders.csv"), format!("Email\n{}\n", email())).unwrap();
            typo.columns = vec![choice("Emial", "email")];
            let err = pseudonymize_inspect(root, typo).unwrap_err();
            assert!(err.to_string().contains("Emial"), "{err}");
        }

        #[test]
        fn key_status_reports_the_store_without_creating_a_key() {
            let dir = project();
            let root = dir.path();
            let store = Arc::new(MemoryStore::default());
            let open = opener(Arc::clone(&store));
            let status = pseudonymize_key_status_with(root, &open).unwrap();
            assert!(!status.exists);
            assert!(status.fingerprint.is_none());
            assert!(status.unavailable_reason.is_none());
            assert_eq!(status.backend, "OS credential store");
            assert!(store.entries.lock().unwrap().is_empty());

            let failing = |_: &crate::env_store::ProjectIdentity, _: &Policy| {
                Err(anyhow::anyhow!("store exploded"))
            };
            assert!(pseudonymize_key_status_with(root, &failing).is_err());

            let unavailable = |_: &crate::env_store::ProjectIdentity, _: &Policy| {
                Err(anyhow::Error::new(keyring::Error::NoStorageAccess(
                    Box::new(std::io::Error::other("locked")),
                )))
            };
            let status = pseudonymize_key_status_with(root, &unavailable).unwrap();
            assert!(!status.exists);
            assert_eq!(status.backend, "OS credential store");
            assert!(
                status
                    .unavailable_reason
                    .as_deref()
                    .unwrap_or("")
                    .contains("locked"),
                "{status:?}"
            );
            let no_policy = tempfile::tempdir().unwrap();
            assert!(pseudonymize_key_status_with(no_policy.path(), &open).is_err());
        }

        #[test]
        fn run_writes_files_and_restores_through_the_map() {
            let dir = project();
            let root = dir.path();
            let store = Arc::new(MemoryStore::default());
            let open = opener(Arc::clone(&store));
            let card = ["4111", "1111", "1111", "1111"].join(" ");
            let input = format!("Email,Card,Note\n{},{card},keep\n", email());
            fs::write(root.join("orders.csv"), &input).unwrap();

            let mut options = run_options(
                file_options(&root.join("orders.csv")),
                Some(&root.join("orders.pseudo.csv")),
            );
            options.map_path = Some(root.join("orders.shk-map").display().to_string());
            options.check_remaining = true;
            options.input.columns = vec![
                choice("Email", "email"),
                choice("Card", "none"),
                choice("Note", "none"),
            ];
            let result = pseudonymize_run_with(root, options, &open).unwrap();
            assert_eq!(result.mode, "table");
            assert_eq!(result.rows_processed, 1);
            assert_eq!(result.replaced.get("email"), Some(&1));
            assert_eq!(result.columns.len(), 1);
            assert_eq!(result.columns[0].name, "Email");
            assert!(result.key_fingerprint.is_some());
            assert!(result.inline_output.is_none());
            assert_eq!(
                result.remaining_rule_ids,
                vec!["pii.credit_card".to_string()]
            );
            assert!(result.remaining_check_error.is_none());
            let output = PathBuf::from(result.output_path.clone().unwrap());
            let pseudo = fs::read_to_string(&output).unwrap();
            assert!(
                pseudo.contains("email_") && !pseudo.contains(&email()),
                "{pseudo}"
            );
            assert!(pseudo.contains(&card), "skipped column stays");
            let sidecar = fs::read_to_string(result.meta_path.unwrap()).unwrap();
            assert!(sidecar.contains("\"map_created\": true"), "{sidecar}");
            let map = PathBuf::from(result.map_path.unwrap());
            assert!(fs::read(&map).unwrap().starts_with(b"SHKMAP"));
            assert_eq!(store.entries.lock().unwrap().len(), 1);

            let status = pseudonymize_key_status_with(root, &open).unwrap();
            assert!(status.exists);
            assert_eq!(status.fingerprint, result.key_fingerprint);

            let restored = pseudonymize_restore_with(
                root,
                &output,
                &map,
                &root.join("orders.restored.csv"),
                &open,
            )
            .unwrap();
            assert_eq!(restored.replacements, 1);
            assert_eq!(restored.ambiguous_tokens, 0);
            assert_eq!(fs::read_to_string(restored.output_path).unwrap(), input);
            assert!(
                pseudonymize_restore_with(
                    root,
                    &output,
                    &root.join("nope.shk-map"),
                    &root.join("x.csv"),
                    &open
                )
                .is_err()
            );
        }

        #[test]
        fn run_returns_pasted_content_in_place() {
            let dir = project();
            let root = dir.path();
            let store = Arc::new(MemoryStore::default());
            let open = opener(Arc::clone(&store));
            let text = format!("contact {}\n", email());
            let result = pseudonymize_run_with(
                root,
                run_options(inline_options(&text, "text"), None),
                &open,
            )
            .unwrap();
            let output = result.inline_output.unwrap();
            assert!(
                output.contains("email_") && !output.contains(&email()),
                "{output}"
            );
            assert!(result.output_path.is_none() && result.map_path.is_none());
            assert_eq!(result.mode, "text");

            let mut table = run_options(
                inline_options(&format!("Email,Member\n{},m-1\n", email()), "table"),
                None,
            );
            table.input.columns = vec![
                choice("Email", "email"),
                PseudonymizeColumnChoice {
                    index: None,
                    name: "Member".into(),
                    kind: "custom".into(),
                    custom_label: Some("member".into()),
                },
            ];
            let result = pseudonymize_run_with(root, table, &open).unwrap();
            let output = result.inline_output.unwrap();
            assert!(
                output.contains("member_") && output.contains("email_"),
                "{output}"
            );
            assert_eq!(result.columns.len(), 2);
            assert_eq!(result.columns[1].kind, "custom");

            let leftovers: Vec<String> = fs::read_dir(root)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .filter(|name| name != "shk.toml" && name != ".shk")
                .collect();
            assert!(leftovers.is_empty(), "{leftovers:?}");

            let with_output = run_options(inline_options("x", "text"), Some(&root.join("out.txt")));
            assert!(pseudonymize_run_with(root, with_output, &open).is_err());
        }

        #[test]
        fn run_rejects_bad_requests_before_touching_the_key() {
            let dir = project();
            let root = dir.path();
            let store = Arc::new(MemoryStore::default());
            let open = opener(Arc::clone(&store));
            fs::write(
                root.join("orders.csv"),
                format!("Email,Note\n{},keep\n", email()),
            )
            .unwrap();
            let csv = root.join("orders.csv");

            let mut no_output = run_options(file_options(&csv), None);
            no_output.input.columns = vec![choice("Email", "email"), choice("Note", "none")];
            let err = pseudonymize_run_with(root, no_output, &open).unwrap_err();
            assert!(err.to_string().contains("choose where"), "{err}");

            // A table run without any choices must not fall back to inference.
            let no_choices = run_options(file_options(&csv), Some(&root.join("z.csv")));
            let err = pseudonymize_run_with(root, no_choices, &open).unwrap_err();
            assert!(err.to_string().contains("choose what each column"), "{err}");
            assert!(!root.join("z.csv").exists());
            // Partial choices leave a header to inference, which fails closed.
            let mut partial = run_options(file_options(&csv), Some(&root.join("y.csv")));
            partial.input.columns = vec![choice("Note", "none")];
            let err = pseudonymize_run_with(root, partial, &open).unwrap_err();
            assert!(err.to_string().contains("confirmation"), "{err}");
            assert!(!root.join("y.csv").exists());
            let mut duplicate = run_options(file_options(&csv), Some(&root.join("y.csv")));
            duplicate.input.columns = vec![choice("Email", "email"), choice("email", "none")];
            let err = pseudonymize_run_with(root, duplicate, &open).unwrap_err();
            assert!(err.to_string().contains("twice"), "{err}");

            let mut bad_map = run_options(file_options(&csv), Some(&root.join("a.csv")));
            bad_map.input.columns = vec![choice("Email", "email"), choice("Note", "none")];
            bad_map.map_path = Some(root.join("a.map").display().to_string());
            let err = pseudonymize_run_with(root, bad_map, &open).unwrap_err();
            assert!(err.to_string().contains(".shk-map"), "{err}");
            assert!(!root.join("a.csv").exists());

            let mut all_none = run_options(file_options(&csv), Some(&root.join("b.csv")));
            all_none.input.columns = vec![choice("Email", "none"), choice("Note", "none")];
            let err = pseudonymize_run_with(root, all_none, &open).unwrap_err();
            assert!(err.to_string().contains("no columns"), "{err}");

            let mut bad_label = run_options(file_options(&csv), Some(&root.join("c.csv")));
            bad_label.input.columns = vec![PseudonymizeColumnChoice {
                index: None,
                name: "Note".into(),
                kind: "custom".into(),
                custom_label: Some("Bad Label".into()),
            }];
            assert!(pseudonymize_run_with(root, bad_label, &open).is_err());
            let mut empty_label = run_options(file_options(&csv), Some(&root.join("c.csv")));
            empty_label.input.columns = vec![choice("Note", "custom")];
            assert!(pseudonymize_run_with(root, empty_label, &open).is_err());
            let mut bad_kind = run_options(file_options(&csv), Some(&root.join("c.csv")));
            bad_kind.input.columns = vec![choice("Note", "bogus")];
            assert!(pseudonymize_run_with(root, bad_kind, &open).is_err());
            let mut blank_name = run_options(file_options(&csv), Some(&root.join("c.csv")));
            blank_name.input.columns = vec![choice(" ", "email")];
            assert!(pseudonymize_run_with(root, blank_name, &open).is_err());

            let mut no_key = run_options(file_options(&csv), Some(&root.join("d.csv")));
            no_key.input.columns = vec![choice("Email", "email"), choice("Note", "none")];
            no_key.create_key = false;
            let err = pseudonymize_run_with(root, no_key, &open).unwrap_err();
            assert_eq!(err.to_string(), NO_KEY_MESSAGE);
            assert!(store.entries.lock().unwrap().is_empty());
            assert!(!root.join("d.csv").exists());
        }

        #[test]
        fn preview_helpers_cover_edge_cases() {
            assert_eq!(truncate_cell("abc"), "abc");
            let exact = "y".repeat(PSEUDONYMIZE_PREVIEW_CELL_CHARS);
            assert_eq!(truncate_cell(&exact), exact);
            let sheets = vec!["A".to_string(), "2".to_string()];
            assert_eq!(resolve_sheet_name(&sheets, None).as_deref(), Some("A"));
            assert_eq!(resolve_sheet_name(&sheets, Some("2")).as_deref(), Some("2"));
            assert_eq!(resolve_sheet_name(&sheets, Some("A")).as_deref(), Some("A"));
            assert_eq!(resolve_sheet_name(&sheets, Some("9")), None);
            assert_eq!(resolve_sheet_name(&sheets, Some("0")), None);
            assert_eq!(resolve_sheet_name(&sheets, Some("Zed")), None);
            assert_eq!(resolve_sheet_name(&[], None), None);
            assert!(column_overrides(&[]).unwrap().is_none());
            let overrides = column_overrides(&[choice("A", "phone"), choice("B", "none")])
                .unwrap()
                .unwrap();
            assert_eq!(overrides.entries.len(), 1);
            assert_eq!(overrides.skip, vec!["B".to_string()]);
            assert_eq!(non_blank(Some("  ")), None);
            assert_eq!(non_blank(Some(" x ")), Some("x"));
            assert_eq!(source_label_for(Path::new("dir/file.csv")), "file.csv");
        }
    }
}
