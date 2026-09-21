use crate::args::{PseudonymizeFormatArg, PseudonymizeModeArg};
use crate::env_store::{
    ProjectIdentity, SecretStore, open_pseudonymize_store, with_secret_store_lock,
};
use crate::exit::CliExit;
use crate::safety;
use anyhow::{Context, Result, anyhow};
use dialoguer::Confirm;
use sha2::{Digest, Sha256};
use shk_core::policy::{Policy, SecretStoreBackend};
use shk_core::pseudonymize::{
    ColumnOverrides, ColumnSource, KeyMaterial, Kind, MapCollector, NormalizeSettings,
    PseudonymizeMeta, ResolvedColumn, TableOptions, TableResult, TextOptions, TokenIndex,
    decrypt_map, delimiter_for_path, encrypt_map, formula_cell_error, parse_columns_spec,
    parse_stored_material, restore_table, run_office_text, run_table, run_text, run_xlsx,
};
use shk_core::scanner::{ScanOptions, scan_path};
use std::borrow::Cow;
use std::fs::File;
use std::io::{self, BufReader, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use tempfile::TempPath;
use zeroize::Zeroizing;

const STORE_ITEM: &str = "v1";
const OPERATION_LOCK: &str = "pseudonymize-v1-operation";
const MAX_MAP_BYTES: u64 = 64 * 1024 * 1024;
const NOT_UTF8_HINT: &str = "input is not valid UTF-8. Convert it first, for example: iconv -f SHIFT_JIS -t UTF-8 src.csv > utf8.csv";

pub struct MaskPseudonymizeArgs {
    pub project_root: PathBuf,
    pub file: Option<PathBuf>,
    pub json: bool,
    pub output: Option<PathBuf>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InputKind {
    TableCsv,
    TableXlsx,
    TextPlain,
    TextOffice,
}

/// Where the input bytes come from. `Stdin` is CLI-only; `Buffer` holds
/// content a GUI caller pasted and never touches disk. The wrapper wipes the
/// buffer on drop, but copies made while planning (sample rows, writer
/// buffers, the returned text) are ordinary allocations: treat zeroization
/// as best effort, not a guarantee.
pub(crate) enum PseudonymizeSource {
    File(PathBuf),
    Stdin,
    Buffer(Zeroizing<Vec<u8>>),
}

impl PseudonymizeSource {
    pub(crate) fn path(&self) -> Option<&Path> {
        match self {
            Self::File(path) => Some(path),
            Self::Stdin | Self::Buffer(_) => None,
        }
    }
}

/// Column choices. The CLI keeps its `Name:kind` spec so parse errors surface
/// at the same point as before; a GUI caller passes an already resolved list,
/// which may also `skip` columns the plan would otherwise select.
pub(crate) enum ColumnSelection {
    Spec(String),
    Resolved(ColumnOverrides),
}

/// One pseudonymize run, independent of how the caller talks to the user.
pub(crate) struct PseudonymizeRequest {
    pub project_root: PathBuf,
    pub source: PseudonymizeSource,
    pub output: Option<PathBuf>,
    pub dry_run: bool,
    pub columns: Option<ColumnSelection>,
    pub no_header: bool,
    pub mode: Option<PseudonymizeModeArg>,
    pub format: Option<PseudonymizeFormatArg>,
    pub sheet: Option<String>,
    pub map: Option<PathBuf>,
    pub check_remaining: bool,
}

/// The two points where the engine needs a human decision. The CLI prompts;
/// a GUI collects the answers up front so the engine never blocks.
pub(crate) trait Interaction {
    /// Called only when at least one column was inferred rather than named.
    fn confirm_inferred_columns(&self, columns: &[ResolvedColumn]) -> Result<()>;
    /// Called only when the project has no pseudonymize key yet.
    fn confirm_create_key(&self) -> Result<()>;
}

struct CliInteraction {
    yes: bool,
    no_create_key: bool,
}

impl Interaction for CliInteraction {
    fn confirm_inferred_columns(&self, columns: &[ResolvedColumn]) -> Result<()> {
        print_column_plan(columns);
        confirm(self.yes, "Pseudonymize the inferred columns listed above?")
    }

    fn confirm_create_key(&self) -> Result<()> {
        if self.no_create_key {
            return Err(fail(
                "no pseudonymize key for this project; omit --no-create-key to create one",
            ));
        }
        confirm(
            self.yes,
            "No pseudonymize key found. Create a new project key in the configured secret store?",
        )
    }
}

pub(crate) const NO_KEY_MESSAGE: &str =
    "no pseudonymize key for this project; confirm key creation to continue";

/// Decisions a GUI caller already collected from the user.
#[derive(Debug)]
pub(crate) struct Decisions {
    pub accept_inferred: bool,
    pub create_key: bool,
}

impl Interaction for Decisions {
    fn confirm_inferred_columns(&self, _columns: &[ResolvedColumn]) -> Result<()> {
        if self.accept_inferred {
            Ok(())
        } else {
            Err(fail("inferred columns require confirmation"))
        }
    }

    fn confirm_create_key(&self) -> Result<()> {
        if self.create_key {
            Ok(())
        } else {
            Err(fail(NO_KEY_MESSAGE))
        }
    }
}

#[derive(Debug)]
pub(crate) struct WrittenPaths {
    pub output: PathBuf,
    pub meta: PathBuf,
    pub map: Option<PathBuf>,
}

#[derive(Debug)]
pub(crate) struct PseudonymizeOutcome {
    pub meta: PseudonymizeMeta,
    /// Resolved columns for table modes; `None` in text modes.
    pub columns: Option<Vec<ResolvedColumn>>,
    /// `None` on a dry run.
    pub written: Option<WrittenPaths>,
    /// `--check-remaining` result: leftover rule ids, or the reason the output
    /// could not be verified. Carried instead of raised so the CLI can print
    /// its summary first, exactly as it always has.
    pub remaining: Option<Result<Vec<String>>>,
}

/// Opens the project's pseudonymize key store. Injected so the complete
/// write / restore path can run against an in-memory store in unit tests.
pub(crate) type StoreOpener<'a> =
    &'a dyn Fn(&ProjectIdentity, &Policy) -> Result<(Box<dyn SecretStore>, SecretStoreBackend)>;

/// Every failure on the pseudonymize path exits 2 (usage / runtime error) so
/// that exit 1 stays reserved for `--check-remaining` leftovers.
pub fn mask(args: MaskPseudonymizeArgs) -> Result<()> {
    mask_with(args, &open_pseudonymize_store)
}

fn mask_with(args: MaskPseudonymizeArgs, open_store: StoreOpener<'_>) -> Result<()> {
    let json = args.json;
    let interaction = CliInteraction {
        yes: args.yes,
        no_create_key: args.no_create_key,
    };
    let outcome = mask_core(request_from_cli(args), open_store, &interaction).map_err(fail_run)?;
    print_outcome(json, &outcome).map_err(fail_run)?;
    match outcome.remaining {
        Some(Err(err)) => Err(fail_run(err)),
        Some(Ok(leftover)) if !leftover.is_empty() => Err(leftover_error(&leftover)),
        _ => Ok(()),
    }
}

fn request_from_cli(args: MaskPseudonymizeArgs) -> PseudonymizeRequest {
    PseudonymizeRequest {
        project_root: args.project_root,
        source: args
            .file
            .map_or(PseudonymizeSource::Stdin, PseudonymizeSource::File),
        output: args.output,
        dry_run: args.dry_run,
        columns: args.columns.map(ColumnSelection::Spec),
        no_header: args.no_header,
        mode: args.mode,
        format: args.format,
        sheet: args.sheet,
        map: args.map,
        check_remaining: args.check_remaining,
    }
}

/// The engine behind `shk mask --pseudonymize`: no printing, no prompting.
/// Errors are plain runtime errors; callers map them to exit codes.
pub(crate) fn mask_core(
    req: PseudonymizeRequest,
    open_store: StoreOpener<'_>,
    interaction: &dyn Interaction,
) -> Result<PseudonymizeOutcome> {
    let (kind, policy) = preflight(&req)?;
    let run = || match kind {
        InputKind::TableCsv => run_table_csv(&req, &policy, open_store, interaction),
        InputKind::TableXlsx => run_table_xlsx(&req, &policy, open_store, interaction),
        InputKind::TextPlain => run_text_plain(&req, &policy, open_store, interaction),
        InputKind::TextOffice => run_text_office(&req, &policy, open_store, interaction),
    };
    if req.dry_run {
        run()
    } else {
        let project = ProjectIdentity::from_root_and_policy(req.project_root.clone(), &policy);
        with_secret_store_lock(&project, OPERATION_LOCK, run)
    }
}

/// Everything that must hold before any input is read or any key is touched.
pub(crate) fn preflight(req: &PseudonymizeRequest) -> Result<(InputKind, Policy)> {
    if !req.dry_run && req.output.is_none() {
        return Err(fail(
            "`mask --pseudonymize` requires --output so tokens are not written to stdout",
        ));
    }
    if req.check_remaining && req.dry_run {
        return Err(fail(
            "`--check-remaining` cannot be combined with `--dry-run`",
        ));
    }
    validate_output_paths(req)?;
    if let Some(output) = req.output.as_ref() {
        safety::require_project_policy(&req.project_root, "mask --output")?;
        safety::ensure_writable_path_allowed(output)?;
    }
    if let Some(map) = req.map.as_ref() {
        require_map_path(map)?;
        safety::require_project_policy(&req.project_root, "mask --map")?;
        safety::ensure_writable_path_allowed(map)?;
    }

    let kind = classify_input(req.source.path(), req.mode, req.format)?;
    validate_mode_flags(req, &kind)?;
    validate_restore_compatible_output(req, &kind)?;

    match &req.source {
        PseudonymizeSource::Stdin => {
            if io::stdin().is_terminal() {
                return Err(fail(
                    "pass a file or redirect stdin; `mask --pseudonymize` does not prompt for input",
                ));
            }
        }
        PseudonymizeSource::File(input) => {
            // The input is opened several times (UTF-8 check, digest, plan, run),
            // so streams cannot be consumed correctly; ask for stdin instead.
            if !input.is_file() {
                return Err(fail(format!(
                    "{} is not a regular file; pipe streams on stdin instead",
                    input.display()
                )));
            }
            if !matches!(kind, InputKind::TableXlsx | InputKind::TextOffice) {
                ensure_utf8_file(input)?;
            }
        }
        // Buffers are UTF-8 checked when they are read, like stdin.
        PseudonymizeSource::Buffer(_) => {}
    }

    let (policy, _) = Policy::load_from_dir(&req.project_root)?;
    validate_policy_section(&policy)?;
    Ok((kind, policy))
}

#[derive(Debug)]
pub(crate) enum Preview {
    Table(Box<TableResult>),
    Text,
}

/// The dry-run planning pass on its own: never prompts, never opens the key
/// store, never takes the operation lock. A table preview may resolve zero
/// columns; that is for the caller to decide about.
pub(crate) fn preview(req: &PseudonymizeRequest) -> Result<Preview> {
    if !req.dry_run {
        return Err(fail("preview requires a dry-run request"));
    }
    let (kind, policy) = preflight(req)?;
    Ok(match kind {
        InputKind::TableCsv => Preview::Table(Box::new(plan_table_csv(req, &policy)?.preview)),
        InputKind::TableXlsx => {
            Preview::Table(Box::new(plan_table_xlsx(req, &policy, false)?.preview))
        }
        InputKind::TextPlain => {
            let input = read_text_source(req)?;
            run_text(&input, None, &text_options(req, &policy, true), None)?;
            Preview::Text
        }
        InputKind::TextOffice => {
            let input = office_input(req)?;
            run_office_text(
                input,
                None,
                None,
                &text_options(req, &policy, true),
                None,
                policy.scan.max_file_size_bytes,
            )?;
            Preview::Text
        }
    })
}

/// Pasted content for a GUI caller: the result stays in memory and no
/// output, metadata sidecar, or restore map is written.
pub(crate) struct InlineRequest {
    pub project_root: PathBuf,
    pub bytes: Zeroizing<Vec<u8>>,
    pub mode: PseudonymizeModeArg,
    pub format: Option<PseudonymizeFormatArg>,
    pub columns: Option<ColumnOverrides>,
    pub no_header: bool,
}

#[derive(Debug)]
pub(crate) struct InlineOutcome {
    pub output: Zeroizing<String>,
    pub meta: PseudonymizeMeta,
    pub columns: Option<Vec<ResolvedColumn>>,
}

pub(crate) fn pseudonymize_inline(
    inline: InlineRequest,
    open_store: StoreOpener<'_>,
    interaction: &dyn Interaction,
) -> Result<InlineOutcome> {
    let req = PseudonymizeRequest {
        project_root: inline.project_root,
        source: PseudonymizeSource::Buffer(inline.bytes),
        output: None,
        dry_run: true,
        columns: inline.columns.map(ColumnSelection::Resolved),
        no_header: inline.no_header,
        mode: Some(inline.mode),
        format: inline.format,
        sheet: None,
        map: None,
        check_remaining: false,
    };
    let (kind, policy) = preflight(&req)?;
    let project = ProjectIdentity::from_root_and_policy(req.project_root.clone(), &policy);
    let outcome = with_secret_store_lock(&project, OPERATION_LOCK, || match kind {
        InputKind::TableCsv => inline_table(&req, &policy, &project, open_store, interaction),
        InputKind::TextPlain => inline_text(&req, &policy, &project, open_store, interaction),
        // A buffer has no path, so `classify_input` never yields these.
        InputKind::TableXlsx | InputKind::TextOffice => {
            unreachable!("buffers classify as csv or text")
        }
    })?;
    let _ = crate::audit_log::append_line(
        &req.project_root,
        serde_json::json!({
            "event": "pseudonymize",
            "mode": outcome.meta.mode,
            "inline": true,
            "rows": outcome.meta.rows_processed,
            "columns": outcome.columns.as_ref().map(Vec::len).unwrap_or(0),
            "kinds": outcome
                .meta
                .columns
                .iter()
                .map(|column| column.kind.as_str())
                .collect::<Vec<_>>(),
            "map": false,
        }),
    );
    Ok(outcome)
}

fn inline_table(
    req: &PseudonymizeRequest,
    policy: &Policy,
    project: &ProjectIdentity,
    open_store: StoreOpener<'_>,
    interaction: &dyn Interaction,
) -> Result<InlineOutcome> {
    let plan = plan_table_csv(req, policy)?;
    confirm_table_plan(interaction, &plan.preview)?;
    let material = load_or_create_material(project, policy, open_store, interaction)?;
    let mut run_options = plan.options;
    run_options.dry_run = false;
    let mut out = Zeroizing::new(Vec::new());
    let result = run_table(
        plan.source.open()?,
        Some(&mut *out),
        &run_options,
        Some(&material),
        None,
    )?;
    let output =
        Zeroizing::new(String::from_utf8(std::mem::take(&mut *out)).map_err(|_| encoding_error())?);
    Ok(InlineOutcome {
        output,
        meta: result.meta,
        columns: Some(result.columns),
    })
}

fn inline_text(
    req: &PseudonymizeRequest,
    policy: &Policy,
    project: &ProjectIdentity,
    open_store: StoreOpener<'_>,
    interaction: &dyn Interaction,
) -> Result<InlineOutcome> {
    let input = Zeroizing::new(read_text_source(req)?);
    let material = load_or_create_material(project, policy, open_store, interaction)?;
    let result = run_text(
        &input,
        Some(&material),
        &text_options(req, policy, false),
        None,
    )?;
    Ok(InlineOutcome {
        output: Zeroizing::new(result.output),
        meta: result.meta,
        columns: None,
    })
}

/// Reject broken `[pseudonymize]` settings before any prompt or key creation,
/// including `rules` entries that would otherwise only fail once a rule matches.
pub(crate) fn validate_policy_section(policy: &Policy) -> Result<()> {
    let section = &policy.pseudonymize;
    shk_core::pseudonymize::validate_norm(&section.norm).map_err(fail)?;
    shk_core::pseudonymize::validate_token_bits(section.token_bits).map_err(fail)?;
    for (table, entries) in [("columns", &section.columns), ("rules", &section.rules)] {
        for (name, raw) in entries {
            Kind::parse(raw)
                .map_err(|err| fail(format!("[pseudonymize.{table}] `{name}`: {err}")))?;
        }
    }
    Ok(())
}

fn validate_output_paths(req: &PseudonymizeRequest) -> Result<()> {
    let mut paths: Vec<(&str, PathBuf)> = Vec::new();
    if let Some(input) = req.source.path() {
        paths.push(("input", input.to_path_buf()));
    }
    if let Some(output) = &req.output {
        ensure_regular_destination(output, "output")?;
        paths.push(("output", output.clone()));
        let meta = meta_sidecar(output);
        ensure_regular_destination(&meta, "metadata")?;
        safety::ensure_writable_path_allowed(&meta)?;
        paths.push(("metadata", meta));
    }
    if let Some(map) = &req.map {
        ensure_regular_destination(map, "map")?;
        paths.push(("map", map.clone()));
    }
    for (index, (label, path)) in paths.iter().enumerate() {
        for (other_label, other) in &paths[..index] {
            if paths_equal(path, other) {
                return Err(fail(format!(
                    "{label} and {other_label} must use different paths"
                )));
            }
        }
    }
    Ok(())
}

fn ensure_regular_destination(path: &Path, label: &str) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_file() => Err(fail(format!(
            "{label} path exists and is not a regular file: {}",
            path.display()
        ))),
        Ok(_) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("inspect {}", path.display())),
    }
}

#[derive(Debug)]
pub(crate) struct RestoreSummary {
    pub output: PathBuf,
    pub replacements: usize,
    /// Tokens that had several originals; the first-seen value was used.
    pub ambiguous: usize,
}

pub fn restore(cwd: &Path, file: PathBuf, map: PathBuf, output: PathBuf) -> Result<()> {
    let summary = restore_with(cwd, file, map, output, &open_pseudonymize_store)?;
    println!(
        "Restored {} token(s) to {}",
        summary.replacements,
        summary.output.display()
    );
    if summary.ambiguous > 0 {
        eprintln!(
            "warning: {} token(s) had multiple originals; first-seen value was used",
            summary.ambiguous
        );
    }
    Ok(())
}

pub(crate) fn restore_with(
    cwd: &Path,
    file: PathBuf,
    map: PathBuf,
    output: PathBuf,
    open_store: StoreOpener<'_>,
) -> Result<RestoreSummary> {
    let result = (|| {
        let (policy, _) = Policy::load_from_dir(cwd)?;
        let project = ProjectIdentity::from_root_and_policy(cwd.to_path_buf(), &policy);
        with_secret_store_lock(&project, OPERATION_LOCK, || {
            restore_inner(cwd, file, map, output, open_store)
        })
    })();
    result.map_err(fail_run)
}

fn restore_inner(
    cwd: &Path,
    file: PathBuf,
    map: PathBuf,
    output: PathBuf,
    open_store: StoreOpener<'_>,
) -> Result<RestoreSummary> {
    require_map_path(&map)?;
    ensure_regular_destination(&output, "output")?;
    ensure_regular_destination(&map, "map")?;
    if paths_equal(&map, &output) {
        return Err(fail("refusing to overwrite the restore map"));
    }
    if paths_equal(&file, &output) {
        return Err(fail("refusing to overwrite the input file"));
    }
    safety::require_project_policy(cwd, "pseudonymize restore --output")?;
    safety::ensure_writable_path_allowed(&output)?;
    if !map.exists() {
        return Err(fail(format!("restore map not found: {}", map.display())));
    }

    let (policy, project, store, _backend) = open_context(cwd, open_store)?;
    let material = load_material(store.as_ref(), &project)?.ok_or_else(|| {
        fail("no pseudonymize key for this project; cannot decrypt the restore map")
    })?;
    let bytes = read_map_bounded(&map)?;
    let document = decrypt_map(&material, &bytes)?;
    if document.key_fingerprint != material.fingerprint() {
        return Err(fail(
            "restore map fingerprint does not match this project's key",
        ));
    }
    let index = TokenIndex::new(&document);

    let (replacements, ambiguous) = if is_office_path(&file) {
        let mut replacements = 0usize;
        let mut multi = 0usize;
        shk_core::document_masker::rewrite_ooxml_text_groups(
            &file,
            &output,
            policy.scan.max_file_size_bytes,
            |group| {
                let (restored, n, m) = index.restore(group);
                replacements += n;
                multi += m;
                Ok(restored)
            },
        )?;
        (replacements, multi)
    } else {
        ensure_utf8_file(&file)?;
        let input =
            std::fs::read_to_string(&file).with_context(|| format!("read {}", file.display()))?;
        let (restored, replacements, multi) = if is_table_path(&file) {
            restore_table(&input, &document, delimiter_for_path(Some(&file)))?
        } else {
            index.restore(&input)
        };
        crate::fs_atomic::write_atomic(&output, restored.as_bytes())?;
        (replacements, multi)
    };
    Ok(RestoreSummary {
        output,
        replacements,
        ambiguous,
    })
}

/// A CSV plan: the re-openable source plus the dry-run result it produced.
struct CsvPlan<'a> {
    source: TableSource<'a>,
    options: TableOptions,
    preview: TableResult,
}

fn plan_table_csv<'a>(req: &'a PseudonymizeRequest, policy: &Policy) -> Result<CsvPlan<'a>> {
    let cli_columns = resolve_column_selection(req)?;
    let (source, crlf, delimiter) = read_table_source(req)?;
    let options = table_options(req, policy, delimiter, crlf, cli_columns, true);
    let preview = run_table(source.open()?, None::<&mut Vec<u8>>, &options, None, None)?;
    Ok(CsvPlan {
        source,
        options,
        preview,
    })
}

struct XlsxPlan<'a> {
    input: &'a Path,
    /// Taken before the planning read so a run can prove the file did not
    /// change in between; a preview on its own does not need it.
    digest: Option<[u8; 32]>,
    options: TableOptions,
    preview: TableResult,
}

fn plan_table_xlsx<'a>(
    req: &'a PseudonymizeRequest,
    policy: &Policy,
    with_digest: bool,
) -> Result<XlsxPlan<'a>> {
    let input = req
        .source
        .path()
        .ok_or_else(|| fail("xlsx table mode requires a file path"))?;
    let digest = if with_digest {
        Some(file_digest(input)?)
    } else {
        None
    };
    let cli_columns = resolve_column_selection(req)?;
    let options = table_options(req, policy, b',', false, cli_columns, true);
    let preview = run_xlsx(input, None, req.sheet.as_deref(), &options, None, None)?;
    Ok(XlsxPlan {
        input,
        digest,
        options,
        preview,
    })
}

fn office_input(req: &PseudonymizeRequest) -> Result<&Path> {
    req.source
        .path()
        .ok_or_else(|| fail("Office text mode requires a file path"))
}

fn dry_run_outcome(
    meta: PseudonymizeMeta,
    columns: Option<Vec<ResolvedColumn>>,
) -> PseudonymizeOutcome {
    PseudonymizeOutcome {
        meta,
        columns,
        written: None,
        remaining: None,
    }
}

fn run_table_csv(
    req: &PseudonymizeRequest,
    policy: &Policy,
    open_store: StoreOpener<'_>,
    interaction: &dyn Interaction,
) -> Result<PseudonymizeOutcome> {
    let plan = plan_table_csv(req, policy)?;
    confirm_table_plan(interaction, &plan.preview)?;
    if req.dry_run {
        return Ok(dry_run_outcome(
            plan.preview.meta,
            Some(plan.preview.columns),
        ));
    }

    let output = req.output.as_ref().expect("checked above");
    let project = ProjectIdentity::from_root_and_policy(req.project_root.clone(), policy);
    let material = load_or_create_material(&project, policy, open_store, interaction)?;
    let mut collector = prepare_map(req.map.as_deref(), &material)?;
    plan.source.ensure_unchanged()?;
    let mut run_options = plan.options;
    run_options.dry_run = false;
    let mut tmp = new_output_temp(output)?;
    let result = run_table(
        plan.source.open()?,
        Some(tmp.as_file_mut()),
        &run_options,
        Some(&material),
        collector.as_mut(),
    )?;
    plan.source.ensure_unchanged()?;
    tmp.flush()?;
    tmp.as_file().sync_all()?;
    finish_run(
        req,
        policy,
        &material,
        result.meta,
        Some(result.columns),
        collector,
        "table",
        tmp.into_temp_path(),
    )
}

fn run_table_xlsx(
    req: &PseudonymizeRequest,
    policy: &Policy,
    open_store: StoreOpener<'_>,
    interaction: &dyn Interaction,
) -> Result<PseudonymizeOutcome> {
    let plan = plan_table_xlsx(req, policy, !req.dry_run)?;
    // The planning pass only reports formula cells; the CLI refuses them up
    // front (as it always has), while a GUI preview shows them instead.
    if let Some(&(row, col)) = plan.preview.formula_cells.first() {
        return Err(formula_cell_error(row, col));
    }
    confirm_table_plan(interaction, &plan.preview)?;
    if req.dry_run {
        return Ok(dry_run_outcome(
            plan.preview.meta,
            Some(plan.preview.columns),
        ));
    }
    let digest = plan.digest.expect("digest is taken for a real run");

    let output = req.output.as_ref().expect("checked above");
    let project = ProjectIdentity::from_root_and_policy(req.project_root.clone(), policy);
    let material = load_or_create_material(&project, policy, open_store, interaction)?;
    let mut collector = prepare_map(req.map.as_deref(), &material)?;
    ensure_digest_unchanged(plan.input, digest)?;
    let mut run_options = plan.options;
    run_options.dry_run = false;
    let staged_output = new_output_temp(output)?.into_temp_path();
    let result = run_xlsx(
        plan.input,
        Some(staged_output.as_ref()),
        req.sheet.as_deref(),
        &run_options,
        Some(&material),
        collector.as_mut(),
    )?;
    ensure_digest_unchanged(plan.input, digest)?;
    finish_run(
        req,
        policy,
        &material,
        result.meta,
        Some(result.columns),
        collector,
        "table",
        staged_output,
    )
}

fn run_text_plain(
    req: &PseudonymizeRequest,
    policy: &Policy,
    open_store: StoreOpener<'_>,
    interaction: &dyn Interaction,
) -> Result<PseudonymizeOutcome> {
    let input = read_text_source(req)?;
    let options = text_options(req, policy, true);
    if req.dry_run {
        let result = run_text(&input, None, &options, None)?;
        return Ok(dry_run_outcome(result.meta, None));
    }
    let output = req.output.as_ref().expect("checked above");
    let project = ProjectIdentity::from_root_and_policy(req.project_root.clone(), policy);
    let material = load_or_create_material(&project, policy, open_store, interaction)?;
    let mut collector = prepare_map(req.map.as_deref(), &material)?;
    let mut run_options = options;
    run_options.dry_run = false;
    let result = run_text(&input, Some(&material), &run_options, collector.as_mut())?;
    let staged_output = stage_bytes(output, result.output.as_bytes())?;
    finish_run(
        req,
        policy,
        &material,
        result.meta,
        None,
        collector,
        "text",
        staged_output,
    )
}

fn run_text_office(
    req: &PseudonymizeRequest,
    policy: &Policy,
    open_store: StoreOpener<'_>,
    interaction: &dyn Interaction,
) -> Result<PseudonymizeOutcome> {
    let input = office_input(req)?;
    let options = text_options(req, policy, true);
    if req.dry_run {
        let result = run_office_text(
            input,
            None,
            None,
            &options,
            None,
            policy.scan.max_file_size_bytes,
        )?;
        return Ok(dry_run_outcome(result.meta, None));
    }
    let output = req.output.as_ref().expect("checked above");
    let project = ProjectIdentity::from_root_and_policy(req.project_root.clone(), policy);
    let material = load_or_create_material(&project, policy, open_store, interaction)?;
    let mut collector = prepare_map(req.map.as_deref(), &material)?;
    let mut run_options = options;
    run_options.dry_run = false;
    let staged_output = new_output_temp(output)?.into_temp_path();
    let result = run_office_text(
        input,
        Some(staged_output.as_ref()),
        Some(&material),
        &run_options,
        collector.as_mut(),
        policy.scan.max_file_size_bytes,
    )?;
    finish_run(
        req,
        policy,
        &material,
        result.meta,
        None,
        collector,
        "text",
        staged_output,
    )
}

#[allow(clippy::too_many_arguments)]
fn finish_run(
    req: &PseudonymizeRequest,
    policy: &Policy,
    material: &KeyMaterial,
    mut meta: PseudonymizeMeta,
    columns: Option<Vec<ResolvedColumn>>,
    collector: Option<MapCollector>,
    mode: &str,
    staged_output: TempPath,
) -> Result<PseudonymizeOutcome> {
    let output = req.output.as_ref().expect("checked above");
    let staged_map = if let (Some(map_path), Some(collector)) = (req.map.as_ref(), collector) {
        let document =
            collector.into_document(policy.pseudonymize.norm.clone(), material.fingerprint());
        let bytes = encrypt_map(material, &document)?;
        if bytes.len() as u64 > MAX_MAP_BYTES {
            return Err(fail(format!(
                "restore map exceeds the {} MiB limit",
                MAX_MAP_BYTES / (1024 * 1024)
            )));
        }
        meta.map_created = true;
        Some((map_path, stage_bytes(map_path, &bytes)?))
    } else {
        None
    };

    let meta_path = meta_sidecar(output);
    safety::ensure_writable_path_allowed(&meta_path)?;
    let meta_bytes = serde_json::to_vec_pretty(&meta)?;
    let staged_meta = stage_bytes(&meta_path, &meta_bytes)?;

    // Commit recovery material and metadata before exposing the new output.
    // A failed output commit may leave harmless superset metadata/map entries,
    // but a visible pseudonymized output is never left without its restore map.
    if let Some((map_path, staged_map)) = staged_map {
        persist_temp_path(staged_map, map_path)?;
    }
    persist_temp_path(staged_meta, &meta_path)?;
    persist_temp_path(staged_output, output)?;

    let _ = crate::audit_log::append_line(
        &req.project_root,
        serde_json::json!({
            "event": "pseudonymize",
            "mode": mode,
            "rows": meta.rows_processed,
            "columns": columns.as_ref().map(Vec::len).unwrap_or(0),
            "kinds": meta
                .columns
                .iter()
                .map(|column| column.kind.as_str())
                .collect::<Vec<_>>(),
            "map": req.map.is_some(),
        }),
    );

    let remaining = req
        .check_remaining
        .then(|| check_remaining(&req.project_root, policy, output));
    Ok(PseudonymizeOutcome {
        meta,
        columns,
        written: Some(WrittenPaths {
            output: output.clone(),
            meta: meta_path,
            map: req.map.clone(),
        }),
        remaining,
    })
}

fn print_outcome(json: bool, outcome: &PseudonymizeOutcome) -> Result<()> {
    let Some(written) = outcome.written.as_ref() else {
        return emit_dry_run(json, &outcome.meta, outcome.columns.as_deref());
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&outcome.meta)?);
    } else {
        print_meta_summary(&outcome.meta, outcome.columns.as_deref());
        println!("Wrote {}", written.output.display());
        println!("Wrote {}", written.meta.display());
        if let Some(map) = written.map.as_ref() {
            println!("Wrote {}", map.display());
        }
    }
    Ok(())
}

fn confirm_table_plan(interaction: &dyn Interaction, preview: &TableResult) -> Result<()> {
    if preview.columns.is_empty() {
        return Err(fail(
            "no columns to pseudonymize; pass --columns or add [pseudonymize.columns]",
        ));
    }
    let inferred = preview
        .columns
        .iter()
        .any(|column| column.source == ColumnSource::Inferred);
    if inferred {
        interaction.confirm_inferred_columns(&preview.columns)?;
    }
    Ok(())
}

fn emit_dry_run(
    json: bool,
    meta: &PseudonymizeMeta,
    columns: Option<&[ResolvedColumn]>,
) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(meta)?);
    } else if let Some(columns) = columns {
        print_column_plan(columns);
        println!("dry-run: no files written and no key created");
    } else {
        println!("dry-run: text mode would replace email/phone/name matches");
        println!("dry-run: no files written and no key created");
    }
    Ok(())
}

pub(crate) fn classify_input(
    path: Option<&Path>,
    mode: Option<PseudonymizeModeArg>,
    format: Option<PseudonymizeFormatArg>,
) -> Result<InputKind> {
    if matches!(
        path.and_then(|p| p.extension())
            .and_then(|ext| ext.to_str()),
        Some(ext) if ext.eq_ignore_ascii_case("pdf")
    ) {
        return Err(fail("PDF pseudonymization is not supported"));
    }
    if mode == Some(PseudonymizeModeArg::Text) {
        return Ok(if path.is_some_and(is_office_path) {
            InputKind::TextOffice
        } else {
            InputKind::TextPlain
        });
    }
    if format.is_some() {
        if path.is_some_and(is_xlsx_path) {
            return Err(fail("`--format` only applies to CSV/TSV input, not xlsx"));
        }
        return Ok(InputKind::TableCsv);
    }
    if mode == Some(PseudonymizeModeArg::Table) {
        return Ok(if path.is_some_and(is_xlsx_path) {
            InputKind::TableXlsx
        } else {
            InputKind::TableCsv
        });
    }
    match path {
        None => Ok(InputKind::TextPlain),
        Some(path) if is_table_path(path) => Ok(InputKind::TableCsv),
        Some(path) if is_xlsx_path(path) => Ok(InputKind::TableXlsx),
        Some(path) if is_office_path(path) => Ok(InputKind::TextOffice),
        Some(_) => Ok(InputKind::TextPlain),
    }
}

fn validate_mode_flags(req: &PseudonymizeRequest, kind: &InputKind) -> Result<()> {
    match kind {
        InputKind::TextPlain | InputKind::TextOffice => {
            if req.columns.is_some() {
                return Err(fail("`--columns` is only valid in table mode"));
            }
            if req.format.is_some() {
                return Err(fail("`--format` is only valid in table mode"));
            }
            if req.no_header {
                return Err(fail("`--no-header` is only valid in table mode"));
            }
            if req.sheet.is_some() {
                return Err(fail("`--sheet` is only valid for xlsx table mode"));
            }
        }
        InputKind::TableCsv => {
            if req.sheet.is_some() {
                return Err(fail("`--sheet` is only valid for xlsx table mode"));
            }
        }
        InputKind::TableXlsx => {}
    }
    Ok(())
}

fn validate_restore_compatible_output(req: &PseudonymizeRequest, kind: &InputKind) -> Result<()> {
    let (Some(_map), Some(output)) = (req.map.as_ref(), req.output.as_ref()) else {
        return Ok(());
    };
    let output_ext = output
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default();
    match kind {
        InputKind::TableCsv => {
            let expected = if table_delimiter(req, req.source.path()) == b'\t' {
                "tsv"
            } else {
                "csv"
            };
            if !output_ext.eq_ignore_ascii_case(expected) {
                return Err(fail(format!(
                    "reversible {expected} output requires a .{expected} --output path"
                )));
            }
        }
        InputKind::TableXlsx => {
            if !output_ext.eq_ignore_ascii_case("xlsx") {
                return Err(fail(
                    "reversible xlsx output requires a .xlsx --output path",
                ));
            }
        }
        InputKind::TextOffice => {
            let input_ext = req
                .source
                .path()
                .and_then(Path::extension)
                .and_then(|ext| ext.to_str())
                .unwrap_or_default();
            if input_ext.is_empty() || !output_ext.eq_ignore_ascii_case(input_ext) {
                return Err(fail(format!(
                    "reversible Office output must keep the .{input_ext} extension"
                )));
            }
        }
        InputKind::TextPlain => {
            if is_table_path(output) || is_office_path(output) {
                return Err(fail(
                    "reversible text output must not use a CSV/TSV/Office extension",
                ));
            }
        }
    }
    Ok(())
}

fn resolve_column_selection(req: &PseudonymizeRequest) -> Result<Option<ColumnOverrides>> {
    match req.columns.as_ref() {
        None => Ok(None),
        Some(ColumnSelection::Spec(spec)) => parse_columns_spec(spec)
            .map(Some)
            .map_err(|err| fail(err.0)),
        Some(ColumnSelection::Resolved(overrides)) => Ok(Some(overrides.clone())),
    }
}

fn table_options(
    req: &PseudonymizeRequest,
    policy: &Policy,
    delimiter: u8,
    crlf: bool,
    cli_columns: Option<ColumnOverrides>,
    dry_run: bool,
) -> TableOptions {
    TableOptions {
        delimiter,
        no_header: req.no_header,
        token_bits: policy.pseudonymize.token_bits,
        norm: policy.pseudonymize.norm.clone(),
        settings: NormalizeSettings {
            email_strip_subaddress: policy.pseudonymize.email_strip_subaddress,
        },
        config_columns: policy.pseudonymize.columns.clone(),
        cli_columns,
        dry_run,
        crlf,
        shk_version: env!("CARGO_PKG_VERSION").into(),
        key_namespace: key_namespace(&req.project_root, policy.env.project_id.as_deref()),
    }
}

fn text_options(req: &PseudonymizeRequest, policy: &Policy, dry_run: bool) -> TextOptions {
    TextOptions {
        token_bits: policy.pseudonymize.token_bits,
        norm: policy.pseudonymize.norm.clone(),
        settings: NormalizeSettings {
            email_strip_subaddress: policy.pseudonymize.email_strip_subaddress,
        },
        rule_overrides: policy.pseudonymize.rules.clone(),
        shk_version: env!("CARGO_PKG_VERSION").into(),
        key_namespace: key_namespace(&req.project_root, policy.env.project_id.as_deref()),
        dry_run,
    }
}

/// Table input is read twice (plan, then rewrite). Files are streamed so
/// memory stays flat for large exports; stdin and pasted content are buffered.
enum TableSource<'a> {
    File { path: PathBuf, digest: [u8; 32] },
    Buffer(Cow<'a, [u8]>),
}

impl TableSource<'_> {
    fn open(&self) -> Result<Box<dyn Read + '_>> {
        match self {
            Self::File { path, .. } => {
                let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
                Ok(Box::new(BufReader::new(file)))
            }
            Self::Buffer(bytes) => Ok(Box::new(bytes.as_ref())),
        }
    }

    fn ensure_unchanged(&self) -> Result<()> {
        if let Self::File { path, digest } = self {
            ensure_digest_unchanged(path, *digest)?;
        }
        Ok(())
    }
}

fn read_table_source(req: &PseudonymizeRequest) -> Result<(TableSource<'_>, bool, u8)> {
    let buffered: Cow<'_, [u8]> = match &req.source {
        PseudonymizeSource::File(path) => {
            // UTF-8 validity was checked in `preflight` before the policy loaded.
            return Ok((
                TableSource::File {
                    path: path.clone(),
                    digest: file_digest(path)?,
                },
                file_uses_crlf(path)?,
                table_delimiter(req, Some(path)),
            ));
        }
        PseudonymizeSource::Stdin => Cow::Owned(read_stdin_bytes()?),
        PseudonymizeSource::Buffer(bytes) => Cow::Borrowed(bytes.as_slice()),
    };
    ensure_utf8_bytes(&buffered)?;
    let crlf = buffered.windows(2).any(|pair| pair == b"\r\n");
    Ok((
        TableSource::Buffer(buffered),
        crlf,
        table_delimiter(req, None),
    ))
}

fn file_digest(path: &Path) -> Result<[u8; 32]> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("read {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

fn ensure_digest_unchanged(path: &Path, expected: [u8; 32]) -> Result<()> {
    if file_digest(path)? != expected {
        return Err(fail(format!(
            "input changed after the pseudonymization plan was created: {}",
            path.display()
        )));
    }
    Ok(())
}

fn read_text_source(req: &PseudonymizeRequest) -> Result<String> {
    let bytes = match &req.source {
        PseudonymizeSource::File(path) => {
            std::fs::read(path).with_context(|| format!("read {}", path.display()))?
        }
        PseudonymizeSource::Stdin => read_stdin_bytes()?,
        // Pasted content is borrowed by the table path; text mode needs an
        // owned String either way.
        PseudonymizeSource::Buffer(bytes) => bytes.to_vec(),
    };
    String::from_utf8(bytes).map_err(|_| encoding_error())
}

fn read_stdin_bytes() -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    io::stdin().read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn table_delimiter(req: &PseudonymizeRequest, path: Option<&Path>) -> u8 {
    match req.format {
        Some(PseudonymizeFormatArg::Tsv) => b'\t',
        Some(PseudonymizeFormatArg::Csv) => b',',
        None => delimiter_for_path(path),
    }
}

/// Load an existing map for merging. `decrypt_map` already enforces the
/// document version and normalization; a wrong key fails the AEAD tag.
fn prepare_map(map: Option<&Path>, material: &KeyMaterial) -> Result<Option<MapCollector>> {
    let Some(path) = map else {
        return Ok(None);
    };
    let mut collector = MapCollector::default();
    if path.exists() {
        let bytes = read_map_bounded(path)?;
        let existing = decrypt_map(material, &bytes)?;
        if existing.key_fingerprint != material.fingerprint() {
            return Err(fail("existing --map was encrypted with a different key"));
        }
        collector.merge(existing);
    }
    Ok(Some(collector))
}

fn read_map_bounded(path: &Path) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let size = file
        .metadata()
        .with_context(|| format!("inspect {}", path.display()))?
        .len();
    if size > MAX_MAP_BYTES {
        return Err(fail(format!(
            "restore map exceeds the {} MiB limit: {}",
            MAX_MAP_BYTES / (1024 * 1024),
            path.display()
        )));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
    file.take(MAX_MAP_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", path.display()))?;
    if bytes.len() as u64 > MAX_MAP_BYTES {
        return Err(fail(format!(
            "restore map exceeds the {} MiB limit: {}",
            MAX_MAP_BYTES / (1024 * 1024),
            path.display()
        )));
    }
    Ok(bytes)
}

pub(crate) fn require_map_path(path: &Path) -> Result<()> {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some(ext) if ext.eq_ignore_ascii_case("shk-map") => Ok(()),
        _ => Err(fail("--map path must end with .shk-map")),
    }
}

/// Scan the written output for anything `pii.*` / `secret.*` still detects
/// and return the leftover rule ids. A file the scanner would silently skip
/// (excluded by `[scan]` patterns or above `max_file_size_bytes`) is an
/// error, never a pass.
fn check_remaining(project_root: &Path, policy: &Policy, output: &Path) -> Result<Vec<String>> {
    let rel = policy_relative_label(project_root, output);
    if shk_core::scanner::path_is_excluded(policy, &rel)? {
        return Err(fail(format!(
            "--check-remaining cannot verify `{rel}`: it matches a [scan] exclude / include pattern"
        )));
    }
    let result = scan_path(
        output,
        ScanOptions {
            policy_root: Some(project_root.to_path_buf()),
            sensitive_check: true,
            ..Default::default()
        },
    )?;
    // Only skips that mean "the bytes were never inspected" invalidate the
    // check; an Office file with no extractable text has nothing to leak.
    const NOT_INSPECTED: &[&str] = &[
        "scan.file_too_large",
        "scan.file_read_error",
        "scan.binary_skipped",
        "scan.walk_error",
    ];
    let skipped: Vec<&str> = result
        .findings
        .iter()
        .filter(|finding| NOT_INSPECTED.contains(&finding.rule_id.as_str()))
        .map(|finding| finding.message.as_str())
        .collect();
    if !skipped.is_empty() {
        return Err(fail(format!(
            "--check-remaining could not scan the output: {}",
            skipped.join("; ")
        )));
    }
    // The plaintext-map heuristic keys on tokens, which every output contains;
    // a real leftover next to a token is already reported by its own rule.
    let mut leftover: Vec<String> = result
        .findings
        .iter()
        .filter(|finding| {
            (finding.rule_id.starts_with("pii.") || finding.rule_id.starts_with("secret."))
                && finding.rule_id != "pii.shk_plaintext_map"
        })
        .map(|finding| finding.rule_id.clone())
        .collect();
    leftover.sort();
    leftover.dedup();
    Ok(leftover)
}

/// Leftovers are the one exit-1 outcome on the pseudonymize path.
fn leftover_error(leftover: &[String]) -> anyhow::Error {
    anyhow!(CliExit::message(
        1,
        format!(
            "--check-remaining found leftover detections (not a sufficiency guarantee): {}",
            leftover.join(", ")
        )
    ))
}

/// The scanner labels a single-file target by its path relative to the policy
/// root, falling back to the bare file name; mirror that for filter checks.
fn policy_relative_label(project_root: &Path, output: &Path) -> String {
    let root = std::fs::canonicalize(project_root).unwrap_or_else(|_| project_root.to_path_buf());
    let abs = std::fs::canonicalize(output).unwrap_or_else(|_| output.to_path_buf());
    abs.strip_prefix(&root)
        .map(|rel| rel.to_string_lossy().replace('\\', "/"))
        .unwrap_or_else(|_| {
            output
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default()
        })
}

fn print_meta_summary(meta: &PseudonymizeMeta, columns: Option<&[ResolvedColumn]>) {
    println!("Pseudonymized {} rows", meta.rows_processed);
    if let Some(columns) = columns {
        print_column_plan(columns);
    }
    for (kind, count) in &meta.replaced {
        println!("  {kind}: {count} replaced");
    }
    for (kind, count) in &meta.unparsed {
        println!("  {kind}: {count} unparsed");
    }
}

pub fn key_show(cwd: &Path) -> Result<()> {
    key_show_with(cwd, &open_pseudonymize_store)
}

fn key_show_with(cwd: &Path, open_store: StoreOpener<'_>) -> Result<()> {
    key_show_inner(cwd, open_store).map_err(fail_run)
}

fn key_show_inner(cwd: &Path, open_store: StoreOpener<'_>) -> Result<()> {
    let (policy, project, store, backend) = open_context(cwd, open_store)?;
    match load_material(store.as_ref(), &project)? {
        Some(material) => {
            println!("fingerprint: {}", material.fingerprint());
            println!(
                "namespace: {}",
                key_namespace(cwd, policy.env.project_id.as_deref())
            );
            println!("store: {}", backend_label(backend));
        }
        None => {
            return Err(fail(
                "no pseudonymize key for this project; run `shk mask --pseudonymize` to create one",
            ));
        }
    }
    Ok(())
}

pub fn key_rotate(cwd: &Path, yes: bool) -> Result<()> {
    key_rotate_with(cwd, yes, &open_pseudonymize_store)
}

fn key_rotate_with(cwd: &Path, yes: bool, open_store: StoreOpener<'_>) -> Result<()> {
    with_pseudonymize_lock(cwd, || key_rotate_inner(cwd, yes, open_store)).map_err(fail_run)
}

fn key_rotate_inner(cwd: &Path, yes: bool, open_store: StoreOpener<'_>) -> Result<()> {
    confirm(
        yes,
        "Replace the pseudonymize key? Existing tokens will no longer match and existing restore maps will become unrestorable.",
    )?;
    let (_policy, project, store, _backend) = open_context(cwd, open_store)?;
    let material = KeyMaterial::generate()?;
    store_material(store.as_ref(), &project, &material)
        .context("store rotated pseudonymize material")?;
    println!("rotated fingerprint: {}", material.fingerprint());
    Ok(())
}

pub fn key_delete(cwd: &Path, yes: bool) -> Result<()> {
    key_delete_with(cwd, yes, &open_pseudonymize_store)
}

fn key_delete_with(cwd: &Path, yes: bool, open_store: StoreOpener<'_>) -> Result<()> {
    with_pseudonymize_lock(cwd, || key_delete_inner(cwd, yes, open_store)).map_err(fail_run)
}

fn key_delete_inner(cwd: &Path, yes: bool, open_store: StoreOpener<'_>) -> Result<()> {
    confirm(
        yes,
        "Delete the pseudonymize key? Existing tokens will no longer be reproducible.",
    )?;
    let (_policy, project, store, _backend) = open_context(cwd, open_store)?;
    // Store backends treat a missing entry as success, so check first to
    // avoid reporting a deletion that never happened.
    let present = store
        .get(&project, STORE_ITEM)?
        .map(Zeroizing::new)
        .is_some();
    if !present {
        println!("no pseudonymize key for this project; nothing to delete");
        return Ok(());
    }
    store
        .delete(&project, STORE_ITEM)
        .context("delete pseudonymize material")?;
    println!("deleted project pseudonymize key");
    Ok(())
}

pub fn key_export(cwd: &Path, instructions: bool) -> Result<()> {
    key_export_with(cwd, instructions, &open_pseudonymize_store)
}

fn key_export_with(cwd: &Path, instructions: bool, open_store: StoreOpener<'_>) -> Result<()> {
    key_export_inner(cwd, instructions, open_store).map_err(fail_run)
}

fn key_export_inner(cwd: &Path, instructions: bool, open_store: StoreOpener<'_>) -> Result<()> {
    if !instructions {
        return Err(fail(
            "--instructions is required; raw material export is intentionally not supported",
        ));
    }
    let (_policy, project, store, backend) = open_context(cwd, open_store)?;
    let present = load_material(store.as_ref(), &project)?.is_some();
    let status = if present { "found" } else { "not found" };
    println!(
        "Project: {}\n\
Status: {status} in the {}\n\n\
Local team handoff:\n\
1. Retrieve the project pseudonymize material from your approved credential store.\n\
2. Share access only with teammates who need to reproduce tokens for this project.\n\
3. Ask each recipient to run:\n\n\
   shk pseudonymize key import --stdin\n\n\
For stdin-based imports from a password manager CLI:\n\n\
   <password-manager-read-command> | shk pseudonymize key import --stdin\n\n\
If the only copy is in the {}, retrieve it using your approved credential-store workflow; shk does not print raw material.\n\
Avoid committing stored material, pasting it into issue trackers, or sending it in public channels.\n\
This command intentionally does not print raw key material.",
        cwd.display(),
        backend_label(backend),
        backend_label(backend)
    );
    Ok(())
}

pub fn key_import(cwd: &Path, stdin: bool) -> Result<()> {
    if !stdin {
        return Err(fail("`shk pseudonymize key import` requires --stdin"));
    }
    if io::stdin().is_terminal() {
        return Err(fail(
            "pipe material on stdin; this command does not prompt for raw material",
        ));
    }
    key_import_with(cwd, io::stdin().lock(), &open_pseudonymize_store)
}

fn key_import_with(cwd: &Path, source: impl Read, open_store: StoreOpener<'_>) -> Result<()> {
    with_pseudonymize_lock(cwd, || key_import_inner(cwd, source, open_store)).map_err(fail_run)
}

fn key_import_inner(cwd: &Path, mut source: impl Read, open_store: StoreOpener<'_>) -> Result<()> {
    let mut raw = Zeroizing::new(String::new());
    source.read_to_string(&mut raw)?;
    let material = parse_stored_material(raw.trim())?;
    let (_policy, project, store, _backend) = open_context(cwd, open_store)?;
    if load_material(store.as_ref(), &project)?.is_some() {
        return Err(fail(
            "a pseudonymize key already exists; delete it explicitly before importing a replacement",
        ));
    }
    store_material(store.as_ref(), &project, &material).context("import pseudonymize material")?;
    println!("imported fingerprint: {}", material.fingerprint());
    Ok(())
}

fn with_pseudonymize_lock<T>(cwd: &Path, operation: impl FnOnce() -> Result<T>) -> Result<T> {
    let (policy, _) = Policy::load_from_dir(cwd)?;
    let project = ProjectIdentity::from_root_and_policy(cwd.to_path_buf(), &policy);
    with_secret_store_lock(&project, OPERATION_LOCK, operation)
}

pub(crate) fn open_context(
    cwd: &Path,
    open_store: StoreOpener<'_>,
) -> Result<(
    Policy,
    ProjectIdentity,
    Box<dyn SecretStore>,
    SecretStoreBackend,
)> {
    let (policy, _) = Policy::load_from_dir(cwd)?;
    let project = ProjectIdentity::from_root_and_policy(cwd.to_path_buf(), &policy);
    let (store, backend) = open_store(&project, &policy)?;
    Ok((policy, project, store, backend))
}

fn load_or_create_material(
    project: &ProjectIdentity,
    policy: &Policy,
    open_store: StoreOpener<'_>,
    interaction: &dyn Interaction,
) -> Result<KeyMaterial> {
    let (store, _backend) = open_store(project, policy)?;
    if let Some(material) = load_material(store.as_ref(), project)? {
        return Ok(material);
    }
    interaction.confirm_create_key()?;
    let material = KeyMaterial::generate()?;
    store_material(store.as_ref(), project, &material)
        .context("store new pseudonymize material")?;
    Ok(material)
}

pub(crate) fn load_material(
    store: &dyn SecretStore,
    project: &ProjectIdentity,
) -> Result<Option<KeyMaterial>> {
    let Some(raw) = store.get(project, STORE_ITEM)? else {
        return Ok(None);
    };
    let raw = Zeroizing::new(raw);
    parse_stored_material(&raw)
        .context("parse stored pseudonymize material")
        .map(Some)
}

fn store_material(
    store: &dyn SecretStore,
    project: &ProjectIdentity,
    material: &KeyMaterial,
) -> Result<()> {
    let encoded = Zeroizing::new(material.encode_store());
    store.put(project, STORE_ITEM, &encoded)
}

fn confirm(yes: bool, prompt: &str) -> Result<()> {
    if yes {
        return Ok(());
    }
    if !io::stdin().is_terminal() {
        return Err(fail("confirmation requires a TTY; pass --yes"));
    }
    let accepted = Confirm::new()
        .with_prompt(prompt)
        .default(false)
        .interact()
        .context("confirmation prompt")?;
    if accepted {
        Ok(())
    } else {
        Err(fail("cancelled"))
    }
}

fn print_column_plan(columns: &[ResolvedColumn]) {
    println!("Columns:");
    for column in columns {
        let source = match column.source {
            ColumnSource::Config => "config",
            ColumnSource::Cli => "cli",
            ColumnSource::Inferred => "inferred",
            ColumnSource::Rule => "rule",
        };
        match column.match_rate {
            Some(rate) => println!(
                "  {} ({}, {source}, match {:.0}%)",
                column.name,
                column.kind.as_config_value(),
                rate * 100.0
            ),
            None => println!(
                "  {} ({}, {source})",
                column.name,
                column.kind.as_config_value()
            ),
        }
    }
}

fn ensure_utf8_bytes(bytes: &[u8]) -> Result<()> {
    std::str::from_utf8(bytes)
        .map(|_| ())
        .map_err(|_| encoding_error())
}

fn ensure_utf8_file(path: &Path) -> Result<()> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut buf = [0u8; 65_536];
    let mut leftover = Vec::new();
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        leftover.extend_from_slice(&buf[..n]);
        match std::str::from_utf8(&leftover) {
            Ok(_) => leftover.clear(),
            Err(err) if err.error_len().is_some() => {
                return Err(encoding_error());
            }
            Err(err) => leftover = leftover[err.valid_up_to()..].to_vec(),
        }
    }
    if leftover.is_empty() {
        Ok(())
    } else {
        Err(encoding_error())
    }
}

/// Invalid UTF-8 in this product almost always means a Shift_JIS export, so
/// the hint names that conversion directly.
fn encoding_error() -> anyhow::Error {
    fail(NOT_UTF8_HINT)
}

/// Whether the first line ends in CRLF. Reads until the first `\n` (bounded)
/// so a very wide header row cannot hide the terminator.
fn file_uses_crlf(path: &Path) -> Result<bool> {
    const MAX_PROBE_BYTES: usize = 8 * 1024 * 1024;
    let mut file = BufReader::new(File::open(path)?);
    let mut line = Vec::new();
    let mut chunk = [0u8; 8192];
    while line.len() < MAX_PROBE_BYTES {
        let n = file.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        line.extend_from_slice(&chunk[..n]);
        if let Some(pos) = line.iter().position(|byte| *byte == b'\n') {
            return Ok(pos > 0 && line[pos - 1] == b'\r');
        }
    }
    Ok(false)
}

fn is_table_path(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some(ext) if ext.eq_ignore_ascii_case("csv") || ext.eq_ignore_ascii_case("tsv")
    )
}

fn is_xlsx_path(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("xlsx"))
}

fn is_office_path(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some(ext) if ext.eq_ignore_ascii_case("docx")
            || ext.eq_ignore_ascii_case("pptx")
            || ext.eq_ignore_ascii_case("xlsx")
    )
}

fn paths_equal(left: &Path, right: &Path) -> bool {
    fn resolved(path: &Path) -> PathBuf {
        if let Ok(path) = std::fs::canonicalize(path) {
            return path;
        }
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir().unwrap_or_default().join(path)
        };
        let mut normalized = PathBuf::new();
        for component in absolute.components() {
            match component {
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    normalized.pop();
                }
                other => normalized.push(other.as_os_str()),
            }
            if let Ok(canonical) = std::fs::canonicalize(&normalized) {
                normalized = canonical;
            }
        }
        normalized
    }
    resolved(left) == resolved(right)
}

fn new_output_temp(path: &Path) -> Result<tempfile::NamedTempFile> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let tmp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("create temp file in {}", parent.display()))?;
    if let Ok(metadata) = std::fs::metadata(path) {
        std::fs::set_permissions(tmp.path(), metadata.permissions())
            .with_context(|| format!("preserve permissions for {}", path.display()))?;
    }
    Ok(tmp)
}

fn stage_bytes(path: &Path, bytes: &[u8]) -> Result<TempPath> {
    let mut tmp = new_output_temp(path)?;
    tmp.write_all(bytes)
        .with_context(|| format!("write staged output for {}", path.display()))?;
    tmp.flush()
        .with_context(|| format!("flush staged output for {}", path.display()))?;
    tmp.as_file()
        .sync_all()
        .with_context(|| format!("sync staged output for {}", path.display()))?;
    Ok(tmp.into_temp_path())
}

fn persist_temp_path(tmp: TempPath, path: &Path) -> Result<()> {
    tmp.persist(path)
        .map(|_| ())
        .map_err(|err| anyhow!("write {}: {}", path.display(), err.error))
}

pub(crate) fn meta_sidecar(output: &Path) -> PathBuf {
    let mut name = output.as_os_str().to_os_string();
    name.push(".shk-meta.json");
    PathBuf::from(name)
}

fn key_namespace(root: &Path, project_id: Option<&str>) -> String {
    if let Some(id) = project_id.map(str::trim).filter(|id| !id.is_empty()) {
        return id.to_string();
    }
    std::fs::canonicalize(root)
        .unwrap_or_else(|_| root.to_path_buf())
        .to_string_lossy()
        .replace('\\', "/")
}

pub(crate) fn backend_label(backend: SecretStoreBackend) -> &'static str {
    match backend {
        SecretStoreBackend::Keyring => "OS credential store",
        SecretStoreBackend::OnePassword => "configured 1Password vault",
    }
}

fn fail(message: impl Into<String>) -> anyhow::Error {
    CliExit::message(2, message).into()
}

/// Map a runtime error to exit 2 unless it already carries an explicit exit code.
fn fail_run(err: anyhow::Error) -> anyhow::Error {
    if err
        .chain()
        .any(|cause| cause.downcast_ref::<CliExit>().is_some())
    {
        return err;
    }
    CliExit::message(2, format!("{err:#}")).into()
}

/// Fixtures shared with `desktop_api` tests: an in-memory key store and
/// minimal Office containers.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::{Arc, Mutex};
    use zip::write::{FileOptions, ZipWriter};

    /// Single-project in-memory store; `Arc` so every `open_store` call
    /// sees the same entries, like a real keyring would.
    #[derive(Default)]
    pub(crate) struct MemoryStore {
        pub(crate) entries: Mutex<BTreeMap<String, String>>,
    }

    impl SecretStore for Arc<MemoryStore> {
        fn put(&self, _project: &ProjectIdentity, key: &str, value: &str) -> Result<()> {
            self.entries
                .lock()
                .unwrap()
                .insert(key.to_string(), value.to_string());
            Ok(())
        }

        fn get(&self, _project: &ProjectIdentity, key: &str) -> Result<Option<String>> {
            Ok(self.entries.lock().unwrap().get(key).cloned())
        }

        fn delete(&self, _project: &ProjectIdentity, key: &str) -> Result<()> {
            self.entries.lock().unwrap().remove(key);
            Ok(())
        }

        fn list_keys(&self, _project: &ProjectIdentity) -> Result<BTreeSet<String>> {
            Ok(self.entries.lock().unwrap().keys().cloned().collect())
        }
    }

    pub(crate) fn opener(
        store: Arc<MemoryStore>,
    ) -> impl Fn(&ProjectIdentity, &Policy) -> Result<(Box<dyn SecretStore>, SecretStoreBackend)> + 'static
    {
        move |_, _| {
            Ok((
                Box::new(Arc::clone(&store)) as Box<dyn SecretStore>,
                SecretStoreBackend::Keyring,
            ))
        }
    }

    pub(crate) fn project() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("shk.toml"), "").unwrap();
        dir
    }

    pub(crate) fn email() -> String {
        ["ada", "@", "example.com"].concat()
    }

    pub(crate) fn zip_options() -> FileOptions<'static, ()> {
        FileOptions::default().compression_method(zip::CompressionMethod::Deflated)
    }

    pub(crate) fn create_docx(path: &Path, text: &str) {
        let mut zip = ZipWriter::new(File::create(path).unwrap());
        zip.start_file("[Content_Types].xml", zip_options())
            .unwrap();
        zip.write_all(br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#).unwrap();
        zip.start_file("word/document.xml", zip_options()).unwrap();
        write!(
            zip,
            r#"<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>"#
        )
        .unwrap();
        zip.finish().unwrap();
    }

    /// Write an xlsx-shaped zip from raw entries.
    pub(crate) fn build_xlsx(path: &Path, entries: &[(&str, String)]) {
        let mut zip = ZipWriter::new(File::create(path).unwrap());
        for (name, body) in entries {
            zip.start_file(*name, zip_options()).unwrap();
            zip.write_all(body.as_bytes()).unwrap();
        }
        zip.finish().unwrap();
    }

    pub(crate) fn create_xlsx(path: &Path, header: &str, value: &str) {
        let mut zip = ZipWriter::new(File::create(path).unwrap());
        zip.start_file("[Content_Types].xml", zip_options())
            .unwrap();
        zip.write_all(b"<Types/>").unwrap();
        zip.start_file("xl/workbook.xml", zip_options()).unwrap();
        zip.write_all(br#"<workbook xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Customers" sheetId="1" r:id="rId1"/></sheets></workbook>"#).unwrap();
        zip.start_file("xl/_rels/workbook.xml.rels", zip_options())
            .unwrap();
        zip.write_all(br#"<Relationships><Relationship Id="rId1" Target="worksheets/sheet1.xml"/></Relationships>"#).unwrap();
        zip.start_file("xl/sharedStrings.xml", zip_options())
            .unwrap();
        write!(zip, "<sst><si><t>{value}</t></si></sst>").unwrap();
        zip.start_file("xl/worksheets/sheet1.xml", zip_options())
            .unwrap();
        write!(
            zip,
            r#"<worksheet><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>{header}</t></is></c></row><row r="2"><c r="A2" t="s"><v>0</v></c></row></sheetData></worksheet>"#
        )
        .unwrap();
        zip.finish().unwrap();
    }

    pub(crate) fn read_zip_entry(path: &Path, name: &str) -> String {
        let mut archive = zip::ZipArchive::new(File::open(path).unwrap()).unwrap();
        let mut body = String::new();
        archive
            .by_name(name)
            .unwrap()
            .read_to_string(&mut body)
            .unwrap();
        body
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use shk_core::pseudonymize::parse_columns_spec;
    use std::sync::Arc;

    fn args(root: &Path, file: &str, output: Option<&str>) -> MaskPseudonymizeArgs {
        MaskPseudonymizeArgs {
            project_root: root.to_path_buf(),
            file: Some(root.join(file)),
            json: false,
            output: output.map(|name| root.join(name)),
            yes: true,
            dry_run: false,
            columns: None,
            no_header: false,
            no_create_key: false,
            mode: None,
            format: None,
            sheet: None,
            map: None,
            check_remaining: false,
        }
    }

    fn exit_code(err: anyhow::Error) -> i32 {
        crate::exit::code_for(&err)
    }

    fn request(root: &Path, source: PseudonymizeSource) -> PseudonymizeRequest {
        PseudonymizeRequest {
            project_root: root.to_path_buf(),
            source,
            output: None,
            dry_run: true,
            columns: None,
            no_header: false,
            mode: None,
            format: None,
            sheet: None,
            map: None,
            check_remaining: false,
        }
    }

    fn buffer(text: &str) -> PseudonymizeSource {
        PseudonymizeSource::Buffer(Zeroizing::new(text.as_bytes().to_vec()))
    }

    #[test]
    fn preview_plans_without_touching_the_key_store() {
        let dir = project();
        let root = dir.path();
        let body = format!("Email,Note\n{},keep\n{},also\n", email(), email());
        std::fs::write(root.join("orders.csv"), &body).unwrap();

        let file = request(root, PseudonymizeSource::File(root.join("orders.csv")));
        let Preview::Table(table) = preview(&file).unwrap() else {
            panic!("csv previews as a table");
        };
        assert_eq!(table.headers, vec!["Email".to_string(), "Note".to_string()]);
        assert_eq!(table.sample_rows.len(), 2);
        assert_eq!(table.meta.rows_processed, 2);
        assert_eq!(table.columns.len(), 1);
        assert_eq!(table.columns[0].source, ColumnSource::Inferred);
        assert!(
            !root.join(".shk").exists(),
            "preview must not write anything"
        );

        // A pasted buffer plans the same way, and an exact selection can skip
        // what inference picked.
        let mut pasted = request(root, buffer(&body));
        pasted.mode = Some(PseudonymizeModeArg::Table);
        pasted.columns = Some(ColumnSelection::Resolved(ColumnOverrides {
            entries: vec![("Note".into(), Kind::Custom("note".into()))],
            skip: vec!["Email".into()],
            positions: Vec::new(),
        }));
        let Preview::Table(table) = preview(&pasted).unwrap() else {
            panic!("buffer previews as a table");
        };
        assert_eq!(table.columns.len(), 1);
        assert_eq!(table.columns[0].name, "Note");
        assert_eq!(table.columns[0].source, ColumnSource::Cli);

        // Zero columns is a valid preview; the caller decides what to do.
        let mut none = request(root, buffer("Note\nkeep\n"));
        none.mode = Some(PseudonymizeModeArg::Table);
        let Preview::Table(table) = preview(&none).unwrap() else {
            panic!("table");
        };
        assert!(table.columns.is_empty());

        let mut text = request(root, buffer("hello\n"));
        text.mode = Some(PseudonymizeModeArg::Text);
        assert!(matches!(preview(&text).unwrap(), Preview::Text));
        create_docx(&root.join("memo.docx"), "hello");
        let office = request(root, PseudonymizeSource::File(root.join("memo.docx")));
        assert!(matches!(preview(&office).unwrap(), Preview::Text));
        create_xlsx(&root.join("book.xlsx"), "Email", &email());
        let mut sheet = request(root, PseudonymizeSource::File(root.join("book.xlsx")));
        sheet.sheet = Some("Customers".into());
        let Preview::Table(table) = preview(&sheet).unwrap() else {
            panic!("xlsx");
        };
        assert_eq!(table.headers, vec!["Email".to_string()]);

        let mut not_dry = request(root, buffer("x\n"));
        not_dry.dry_run = false;
        assert!(preview(&not_dry).is_err());
    }

    #[test]
    fn decisions_replace_the_interactive_prompts() {
        let dir = project();
        let root = dir.path();
        let store = Arc::new(MemoryStore::default());
        let open = opener(Arc::clone(&store));
        std::fs::write(root.join("orders.csv"), format!("Email\n{}\n", email())).unwrap();

        let run = |accept_inferred: bool, create_key: bool, output: &str| {
            let mut req = request(root, PseudonymizeSource::File(root.join("orders.csv")));
            req.dry_run = false;
            req.output = Some(root.join(output));
            mask_core(
                req,
                &open,
                &Decisions {
                    accept_inferred,
                    create_key,
                },
            )
        };
        let err = run(false, true, "a.csv").unwrap_err();
        assert!(err.to_string().contains("confirmation"), "{err}");
        let err = run(true, false, "b.csv").unwrap_err();
        assert_eq!(err.to_string(), NO_KEY_MESSAGE);
        assert!(store.entries.lock().unwrap().is_empty());
        assert!(!root.join("b.csv").exists());

        let outcome = run(true, true, "c.csv").unwrap();
        assert_eq!(store.entries.lock().unwrap().len(), 1);
        let written = outcome.written.expect("real run writes");
        assert_eq!(written.output, root.join("c.csv"));
        assert_eq!(written.meta, root.join("c.csv.shk-meta.json"));
        assert!(written.map.is_none());
        assert!(outcome.remaining.is_none());
        assert_eq!(outcome.columns.map(|cols| cols.len()), Some(1));
        assert!(written.output.exists() && written.meta.exists());

        // Once the key exists, `create_key: false` no longer matters.
        let outcome = run(true, false, "d.csv").unwrap();
        assert!(outcome.written.is_some());
    }

    #[test]
    fn inline_runs_keep_everything_in_memory() {
        let dir = project();
        let root = dir.path();
        let store = Arc::new(MemoryStore::default());
        let open = opener(Arc::clone(&store));
        let decide = Decisions {
            accept_inferred: true,
            create_key: true,
        };
        let inline = |text: &str, mode, columns| InlineRequest {
            project_root: root.to_path_buf(),
            bytes: Zeroizing::new(text.as_bytes().to_vec()),
            mode,
            format: None,
            columns,
            no_header: false,
        };

        let text = pseudonymize_inline(
            inline(
                &format!("contact {}\n", email()),
                PseudonymizeModeArg::Text,
                None,
            ),
            &open,
            &decide,
        )
        .unwrap();
        assert!(text.output.contains("email_"), "{}", *text.output);
        assert!(!text.output.contains(&email()));
        assert!(text.columns.is_none());
        assert_eq!(text.meta.mode, "text");

        let table = pseudonymize_inline(
            inline(
                &format!("Email,Member\n{},m-1\n", email()),
                PseudonymizeModeArg::Table,
                Some(ColumnOverrides {
                    entries: vec![("Member".into(), Kind::Custom("member".into()))],
                    skip: vec!["Email".into()],
                    positions: Vec::new(),
                }),
            ),
            &open,
            &decide,
        )
        .unwrap();
        assert!(
            table.output.starts_with("Email,Member\n"),
            "{}",
            *table.output
        );
        assert!(
            table.output.contains(&email()),
            "skipped column is untouched"
        );
        assert!(table.output.contains("member_"), "{}", *table.output);
        assert_eq!(table.columns.as_ref().map(Vec::len), Some(1));
        assert_eq!(store.entries.lock().unwrap().len(), 1);

        let audit = std::fs::read_to_string(root.join(".shk").join("audit.log")).unwrap();
        assert!(audit.contains("\"inline\":true"), "{audit}");
        assert!(!audit.contains(&email()), "{audit}");
        // Nothing but the audit log touched the disk.
        let entries: Vec<_> = std::fs::read_dir(root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name != "shk.toml" && name != ".shk")
            .collect();
        assert!(entries.is_empty(), "{entries:?}");

        let err = pseudonymize_inline(
            inline("Note\nkeep\n", PseudonymizeModeArg::Table, None),
            &open,
            &decide,
        )
        .unwrap_err();
        assert!(err.to_string().contains("no columns"), "{err}");
        let err = pseudonymize_inline(
            inline("x", PseudonymizeModeArg::Text, None),
            &open,
            &Decisions {
                accept_inferred: true,
                create_key: false,
            },
        );
        assert!(err.is_ok(), "existing key needs no confirmation");
    }

    #[test]
    fn outcome_carries_leftovers_for_the_cli_to_report() {
        let dir = project();
        let root = dir.path();
        let open = opener(Arc::new(MemoryStore::default()));
        let card = ["4111", "1111", "1111", "1111"].join(" ");
        std::fs::write(
            root.join("rows.csv"),
            format!("Email,Card\n{},{card}\n", email()),
        )
        .unwrap();
        let mut req = request(root, PseudonymizeSource::File(root.join("rows.csv")));
        req.dry_run = false;
        req.output = Some(root.join("out.csv"));
        req.check_remaining = true;
        let outcome = mask_core(
            req,
            &open,
            &Decisions {
                accept_inferred: true,
                create_key: true,
            },
        )
        .unwrap();
        let leftover = outcome.remaining.unwrap().unwrap();
        assert_eq!(leftover, vec!["pii.credit_card".to_string()]);
    }

    #[test]
    fn csv_full_run_writes_everything_and_restores() {
        let dir = project();
        let root = dir.path();
        let store = Arc::new(MemoryStore::default());
        let open = opener(Arc::clone(&store));
        let input = format!("Email,Name,Note\n{},\"Lovelace, Ada\",keep\n", email());
        std::fs::write(root.join("orders.csv"), &input).unwrap();

        let mut first = args(root, "orders.csv", Some("out.csv"));
        first.columns = Some("Email:email,Name:name".into());
        first.map = Some(root.join("out.shk-map"));
        first.check_remaining = true;
        mask_with(first, &open).unwrap();

        let pseudo = std::fs::read_to_string(root.join("out.csv")).unwrap();
        assert!(
            !pseudo.contains("Lovelace") && !pseudo.contains("ada@"),
            "{pseudo}"
        );
        assert!(
            pseudo.contains("email_") && pseudo.contains("name_"),
            "{pseudo}"
        );
        let sidecar = std::fs::read_to_string(root.join("out.csv.shk-meta.json")).unwrap();
        assert!(sidecar.contains("\"map_created\": true"), "{sidecar}");
        assert!(!sidecar.contains("Lovelace"), "{sidecar}");
        assert!(
            std::fs::read(root.join("out.shk-map"))
                .unwrap()
                .starts_with(b"SHKMAP")
        );
        assert!(root.join(".shk").join("audit.log").exists());
        assert_eq!(store.entries.lock().unwrap().len(), 1);

        // Second run merges into the existing map and takes the JSON branch.
        let mut second = args(root, "orders.csv", Some("again.csv"));
        second.columns = Some("Email:email".into());
        second.map = Some(root.join("out.shk-map"));
        second.json = true;
        mask_with(second, &open).unwrap();

        restore_with(
            root,
            root.join("out.csv"),
            root.join("out.shk-map"),
            root.join("restored.csv"),
            &open,
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(root.join("restored.csv")).unwrap(),
            input
        );

        key_show_with(root, &open).unwrap();
        key_export_with(root, true, &open).unwrap();
        assert_eq!(
            exit_code(key_export_with(root, false, &open).unwrap_err()),
            2
        );
    }

    #[test]
    fn inferred_columns_and_dry_run_paths() {
        let dir = project();
        let root = dir.path();
        let store = Arc::new(MemoryStore::default());
        let open = opener(Arc::clone(&store));
        std::fs::write(
            root.join("orders.csv"),
            format!("Email,Note\n{},keep\n", email()),
        )
        .unwrap();
        let mut dry = args(root, "orders.csv", None);
        dry.dry_run = true;
        mask_with(dry, &open).unwrap();
        assert!(store.entries.lock().unwrap().is_empty());

        let mut no_key = args(root, "orders.csv", Some("out.csv"));
        no_key.no_create_key = true;
        assert_eq!(exit_code(mask_with(no_key, &open).unwrap_err()), 2);

        mask_with(args(root, "orders.csv", Some("out.csv")), &open).unwrap();
        let pseudo = std::fs::read_to_string(root.join("out.csv")).unwrap();
        assert!(
            pseudo.contains("email_") && pseudo.contains("keep"),
            "{pseudo}"
        );

        std::fs::write(root.join("notes.md"), "hello\n").unwrap();
        let mut text_dry = args(root, "notes.md", None);
        text_dry.dry_run = true;
        mask_with(text_dry, &open).unwrap();

        std::fs::write(root.join("broken.docx"), b"not an Office archive").unwrap();
        let mut office_dry = args(root, "broken.docx", None);
        office_dry.dry_run = true;
        assert_eq!(exit_code(mask_with(office_dry, &open).unwrap_err()), 2);
    }

    #[test]
    fn check_remaining_exits_1_when_pii_survives() {
        let dir = project();
        let root = dir.path();
        let store = Arc::new(MemoryStore::default());
        let open = opener(Arc::clone(&store));
        // Column inference only covers email / phone, so a card number in an
        // unselected column survives and must trip the leftover check.
        let card = ["4111", "1111", "1111", "1111"].join(" ");
        std::fs::write(root.join("rows.tsv"), format!("{}\t{card}\n", email())).unwrap();
        let mut run = args(root, "rows.tsv", Some("out.tsv"));
        run.no_header = true;
        run.columns = Some("0:email".into());
        run.check_remaining = true;
        let err = mask_with(run, &open).unwrap_err();
        assert_eq!(exit_code(err), 1);
        // The output is still written; only the leftover check failed.
        let pseudo = std::fs::read_to_string(root.join("out.tsv")).unwrap();
        assert!(pseudo.starts_with("email_"), "{pseudo}");
        assert!(pseudo.contains(&card), "{pseudo}");
    }

    #[test]
    fn check_remaining_refuses_outputs_the_scanner_would_skip() {
        let store = Arc::new(MemoryStore::default());
        let open = opener(Arc::clone(&store));
        for (policy, needle) in [
            ("[scan]\nexclude = [\"out.*\"]\n", "exclude"),
            ("[scan]\nmax_file_size_bytes = 8\n", "could not scan"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path();
            std::fs::write(root.join("shk.toml"), policy).unwrap();
            std::fs::write(root.join("orders.csv"), format!("Email\n{}\n", email())).unwrap();
            let mut run = args(root, "orders.csv", Some("out.csv"));
            run.columns = Some("Email:email".into());
            run.check_remaining = true;
            let err = mask_with(run, &open).unwrap_err();
            let message = err.to_string();
            assert_eq!(exit_code(err), 2, "{policy}");
            assert!(message.contains(needle), "{policy}: {message}");
        }
    }

    #[test]
    fn check_remaining_ignores_rule_and_suppression_bypasses() {
        let card = ["4111", "1111", "1111", "1111"].join(" ");
        for (policy_text, body) in [
            ("[rules]\npii = false\nsecrets = false\n", card.clone()),
            (
                "[[allowlist]]\nrule_id = \"pii.credit_card\"\npath = \"out.txt\"\nreason = \"test\"\n",
                card.clone(),
            ),
            (
                "",
                format!("# shk-ignore-next-line pii.credit_card\n{card}\n"),
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path();
            std::fs::write(root.join("shk.toml"), policy_text).unwrap();
            let output = root.join("out.txt");
            std::fs::write(&output, body).unwrap();
            let (policy, _) = Policy::load_from_dir(root).unwrap();
            let leftover = check_remaining(root, &policy, &output).unwrap();
            assert_eq!(
                leftover,
                vec!["pii.credit_card".to_string()],
                "{policy_text}"
            );
            assert_eq!(exit_code(leftover_error(&leftover)), 1, "{policy_text}");
        }
    }

    #[test]
    fn reversible_outputs_require_restore_compatible_extensions() {
        let dir = project();
        let root = dir.path();

        let mut table = args(root, "rows.csv", Some("out.csv"));
        table.map = Some(root.join("out.shk-map"));
        table.format = Some(PseudonymizeFormatArg::Tsv);
        let mut table_tsv = args(root, "rows.csv", Some("out.tsv"));
        table_tsv.map = Some(root.join("out.shk-map"));
        table_tsv.format = Some(PseudonymizeFormatArg::Tsv);
        let mut office = args(root, "report.docx", Some("out.bin"));
        office.map = Some(root.join("out.shk-map"));
        let mut text = args(root, "notes.md", Some("out.csv"));
        text.map = Some(root.join("out.shk-map"));

        let check = |cli: MaskPseudonymizeArgs, kind: InputKind| {
            validate_restore_compatible_output(&request_from_cli(cli), &kind)
        };
        assert!(check(table, InputKind::TableCsv).is_err());
        assert!(check(office, InputKind::TextOffice).is_err());
        assert!(check(text, InputKind::TextPlain).is_err());
        assert!(check(table_tsv, InputKind::TableCsv).is_ok());
    }

    #[test]
    fn mode_flag_conflicts_and_empty_plans_exit_2() {
        let dir = project();
        let root = dir.path();
        let open = opener(Arc::new(MemoryStore::default()));
        std::fs::write(root.join("notes.md"), "hello\n").unwrap();
        std::fs::write(root.join("plain.csv"), "Note\nkeep\n").unwrap();
        type Tweak = Box<dyn Fn(&mut MaskPseudonymizeArgs)>;
        let cases: Vec<(&str, Tweak)> = vec![
            (
                "notes.md",
                Box::new(|a| a.columns = Some("Email:email".into())),
            ),
            ("notes.md", Box::new(|a| a.no_header = true)),
            ("notes.md", Box::new(|a| a.sheet = Some("1".into()))),
            ("plain.csv", Box::new(|a| a.sheet = Some("1".into()))),
            ("plain.csv", Box::new(|_| {})),
            (
                "plain.csv",
                Box::new(|a| a.columns = Some("Note:bogus".into())),
            ),
        ];
        for (file, tweak) in cases {
            let mut run = args(root, file, Some("out.bin"));
            tweak(&mut run);
            let err = mask_with(run, &open).unwrap_err();
            let message = err.to_string();
            assert_eq!(exit_code(err), 2, "{file}: {message}");
        }
        // Unparsed counts are printed in the human summary.
        std::fs::write(root.join("tel.csv"), "Phone\nnot-a-number\n").unwrap();
        let mut run = args(root, "tel.csv", Some("tel.out.csv"));
        run.columns = Some("Phone:phone".into());
        mask_with(run, &open).unwrap();
        let sidecar = std::fs::read_to_string(root.join("tel.out.csv.shk-meta.json")).unwrap();
        assert!(sidecar.contains("\"unparsed\""), "{sidecar}");
    }

    #[test]
    fn restore_guards_paths_keys_and_multiple_originals() {
        let dir = project();
        let root = dir.path();
        let store = Arc::new(MemoryStore::default());
        let open = opener(Arc::clone(&store));
        let upper = ["Ada", "@", "Example.com"].concat();
        std::fs::write(root.join("notes.md"), format!("{} {upper}\n", email())).unwrap();
        let mut run = args(root, "notes.md", Some("out.md"));
        run.map = Some(root.join("out.shk-map"));
        mask_with(run, &open).unwrap();
        // Both spellings share a token; restore warns and uses the first one.
        let summary = restore_with(
            root,
            root.join("out.md"),
            root.join("out.shk-map"),
            root.join("back.md"),
            &open,
        )
        .unwrap();
        assert_eq!(summary.output, root.join("back.md"));
        assert_eq!(summary.replacements, 2);
        assert!(summary.ambiguous >= 1, "{}", summary.ambiguous);
        let back = std::fs::read_to_string(root.join("back.md")).unwrap();
        assert_eq!(back, format!("{0} {0}\n", email()));

        for (file, map, output) in [
            ("out.md", "out.shk-map", "out.shk-map"),
            ("out.md", "out.shk-map", "out.md"),
            ("out.md", "out.json", "x.md"),
        ] {
            let err = restore_with(
                root,
                root.join(file),
                root.join(map),
                root.join(output),
                &open,
            )
            .unwrap_err();
            assert_eq!(exit_code(err), 2, "{file} {map} {output}");
        }
        let keyless = opener(Arc::new(MemoryStore::default()));
        let err = restore_with(
            root,
            root.join("out.md"),
            root.join("out.shk-map"),
            root.join("y.md"),
            &keyless,
        )
        .unwrap_err();
        assert!(err.to_string().contains("no pseudonymize key"), "{err}");
    }

    #[test]
    fn utf8_check_streams_across_chunk_boundaries() {
        let dir = project();
        let root = dir.path();
        // 3-byte characters never divide 64 KiB evenly, so one straddles the chunk edge.
        let body = "日".repeat(30_000);
        std::fs::write(root.join("big.txt"), &body).unwrap();
        ensure_utf8_file(&root.join("big.txt")).unwrap();
        let mut broken = body.into_bytes();
        broken.push(0xff);
        std::fs::write(root.join("broken.txt"), broken).unwrap();
        assert!(ensure_utf8_file(&root.join("broken.txt")).is_err());
        assert!(paths_equal(&root.join("big.txt"), &root.join("./big.txt")));
        assert_eq!(
            policy_relative_label(root, &root.join("big.txt")),
            "big.txt"
        );
        assert_eq!(
            policy_relative_label(root, Path::new("/elsewhere/out.csv")),
            "out.csv"
        );
    }

    #[test]
    fn text_and_docx_runs_restore_through_the_map() {
        let dir = project();
        let root = dir.path();
        let store = Arc::new(MemoryStore::default());
        let open = opener(Arc::clone(&store));
        let secret = format!("sk-proj-{}abcdefghijklmnopqrstuvwxyz0123456789", "z");
        std::fs::write(
            root.join("notes.md"),
            format!("contact {} key {secret}\n", email()),
        )
        .unwrap();
        let mut text = args(root, "notes.md", Some("notes.pseudo.md"));
        text.map = Some(root.join("notes.shk-map"));
        mask_with(text, &open).unwrap();
        let pseudo = std::fs::read_to_string(root.join("notes.pseudo.md")).unwrap();
        assert!(
            pseudo.contains("email_") && pseudo.contains("[REDACTED]"),
            "{pseudo}"
        );
        assert!(!pseudo.contains(&secret), "{pseudo}");
        restore_with(
            root,
            root.join("notes.pseudo.md"),
            root.join("notes.shk-map"),
            root.join("notes.restored.md"),
            &open,
        )
        .unwrap();
        let restored = std::fs::read_to_string(root.join("notes.restored.md")).unwrap();
        assert_eq!(restored, format!("contact {} key [REDACTED]\n", email()));

        create_docx(&root.join("memo.docx"), &email());
        let mut office_dry = args(root, "memo.docx", None);
        office_dry.dry_run = true;
        mask_with(office_dry, &open).unwrap();
        let mut office = args(root, "memo.docx", Some("memo.pseudo.docx"));
        office.map = Some(root.join("notes.shk-map"));
        mask_with(office, &open).unwrap();
        let body = read_zip_entry(&root.join("memo.pseudo.docx"), "word/document.xml");
        assert!(
            body.contains("email_") && !body.contains(&email()),
            "{body}"
        );
        restore_with(
            root,
            root.join("memo.pseudo.docx"),
            root.join("notes.shk-map"),
            root.join("memo.restored.docx"),
            &open,
        )
        .unwrap();
        let body = read_zip_entry(&root.join("memo.restored.docx"), "word/document.xml");
        assert!(body.contains(&email()), "{body}");
    }

    #[test]
    fn xlsx_table_run_rewrites_the_selected_sheet() {
        let dir = project();
        let root = dir.path();
        let store = Arc::new(MemoryStore::default());
        let open = opener(Arc::clone(&store));
        create_xlsx(&root.join("book.xlsx"), "Email", &email());
        let mut dry = args(root, "book.xlsx", None);
        dry.dry_run = true;
        dry.sheet = Some("Customers".into());
        mask_with(dry, &open).unwrap();
        let mut run = args(root, "book.xlsx", Some("book.pseudo.xlsx"));
        run.columns = Some("Email:email".into());
        run.sheet = Some("1".into());
        run.check_remaining = true;
        mask_with(run, &open).unwrap();
        let sheet = read_zip_entry(&root.join("book.pseudo.xlsx"), "xl/worksheets/sheet1.xml");
        assert!(
            sheet.contains("email_") && !sheet.contains(&email()),
            "{sheet}"
        );
        let mut missing = args(root, "book.xlsx", Some("other.xlsx"));
        missing.sheet = Some("Nope".into());
        assert_eq!(exit_code(mask_with(missing, &open).unwrap_err()), 2);
    }

    #[test]
    fn map_from_another_key_is_rejected() {
        let dir = project();
        let root = dir.path();
        std::fs::write(root.join("notes.md"), format!("{}\n", email())).unwrap();
        let first = opener(Arc::new(MemoryStore::default()));
        let mut run = args(root, "notes.md", Some("a.md"));
        run.map = Some(root.join("shared.shk-map"));
        mask_with(run, &first).unwrap();

        let second = opener(Arc::new(MemoryStore::default()));
        let mut again = args(root, "notes.md", Some("b.md"));
        again.map = Some(root.join("shared.shk-map"));
        let err = mask_with(again, &second).unwrap_err();
        assert_eq!(exit_code(err), 2);
        let err = restore_with(
            root,
            root.join("a.md"),
            root.join("shared.shk-map"),
            root.join("c.md"),
            &second,
        )
        .unwrap_err();
        assert_eq!(exit_code(err), 2);
        let err = restore_with(
            root,
            root.join("a.md"),
            root.join("missing.shk-map"),
            root.join("d.md"),
            &first,
        )
        .unwrap_err();
        assert_eq!(exit_code(err), 2);
    }

    #[test]
    fn key_lifecycle_import_rotate_delete() {
        let dir = project();
        let root = dir.path();
        let store = Arc::new(MemoryStore::default());
        let open = opener(Arc::clone(&store));
        assert_eq!(exit_code(key_show_with(root, &open).unwrap_err()), 2);
        assert_eq!(
            exit_code(key_import_with(root, "garbage".as_bytes(), &open).unwrap_err()),
            2
        );
        let material = KeyMaterial::generate().unwrap();
        let encoded = format!("{}\n", material.encode_store());
        key_import_with(root, encoded.as_bytes(), &open).unwrap();
        let (_, project, boxed, _) = open_context(root, &open).unwrap();
        let loaded = load_material(boxed.as_ref(), &project).unwrap().unwrap();
        assert_eq!(loaded.fingerprint(), material.fingerprint());
        let replacement = KeyMaterial::generate().unwrap().encode_store();
        let err = key_import_with(root, replacement.as_bytes(), &open).unwrap_err();
        assert_eq!(exit_code(err), 2);
        let still_loaded = load_material(boxed.as_ref(), &project).unwrap().unwrap();
        assert_eq!(still_loaded.fingerprint(), material.fingerprint());
        key_rotate_with(root, true, &open).unwrap();
        let rotated = load_material(boxed.as_ref(), &project).unwrap().unwrap();
        assert_ne!(rotated.fingerprint(), material.fingerprint());
        key_delete_with(root, true, &open).unwrap();
        assert!(load_material(boxed.as_ref(), &project).unwrap().is_none());
        // Deleting again is a no-op that must still succeed.
        key_delete_with(root, true, &open).unwrap();
        assert!(store.entries.lock().unwrap().is_empty());
    }

    #[test]
    fn output_path_and_encoding_guards() {
        let dir = project();
        let root = dir.path();
        let open = opener(Arc::new(MemoryStore::default()));
        std::fs::write(root.join("orders.csv"), "Email\r\n").unwrap();
        let mut same = args(root, "orders.csv", Some("orders.csv"));
        same.columns = Some("Email:email".into());
        assert_eq!(exit_code(mask_with(same, &open).unwrap_err()), 2);
        let mut clash = args(root, "orders.csv", Some("out.csv"));
        clash.map = Some(root.join("out.csv.shk-meta.json"));
        assert_eq!(exit_code(mask_with(clash, &open).unwrap_err()), 2);
        std::fs::create_dir(root.join("blocked.csv.shk-meta.json")).unwrap();
        let mut blocked = args(root, "orders.csv", Some("blocked.csv"));
        blocked.columns = Some("Email:email".into());
        assert_eq!(exit_code(mask_with(blocked, &open).unwrap_err()), 2);
        assert!(!root.join("blocked.csv").exists());
        let mut no_output = args(root, "orders.csv", None);
        no_output.check_remaining = true;
        assert_eq!(exit_code(mask_with(no_output, &open).unwrap_err()), 2);
        assert!(file_uses_crlf(&root.join("orders.csv")).unwrap());
        let wide = format!("{}\r\nx\r\n", "h,".repeat(5000));
        std::fs::write(root.join("wide.csv"), wide).unwrap();
        assert!(file_uses_crlf(&root.join("wide.csv")).unwrap());
        std::fs::write(root.join("lf.csv"), "a\nb\r\n").unwrap();
        assert!(!file_uses_crlf(&root.join("lf.csv")).unwrap());
        std::fs::create_dir(root.join("dir.csv")).unwrap();
        let mut directory = args(root, "dir.csv", Some("out2.csv"));
        directory.columns = Some("Email:email".into());
        let err = mask_with(directory, &open).unwrap_err();
        assert!(err.to_string().contains("regular file"), "{err}");

        std::fs::write(root.join("sjis.csv"), [0x82, 0xa0, b'\n']).unwrap();
        let err = ensure_utf8_file(&root.join("sjis.csv")).unwrap_err();
        assert!(err.to_string().contains("UTF-8"), "{err}");
        let mut bad = args(root, "sjis.csv", Some("out.csv"));
        bad.no_header = true;
        assert_eq!(exit_code(mask_with(bad, &open).unwrap_err()), 2);
    }

    #[test]
    fn path_comparison_resolves_missing_destinations() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("output.shk-map");
        assert!(paths_equal(&output, &dir.path().join("./output.shk-map")));
        assert!(!paths_equal(&output, &dir.path().join("other.shk-map")));
    }

    #[test]
    fn table_paths_accept_csv_and_tsv() {
        assert!(is_table_path(Path::new("orders.csv")));
        assert!(is_table_path(Path::new("orders.TSV")));
        assert!(!is_table_path(Path::new("notes.md")));
    }

    #[test]
    fn sidecar_appends_suffix() {
        assert_eq!(
            meta_sidecar(Path::new("out.pseudo.csv")),
            PathBuf::from("out.pseudo.csv.shk-meta.json")
        );
    }

    #[test]
    fn restore_map_reader_rejects_oversized_files_before_allocation() {
        let dir = project();
        let map = dir.path().join("huge.shk-map");
        let file = File::create(&map).unwrap();
        file.set_len(MAX_MAP_BYTES + 1).unwrap();
        let err = read_map_bounded(&map).unwrap_err();
        assert!(err.to_string().contains("64 MiB"), "{err}");
    }

    #[test]
    fn columns_spec_from_cli_parses() {
        let parsed = parse_columns_spec("Email:email,0:phone").unwrap();
        assert_eq!(parsed.entries.len(), 2);
    }

    #[test]
    fn classifies_phase1b_inputs() {
        assert!(matches!(
            classify_input(Some(Path::new("notes.md")), None, None).unwrap(),
            InputKind::TextPlain
        ));
        assert!(matches!(
            classify_input(Some(Path::new("book.xlsx")), None, None).unwrap(),
            InputKind::TableXlsx
        ));
        assert!(matches!(
            classify_input(
                Some(Path::new("book.xlsx")),
                Some(PseudonymizeModeArg::Text),
                None
            )
            .unwrap(),
            InputKind::TextOffice
        ));
        assert!(matches!(
            classify_input(Some(Path::new("talk.pptx")), None, None).unwrap(),
            InputKind::TextOffice
        ));
        assert!(classify_input(Some(Path::new("doc.pdf")), None, None).is_err());
        assert!(
            classify_input(
                Some(Path::new("book.xlsx")),
                None,
                Some(PseudonymizeFormatArg::Csv)
            )
            .is_err()
        );
        assert!(matches!(
            classify_input(None, None, Some(PseudonymizeFormatArg::Tsv)).unwrap(),
            InputKind::TableCsv
        ));
        assert!(matches!(
            classify_input(None, None, None).unwrap(),
            InputKind::TextPlain
        ));
        assert!(matches!(
            classify_input(
                Some(Path::new("data.bin")),
                Some(PseudonymizeModeArg::Table),
                None
            )
            .unwrap(),
            InputKind::TableCsv
        ));
        assert!(matches!(
            classify_input(
                Some(Path::new("book.xlsx")),
                Some(PseudonymizeModeArg::Table),
                None
            )
            .unwrap(),
            InputKind::TableXlsx
        ));
        assert!(require_map_path(Path::new("out.shk-map")).is_ok());
        assert!(require_map_path(Path::new("out.json")).is_err());
    }

    #[test]
    fn fail_run_keeps_explicit_exit_codes() {
        let leftover: anyhow::Error = CliExit::message(1, "leftover").into();
        assert_eq!(crate::exit::code_for(&fail_run(leftover)), 1);
        let plain = anyhow!("io failure");
        assert_eq!(crate::exit::code_for(&fail_run(plain)), 2);
    }

    #[test]
    fn policy_section_rejects_invalid_rule_kinds() {
        let mut policy = Policy::default();
        policy
            .pseudonymize
            .rules
            .insert("pii.email".into(), "custom:Bad Label".into());
        let err = validate_policy_section(&policy).unwrap_err();
        assert!(err.to_string().contains("[pseudonymize.rules]"), "{err}");
        assert_eq!(crate::exit::code_for(&err), 2);
    }
}
