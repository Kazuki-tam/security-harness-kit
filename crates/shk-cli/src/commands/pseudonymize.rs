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
    decrypt_map, delimiter_for_path, encrypt_map, parse_columns_spec, parse_stored_material,
    restore_table, run_office_text, run_table, run_text, run_xlsx,
};
use shk_core::scanner::{ScanOptions, scan_path};
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

enum InputKind {
    TableCsv,
    TableXlsx,
    TextPlain,
    TextOffice,
}

/// Opens the project's pseudonymize key store. Injected so the complete
/// write / restore path can run against an in-memory store in unit tests.
type StoreOpener<'a> =
    &'a dyn Fn(&ProjectIdentity, &Policy) -> Result<(Box<dyn SecretStore>, SecretStoreBackend)>;

/// Every failure on the pseudonymize path exits 2 (usage / runtime error) so
/// that exit 1 stays reserved for `--check-remaining` leftovers.
pub fn mask(args: MaskPseudonymizeArgs) -> Result<()> {
    mask_with(args, &open_pseudonymize_store)
}

fn mask_with(args: MaskPseudonymizeArgs, open_store: StoreOpener<'_>) -> Result<()> {
    mask_inner(args, open_store).map_err(fail_run)
}

fn mask_inner(args: MaskPseudonymizeArgs, open_store: StoreOpener<'_>) -> Result<()> {
    if !args.dry_run && args.output.is_none() {
        return Err(fail(
            "`mask --pseudonymize` requires --output so tokens are not written to stdout",
        ));
    }
    if args.check_remaining && args.dry_run {
        return Err(fail(
            "`--check-remaining` cannot be combined with `--dry-run`",
        ));
    }
    validate_output_paths(&args)?;
    if let Some(output) = args.output.as_ref() {
        safety::require_project_policy(&args.project_root, "mask --output")?;
        safety::ensure_writable_path_allowed(output)?;
    }
    if let Some(map) = args.map.as_ref() {
        require_map_path(map)?;
        safety::require_project_policy(&args.project_root, "mask --map")?;
        safety::ensure_writable_path_allowed(map)?;
    }

    let kind = classify_input(args.file.as_deref(), args.mode, args.format)?;
    validate_mode_flags(&args, &kind)?;

    if args.file.is_none() {
        if io::stdin().is_terminal() {
            return Err(fail(
                "pass a file or redirect stdin; `mask --pseudonymize` does not prompt for input",
            ));
        }
    } else {
        let input = args.file.as_ref().expect("file present");
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

    let (policy, _) = Policy::load_from_dir(&args.project_root)?;
    validate_policy_section(&policy)?;

    let run = || match kind {
        InputKind::TableCsv => run_table_csv(&args, &policy, open_store),
        InputKind::TableXlsx => run_table_xlsx(&args, &policy, open_store),
        InputKind::TextPlain => run_text_plain(&args, &policy, open_store),
        InputKind::TextOffice => run_text_office(&args, &policy, open_store),
    };
    if args.dry_run {
        run()
    } else {
        let project = ProjectIdentity::from_root_and_policy(args.project_root.clone(), &policy);
        with_secret_store_lock(&project, OPERATION_LOCK, run)
    }
}

/// Reject broken `[pseudonymize]` settings before any prompt or key creation,
/// including `rules` entries that would otherwise only fail once a rule matches.
fn validate_policy_section(policy: &Policy) -> Result<()> {
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

fn validate_output_paths(args: &MaskPseudonymizeArgs) -> Result<()> {
    let mut paths: Vec<(&str, PathBuf)> = Vec::new();
    if let Some(input) = &args.file {
        paths.push(("input", input.clone()));
    }
    if let Some(output) = &args.output {
        ensure_regular_destination(output, "output")?;
        paths.push(("output", output.clone()));
        let meta = meta_sidecar(output);
        ensure_regular_destination(&meta, "metadata")?;
        safety::ensure_writable_path_allowed(&meta)?;
        paths.push(("metadata", meta));
    }
    if let Some(map) = &args.map {
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

pub fn restore(cwd: &Path, file: PathBuf, map: PathBuf, output: PathBuf) -> Result<()> {
    restore_with(cwd, file, map, output, &open_pseudonymize_store)
}

fn restore_with(
    cwd: &Path,
    file: PathBuf,
    map: PathBuf,
    output: PathBuf,
    open_store: StoreOpener<'_>,
) -> Result<()> {
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
) -> Result<()> {
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

    let (replacements, multi) = if is_office_path(&file) {
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
    println!("Restored {replacements} token(s) to {}", output.display());
    if multi > 0 {
        eprintln!("warning: {multi} token(s) had multiple originals; first-seen value was used");
    }
    Ok(())
}

fn run_table_csv(
    args: &MaskPseudonymizeArgs,
    policy: &Policy,
    open_store: StoreOpener<'_>,
) -> Result<()> {
    let cli_columns = parse_cli_columns(args.columns.as_deref())?;
    let (source, crlf, delimiter) = read_table_source(args)?;
    let options = table_options(args, policy, delimiter, crlf, cli_columns, true);
    let preview = run_table(source.open()?, None::<&mut Vec<u8>>, &options, None, None)?;
    confirm_table_plan(args, &preview)?;
    if args.dry_run {
        return emit_dry_run(args, &preview.meta, Some(&preview.columns));
    }

    let output = args.output.as_ref().expect("checked above");
    let project = ProjectIdentity::from_root_and_policy(args.project_root.clone(), policy);
    let material =
        load_or_create_material(&project, policy, open_store, args.yes, args.no_create_key)?;
    let mut collector = prepare_map(args.map.as_deref(), &material)?;
    source.ensure_unchanged()?;
    let mut run_options = options;
    run_options.dry_run = false;
    let mut tmp = new_output_temp(output)?;
    let result = run_table(
        source.open()?,
        Some(tmp.as_file_mut()),
        &run_options,
        Some(&material),
        collector.as_mut(),
    )?;
    source.ensure_unchanged()?;
    tmp.flush()?;
    tmp.as_file().sync_all()?;
    finish_run(
        args,
        policy,
        &material,
        result.meta,
        Some(&result.columns),
        collector,
        "table",
        tmp.into_temp_path(),
    )
}

fn run_table_xlsx(
    args: &MaskPseudonymizeArgs,
    policy: &Policy,
    open_store: StoreOpener<'_>,
) -> Result<()> {
    let input = args
        .file
        .as_ref()
        .ok_or_else(|| fail("xlsx table mode requires a file path"))?;
    let input_digest = file_digest(input)?;
    let cli_columns = parse_cli_columns(args.columns.as_deref())?;
    let options = table_options(args, policy, b',', false, cli_columns, true);
    let preview = run_xlsx(input, None, args.sheet.as_deref(), &options, None, None)?;
    confirm_table_plan(args, &preview)?;
    if args.dry_run {
        return emit_dry_run(args, &preview.meta, Some(&preview.columns));
    }

    let output = args.output.as_ref().expect("checked above");
    let project = ProjectIdentity::from_root_and_policy(args.project_root.clone(), policy);
    let material =
        load_or_create_material(&project, policy, open_store, args.yes, args.no_create_key)?;
    let mut collector = prepare_map(args.map.as_deref(), &material)?;
    ensure_digest_unchanged(input, input_digest)?;
    let mut run_options = options;
    run_options.dry_run = false;
    let staged_output = new_output_temp(output)?.into_temp_path();
    let result = run_xlsx(
        input,
        Some(staged_output.as_ref()),
        args.sheet.as_deref(),
        &run_options,
        Some(&material),
        collector.as_mut(),
    )?;
    ensure_digest_unchanged(input, input_digest)?;
    finish_run(
        args,
        policy,
        &material,
        result.meta,
        Some(&result.columns),
        collector,
        "table",
        staged_output,
    )
}

fn run_text_plain(
    args: &MaskPseudonymizeArgs,
    policy: &Policy,
    open_store: StoreOpener<'_>,
) -> Result<()> {
    let input = read_text_source(args)?;
    let options = text_options(args, policy, true);
    if args.dry_run {
        let result = run_text(&input, None, &options, None)?;
        return emit_dry_run(args, &result.meta, None);
    }
    let output = args.output.as_ref().expect("checked above");
    let project = ProjectIdentity::from_root_and_policy(args.project_root.clone(), policy);
    let material =
        load_or_create_material(&project, policy, open_store, args.yes, args.no_create_key)?;
    let mut collector = prepare_map(args.map.as_deref(), &material)?;
    let mut run_options = options;
    run_options.dry_run = false;
    let result = run_text(&input, Some(&material), &run_options, collector.as_mut())?;
    let staged_output = stage_bytes(output, result.output.as_bytes())?;
    finish_run(
        args,
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
    args: &MaskPseudonymizeArgs,
    policy: &Policy,
    open_store: StoreOpener<'_>,
) -> Result<()> {
    let input = args
        .file
        .as_ref()
        .ok_or_else(|| fail("Office text mode requires a file path"))?;
    let options = text_options(args, policy, true);
    if args.dry_run {
        let result = run_office_text(
            input,
            None,
            None,
            &options,
            None,
            policy.scan.max_file_size_bytes,
        )?;
        return emit_dry_run(args, &result.meta, None);
    }
    let output = args.output.as_ref().expect("checked above");
    let project = ProjectIdentity::from_root_and_policy(args.project_root.clone(), policy);
    let material =
        load_or_create_material(&project, policy, open_store, args.yes, args.no_create_key)?;
    let mut collector = prepare_map(args.map.as_deref(), &material)?;
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
        args,
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
    args: &MaskPseudonymizeArgs,
    policy: &Policy,
    material: &KeyMaterial,
    mut meta: PseudonymizeMeta,
    columns: Option<&[ResolvedColumn]>,
    collector: Option<MapCollector>,
    mode: &str,
    staged_output: TempPath,
) -> Result<()> {
    let output = args.output.as_ref().expect("checked above");
    let staged_map = if let (Some(map_path), Some(collector)) = (args.map.as_ref(), collector) {
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
        &args.project_root,
        serde_json::json!({
            "event": "pseudonymize",
            "mode": mode,
            "rows": meta.rows_processed,
            "columns": columns.map(|cols| cols.len()).unwrap_or(0),
            "kinds": meta
                .columns
                .iter()
                .map(|column| column.kind.as_str())
                .collect::<Vec<_>>(),
            "map": args.map.is_some(),
        }),
    );

    if args.json {
        println!("{}", serde_json::to_string_pretty(&meta)?);
    } else {
        print_meta_summary(&meta, columns);
        println!("Wrote {}", output.display());
        println!("Wrote {}", meta_path.display());
        if let Some(map) = args.map.as_ref() {
            println!("Wrote {}", map.display());
        }
    }
    if args.check_remaining {
        check_remaining(&args.project_root, policy, output)?;
    }
    Ok(())
}

fn confirm_table_plan(args: &MaskPseudonymizeArgs, preview: &TableResult) -> Result<()> {
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
        print_column_plan(&preview.columns);
        confirm(args.yes, "Pseudonymize the inferred columns listed above?")?;
    }
    Ok(())
}

fn emit_dry_run(
    args: &MaskPseudonymizeArgs,
    meta: &PseudonymizeMeta,
    columns: Option<&[ResolvedColumn]>,
) -> Result<()> {
    if args.json {
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

fn classify_input(
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

fn validate_mode_flags(args: &MaskPseudonymizeArgs, kind: &InputKind) -> Result<()> {
    match kind {
        InputKind::TextPlain | InputKind::TextOffice => {
            if args.columns.is_some() {
                return Err(fail("`--columns` is only valid in table mode"));
            }
            if args.format.is_some() {
                return Err(fail("`--format` is only valid in table mode"));
            }
            if args.no_header {
                return Err(fail("`--no-header` is only valid in table mode"));
            }
            if args.sheet.is_some() {
                return Err(fail("`--sheet` is only valid for xlsx table mode"));
            }
        }
        InputKind::TableCsv => {
            if args.sheet.is_some() {
                return Err(fail("`--sheet` is only valid for xlsx table mode"));
            }
        }
        InputKind::TableXlsx => {}
    }
    Ok(())
}

fn parse_cli_columns(spec: Option<&str>) -> Result<Option<ColumnOverrides>> {
    spec.map(|spec| parse_columns_spec(spec).map_err(|err| fail(err.0)))
        .transpose()
}

fn table_options(
    args: &MaskPseudonymizeArgs,
    policy: &Policy,
    delimiter: u8,
    crlf: bool,
    cli_columns: Option<ColumnOverrides>,
    dry_run: bool,
) -> TableOptions {
    TableOptions {
        delimiter,
        no_header: args.no_header,
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
        key_namespace: key_namespace(&args.project_root, policy.env.project_id.as_deref()),
    }
}

fn text_options(args: &MaskPseudonymizeArgs, policy: &Policy, dry_run: bool) -> TextOptions {
    TextOptions {
        token_bits: policy.pseudonymize.token_bits,
        norm: policy.pseudonymize.norm.clone(),
        settings: NormalizeSettings {
            email_strip_subaddress: policy.pseudonymize.email_strip_subaddress,
        },
        rule_overrides: policy.pseudonymize.rules.clone(),
        shk_version: env!("CARGO_PKG_VERSION").into(),
        key_namespace: key_namespace(&args.project_root, policy.env.project_id.as_deref()),
        dry_run,
    }
}

/// Table input is read twice (plan, then rewrite). Files are streamed so
/// memory stays flat for large exports; stdin has to be buffered.
enum TableSource {
    File { path: PathBuf, digest: [u8; 32] },
    Stdin(Vec<u8>),
}

impl TableSource {
    fn open(&self) -> Result<Box<dyn Read + '_>> {
        match self {
            Self::File { path, .. } => {
                let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
                Ok(Box::new(BufReader::new(file)))
            }
            Self::Stdin(bytes) => Ok(Box::new(bytes.as_slice())),
        }
    }

    fn ensure_unchanged(&self) -> Result<()> {
        if let Self::File { path, digest } = self {
            ensure_digest_unchanged(path, *digest)?;
        }
        Ok(())
    }
}

fn read_table_source(args: &MaskPseudonymizeArgs) -> Result<(TableSource, bool, u8)> {
    if let Some(path) = args.file.as_ref() {
        // UTF-8 validity was checked in `mask_inner` before the policy loaded.
        return Ok((
            TableSource::File {
                path: path.clone(),
                digest: file_digest(path)?,
            },
            file_uses_crlf(path)?,
            table_delimiter(args, Some(path)),
        ));
    }
    let bytes = read_stdin_bytes()?;
    ensure_utf8_bytes(&bytes)?;
    let crlf = bytes.windows(2).any(|pair| pair == b"\r\n");
    Ok((TableSource::Stdin(bytes), crlf, table_delimiter(args, None)))
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

fn read_text_source(args: &MaskPseudonymizeArgs) -> Result<String> {
    let bytes = match args.file.as_ref() {
        Some(path) => std::fs::read(path).with_context(|| format!("read {}", path.display()))?,
        None => read_stdin_bytes()?,
    };
    String::from_utf8(bytes).map_err(|_| encoding_error())
}

fn read_stdin_bytes() -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    io::stdin().read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn table_delimiter(args: &MaskPseudonymizeArgs, path: Option<&Path>) -> u8 {
    match args.format {
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

fn require_map_path(path: &Path) -> Result<()> {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some(ext) if ext.eq_ignore_ascii_case("shk-map") => Ok(()),
        _ => Err(fail("--map path must end with .shk-map")),
    }
}

/// Scan the written output for anything `pii.*` / `secret.*` still detects.
/// A file the scanner would silently skip (excluded by `[scan]` patterns or
/// above `max_file_size_bytes`) is an error, never a pass.
fn check_remaining(project_root: &Path, policy: &Policy, output: &Path) -> Result<()> {
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
    if leftover.is_empty() {
        return Ok(());
    }
    Err(anyhow!(CliExit::message(
        1,
        format!(
            "--check-remaining found leftover detections (not a sufficiency guarantee): {}",
            leftover.join(", ")
        )
    )))
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

fn open_context(
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
    yes: bool,
    no_create: bool,
) -> Result<KeyMaterial> {
    let (store, _backend) = open_store(project, policy)?;
    if let Some(material) = load_material(store.as_ref(), project)? {
        return Ok(material);
    }
    if no_create {
        return Err(fail(
            "no pseudonymize key for this project; omit --no-create-key to create one",
        ));
    }
    confirm(
        yes,
        "No pseudonymize key found. Create a new project key in the configured secret store?",
    )?;
    let material = KeyMaterial::generate()?;
    store_material(store.as_ref(), project, &material)
        .context("store new pseudonymize material")?;
    Ok(material)
}

fn load_material(
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

fn meta_sidecar(output: &Path) -> PathBuf {
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

fn backend_label(backend: SecretStoreBackend) -> &'static str {
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

#[cfg(test)]
mod tests {
    use super::*;
    use shk_core::pseudonymize::parse_columns_spec;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::{Arc, Mutex};
    use zip::write::{FileOptions, ZipWriter};

    /// Single-project in-memory store; `Arc` so every `open_store` call
    /// sees the same entries, like a real keyring would.
    #[derive(Default)]
    struct MemoryStore {
        entries: Mutex<BTreeMap<String, String>>,
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

    fn opener(
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

    fn project() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("shk.toml"), "").unwrap();
        dir
    }

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

    fn email() -> String {
        ["ada", "@", "example.com"].concat()
    }

    fn zip_options() -> FileOptions<'static, ()> {
        FileOptions::default().compression_method(zip::CompressionMethod::Deflated)
    }

    fn create_docx(path: &Path, text: &str) {
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

    fn create_xlsx(path: &Path, header: &str, value: &str) {
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

    fn read_zip_entry(path: &Path, name: &str) -> String {
        let mut archive = zip::ZipArchive::new(File::open(path).unwrap()).unwrap();
        let mut body = String::new();
        archive
            .by_name(name)
            .unwrap()
            .read_to_string(&mut body)
            .unwrap();
        body
    }

    fn exit_code(err: anyhow::Error) -> i32 {
        crate::exit::code_for(&err)
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
        restore_with(
            root,
            root.join("out.md"),
            root.join("out.shk-map"),
            root.join("back.md"),
            &open,
        )
        .unwrap();
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
