use crate::args::{PseudonymizeFormatArg, PseudonymizeModeArg};
use crate::env_store::{ProjectIdentity, SecretStore, open_pseudonymize_store};
use crate::exit::CliExit;
use crate::safety;
use anyhow::{Context, Result, anyhow};
use dialoguer::Confirm;
use shk_core::policy::{Policy, SecretStoreBackend};
use shk_core::pseudonymize::{
    ColumnSource, KeyMaterial, MapCollector, NormalizeSettings, TableOptions, TextOptions,
    decrypt_map, delimiter_for_path, encrypt_map, parse_columns_spec, parse_stored_material,
    restore_text, run_office_text, run_table, run_text, run_xlsx,
};
use shk_core::scanner::{ScanOptions, scan_path};
use std::fs::File;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

const STORE_ITEM: &str = "v1";
const SHIFT_JIS_HINT: &str = "input is not valid UTF-8. Convert it first, for example: iconv -f SHIFT_JIS -t UTF-8 src.csv > utf8.csv";

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

pub fn mask(args: MaskPseudonymizeArgs) -> Result<()> {
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
    if let Some(output) = args.output.as_ref() {
        if let Some(input) = args.file.as_ref()
            && paths_equal(input, output)
        {
            return Err(fail("refusing to overwrite the input file"));
        }
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
    } else if !matches!(kind, InputKind::TableXlsx | InputKind::TextOffice) {
        ensure_utf8_file(args.file.as_ref().expect("file present"))?;
    }

    let (policy, _) = Policy::load_from_dir(&args.project_root)?;
    shk_core::pseudonymize::validate_norm(&policy.pseudonymize.norm)
        .map_err(|err| CliExit::message(2, err))?;
    shk_core::pseudonymize::validate_token_bits(policy.pseudonymize.token_bits)
        .map_err(|err| CliExit::message(2, err))?;

    match kind {
        InputKind::TableCsv => run_table_csv(&args, &policy),
        InputKind::TableXlsx => run_table_xlsx(&args, &policy),
        InputKind::TextPlain => run_text_plain(&args, &policy),
        InputKind::TextOffice => run_text_office(&args, &policy),
    }
}

pub fn restore(cwd: &Path, file: PathBuf, map: PathBuf, output: PathBuf) -> Result<()> {
    require_map_path(&map)?;
    if paths_equal(&file, &output) {
        return Err(fail("refusing to overwrite the input file"));
    }
    safety::require_project_policy(cwd, "pseudonymize restore --output")?;
    safety::ensure_writable_path_allowed(&output)?;
    if !map.exists() {
        return Err(fail(format!("restore map not found: {}", map.display())));
    }

    let (policy, project, store, _backend) = open_context(cwd)?;
    let material = load_material(store.as_ref(), &project)?.ok_or_else(|| {
        fail("no pseudonymize key for this project; cannot decrypt the restore map")
    })?;
    let bytes = std::fs::read(&map).with_context(|| format!("read {}", map.display()))?;
    let document = decrypt_map(&material, &bytes).map_err(fail_run)?;
    if document.key_fingerprint != material.fingerprint() {
        return Err(fail(
            "restore map fingerprint does not match this project's key",
        ));
    }
    let _ = policy;

    if is_office_path(&file) {
        shk_core::document_masker::rewrite_ooxml_text_groups(
            &file,
            &output,
            policy.scan.max_file_size_bytes,
            |group| Ok(restore_text(group, &document).0),
        )
        .map_err(fail_run)?;
        println!("Restored {}", output.display());
        return Ok(());
    }

    ensure_utf8_file(&file)?;
    let input =
        std::fs::read_to_string(&file).with_context(|| format!("read {}", file.display()))?;
    let (restored, replacements, multi) = restore_text(&input, &document);
    crate::fs_atomic::write_atomic(&output, restored.as_bytes())?;
    println!("Restored {replacements} token(s) to {}", output.display());
    if multi > 0 {
        eprintln!("warning: {multi} token(s) had multiple originals; first-seen value was used");
    }
    Ok(())
}

fn run_table_csv(args: &MaskPseudonymizeArgs, policy: &Policy) -> Result<()> {
    let cli_columns = parse_cli_columns(args.columns.as_deref())?;
    let (input_bytes, crlf, delimiter) = read_table_source(args)?;
    let options = table_options(args, policy, delimiter, crlf, cli_columns, true);
    let preview = run_table(
        input_bytes.as_slice(),
        None::<&mut Vec<u8>>,
        &options,
        None,
        None,
    )
    .map_err(fail_run)?;
    confirm_table_plan(args, &preview)?;
    if args.dry_run {
        return emit_dry_run(args, &preview.meta, Some(&preview.columns));
    }

    let output = args.output.as_ref().expect("checked above");
    let project = ProjectIdentity::from_root_and_policy(args.project_root.clone(), policy);
    let material = load_or_create_material(&project, policy, args.yes, args.no_create_key)?;
    let mut collector = prepare_map(args.map.as_deref(), &material, &policy.pseudonymize.norm)?;
    let mut run_options = options;
    run_options.dry_run = false;
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("create temp file in {}", parent.display()))?;
    let result = run_table(
        input_bytes.as_slice(),
        Some(tmp.as_file_mut()),
        &run_options,
        Some(&material),
        collector.as_mut(),
    )
    .map_err(fail_run)?;
    tmp.flush()?;
    shk_core::fs_atomic::persist_named_temp_file(tmp, output)?;
    finish_run(
        args,
        policy,
        &material,
        result.meta,
        Some(&result.columns),
        collector,
        "table",
    )
}

fn run_table_xlsx(args: &MaskPseudonymizeArgs, policy: &Policy) -> Result<()> {
    let input = args
        .file
        .as_ref()
        .ok_or_else(|| fail("xlsx table mode requires a file path"))?;
    let cli_columns = parse_cli_columns(args.columns.as_deref())?;
    let options = table_options(args, policy, b',', false, cli_columns, true);
    let preview =
        run_xlsx(input, None, args.sheet.as_deref(), &options, None, None).map_err(fail_run)?;
    confirm_table_plan(args, &preview)?;
    if args.dry_run {
        return emit_dry_run(args, &preview.meta, Some(&preview.columns));
    }

    let output = args.output.as_ref().expect("checked above");
    let project = ProjectIdentity::from_root_and_policy(args.project_root.clone(), policy);
    let material = load_or_create_material(&project, policy, args.yes, args.no_create_key)?;
    let mut collector = prepare_map(args.map.as_deref(), &material, &policy.pseudonymize.norm)?;
    let mut run_options = options;
    run_options.dry_run = false;
    let result = run_xlsx(
        input,
        Some(output),
        args.sheet.as_deref(),
        &run_options,
        Some(&material),
        collector.as_mut(),
    )
    .map_err(fail_run)?;
    finish_run(
        args,
        policy,
        &material,
        result.meta,
        Some(&result.columns),
        collector,
        "table",
    )
}

fn run_text_plain(args: &MaskPseudonymizeArgs, policy: &Policy) -> Result<()> {
    let input = read_text_source(args)?;
    let options = text_options(args, policy, true);
    if args.dry_run {
        let result = run_text(&input, None, &options, None).map_err(fail_run)?;
        return emit_dry_run(args, &result.meta, None);
    }
    let output = args.output.as_ref().expect("checked above");
    let project = ProjectIdentity::from_root_and_policy(args.project_root.clone(), policy);
    let material = load_or_create_material(&project, policy, args.yes, args.no_create_key)?;
    let mut collector = prepare_map(args.map.as_deref(), &material, &policy.pseudonymize.norm)?;
    let mut run_options = options;
    run_options.dry_run = false;
    let result =
        run_text(&input, Some(&material), &run_options, collector.as_mut()).map_err(fail_run)?;
    crate::fs_atomic::write_atomic(output, result.output.as_bytes())?;
    finish_run(
        args,
        policy,
        &material,
        result.meta,
        None,
        collector,
        "text",
    )
}

fn run_text_office(args: &MaskPseudonymizeArgs, policy: &Policy) -> Result<()> {
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
        )
        .map_err(fail_run)?;
        return emit_dry_run(args, &result.meta, None);
    }
    let output = args.output.as_ref().expect("checked above");
    let project = ProjectIdentity::from_root_and_policy(args.project_root.clone(), policy);
    let material = load_or_create_material(&project, policy, args.yes, args.no_create_key)?;
    let mut collector = prepare_map(args.map.as_deref(), &material, &policy.pseudonymize.norm)?;
    let mut run_options = options;
    run_options.dry_run = false;
    let result = run_office_text(
        input,
        Some(output),
        Some(&material),
        &run_options,
        collector.as_mut(),
        policy.scan.max_file_size_bytes,
    )
    .map_err(fail_run)?;
    finish_run(
        args,
        policy,
        &material,
        result.meta,
        None,
        collector,
        "text",
    )
}

fn finish_run(
    args: &MaskPseudonymizeArgs,
    policy: &Policy,
    material: &KeyMaterial,
    mut meta: shk_core::pseudonymize::PseudonymizeMeta,
    columns: Option<&[shk_core::pseudonymize::ResolvedColumn]>,
    collector: Option<MapCollector>,
    mode: &str,
) -> Result<()> {
    let output = args.output.as_ref().expect("checked above");
    if let (Some(map_path), Some(collector)) = (args.map.as_ref(), collector) {
        let document =
            collector.into_document(policy.pseudonymize.norm.clone(), material.fingerprint());
        let bytes = encrypt_map(material, &document).map_err(fail_run)?;
        crate::fs_atomic::write_atomic(map_path, &bytes)?;
        meta.map_created = true;
    }

    let meta_path = meta_sidecar(output);
    safety::ensure_writable_path_allowed(&meta_path)?;
    crate::fs_atomic::write_atomic(&meta_path, serde_json::to_vec_pretty(&meta)?.as_slice())?;

    let _ = crate::audit_log::append_line(
        &args.project_root,
        serde_json::json!({
            "event": "pseudonymize",
            "mode": mode,
            "rows": meta.rows_processed,
            "columns": columns.map(|cols| cols.len()).unwrap_or(0),
            "kinds": columns
                .unwrap_or(&[])
                .iter()
                .map(|c| c.kind.as_config_value())
                .collect::<Vec<_>>(),
            "map": args.map.is_some(),
        }),
    );

    if args.check_remaining {
        check_remaining(&args.project_root, output)?;
    }

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
    Ok(())
}

fn confirm_table_plan(
    args: &MaskPseudonymizeArgs,
    preview: &shk_core::pseudonymize::TableResult,
) -> Result<()> {
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
    meta: &shk_core::pseudonymize::PseudonymizeMeta,
    columns: Option<&[shk_core::pseudonymize::ResolvedColumn]>,
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
    if format.is_some() || mode == Some(PseudonymizeModeArg::Table) {
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

fn parse_cli_columns(
    spec: Option<&str>,
) -> Result<Option<shk_core::pseudonymize::ColumnOverrides>> {
    match spec {
        Some(spec) => Ok(Some(
            parse_columns_spec(spec).map_err(|err| CliExit::message(2, err.0))?,
        )),
        None => Ok(None),
    }
}

fn table_options(
    args: &MaskPseudonymizeArgs,
    policy: &Policy,
    delimiter: u8,
    crlf: bool,
    cli_columns: Option<shk_core::pseudonymize::ColumnOverrides>,
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

fn read_table_source(args: &MaskPseudonymizeArgs) -> Result<(Vec<u8>, bool, u8)> {
    if let Some(path) = args.file.as_ref() {
        let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
        ensure_utf8_bytes(&bytes)?;
        return Ok((
            bytes,
            file_uses_crlf(path)?,
            table_delimiter(args, Some(path)),
        ));
    }
    let bytes = read_stdin_bytes()?;
    ensure_utf8_bytes(&bytes)?;
    let crlf = bytes.windows(2).any(|pair| pair == b"\r\n");
    Ok((bytes, crlf, table_delimiter(args, None)))
}

fn read_text_source(args: &MaskPseudonymizeArgs) -> Result<String> {
    if let Some(path) = args.file.as_ref() {
        let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
        ensure_utf8_bytes(&bytes)?;
        return String::from_utf8(bytes).map_err(|_| encoding_error(&[]));
    }
    let bytes = read_stdin_bytes()?;
    ensure_utf8_bytes(&bytes)?;
    String::from_utf8(bytes).map_err(|_| encoding_error(&[]))
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

fn prepare_map(
    map: Option<&Path>,
    material: &KeyMaterial,
    _norm: &str,
) -> Result<Option<MapCollector>> {
    let Some(path) = map else {
        return Ok(None);
    };
    let mut collector = MapCollector::default();
    if path.exists() {
        let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
        let existing = decrypt_map(material, &bytes).map_err(fail_run)?;
        if existing.key_fingerprint != material.fingerprint() {
            return Err(fail("existing --map was encrypted with a different key"));
        }
        collector.merge(existing);
    }
    Ok(Some(collector))
}

fn require_map_path(path: &Path) -> Result<()> {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some(ext) if ext.eq_ignore_ascii_case("shk-map") => Ok(()),
        _ => Err(fail("--map path must end with .shk-map")),
    }
}

fn check_remaining(project_root: &Path, output: &Path) -> Result<()> {
    let result = scan_path(
        output,
        ScanOptions {
            policy_root: Some(project_root.to_path_buf()),
            ..Default::default()
        },
    )
    .map_err(fail_run)?;
    let mut leftover: Vec<String> = result
        .findings
        .iter()
        .filter(|finding| {
            finding.rule_id.starts_with("pii.") || finding.rule_id.starts_with("secret.")
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

fn print_meta_summary(
    meta: &shk_core::pseudonymize::PseudonymizeMeta,
    columns: Option<&[shk_core::pseudonymize::ResolvedColumn]>,
) {
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
    let (policy, project, store, backend) = open_context(cwd)?;
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
    confirm(
        yes,
        "Replace the pseudonymize key? Existing tokens will no longer match and existing restore maps will become unrestorable.",
    )?;
    let (_policy, project, store, _backend) = open_context(cwd)?;
    let material = generate_material()?;
    store
        .put(&project, STORE_ITEM, &material.encode_store())
        .context("store rotated pseudonymize material")?;
    println!("rotated fingerprint: {}", material.fingerprint());
    Ok(())
}

pub fn key_delete(cwd: &Path, yes: bool) -> Result<()> {
    confirm(
        yes,
        "Delete the pseudonymize key? Existing tokens will no longer be reproducible.",
    )?;
    let (_policy, project, store, _backend) = open_context(cwd)?;
    store
        .delete(&project, STORE_ITEM)
        .context("delete pseudonymize material")?;
    println!("deleted project pseudonymize key");
    Ok(())
}

pub fn key_export(cwd: &Path, instructions: bool) -> Result<()> {
    if !instructions {
        return Err(fail(
            "--instructions is required; raw material export is intentionally not supported",
        ));
    }
    let (policy, project, store, backend) = open_context(cwd)?;
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
    let _ = policy;
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
    let mut raw = String::new();
    io::stdin().read_to_string(&mut raw)?;
    let material =
        parse_stored_material(raw.trim()).map_err(|err| CliExit::message(2, format!("{err}")))?;
    let (_policy, project, store, _backend) = open_context(cwd)?;
    store
        .put(&project, STORE_ITEM, &material.encode_store())
        .context("import pseudonymize material")?;
    println!("imported fingerprint: {}", material.fingerprint());
    Ok(())
}

fn open_context(
    cwd: &Path,
) -> Result<(
    Policy,
    ProjectIdentity,
    Box<dyn SecretStore>,
    SecretStoreBackend,
)> {
    let (policy, _) = Policy::load_from_dir(cwd)?;
    let project = ProjectIdentity::from_root_and_policy(cwd.to_path_buf(), &policy);
    let (store, backend) = open_pseudonymize_store(&project, &policy)?;
    Ok((policy, project, store, backend))
}

fn load_or_create_material(
    project: &ProjectIdentity,
    policy: &Policy,
    yes: bool,
    no_create: bool,
) -> Result<KeyMaterial> {
    let (store, _backend) = open_pseudonymize_store(project, policy)?;
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
    let material = generate_material()?;
    store
        .put(project, STORE_ITEM, &material.encode_store())
        .context("store new pseudonymize material")?;
    Ok(material)
}

fn load_material(
    store: &dyn SecretStore,
    project: &ProjectIdentity,
) -> Result<Option<KeyMaterial>> {
    match store.get(project, STORE_ITEM)? {
        Some(raw) => Ok(Some(
            parse_stored_material(&raw).context("parse stored pseudonymize material")?,
        )),
        None => Ok(None),
    }
}

fn generate_material() -> Result<KeyMaterial> {
    let mut master = [0u8; 32];
    let mut salt = [0u8; 32];
    getrandom::getrandom(&mut master).map_err(|err| anyhow!("CSPRNG failed: {err}"))?;
    getrandom::getrandom(&mut salt).map_err(|err| anyhow!("CSPRNG failed: {err}"))?;
    Ok(KeyMaterial::from_parts(master, salt))
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

fn print_column_plan(columns: &[shk_core::pseudonymize::ResolvedColumn]) {
    println!("Columns:");
    for column in columns {
        let source = match column.source {
            ColumnSource::Config => "config",
            ColumnSource::Cli => "cli",
            ColumnSource::Inferred => "inferred",
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
    match std::str::from_utf8(bytes) {
        Ok(_) => Ok(()),
        Err(_) => Err(encoding_error(bytes)),
    }
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
                return Err(encoding_error(&leftover));
            }
            Err(err) => leftover = leftover[err.valid_up_to()..].to_vec(),
        }
    }
    if leftover.is_empty() || std::str::from_utf8(&leftover).is_ok() {
        Ok(())
    } else {
        Err(encoding_error(&leftover))
    }
}

fn encoding_error(sample: &[u8]) -> anyhow::Error {
    let (_, _decoded, had_errors) = encoding_rs::SHIFT_JIS.decode(sample);
    let hint = if !had_errors || sample.iter().any(|b| *b >= 0x80) {
        SHIFT_JIS_HINT
    } else {
        "input is not valid UTF-8"
    };
    anyhow!(CliExit::message(2, hint))
}

fn file_uses_crlf(path: &Path) -> Result<bool> {
    let mut file = File::open(path)?;
    let mut buf = [0u8; 4096];
    let n = file.read(&mut buf)?;
    Ok(buf[..n].windows(2).any(|pair| pair == b"\r\n"))
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
    match (std::fs::canonicalize(left), std::fs::canonicalize(right)) {
        (Ok(a), Ok(b)) => a == b,
        _ => left == right,
    }
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

fn fail_run(err: anyhow::Error) -> anyhow::Error {
    CliExit::message(2, format!("{err:#}")).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use shk_core::pseudonymize::parse_columns_spec;

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
        assert!(require_map_path(Path::new("out.shk-map")).is_ok());
        assert!(require_map_path(Path::new("out.json")).is_err());
    }
}
