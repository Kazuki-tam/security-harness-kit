use crate::args::PseudonymizeModeArg;
use crate::env_store::{ProjectIdentity, SecretStore, open_pseudonymize_store};
use crate::exit::CliExit;
use crate::safety;
use anyhow::{Context, Result, anyhow};
use dialoguer::Confirm;
use shk_core::policy::{Policy, SecretStoreBackend};
use shk_core::pseudonymize::{
    ColumnSource, KeyMaterial, NormalizeSettings, TableOptions, delimiter_for_path,
    parse_columns_spec, parse_stored_material, run_table,
};
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
}

pub fn mask(args: MaskPseudonymizeArgs) -> Result<()> {
    if args.mode == Some(PseudonymizeModeArg::Text) {
        return Err(fail(
            "text mode arrives in shk 0.8.0; use a .csv or .tsv file",
        ));
    }
    let input = args.file.as_ref().ok_or_else(|| {
        anyhow!(CliExit::message(
            2,
            "stdin / text input arrives in shk 0.8.0; pass a .csv or .tsv file"
        ))
    })?;
    if !is_table_path(input) && args.mode != Some(PseudonymizeModeArg::Table) {
        return Err(fail(
            "Phase 1a accepts .csv and .tsv only; xlsx and text modes arrive in shk 0.8.0",
        ));
    }
    if !args.dry_run && args.output.is_none() {
        return Err(fail(
            "`mask --pseudonymize` requires --output so tokens are not written to stdout",
        ));
    }
    if let Some(output) = args.output.as_ref() {
        if paths_equal(input, output) {
            return Err(fail("refusing to overwrite the input file"));
        }
        safety::require_project_policy(&args.project_root, "mask --output")?;
        safety::ensure_writable_path_allowed(output)?;
    }

    ensure_utf8_file(input)?;

    let (policy, _) = Policy::load_from_dir(&args.project_root)?;
    shk_core::pseudonymize::validate_norm(&policy.pseudonymize.norm)
        .map_err(|err| CliExit::message(2, err))?;
    shk_core::pseudonymize::validate_token_bits(policy.pseudonymize.token_bits)
        .map_err(|err| CliExit::message(2, err))?;

    let cli_columns = match args.columns.as_deref() {
        Some(spec) => Some(parse_columns_spec(spec).map_err(|err| CliExit::message(2, err.0))?),
        None => None,
    };

    let crlf = file_uses_crlf(input)?;
    let options = TableOptions {
        delimiter: delimiter_for_path(Some(input)),
        no_header: args.no_header,
        token_bits: policy.pseudonymize.token_bits,
        norm: policy.pseudonymize.norm.clone(),
        settings: NormalizeSettings {
            email_strip_subaddress: policy.pseudonymize.email_strip_subaddress,
        },
        config_columns: policy.pseudonymize.columns.clone(),
        cli_columns,
        dry_run: true,
        crlf,
        shk_version: env!("CARGO_PKG_VERSION").into(),
        key_namespace: key_namespace(&args.project_root, policy.env.project_id.as_deref()),
    };

    let preview = {
        let file = File::open(input).with_context(|| format!("open {}", input.display()))?;
        run_table(file, None::<&mut Vec<u8>>, &options, None).map_err(fail_run)?
    };
    if preview.columns.is_empty() {
        return Err(fail(
            "no columns to pseudonymize; pass --columns or add [pseudonymize.columns]",
        ));
    }
    if preview.columns.iter().any(|column| column.kind.is_name()) {
        return Err(fail(
            "name kind arrives in shk 0.8.0; omit name columns for this release",
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

    if args.dry_run {
        if args.json {
            println!("{}", serde_json::to_string_pretty(&preview.meta)?);
        } else {
            print_column_plan(&preview.columns);
            println!("dry-run: no files written and no key created");
        }
        return Ok(());
    }

    let output = args.output.as_ref().expect("checked above");
    let project = ProjectIdentity::from_root_and_policy(args.project_root.clone(), &policy);
    let material = load_or_create_material(&project, &policy, args.yes, args.no_create_key)?;

    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("create temp file in {}", parent.display()))?;
    let mut run_options = options;
    run_options.dry_run = false;
    let file = File::open(input).with_context(|| format!("open {}", input.display()))?;
    let result = run_table(file, Some(tmp.as_file_mut()), &run_options, Some(&material))
        .map_err(fail_run)?;
    tmp.flush()?;
    shk_core::fs_atomic::persist_named_temp_file(tmp, output)?;

    let meta_path = meta_sidecar(output);
    safety::ensure_writable_path_allowed(&meta_path)?;
    crate::fs_atomic::write_atomic(
        &meta_path,
        serde_json::to_vec_pretty(&result.meta)?.as_slice(),
    )?;

    let _ = crate::audit_log::append_line(
        &args.project_root,
        serde_json::json!({
            "event": "pseudonymize",
            "mode": "table",
            "rows": result.meta.rows_processed,
            "columns": result.columns.len(),
            "kinds": result.columns.iter().map(|c| c.kind.as_config_value()).collect::<Vec<_>>(),
        }),
    );

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result.meta)?);
    } else {
        print_summary(&result);
        println!("Wrote {}", output.display());
        println!("Wrote {}", meta_path.display());
    }
    Ok(())
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

fn print_summary(result: &shk_core::pseudonymize::TableResult) {
    println!("Pseudonymized {} rows", result.meta.rows_processed);
    print_column_plan(&result.columns);
    for (kind, count) in &result.meta.replaced {
        println!("  {kind}: {count} replaced");
    }
    for (kind, count) in &result.meta.unparsed {
        println!("  {kind}: {count} unparsed");
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
}
