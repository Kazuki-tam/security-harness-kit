use crate::args::{
    DotenvxDeleteArgs, DotenvxRunArgs, EnvDecryptArgs, EnvEncryptArgs, EnvKeyDeleteArgs,
    EnvKeyExportArgs, EnvKeyImportArgs, EnvKeyMigrateArgs, EnvRunArgs,
};
use crate::env_store::{
    EnvStores, ProjectIdentity, SecretStore, SecretStoreBackend, open_env_stores,
    parse_secret_store_backend,
};
use crate::exit::CliExit;
use crate::{fs_atomic, safety};
use anyhow::{Context, Result, anyhow, bail, ensure};
use dialoguer::Password;
use dotenvx::{Keypair, decrypt as dotenvx_decrypt, encrypt as dotenvx_encrypt};
use serde::{Deserialize, Serialize};
use shk_core::policy::Policy;
use std::collections::BTreeSet;
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::NamedTempFile;
use zeroize::Zeroize;

const PRIVATE_KEY_PREFIX: &str = "DOTENV_PRIVATE_KEY";
const DOTENV_PUBLIC_KEY_PREFIX: &str = "DOTENV_PUBLIC_KEY";
const DOTENV_ENCRYPTED_PREFIX: &str = "encrypted:";
const SHK_NATIVE_ENV_HEADER_START: &str =
    "#/----------------------[SHK_NATIVE_ENV]----------------------/";
const SHK_NATIVE_ENV_HEADER_BODY: &str =
    "#/ encrypted dotenv values managed by shk native env           /";
const SHK_NATIVE_ENV_HEADER_END: &str =
    "#/------------------------------------------------------------/";
const DOTENV_PUBLIC_KEY_HEADER_START: &str =
    "#/-------------------[DOTENV_PUBLIC_KEY]--------------------/";
const SHK_PUBLIC_KEY_HEADER_BODY: &str =
    "#/           public key for shk native env encryption       /";
const SHK_PUBLIC_KEY_HEADER_DETAIL: &str =
    "#/       private key is stored in the OS credential store   /";
const SHK_PUBLIC_KEY_HEADER_END: &str =
    "#/----------------------------------------------------------/";
const LEGACY_DOTENV_PUBLIC_KEY_HEADER_BODY: &str =
    "#/            public-key encryption for .env files          /";
const LEGACY_DOTENV_PUBLIC_KEY_HEADER_LINK: &str =
    "#/       [how it works](https://dotenvx.com/encryption)     /";
const SHK_NATIVE_ENV_HEADER_LINES: [&str; 3] = [
    SHK_NATIVE_ENV_HEADER_START,
    SHK_NATIVE_ENV_HEADER_BODY,
    SHK_NATIVE_ENV_HEADER_END,
];
const SHK_PUBLIC_KEY_HEADER_LINES: [&str; 4] = [
    DOTENV_PUBLIC_KEY_HEADER_START,
    SHK_PUBLIC_KEY_HEADER_BODY,
    SHK_PUBLIC_KEY_HEADER_DETAIL,
    SHK_PUBLIC_KEY_HEADER_END,
];
const LEGACY_DOTENV_PUBLIC_KEY_HEADER_LINES: [&str; 4] = [
    DOTENV_PUBLIC_KEY_HEADER_START,
    LEGACY_DOTENV_PUBLIC_KEY_HEADER_BODY,
    LEGACY_DOTENV_PUBLIC_KEY_HEADER_LINK,
    SHK_PUBLIC_KEY_HEADER_END,
];

#[derive(Deserialize, Serialize)]
struct NativeEnvKeyMaterial {
    public_key: String,
    private_key: String,
}

impl Drop for NativeEnvKeyMaterial {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

fn load_env_context(cwd: &Path) -> Result<(PathBuf, ProjectIdentity, EnvStores)> {
    let (project_root, project) = load_env_project(cwd)?;
    let (policy, _) = Policy::load_from_dir(&project_root)?;
    let stores = open_env_stores(&project, &policy)?;
    Ok((project_root, project, stores))
}

fn load_env_project(cwd: &Path) -> Result<(PathBuf, ProjectIdentity)> {
    let project_root = project_root(cwd)?;
    let (policy, _) = Policy::load_from_dir(&project_root)?;
    let project = ProjectIdentity::from_root_and_policy(project_root.clone(), &policy);
    Ok((project_root, project))
}

fn credential_store_label(stores: &EnvStores) -> &'static str {
    match stores.backend {
        SecretStoreBackend::Keyring => "OS credential store",
        SecretStoreBackend::OnePassword => "1Password vault",
    }
}

pub fn dotenvx_import_keys(cwd: &Path, file: &Path) -> Result<()> {
    let (_project_root, project, stores) = load_env_context(cwd)?;
    let body = std::fs::read_to_string(file).with_context(|| format!("read {}", file.display()))?;
    let entries = parse_dotenvx_keys(&body)?;
    if entries.is_empty() {
        bail!("no DOTENV_PRIVATE_KEY* entries found in {}", file.display());
    }
    let imported = entries.len();

    dotenvx_import_keys_with_store(stores.dotenvx.as_ref(), &project, entries)?;

    println!(
        "Imported {imported} dotenvx private key(s) into the {}",
        credential_store_label(&stores)
    );
    println!("Raw key values were not printed.");
    Ok(())
}

pub fn encrypt(cwd: &Path, args: EnvEncryptArgs) -> Result<()> {
    let (_project_root, project, stores) = load_env_context(cwd)?;
    let private_key_name = env_key_name(args.key.as_ref(), &args.env)?;
    let public_key_name = private_to_public_key_name(&private_key_name);
    if args.remove_source {
        ensure!(
            !args.in_place,
            "--remove-source cannot be combined with --in-place"
        );
    }
    let output = env_encrypt_output_path(&args)?;
    if args.remove_source {
        ensure!(
            comparable_path(cwd, &args.file) != comparable_path(cwd, output),
            "--remove-source requires input and output to be different files"
        );
    }
    let mut key_material = read_or_create_native_env_key(
        stores.native.as_ref(),
        stores.dotenvx.as_ref(),
        &project,
        &private_key_name,
    )?;
    let mut plaintext = std::fs::read_to_string(&args.file)
        .with_context(|| format!("read {}", args.file.display()))?;
    let encrypt_result =
        encrypt_dotenv_body(&plaintext, &public_key_name, &key_material.public_key);
    plaintext.zeroize();
    let encrypted = encrypt_result?;
    key_material.private_key.zeroize();
    write_output(output, encrypted.as_bytes(), args.force || args.in_place)?;
    println!(
        "Encrypted {} to {} with {private_key_name}",
        args.file.display(),
        output.display()
    );
    println!(
        "Public key was written to the env file; private key was stored in the {} and was not printed.",
        credential_store_label(&stores)
    );
    if args.remove_source {
        std::fs::remove_file(&args.file)
            .with_context(|| format!("remove source {}", args.file.display()))?;
        println!("Removed plaintext source {}", args.file.display());
    }
    Ok(())
}

pub fn decrypt(cwd: &Path, args: EnvDecryptArgs) -> Result<()> {
    let output = &args.output;
    let (_project_root, project, stores) = load_env_context(cwd)?;
    let private_key_name = env_key_name(args.key.as_ref(), &args.env)?;
    let body = std::fs::read_to_string(&args.file)
        .with_context(|| format!("read {}", args.file.display()))?;
    let mut key_material = read_or_adopt_env_key_material(
        stores.native.as_ref(),
        stores.dotenvx.as_ref(),
        &project,
        &private_key_name,
    )?
        .ok_or_else(|| {
            anyhow!(
                "no stored {private_key_name}; run `shk env encrypt` or `shk env dotenvx import-keys .env.keys` first"
            )
        })?;
    let mut plaintext = decrypt_dotenv_body(&body, &key_material.private_key)?;
    key_material.private_key.zeroize();
    let write_result = write_output(output, &plaintext, args.force);
    plaintext.zeroize();
    write_result?;
    println!(
        "Decrypted {} to {} with {}",
        args.file.display(),
        output.display(),
        private_key_name
    );
    Ok(())
}

pub fn run(cwd: &Path, args: EnvRunArgs) -> Result<()> {
    let (_project_root, project, stores) = load_env_context(cwd)?;
    let mut key_materials = read_native_env_run_keys(
        stores.native.as_ref(),
        stores.dotenvx.as_ref(),
        &project,
        &args,
    )?;
    let mut cmd = build_native_env_run_command(cwd, &args, &key_materials)?;
    for key in &mut key_materials {
        key.private_key.zeroize();
    }

    let status = cmd
        .status()
        .with_context(|| format!("run `{}`", args.command.join(" ")))?;
    if !status.success() {
        return Err(CliExit::silent(status.code().unwrap_or(2)).into());
    }
    Ok(())
}

pub fn key_import(cwd: &Path, args: EnvKeyImportArgs) -> Result<()> {
    let (_project_root, project, stores) = load_env_context(cwd)?;
    let private_key_name = env_key_name(args.key.as_ref(), &args.env)?;
    let mut private_key = read_private_key_for_import(&private_key_name, args.stdin)?;
    let result = import_native_env_key_with_store(
        stores.native.as_ref(),
        &project,
        &private_key_name,
        &private_key,
        args.force,
    );
    private_key.zeroize();
    result?;

    println!(
        "Imported {private_key_name} into the shk native {} for {}",
        credential_store_label(&stores),
        project.root.display()
    );
    println!("Raw key value was not printed.");
    Ok(())
}

pub fn key_list(cwd: &Path) -> Result<()> {
    let (_project_root, project, stores) = load_env_context(cwd)?;
    let index = stores.native.list_keys(&project)?;
    if index.is_empty() {
        println!(
            "native env: no indexed private keys for {}",
            project.root.display()
        );
        println!(
            "Keys created by older versions can still be removed with `shk env key delete --key <DOTENV_PRIVATE_KEY*>`."
        );
    } else {
        println!("native env private keys for {}:", project.root.display());
        for key in index {
            println!("  - {key}");
        }
    }
    Ok(())
}

pub fn key_delete(cwd: &Path, args: EnvKeyDeleteArgs) -> Result<()> {
    let (_project_root, project, stores) = load_env_context(cwd)?;
    key_delete_with_store(stores.native.as_ref(), &project, args)
}

pub fn key_migrate(cwd: &Path, args: EnvKeyMigrateArgs) -> Result<()> {
    let (project_root, project) = load_env_project(cwd)?;
    let (policy, policy_path) = Policy::load_from_dir(&project_root)?;
    let to_backend = parse_secret_store_backend(&args.to)?;
    let source_backend = parse_secret_store_backend(&policy.env.secret_store)?;

    if source_backend == to_backend {
        bail!(
            "env.secret_store is already \"{}\"; choose the other backend with --to",
            args.to
        );
    }

    ensure!(
        !args.delete_source || policy_path.is_some(),
        "--delete-source requires a project shk.toml so env.secret_store can be switched \
         before source keys are deleted; create and configure shk.toml, then retry"
    );

    let mut target_policy = policy.clone();
    target_policy.env.secret_store = args.to.clone();
    target_policy.validate_env_config(&project_root)?;

    let source_stores = open_env_stores(&project, &policy)?;
    let target_stores = open_env_stores(&project, &target_policy)?;

    if args.delete_source {
        confirm_migration_delete_source(&args)?;
    }

    let MigrationCopy {
        migrated,
        native_keys,
        dotenvx_keys,
    } = copy_keys_between_stores(
        &project_root,
        &project,
        source_stores.native.as_ref(),
        source_stores.dotenvx.as_ref(),
        target_stores.native.as_ref(),
        target_stores.dotenvx.as_ref(),
    )?;

    if migrated == 0 {
        println!(
            "No keys found in the {} backend to migrate to {}",
            source_backend.as_config_value(),
            to_backend.as_config_value()
        );
        return Ok(());
    }

    println!(
        "Migrated {migrated} key(s) from {} to {}",
        source_backend.as_config_value(),
        to_backend.as_config_value()
    );

    if let Some(path) = policy_path {
        safety::ensure_write_path_within(&project_root, &path)?;
        update_policy_secret_store(&path, &args.to)?;
        println!(
            "Updated {} to set env.secret_store = \"{}\"",
            path.display(),
            args.to
        );
    } else {
        println!(
            "Create shk.toml with env.secret_store = \"{}\" so env commands use the destination backend",
            args.to
        );
    }

    if args.delete_source {
        delete_migrated_source_keys(
            &project,
            source_stores.native.as_ref(),
            source_stores.dotenvx.as_ref(),
            &native_keys,
            &dotenvx_keys,
        )
        .with_context(|| {
            "delete migrated keys from source backend after updating shk.toml; \
             destination already has the keys, but shk.toml now selects the destination backend — \
             remove any remaining source keys manually"
        })?;
        println!("Deleted migrated key(s) from the source backend.");
    }

    Ok(())
}

#[derive(Debug)]
struct MigrationCopy {
    migrated: usize,
    native_keys: BTreeSet<String>,
    dotenvx_keys: BTreeSet<String>,
}

fn copy_keys_between_stores(
    project_root: &Path,
    project: &ProjectIdentity,
    from_native: &dyn SecretStore,
    from_dotenvx: &dyn SecretStore,
    to_native: &dyn SecretStore,
    to_dotenvx: &dyn SecretStore,
) -> Result<MigrationCopy> {
    let candidates = discover_private_key_candidates(project_root)?;
    let mut migrated = 0usize;
    let mut native_keys = BTreeSet::new();
    let mut dotenvx_keys = BTreeSet::new();
    for (store_name, from, to, keys) in [
        ("native env", from_native, to_native, &mut native_keys),
        ("dotenvx", from_dotenvx, to_dotenvx, &mut dotenvx_keys),
    ] {
        for key in keys_for_migration(from, project, &candidates)? {
            let Some(mut value) = from.get(project, &key)? else {
                continue;
            };
            let target_value = match to.get(project, &key) {
                Ok(value) => value,
                Err(err) => {
                    value.zeroize();
                    return Err(err).with_context(|| {
                        format!("check destination {store_name} key {key} before migration")
                    });
                }
            };
            if let Some(mut existing) = target_value {
                let matches = existing == value;
                existing.zeroize();
                if !matches {
                    value.zeroize();
                    bail!(
                        "destination {store_name} already contains a different value for {key}; resolve the conflict before migrating"
                    );
                }
            } else if let Err(err) = to.put(project, &key, &value) {
                value.zeroize();
                return Err(err)
                    .with_context(|| format!("copy {store_name} key {key} to destination"));
            }
            value.zeroize();
            keys.insert(key);
            migrated += 1;
        }
    }
    Ok(MigrationCopy {
        migrated,
        native_keys,
        dotenvx_keys,
    })
}

fn update_policy_secret_store(path: &Path, backend: &str) -> Result<()> {
    let body = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let mut document = body
        .parse::<toml_edit::DocumentMut>()
        .with_context(|| format!("parse {} for update", path.display()))?;
    let env = document
        .entry("env")
        .or_insert_with(|| toml_edit::Item::Table(toml_edit::Table::new()));
    if let Some(table) = env.as_table_mut() {
        table["secret_store"] = toml_edit::value(backend);
    } else if let Some(table) = env.as_inline_table_mut() {
        table.insert("secret_store", toml_edit::Value::from(backend));
    } else {
        bail!("[env] in {} must be a TOML table", path.display());
    }
    fs_atomic::write_atomic(path, document.to_string().as_bytes())
        .with_context(|| format!("update {}", path.display()))
}

fn keys_for_migration(
    store: &dyn SecretStore,
    project: &ProjectIdentity,
    candidates: &BTreeSet<String>,
) -> Result<BTreeSet<String>> {
    let mut keys = store.list_keys(project)?;
    for candidate in candidates {
        if store_has_key(store, project, candidate)? {
            keys.insert(candidate.clone());
        }
    }
    Ok(keys)
}

fn discover_private_key_candidates(project_root: &Path) -> Result<BTreeSet<String>> {
    let mut candidates = BTreeSet::new();
    let entries = match std::fs::read_dir(project_root) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(candidates),
        Err(err) => return Err(err.into()),
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == ".env.keys" {
            let body = std::fs::read_to_string(entry.path())
                .with_context(|| format!("read {}", entry.path().display()))?;
            for (key, _) in parse_dotenvx_keys(&body)? {
                candidates.insert(key);
            }
            continue;
        }
        if name == ".env" || name.starts_with(".env.") {
            if name == ".env.vault" {
                continue;
            }
            let body = std::fs::read_to_string(entry.path())
                .with_context(|| format!("read {}", entry.path().display()))?;
            candidates.extend(public_keys_from_env_body(&body));
        }
    }
    Ok(candidates)
}

fn public_keys_from_env_body(body: &str) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    for raw_line in body.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        let Some((raw_key, _)) = line.split_once('=') else {
            continue;
        };
        let key = raw_key.trim();
        if let Some(private_key) = public_to_private_key_name(key) {
            keys.insert(private_key);
        }
    }
    keys
}

fn public_to_private_key_name(public_key: &str) -> Option<String> {
    if public_key == DOTENV_PUBLIC_KEY_PREFIX {
        return Some(PRIVATE_KEY_PREFIX.to_string());
    }
    let suffix = public_key.strip_prefix(&format!("{DOTENV_PUBLIC_KEY_PREFIX}_"))?;
    if suffix.is_empty() || !suffix.chars().all(is_env_key_char) {
        return None;
    }
    Some(format!("{PRIVATE_KEY_PREFIX}_{suffix}"))
}

fn delete_migrated_source_keys(
    project: &ProjectIdentity,
    source_native: &dyn SecretStore,
    source_dotenvx: &dyn SecretStore,
    native_keys: &BTreeSet<String>,
    dotenvx_keys: &BTreeSet<String>,
) -> Result<()> {
    delete_keys_from_stores(project, source_native, native_keys)?;
    delete_keys_from_stores(project, source_dotenvx, dotenvx_keys)?;
    Ok(())
}

fn delete_keys_from_stores(
    project: &ProjectIdentity,
    store: &dyn SecretStore,
    keys: &BTreeSet<String>,
) -> Result<()> {
    for key in keys {
        store.delete(project, key)?;
    }
    Ok(())
}

fn confirm_migration_delete_source(args: &EnvKeyMigrateArgs) -> Result<()> {
    if args.yes {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        return Err(
            crate::exit::CliExit::message(2, "confirmation requires a TTY; pass --yes").into(),
        );
    }
    eprint!(
        "Delete source keys after migrating to {}? Type `yes` to continue: ",
        args.to
    );
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("read confirmation")?;
    if line.trim() == "yes" {
        Ok(())
    } else {
        bail!("migration cancelled")
    }
}

pub fn key_export(cwd: &Path, args: EnvKeyExportArgs) -> Result<()> {
    ensure!(
        args.instructions,
        "--instructions is required; raw key export is intentionally not supported"
    );
    let (_project_root, project, stores) = load_env_context(cwd)?;
    let private_key_name = env_key_name(args.key.as_ref(), &args.env)?;
    let status = stored_key_status(
        stores.native.as_ref(),
        stores.dotenvx.as_ref(),
        &project,
        &private_key_name,
    )?;
    println!(
        "{}",
        key_export_instructions(
            &project.root,
            &private_key_name,
            &args.env,
            args.key.as_deref(),
            status
        )
    );
    Ok(())
}

fn key_delete_with_store(
    store: &dyn SecretStore,
    project: &ProjectIdentity,
    args: EnvKeyDeleteArgs,
) -> Result<()> {
    let index = store.list_keys(project)?;
    let targets = native_delete_targets(store, project, args, &index)?;
    if targets.is_empty() {
        println!(
            "native env: no matching private keys for {}",
            project.root.display()
        );
        return Ok(());
    }

    for key in &targets {
        store
            .delete(project, key)
            .with_context(|| format!("delete {key}"))?;
    }
    println!("Deleted {} native env private key(s)", targets.len());
    Ok(())
}

fn dotenvx_import_keys_with_store(
    store: &dyn SecretStore,
    project: &ProjectIdentity,
    entries: Vec<(String, String)>,
) -> Result<()> {
    for (key, mut value) in entries {
        store
            .put(project, &key, &value)
            .with_context(|| format!("store {key}"))?;
        value.zeroize();
    }
    Ok(())
}

pub fn dotenvx_list(cwd: &Path) -> Result<()> {
    let (_project_root, project, stores) = load_env_context(cwd)?;
    let index = stores.dotenvx.list_keys(&project)?;
    if index.is_empty() {
        println!(
            "dotenvx: no stored private keys for {}",
            project.root.display()
        );
    } else {
        println!("dotenvx private keys for {}:", project.root.display());
        for key in index {
            println!("  - {key}");
        }
    }
    Ok(())
}

pub fn dotenvx_delete(cwd: &Path, args: DotenvxDeleteArgs) -> Result<()> {
    let (_project_root, project, stores) = load_env_context(cwd)?;
    dotenvx_delete_with_store(stores.dotenvx.as_ref(), &project, args)
}

fn dotenvx_delete_with_store(
    store: &dyn SecretStore,
    project: &ProjectIdentity,
    args: DotenvxDeleteArgs,
) -> Result<()> {
    let index = store.list_keys(project)?;
    let targets = delete_targets(args, &index)?;
    if targets.is_empty() {
        println!(
            "dotenvx: no matching private keys for {}",
            project.root.display()
        );
        return Ok(());
    }

    for key in &targets {
        store
            .delete(project, key)
            .with_context(|| format!("delete {key}"))?;
    }
    println!("Deleted {} dotenvx private key(s)", targets.len());
    Ok(())
}

pub fn dotenvx_run(cwd: &Path, args: DotenvxRunArgs) -> Result<()> {
    let (_project_root, project, stores) = load_env_context(cwd)?;
    let mut cmd = build_dotenvx_run_command(stores.dotenvx.as_ref(), &project, cwd, &args)?;
    let status = cmd.status().with_context(|| {
        format!(
            "run `{}`; install dotenvx or pass --dotenvx-bin",
            args.dotenvx_bin
        )
    })?;
    if !status.success() {
        return Err(CliExit::silent(status.code().unwrap_or(2)).into());
    }
    Ok(())
}

fn build_dotenvx_run_command(
    store: &dyn SecretStore,
    project: &ProjectIdentity,
    cwd: &Path,
    args: &DotenvxRunArgs,
) -> Result<Command> {
    let index = store.list_keys(project)?;
    let selected = run_targets(args, &index)?;
    if selected.is_empty() {
        bail!(
            "no stored dotenvx private keys for {}; run `shk env dotenvx import-keys .env.keys` first",
            project.root.display()
        );
    }

    let mut cmd = Command::new(&args.dotenvx_bin);
    cmd.arg("run");
    for file in &args.files {
        cmd.arg("-f").arg(file);
    }
    cmd.arg("--");
    cmd.args(&args.command);
    cmd.current_dir(cwd);
    remove_inherited_private_key_env(&mut cmd);

    for key in selected {
        let mut value = store
            .get(project, &key)
            .with_context(|| format!("read {key}"))?
            .ok_or_else(|| {
                anyhow!("stored index references {key}, but the credential is missing")
            })?;
        cmd.env(&key, &value);
        value.zeroize();
    }
    Ok(cmd)
}

fn read_native_env_run_keys(
    native_store: &dyn SecretStore,
    dotenvx_store: &dyn SecretStore,
    project: &ProjectIdentity,
    args: &EnvRunArgs,
) -> Result<Vec<NativeEnvKeyMaterial>> {
    let selected = native_run_targets(args)?;
    let mut keys = Vec::new();
    for key in selected {
        let material =
            match read_or_adopt_env_key_material(native_store, dotenvx_store, project, &key) {
                Ok(Some(material)) => material,
                Ok(None) => return Err(missing_env_key_error(&key)),
                Err(err) if crate::env_store::is_secret_store_unavailable(&err) => {
                    return Err(err.context(missing_env_key_message(&key)));
                }
                Err(err) => return Err(err),
            };
        keys.push(material);
    }
    Ok(keys)
}

fn missing_env_key_error(private_key_name: &str) -> anyhow::Error {
    anyhow!(missing_env_key_message(private_key_name))
}

fn missing_env_key_message(private_key_name: &str) -> String {
    format!(
        "no stored {private_key_name}; run `shk env encrypt` or `shk env dotenvx import-keys .env.keys` first"
    )
}

fn native_run_targets(args: &EnvRunArgs) -> Result<Vec<String>> {
    let mut selected = BTreeSet::new();
    for key in &args.keys {
        validate_private_key_name(key)?;
        selected.insert(key.clone());
    }
    for env in &args.envs {
        let key = env_to_key(env);
        validate_private_key_name(&key)?;
        selected.insert(key);
    }
    if selected.is_empty() {
        selected.insert(PRIVATE_KEY_PREFIX.to_string());
    }
    Ok(selected.into_iter().collect())
}

fn build_native_env_run_command(
    cwd: &Path,
    args: &EnvRunArgs,
    key_materials: &[NativeEnvKeyMaterial],
) -> Result<Command> {
    let (program, command_args) = args
        .command
        .split_first()
        .ok_or_else(|| anyhow!("command is required"))?;
    let mut cmd = Command::new(program);
    cmd.args(command_args);
    cmd.current_dir(cwd);
    remove_inherited_private_key_env(&mut cmd);

    let files = native_run_files(args);
    for file in files {
        let file_path = if file.is_absolute() {
            file
        } else {
            cwd.join(file)
        };
        let body = std::fs::read_to_string(&file_path)
            .with_context(|| format!("read {}", file_path.display()))?;
        for (key, value) in decrypt_dotenv_env_pairs(&body, key_materials)
            .with_context(|| format!("load {}", file_path.display()))?
        {
            cmd.env(key, value);
        }
    }
    Ok(cmd)
}

fn remove_inherited_private_key_env(cmd: &mut Command) {
    remove_private_key_env_vars(cmd, std::env::vars_os());
}

fn remove_private_key_env_vars<I, K, V>(cmd: &mut Command, vars: I)
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<std::ffi::OsStr>,
{
    for (key, _) in vars {
        let key = key.as_ref();
        if key.to_str().is_some_and(is_dotenvx_private_key_name) {
            cmd.env_remove(key);
        }
    }
}

fn native_run_files(args: &EnvRunArgs) -> Vec<PathBuf> {
    if args.files.is_empty() {
        vec![PathBuf::from(".env")]
    } else {
        args.files.clone()
    }
}

fn comparable_path(cwd: &Path, path: &Path) -> PathBuf {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

fn read_private_key_for_import(private_key_name: &str, from_stdin: bool) -> Result<String> {
    let mut input = String::new();
    if from_stdin {
        std::io::stdin()
            .read_to_string(&mut input)
            .context("read private key from stdin")?;
    } else {
        input = Password::new()
            .with_prompt(format!("Paste {private_key_name}"))
            .interact()
            .context("read private key from prompt")?;
    }
    let mut private_key = input.trim().to_string();
    input.zeroize();
    if private_key.is_empty() {
        private_key.zeroize();
        bail!("{private_key_name} is empty");
    }
    Ok(private_key)
}

fn import_native_env_key_with_store(
    store: &dyn SecretStore,
    project: &ProjectIdentity,
    private_key_name: &str,
    private_key: &str,
    force: bool,
) -> Result<()> {
    validate_private_key_name(private_key_name)?;
    if !force && read_native_env_key(store, project, private_key_name)?.is_some() {
        bail!("stored {private_key_name} already exists; pass --force to replace it");
    }
    let keypair = Keypair::from_private_key(private_key)
        .with_context(|| format!("validate {private_key_name} private key"))?;
    let key = NativeEnvKeyMaterial {
        public_key: keypair.public_key(),
        private_key: private_key.to_string(),
    };
    store_native_env_key(store, project, private_key_name, &key)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeyStoreStatus {
    Native,
    DotenvxImported,
    Missing,
}

fn stored_key_status(
    native_store: &dyn SecretStore,
    dotenvx_store: &dyn SecretStore,
    project: &ProjectIdentity,
    private_key_name: &str,
) -> Result<KeyStoreStatus> {
    if store_has_key(native_store, project, private_key_name)? {
        return Ok(KeyStoreStatus::Native);
    }
    if store_has_key(dotenvx_store, project, private_key_name)? {
        return Ok(KeyStoreStatus::DotenvxImported);
    }
    Ok(KeyStoreStatus::Missing)
}

fn store_has_key(store: &dyn SecretStore, project: &ProjectIdentity, key: &str) -> Result<bool> {
    let Some(mut value) = store.get(project, key)? else {
        return Ok(false);
    };
    value.zeroize();
    Ok(true)
}

fn key_export_instructions(
    project_root: &Path,
    private_key_name: &str,
    env: &str,
    exact_key: Option<&str>,
    status: KeyStoreStatus,
) -> String {
    let import_cmd = match exact_key {
        Some(key) => format!("shk env key import --key {key}"),
        None if env.eq_ignore_ascii_case("default") => "shk env key import".to_string(),
        None => format!("shk env key import --env {env}"),
    };
    let status = match status {
        KeyStoreStatus::Native => "found in the shk native OS credential store",
        KeyStoreStatus::DotenvxImported => {
            "found as an imported dotenvx key; running a native env command can adopt it"
        }
        KeyStoreStatus::Missing => "not found on this machine",
    };

    format!(
        "Key: {private_key_name}\n\
Project: {}\n\
Status: {status}\n\n\
Local team handoff:\n\
1. Store {private_key_name} in your team password manager or another approved secret vault.\n\
2. Share access only with teammates who need this project's local env access.\n\
3. Ask each recipient to retrieve the value from the vault and run:\n\n\
   {import_cmd}\n\n\
For stdin-based imports from a password manager CLI:\n\n\
   <password-manager-read-command> | {import_cmd} --stdin\n\n\
If the only copy is in your OS credential store, retrieve it using your approved OS or vault workflow; shk does not print private keys.\n\
Avoid committing .env.keys, pasting private keys into issue trackers, or sending keys in public channels.\n\
This command intentionally does not print raw key material.",
        project_root.display()
    )
}

fn project_root(cwd: &Path) -> Result<PathBuf> {
    let root = shk_core::git::discover_repo_root(cwd).unwrap_or_else(|| cwd.to_path_buf());
    std::fs::canonicalize(&root).with_context(|| format!("canonicalize {}", root.display()))
}

fn parse_dotenvx_keys(body: &str) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for (idx, raw_line) in body.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        let Some((raw_key, raw_value)) = line.split_once('=') else {
            continue;
        };
        let key = raw_key.trim();
        if !is_dotenvx_private_key_name(key) {
            continue;
        }
        let value = parse_env_value(raw_value)
            .with_context(|| format!("parse {} on line {}", key, idx + 1))?;
        if value.is_empty() {
            bail!("{key} on line {} is empty", idx + 1);
        }
        out.push((key.to_string(), value));
    }
    Ok(out)
}

fn parse_env_value(raw: &str) -> Result<String> {
    let value = raw.trim();
    if let Some(quote) = value.chars().next().filter(|ch| *ch == '"' || *ch == '\'') {
        return parse_quoted_env_value(value, quote);
    }
    Ok(value
        .split_once(" #")
        .map(|(before, _)| before.trim_end())
        .unwrap_or(value)
        .to_string())
}

fn parse_quoted_env_value(value: &str, quote: char) -> Result<String> {
    let mut out = String::new();
    let mut chars = value[quote.len_utf8()..].char_indices().peekable();
    while let Some((idx, ch)) = chars.next() {
        if ch == quote {
            let rest = value[quote.len_utf8() + idx + ch.len_utf8()..].trim();
            if rest.is_empty() || rest.starts_with('#') {
                return Ok(out);
            }
            bail!("unexpected characters after quoted value");
        }
        if quote == '"' && ch == '\\' {
            let Some((_, escaped)) = chars.next() else {
                bail!("unterminated escape sequence");
            };
            match escaped {
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                '$' => out.push('$'),
                other => {
                    out.push('\\');
                    out.push(other);
                }
            }
        } else {
            out.push(ch);
        }
    }
    bail!("unterminated quoted value");
}

fn is_dotenvx_private_key_name(key: &str) -> bool {
    key == PRIVATE_KEY_PREFIX
        || key
            .strip_prefix(&format!("{PRIVATE_KEY_PREFIX}_"))
            .is_some_and(|suffix| !suffix.is_empty() && suffix.chars().all(is_env_key_char))
}

fn is_dotenvx_public_key_name(key: &str) -> bool {
    key == DOTENV_PUBLIC_KEY_PREFIX
        || key
            .strip_prefix(&format!("{DOTENV_PUBLIC_KEY_PREFIX}_"))
            .is_some_and(|suffix| !suffix.is_empty() && suffix.chars().all(is_env_key_char))
}

fn is_env_key_char(ch: char) -> bool {
    ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_'
}

fn env_to_key(env: &str) -> String {
    if env.eq_ignore_ascii_case("default") {
        PRIVATE_KEY_PREFIX.to_string()
    } else {
        format!("{PRIVATE_KEY_PREFIX}_{}", env.to_ascii_uppercase())
    }
}

fn delete_targets(args: DotenvxDeleteArgs, index: &BTreeSet<String>) -> Result<Vec<String>> {
    if args.all {
        return Ok(index.iter().cloned().collect());
    }
    let key = match (args.key, args.env) {
        (Some(key), None) => key,
        (None, Some(env)) => env_to_key(&env),
        (None, None) => bail!("pass --all, --key, or --env to choose private keys to delete"),
        (Some(_), Some(_)) => bail!("pass only one of --key or --env"),
    };
    validate_private_key_name(&key)?;
    Ok(index.contains(&key).then_some(key).into_iter().collect())
}

fn native_delete_targets(
    store: &dyn SecretStore,
    project: &ProjectIdentity,
    args: EnvKeyDeleteArgs,
    index: &BTreeSet<String>,
) -> Result<Vec<String>> {
    if args.all {
        return Ok(index.iter().cloned().collect());
    }
    let key = match (args.key, args.env) {
        (Some(key), None) => key,
        (None, Some(env)) => env_to_key(&env),
        (None, None) => bail!("pass --all, --key, or --env to choose private keys to delete"),
        (Some(_), Some(_)) => bail!("pass only one of --key or --env"),
    };
    validate_private_key_name(&key)?;
    if index.contains(&key) || store_has_key(store, project, &key)? {
        Ok(vec![key])
    } else {
        Ok(Vec::new())
    }
}

fn run_targets(args: &DotenvxRunArgs, index: &BTreeSet<String>) -> Result<Vec<String>> {
    let mut selected = BTreeSet::new();
    for key in &args.keys {
        validate_private_key_name(key)?;
        selected.insert(key.clone());
    }
    for env in &args.envs {
        selected.insert(env_to_key(env));
    }
    if selected.is_empty() {
        selected = index.clone();
    }
    let missing: Vec<String> = selected
        .iter()
        .filter(|key| !index.contains(*key))
        .cloned()
        .collect();
    if !missing.is_empty() {
        bail!(
            "dotenvx private key(s) not imported: {}",
            missing.join(", ")
        );
    }
    Ok(selected.into_iter().collect())
}

fn validate_private_key_name(key: &str) -> Result<()> {
    if is_dotenvx_private_key_name(key) {
        Ok(())
    } else {
        bail!("expected DOTENV_PRIVATE_KEY or DOTENV_PRIVATE_KEY_<ENV>, got {key}")
    }
}

fn env_key_name(key: Option<&String>, env: &str) -> Result<String> {
    if key.is_some() && !env.eq_ignore_ascii_case("default") {
        bail!("pass only one of --key or --env");
    }
    let key = match key {
        Some(key) => key.clone(),
        None => env_to_key(env),
    };
    validate_private_key_name(&key)?;
    Ok(key)
}

fn env_encrypt_output_path(args: &EnvEncryptArgs) -> Result<&Path> {
    if args.in_place {
        return Ok(&args.file);
    }
    args.output
        .as_deref()
        .ok_or_else(|| anyhow!("--output or --in-place is required for `shk env encrypt`"))
}

fn private_to_public_key_name(private_key_name: &str) -> String {
    if private_key_name == PRIVATE_KEY_PREFIX {
        DOTENV_PUBLIC_KEY_PREFIX.to_string()
    } else {
        private_key_name.replacen(PRIVATE_KEY_PREFIX, DOTENV_PUBLIC_KEY_PREFIX, 1)
    }
}

fn read_or_create_native_env_key(
    native_store: &dyn SecretStore,
    dotenvx_store: &dyn SecretStore,
    project: &ProjectIdentity,
    private_key_name: &str,
) -> Result<NativeEnvKeyMaterial> {
    if let Some(key) =
        read_or_adopt_env_key_material(native_store, dotenvx_store, project, private_key_name)?
    {
        return Ok(key);
    }
    let keypair = Keypair::generate();
    let key = NativeEnvKeyMaterial {
        public_key: keypair.public_key(),
        private_key: keypair.private_key(),
    };
    store_native_env_key(native_store, project, private_key_name, &key)?;
    Ok(key)
}

fn read_or_adopt_env_key_material(
    native_store: &dyn SecretStore,
    dotenvx_store: &dyn SecretStore,
    project: &ProjectIdentity,
    private_key_name: &str,
) -> Result<Option<NativeEnvKeyMaterial>> {
    if let Some(key) = read_native_env_key(native_store, project, private_key_name)? {
        return Ok(Some(key));
    }
    let Some(key) = read_dotenvx_env_key(dotenvx_store, project, private_key_name)? else {
        return Ok(None);
    };
    match store_native_env_key(native_store, project, private_key_name, &key) {
        Ok(()) => eprintln!("Adopted imported dotenvx {private_key_name} into shk native store."),
        Err(err) => eprintln!(
            "warning: could not adopt imported dotenvx {private_key_name} into shk native store: {err}"
        ),
    }
    Ok(Some(key))
}

fn store_native_env_key(
    store: &dyn SecretStore,
    project: &ProjectIdentity,
    private_key_name: &str,
    key: &NativeEnvKeyMaterial,
) -> Result<()> {
    let mut encoded = serde_json::to_string(key).context("serialize env key material")?;
    let result = store
        .put(project, private_key_name, &encoded)
        .with_context(|| format!("store {private_key_name}"));
    encoded.zeroize();
    result
}

fn read_native_env_key(
    store: &dyn SecretStore,
    project: &ProjectIdentity,
    private_key_name: &str,
) -> Result<Option<NativeEnvKeyMaterial>> {
    let Some(mut encoded) = store.get(project, private_key_name)? else {
        return Ok(None);
    };
    let key: NativeEnvKeyMaterial = match serde_json::from_str(&encoded)
        .with_context(|| format!("parse stored {private_key_name}"))
    {
        Ok(key) => key,
        Err(err) => {
            encoded.zeroize();
            return Err(err);
        }
    };
    encoded.zeroize();
    ensure!(
        !key.public_key.is_empty(),
        "stored {private_key_name} has no public key"
    );
    ensure!(
        !key.private_key.is_empty(),
        "stored {private_key_name} has no private key"
    );
    Ok(Some(key))
}

fn read_dotenvx_env_key(
    store: &dyn SecretStore,
    project: &ProjectIdentity,
    private_key_name: &str,
) -> Result<Option<NativeEnvKeyMaterial>> {
    let Some(mut private_key) = store.get(project, private_key_name)? else {
        return Ok(None);
    };
    let public_key = match Keypair::from_private_key(&private_key)
        .with_context(|| format!("derive public key from stored dotenvx {private_key_name}"))
    {
        Ok(keypair) => keypair.public_key(),
        Err(err) => {
            private_key.zeroize();
            return Err(err);
        }
    };
    Ok(Some(NativeEnvKeyMaterial {
        public_key,
        private_key,
    }))
}

fn encrypt_dotenv_body(body: &str, public_key_name: &str, public_key: &str) -> Result<String> {
    let mut out = Vec::new();
    // Keep the managed marker at the top, before preserving original comments or blank lines.
    push_shk_public_key_header(&mut out, public_key_name, public_key);

    for raw_line in body.lines() {
        let line = raw_line.trim_start();
        if is_managed_env_header_line(line.trim()) {
            continue;
        }
        let Some((raw_key, raw_value)) = split_dotenv_assignment(raw_line) else {
            out.push(raw_line.to_string());
            continue;
        };
        let key = raw_key.trim();
        validate_dotenv_assignment_key(key)?;
        if is_dotenvx_private_key_name(key) {
            bail!(
                "refusing to encrypt dotenv file containing {key}; store private keys outside the env file"
            );
        }
        if key == public_key_name {
            continue;
        }
        if is_dotenvx_public_key_name(key) {
            continue;
        }
        let value = parse_env_value(raw_value)
            .with_context(|| format!("parse {key} while encrypting dotenv"))?;
        if value.starts_with(DOTENV_ENCRYPTED_PREFIX) {
            out.push(format!("{key}=\"{value}\""));
            continue;
        }
        let encrypted = dotenvx_encrypt(&value, public_key)
            .map_err(|err| anyhow!("encrypt {key} with dotenvx ECIES: {err}"))?;
        let encrypted_value = if encrypted.starts_with(DOTENV_ENCRYPTED_PREFIX) {
            encrypted
        } else {
            format!("{DOTENV_ENCRYPTED_PREFIX}{encrypted}")
        };
        out.push(format!("{key}=\"{encrypted_value}\""));
    }
    Ok(format!("{}\n", out.join("\n")))
}

fn decrypt_dotenv_body(body: &str, private_key: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for raw_line in body.lines() {
        let line = raw_line.trim_start();
        if is_managed_env_header_line(line.trim()) {
            continue;
        }
        let Some((raw_key, raw_value)) = split_dotenv_assignment(raw_line) else {
            out.push(raw_line.to_string());
            continue;
        };
        let key = raw_key.trim();
        validate_dotenv_assignment_key(key)?;
        if is_dotenvx_private_key_name(key) {
            bail!(
                "refusing to decrypt dotenv file containing {key}; private keys must stay outside env files"
            );
        }
        if is_dotenvx_public_key_name(key) {
            continue;
        }
        let value = parse_env_value(raw_value)
            .with_context(|| format!("parse {key} while decrypting dotenv"))?;
        if value.starts_with(DOTENV_ENCRYPTED_PREFIX) {
            let decrypted = dotenvx_decrypt(&value, private_key)
                .map_err(|err| anyhow!("decrypt {key} with dotenvx ECIES: {err}"))?;
            out.push(format!("{key}={}", quote_env_value(&decrypted)));
        } else {
            out.push(raw_line.to_string());
        }
    }
    Ok(format!("{}\n", out.join("\n")).into_bytes())
}

fn decrypt_dotenv_env_pairs(
    body: &str,
    key_materials: &[NativeEnvKeyMaterial],
) -> Result<Vec<(String, String)>> {
    ensure!(
        !key_materials.is_empty(),
        "at least one stored native env key is required"
    );
    let mut out = Vec::new();
    for raw_line in body.lines() {
        let Some((raw_key, raw_value)) = split_dotenv_assignment(raw_line) else {
            continue;
        };
        let key = raw_key.trim();
        validate_dotenv_assignment_key(key)?;
        if is_dotenvx_private_key_name(key) {
            bail!(
                "refusing to load dotenv file containing {key}; private keys must stay outside env files"
            );
        }
        if is_dotenvx_public_key_name(key) {
            continue;
        }
        let value = parse_env_value(raw_value)
            .with_context(|| format!("parse {key} while loading dotenv"))?;
        let value = decrypt_env_value(key, &value, key_materials)?;
        out.push((key.to_string(), value));
    }
    Ok(out)
}

fn split_dotenv_assignment(raw_line: &str) -> Option<(&str, &str)> {
    let line = raw_line.trim_start();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let line = line
        .strip_prefix("export ")
        .map(str::trim_start)
        .unwrap_or(line);
    line.split_once('=')
}

fn decrypt_env_value(
    key: &str,
    value: &str,
    key_materials: &[NativeEnvKeyMaterial],
) -> Result<String> {
    if !value.starts_with(DOTENV_ENCRYPTED_PREFIX) {
        return Ok(value.to_string());
    }

    let mut last_error = None;
    for material in key_materials {
        match dotenvx_decrypt(value, &material.private_key) {
            Ok(decrypted) => return Ok(decrypted),
            Err(err) => last_error = Some(err.to_string()),
        }
    }
    let detail = last_error.unwrap_or_else(|| "no key attempted".to_string());
    bail!("decrypt {key} with stored native env keys: {detail}")
}

fn validate_dotenv_assignment_key(key: &str) -> Result<()> {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        bail!("empty dotenv key");
    };
    ensure!(
        first.is_ascii_alphabetic() || first == '_',
        "invalid dotenv key {key}"
    );
    ensure!(
        chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_'),
        "invalid dotenv key {key}"
    );
    Ok(())
}

fn is_managed_env_header_line(line: &str) -> bool {
    SHK_NATIVE_ENV_HEADER_LINES.contains(&line)
        || SHK_PUBLIC_KEY_HEADER_LINES.contains(&line)
        || LEGACY_DOTENV_PUBLIC_KEY_HEADER_LINES.contains(&line)
}

fn push_shk_public_key_header(out: &mut Vec<String>, public_key_name: &str, public_key: &str) {
    out.extend(
        SHK_NATIVE_ENV_HEADER_LINES
            .iter()
            .map(|line| line.to_string()),
    );
    out.extend(
        SHK_PUBLIC_KEY_HEADER_LINES
            .iter()
            .map(|line| line.to_string()),
    );
    out.push(format!("{public_key_name}=\"{public_key}\""));
}

fn quote_env_value(value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r");
    format!("\"{escaped}\"")
}

fn write_output(path: &Path, body: &[u8], force: bool) -> Result<()> {
    if path.exists() && !force {
        bail!(
            "{} already exists; pass --force to overwrite",
            path.display()
        );
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut tmp = NamedTempFile::new_in(parent)
        .with_context(|| format!("create temp file in {}", parent.display()))?;
    tmp.write_all(body)
        .with_context(|| format!("write temp output for {}", path.display()))?;
    tmp.flush()
        .with_context(|| format!("flush temp output for {}", path.display()))?;

    if force {
        shk_core::fs_atomic::persist_named_temp_file(tmp, path)
    } else {
        shk_core::fs_atomic::persist_named_temp_file_noclobber(tmp, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env_store::{ProjectIdentity, test_support::MockSecretStore};

    fn test_project(root: &Path) -> ProjectIdentity {
        ProjectIdentity {
            root: root.to_path_buf(),
            project_id: None,
        }
    }

    struct FailingPutSecretStore;

    impl SecretStore for FailingPutSecretStore {
        fn put(&self, _project: &ProjectIdentity, _key: &str, _value: &str) -> Result<()> {
            bail!("simulated credential store write failure")
        }

        fn get(&self, _project: &ProjectIdentity, _key: &str) -> Result<Option<String>> {
            Ok(None)
        }

        fn delete(&self, _project: &ProjectIdentity, _key: &str) -> Result<()> {
            Ok(())
        }

        fn list_keys(&self, _project: &ProjectIdentity) -> Result<BTreeSet<String>> {
            Ok(BTreeSet::new())
        }
    }

    #[test]
    fn write_output_noclobber_preserves_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("output.env");
        std::fs::write(&path, b"old").unwrap();

        let err = write_output(&path, b"new", false).unwrap_err();

        assert!(err.to_string().contains("--force"), "{err}");
        assert_eq!(std::fs::read(&path).unwrap(), b"old");
    }

    #[test]
    fn write_output_force_replaces_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("output.env");
        std::fs::write(&path, b"old").unwrap();

        write_output(&path, b"new", true).unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"new");
    }

    fn run_args() -> DotenvxRunArgs {
        DotenvxRunArgs {
            dotenvx_bin: "dotenvx-test-bin".to_string(),
            files: vec![PathBuf::from(".env"), PathBuf::from(".env.production")],
            keys: Vec::new(),
            envs: Vec::new(),
            command: vec!["npm".to_string(), "test".to_string()],
        }
    }

    #[test]
    fn parses_dotenvx_keys_without_values_in_output() {
        let parsed = parse_dotenvx_keys(
            r#"
            # comment
            export DOTENV_PRIVATE_KEY="dotenvx-default-value"
            DOTENV_PRIVATE_KEY_PRODUCTION='dotenvx-prod-value'
            NOT_PRIVATE=value
            "#,
        )
        .unwrap();
        assert_eq!(
            parsed,
            vec![
                (
                    "DOTENV_PRIVATE_KEY".to_string(),
                    "dotenvx-default-value".to_string()
                ),
                (
                    "DOTENV_PRIVATE_KEY_PRODUCTION".to_string(),
                    "dotenvx-prod-value".to_string()
                ),
            ]
        );
    }

    #[test]
    fn parses_quoted_dotenvx_values_with_escapes_and_comments() {
        let parsed = parse_dotenvx_keys(
            r#"
            DOTENV_PRIVATE_KEY="value with \"escaped quote\"" # trailing comment
            DOTENV_PRIVATE_KEY_PRODUCTION='single quoted value' # trailing comment
            "#,
        )
        .unwrap();
        assert_eq!(
            parsed,
            vec![
                (
                    "DOTENV_PRIVATE_KEY".to_string(),
                    "value with \"escaped quote\"".to_string()
                ),
                (
                    "DOTENV_PRIVATE_KEY_PRODUCTION".to_string(),
                    "single quoted value".to_string()
                ),
            ]
        );
    }

    #[test]
    fn import_and_delete_update_store_index() {
        let store = MockSecretStore::keyring();
        let root = Path::new("/repo/app");
        let project = test_project(root);
        dotenvx_import_keys_with_store(
            &store,
            &project,
            vec![
                (
                    "DOTENV_PRIVATE_KEY".to_string(),
                    "dotenvx-default-value".to_string(),
                ),
                (
                    "DOTENV_PRIVATE_KEY_PRODUCTION".to_string(),
                    "dotenvx-production-value".to_string(),
                ),
            ],
        )
        .unwrap();

        assert_eq!(
            store.get(&project, "DOTENV_PRIVATE_KEY").unwrap(),
            Some("dotenvx-default-value".to_string())
        );
        assert_eq!(
            store.list_keys(&project).unwrap(),
            BTreeSet::from([
                "DOTENV_PRIVATE_KEY".to_string(),
                "DOTENV_PRIVATE_KEY_PRODUCTION".to_string()
            ])
        );

        dotenvx_delete_with_store(
            &store,
            &project,
            DotenvxDeleteArgs {
                all: false,
                key: None,
                env: Some("production".to_string()),
            },
        )
        .unwrap();

        assert_eq!(
            store
                .get(&project, "DOTENV_PRIVATE_KEY_PRODUCTION")
                .unwrap(),
            None
        );
        assert_eq!(
            store.list_keys(&project).unwrap(),
            BTreeSet::from(["DOTENV_PRIVATE_KEY".to_string()])
        );
    }

    #[test]
    fn delete_all_removes_keys_and_index() {
        let store = MockSecretStore::keyring();
        let root = Path::new("/repo/app");
        let project = test_project(root);
        dotenvx_import_keys_with_store(
            &store,
            &project,
            vec![
                (
                    "DOTENV_PRIVATE_KEY".to_string(),
                    "dotenvx-default-value".to_string(),
                ),
                (
                    "DOTENV_PRIVATE_KEY_STAGING".to_string(),
                    "dotenvx-staging-value".to_string(),
                ),
            ],
        )
        .unwrap();

        dotenvx_delete_with_store(
            &store,
            &project,
            DotenvxDeleteArgs {
                all: true,
                key: None,
                env: None,
            },
        )
        .unwrap();

        assert!(store.list_keys(&project).unwrap().is_empty());
        assert_eq!(store.get(&project, "DOTENV_PRIVATE_KEY").unwrap(), None);
        assert_eq!(
            store.get(&project, "DOTENV_PRIVATE_KEY_STAGING").unwrap(),
            None
        );
    }

    #[test]
    fn delete_targets_require_explicit_target() {
        let err = delete_targets(
            DotenvxDeleteArgs {
                all: false,
                key: None,
                env: None,
            },
            &BTreeSet::new(),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("pass --all, --key, or --env"),
            "{err}"
        );
    }

    #[test]
    fn delete_targets_validate_explicit_key_names() {
        let err = delete_targets(
            DotenvxDeleteArgs {
                all: false,
                key: Some("DOTENV_PUBLIC_KEY".to_string()),
                env: None,
            },
            &BTreeSet::new(),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("expected DOTENV_PRIVATE_KEY"),
            "{err}"
        );
    }

    #[test]
    fn run_targets_default_to_all_index_keys() {
        let args = run_args();
        let index = BTreeSet::from([
            "DOTENV_PRIVATE_KEY".to_string(),
            "DOTENV_PRIVATE_KEY_PRODUCTION".to_string(),
        ]);

        assert_eq!(
            run_targets(&args, &index).unwrap(),
            vec![
                "DOTENV_PRIVATE_KEY".to_string(),
                "DOTENV_PRIVATE_KEY_PRODUCTION".to_string()
            ]
        );
    }

    #[test]
    fn run_targets_validate_and_report_missing_keys() {
        let mut args = run_args();
        args.keys = vec!["DOTENV_PRIVATE_KEY_PRODUCTION".to_string()];
        args.envs = vec!["staging".to_string()];

        let err = run_targets(
            &args,
            &BTreeSet::from(["DOTENV_PRIVATE_KEY_PRODUCTION".to_string()]),
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("dotenvx private key(s) not imported: DOTENV_PRIVATE_KEY_STAGING"),
            "{err}"
        );
    }

    #[test]
    fn build_run_command_injects_selected_keys_and_args() {
        let store = MockSecretStore::keyring();
        let root = Path::new("/repo/app");
        let project = test_project(root);
        dotenvx_import_keys_with_store(
            &store,
            &project,
            vec![
                (
                    "DOTENV_PRIVATE_KEY".to_string(),
                    "dotenvx-default-value".to_string(),
                ),
                (
                    "DOTENV_PRIVATE_KEY_PRODUCTION".to_string(),
                    "dotenvx-production-value".to_string(),
                ),
            ],
        )
        .unwrap();
        let mut args = run_args();
        args.envs = vec!["production".to_string()];

        let cmd = build_dotenvx_run_command(&store, &project, Path::new("/repo/app/subdir"), &args)
            .unwrap();
        assert_eq!(cmd.get_program(), "dotenvx-test-bin");
        assert_eq!(cmd.get_current_dir(), Some(Path::new("/repo/app/subdir")));
        assert_eq!(
            cmd.get_args().collect::<Vec<_>>(),
            vec![
                "run",
                "-f",
                ".env",
                "-f",
                ".env.production",
                "--",
                "npm",
                "test"
            ]
        );

        let envs = cmd.get_envs().collect::<Vec<_>>();
        assert!(envs.iter().any(|(key, value)| {
            *key == "DOTENV_PRIVATE_KEY_PRODUCTION"
                && value.as_deref() == Some(std::ffi::OsStr::new("dotenvx-production-value"))
        }));
        assert!(!envs.iter().any(|(key, _)| *key == "DOTENV_PRIVATE_KEY"));
    }

    #[test]
    fn build_run_command_reports_empty_index_and_missing_credential() {
        let store = MockSecretStore::keyring();
        let root = Path::new("/repo/app");
        let project = test_project(root);
        let empty_err = build_dotenvx_run_command(&store, &project, root, &run_args()).unwrap_err();
        assert!(
            empty_err
                .to_string()
                .contains("no stored dotenvx private keys"),
            "{empty_err}"
        );

        store
            .put(&project, "__index", r#"{"keys":["DOTENV_PRIVATE_KEY"]}"#)
            .unwrap();
        let missing_err =
            build_dotenvx_run_command(&store, &project, root, &run_args()).unwrap_err();
        assert!(
            missing_err
                .to_string()
                .contains("stored index references DOTENV_PRIVATE_KEY"),
            "{missing_err}"
        );
    }

    #[test]
    fn parse_env_value_rejects_malformed_quotes() {
        assert!(parse_env_value(r#""unterminated"#).is_err());
        assert!(parse_env_value(r#""value" trailing"#).is_err());
        assert!(parse_env_value(r#""dangling\"#).is_err());
    }

    #[test]
    fn rejects_invalid_private_key_name() {
        assert!(is_dotenvx_private_key_name("DOTENV_PRIVATE_KEY"));
        assert!(is_dotenvx_private_key_name("DOTENV_PRIVATE_KEY_PRODUCTION"));
        assert!(!is_dotenvx_private_key_name(
            "DOTENV_PRIVATE_KEY_production"
        ));
        assert!(!is_dotenvx_private_key_name("DOTENV_PUBLIC_KEY"));
    }

    #[test]
    fn maps_env_to_key() {
        assert_eq!(env_to_key("default"), "DOTENV_PRIVATE_KEY");
        assert_eq!(env_to_key("production"), "DOTENV_PRIVATE_KEY_PRODUCTION");
    }

    #[test]
    fn encrypt_decrypt_env_roundtrip_without_printing_key_material() {
        let keypair = Keypair::generate();
        let encrypted = encrypt_dotenv_body(
            "API_KEY=secret\nPUBLIC_VALUE=ok\n",
            "DOTENV_PUBLIC_KEY",
            &keypair.public_key(),
        )
        .unwrap();
        assert!(encrypted.contains("[SHK_NATIVE_ENV]"), "{encrypted}");
        assert!(encrypted.contains("DOTENV_PUBLIC_KEY="), "{encrypted}");
        assert!(encrypted.contains("API_KEY=\"encrypted:"), "{encrypted}");
        assert!(!encrypted.contains("API_KEY=secret"), "{encrypted}");
        assert!(!encrypted.contains(&keypair.private_key()), "{encrypted}");
        let plaintext = decrypt_dotenv_body(&encrypted, &keypair.private_key()).unwrap();
        let plaintext = String::from_utf8(plaintext).unwrap();
        assert!(plaintext.contains("API_KEY=\"secret\""), "{plaintext}");
        assert!(plaintext.contains("PUBLIC_VALUE=\"ok\""), "{plaintext}");
    }

    #[test]
    fn encrypt_decrypt_preserve_commented_dotenv_assignments() {
        let keypair = Keypair::generate();
        // shk-ignore-next-line secret.generic_api_key
        let commented = "  # API_KEY=commented-secret";
        let body = format!("{commented}\nexport   ACTIVE=secret\n");
        let encrypted =
            encrypt_dotenv_body(&body, "DOTENV_PUBLIC_KEY", &keypair.public_key()).unwrap();

        assert!(encrypted.contains(commented), "{encrypted}");
        assert!(encrypted.contains("ACTIVE=\"encrypted:"), "{encrypted}");
        assert!(!encrypted.contains("# API_KEY=\"encrypted:"), "{encrypted}");

        let plaintext = decrypt_dotenv_body(&encrypted, &keypair.private_key()).unwrap();
        let plaintext = String::from_utf8(plaintext).unwrap();

        assert!(plaintext.contains(commented), "{plaintext}");
        assert!(plaintext.contains("ACTIVE=\"secret\""), "{plaintext}");
    }

    #[test]
    fn encrypt_places_native_header_before_leading_comments() {
        let keypair = Keypair::generate();
        let public_key = keypair.public_key();
        let encrypted = encrypt_dotenv_body(
            "# leading comment\n\nAPI_KEY=secret\n",
            "DOTENV_PUBLIC_KEY",
            &public_key,
        )
        .unwrap();

        assert!(
            encrypted.starts_with(SHK_NATIVE_ENV_HEADER_START),
            "{encrypted}"
        );
        assert!(
            encrypted.contains(&format!(
                "DOTENV_PUBLIC_KEY=\"{public_key}\"\n# leading comment\n\nAPI_KEY=\"encrypted:"
            )),
            "{encrypted}"
        );
    }

    #[test]
    fn encrypt_marks_native_output_without_duplicating_header() {
        let keypair = Keypair::generate();
        let encrypted = encrypt_dotenv_body(
            "API_KEY=secret\n",
            "DOTENV_PUBLIC_KEY",
            &keypair.public_key(),
        )
        .unwrap();
        let encrypted_again =
            encrypt_dotenv_body(&encrypted, "DOTENV_PUBLIC_KEY", &keypair.public_key()).unwrap();

        assert_eq!(encrypted_again.matches("[SHK_NATIVE_ENV]").count(), 1);
        assert_eq!(encrypted_again.matches("[DOTENV_PUBLIC_KEY]").count(), 1);
        assert_eq!(
            encrypted_again.matches("shk native env encryption").count(),
            1
        );
        assert_eq!(encrypted_again.matches("dotenvx.com").count(), 0);
        assert_eq!(encrypted_again.matches("DOTENV_PUBLIC_KEY=").count(), 1);
        assert!(
            encrypted_again.contains("API_KEY=\"encrypted:"),
            "{encrypted_again}"
        );
    }

    #[test]
    fn encrypt_replaces_legacy_dotenvx_public_key_header() {
        let keypair = Keypair::generate();
        let encrypted = format!(
            "{}\n{}\n{}\n{}\nDOTENV_PUBLIC_KEY=\"{}\"\nAPI_KEY=\"encrypted:already\"\n",
            DOTENV_PUBLIC_KEY_HEADER_START,
            LEGACY_DOTENV_PUBLIC_KEY_HEADER_BODY,
            LEGACY_DOTENV_PUBLIC_KEY_HEADER_LINK,
            SHK_PUBLIC_KEY_HEADER_END,
            keypair.public_key(),
        );

        let encrypted_again =
            encrypt_dotenv_body(&encrypted, "DOTENV_PUBLIC_KEY", &keypair.public_key()).unwrap();

        assert!(
            encrypted_again.contains("[DOTENV_PUBLIC_KEY]"),
            "{encrypted_again}"
        );
        assert!(encrypted_again.contains("shk native env encryption"));
        assert!(!encrypted_again.contains("public-key encryption"));
        assert!(
            !encrypted_again.contains("dotenvx.com"),
            "{encrypted_again}"
        );
        assert!(encrypted_again.contains("API_KEY=\"encrypted:already\""));
    }

    #[test]
    fn decrypt_removes_managed_headers() {
        let keypair = Keypair::generate();
        let encrypted = encrypt_dotenv_body(
            "API_KEY=secret\n",
            "DOTENV_PUBLIC_KEY",
            &keypair.public_key(),
        )
        .unwrap();
        let plaintext = decrypt_dotenv_body(&encrypted, &keypair.private_key()).unwrap();
        let plaintext = String::from_utf8(plaintext).unwrap();

        assert!(!plaintext.contains("[SHK_NATIVE_ENV]"), "{plaintext}");
        assert!(!plaintext.contains("[DOTENV_PUBLIC_KEY]"), "{plaintext}");
        assert!(
            !plaintext.contains("shk native env encryption"),
            "{plaintext}"
        );
        assert!(!plaintext.contains("dotenvx.com"), "{plaintext}");
        assert!(plaintext.contains("API_KEY=\"secret\""), "{plaintext}");
    }

    #[test]
    fn decrypt_rejects_wrong_private_key() {
        let keypair = Keypair::generate();
        let wrong_keypair = Keypair::generate();
        let encrypted =
            encrypt_dotenv_body("SECRET=value\n", "DOTENV_PUBLIC_KEY", &keypair.public_key())
                .unwrap();
        let err = decrypt_dotenv_body(&encrypted, &wrong_keypair.private_key()).unwrap_err();
        assert!(err.to_string().contains("decrypt SECRET"), "{err:#}");
    }

    #[test]
    fn env_root_key_is_created_once_in_store() {
        let native_store = MockSecretStore::keyring();
        let dotenvx_store = MockSecretStore::keyring();
        let root = Path::new("/repo");
        let project = test_project(root);
        let first = read_or_create_native_env_key(
            &native_store,
            &dotenvx_store,
            &project,
            "DOTENV_PRIVATE_KEY",
        )
        .unwrap();
        let second = read_or_create_native_env_key(
            &native_store,
            &dotenvx_store,
            &project,
            "DOTENV_PRIVATE_KEY",
        )
        .unwrap();
        assert_eq!(first.public_key, second.public_key);
        assert_eq!(first.private_key, second.private_key);
    }

    #[test]
    fn key_import_stores_native_key_material_without_printing_value() {
        let store = MockSecretStore::keyring();
        let root = Path::new("/repo");
        let project = test_project(root);
        let keypair = Keypair::generate();

        import_native_env_key_with_store(
            &store,
            &project,
            "DOTENV_PRIVATE_KEY",
            &keypair.private_key(),
            false,
        )
        .unwrap();

        let stored = read_native_env_key(&store, &project, "DOTENV_PRIVATE_KEY")
            .unwrap()
            .unwrap();
        assert_eq!(stored.public_key, keypair.public_key());
        assert_eq!(stored.private_key, keypair.private_key());
        assert_eq!(
            store.list_keys(&project).unwrap(),
            BTreeSet::from(["DOTENV_PRIVATE_KEY".to_string()])
        );
    }

    #[test]
    fn key_import_requires_force_for_existing_native_key() {
        let store = MockSecretStore::keyring();
        let root = Path::new("/repo");
        let project = test_project(root);
        let first = Keypair::generate();
        let second = Keypair::generate();
        import_native_env_key_with_store(
            &store,
            &project,
            "DOTENV_PRIVATE_KEY",
            &first.private_key(),
            false,
        )
        .unwrap();

        let err = import_native_env_key_with_store(
            &store,
            &project,
            "DOTENV_PRIVATE_KEY",
            &second.private_key(),
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("--force"), "{err}");

        import_native_env_key_with_store(
            &store,
            &project,
            "DOTENV_PRIVATE_KEY",
            &second.private_key(),
            true,
        )
        .unwrap();
        let stored = read_native_env_key(&store, &project, "DOTENV_PRIVATE_KEY")
            .unwrap()
            .unwrap();
        assert_eq!(stored.private_key, second.private_key());
    }

    #[test]
    fn native_key_delete_updates_store_index() {
        let store = MockSecretStore::keyring();
        let root = Path::new("/repo");
        let project = test_project(root);
        let default = Keypair::generate();
        let production = Keypair::generate();
        import_native_env_key_with_store(
            &store,
            &project,
            "DOTENV_PRIVATE_KEY",
            &default.private_key(),
            false,
        )
        .unwrap();
        import_native_env_key_with_store(
            &store,
            &project,
            "DOTENV_PRIVATE_KEY_PRODUCTION",
            &production.private_key(),
            false,
        )
        .unwrap();

        key_delete_with_store(
            &store,
            &project,
            EnvKeyDeleteArgs {
                all: false,
                key: None,
                env: Some("production".to_string()),
            },
        )
        .unwrap();

        assert!(
            read_native_env_key(&store, &project, "DOTENV_PRIVATE_KEY_PRODUCTION")
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store.list_keys(&project).unwrap(),
            BTreeSet::from(["DOTENV_PRIVATE_KEY".to_string()])
        );

        key_delete_with_store(
            &store,
            &project,
            EnvKeyDeleteArgs {
                all: true,
                key: None,
                env: None,
            },
        )
        .unwrap();
        assert!(store.list_keys(&project).unwrap().is_empty());
        assert!(
            read_native_env_key(&store, &project, "DOTENV_PRIVATE_KEY")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn native_key_delete_can_remove_unindexed_explicit_key() {
        let store = MockSecretStore::keyring();
        let root = Path::new("/repo");
        let project = test_project(root);
        let keypair = Keypair::generate();
        let material = NativeEnvKeyMaterial {
            public_key: keypair.public_key(),
            private_key: keypair.private_key(),
        };
        store
            .put(
                &project,
                "DOTENV_PRIVATE_KEY_STAGING",
                &serde_json::to_string(&material).unwrap(),
            )
            .unwrap();

        key_delete_with_store(
            &store,
            &project,
            EnvKeyDeleteArgs {
                all: false,
                key: Some("DOTENV_PRIVATE_KEY_STAGING".to_string()),
                env: None,
            },
        )
        .unwrap();

        assert_eq!(
            store.get(&project, "DOTENV_PRIVATE_KEY_STAGING").unwrap(),
            None
        );
    }

    #[test]
    fn key_export_instructions_do_not_include_raw_key_material() {
        let keypair = Keypair::generate();
        let default_body = key_export_instructions(
            Path::new("/repo"),
            "DOTENV_PRIVATE_KEY",
            "default",
            None,
            KeyStoreStatus::Missing,
        );
        assert!(
            default_body.contains("shk env key import"),
            "{default_body}"
        );
        assert!(
            !default_body.contains("shk env key import --env default"),
            "{default_body}"
        );

        let body = key_export_instructions(
            Path::new("/repo"),
            "DOTENV_PRIVATE_KEY_PRODUCTION",
            "production",
            None,
            KeyStoreStatus::Native,
        );

        assert!(
            body.contains("shk env key import --env production"),
            "{body}"
        );
        assert!(body.contains("does not print raw key material"), "{body}");
        assert!(!body.contains(&keypair.private_key()), "{body}");
    }

    #[test]
    fn env_key_name_rejects_key_and_non_default_env_together() {
        let err = env_key_name(
            Some(&"DOTENV_PRIVATE_KEY_PRODUCTION".to_string()),
            "staging",
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("only one of --key or --env"),
            "{err}"
        );
        assert_eq!(
            env_key_name(
                Some(&"DOTENV_PRIVATE_KEY_PRODUCTION".to_string()),
                "default"
            )
            .unwrap(),
            "DOTENV_PRIVATE_KEY_PRODUCTION"
        );
    }

    #[test]
    fn stored_key_status_prefers_native_store() {
        let native_store = MockSecretStore::keyring();
        let dotenvx_store = MockSecretStore::keyring();
        let root = Path::new("/repo");
        let project = test_project(root);
        let native = Keypair::generate();
        let imported = Keypair::generate();
        import_native_env_key_with_store(
            &native_store,
            &project,
            "DOTENV_PRIVATE_KEY",
            &native.private_key(),
            false,
        )
        .unwrap();
        dotenvx_store
            .put(&project, "DOTENV_PRIVATE_KEY", &imported.private_key())
            .unwrap();

        assert_eq!(
            stored_key_status(
                &native_store,
                &dotenvx_store,
                &project,
                "DOTENV_PRIVATE_KEY"
            )
            .unwrap(),
            KeyStoreStatus::Native
        );
    }

    #[test]
    fn native_env_adopts_imported_dotenvx_keys_for_migration() {
        let native_store = MockSecretStore::keyring();
        let dotenvx_store = MockSecretStore::keyring();
        let root = Path::new("/repo");
        let project = test_project(root);
        let keypair = Keypair::generate();
        dotenvx_store
            .put(&project, "DOTENV_PRIVATE_KEY", &keypair.private_key())
            .unwrap();

        let key = read_or_adopt_env_key_material(
            &native_store,
            &dotenvx_store,
            &project,
            "DOTENV_PRIVATE_KEY",
        )
        .unwrap()
        .unwrap();
        assert_eq!(key.public_key, keypair.public_key());
        assert_eq!(key.private_key, keypair.private_key());
        let adopted = read_native_env_key(&native_store, &project, "DOTENV_PRIVATE_KEY")
            .unwrap()
            .unwrap();
        assert_eq!(adopted.public_key, keypair.public_key());
        assert_eq!(adopted.private_key, keypair.private_key());
    }

    #[test]
    fn native_env_uses_imported_dotenvx_key_when_adoption_fails() {
        let native_store = FailingPutSecretStore;
        let dotenvx_store = MockSecretStore::keyring();
        let root = Path::new("/repo");
        let project = test_project(root);
        let keypair = Keypair::generate();
        dotenvx_store
            .put(&project, "DOTENV_PRIVATE_KEY", &keypair.private_key())
            .unwrap();

        let key = read_or_adopt_env_key_material(
            &native_store,
            &dotenvx_store,
            &project,
            "DOTENV_PRIVATE_KEY",
        )
        .unwrap()
        .unwrap();

        assert_eq!(key.public_key, keypair.public_key());
        assert_eq!(key.private_key, keypair.private_key());
    }

    #[test]
    fn native_env_prefers_native_key_over_imported_dotenvx_key() {
        let native_store = MockSecretStore::keyring();
        let dotenvx_store = MockSecretStore::keyring();
        let root = Path::new("/repo");
        let project = test_project(root);
        let native = Keypair::generate();
        let imported = Keypair::generate();
        let native_material = NativeEnvKeyMaterial {
            public_key: native.public_key(),
            private_key: native.private_key(),
        };
        native_store
            .put(
                &project,
                "DOTENV_PRIVATE_KEY",
                &serde_json::to_string(&native_material).unwrap(),
            )
            .unwrap();
        dotenvx_store
            .put(&project, "DOTENV_PRIVATE_KEY", &imported.private_key())
            .unwrap();

        let key = read_or_adopt_env_key_material(
            &native_store,
            &dotenvx_store,
            &project,
            "DOTENV_PRIVATE_KEY",
        )
        .unwrap()
        .unwrap();
        assert_eq!(key.public_key, native.public_key());
        assert_eq!(key.private_key, native.private_key());
    }

    #[test]
    fn encrypt_rejects_private_key_entries() {
        let keypair = Keypair::generate();
        let err = encrypt_dotenv_body(
            "DOTENV_PRIVATE_KEY=dotenvx-secret-demo-value\n",
            "DOTENV_PUBLIC_KEY",
            &keypair.public_key(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("refusing to encrypt"), "{err}");
    }

    #[test]
    fn native_run_command_decrypts_values_without_key_env_injection() {
        let keypair = Keypair::generate();
        let encrypted = encrypt_dotenv_body(
            "API_KEY=secret\n",
            "DOTENV_PUBLIC_KEY",
            &keypair.public_key(),
        )
        .unwrap();
        let material = NativeEnvKeyMaterial {
            public_key: keypair.public_key(),
            private_key: keypair.private_key(),
        };
        let args = EnvRunArgs {
            files: Vec::new(),
            keys: Vec::new(),
            envs: Vec::new(),
            command: vec!["npm".to_string(), "test".to_string()],
        };
        let pairs = decrypt_dotenv_env_pairs(&encrypted, &[material]).unwrap();
        assert_eq!(pairs, vec![("API_KEY".to_string(), "secret".to_string())]);

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".env"), encrypted).unwrap();
        let keypair = Keypair::generate();
        let encrypted = encrypt_dotenv_body(
            "API_KEY=secret\n",
            "DOTENV_PUBLIC_KEY",
            &keypair.public_key(),
        )
        .unwrap();
        std::fs::write(dir.path().join(".env"), encrypted).unwrap();
        let material = NativeEnvKeyMaterial {
            public_key: keypair.public_key(),
            private_key: keypair.private_key(),
        };
        let cmd = build_native_env_run_command(dir.path(), &args, &[material]).unwrap();
        let envs = cmd.get_envs().collect::<Vec<_>>();
        assert!(envs.iter().any(|(key, value)| {
            *key == "API_KEY" && value.as_deref() == Some(std::ffi::OsStr::new("secret"))
        }));
        assert!(!envs.iter().any(|(key, _)| *key == "DOTENV_PRIVATE_KEY"));
    }

    #[test]
    fn run_commands_remove_inherited_private_key_env_vars() {
        let mut cmd = Command::new("npm");
        remove_private_key_env_vars(
            &mut cmd,
            [
                ("DOTENV_PRIVATE_KEY", "default-secret"),
                ("DOTENV_PRIVATE_KEY_PRODUCTION", "production-secret"),
                ("DOTENV_PRIVATE_KEY_production", "invalid-lowercase"),
                ("APP_SECRET", "app-secret"),
            ],
        );

        let envs = cmd.get_envs().collect::<Vec<_>>();
        assert!(
            envs.iter()
                .any(|(key, value)| { *key == "DOTENV_PRIVATE_KEY" && value.is_none() })
        );
        assert!(
            envs.iter()
                .any(|(key, value)| { *key == "DOTENV_PRIVATE_KEY_PRODUCTION" && value.is_none() })
        );
        assert!(!envs.iter().any(|(key, _)| *key == "APP_SECRET"));
        assert!(
            !envs
                .iter()
                .any(|(key, _)| *key == "DOTENV_PRIVATE_KEY_production")
        );
    }

    #[test]
    fn native_run_targets_default_to_project_key() {
        let args = EnvRunArgs {
            files: Vec::new(),
            keys: Vec::new(),
            envs: Vec::new(),
            command: vec!["echo".to_string(), "ok".to_string()],
        };
        assert_eq!(
            native_run_targets(&args).unwrap(),
            vec!["DOTENV_PRIVATE_KEY".to_string()]
        );
    }

    #[test]
    fn comparable_path_normalizes_relative_segments() {
        assert_eq!(
            comparable_path(Path::new("/repo/app"), Path::new("./.env")),
            comparable_path(Path::new("/repo/app"), Path::new(".env"))
        );
        assert_eq!(
            comparable_path(Path::new("/repo/app/sub"), Path::new("../.env")),
            PathBuf::from("/repo/app/.env")
        );
    }

    #[test]
    fn keys_for_migration_includes_unindexed_legacy_keys() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".env"),
            "DOTENV_PUBLIC_KEY=\"public-demo-key\"\n",
        )
        .unwrap();
        let project = test_project(dir.path());
        let store = MockSecretStore::keyring();
        store.insert_legacy_key(&project, "DOTENV_PRIVATE_KEY", "secret");
        assert!(store.list_keys(&project).unwrap().is_empty());

        let candidates = discover_private_key_candidates(dir.path()).unwrap();
        let keys = keys_for_migration(&store, &project, &candidates).unwrap();
        assert_eq!(keys, BTreeSet::from(["DOTENV_PRIVATE_KEY".to_string()]));
    }

    #[test]
    fn public_to_private_key_name_maps_env_suffixes() {
        assert_eq!(
            public_to_private_key_name("DOTENV_PUBLIC_KEY").as_deref(),
            Some("DOTENV_PRIVATE_KEY")
        );
        assert_eq!(
            public_to_private_key_name("DOTENV_PUBLIC_KEY_PRODUCTION").as_deref(),
            Some("DOTENV_PRIVATE_KEY_PRODUCTION")
        );
        assert!(public_to_private_key_name("DOTENV_PUBLIC_KEY_production").is_none());
    }

    #[test]
    fn copy_keys_between_mock_stores_then_delete_source() {
        let project = test_project(Path::new("/repo/app"));
        let source_native = MockSecretStore::keyring();
        let source_dotenvx = MockSecretStore::keyring();
        let target_native = MockSecretStore::keyring();
        let target_dotenvx = MockSecretStore::keyring();
        source_native
            .put(&project, "DOTENV_PRIVATE_KEY", "value-a")
            .unwrap();
        source_dotenvx
            .put(&project, "DOTENV_PRIVATE_KEY_PRODUCTION", "value-b")
            .unwrap();

        let MigrationCopy {
            migrated,
            native_keys,
            dotenvx_keys,
        } = copy_keys_between_stores(
            Path::new("/repo/app"),
            &project,
            &source_native,
            &source_dotenvx,
            &target_native,
            &target_dotenvx,
        )
        .unwrap();
        assert_eq!(migrated, 2);
        assert_eq!(
            source_native.list_keys(&project).unwrap(),
            BTreeSet::from(["DOTENV_PRIVATE_KEY".to_string()])
        );
        assert_eq!(
            source_dotenvx.list_keys(&project).unwrap(),
            BTreeSet::from(["DOTENV_PRIVATE_KEY_PRODUCTION".to_string()])
        );
        assert_eq!(
            target_native.list_keys(&project).unwrap(),
            BTreeSet::from(["DOTENV_PRIVATE_KEY".to_string()])
        );
        assert_eq!(
            target_dotenvx.list_keys(&project).unwrap(),
            BTreeSet::from(["DOTENV_PRIVATE_KEY_PRODUCTION".to_string()])
        );

        delete_keys_from_stores(&project, &source_native, &native_keys).unwrap();
        delete_keys_from_stores(&project, &source_dotenvx, &dotenvx_keys).unwrap();
        assert!(source_native.list_keys(&project).unwrap().is_empty());
        assert!(source_dotenvx.list_keys(&project).unwrap().is_empty());
    }

    #[test]
    fn copy_keys_between_stores_rejects_destination_conflicts() {
        let project = test_project(Path::new("/repo/app"));
        let source_native = MockSecretStore::keyring();
        let source_dotenvx = MockSecretStore::keyring();
        let target_native = MockSecretStore::keyring();
        let target_dotenvx = MockSecretStore::keyring();
        source_native
            .put(&project, "DOTENV_PRIVATE_KEY", "source-value")
            .unwrap();
        target_native
            .put(&project, "DOTENV_PRIVATE_KEY", "destination-value")
            .unwrap();

        let err = copy_keys_between_stores(
            Path::new("/repo/app"),
            &project,
            &source_native,
            &source_dotenvx,
            &target_native,
            &target_dotenvx,
        )
        .unwrap_err();

        assert!(err.to_string().contains("different value"), "{err}");
        assert!(!err.to_string().contains("source-value"));
        assert!(!err.to_string().contains("destination-value"));
        assert_eq!(
            source_native
                .get(&project, "DOTENV_PRIVATE_KEY")
                .unwrap()
                .as_deref(),
            Some("source-value")
        );
        assert_eq!(
            target_native
                .get(&project, "DOTENV_PRIVATE_KEY")
                .unwrap()
                .as_deref(),
            Some("destination-value")
        );
    }

    #[test]
    fn update_policy_secret_store_preserves_comments_and_other_values() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shk.toml");
        std::fs::write(
            &path,
            "# project policy\n[env]\n# backend choice\nsecret_store = \"keyring\"\nproject_id = \"acme/app\"\n\n[rules]\nsecrets = true # keep me\n",
        )
        .unwrap();

        update_policy_secret_store(&path, "1password").unwrap();

        let updated = std::fs::read_to_string(path).unwrap();
        assert!(updated.contains("# project policy"));
        assert!(updated.contains("# backend choice"));
        assert!(updated.contains("secret_store = \"1password\""));
        assert!(updated.contains("project_id = \"acme/app\""));
        assert!(updated.contains("secrets = true # keep me"));
    }
}
