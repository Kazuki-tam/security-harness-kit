use crate::args::{DotenvxDeleteArgs, DotenvxRunArgs};
use crate::exit::CliExit;
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use zeroize::Zeroize;

const DOTENVX_SERVICE: &str = "security-harness-kit/dotenvx";
const DOTENVX_INDEX_KEY: &str = "__index";
const PRIVATE_KEY_PREFIX: &str = "DOTENV_PRIVATE_KEY";

#[derive(Debug, Deserialize, Serialize)]
struct KeyIndex {
    keys: Vec<String>,
}

pub fn dotenvx_import_keys(cwd: &Path, file: &Path) -> Result<()> {
    let project_root = project_root(cwd)?;
    let body = std::fs::read_to_string(file).with_context(|| format!("read {}", file.display()))?;
    let entries = parse_dotenvx_keys(&body)?;
    if entries.is_empty() {
        bail!("no DOTENV_PRIVATE_KEY* entries found in {}", file.display());
    }
    let imported = entries.len();

    let store = KeyringSecretStore;
    dotenvx_import_keys_with_store(&store, &project_root, entries)?;

    println!("Imported {imported} dotenvx private key(s) into the OS credential store");
    println!("Raw key values were not printed.");
    Ok(())
}

fn dotenvx_import_keys_with_store(
    store: &impl SecretStore,
    project_root: &Path,
    entries: Vec<(String, String)>,
) -> Result<()> {
    let mut index = read_index(store, project_root)?;
    for (key, mut value) in entries {
        store
            .put(&account(project_root, &key), &value)
            .with_context(|| format!("store {key} in OS credential store"))?;
        value.zeroize();
        index.insert(key);
    }
    write_index(store, project_root, &index)?;
    Ok(())
}

pub fn dotenvx_list(cwd: &Path) -> Result<()> {
    let project_root = project_root(cwd)?;
    let store = KeyringSecretStore;
    let index = read_index(&store, &project_root)?;
    if index.is_empty() {
        println!(
            "dotenvx: no stored private keys for {}",
            project_root.display()
        );
    } else {
        println!("dotenvx private keys for {}:", project_root.display());
        for key in index {
            println!("  - {key}");
        }
    }
    Ok(())
}

pub fn dotenvx_delete(cwd: &Path, args: DotenvxDeleteArgs) -> Result<()> {
    let project_root = project_root(cwd)?;
    let store = KeyringSecretStore;
    dotenvx_delete_with_store(&store, &project_root, args)
}

fn dotenvx_delete_with_store(
    store: &impl SecretStore,
    project_root: &Path,
    args: DotenvxDeleteArgs,
) -> Result<()> {
    let mut index = read_index(store, project_root)?;
    let targets = delete_targets(args, &index)?;
    if targets.is_empty() {
        println!(
            "dotenvx: no matching private keys for {}",
            project_root.display()
        );
        return Ok(());
    }

    for key in &targets {
        store
            .delete(&account(project_root, key))
            .with_context(|| format!("delete {key} from OS credential store"))?;
        index.remove(key);
    }
    write_index(store, project_root, &index)?;
    println!("Deleted {} dotenvx private key(s)", targets.len());
    Ok(())
}

pub fn dotenvx_run(cwd: &Path, args: DotenvxRunArgs) -> Result<()> {
    let project_root = project_root(cwd)?;
    let store = KeyringSecretStore;
    let index = read_index(&store, &project_root)?;
    let selected = run_targets(&args, &index)?;
    if selected.is_empty() {
        bail!(
            "no stored dotenvx private keys for {}; run `shk env dotenvx import-keys .env.keys` first",
            project_root.display()
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

    for key in selected {
        let mut value = store
            .get(&account(&project_root, &key))
            .with_context(|| format!("read {key} from OS credential store"))?
            .ok_or_else(|| {
                anyhow!("stored index references {key}, but the credential is missing")
            })?;
        cmd.env(&key, &value);
        value.zeroize();
    }

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

trait SecretStore {
    fn put(&self, account: &str, value: &str) -> Result<()>;
    fn get(&self, account: &str) -> Result<Option<String>>;
    fn delete(&self, account: &str) -> Result<()>;
}

struct KeyringSecretStore;

impl SecretStore for KeyringSecretStore {
    fn put(&self, account: &str, value: &str) -> Result<()> {
        keyring::Entry::new(DOTENVX_SERVICE, account)?
            .set_password(value)
            .map_err(Into::into)
    }

    fn get(&self, account: &str) -> Result<Option<String>> {
        match keyring::Entry::new(DOTENVX_SERVICE, account)?.get_password() {
            Ok(value) => Ok(Some(value)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    fn delete(&self, account: &str) -> Result<()> {
        match keyring::Entry::new(DOTENVX_SERVICE, account)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }
}

fn project_root(cwd: &Path) -> Result<PathBuf> {
    let root = shk_core::git::discover_repo_root(cwd).unwrap_or_else(|| cwd.to_path_buf());
    std::fs::canonicalize(&root).with_context(|| format!("canonicalize {}", root.display()))
}

fn account(project_root: &Path, key: &str) -> String {
    let project = project_root.to_string_lossy().replace('\\', "/");
    format!("{project}::{key}")
}

fn index_account(project_root: &Path) -> String {
    account(project_root, DOTENVX_INDEX_KEY)
}

fn read_index(store: &impl SecretStore, project_root: &Path) -> Result<BTreeSet<String>> {
    let Some(raw) = store.get(&index_account(project_root))? else {
        return Ok(BTreeSet::new());
    };
    let index: KeyIndex = serde_json::from_str(&raw).context("parse dotenvx key index")?;
    Ok(index.keys.into_iter().collect())
}

fn write_index(
    store: &impl SecretStore,
    project_root: &Path,
    index: &BTreeSet<String>,
) -> Result<()> {
    if index.is_empty() {
        store.delete(&index_account(project_root))?;
        return Ok(());
    }
    let body = serde_json::to_string(&KeyIndex {
        keys: index.iter().cloned().collect(),
    })?;
    store.put(&index_account(project_root), &body)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct MockSecretStore {
        entries: RefCell<BTreeMap<String, String>>,
    }

    impl SecretStore for MockSecretStore {
        fn put(&self, account: &str, value: &str) -> Result<()> {
            self.entries
                .borrow_mut()
                .insert(account.to_string(), value.to_string());
            Ok(())
        }

        fn get(&self, account: &str) -> Result<Option<String>> {
            Ok(self.entries.borrow().get(account).cloned())
        }

        fn delete(&self, account: &str) -> Result<()> {
            self.entries.borrow_mut().remove(account);
            Ok(())
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
    fn account_normalizes_windows_path_separators() {
        assert_eq!(
            account(
                Path::new(r"C:\Users\alice\repo"),
                "DOTENV_PRIVATE_KEY_PRODUCTION"
            ),
            "C:/Users/alice/repo::DOTENV_PRIVATE_KEY_PRODUCTION"
        );
    }

    #[test]
    fn import_and_delete_update_store_index() {
        let store = MockSecretStore::default();
        let root = Path::new("/repo/app");
        dotenvx_import_keys_with_store(
            &store,
            root,
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
            store.get(&account(root, "DOTENV_PRIVATE_KEY")).unwrap(),
            Some("dotenvx-default-value".to_string())
        );
        assert_eq!(
            read_index(&store, root).unwrap(),
            BTreeSet::from([
                "DOTENV_PRIVATE_KEY".to_string(),
                "DOTENV_PRIVATE_KEY_PRODUCTION".to_string()
            ])
        );

        dotenvx_delete_with_store(
            &store,
            root,
            DotenvxDeleteArgs {
                all: false,
                key: None,
                env: Some("production".to_string()),
            },
        )
        .unwrap();

        assert_eq!(
            store
                .get(&account(root, "DOTENV_PRIVATE_KEY_PRODUCTION"))
                .unwrap(),
            None
        );
        assert_eq!(
            read_index(&store, root).unwrap(),
            BTreeSet::from(["DOTENV_PRIVATE_KEY".to_string()])
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
}
