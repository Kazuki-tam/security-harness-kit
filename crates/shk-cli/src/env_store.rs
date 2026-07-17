use crate::audit_log;
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use shk_core::policy::Policy;
use std::collections::BTreeSet;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use tempfile::NamedTempFile;

const DOTENVX_SERVICE: &str = "security-harness-kit/dotenvx";
const DOTENVX_INDEX_KEY: &str = "__index";
const SHK_ENV_SERVICE: &str = "security-harness-kit/env";
const SHK_OP_PATH_ENV: &str = "SHK_OP_PATH";
const MIN_OP_VERSION: &str = "2.24.0";
const OP_TAG: &str = "shk";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreKind {
    NativeEnv,
    Dotenvx,
}

impl StoreKind {
    fn segment(self) -> &'static str {
        match self {
            Self::NativeEnv => "env",
            Self::Dotenvx => "dotenvx",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretStoreBackend {
    Keyring,
    OnePassword,
}

impl SecretStoreBackend {
    pub fn as_config_value(self) -> &'static str {
        match self {
            Self::Keyring => "keyring",
            Self::OnePassword => "1password",
        }
    }
}

pub fn parse_secret_store_backend(raw: &str) -> Result<SecretStoreBackend> {
    match raw {
        "keyring" => Ok(SecretStoreBackend::Keyring),
        "1password" => Ok(SecretStoreBackend::OnePassword),
        other => bail!("unsupported secret store backend `{other}`; supported: keyring, 1password"),
    }
}

#[derive(Clone, Debug)]
pub struct ProjectIdentity {
    pub root: PathBuf,
    pub project_id: Option<String>,
}

impl ProjectIdentity {
    pub fn from_root_and_policy(root: PathBuf, policy: &Policy) -> Self {
        Self {
            root,
            project_id: policy.env.project_id.clone(),
        }
    }

    fn require_project_id(&self) -> Result<&str> {
        self.project_id
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| anyhow!("env.project_id is required for the 1Password secret store"))
    }
}

pub trait SecretStore: Send + Sync {
    fn put(&self, project: &ProjectIdentity, key: &str, value: &str) -> Result<()>;
    fn get(&self, project: &ProjectIdentity, key: &str) -> Result<Option<String>>;
    fn delete(&self, project: &ProjectIdentity, key: &str) -> Result<()>;
    fn list_keys(&self, project: &ProjectIdentity) -> Result<BTreeSet<String>>;
}

pub struct EnvStores {
    pub native: Box<dyn SecretStore>,
    pub dotenvx: Box<dyn SecretStore>,
    pub backend: SecretStoreBackend,
}

pub fn open_env_stores(project: &ProjectIdentity, policy: &Policy) -> Result<EnvStores> {
    policy.validate_env_config(&project.root)?;
    let backend = parse_secret_store_backend(&policy.env.secret_store)?;
    Ok(EnvStores {
        native: open_store(StoreKind::NativeEnv, backend, project, policy)?,
        dotenvx: open_store(StoreKind::Dotenvx, backend, project, policy)?,
        backend,
    })
}

fn open_store(
    kind: StoreKind,
    backend: SecretStoreBackend,
    project: &ProjectIdentity,
    policy: &Policy,
) -> Result<Box<dyn SecretStore>> {
    match backend {
        SecretStoreBackend::Keyring => Ok(Box::new(KeyringSecretStore::new(kind))),
        SecretStoreBackend::OnePassword => {
            let vault = policy
                .env
                .onepassword
                .vault
                .clone()
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| anyhow!("env.onepassword.vault is required"))?;
            let op_path = resolve_op_path()?;
            Ok(Box::new(OnePasswordSecretStore::new(
                kind,
                op_path,
                vault,
                project.root.clone(),
            )?))
        }
    }
}

pub fn is_secret_store_unavailable(err: &anyhow::Error) -> bool {
    err.chain().any(|source| {
        source.downcast_ref::<keyring::Error>().is_some_and(|err| {
            matches!(
                err,
                keyring::Error::PlatformFailure(_) | keyring::Error::NoStorageAccess(_)
            )
        }) || source
            .downcast_ref::<OnePasswordError>()
            .is_some_and(|err| err.unavailable)
    })
}

#[derive(Debug)]
struct OnePasswordError {
    unavailable: bool,
    message: String,
}

impl std::fmt::Display for OnePasswordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for OnePasswordError {}

#[derive(Debug, Deserialize, Serialize)]
struct KeyIndex {
    keys: Vec<String>,
}

struct KeyringSecretStore {
    service: &'static str,
}

impl KeyringSecretStore {
    fn new(kind: StoreKind) -> Self {
        let service = match kind {
            StoreKind::NativeEnv => SHK_ENV_SERVICE,
            StoreKind::Dotenvx => DOTENVX_SERVICE,
        };
        Self { service }
    }

    pub(crate) fn account(project: &ProjectIdentity, key: &str) -> String {
        let project = project.root.to_string_lossy().replace('\\', "/");
        format!("{project}::{key}")
    }

    fn index_account(project: &ProjectIdentity) -> String {
        Self::account(project, DOTENVX_INDEX_KEY)
    }

    fn read_index(&self, project: &ProjectIdentity) -> Result<BTreeSet<String>> {
        let Some(raw) = self.get_raw(&Self::index_account(project))? else {
            return Ok(BTreeSet::new());
        };
        let index: KeyIndex = serde_json::from_str(&raw).context("parse secret store key index")?;
        Ok(index.keys.into_iter().collect())
    }

    fn write_index(&self, project: &ProjectIdentity, index: &BTreeSet<String>) -> Result<()> {
        if index.is_empty() {
            return self.delete_raw(&Self::index_account(project));
        }
        let body = serde_json::to_string(&KeyIndex {
            keys: index.iter().cloned().collect(),
        })?;
        self.put_raw(&Self::index_account(project), &body)
    }

    fn put_raw(&self, account: &str, value: &str) -> Result<()> {
        keyring::Entry::new(self.service, account)?
            .set_password(value)
            .map_err(Into::into)
    }

    fn get_raw(&self, account: &str) -> Result<Option<String>> {
        match keyring::Entry::new(self.service, account)?.get_password() {
            Ok(value) => Ok(Some(value)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    fn delete_raw(&self, account: &str) -> Result<()> {
        match keyring::Entry::new(self.service, account)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }
}

impl SecretStore for KeyringSecretStore {
    fn put(&self, project: &ProjectIdentity, key: &str, value: &str) -> Result<()> {
        self.put_raw(&Self::account(project, key), value)
            .with_context(|| format!("store {key} in OS credential store"))?;
        if key != DOTENVX_INDEX_KEY {
            let mut index = self.read_index(project)?;
            index.insert(key.to_string());
            self.write_index(project, &index)?;
        }
        Ok(())
    }

    fn get(&self, project: &ProjectIdentity, key: &str) -> Result<Option<String>> {
        self.get_raw(&Self::account(project, key))
    }

    fn delete(&self, project: &ProjectIdentity, key: &str) -> Result<()> {
        self.delete_raw(&Self::account(project, key))
            .with_context(|| format!("delete {key} from OS credential store"))?;
        if key != DOTENVX_INDEX_KEY {
            let mut index = self.read_index(project)?;
            index.remove(key);
            self.write_index(project, &index)?;
        }
        Ok(())
    }

    fn list_keys(&self, project: &ProjectIdentity) -> Result<BTreeSet<String>> {
        self.read_index(project)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpPathSource {
    EnvVar,
    KnownPath,
    PathSearch,
}

impl OpPathSource {
    pub fn label(self) -> &'static str {
        match self {
            Self::EnvVar => "SHK_OP_PATH",
            Self::KnownPath => "known install path",
            Self::PathSearch => "PATH (warning: susceptible to hijacking)",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ResolvedOpPath {
    pub path: PathBuf,
    pub source: OpPathSource,
}

pub fn resolve_op_path() -> Result<ResolvedOpPath> {
    if let Ok(raw) = std::env::var(SHK_OP_PATH_ENV) {
        let path = PathBuf::from(raw.trim());
        validate_op_binary(&path)?;
        return Ok(ResolvedOpPath {
            path,
            source: OpPathSource::EnvVar,
        });
    }

    for candidate in known_op_paths() {
        if candidate.is_file() {
            validate_op_binary(&candidate)?;
            return Ok(ResolvedOpPath {
                path: candidate,
                source: OpPathSource::KnownPath,
            });
        }
    }

    if let Some(path) = find_op_on_path()? {
        validate_op_binary(&path)?;
        return Ok(ResolvedOpPath {
            path,
            source: OpPathSource::PathSearch,
        });
    }

    bail!(
        "1Password CLI (`op`) not found; install it, add it to PATH, or set {SHK_OP_PATH_ENV} to an absolute path"
    )
}

fn known_op_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    #[cfg(target_os = "macos")]
    {
        paths.push(PathBuf::from("/opt/homebrew/bin/op"));
        paths.push(PathBuf::from("/usr/local/bin/op"));
    }
    #[cfg(target_os = "linux")]
    {
        paths.push(PathBuf::from("/usr/local/bin/op"));
        paths.push(PathBuf::from("/usr/bin/op"));
    }
    #[cfg(target_os = "windows")]
    {
        paths.push(PathBuf::from(r"C:\Program Files\1Password CLI\op.exe"));
        paths.push(PathBuf::from(r"C:\Program Files\1Password\op.exe"));
    }
    paths
}

fn find_op_on_path() -> Result<Option<PathBuf>> {
    let path_var = std::env::var_os("PATH").ok_or_else(|| anyhow!("PATH is not set"))?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(if cfg!(windows) { "op.exe" } else { "op" });
        if candidate.is_file() {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

fn validate_op_binary(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("{SHK_OP_PATH_ENV} must be an absolute path to the 1Password CLI binary");
    }
    if !path.is_file() {
        bail!("1Password CLI binary not found at {}", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata =
            std::fs::metadata(path).with_context(|| format!("inspect {}", path.display()))?;
        if metadata.permissions().mode() & 0o002 != 0 {
            bail!(
                "refusing to execute world-writable 1Password CLI binary at {}",
                path.display()
            );
        }
    }
    Ok(())
}

trait OpRunner: Send + Sync {
    fn run(&self, op_path: &Path, args: &[&str]) -> Result<Output>;
}

struct ProcessOpRunner;

impl OpRunner for ProcessOpRunner {
    fn run(&self, op_path: &Path, args: &[&str]) -> Result<Output> {
        let output = Command::new(op_path)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .with_context(|| format!("run `{}`", command_line(op_path, args)))?;
        Ok(output)
    }
}

struct OnePasswordSecretStore {
    kind: StoreKind,
    op_path: PathBuf,
    vault: String,
    repo_root: PathBuf,
    runner: Box<dyn OpRunner>,
}

impl OnePasswordSecretStore {
    fn new(
        kind: StoreKind,
        resolved: ResolvedOpPath,
        vault: String,
        repo_root: PathBuf,
    ) -> Result<Self> {
        let store = Self {
            kind,
            op_path: resolved.path,
            vault,
            repo_root,
            runner: Box::new(ProcessOpRunner),
        };
        store.ensure_op_version()?;
        Ok(store)
    }

    #[cfg(test)]
    fn with_runner(
        kind: StoreKind,
        op_path: PathBuf,
        vault: String,
        repo_root: PathBuf,
        runner: Box<dyn OpRunner>,
    ) -> Self {
        Self {
            kind,
            op_path,
            vault,
            repo_root,
            runner,
        }
    }

    fn title_prefix(&self, project: &ProjectIdentity) -> Result<String> {
        let project_id = project.require_project_id()?;
        Ok(format!("shk:{project_id}:{}:", self.kind.segment()))
    }

    fn item_title(&self, project: &ProjectIdentity, key: &str) -> Result<String> {
        Ok(format!("{}{key}", self.title_prefix(project)?))
    }

    fn ensure_op_version(&self) -> Result<()> {
        let output = self
            .runner
            .run(&self.op_path, &["--version"])
            .context("run `op --version`")?;
        if !output.status.success() {
            return Err(map_op_failure(&output, "check 1Password CLI version"));
        }
        let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !op_version_meets_minimum(&version, MIN_OP_VERSION) {
            bail!(
                "1Password CLI version {version} is older than supported minimum {MIN_OP_VERSION}"
            );
        }
        Ok(())
    }

    fn run_json(&self, args: &[&str]) -> Result<serde_json::Value> {
        let mut full_args = args.to_vec();
        full_args.push("--format");
        full_args.push("json");
        let output = self.runner.run(&self.op_path, &full_args)?;
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.trim().is_empty() {
                return Ok(serde_json::Value::Null);
            }
            return serde_json::from_str(stdout.trim())
                .with_context(|| format!("parse 1Password JSON from `{}`", args.join(" ")));
        }
        Err(map_op_failure(
            &output,
            &format!("run `{}`", args.join(" ")),
        ))
    }

    fn find_item_id(&self, title: &str) -> Result<Option<String>> {
        let value = self.run_json(&["item", "list", "--vault", &self.vault])?;
        let Some(items) = value.as_array() else {
            return Ok(None);
        };
        let mut matching_ids = Vec::new();
        for item in items {
            if item.get("title").and_then(|value| value.as_str()) != Some(title) {
                continue;
            }
            let id = item
                .get("id")
                .and_then(|value| value.as_str())
                .filter(|value| !value.is_empty())
                .ok_or_else(|| anyhow!("1Password item `{title}` has no item ID"))?;
            matching_ids.push(id.to_string());
        }
        match matching_ids.len() {
            0 => Ok(None),
            1 => Ok(matching_ids.pop()),
            count => bail!(
                "found {count} 1Password items named `{title}`; remove duplicates before continuing"
            ),
        }
    }

    fn put_item(&self, project: &ProjectIdentity, key: &str, value: &str) -> Result<()> {
        let title = self.item_title(project, key)?;
        let existing_id = self.find_item_id(&title)?;
        let template = serde_json::json!({
            "title": title,
            "tags": [OP_TAG],
            "category": "API_CREDENTIAL",
            "fields": [{
                "label": "credential",
                "type": "CONCEALED",
                "value": value,
            }],
        });
        let mut tmp = write_temp_json(&template)?;
        let template_path = tmp.path().to_string_lossy().to_string();
        let args = if let Some(id) = existing_id.as_deref() {
            vec![
                "item",
                "edit",
                id,
                "--vault",
                &self.vault,
                "--template",
                &template_path,
            ]
        } else {
            vec![
                "item",
                "create",
                "--vault",
                &self.vault,
                "--template",
                &template_path,
            ]
        };
        let action = if existing_id.is_some() {
            "update"
        } else {
            "create"
        };
        let result = self.runner.run(&self.op_path, &args);
        zero_temp_file(&mut tmp, template.to_string().len())?;
        let output = result?;
        if output.status.success() {
            return Ok(());
        }
        Err(map_op_failure(
            &output,
            &format!("{action} 1Password item `{title}`"),
        ))
    }

    fn get_item_value(&self, project: &ProjectIdentity, key: &str) -> Result<Option<String>> {
        let title = self.item_title(project, key)?;
        let Some(item_id) = self.find_item_id(&title)? else {
            return Ok(None);
        };
        let args = [
            "item",
            "get",
            &item_id,
            "--vault",
            &self.vault,
            "--fields",
            "label=credential",
            "--reveal",
        ];
        let output = self.runner.run(&self.op_path, &args)?;
        if output.status.success() {
            let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if value.is_empty() {
                return Ok(None);
            }
            let _ = audit_log::append_line(
                &self.repo_root,
                serde_json::json!({
                    "event": "env_secret_read",
                    "backend": "1password",
                    "store": self.kind.segment(),
                    "key": key,
                    "project_id": project.project_id,
                }),
            );
            return Ok(Some(value));
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        if is_op_not_found(&stderr) {
            return Ok(None);
        }
        Err(map_op_failure(
            &output,
            &format!("read 1Password item `{title}`"),
        ))
    }

    fn delete_item(&self, project: &ProjectIdentity, key: &str) -> Result<()> {
        let title = self.item_title(project, key)?;
        let Some(item_id) = self.find_item_id(&title)? else {
            return Ok(());
        };
        let args = ["item", "delete", &item_id, "--vault", &self.vault];
        let output = self.runner.run(&self.op_path, &args)?;
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        if is_op_not_found(&stderr) {
            return Ok(());
        }
        Err(map_op_failure(
            &output,
            &format!("delete 1Password item `{title}`"),
        ))
    }
}

impl SecretStore for OnePasswordSecretStore {
    fn put(&self, project: &ProjectIdentity, key: &str, value: &str) -> Result<()> {
        self.put_item(project, key, value)
            .with_context(|| format!("store {key} in 1Password vault {}", self.vault))
    }

    fn get(&self, project: &ProjectIdentity, key: &str) -> Result<Option<String>> {
        self.get_item_value(project, key)
    }

    fn delete(&self, project: &ProjectIdentity, key: &str) -> Result<()> {
        self.delete_item(project, key)
            .with_context(|| format!("delete {key} from 1Password vault {}", self.vault))
    }

    fn list_keys(&self, project: &ProjectIdentity) -> Result<BTreeSet<String>> {
        let prefix = self.title_prefix(project)?;
        let value = self.run_json(&["item", "list", "--tags", OP_TAG, "--vault", &self.vault])?;
        let Some(items) = value.as_array() else {
            return Ok(BTreeSet::new());
        };
        let mut keys = BTreeSet::new();
        for item in items {
            let Some(title) = item.get("title").and_then(|v| v.as_str()) else {
                continue;
            };
            if let Some(key) = title.strip_prefix(&prefix) {
                if !key.is_empty() {
                    keys.insert(key.to_string());
                }
            }
        }
        Ok(keys)
    }
}

pub fn collect_onepassword_doctor_status(policy: &Policy) -> Result<OnePasswordDoctorStatus> {
    let mut status = OnePasswordDoctorStatus {
        configured: policy.env.secret_store == "1password",
        ..Default::default()
    };
    if !status.configured {
        return Ok(status);
    }

    status.project_id_ok = policy
        .env
        .project_id
        .as_ref()
        .is_some_and(|value| !value.trim().is_empty());
    status.vault_ok = policy
        .env
        .onepassword
        .vault
        .as_ref()
        .is_some_and(|value| !value.trim().is_empty());

    match resolve_op_path() {
        Ok(resolved) => {
            status.op_path = Some(resolved.path.display().to_string());
            status.op_path_source = Some(resolved.source);
            let output = Command::new(&resolved.path)
                .arg("--version")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .context("run `op --version`")?;
            if output.status.success() {
                let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
                status.op_version = Some(version.clone());
                status.op_version_ok = op_version_meets_minimum(&version, MIN_OP_VERSION);
            } else {
                status.op_version_error =
                    Some(String::from_utf8_lossy(&output.stderr).trim().to_string());
            }

            let whoami = Command::new(&resolved.path)
                .args(["whoami"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .context("run `op whoami`")?;
            status.op_signed_in = whoami.status.success();
            if !status.op_signed_in {
                status.op_sign_in_error =
                    Some(String::from_utf8_lossy(&whoami.stderr).trim().to_string());
            }
        }
        Err(err) => status.op_resolution_error = Some(err.to_string()),
    }

    Ok(status)
}

#[derive(Clone, Debug, Default)]
pub struct OnePasswordDoctorStatus {
    pub configured: bool,
    pub project_id_ok: bool,
    pub vault_ok: bool,
    pub op_path: Option<String>,
    pub op_path_source: Option<OpPathSource>,
    pub op_version: Option<String>,
    pub op_version_ok: bool,
    pub op_version_error: Option<String>,
    pub op_signed_in: bool,
    pub op_sign_in_error: Option<String>,
    pub op_resolution_error: Option<String>,
}

fn write_temp_json(value: &serde_json::Value) -> Result<NamedTempFile> {
    let mut tmp = NamedTempFile::new().context("create temporary 1Password template file")?;
    let bytes = serde_json::to_vec(value).context("serialize 1Password template JSON")?;
    tmp.write_all(&bytes)
        .context("write temporary 1Password template file")?;
    tmp.flush()
        .context("flush temporary 1Password template file")?;
    Ok(tmp)
}

fn zero_temp_file(tmp: &mut NamedTempFile, len: usize) -> Result<()> {
    tmp.as_file_mut()
        .seek(SeekFrom::Start(0))
        .context("seek temporary secret payload file")?;
    tmp.write_all(&vec![0u8; len])
        .context("zero temporary secret payload file")?;
    tmp.flush()
        .context("flush zeroed temporary secret payload file")?;
    Ok(())
}

fn command_line(program: &Path, args: &[&str]) -> String {
    std::iter::once(program.display().to_string())
        .chain(args.iter().map(|arg| arg.to_string()))
        .collect::<Vec<_>>()
        .join(" ")
}

fn map_op_failure(output: &Output, action: &str) -> anyhow::Error {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let message = if stderr.is_empty() {
        format!("failed to {action}")
    } else {
        format!("failed to {action}: {stderr}")
    };
    let unavailable = stderr.contains("not currently signed in")
        || stderr.contains("account is locked")
        || stderr.contains("isn't unlocked")
        || stderr.contains("no account configured")
        || stderr.contains("connect to 1Password");
    OnePasswordError {
        unavailable,
        message,
    }
    .into()
}

fn is_op_not_found(stderr: &str) -> bool {
    stderr.contains("isn't an item in this vault")
        || stderr.contains("no item found")
        || stderr.contains("item not found")
}

pub(crate) fn op_version_meets_minimum(actual: &str, minimum: &str) -> bool {
    parse_op_version(actual) >= parse_op_version(minimum)
}

fn parse_op_version(raw: &str) -> Vec<u32> {
    raw.split(|ch: char| !ch.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .filter_map(|part| part.parse().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    #[cfg(unix)]
    use std::os::unix::process::ExitStatusExt;
    use std::sync::{Arc, Mutex};

    pub struct MockSecretStore {
        entries: Mutex<BTreeMap<String, String>>,
    }

    impl Default for MockSecretStore {
        fn default() -> Self {
            Self {
                entries: Mutex::new(BTreeMap::new()),
            }
        }
    }

    impl MockSecretStore {
        pub fn keyring() -> Self {
            Self::default()
        }

        pub fn insert_legacy_key(&self, project: &ProjectIdentity, key: &str, value: &str) {
            self.entries
                .lock()
                .unwrap()
                .insert(Self::account(project, key), value.to_string());
        }

        fn account(project: &ProjectIdentity, key: &str) -> String {
            KeyringSecretStore::account(project, key)
        }

        fn read_index(&self, project: &ProjectIdentity) -> BTreeSet<String> {
            let entries = self.entries.lock().unwrap();
            let Some(raw) = entries.get(&Self::account(project, DOTENVX_INDEX_KEY)) else {
                return BTreeSet::new();
            };
            serde_json::from_str::<KeyIndex>(raw)
                .map(|index| index.keys.into_iter().collect())
                .unwrap_or_default()
        }

        fn write_index(&self, project: &ProjectIdentity, index: &BTreeSet<String>) {
            if index.is_empty() {
                self.entries
                    .lock()
                    .unwrap()
                    .remove(&Self::account(project, DOTENVX_INDEX_KEY));
                return;
            }
            let body = serde_json::to_string(&KeyIndex {
                keys: index.iter().cloned().collect(),
            })
            .unwrap();
            self.entries
                .lock()
                .unwrap()
                .insert(Self::account(project, DOTENVX_INDEX_KEY), body);
        }
    }

    impl SecretStore for MockSecretStore {
        fn put(&self, project: &ProjectIdentity, key: &str, value: &str) -> Result<()> {
            self.entries
                .lock()
                .unwrap()
                .insert(Self::account(project, key), value.to_string());
            if key != DOTENVX_INDEX_KEY {
                let mut index = self.read_index(project);
                index.insert(key.to_string());
                self.write_index(project, &index);
            }
            Ok(())
        }

        fn get(&self, project: &ProjectIdentity, key: &str) -> Result<Option<String>> {
            Ok(self
                .entries
                .lock()
                .unwrap()
                .get(&Self::account(project, key))
                .cloned())
        }

        fn delete(&self, project: &ProjectIdentity, key: &str) -> Result<()> {
            self.entries
                .lock()
                .unwrap()
                .remove(&Self::account(project, key));
            if key != DOTENVX_INDEX_KEY {
                let mut index = self.read_index(project);
                index.remove(key);
                self.write_index(project, &index);
            }
            Ok(())
        }

        fn list_keys(&self, project: &ProjectIdentity) -> Result<BTreeSet<String>> {
            Ok(self.read_index(project))
        }
    }

    pub(crate) fn run_secret_store_contract<S: SecretStore>(store: &S, project: &ProjectIdentity) {
        assert!(store.list_keys(project).unwrap().is_empty());
        store.put(project, "DOTENV_PRIVATE_KEY", "value-a").unwrap();
        store
            .put(project, "DOTENV_PRIVATE_KEY_PRODUCTION", "value-b")
            .unwrap();
        assert_eq!(
            store.get(project, "DOTENV_PRIVATE_KEY").unwrap(),
            Some("value-a".to_string())
        );
        assert_eq!(
            store.list_keys(project).unwrap(),
            BTreeSet::from([
                "DOTENV_PRIVATE_KEY".to_string(),
                "DOTENV_PRIVATE_KEY_PRODUCTION".to_string()
            ])
        );
        store.delete(project, "DOTENV_PRIVATE_KEY").unwrap();
        assert!(store.get(project, "DOTENV_PRIVATE_KEY").unwrap().is_none());
        store.delete(project, "DOTENV_PRIVATE_KEY").unwrap();
        assert_eq!(
            store.list_keys(project).unwrap(),
            BTreeSet::from(["DOTENV_PRIVATE_KEY_PRODUCTION".to_string()])
        );
    }

    struct RecordingOpRunner {
        responses: Arc<Mutex<Vec<Result<Output, String>>>>,
        calls: Arc<Mutex<Vec<Vec<String>>>>,
    }

    impl RecordingOpRunner {
        fn new(responses: Vec<Result<Output, String>>) -> (Self, Arc<Mutex<Vec<Vec<String>>>>) {
            let calls = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    responses: Arc::new(Mutex::new(responses)),
                    calls: Arc::clone(&calls),
                },
                calls,
            )
        }
    }

    impl OpRunner for RecordingOpRunner {
        fn run(&self, _op_path: &Path, args: &[&str]) -> Result<Output> {
            self.calls
                .lock()
                .unwrap()
                .push(args.iter().map(|arg| (*arg).to_string()).collect());
            self.responses
                .lock()
                .unwrap()
                .remove(0)
                .map_err(|err| anyhow!(err))
        }
    }

    fn sample_project() -> ProjectIdentity {
        ProjectIdentity {
            root: PathBuf::from("/repo/app"),
            project_id: Some("acme/backend".to_string()),
        }
    }

    fn ok_output(body: &str) -> Output {
        Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: body.as_bytes().to_vec(),
            stderr: Vec::new(),
        }
    }

    #[test]
    fn mock_secret_store_contract() {
        let store = MockSecretStore::keyring();
        run_secret_store_contract(&store, &sample_project());
    }

    #[test]
    fn keyring_account_normalizes_windows_path_separators() {
        assert_eq!(
            KeyringSecretStore::account(
                &ProjectIdentity {
                    root: PathBuf::from(r"C:\Users\alice\repo"),
                    project_id: None,
                },
                "DOTENV_PRIVATE_KEY_PRODUCTION"
            ),
            "C:/Users/alice/repo::DOTENV_PRIVATE_KEY_PRODUCTION"
        );
    }

    #[test]
    fn op_version_meets_minimum_supports_prefixes() {
        assert!(op_version_meets_minimum("2.30.0-beta.01", "2.24.0"));
        assert!(!op_version_meets_minimum("2.20.0", "2.24.0"));
    }

    #[test]
    fn onepassword_get_rejects_generic_not_found_errors() {
        let (runner, _calls) = RecordingOpRunner::new(vec![
            Ok(ok_output(
                r#"[{"id":"item-id","title":"shk:acme/backend:env:DOTENV_PRIVATE_KEY"}]"#,
            )),
            Ok(Output {
                status: std::process::ExitStatus::from_raw(1),
                stdout: Vec::new(),
                stderr: b"vault not found".to_vec(),
            }),
        ]);
        let store = OnePasswordSecretStore::with_runner(
            StoreKind::NativeEnv,
            PathBuf::from("/usr/local/bin/op"),
            "vault".to_string(),
            PathBuf::from("/repo"),
            Box::new(runner),
        );
        assert!(store.get(&sample_project(), "DOTENV_PRIVATE_KEY").is_err());
    }

    #[test]
    fn onepassword_get_maps_not_found_to_none() {
        let (runner, _calls) = RecordingOpRunner::new(vec![
            Ok(ok_output(
                r#"[{"id":"item-id","title":"shk:acme/backend:env:DOTENV_PRIVATE_KEY"}]"#,
            )),
            Ok(Output {
                status: std::process::ExitStatus::from_raw(1),
                stdout: Vec::new(),
                stderr: b"item isn't an item in this vault".to_vec(),
            }),
        ]);
        let store = OnePasswordSecretStore::with_runner(
            StoreKind::NativeEnv,
            PathBuf::from("/usr/local/bin/op"),
            "vault".to_string(),
            PathBuf::from("/repo"),
            Box::new(runner),
        );
        assert!(
            store
                .get(&sample_project(), "DOTENV_PRIVATE_KEY")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn onepassword_put_does_not_place_value_in_argv() {
        let (runner, calls) =
            RecordingOpRunner::new(vec![Ok(ok_output("[]")), Ok(ok_output("{}"))]);
        let store = OnePasswordSecretStore::with_runner(
            StoreKind::NativeEnv,
            PathBuf::from("/usr/local/bin/op"),
            "vault".to_string(),
            PathBuf::from("/repo"),
            Box::new(runner),
        );
        store
            .put(&sample_project(), "DOTENV_PRIVATE_KEY", "demo-value")
            .unwrap();
        let recorded = calls.lock().unwrap();
        assert_eq!(recorded.len(), 2);
        assert!(
            recorded
                .iter()
                .all(|call| !call.join(" ").contains("demo-value"))
        );
        assert!(recorded[1].contains(&"--template".to_string()));
        assert_eq!(&recorded[1][..2], ["item", "create"]);
    }

    #[test]
    fn onepassword_put_edits_existing_item_by_id() {
        let (runner, calls) = RecordingOpRunner::new(vec![
            Ok(ok_output(
                r#"[{"id":"stable-item-id","title":"shk:acme/backend:env:DOTENV_PRIVATE_KEY"}]"#,
            )),
            Ok(ok_output("{}")),
        ]);
        let store = OnePasswordSecretStore::with_runner(
            StoreKind::NativeEnv,
            PathBuf::from("/usr/local/bin/op"),
            "vault".to_string(),
            PathBuf::from("/repo"),
            Box::new(runner),
        );
        store
            .put(&sample_project(), "DOTENV_PRIVATE_KEY", "demo-value")
            .unwrap();
        let recorded = calls.lock().unwrap();
        assert_eq!(&recorded[1][..3], ["item", "edit", "stable-item-id"]);
    }

    #[test]
    fn onepassword_put_rejects_duplicate_titles() {
        let (runner, _calls) = RecordingOpRunner::new(vec![Ok(ok_output(
            r#"[{"id":"item-a","title":"shk:acme/backend:env:DOTENV_PRIVATE_KEY"},{"id":"item-b","title":"shk:acme/backend:env:DOTENV_PRIVATE_KEY"}]"#,
        ))]);
        let store = OnePasswordSecretStore::with_runner(
            StoreKind::NativeEnv,
            PathBuf::from("/usr/local/bin/op"),
            "vault".to_string(),
            PathBuf::from("/repo"),
            Box::new(runner),
        );
        let err = store
            .put(&sample_project(), "DOTENV_PRIVATE_KEY", "demo-value")
            .unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("remove duplicates"), "{message}");
        assert!(!message.contains("demo-value"));
    }

    #[test]
    fn onepassword_list_keys_filters_by_project_prefix() {
        let (runner, _calls) = RecordingOpRunner::new(vec![Ok(ok_output(
            r#"[{"title":"shk:acme/backend:env:DOTENV_PRIVATE_KEY"},{"title":"shk:other:env:DOTENV_PRIVATE_KEY"}]"#,
        ))]);
        let store = OnePasswordSecretStore::with_runner(
            StoreKind::NativeEnv,
            PathBuf::from("/usr/local/bin/op"),
            "vault".to_string(),
            PathBuf::from("/repo"),
            Box::new(runner),
        );
        assert_eq!(
            store.list_keys(&sample_project()).unwrap(),
            BTreeSet::from(["DOTENV_PRIVATE_KEY".to_string()])
        );
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    pub use super::tests::MockSecretStore;
}
