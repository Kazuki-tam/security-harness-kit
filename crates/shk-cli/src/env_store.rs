use crate::audit_log;
use anyhow::{Context, Result, anyhow, bail};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shk_core::policy::Policy;
use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};
use wait_timeout::ChildExt;
use zeroize::{Zeroize, Zeroizing};

const DOTENVX_SERVICE: &str = "security-harness-kit/dotenvx";
const DOTENVX_INDEX_KEY: &str = "__index";
const KEYRING_TRANSACTION_KEY: &str = "__transaction_v1";
const SHK_ENV_SERVICE: &str = "security-harness-kit/env";
const SHK_OP_PATH_ENV: &str = "SHK_OP_PATH";
const MIN_OP_VERSION: &str = "2.24.0";
const OP_TAG: &str = "shk";
const OP_CATEGORY: &str = "API_CREDENTIAL";
const OP_CONFLICT_RETRY_DELAYS: &[Duration] =
    &[Duration::from_millis(250), Duration::from_millis(750)];
const OP_SPAWN_RETRY_DELAYS: &[Duration] = &[Duration::from_millis(10), Duration::from_millis(25)];
const OP_DOCTOR_TIMEOUT: Duration = Duration::from_secs(5);
const OP_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const SECRET_STORE_LOCK_TIMEOUT: Duration = Duration::from_secs(10);

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

pub fn with_secret_store_lock<T>(
    project: &ProjectIdentity,
    purpose: &str,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let cache_dir = secret_store_cache_dir();
    let lock_dir = secure_lock_directory(&cache_dir)?;
    let lock_path = secret_store_lock_path(&lock_dir, project, purpose);
    let mut file = open_lock_file(&lock_path)?;

    let deadline = Instant::now() + SECRET_STORE_LOCK_TIMEOUT;
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => break,
            Err(err) if is_lock_contention(&err) => {
                if Instant::now() >= deadline {
                    let holder = lock_holder_label(&mut file).unwrap_or_default();
                    bail!(
                        "timed out waiting {} seconds for secret store operation `{purpose}`{holder}",
                        SECRET_STORE_LOCK_TIMEOUT.as_secs()
                    );
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("lock secret store operation `{purpose}`"));
            }
        }
    }
    file.set_len(0)
        .with_context(|| format!("reset secret store lock {}", lock_path.display()))?;
    write!(file, "pid={}", std::process::id())
        .with_context(|| format!("record secret store lock holder {}", lock_path.display()))?;
    file.flush()
        .with_context(|| format!("flush secret store lock {}", lock_path.display()))?;
    let result = operation();
    let unlock_result = FileExt::unlock(&file)
        .with_context(|| format!("unlock secret store operation `{purpose}`"));
    match (result, unlock_result) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(err)) | (Err(err), _) => Err(err),
    }
}

fn secret_store_lock_path(lock_dir: &Path, project: &ProjectIdentity, purpose: &str) -> PathBuf {
    let root = std::fs::canonicalize(&project.root).unwrap_or_else(|_| project.root.clone());
    let mut hasher = Sha256::new();
    hasher.update(root.to_string_lossy().as_bytes());
    hasher.update(b"\0");
    hasher.update(purpose.as_bytes());
    let digest = hasher.finalize();
    let lock_name = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    lock_dir.join(format!("{lock_name}.lock"))
}

fn is_lock_contention(err: &std::io::Error) -> bool {
    if err.kind() == std::io::ErrorKind::WouldBlock {
        return true;
    }
    #[cfg(windows)]
    {
        // Windows reports a competing byte-range lock as ERROR_LOCK_VIOLATION,
        // which Rust does not consistently normalize to WouldBlock.
        err.raw_os_error() == Some(33)
    }
    #[cfg(not(windows))]
    false
}

fn lock_holder_label(file: &mut std::fs::File) -> Option<String> {
    file.seek(SeekFrom::Start(0)).ok()?;
    let mut value = String::new();
    file.take(64).read_to_string(&mut value).ok()?;
    let pid = value.trim().strip_prefix("pid=")?;
    if pid.is_empty() || !pid.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(format!("; lock holder pid={pid}"))
}

fn secret_store_cache_dir() -> PathBuf {
    #[cfg(test)]
    {
        let directory = std::env::temp_dir().join(format!("shk-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&directory);
        directory
    }
    #[cfg(not(test))]
    {
        dirs::cache_dir().unwrap_or_else(std::env::temp_dir)
    }
}

fn secure_lock_directory(cache_dir: &Path) -> Result<PathBuf> {
    std::fs::create_dir_all(cache_dir)
        .with_context(|| format!("create cache directory {}", cache_dir.display()))?;
    let shk_dir = cache_dir.join("shk");
    let lock_dir = shk_dir.join("locks");
    for directory in [&shk_dir, &lock_dir] {
        match std::fs::create_dir(directory) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("create secret store lock directory {}", directory.display())
                });
            }
        }
        let metadata = std::fs::symlink_metadata(directory).with_context(|| {
            format!(
                "inspect secret store lock directory {}",
                directory.display()
            )
        })?;
        if metadata.file_type().is_symlink() {
            bail!(
                "refusing symlinked secret store lock directory {}",
                directory.display()
            );
        }
        if !metadata.is_dir() {
            bail!(
                "secret store lock path is not a directory: {}",
                directory.display()
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let directory_file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
                .open(directory)
                .with_context(|| {
                    format!("open secret store lock directory {}", directory.display())
                })?;
            directory_file
                .set_permissions(std::fs::Permissions::from_mode(0o700))
                .with_context(|| {
                    format!("secure secret store lock directory {}", directory.display())
                })?;
        }
    }
    Ok(lock_dir)
}

fn open_lock_file(path: &Path) -> Result<std::fs::File> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .with_context(|| format!("open secret store lock {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect secret store lock {}", path.display()))?;
    if !metadata.is_file() {
        bail!(
            "secret store lock is not a regular file: {}",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.nlink() != 1 {
            bail!(
                "refusing multiply-linked secret store lock {}",
                path.display()
            );
        }
        // SAFETY: `geteuid` has no preconditions and does not dereference pointers.
        if metadata.uid() != unsafe { libc::geteuid() } {
            bail!(
                "secret store lock is not owned by this user: {}",
                path.display()
            );
        }
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("secure secret store lock {}", path.display()))?;
    }
    Ok(file)
}

pub trait SecretStore: Send + Sync {
    fn put(&self, project: &ProjectIdentity, key: &str, value: &str) -> Result<()>;
    fn get(&self, project: &ProjectIdentity, key: &str) -> Result<Option<String>>;
    fn delete(&self, project: &ProjectIdentity, key: &str) -> Result<()>;
    fn list_keys(&self, project: &ProjectIdentity) -> Result<BTreeSet<String>>;
    fn delete_if_value(
        &self,
        _project: &ProjectIdentity,
        _key: &str,
        _expected: &str,
    ) -> Result<bool> {
        Ok(false)
    }
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

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum KeyringTransactionOperation {
    Put,
    Delete,
}

#[derive(Debug, Deserialize, Serialize)]
struct KeyringTransaction {
    operation: KeyringTransactionOperation,
    key: String,
    value: Option<String>,
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

    fn transaction_account(project: &ProjectIdentity) -> String {
        Self::account(project, KEYRING_TRANSACTION_KEY)
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

    fn write_transaction(
        &self,
        project: &ProjectIdentity,
        transaction: &KeyringTransaction,
    ) -> Result<()> {
        let mut body =
            serde_json::to_string(transaction).context("serialize keyring transaction")?;
        let result = self
            .put_raw(&Self::transaction_account(project), &body)
            .context("write keyring transaction journal");
        body.zeroize();
        result
    }

    fn recover_transaction(&self, project: &ProjectIdentity) -> Result<()> {
        let Some(raw) = self.get_raw(&Self::transaction_account(project))? else {
            return Ok(());
        };
        let raw = Zeroizing::new(raw);
        let mut transaction = match serde_json::from_str::<KeyringTransaction>(&raw) {
            Ok(transaction) => transaction,
            Err(err) => {
                eprintln!(
                    "warning: ignoring corrupt keyring transaction journal for {}: {err}",
                    project.root.display()
                );
                return self
                    .delete_raw(&Self::transaction_account(project))
                    .context("clear corrupt keyring transaction journal");
            }
        };
        let result = self.apply_transaction(project, &mut transaction);
        if let Some(value) = transaction.value.as_mut() {
            value.zeroize();
        }
        result
    }

    fn recover_transaction_before_read(&self, project: &ProjectIdentity) -> Result<()> {
        // Keep the normal read path read-only. If a journal is visible, take
        // the same lock as writers and replay it before observing the value or
        // index. A writer that starts after the journal check linearizes after
        // this read, so no lock is needed when the journal is absent.
        if self.get_raw(&Self::transaction_account(project))?.is_some() {
            with_secret_store_lock(project, self.service, || self.recover_transaction(project))?;
        }
        Ok(())
    }

    fn apply_transaction(
        &self,
        project: &ProjectIdentity,
        transaction: &mut KeyringTransaction,
    ) -> Result<()> {
        let account = Self::account(project, &transaction.key);
        let mut index = self.read_index(project)?;
        match transaction.operation {
            KeyringTransactionOperation::Put => {
                let value = transaction
                    .value
                    .as_deref()
                    .ok_or_else(|| anyhow!("keyring put transaction has no value"))?;
                self.put_raw(&account, value)
                    .with_context(|| format!("store {} in OS credential store", transaction.key))?;
                index.insert(transaction.key.clone());
            }
            KeyringTransactionOperation::Delete => {
                self.delete_raw(&account).with_context(|| {
                    format!("delete {} from OS credential store", transaction.key)
                })?;
                index.remove(&transaction.key);
            }
        }
        self.write_index(project, &index)
            .context("update keyring index during transaction")?;
        self.delete_raw(&Self::transaction_account(project))
            .context("clear keyring transaction journal")
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
        if key == DOTENVX_INDEX_KEY {
            return self.put_raw(&Self::account(project, key), value);
        }
        with_secret_store_lock(project, self.service, || {
            self.recover_transaction(project)?;
            let mut transaction = KeyringTransaction {
                operation: KeyringTransactionOperation::Put,
                key: key.to_string(),
                value: Some(value.to_string()),
            };
            self.write_transaction(project, &transaction)?;
            let result = self.apply_transaction(project, &mut transaction);
            if let Some(value) = transaction.value.as_mut() {
                value.zeroize();
            }
            result
        })
    }

    fn get(&self, project: &ProjectIdentity, key: &str) -> Result<Option<String>> {
        self.recover_transaction_before_read(project)?;
        self.get_raw(&Self::account(project, key))
    }

    fn delete(&self, project: &ProjectIdentity, key: &str) -> Result<()> {
        if key == DOTENVX_INDEX_KEY {
            return self.delete_raw(&Self::account(project, key));
        }
        with_secret_store_lock(project, self.service, || {
            self.recover_transaction(project)?;
            let mut transaction = KeyringTransaction {
                operation: KeyringTransactionOperation::Delete,
                key: key.to_string(),
                value: None,
            };
            self.write_transaction(project, &transaction)?;
            self.apply_transaction(project, &mut transaction)
        })
    }

    fn list_keys(&self, project: &ProjectIdentity) -> Result<BTreeSet<String>> {
        self.recover_transaction_before_read(project)?;
        self.read_index(project)
    }

    fn delete_if_value(
        &self,
        project: &ProjectIdentity,
        key: &str,
        expected: &str,
    ) -> Result<bool> {
        with_secret_store_lock(project, self.service, || {
            self.recover_transaction(project)?;
            let Some(current) = self.get_raw(&Self::account(project, key))? else {
                return Ok(true);
            };
            let current = Zeroizing::new(current);
            if current.as_str() != expected {
                return Ok(false);
            }
            let mut transaction = KeyringTransaction {
                operation: KeyringTransactionOperation::Delete,
                key: key.to_string(),
                value: None,
            };
            self.write_transaction(project, &transaction)?;
            self.apply_transaction(project, &mut transaction)?;
            Ok(true)
        })
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
    if let Some(path) = configured_op_path(std::env::var(SHK_OP_PATH_ENV).ok().as_deref()) {
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

fn configured_op_path(raw: Option<&str>) -> Option<PathBuf> {
    raw.map(str::trim)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
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
        if metadata.permissions().mode() & 0o111 == 0 {
            bail!(
                "1Password CLI binary is not executable at {}",
                path.display()
            );
        }
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
    fn run_with_stdin(&self, op_path: &Path, args: &[&str], input: &[u8]) -> Result<Output>;

    fn wait_before_retry(&self, _delay: Duration) {}
}

struct ProcessOpRunner;

impl OpRunner for ProcessOpRunner {
    fn run(&self, op_path: &Path, args: &[&str]) -> Result<Output> {
        run_op_process_with_timeout(op_path, args, None, OP_COMMAND_TIMEOUT)
    }

    fn run_with_stdin(&self, op_path: &Path, args: &[&str], input: &[u8]) -> Result<Output> {
        run_op_process_with_timeout(op_path, args, Some(input), OP_COMMAND_TIMEOUT)
    }

    fn wait_before_retry(&self, delay: Duration) {
        std::thread::sleep(delay);
    }
}

fn run_op_process_with_timeout(
    op_path: &Path,
    args: &[&str],
    input: Option<&[u8]>,
    timeout: Duration,
) -> Result<Output> {
    let command = command_line(op_path, args);
    let mut process = Command::new(op_path);
    process
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut retry = 0;
    let mut child = loop {
        match process.spawn() {
            Ok(child) => break child,
            Err(err) if is_transient_exec_busy(&err) && retry < OP_SPAWN_RETRY_DELAYS.len() => {
                std::thread::sleep(OP_SPAWN_RETRY_DELAYS[retry]);
                retry += 1;
            }
            Err(err) => return Err(err).with_context(|| format!("run `{command}`")),
        }
    };
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("capture stdout for `{command}`"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("capture stderr for `{command}`"))?;
    let stdout_reader = std::thread::spawn(move || {
        let mut output = Vec::new();
        stdout.read_to_end(&mut output)?;
        Ok::<_, std::io::Error>(output)
    });
    let stderr_reader = std::thread::spawn(move || {
        let mut output = Vec::new();
        stderr.read_to_end(&mut output)?;
        Ok::<_, std::io::Error>(output)
    });
    let writer = if let Some(input) = input {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("open stdin for `{command}`"))?;
        let input = Zeroizing::new(input.to_vec());
        Some(std::thread::spawn(move || stdin.write_all(&input)))
    } else {
        None
    };

    let status = if let Some(status) = child
        .wait_timeout(timeout)
        .with_context(|| format!("wait for `{command}`"))?
    {
        status
    } else {
        let _ = child.kill();
        let _ = child.wait();
        if let Some(writer) = writer {
            let _ = writer.join();
        }
        let mut stdout = stdout_reader
            .join()
            .ok()
            .and_then(Result::ok)
            .unwrap_or_default();
        let mut stderr = stderr_reader
            .join()
            .ok()
            .and_then(Result::ok)
            .unwrap_or_default();
        stdout.zeroize();
        stderr.zeroize();
        bail!(
            "`{command}` timed out after {} seconds",
            timeout.as_secs_f64()
        );
    };
    if let Some(writer) = writer {
        let write_result = writer
            .join()
            .map_err(|_| anyhow!("stdin writer panicked for `{command}`"))?;
        if let Err(err) = write_result
            && !(status.success() && err.kind() == std::io::ErrorKind::BrokenPipe)
        {
            return Err(err).with_context(|| format!("write stdin for `{command}`"));
        }
    }
    let stdout = stdout_reader
        .join()
        .map_err(|_| anyhow!("stdout reader panicked for `{command}`"))?
        .with_context(|| format!("read stdout from `{command}`"))?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| anyhow!("stderr reader panicked for `{command}`"))?
        .with_context(|| format!("read stderr from `{command}`"))?;
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

fn is_transient_exec_busy(err: &std::io::Error) -> bool {
    #[cfg(unix)]
    {
        err.raw_os_error() == Some(libc::ETXTBSY)
    }
    #[cfg(not(unix))]
    {
        let _ = err;
        false
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
    fn lock_purpose(&self, key: &str) -> String {
        format!("1password:{}:{}:{key}", self.vault, self.kind.segment())
    }

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
        let mut matching_ids = self.find_item_ids(title)?;
        match matching_ids.len() {
            0 => Ok(None),
            1 => Ok(matching_ids.pop()),
            count => bail!(
                "found {count} 1Password items named `{title}`; remove duplicates before continuing"
            ),
        }
    }

    fn find_item_ids(&self, title: &str) -> Result<Vec<String>> {
        let value = self.run_json(&["item", "list", "--tags", OP_TAG, "--vault", &self.vault])?;
        let Some(items) = value.as_array() else {
            return Ok(Vec::new());
        };
        let mut matching_ids = Vec::new();
        for item in items {
            if item.get("title").and_then(|value| value.as_str()) != Some(title) {
                continue;
            }
            // Items without the shk-managed category are treated as unmanaged and never
            // read, edited, or deleted, even when the tag and title match.
            if !is_managed_op_item(item) {
                continue;
            }
            let id = item
                .get("id")
                .and_then(|value| value.as_str())
                .filter(|value| !value.is_empty())
                .ok_or_else(|| anyhow!("1Password item `{title}` has no item ID"))?;
            matching_ids.push(id.to_string());
        }
        Ok(matching_ids)
    }

    fn put_item(&self, project: &ProjectIdentity, key: &str, value: &str) -> Result<()> {
        let title = self.item_title(project, key)?;
        let existing_id = self.find_item_id(&title)?;
        let template_json = if let Some(id) = existing_id.as_deref() {
            // `op item edit` expects an existing item's complete JSON when a
            // template is piped on stdin. Preserve the server-assigned field
            // IDs and update only the managed credential value.
            let mut item = self.get_item_json(id, &title)?.ok_or_else(|| {
                anyhow!("1Password item `{title}` disappeared while it was being updated")
            })?;
            let credential_index = item
                .get("fields")
                .and_then(serde_json::Value::as_array)
                .and_then(|fields| {
                    fields.iter().position(|field| {
                        field.get("label").and_then(serde_json::Value::as_str) == Some("credential")
                    })
                });
            let Some(credential_index) = credential_index else {
                zeroize_json_strings(&mut item);
                bail!("1Password item `{title}` is corrupt: credential field is missing");
            };
            item["fields"][credential_index]["value"] =
                serde_json::Value::String(value.to_string());
            let serialized = serde_json::to_vec(&item).context("serialize 1Password item JSON");
            zeroize_json_strings(&mut item);
            Zeroizing::new(serialized?)
        } else {
            let template = OnePasswordItemTemplate {
                title: &title,
                tags: [OP_TAG],
                category: OP_CATEGORY,
                fields: [OnePasswordItemField {
                    label: "credential",
                    field_type: "CONCEALED",
                    value,
                }],
            };
            Zeroizing::new(serde_json::to_vec(&template).context("serialize 1Password item JSON")?)
        };
        let args = if let Some(id) = existing_id.as_deref() {
            vec!["item", "edit", id, "--vault", &self.vault]
        } else {
            vec![
                "item",
                "create",
                "-",
                "--vault",
                &self.vault,
                "--format",
                "json",
            ]
        };
        let action = if existing_id.is_some() {
            "update"
        } else {
            "create"
        };
        let mut output = self
            .runner
            .run_with_stdin(&self.op_path, &args, &template_json)?;
        if !output.status.success() {
            output.stdout.zeroize();
            return Err(map_op_failure(
                &output,
                &format!("{action} 1Password item `{title}`"),
            ));
        }
        if existing_id.is_some() {
            output.stdout.zeroize();
            let stored = self.get_item_value(project, key)?;
            match stored {
                Some(current) if current == value => return Ok(()),
                Some(_) => bail!(
                    "1Password item `{title}` was not updated to the expected value; retry the command"
                ),
                None => {
                    bail!("1Password item `{title}` disappeared after update; retry the command")
                }
            }
        }

        let created = serde_json::from_slice::<serde_json::Value>(&output.stdout)
            .context("parse created 1Password item JSON");
        output.stdout.zeroize();
        let mut created = created?;
        let created_id = created
            .get("id")
            .and_then(serde_json::Value::as_str)
            .filter(|id| !id.is_empty())
            .map(str::to_owned);
        zeroize_json_strings(&mut created);
        let created_id =
            created_id.ok_or_else(|| anyhow!("created 1Password item `{title}` has no item ID"))?;
        let mut matching_ids = match self.find_item_ids(&title) {
            Ok(ids) => ids,
            Err(err) => {
                return self.fail_created_item(
                    &created_id,
                    &title,
                    err.context("verify created 1Password item"),
                );
            }
        };
        for delay in OP_CONFLICT_RETRY_DELAYS {
            if matching_ids.iter().any(|id| id == &created_id) {
                break;
            }
            self.runner.wait_before_retry(*delay);
            matching_ids = match self.find_item_ids(&title) {
                Ok(ids) => ids,
                Err(err) => {
                    return self.fail_created_item(
                        &created_id,
                        &title,
                        err.context("verify created 1Password item"),
                    );
                }
            };
        }
        if !matching_ids.iter().any(|id| id == &created_id) {
            return self.fail_created_item(
                &created_id,
                &title,
                anyhow!(
                    "created 1Password item `{title}` was not visible after creation; retry the command"
                ),
            );
        }
        if matching_ids.len() <= 1 {
            return Ok(());
        }

        self.delete_item_by_id(&created_id, &title)?;
        bail!(
            "concurrent creation detected for 1Password item `{title}`; removed this operation's \
             duplicate item, retry the command"
        )
    }

    fn fail_created_item(&self, created_id: &str, title: &str, error: anyhow::Error) -> Result<()> {
        match self.delete_item_by_id(created_id, title) {
            Ok(()) => Err(error.context("removed the newly-created 1Password item")),
            Err(cleanup_err) => bail!(
                "{error:#}; additionally failed to remove newly-created item `{created_id}`: {cleanup_err:#}"
            ),
        }
    }

    fn get_item_value(&self, project: &ProjectIdentity, key: &str) -> Result<Option<String>> {
        let title = self.item_title(project, key)?;
        let Some(item_id) = self.find_item_id(&title)? else {
            return Ok(None);
        };
        let Some(mut item) = self.get_item_json(&item_id, &title)? else {
            return Ok(None);
        };
        let credential = item
            .get_mut("fields")
            .and_then(serde_json::Value::as_array_mut)
            .and_then(|fields| {
                fields.iter_mut().find(|field| {
                    field.get("label").and_then(serde_json::Value::as_str) == Some("credential")
                })
            })
            .and_then(|field| field.get_mut("value"))
            .map(serde_json::Value::take);
        zeroize_json_strings(&mut item);
        let mut value = match credential {
            Some(serde_json::Value::String(value)) => value,
            Some(mut unexpected) => {
                zeroize_json_strings(&mut unexpected);
                bail!("1Password item `{title}` is corrupt: credential field must be a string");
            }
            None => {
                bail!("1Password item `{title}` is corrupt: credential field is missing");
            }
        };
        if value.trim().is_empty() {
            value.zeroize();
            bail!("1Password item `{title}` is corrupt: credential field is empty");
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
        Ok(Some(value))
    }

    fn get_item_json(&self, item_id: &str, title: &str) -> Result<Option<serde_json::Value>> {
        let args = [
            "item",
            "get",
            item_id,
            "--vault",
            &self.vault,
            "--format",
            "json",
            "--reveal",
        ];
        let mut output = self.runner.run(&self.op_path, &args)?;
        if output.status.success() {
            let parsed = serde_json::from_slice::<serde_json::Value>(&output.stdout);
            output.stdout.zeroize();
            return parsed.map(Some).context("parse 1Password item JSON");
        }
        // `--reveal` may emit (partial) credential output even when the command
        // ultimately fails; zero it before entering any failure branch.
        output.stdout.zeroize();
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
        self.delete_item_by_id(&item_id, &title)
    }

    fn delete_item_by_id(&self, item_id: &str, title: &str) -> Result<()> {
        let args = ["item", "delete", item_id, "--vault", &self.vault];
        let mut output = self.runner.run(&self.op_path, &args)?;
        for delay in OP_CONFLICT_RETRY_DELAYS {
            if output.status.success() {
                return Ok(());
            }
            let stderr = String::from_utf8_lossy(&output.stderr);
            if is_op_not_found(&stderr) {
                return Ok(());
            }
            if !is_op_conflict(&stderr) {
                break;
            }
            self.runner.wait_before_retry(*delay);
            output = self.runner.run(&self.op_path, &args)?;
        }
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

fn is_managed_op_item(item: &serde_json::Value) -> bool {
    if item.get("category").and_then(|value| value.as_str()) != Some(OP_CATEGORY) {
        return false;
    }
    // `op item list --tags shk` also matches nested sub-tags such as `shk/foo`,
    // so require an exact `shk` tag in the item's tag list.
    item.get("tags")
        .and_then(|value| value.as_array())
        .is_some_and(|tags| tags.iter().any(|tag| tag.as_str() == Some(OP_TAG)))
}

fn zeroize_json_strings(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(value) => value.zeroize(),
        serde_json::Value::Array(values) => {
            for value in values {
                zeroize_json_strings(value);
            }
        }
        serde_json::Value::Object(values) => {
            for value in values.values_mut() {
                zeroize_json_strings(value);
            }
        }
        _ => {}
    }
}

#[derive(Serialize)]
struct OnePasswordItemTemplate<'a> {
    title: &'a str,
    tags: [&'static str; 1],
    category: &'static str,
    fields: [OnePasswordItemField<'a>; 1],
}

#[derive(Serialize)]
struct OnePasswordItemField<'a> {
    label: &'static str,
    #[serde(rename = "type")]
    field_type: &'static str,
    value: &'a str,
}

impl SecretStore for OnePasswordSecretStore {
    fn put(&self, project: &ProjectIdentity, key: &str, value: &str) -> Result<()> {
        with_secret_store_lock(project, &self.lock_purpose(key), || {
            self.put_item(project, key, value)
                .with_context(|| format!("store {key} in 1Password vault {}", self.vault))
        })
    }

    fn get(&self, project: &ProjectIdentity, key: &str) -> Result<Option<String>> {
        self.get_item_value(project, key)
    }

    fn delete(&self, project: &ProjectIdentity, key: &str) -> Result<()> {
        with_secret_store_lock(project, &self.lock_purpose(key), || {
            self.delete_item(project, key)
                .with_context(|| format!("delete {key} from 1Password vault {}", self.vault))
        })
    }

    fn list_keys(&self, project: &ProjectIdentity) -> Result<BTreeSet<String>> {
        let prefix = self.title_prefix(project)?;
        let value = self.run_json(&["item", "list", "--tags", OP_TAG, "--vault", &self.vault])?;
        let Some(items) = value.as_array() else {
            return Ok(BTreeSet::new());
        };
        let mut keys = BTreeSet::new();
        for item in items {
            if !is_managed_op_item(item) {
                continue;
            }
            let Some(title) = item.get("title").and_then(|v| v.as_str()) else {
                continue;
            };
            if let Some(key) = title.strip_prefix(&prefix) {
                if !key.is_empty() && !key.contains(':') {
                    keys.insert(key.to_string());
                }
            }
        }
        Ok(keys)
    }

    fn delete_if_value(
        &self,
        project: &ProjectIdentity,
        key: &str,
        expected: &str,
    ) -> Result<bool> {
        with_secret_store_lock(project, &self.lock_purpose(key), || {
            let Some(current) = self.get_item_value(project, key)? else {
                return Ok(true);
            };
            let current = Zeroizing::new(current);
            if current.as_str() != expected {
                return Ok(false);
            }
            self.delete_item(project, key)
                .with_context(|| format!("roll back {key} from 1Password vault {}", self.vault))?;
            Ok(true)
        })
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
            match run_doctor_op_command(&resolved.path, &["--version"]) {
                Ok(output) if output.status.success() => {
                    let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    status.op_version = Some(version.clone());
                    status.op_version_ok = op_version_meets_minimum(&version, MIN_OP_VERSION);
                }
                Ok(output) => {
                    status.op_version_error =
                        Some(String::from_utf8_lossy(&output.stderr).trim().to_string());
                }
                Err(err) => status.op_version_error = Some(err.to_string()),
            }

            match run_doctor_op_command(&resolved.path, &["whoami"]) {
                Ok(output) => {
                    status.op_signed_in = output.status.success();
                    if !status.op_signed_in {
                        status.op_sign_in_error =
                            Some(String::from_utf8_lossy(&output.stderr).trim().to_string());
                    }
                }
                Err(err) => status.op_sign_in_error = Some(err.to_string()),
            }
        }
        Err(err) => status.op_resolution_error = Some(err.to_string()),
    }

    Ok(status)
}

fn run_doctor_op_command(op_path: &Path, args: &[&str]) -> Result<Output> {
    run_doctor_op_command_with_timeout(op_path, args, OP_DOCTOR_TIMEOUT)
}

fn run_doctor_op_command_with_timeout(
    op_path: &Path,
    args: &[&str],
    timeout: Duration,
) -> Result<Output> {
    run_op_process_with_timeout(op_path, args, None, timeout)
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

fn is_op_conflict(stderr: &str) -> bool {
    stderr.contains("(409) Conflict") || stderr.contains("Internal server conflict")
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
    #[cfg(windows)]
    use std::os::windows::process::ExitStatusExt;
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

        fn delete_if_value(
            &self,
            project: &ProjectIdentity,
            key: &str,
            expected: &str,
        ) -> Result<bool> {
            if self.get(project, key)?.as_deref() != Some(expected) {
                return Ok(false);
            }
            self.delete(project, key)?;
            Ok(true)
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

        fn run_with_stdin(&self, _op_path: &Path, args: &[&str], _input: &[u8]) -> Result<Output> {
            self.run(Path::new("op"), args)
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
    fn would_block_is_lock_contention() {
        assert!(is_lock_contention(&std::io::Error::from(
            std::io::ErrorKind::WouldBlock
        )));
    }

    #[cfg(windows)]
    #[test]
    fn windows_lock_violation_is_lock_contention() {
        assert!(is_lock_contention(&std::io::Error::from_raw_os_error(33)));
    }

    #[cfg(unix)]
    #[test]
    fn unix_text_file_busy_is_transient() {
        assert!(is_transient_exec_busy(&std::io::Error::from_raw_os_error(
            libc::ETXTBSY
        )));
        assert!(!is_transient_exec_busy(&std::io::Error::from_raw_os_error(
            libc::ENOENT
        )));
    }

    #[test]
    fn op_version_meets_minimum_supports_prefixes() {
        assert!(op_version_meets_minimum("2.30.0-beta.01", "2.24.0"));
        assert!(!op_version_meets_minimum("2.20.0", "2.24.0"));
    }

    #[test]
    fn empty_configured_op_path_uses_normal_fallbacks() {
        assert_eq!(configured_op_path(None), None);
        assert_eq!(configured_op_path(Some("")), None);
        assert_eq!(configured_op_path(Some("  \t")), None);
        assert_eq!(
            configured_op_path(Some(" /usr/local/bin/op ")),
            Some(PathBuf::from("/usr/local/bin/op"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn op_validation_rejects_non_executable_files() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("op");
        std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let err = validate_op_binary(&path).unwrap_err();
        assert!(err.to_string().contains("not executable"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn lock_file_rejects_symlinks_and_hard_links() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, "preserve me").unwrap();

        let symlink_path = dir.path().join("symlink.lock");
        symlink(&victim, &symlink_path).unwrap();
        assert!(open_lock_file(&symlink_path).is_err());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "preserve me");

        let hard_link_path = dir.path().join("hard-link.lock");
        std::fs::hard_link(&victim, &hard_link_path).unwrap();
        assert!(open_lock_file(&hard_link_path).is_err());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "preserve me");
    }

    #[test]
    fn secure_lock_directory_creates_a_missing_cache_parent() {
        let dir = tempfile::tempdir().unwrap();
        let cache_dir = dir.path().join("missing/cache");

        let lock_dir = secure_lock_directory(&cache_dir).unwrap();

        assert_eq!(lock_dir, cache_dir.join("shk/locks"));
        assert!(lock_dir.is_dir());
    }

    #[test]
    fn lock_identity_does_not_change_with_onepassword_project_id() {
        let lock_dir = Path::new("/cache/shk/locks");
        let first = ProjectIdentity {
            root: PathBuf::from("/repo/app"),
            project_id: Some("team/first".to_string()),
        };
        let second = ProjectIdentity {
            root: first.root.clone(),
            project_id: Some("team/second".to_string()),
        };

        assert_eq!(
            secret_store_lock_path(lock_dir, &first, SHK_ENV_SERVICE),
            secret_store_lock_path(lock_dir, &second, SHK_ENV_SERVICE)
        );
    }

    #[cfg(unix)]
    #[test]
    fn doctor_op_command_times_out() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("op");
        std::fs::write(&path, "#!/bin/sh\nsleep 2\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();

        let err = run_doctor_op_command_with_timeout(&path, &["whoami"], Duration::from_millis(20))
            .unwrap_err();
        assert!(err.to_string().contains("timed out"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn doctor_op_command_collects_successful_output() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("op");
        std::fs::write(&path, "#!/bin/sh\nprintf '2.24.0\\n'\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();

        let output =
            run_doctor_op_command_with_timeout(&path, &["--version"], Duration::from_secs(1))
                .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"2.24.0\n");
    }

    #[cfg(unix)]
    #[test]
    fn regular_op_command_times_out() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("op");
        std::fs::write(&path, "#!/bin/sh\nsleep 2\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();

        let err =
            run_op_process_with_timeout(&path, &["item", "list"], None, Duration::from_millis(20))
                .unwrap_err();
        assert!(err.to_string().contains("timed out"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn regular_op_command_drains_large_stdout() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("op");
        std::fs::write(
            &path,
            "#!/bin/sh\ndd if=/dev/zero bs=1024 count=128 2>/dev/null\n",
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();

        let output = run_op_process_with_timeout(&path, &[], None, Duration::from_secs(2)).unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout.len(), 128 * 1024);
    }

    #[cfg(unix)]
    #[test]
    fn successful_op_command_ignores_broken_pipe_after_early_stdin_close() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("op");
        std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let input = vec![b'x'; 16 * 1024 * 1024];

        let output =
            run_op_process_with_timeout(&path, &[], Some(&input), Duration::from_secs(2)).unwrap();
        assert!(output.status.success());
    }

    #[test]
    fn onepassword_get_decodes_json_credential_once() {
        let (runner, calls) = RecordingOpRunner::new(vec![
            Ok(ok_output(
                r#"[{"id":"item-id","title":"shk:acme/backend:env:DOTENV_PRIVATE_KEY","category":"API_CREDENTIAL","tags":["shk"]}]"#,
            )),
            Ok(ok_output(
                r#"{"fields":[{"label":"credential","type":"CONCEALED","value":"{\"private_key\":\"demo-value\"}"}]}"#,
            )),
        ]);
        let store = OnePasswordSecretStore::with_runner(
            StoreKind::NativeEnv,
            PathBuf::from("/usr/local/bin/op"),
            "vault".to_string(),
            PathBuf::from("/repo"),
            Box::new(runner),
        );

        assert_eq!(
            store.get(&sample_project(), "DOTENV_PRIVATE_KEY").unwrap(),
            Some(r#"{"private_key":"demo-value"}"#.to_string())
        );
        let recorded = calls.lock().unwrap();
        assert!(
            recorded[1]
                .windows(2)
                .any(|args| args == ["--format", "json"])
        );
        assert!(!recorded[1].contains(&"--fields".to_string()));
    }

    #[test]
    fn onepassword_get_rejects_missing_or_invalid_credentials() {
        for item_body in [
            r#"{"fields":[]}"#,
            r#"{"fields":[{"label":"credential","value":"   "}]}"#,
            r#"{"fields":[{"label":"credential","value":42}]}"#,
        ] {
            let (runner, _calls) = RecordingOpRunner::new(vec![
                Ok(ok_output(
                    r#"[{"id":"item-id","title":"shk:acme/backend:env:DOTENV_PRIVATE_KEY","category":"API_CREDENTIAL","tags":["shk"]}]"#,
                )),
                Ok(ok_output(item_body)),
            ]);
            let store = OnePasswordSecretStore::with_runner(
                StoreKind::NativeEnv,
                PathBuf::from("/usr/local/bin/op"),
                "vault".to_string(),
                PathBuf::from("/repo"),
                Box::new(runner),
            );

            let err = store
                .get(&sample_project(), "DOTENV_PRIVATE_KEY")
                .unwrap_err();
            assert!(err.to_string().contains("is corrupt"), "{err}");
        }
    }

    #[test]
    fn onepassword_get_rejects_generic_not_found_errors() {
        let (runner, _calls) = RecordingOpRunner::new(vec![
            Ok(ok_output(
                r#"[{"id":"item-id","title":"shk:acme/backend:env:DOTENV_PRIVATE_KEY","category":"API_CREDENTIAL","tags":["shk"]}]"#,
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
                r#"[{"id":"item-id","title":"shk:acme/backend:env:DOTENV_PRIVATE_KEY","category":"API_CREDENTIAL","tags":["shk"]}]"#,
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
        let created = r#"{"id":"created-item"}"#;
        let listing = r#"[{"id":"created-item","title":"shk:acme/backend:env:DOTENV_PRIVATE_KEY","category":"API_CREDENTIAL","tags":["shk"]}]"#;
        let (runner, calls) = RecordingOpRunner::new(vec![
            Ok(ok_output("[]")),
            Ok(ok_output(created)),
            Ok(ok_output(listing)),
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
        assert_eq!(recorded.len(), 3);
        assert!(
            recorded
                .iter()
                .all(|call| !call.join(" ").contains("demo-value"))
        );
        assert!(
            recorded[0]
                .windows(2)
                .any(|args| args == ["--tags", OP_TAG])
        );
        assert!(!recorded[1].contains(&"--template".to_string()));
        assert_eq!(&recorded[1][..3], ["item", "create", "-"]);
    }

    #[test]
    fn onepassword_put_edits_existing_item_by_id() {
        let listing = r#"[{"id":"stable-item-id","title":"shk:acme/backend:env:DOTENV_PRIVATE_KEY","category":"API_CREDENTIAL","tags":["shk"]}]"#;
        let (runner, calls) = RecordingOpRunner::new(vec![
            Ok(ok_output(listing)),
            Ok(ok_output(
                r#"{"id":"stable-item-id","fields":[{"id":"credential-id","label":"credential","type":"CONCEALED","value":"old-value"}]}"#,
            )),
            Ok(ok_output("{}")),
            Ok(ok_output(listing)),
            Ok(ok_output(
                r#"{"fields":[{"label":"credential","type":"CONCEALED","value":"demo-value"}]}"#,
            )),
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
        assert_eq!(&recorded[2][..3], ["item", "edit", "stable-item-id"]);
    }

    #[test]
    fn onepassword_get_preserves_trailing_whitespace() {
        let listing = r#"[{"id":"stable-item-id","title":"shk:acme/backend:env:DOTENV_PRIVATE_KEY","category":"API_CREDENTIAL","tags":["shk"]}]"#;
        let (runner, _calls) = RecordingOpRunner::new(vec![
            Ok(ok_output(listing)),
            Ok(ok_output(
                r#"{"fields":[{"label":"credential","type":"CONCEALED","value":"secret\n"}]}"#,
            )),
        ]);
        let store = OnePasswordSecretStore::with_runner(
            StoreKind::NativeEnv,
            PathBuf::from("/usr/local/bin/op"),
            "vault".to_string(),
            PathBuf::from("/repo"),
            Box::new(runner),
        );
        assert_eq!(
            store.get(&sample_project(), "DOTENV_PRIVATE_KEY").unwrap(),
            Some("secret\n".to_string())
        );
    }

    #[test]
    fn onepassword_list_keys_rejects_ambiguous_titles() {
        let (runner, _calls) = RecordingOpRunner::new(vec![Ok(ok_output(
            r#"[{"id":"other-item","title":"shk:team:env:env:DOTENV_PRIVATE_KEY","category":"API_CREDENTIAL","tags":["shk"]}]"#,
        ))]);
        let store = OnePasswordSecretStore::with_runner(
            StoreKind::NativeEnv,
            PathBuf::from("/usr/local/bin/op"),
            "vault".to_string(),
            PathBuf::from("/repo"),
            Box::new(runner),
        );
        let project = ProjectIdentity {
            root: PathBuf::from("/repo"),
            project_id: Some("team".to_string()),
        };
        assert!(store.list_keys(&project).unwrap().is_empty());
    }

    #[test]
    fn onepassword_delete_if_value_only_deletes_the_expected_value() {
        let listing = r#"[{"id":"stable-item-id","title":"shk:acme/backend:env:DOTENV_PRIVATE_KEY","category":"API_CREDENTIAL","tags":["shk"]}]"#;
        let (runner, calls) = RecordingOpRunner::new(vec![
            Ok(ok_output(listing)),
            Ok(ok_output(
                r#"{"fields":[{"label":"credential","type":"CONCEALED","value":"expected"}]}"#,
            )),
            Ok(ok_output(listing)),
            Ok(ok_output("{}")),
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
                .delete_if_value(&sample_project(), "DOTENV_PRIVATE_KEY", "expected")
                .unwrap()
        );
        let recorded = calls.lock().unwrap();
        assert_eq!(&recorded[3][..3], ["item", "delete", "stable-item-id"]);
    }

    #[test]
    fn onepassword_delete_if_value_preserves_a_changed_value() {
        let listing = r#"[{"id":"stable-item-id","title":"shk:acme/backend:env:DOTENV_PRIVATE_KEY","category":"API_CREDENTIAL","tags":["shk"]}]"#;
        let (runner, calls) = RecordingOpRunner::new(vec![
            Ok(ok_output(listing)),
            Ok(ok_output(
                r#"{"fields":[{"label":"credential","type":"CONCEALED","value":"changed"}]}"#,
            )),
        ]);
        let store = OnePasswordSecretStore::with_runner(
            StoreKind::NativeEnv,
            PathBuf::from("/usr/local/bin/op"),
            "vault".to_string(),
            PathBuf::from("/repo"),
            Box::new(runner),
        );

        assert!(
            !store
                .delete_if_value(&sample_project(), "DOTENV_PRIVATE_KEY", "expected")
                .unwrap()
        );
        assert_eq!(calls.lock().unwrap().len(), 2);
    }

    #[test]
    fn onepassword_put_rejects_duplicate_titles() {
        let (runner, _calls) = RecordingOpRunner::new(vec![Ok(ok_output(
            r#"[{"id":"item-a","title":"shk:acme/backend:env:DOTENV_PRIVATE_KEY","category":"API_CREDENTIAL","tags":["shk"]},{"id":"item-b","title":"shk:acme/backend:env:DOTENV_PRIVATE_KEY","category":"API_CREDENTIAL","tags":["shk"]}]"#,
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
    fn onepassword_put_removes_its_item_when_a_concurrent_create_wins() {
        let listing = r#"[{"id":"existing-item","title":"shk:acme/backend:env:DOTENV_PRIVATE_KEY","category":"API_CREDENTIAL","tags":["shk"]},{"id":"created-item","title":"shk:acme/backend:env:DOTENV_PRIVATE_KEY","category":"API_CREDENTIAL","tags":["shk"]}]"#;
        let (runner, calls) = RecordingOpRunner::new(vec![
            Ok(ok_output("[]")),
            Ok(ok_output(r#"{"id":"created-item"}"#)),
            Ok(ok_output(listing)),
            Ok(ok_output("{}")),
        ]);
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

        assert!(
            format!("{err:#}").contains("concurrent creation"),
            "{err:#}"
        );
        let recorded = calls.lock().unwrap();
        assert_eq!(&recorded[3][..3], ["item", "delete", "created-item"]);
    }

    #[test]
    fn onepassword_put_never_edits_same_title_item_with_unmanaged_category() {
        let listing = r#"[{"id":"unrelated-item","title":"shk:acme/backend:env:DOTENV_PRIVATE_KEY","category":"LOGIN"},{"id":"created-item","title":"shk:acme/backend:env:DOTENV_PRIVATE_KEY","category":"API_CREDENTIAL","tags":["shk"]}]"#;
        let (runner, calls) = RecordingOpRunner::new(vec![
            Ok(ok_output(
                r#"[{"id":"unrelated-item","title":"shk:acme/backend:env:DOTENV_PRIVATE_KEY","category":"LOGIN"}]"#,
            )),
            Ok(ok_output(r#"{"id":"created-item"}"#)),
            Ok(ok_output(listing)),
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
        assert_eq!(&recorded[1][..2], ["item", "create"]);
        assert!(!recorded[1].contains(&"unrelated-item".to_string()));
    }

    #[test]
    fn onepassword_get_and_delete_skip_unmanaged_same_title_item() {
        let unmanaged = r#"[{"id":"unrelated-item","title":"shk:acme/backend:env:DOTENV_PRIVATE_KEY","category":"LOGIN"}]"#;
        let (runner, calls) =
            RecordingOpRunner::new(vec![Ok(ok_output(unmanaged)), Ok(ok_output(unmanaged))]);
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
        store
            .delete(&sample_project(), "DOTENV_PRIVATE_KEY")
            .unwrap();
        // Only the two `item list` calls; no `item get` / `item delete` reached the runner.
        assert_eq!(calls.lock().unwrap().len(), 2);
    }

    #[test]
    fn onepassword_delete_retries_transient_conflicts() {
        let listing = r#"[{"id":"item-id","title":"shk:acme/backend:env:DOTENV_PRIVATE_KEY","category":"API_CREDENTIAL","tags":["shk"]}]"#;
        let (runner, calls) = RecordingOpRunner::new(vec![
            Ok(ok_output(listing)),
            Ok(Output {
                status: std::process::ExitStatus::from_raw(1),
                stdout: Vec::new(),
                stderr: b"(409) Conflict: Internal server conflict".to_vec(),
            }),
            Ok(ok_output("")),
        ]);
        let store = OnePasswordSecretStore::with_runner(
            StoreKind::NativeEnv,
            PathBuf::from("/usr/local/bin/op"),
            "vault".to_string(),
            PathBuf::from("/repo"),
            Box::new(runner),
        );

        store
            .delete(&sample_project(), "DOTENV_PRIVATE_KEY")
            .unwrap();
        let recorded = calls.lock().unwrap();
        assert_eq!(recorded.len(), 3);
        assert_eq!(recorded[1], recorded[2]);
    }

    #[test]
    fn onepassword_ignores_items_with_only_sub_tags() {
        // `op item list --tags shk` also returns items tagged only `shk/foo`;
        // those must not be treated as shk-managed.
        let sub_tag_only = r#"[{"id":"sub-tag-item","title":"shk:acme/backend:env:DOTENV_PRIVATE_KEY","category":"API_CREDENTIAL","tags":["shk/foo"]}]"#;
        let listing = r#"[{"id":"sub-tag-item","title":"shk:acme/backend:env:DOTENV_PRIVATE_KEY","category":"API_CREDENTIAL","tags":["shk/foo"]},{"id":"created-item","title":"shk:acme/backend:env:DOTENV_PRIVATE_KEY","category":"API_CREDENTIAL","tags":["shk"]}]"#;
        let (runner, calls) = RecordingOpRunner::new(vec![
            Ok(ok_output(sub_tag_only)),
            Ok(ok_output(r#"{"id":"created-item"}"#)),
            Ok(ok_output(listing)),
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
        assert_eq!(&recorded[1][..2], ["item", "create"]);
        assert!(!recorded[1].contains(&"sub-tag-item".to_string()));
    }

    #[test]
    fn onepassword_get_zeroes_stdout_on_failure_paths() {
        // Failure after `--reveal` may leave (partial) secret bytes in stdout;
        // both the not-found and generic-failure branches must complete without
        // surfacing them (zeroization itself is not observable here, but the
        // branches must be exercised with non-empty stdout).
        let listing = r#"[{"id":"item-id","title":"shk:acme/backend:env:DOTENV_PRIVATE_KEY","category":"API_CREDENTIAL","tags":["shk"]}]"#;
        let (runner, _calls) = RecordingOpRunner::new(vec![
            Ok(ok_output(listing)),
            Ok(Output {
                status: std::process::ExitStatus::from_raw(1),
                stdout: b"partial-secret".to_vec(),
                stderr: b"item isn't an item in this vault".to_vec(),
            }),
            Ok(ok_output(listing)),
            Ok(Output {
                status: std::process::ExitStatus::from_raw(1),
                stdout: b"partial-secret".to_vec(),
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
        assert!(
            store
                .get(&sample_project(), "DOTENV_PRIVATE_KEY")
                .unwrap()
                .is_none()
        );
        let err = store
            .get(&sample_project(), "DOTENV_PRIVATE_KEY")
            .unwrap_err();
        assert!(!format!("{err:#}").contains("partial-secret"));
    }

    #[test]
    fn onepassword_list_keys_skips_unmanaged_categories() {
        let (runner, _calls) = RecordingOpRunner::new(vec![Ok(ok_output(
            r#"[{"title":"shk:acme/backend:env:DOTENV_PRIVATE_KEY","category":"API_CREDENTIAL","tags":["shk"]},{"title":"shk:acme/backend:env:DOTENV_PRIVATE_KEY_STAGING","category":"LOGIN"}]"#,
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

    #[test]
    fn onepassword_list_keys_filters_by_project_prefix() {
        let (runner, _calls) = RecordingOpRunner::new(vec![Ok(ok_output(
            r#"[{"title":"shk:acme/backend:env:DOTENV_PRIVATE_KEY","category":"API_CREDENTIAL","tags":["shk"]},{"title":"shk:other:env:DOTENV_PRIVATE_KEY","category":"API_CREDENTIAL","tags":["shk"]}]"#,
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
