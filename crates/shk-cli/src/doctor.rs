use crate::env_store::{OpPathSource, collect_onepassword_doctor_status};
use crate::exit::CliExit;
use crate::{npm_hardening, safety, workflow_hardening};
use anyhow::Result;
use serde_json::Value;
use shk_core::git;
use shk_core::policy::{Policy, SecretStoreBackend};
use shk_core::scanner::{ScanOptions, scan_string};
use shk_integrations::{
    CONFIG_REL_PATH, HOOKS_FEATURE_KEY, LEGACY_HOOKS_FEATURE_KEY, MANAGED_MARKER_JSON,
    MANAGED_MARKER_SH, RISKY_APPROVAL_POLICY, RISKY_DEFAULT_PERMISSIONS, RISKY_SANDBOX_MODE,
    claude_deny_entry_covers, claude_recommended_deny_entries,
};
use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};

const IGNORE_CANDIDATES: &[&str] = &[
    ".gitignore",
    ".cursorignore",
    ".cursorindexingignore",
    ".codeiumignore",
    ".clineignore",
    ".aiderignore",
    ".continueignore",
    ".tabnineignore",
    ".ignore",
    ".aiignore",
];

const DOTENVX_PRIVATE_KEY_FILE: &str = ".env.keys";
const DOTENVX_VAULT_FILE: &str = ".env.vault";
const DOTENVX_HINT_FILES: &[&str] = &[DOTENVX_PRIVATE_KEY_FILE, DOTENVX_VAULT_FILE];
const DOTENV_ENCRYPTED_VALUE_PREFIX: &str = "encrypted:";
const DOTENV_PUBLIC_KEY_PREFIX: &str = "DOTENV_PUBLIC_KEY";
const DOTENV_PRIVATE_KEY_PREFIX: &str = "DOTENV_PRIVATE_KEY";

#[derive(Debug, Clone, serde::Serialize)]
pub struct IgnoreStatus {
    pub missing_patterns: Vec<String>,
    pub load_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct IgnoreFileUpdate {
    pub relative_path: String,
    pub appended: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct IgnoreFixResult {
    pub updates: Vec<IgnoreFileUpdate>,
    pub already_ok: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct IgnoreFixTargetStatus {
    pub name: String,
    pub exists: bool,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EnvFileState {
    Plaintext,
    Mixed,
    Encrypted,
}

/// Per-file env encryption report. Key names only — values are never collected.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvFileStatus {
    pub name: String,
    pub state: EnvFileState,
    pub plaintext_keys: Vec<String>,
    pub encrypted_key_count: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ClaudePermissionsStatus {
    pub settings_exists: bool,
    pub deny_ok: bool,
    pub sandbox_ok: bool,
    pub missing_entries: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CodexConfigStatus {
    pub config_exists: bool,
    pub hooks_enabled: bool,
    pub sandbox_ok: bool,
    pub approval_ok: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShkExecutableCandidate {
    pub path: PathBuf,
    pub resolved_path: PathBuf,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShkExecutableStatus {
    pub current_executable: Option<PathBuf>,
    pub current_resolved_path: Option<PathBuf>,
    pub current_matches_path_candidate: bool,
    pub active_on_path: Option<PathBuf>,
    pub candidates: Vec<ShkExecutableCandidate>,
    pub multiple_distinct: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SecretStoreDoctorStatus {
    backend: String,
    backend_supported: bool,
    warning_count: usize,
    live_checks_performed: bool,
    one_password: Option<OnePasswordDoctorSummary>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct OnePasswordDoctorSummary {
    project_id_ok: bool,
    vault_ok: bool,
}

#[derive(Debug, Eq, PartialEq)]
enum EnvFileEncryptionState {
    Plaintext,
    FullyEncrypted,
    MixedPlaintext { keys: Vec<String> },
}

pub fn ignore_fix_targets() -> &'static [&'static str] {
    IGNORE_CANDIDATES
}

pub fn ignore_fix_target_statuses(root: &Path) -> Vec<IgnoreFixTargetStatus> {
    ignore_fix_targets()
        .iter()
        .map(|name| {
            let path = root.join(name);
            IgnoreFixTargetStatus {
                name: (*name).to_string(),
                exists: path.exists(),
            }
        })
        .collect()
}

pub fn collect_ignore_status(root: &Path) -> IgnoreStatus {
    collect_ignore_status_result(root).unwrap_or_else(|err| IgnoreStatus {
        missing_patterns: Vec::new(),
        load_error: Some(err.to_string()),
    })
}

pub fn collect_env_file_statuses(root: &Path) -> Vec<EnvFileStatus> {
    collect_env_file_statuses_matching(root, is_native_env_candidate_name)
}

fn collect_doctor_env_file_statuses(root: &Path) -> Vec<EnvFileStatus> {
    collect_env_file_statuses_matching(root, is_doctor_env_candidate_name)
}

fn collect_env_file_statuses_matching(
    root: &Path,
    candidate: fn(&str) -> bool,
) -> Vec<EnvFileStatus> {
    let mut files = Vec::new();
    if let Ok(entries) = fs::read_dir(root) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if candidate(&name) && e.path().is_file() {
                let content = fs::read_to_string(e.path()).unwrap_or_default();
                files.push(env_file_status(name, &content));
            }
        }
    }
    files.sort_by(|a, b| a.name.cmp(&b.name));
    files
}

fn is_doctor_env_candidate_name(name: &str) -> bool {
    name == DOTENVX_PRIVATE_KEY_FILE || is_native_env_candidate_name(name)
}

fn is_native_env_candidate_name(name: &str) -> bool {
    (name == ".env" || name.starts_with(".env."))
        && !matches!(
            name,
            ".env.example" | ".env.sample" | ".env.keys" | ".env.vault"
        )
}

fn env_file_status(name: String, content: &str) -> EnvFileStatus {
    let state = match dotenv_encryption_state(content) {
        EnvFileEncryptionState::FullyEncrypted => EnvFileState::Encrypted,
        EnvFileEncryptionState::MixedPlaintext { .. } => EnvFileState::Mixed,
        EnvFileEncryptionState::Plaintext => EnvFileState::Plaintext,
    };
    let (plaintext_keys, encrypted_key_count) = dotenv_key_summary(content);
    EnvFileStatus {
        name,
        state,
        plaintext_keys,
        encrypted_key_count,
    }
}

/// Count encrypted values and collect plaintext key names (never values).
/// Private-key entries count as plaintext: key material inside an env file is
/// exactly what the doctor should surface.
fn dotenv_key_summary(content: &str) -> (Vec<String>, usize) {
    let mut plaintext_keys = Vec::new();
    let mut encrypted_key_count = 0usize;
    for raw_line in content.lines() {
        match classify_dotenv_line(raw_line) {
            DotenvLine::Skip | DotenvLine::Malformed => {}
            DotenvLine::Entry {
                encrypted: true,
                parse_error: false,
                private_key: false,
                ..
            } => encrypted_key_count += 1,
            DotenvLine::Entry { key, .. } => plaintext_keys.push(key.to_string()),
        }
    }
    (plaintext_keys, encrypted_key_count)
}

/// A single dotenv line as seen by the doctor checks. Only key names and value
/// shape are inspected; values themselves are never retained.
enum DotenvLine<'a> {
    /// Blank line, comment, or a public-key entry — not a secret-bearing entry.
    Skip,
    /// No `=` or an empty key.
    Malformed,
    Entry {
        key: &'a str,
        /// Value parsed and carries the `encrypted:` prefix.
        encrypted: bool,
        /// Value quoting could not be parsed.
        parse_error: bool,
        /// Key names dotenv private-key material.
        private_key: bool,
    },
}

fn classify_dotenv_line(raw_line: &str) -> DotenvLine<'_> {
    let line = raw_line.trim();
    if line.is_empty() || line.starts_with('#') {
        return DotenvLine::Skip;
    }
    let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
    let Some((raw_key, raw_value)) = line.split_once('=') else {
        return DotenvLine::Malformed;
    };
    let key = raw_key.trim();
    if key.is_empty() {
        return DotenvLine::Malformed;
    }
    if is_dotenv_public_key_name(key) {
        return DotenvLine::Skip;
    }
    let private_key = is_dotenv_private_key_name(key);
    match dotenv_value_without_wrapping_quotes(raw_value.trim()) {
        Some(value) => DotenvLine::Entry {
            key,
            encrypted: value.starts_with(DOTENV_ENCRYPTED_VALUE_PREFIX),
            parse_error: false,
            private_key,
        },
        None => DotenvLine::Entry {
            key,
            encrypted: false,
            parse_error: true,
            private_key,
        },
    }
}

pub fn run_ignore(root: &Path, fix: bool) -> Result<()> {
    if fix {
        safety::require_project_policy(root, "doctor ignore --fix")?;
        safety::ensure_writable_path_allowed(&root.join(".gitignore"))?;
    }
    let status = collect_ignore_status_result(root)?;
    print_ignore_status(&status.missing_patterns);
    if fix {
        let result = fix_ignore_patterns(root, &[".gitignore".to_string()])?;
        for update in &result.updates {
            println!(
                "Wrote {} pattern(s) to {}",
                update.appended.len(),
                update.relative_path
            );
        }
    }
    run_claude_permissions_check(root);
    run_codex_config_check(root);
    Ok(())
}

pub fn fix_ignore_patterns(root: &Path, targets: &[String]) -> Result<IgnoreFixResult> {
    safety::require_project_policy(root, "doctor ignore --fix")?;
    let normalized = normalize_ignore_fix_targets(targets)?;
    if normalized.is_empty() {
        anyhow::bail!("at least one ignore fix target is required");
    }

    let missing = collect_ignore_status_result(root)?.missing_patterns;
    if missing.is_empty() {
        return Ok(IgnoreFixResult {
            updates: Vec::new(),
            already_ok: true,
        });
    }

    let mut updates = Vec::new();
    for relative_path in normalized {
        let path = root.join(&relative_path);
        safety::ensure_writable_path_allowed(&path)?;
        safety::ensure_write_path_within(root, &path)?;
        let appended = append_patterns_to_ignore_file(&path, &missing)?;
        if !appended.is_empty() {
            updates.push(IgnoreFileUpdate {
                relative_path,
                appended,
            });
        }
    }

    Ok(IgnoreFixResult {
        already_ok: updates.is_empty(),
        updates,
    })
}

fn normalize_ignore_fix_targets(targets: &[String]) -> Result<Vec<String>> {
    let mut normalized = Vec::new();
    for target in targets {
        let trimmed = target.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !ignore_fix_targets().contains(&trimmed) {
            anyhow::bail!("unknown ignore fix target: {trimmed}");
        }
        if !normalized.iter().any(|existing| existing == trimmed) {
            normalized.push(trimmed.to_string());
        }
    }
    Ok(normalized)
}

fn collect_ignore_status_result(root: &Path) -> Result<IgnoreStatus> {
    let (policy, _) = Policy::load_from_dir(root)?;
    collect_ignore_status_with_policy(root, &policy)
}

fn collect_ignore_status_with_policy(root: &Path, policy: &Policy) -> Result<IgnoreStatus> {
    let combined = read_ignore_candidate_files(root)?;
    let missing_patterns = policy
        .doctor
        .ignore
        .effective_required_patterns()
        .iter()
        .filter(|pat| !pattern_present(&combined, pat))
        .cloned()
        .collect();

    Ok(IgnoreStatus {
        missing_patterns,
        load_error: None,
    })
}

fn read_ignore_candidate_files(root: &Path) -> Result<String> {
    let mut combined = String::new();
    for candidate in IGNORE_CANDIDATES {
        let path = root.join(candidate);
        if !path.is_file() {
            continue;
        }
        if !combined.is_empty() {
            combined.push('\n');
        }
        combined.push_str(&fs::read_to_string(&path)?);
    }
    Ok(combined)
}

fn print_ignore_status(missing: &[String]) {
    if missing.is_empty() {
        println!("ignore: OK (required patterns present in ignore files)");
    } else {
        println!("ignore: missing recommended patterns:");
        for pat in missing {
            println!("  - {pat}");
        }
    }
}

fn append_patterns_to_ignore_file(path: &Path, patterns: &[String]) -> Result<Vec<String>> {
    if path.exists() && !path.is_file() {
        anyhow::bail!("ignore target is not a file: {}", path.display());
    }
    let existing = if path.is_file() {
        fs::read_to_string(path)?
    } else {
        String::new()
    };
    let mut appended = Vec::new();
    for pat in patterns {
        if !pattern_present(&existing, pat) {
            appended.push(pat.clone());
        }
    }
    if appended.is_empty() {
        return Ok(Vec::new());
    }

    let mut body = existing;
    if !body.is_empty() && !body.ends_with('\n') {
        body.push('\n');
    }
    body.push_str("\n# shk: appended required patterns\n");
    for pat in &appended {
        body.push_str(pat);
        body.push('\n');
    }
    crate::fs_atomic::write_atomic(path, body.as_bytes())?;
    Ok(appended)
}

pub fn collect_claude_permissions_status(root: &Path) -> ClaudePermissionsStatus {
    let path = root.join(".claude/settings.json");
    if !path.is_file() {
        return ClaudePermissionsStatus {
            settings_exists: false,
            deny_ok: true,
            sandbox_ok: true,
            missing_entries: Vec::new(),
        };
    }

    let Ok(text) = fs::read_to_string(&path) else {
        return ClaudePermissionsStatus {
            settings_exists: true,
            deny_ok: false,
            sandbox_ok: false,
            missing_entries: vec!["unable to read .claude/settings.json".into()],
        };
    };
    let Ok(value) = serde_json::from_str::<Value>(&text) else {
        return ClaudePermissionsStatus {
            settings_exists: true,
            deny_ok: false,
            sandbox_ok: false,
            missing_entries: vec!["unable to parse .claude/settings.json".into()],
        };
    };

    let denies = value
        .pointer("/permissions/deny")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<&str>>()
        })
        .unwrap_or_default();

    let missing_entries = claude_recommended_deny_entries()
        .iter()
        .copied()
        .filter(|entry| !claude_deny_covers(&denies, entry))
        .map(str::to_string)
        .collect::<Vec<_>>();

    ClaudePermissionsStatus {
        settings_exists: true,
        deny_ok: missing_entries.is_empty(),
        sandbox_ok: claude_sandbox_ok(&value),
        missing_entries,
    }
}

fn run_claude_permissions_check(root: &Path) {
    let status = collect_claude_permissions_status(root);
    print_claude_permissions_status(&status);
}

fn print_claude_permissions_status(status: &ClaudePermissionsStatus) {
    if !status.settings_exists {
        return;
    }
    if status.deny_ok {
        println!("claude permissions: OK (recommended action deny entries present)");
    } else {
        println!("claude permissions: missing recommended action deny entries:");
        for pat in &status.missing_entries {
            println!("  - {pat}");
        }
    }
    if status.sandbox_ok {
        println!("claude sandbox: OK");
    } else {
        println!("claude sandbox: recommended project sandbox settings missing");
    }
}

fn claude_deny_covers(denies: &[&str], required: &str) -> bool {
    denies
        .iter()
        .any(|entry| claude_deny_entry_covers(entry, required))
}

fn claude_sandbox_ok(value: &Value) -> bool {
    let Some(sandbox) = value.get("sandbox") else {
        return false;
    };
    let enabled = sandbox
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let fail_if_unavailable = sandbox
        .get("failIfUnavailable")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let blocks_unsandboxed = sandbox
        .get("allowUnsandboxedCommands")
        .and_then(Value::as_bool)
        .map(|allowed| !allowed)
        .unwrap_or(false);
    let filesystem = sandbox.get("filesystem").unwrap_or(&Value::Null);
    enabled
        && fail_if_unavailable
        && blocks_unsandboxed
        && json_array_contains(filesystem.get("denyRead"), "~/")
        && json_array_contains(filesystem.get("allowRead"), ".")
}

fn json_array_contains(value: Option<&Value>, needle: &str) -> bool {
    value
        .and_then(Value::as_array)
        .map(|items| items.iter().any(|item| item.as_str() == Some(needle)))
        .unwrap_or(false)
}

pub fn collect_codex_config_status(root: &Path) -> CodexConfigStatus {
    snapshot_codex_config(root).status
}

#[derive(Debug)]
struct CodexConfigSnapshot {
    status: CodexConfigStatus,
    value: Option<toml::Value>,
}

fn snapshot_codex_config(root: &Path) -> CodexConfigSnapshot {
    let path = root.join(CONFIG_REL_PATH);
    if !path.is_file() {
        return CodexConfigSnapshot {
            status: CodexConfigStatus {
                config_exists: false,
                hooks_enabled: false,
                sandbox_ok: true,
                approval_ok: true,
            },
            value: None,
        };
    }

    let Ok(text) = fs::read_to_string(&path) else {
        return CodexConfigSnapshot {
            status: CodexConfigStatus {
                config_exists: true,
                hooks_enabled: false,
                sandbox_ok: false,
                approval_ok: false,
            },
            value: None,
        };
    };
    let Ok(value) = toml::from_str::<toml::Value>(&text) else {
        return CodexConfigSnapshot {
            status: CodexConfigStatus {
                config_exists: true,
                hooks_enabled: false,
                sandbox_ok: false,
                approval_ok: false,
            },
            value: None,
        };
    };

    CodexConfigSnapshot {
        status: codex_config_status_from_value(&value),
        value: Some(value),
    }
}

fn codex_config_status_from_value(value: &toml::Value) -> CodexConfigStatus {
    CodexConfigStatus {
        config_exists: true,
        hooks_enabled: codex_hooks_feature_enabled(value.get("features")),
        sandbox_ok: !matches!(
            value.get("sandbox_mode").and_then(toml::Value::as_str),
            Some(RISKY_SANDBOX_MODE)
        ) && !matches!(
            value
                .get("default_permissions")
                .and_then(toml::Value::as_str),
            Some(RISKY_DEFAULT_PERMISSIONS)
        ),
        approval_ok: !matches!(
            value.get("approval_policy").and_then(toml::Value::as_str),
            Some(RISKY_APPROVAL_POLICY)
        ),
    }
}

fn codex_hooks_feature_enabled(features: Option<&toml::Value>) -> bool {
    let Some(features) = features else {
        return true;
    };
    features
        .get(HOOKS_FEATURE_KEY)
        .and_then(toml::Value::as_bool)
        .or_else(|| {
            features
                .get(LEGACY_HOOKS_FEATURE_KEY)
                .and_then(toml::Value::as_bool)
        })
        .unwrap_or(true)
}

fn run_codex_config_check(root: &Path) {
    let snapshot = snapshot_codex_config(root);
    print_codex_config_snapshot(&snapshot);
}

fn print_codex_config_snapshot(snapshot: &CodexConfigSnapshot) {
    if !snapshot.status.config_exists {
        return;
    }
    if snapshot.status.hooks_enabled {
        println!("codex config: hooks feature enabled");
    } else {
        println!("codex config: hooks feature disabled (`features.hooks = false`)");
    }

    let Some(value) = snapshot.value.as_ref() else {
        println!("codex config: unable to read or parse {CONFIG_REL_PATH}");
        return;
    };
    print_codex_string_setting(value, "sandbox_mode", Some(RISKY_SANDBOX_MODE));
    print_codex_string_setting(
        value,
        "default_permissions",
        Some(RISKY_DEFAULT_PERMISSIONS),
    );
    print_codex_string_setting(value, "approval_policy", Some(RISKY_APPROVAL_POLICY));
}

fn print_codex_string_setting(value: &toml::Value, key: &str, risky_value: Option<&str>) {
    match value.get(key).and_then(toml::Value::as_str) {
        Some(current) if risky_value == Some(current) => {
            println!("codex config: warning {key}={current}");
        }
        Some(current) => println!("codex config: {key}={current}"),
        None => {
            println!("codex config: {key} not set");
        }
    }
}

fn pattern_present(hay: &str, pat: &str) -> bool {
    let needle = pat.trim();
    hay.lines()
        .filter_map(normalize_ignore_pattern)
        .any(|line| ignore_pattern_covers(line, needle))
}

fn normalize_ignore_pattern(line: &str) -> Option<&str> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        None
    } else {
        Some(line)
    }
}

fn ignore_pattern_covers(existing: &str, required: &str) -> bool {
    if existing == required
        || existing.trim_end_matches('/') == required.trim_end_matches('/')
        || directory_pattern_covers(existing, required)
    {
        return true;
    }

    matches!(
        (existing, required),
        (".env*", ".env") | (".env*", ".env.*")
    )
}

fn directory_pattern_covers(existing: &str, required: &str) -> bool {
    let Some(required_dir) = required.strip_suffix("/**") else {
        return false;
    };
    existing.trim_end_matches('/') == required_dir
}

pub fn run_env(root: &Path, dotenvx: bool) -> Result<()> {
    run_env_with_warning_count(root, dotenvx).map(|_| ())
}

fn run_env_with_warning_count(root: &Path, dotenvx: bool) -> Result<usize> {
    let (policy, _) = Policy::load_from_dir(root)?;
    let mut warning_count = print_secret_store_status(root, &policy)?;
    let mut env_files = Vec::new();
    let mut mixed_env_files = Vec::new();
    for e in fs::read_dir(root)? {
        let e = e?;
        let name = e.file_name().to_string_lossy().to_string();
        if is_doctor_env_candidate_name(&name) && e.path().is_file() {
            let content = fs::read_to_string(e.path()).unwrap_or_default();
            match dotenv_encryption_state(&content) {
                EnvFileEncryptionState::FullyEncrypted => {}
                EnvFileEncryptionState::MixedPlaintext { keys } => {
                    mixed_env_files.push((name, keys));
                }
                EnvFileEncryptionState::Plaintext => {
                    env_files.push((name, e.path(), content));
                }
            }
        }
    }
    if env_files.is_empty() && mixed_env_files.is_empty() {
        println!(
            "env: no plaintext .env / .env.* files (templates and .env.vault excluded) at repo root"
        );
    } else if !env_files.is_empty() {
        warning_count += 1;
        println!("env: plaintext env files detected (review + prefer dotenvx / secret manager):");
        for (name, _path, content) in env_files {
            let findings = scan_string(root, &name, &content, ScanOptions::default())?
                .findings
                .into_iter()
                .filter(|f| f.kind != "ignore")
                .count();
            if findings == 0 {
                println!("  - {name} (no rule hits; still unsafe by default)");
            } else {
                println!("  - {name} ({findings} finding(s))");
            }
        }
        println!("  recommendation: encrypt env files or migrate secrets to a secret manager");
        println!("  recommendation: deny direct AI reads of .env files via tool-specific controls");
    }

    if !mixed_env_files.is_empty() {
        warning_count += 1;
        println!("env: encrypted env files contain plaintext values:");
        for (name, keys) in mixed_env_files {
            let preview = keys.iter().take(5).cloned().collect::<Vec<_>>().join(", ");
            let suffix = if keys.len() > 5 {
                format!(" (+{} more)", keys.len() - 5)
            } else {
                String::new()
            };
            println!(
                "  - {name} ({} plaintext key(s): {preview}{suffix})",
                keys.len()
            );
        }
        println!(
            "  recommendation: run `shk env encrypt <file> --in-place` after editing encrypted env files"
        );
    }

    if dotenvx {
        run_dotenvx(root);
    }
    Ok(warning_count)
}

fn print_secret_store_status(root: &Path, policy: &Policy) -> Result<usize> {
    println!(
        "env secret store: {} (configured in shk.toml [env])",
        policy.env.secret_store
    );
    match policy.env.secret_store.parse::<SecretStoreBackend>() {
        Ok(SecretStoreBackend::Keyring) => {
            println!("  backend: OS keyring (default)");
            return Ok(0);
        }
        Ok(SecretStoreBackend::OnePassword) => {}
        Err(err) => {
            println!("  warning: {err}");
            return Ok(1);
        }
    }

    if policy
        .env
        .project_id
        .as_ref()
        .is_none_or(|v| v.trim().is_empty())
    {
        println!("  warning: env.project_id is required for 1Password");
        if let Some(candidate) = shk_core::policy::suggest_env_project_id(root) {
            println!("  suggestion: project_id = \"{candidate}\"");
        }
    }
    if policy
        .env
        .onepassword
        .vault
        .as_ref()
        .is_none_or(|v| v.trim().is_empty())
    {
        println!("  warning: env.onepassword.vault is required for 1Password");
    }

    let status = collect_onepassword_doctor_status(policy)?;
    let warning_count = onepassword_warning_count(policy, &status);
    if let Some(err) = &status.op_resolution_error {
        println!("  1Password CLI: not resolved ({err})");
        println!("  hint: install `op`, set SHK_OP_PATH, or add it to PATH");
        return Ok(warning_count);
    }
    if let Some(path) = &status.op_path {
        let source = status
            .op_path_source
            .map(OpPathSource::label)
            .unwrap_or("unknown");
        println!("  1Password CLI: {path} (via {source})");
    }
    if let Some(version) = &status.op_version {
        if status.op_version_ok {
            println!("  op version: {version} (>= 2.24.0)");
        } else {
            println!("  warning: op version {version} is below supported minimum 2.24.0");
        }
    } else if let Some(err) = &status.op_version_error {
        println!("  warning: could not read op version: {err}");
    }
    if status.op_signed_in {
        println!("  op sign-in: ok (`op whoami`)");
    } else if let Some(err) = &status.op_sign_in_error {
        println!("  warning: op sign-in check failed: {err}");
        println!("  hint: unlock 1Password and run `op signin`");
    } else {
        println!("  warning: op sign-in check failed");
    }
    Ok(warning_count)
}

fn print_secret_store_doctor_summary(status: &SecretStoreDoctorStatus) {
    println!(
        "env secret store: {} (static configuration check)",
        status.backend
    );
    if !status.backend_supported {
        println!("  warning: unsupported secret-store backend");
        return;
    }
    if let Some(one_password) = &status.one_password {
        if !one_password.project_id_ok {
            println!("  warning: env.project_id is required for 1Password");
        }
        if !one_password.vault_ok {
            println!("  warning: env.onepassword.vault is required for 1Password");
        }
        println!("  live op checks: skipped (run `shk doctor env` to verify sign-in)");
    } else {
        println!("  backend: OS keyring (default)");
    }
}

fn print_env_file_statuses(env_files: &[EnvFileStatus]) {
    let plaintext = env_files
        .iter()
        .filter(|status| status.state == EnvFileState::Plaintext)
        .collect::<Vec<_>>();
    let mixed = env_files
        .iter()
        .filter(|status| status.state == EnvFileState::Mixed)
        .collect::<Vec<_>>();

    if plaintext.is_empty() && mixed.is_empty() {
        println!(
            "env: no plaintext .env / .env.* files (templates and .env.vault excluded) at repo root"
        );
    }
    if !plaintext.is_empty() {
        println!(
            "env: plaintext env files detected (review + prefer encryption / secret manager):"
        );
        for status in plaintext {
            println!("  - {} (unsafe by default)", status.name);
        }
        println!("  recommendation: encrypt env files or migrate secrets to a secret manager");
        println!("  recommendation: deny direct AI reads of .env files via tool-specific controls");
    }
    if !mixed.is_empty() {
        println!("env: encrypted env files contain plaintext values:");
        for status in mixed {
            let preview = status
                .plaintext_keys
                .iter()
                .take(5)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            let suffix = if status.plaintext_keys.len() > 5 {
                format!(" (+{} more)", status.plaintext_keys.len() - 5)
            } else {
                String::new()
            };
            println!(
                "  - {} ({} plaintext key(s): {preview}{suffix})",
                status.name,
                status.plaintext_keys.len()
            );
        }
        println!(
            "  recommendation: run `shk env encrypt <file> --in-place` after editing encrypted env files"
        );
    }
}

fn dotenv_encryption_state(content: &str) -> EnvFileEncryptionState {
    let mut saw_encrypted_value = false;
    let mut plaintext_keys = Vec::new();

    for raw_line in content.lines() {
        match classify_dotenv_line(raw_line) {
            DotenvLine::Skip => {}
            // Malformed lines, unparsable values, and private-key material make
            // the whole file untrusted: report it as plaintext.
            DotenvLine::Malformed
            | DotenvLine::Entry {
                private_key: true, ..
            }
            | DotenvLine::Entry {
                parse_error: true, ..
            } => return EnvFileEncryptionState::Plaintext,
            DotenvLine::Entry {
                encrypted: true, ..
            } => saw_encrypted_value = true,
            DotenvLine::Entry { key, .. } => plaintext_keys.push(key.to_string()),
        }
    }

    match (saw_encrypted_value, plaintext_keys.is_empty()) {
        (true, true) => EnvFileEncryptionState::FullyEncrypted,
        (true, false) => EnvFileEncryptionState::MixedPlaintext {
            keys: plaintext_keys,
        },
        _ => EnvFileEncryptionState::Plaintext,
    }
}

fn dotenv_value_without_wrapping_quotes(value: &str) -> Option<&str> {
    match value.chars().next() {
        Some(quote @ ('"' | '\'')) => {
            let rest = &value[quote.len_utf8()..];
            let end = rest.find(quote)?;
            let trailing = rest[end + quote.len_utf8()..].trim();
            if !trailing.is_empty() && !trailing.starts_with('#') {
                return None;
            }
            Some(&rest[..end])
        }
        _ => Some(
            value
                .split_once(" #")
                .map(|(before, _)| before.trim_end())
                .unwrap_or(value),
        ),
    }
}

fn is_dotenv_public_key_name(key: &str) -> bool {
    key == DOTENV_PUBLIC_KEY_PREFIX
        || key
            .strip_prefix(&format!("{DOTENV_PUBLIC_KEY_PREFIX}_"))
            .is_some_and(|suffix| !suffix.is_empty() && suffix.chars().all(is_env_key_char))
}

fn is_dotenv_private_key_name(key: &str) -> bool {
    key == DOTENV_PRIVATE_KEY_PREFIX
        || key
            .strip_prefix(&format!("{DOTENV_PRIVATE_KEY_PREFIX}_"))
            .is_some_and(|suffix| !suffix.is_empty() && suffix.chars().all(is_env_key_char))
}

fn is_env_key_char(ch: char) -> bool {
    ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_'
}

fn run_dotenvx(root: &Path) {
    let present: Vec<&str> = DOTENVX_HINT_FILES
        .iter()
        .copied()
        .filter(|p| root.join(p).is_file())
        .collect();

    if present.is_empty() {
        println!("dotenvx: no known dotenvx artifact files detected");
        return;
    }

    println!("dotenvx: artifact files detected:");
    for p in &present {
        match *p {
            DOTENVX_PRIVATE_KEY_FILE => {
                println!("  - {p} (private key material; do not commit or expose to AI tools)");
            }
            DOTENVX_VAULT_FILE => {
                println!("  - {p} (encrypted vault; keep private keys separate)");
            }
            _ => println!("  - {p}"),
        }
    }

    if root.join(DOTENVX_PRIVATE_KEY_FILE).is_file() {
        println!(
            "  warning: .env.keys should be stored outside the repository or explicitly ignored"
        );
    }
    if root.join(DOTENVX_VAULT_FILE).is_file() && !root.join(DOTENVX_PRIVATE_KEY_FILE).is_file() {
        println!("  ok: encrypted vault present without local .env.keys");
    }
}

pub fn has_managed_ai_hooks(root: &Path) -> bool {
    let paths = [
        root.join(".claude/settings.json"),
        root.join(".cursor/hooks.json"),
        root.join(".agents/hooks.json"),
        root.join(".github/hooks/shk-security.json"),
        root.join(".windsurf/hooks.json"),
        root.join(CONFIG_REL_PATH),
    ];
    for p in paths {
        if let Ok(s) = fs::read_to_string(&p)
            && (s.contains(MANAGED_MARKER_JSON)
                || s.contains(MANAGED_MARKER_SH)
                || (s.contains("shk scan")
                    && (s.contains("--hook-mode copilot") || s.contains("--hook-mode windsurf"))))
        {
            return true;
        }
    }
    false
}

pub fn has_shk_pre_commit(root: &Path) -> bool {
    git::discover_repo_root(root)
        .as_ref()
        .map(|r| r.join(".git/hooks/pre-commit"))
        .map(|p| {
            p.is_file()
                && fs::read_to_string(&p)
                    .unwrap_or_default()
                    .contains("shk scan --staged")
        })
        .unwrap_or(false)
}

pub fn collect_shk_executable_status() -> ShkExecutableStatus {
    collect_shk_executable_status_from(
        std::env::var_os("PATH").as_deref(),
        std::env::current_exe().ok(),
        std::env::var_os("PATHEXT").as_deref(),
    )
}

fn collect_shk_executable_status_from(
    path: Option<&OsStr>,
    current_executable: Option<PathBuf>,
    pathext: Option<&OsStr>,
) -> ShkExecutableStatus {
    let mut candidates = Vec::new();
    let mut resolved_seen = HashSet::new();
    let names = shk_executable_names(pathext);

    if let Some(path) = path {
        for dir in std::env::split_paths(path) {
            for name in &names {
                let candidate = dir.join(name);
                if !is_executable_file(&candidate) {
                    continue;
                }
                let resolved_path =
                    fs::canonicalize(&candidate).unwrap_or_else(|_| candidate.clone());
                if resolved_seen.insert(resolved_path.clone()) {
                    candidates.push(ShkExecutableCandidate {
                        path: candidate,
                        resolved_path,
                    });
                }
            }
        }
    }

    let current_resolved_path = current_executable
        .as_ref()
        .map(|path| fs::canonicalize(path).unwrap_or_else(|_| path.clone()));
    let current_matches_path_candidate = current_resolved_path.as_ref().is_some_and(|current| {
        candidates
            .iter()
            .any(|candidate| &candidate.resolved_path == current)
    });
    let active_on_path = candidates.first().map(|candidate| candidate.path.clone());
    ShkExecutableStatus {
        current_executable,
        current_resolved_path,
        current_matches_path_candidate,
        active_on_path,
        multiple_distinct: candidates.len() > 1,
        candidates,
    }
}

#[cfg(windows)]
fn shk_executable_names(pathext: Option<&OsStr>) -> Vec<OsString> {
    let pathext = pathext
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".to_string());
    let mut names = Vec::new();
    for extension in pathext.split(';') {
        let extension = extension.trim();
        if extension.is_empty() {
            continue;
        }
        let extension = if extension.starts_with('.') {
            extension.to_ascii_lowercase()
        } else {
            format!(".{}", extension.to_ascii_lowercase())
        };
        let name = OsString::from(format!("shk{extension}"));
        if !names.iter().any(|existing| existing == &name) {
            names.push(name);
        }
    }
    names
}

#[cfg(not(windows))]
fn shk_executable_names(_pathext: Option<&OsStr>) -> Vec<OsString> {
    vec![OsString::from("shk")]
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    fs::metadata(path)
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(windows)]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

#[cfg(not(any(unix, windows)))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

fn print_shk_executable_status(status: &ShkExecutableStatus) {
    println!("shk executable:");
    match &status.current_executable {
        Some(path) => println!("  running: {}", path.display()),
        None => println!("  running: unavailable"),
    }
    match &status.active_on_path {
        Some(path) => println!("  first on PATH: {}", path.display()),
        None => println!("  first on PATH: not found"),
    }
    if status.multiple_distinct {
        println!("  warning: multiple distinct shk executable installations detected:");
        for candidate in &status.candidates {
            println!("    - {}", candidate.path.display());
        }
    } else {
        println!("  PATH: OK (no shadowed shk executable detected)");
    }
}

pub fn run_workflows(root: &Path, fix: bool, json: bool) -> Result<()> {
    let fixes = if fix {
        safety::require_project_policy(root, "doctor workflows --fix")?;
        workflow_hardening::fix_all(root)?
    } else {
        Vec::new()
    };

    // Scan after any fix so the reported state reflects the result.
    let statuses = workflow_hardening::scan_workflows(root);

    if json {
        let v = serde_json::json!({
            "workflows": statuses,
            "fixes": fixes,
            "ok": statuses.iter().all(|s| s.ok()),
        });
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(());
    }

    print_workflow_status(&statuses);
    for fix_result in &fixes {
        println!(
            "Hardened {} checkout step(s) in {}",
            fix_result.fixed_steps, fix_result.relative_path
        );
    }
    Ok(())
}

fn print_workflow_status(statuses: &[workflow_hardening::WorkflowFileStatus]) {
    if statuses.is_empty() {
        println!("workflows: no GitHub Actions checkout steps found under .github/workflows");
        return;
    }
    if statuses.iter().all(|s| s.ok()) {
        println!("workflows: OK (all actions/checkout steps set persist-credentials: false)");
        return;
    }
    println!("workflows: actions/checkout steps missing persist-credentials: false:");
    for status in statuses {
        for step in status.findings() {
            println!("  - {}:{}", status.relative_path, step.line);
        }
    }
    println!("  fix with `shk doctor workflows --fix`");
}

struct DoctorReport {
    hook_ok: bool,
    ai_managed: bool,
    npm: npm_hardening::NpmHardeningStatus,
    workflows: Vec<workflow_hardening::WorkflowFileStatus>,
    executable: ShkExecutableStatus,
    ignore: IgnoreStatus,
    claude: ClaudePermissionsStatus,
    codex: CodexConfigSnapshot,
    env_files: Vec<EnvFileStatus>,
    secret_store: SecretStoreDoctorStatus,
    warning_count: usize,
}

fn collect_doctor_report(root: &Path) -> Result<DoctorReport> {
    let (policy, _) = Policy::load_from_dir(root)?;
    let hook_ok = has_shk_pre_commit(root);
    let ai_managed = has_managed_ai_hooks(root);
    let npm = npm_hardening::status(root);
    let workflows = workflow_hardening::scan_workflows(root);
    let executable = collect_shk_executable_status();
    let ignore = collect_ignore_status_with_policy(root, &policy)?;
    let claude = collect_claude_permissions_status(root);
    let codex = snapshot_codex_config(root);
    let env_files = collect_doctor_env_file_statuses(root);
    let secret_store = collect_secret_store_doctor_status(&policy);
    let warning_count = doctor_warning_count(DoctorWarningInputs {
        hook_ok,
        ai_managed,
        executable: &executable,
        ignore: &ignore,
        claude: &claude,
        codex: &codex.status,
        workflows: &workflows,
        npm: &npm,
        env_files: &env_files,
        secret_store: &secret_store,
    });
    Ok(DoctorReport {
        hook_ok,
        ai_managed,
        npm,
        workflows,
        executable,
        ignore,
        claude,
        codex,
        env_files,
        secret_store,
        warning_count,
    })
}

pub fn run_all(root: &Path, json: bool, strict: bool) -> Result<()> {
    let report = match collect_doctor_report(root) {
        Ok(report) => report,
        Err(err) if json => {
            let value = serde_json::json!({
                "ok": false,
                "strict": strict,
                "warningCount": 0,
                "error": {
                    "kind": "configuration",
                    "message": format!("{err:#}"),
                },
            });
            println!("{}", serde_json::to_string_pretty(&value)?);
            return Err(CliExit::silent(2).into());
        }
        Err(err) => return Err(err),
    };
    let warning_count = report.warning_count;
    if json {
        let v = serde_json::json!({
            "ok": warning_count == 0,
            "strict": strict,
            "warningCount": warning_count,
            "git_pre_commit_shk": report.hook_ok,
            "ai_managed_hooks": report.ai_managed,
            "shkExecutable": report.executable,
            "ignore": report.ignore,
            "claudePermissions": report.claude,
            "codexConfig": report.codex.status,
            "envFiles": report.env_files,
            "envSecretStore": report.secret_store,
            "workflows": {
                "files": report.workflows,
                "ok": report.workflows.iter().all(|s| s.ok()),
            },
            "npm_supply_chain_hardening": {
                "package_json_detected": report.npm.has_npm_projects(),
                "package_dirs": report.npm.package_dirs,
                "package_dirs_without_lockfile": report.npm.package_dirs_without_lockfile,
                "package_managers": report.npm.package_managers.iter().map(|manager| manager.as_str()).collect::<Vec<_>>(),
                "npmrc": report.npm.npmrc_path,
                "pnpm_workspace": report.npm.pnpm_workspace_path,
                "yarnrc": report.npm.yarnrc_path,
                "bunfig": report.npm.bunfig_path,
                "ignore_scripts": report.npm.ignore_scripts_ok,
                "min_release_age": report.npm.min_release_age,
                "min_release_age_ok": report.npm.min_release_age_ok,
                "pnpm_min_release_age_minutes": report.npm.pnpm_min_release_age_minutes,
                "pnpm_min_release_age_ok": report.npm.pnpm_min_release_age_ok,
                "yarn_min_release_age_minutes": report.npm.yarn_min_release_age_minutes,
                "yarn_min_release_age_ok": report.npm.yarn_min_release_age_ok,
                "bun_min_release_age_seconds": report.npm.bun_min_release_age_seconds,
                "bun_min_release_age_ok": report.npm.bun_min_release_age_ok,
                "package_scripts_ok": report.npm.package_scripts_ok(),
                "age_gates_ok": report.npm.age_gates_ok(),
                "dependabot": {
                    "configured": report.npm.dependabot.configured,
                    "config_path": report.npm.dependabot.config_path,
                    "cooldown_days": report.npm.dependabot.cooldown_days,
                    "cooldown_ok": report.npm.dependabot.cooldown_ok,
                },
                "renovate": {
                    "configured": report.npm.renovate.configured,
                    "config_path": report.npm.renovate.config_path,
                    "cooldown_days": report.npm.renovate.cooldown_days,
                    "cooldown_ok": report.npm.renovate.cooldown_ok,
                },
                "dependency_bot_cooldown_ok": report.npm.dependency_bot_cooldown_ok(),
                "ok": report.npm.ok(),
            },
        });
        println!("{}", serde_json::to_string_pretty(&v)?);
        return finish_doctor(strict, warning_count);
    }
    println!("doctor:");
    println!(
        "  Git pre-commit (shk): {}",
        if report.hook_ok {
            "detected"
        } else {
            "not installed"
        }
    );
    println!(
        "  AI managed hooks (shk): {}",
        if report.ai_managed {
            "present"
        } else {
            "not found — run `shk hooks install-ai`"
        }
    );
    println!();
    print_shk_executable_status(&report.executable);
    println!();
    print_ignore_status(&report.ignore.missing_patterns);
    print_claude_permissions_status(&report.claude);
    print_codex_config_snapshot(&report.codex);
    println!();
    print_secret_store_doctor_summary(&report.secret_store);
    print_env_file_statuses(&report.env_files);
    println!();
    print_workflow_status(&report.workflows);
    println!();
    print_npm_hardening_check(&report.npm);
    println!();
    if warning_count == 0 {
        println!("doctor summary: OK (no advisory warnings)");
    } else {
        println!("doctor summary: {warning_count} advisory warning(s)");
        if strict {
            println!("doctor strict: failing because advisory warnings were reported");
        }
    }
    finish_doctor(strict, warning_count)
}

struct DoctorWarningInputs<'a> {
    hook_ok: bool,
    ai_managed: bool,
    executable: &'a ShkExecutableStatus,
    ignore: &'a IgnoreStatus,
    claude: &'a ClaudePermissionsStatus,
    codex: &'a CodexConfigStatus,
    workflows: &'a [workflow_hardening::WorkflowFileStatus],
    npm: &'a npm_hardening::NpmHardeningStatus,
    env_files: &'a [EnvFileStatus],
    secret_store: &'a SecretStoreDoctorStatus,
}

fn doctor_warning_count(inputs: DoctorWarningInputs<'_>) -> usize {
    let mut warnings = 0usize;
    warnings += usize::from(!inputs.hook_ok);
    warnings += usize::from(!inputs.ai_managed);
    warnings += usize::from(inputs.executable.multiple_distinct);
    warnings += usize::from(!inputs.ignore.missing_patterns.is_empty());
    if inputs.claude.settings_exists {
        warnings += usize::from(!inputs.claude.deny_ok);
        warnings += usize::from(!inputs.claude.sandbox_ok);
    }
    if inputs.codex.config_exists {
        warnings += usize::from(!inputs.codex.hooks_enabled);
        warnings += usize::from(!inputs.codex.sandbox_ok);
        warnings += usize::from(!inputs.codex.approval_ok);
    }
    warnings += usize::from(inputs.workflows.iter().any(|status| !status.ok()));
    warnings += usize::from(!inputs.npm.ok());
    warnings += env_file_warning_count(inputs.env_files);
    warnings += inputs.secret_store.warning_count;
    warnings
}

fn env_file_warning_count(env_files: &[EnvFileStatus]) -> usize {
    usize::from(
        env_files
            .iter()
            .any(|status| status.state == EnvFileState::Plaintext),
    ) + usize::from(
        env_files
            .iter()
            .any(|status| status.state == EnvFileState::Mixed),
    )
}

fn collect_secret_store_doctor_status(policy: &Policy) -> SecretStoreDoctorStatus {
    let backend = policy.env.secret_store.clone();
    match policy.env.secret_store.parse::<SecretStoreBackend>() {
        Ok(SecretStoreBackend::Keyring) => SecretStoreDoctorStatus {
            backend,
            backend_supported: true,
            warning_count: 0,
            live_checks_performed: false,
            one_password: None,
        },
        Err(_) => SecretStoreDoctorStatus {
            backend,
            backend_supported: false,
            warning_count: 1,
            live_checks_performed: false,
            one_password: None,
        },
        Ok(SecretStoreBackend::OnePassword) => {
            let project_id_ok = policy
                .env
                .project_id
                .as_ref()
                .is_some_and(|value| !value.trim().is_empty());
            let vault_ok = policy
                .env
                .onepassword
                .vault
                .as_ref()
                .is_some_and(|value| !value.trim().is_empty());
            SecretStoreDoctorStatus {
                backend,
                backend_supported: true,
                warning_count: usize::from(!project_id_ok) + usize::from(!vault_ok),
                live_checks_performed: false,
                one_password: Some(OnePasswordDoctorSummary {
                    project_id_ok,
                    vault_ok,
                }),
            }
        }
    }
}

fn onepassword_warning_count(
    policy: &Policy,
    status: &crate::env_store::OnePasswordDoctorStatus,
) -> usize {
    let mut warnings = 0usize;
    warnings += usize::from(
        policy
            .env
            .project_id
            .as_ref()
            .is_none_or(|value| value.trim().is_empty()),
    );
    warnings += usize::from(
        policy
            .env
            .onepassword
            .vault
            .as_ref()
            .is_none_or(|value| value.trim().is_empty()),
    );
    warnings += usize::from(status.op_resolution_error.is_some());
    if status.op_resolution_error.is_none() {
        warnings += usize::from(
            status
                .op_version
                .as_ref()
                .is_some_and(|_| !status.op_version_ok)
                || status.op_version_error.is_some(),
        );
        warnings += usize::from(!status.op_signed_in);
    }
    warnings
}

fn finish_doctor(strict: bool, warning_count: usize) -> Result<()> {
    if strict && warning_count > 0 {
        return Err(CliExit::silent(1).into());
    }
    Ok(())
}

pub fn doctor_ignore_path(path: Option<PathBuf>) -> PathBuf {
    path.unwrap_or_else(|| PathBuf::from("."))
}

fn print_npm_hardening_check(status: &npm_hardening::NpmHardeningStatus) {
    if !status.has_npm_projects() {
        println!("npm hardening: no package.json detected under project");
        return;
    }

    if status.ok() {
        println!(
            "npm hardening: OK ({} package.json file(s), lockfile and cooldown present)",
            status.package_dirs.len()
        );
        return;
    }

    println!(
        "npm hardening: package.json detected, missing recommended package-manager hardening:"
    );
    if !status.package_scripts_ok() {
        println!("  - {}: ignore-scripts=true", status.npmrc_path.display());
    }
    if status
        .package_managers
        .contains(&npm_hardening::PackageManager::Npm)
        && !status.min_release_age_ok
    {
        match status.min_release_age {
            Some(days) => println!(
                "  - {}: min-release-age=7 days (current: {days} days)",
                status.npmrc_path.display()
            ),
            None => println!(
                "  - {}: min-release-age=7 days",
                status.npmrc_path.display()
            ),
        }
    }
    if status
        .package_managers
        .contains(&npm_hardening::PackageManager::Pnpm)
        && !status.pnpm_min_release_age_ok
    {
        match status.pnpm_min_release_age_minutes {
            Some(minutes) => println!(
                "  - {}: minimumReleaseAge=10080 minutes for pnpm (current: {minutes} minutes)",
                status.pnpm_workspace_path.display()
            ),
            None => println!(
                "  - {}: minimumReleaseAge=10080 minutes for pnpm",
                status.pnpm_workspace_path.display()
            ),
        }
    }
    if status
        .package_managers
        .contains(&npm_hardening::PackageManager::Yarn)
        && !status.yarn_min_release_age_ok
    {
        match status.yarn_min_release_age_minutes {
            Some(minutes) => println!(
                "  - {}: npmMinimalAgeGate=10080 minutes for Yarn (current: {minutes} minutes)",
                status.yarnrc_path.display()
            ),
            None => println!(
                "  - {}: npmMinimalAgeGate=10080 minutes for Yarn",
                status.yarnrc_path.display()
            ),
        }
    }
    if status
        .package_managers
        .contains(&npm_hardening::PackageManager::Bun)
        && !status.bun_min_release_age_ok
    {
        match status.bun_min_release_age_seconds {
            Some(seconds) => println!(
                "  - {}: install.minimumReleaseAge=604800 seconds for Bun (current: {seconds} seconds)",
                status.bunfig_path.display()
            ),
            None => println!(
                "  - {}: install.minimumReleaseAge=604800 seconds for Bun",
                status.bunfig_path.display()
            ),
        }
    }
    if !status.package_dirs_without_lockfile.is_empty() {
        println!("  - lockfile missing for package.json directory:");
        for dir in &status.package_dirs_without_lockfile {
            println!("    - {}", dir.display());
        }
    }
    if !status.dependency_bot_cooldown_ok() {
        println!("  - Renovate minimumReleaseAge=7 days or Dependabot cooldown.default-days=7");
        print_dependency_bot_status("dependabot", &status.dependabot);
        print_dependency_bot_status("renovate", &status.renovate);
    }
    if !status.package_scripts_ok() || !status.age_gates_ok() {
        println!(
            "  recommendation: run `shk init --yes` from the project root to apply package-manager settings"
        );
    }
    if !status.package_dirs_without_lockfile.is_empty() {
        println!("  recommendation: commit a package lockfile manually");
    }
    if !status.dependency_bot_cooldown_ok() {
        println!("  recommendation: add update-bot cooldown manually");
    }
}

fn print_dependency_bot_status(name: &str, status: &npm_hardening::DependencyBotStatus) {
    match (&status.config_path, status.cooldown_days) {
        (Some(path), Some(days)) => {
            println!("    {name}: {} cooldown is {days} day(s)", path.display())
        }
        (Some(path), None) => println!("    {name}: {} has no cooldown", path.display()),
        (None, _) => println!("    {name}: config not found"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[cfg(unix)]
    fn make_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;

        fs::write(path, "#!/bin/sh\nexit 0\n").unwrap();
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn executable_status_detects_distinct_path_entries_without_running_them() {
        let first = tempdir().unwrap();
        let second = tempdir().unwrap();
        make_executable(&first.path().join("shk"));
        make_executable(&second.path().join("shk"));
        let path = std::env::join_paths([first.path(), second.path()]).unwrap();

        let status = collect_shk_executable_status_from(Some(&path), None, None);

        assert!(status.multiple_distinct);
        assert_eq!(status.candidates.len(), 2);
        assert_eq!(status.active_on_path, Some(first.path().join("shk")));
    }

    #[cfg(unix)]
    #[test]
    fn executable_status_deduplicates_symlinks_to_the_same_binary() {
        use std::os::unix::fs::symlink;

        let real = tempdir().unwrap();
        let linked = tempdir().unwrap();
        let binary = real.path().join("shk");
        make_executable(&binary);
        symlink(&binary, linked.path().join("shk")).unwrap();
        let path = std::env::join_paths([linked.path(), real.path()]).unwrap();

        let status = collect_shk_executable_status_from(Some(&path), Some(binary.clone()), None);

        assert!(!status.multiple_distinct);
        assert_eq!(status.candidates.len(), 1);
        assert_eq!(status.active_on_path, Some(linked.path().join("shk")));
        assert!(status.current_matches_path_candidate);
        assert_eq!(
            status.current_resolved_path,
            Some(fs::canonicalize(binary).unwrap())
        );
    }

    #[cfg(unix)]
    #[test]
    fn executable_status_keeps_running_binary_mismatch_informational() {
        let running = tempdir().unwrap();
        let path_dir = tempdir().unwrap();
        let running_binary = running.path().join("shk");
        make_executable(&running_binary);
        make_executable(&path_dir.path().join("shk"));
        let path = std::env::join_paths([path_dir.path()]).unwrap();

        let status =
            collect_shk_executable_status_from(Some(&path), Some(running_binary.clone()), None);

        assert!(!status.multiple_distinct);
        assert!(!status.current_matches_path_candidate);
        assert_eq!(
            status.current_resolved_path,
            Some(fs::canonicalize(running_binary).unwrap())
        );
    }

    #[cfg(windows)]
    #[test]
    fn executable_status_respects_windows_pathext_order() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("shk.exe"), "native").unwrap();
        fs::write(dir.path().join("shk.cmd"), "wrapper").unwrap();
        let path = std::env::join_paths([dir.path()]).unwrap();

        let status =
            collect_shk_executable_status_from(Some(&path), None, Some(OsStr::new(".EXE;.CMD")));

        assert!(status.multiple_distinct);
        assert_eq!(status.candidates.len(), 2);
        assert_eq!(status.active_on_path, Some(dir.path().join("shk.exe")));
    }

    #[cfg(windows)]
    #[test]
    fn executable_status_does_not_warn_for_single_npm_cmd_wrapper() {
        let path_dir = tempdir().unwrap();
        let running_dir = tempdir().unwrap();
        fs::write(path_dir.path().join("shk.cmd"), "wrapper").unwrap();
        let running_binary = running_dir.path().join("shk.exe");
        fs::write(&running_binary, "native").unwrap();
        let path = std::env::join_paths([path_dir.path()]).unwrap();

        let status = collect_shk_executable_status_from(
            Some(&path),
            Some(running_binary),
            Some(OsStr::new(".CMD")),
        );

        assert!(!status.multiple_distinct);
        assert_eq!(status.candidates.len(), 1);
        assert!(!status.current_matches_path_candidate);
    }

    #[test]
    fn doctor_ignore_path_defaults_to_dot() {
        assert_eq!(doctor_ignore_path(None), PathBuf::from("."));
        assert_eq!(
            doctor_ignore_path(Some(PathBuf::from("/tmp/proj"))),
            PathBuf::from("/tmp/proj")
        );
    }

    #[test]
    fn has_managed_ai_hooks_detects_windsurf_command_marker() {
        let dir = tempdir().unwrap();
        assert!(
            !has_managed_ai_hooks(dir.path()),
            "empty project has no managed hooks"
        );

        fs::create_dir_all(dir.path().join(".windsurf")).unwrap();
        // Windsurf entries carry no `_shk_managed` marker; detection relies on
        // the `--hook-mode windsurf` command string.
        fs::write(
            dir.path().join(".windsurf/hooks.json"),
            r#"{"hooks":{"pre_run_command":[{"command":"shk scan --hook-mode windsurf","show_output":true}]}}"#,
        )
        .unwrap();

        assert!(
            has_managed_ai_hooks(dir.path()),
            "managed Windsurf Cascade hooks should be detected"
        );
    }

    #[test]
    fn normalize_ignore_pattern_skips_comments_and_blanks() {
        assert_eq!(normalize_ignore_pattern("  "), None);
        assert_eq!(normalize_ignore_pattern("# comment"), None);
        assert_eq!(normalize_ignore_pattern("  .env  "), Some(".env"));
    }

    #[test]
    fn ignore_pattern_covers_directory_and_env_aliases() {
        assert!(ignore_pattern_covers("secrets/**", "secrets/**"));
        assert!(ignore_pattern_covers(".env*", ".env"));
        assert!(directory_pattern_covers("secrets", "secrets/**"));
        assert!(!directory_pattern_covers(".env", "secrets/**"));
    }

    #[test]
    fn normalize_ignore_fix_targets_rejects_unknown() {
        let err = normalize_ignore_fix_targets(&["not-a-real-ignore".into()]).unwrap_err();
        assert!(err.to_string().contains("unknown ignore fix target"));
    }

    #[test]
    fn collect_env_file_statuses_reports_key_names_per_file() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join(".env"), "API_KEY=plain\nDB_URL=postgres\n").unwrap();
        fs::write(
            dir.path().join(".env.production"),
            "DOTENV_PUBLIC_KEY=pk\nSECRET=encrypted:abc\nPLAIN=value\n",
        )
        .unwrap();
        fs::write(
            dir.path().join(".env.ci"),
            "DOTENV_PUBLIC_KEY=pk\nTOKEN=encrypted:abc\n",
        )
        .unwrap();
        fs::write(dir.path().join(".env.example"), "DEMO=ok\n").unwrap();
        fs::write(dir.path().join(".env.sample"), "DEMO=ok\n").unwrap();
        fs::write(dir.path().join(".env.keys"), "PLACEHOLDER=ok\n").unwrap();
        fs::write(dir.path().join(".env.vault"), "PLACEHOLDER=ok\n").unwrap();

        let files = collect_env_file_statuses(dir.path());
        assert_eq!(
            files.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(),
            vec![".env", ".env.ci", ".env.production"],
            "sorted, templates and dotenvx metadata files excluded"
        );

        let plain = &files[0];
        assert_eq!(plain.state, EnvFileState::Plaintext);
        assert_eq!(plain.plaintext_keys, vec!["API_KEY", "DB_URL"]);
        assert_eq!(plain.encrypted_key_count, 0);

        let encrypted = &files[1];
        assert_eq!(encrypted.state, EnvFileState::Encrypted);
        assert!(encrypted.plaintext_keys.is_empty());
        assert_eq!(encrypted.encrypted_key_count, 1);

        let mixed = &files[2];
        assert_eq!(mixed.state, EnvFileState::Mixed);
        assert_eq!(mixed.plaintext_keys, vec!["PLAIN"]);
        assert_eq!(mixed.encrypted_key_count, 1);
    }

    #[test]
    fn doctor_env_statuses_include_dotenvx_private_key_file() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join(".env.keys"), "PLACEHOLDER=example\n").unwrap();
        fs::write(dir.path().join(".env.vault"), "encrypted metadata\n").unwrap();

        let files = collect_doctor_env_file_statuses(dir.path());

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, ".env.keys");
        assert_eq!(files[0].state, EnvFileState::Plaintext);
    }

    #[test]
    fn dotenv_key_summary_counts_private_key_material_as_plaintext() {
        let (keys, encrypted) = dotenv_key_summary(
            "DOTENV_PUBLIC_KEY=pk\nDOTENV_PRIVATE_KEY=encrypted:looks-encrypted\nTOKEN=encrypted:abc\n",
        );
        assert_eq!(keys, vec!["DOTENV_PRIVATE_KEY"]);
        assert_eq!(encrypted, 1);
    }

    #[test]
    fn ignore_fix_target_statuses_reflect_existing_files() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join(".gitignore"), "node_modules/\n").unwrap();
        let statuses = ignore_fix_target_statuses(dir.path());
        let gitignore = statuses
            .iter()
            .find(|s| s.name == ".gitignore")
            .expect(".gitignore status");
        assert!(gitignore.exists);
        let cursor = statuses
            .iter()
            .find(|s| s.name == ".cursorignore")
            .expect(".cursorignore status");
        assert!(!cursor.exists);
    }
}
