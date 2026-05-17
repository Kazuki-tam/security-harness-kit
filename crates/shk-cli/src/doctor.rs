use crate::{npm_hardening, safety};
use anyhow::Result;
use serde_json::Value;
use shk_core::git;
use shk_core::policy::Policy;
use shk_core::scanner::{ScanOptions, scan_string};
use shk_integrations::{
    MANAGED_MARKER_JSON, MANAGED_MARKER_SH, claude_deny_entry_covers,
    claude_recommended_deny_entries,
};
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
const CODEX_RISKY_SANDBOX_MODE: &str = "danger-full-access";
const CODEX_RISKY_APPROVAL_POLICY: &str = "never";

#[derive(Debug, Eq, PartialEq)]
enum EnvFileEncryptionState {
    Plaintext,
    FullyEncrypted,
    MixedPlaintext { keys: Vec<String> },
}

pub fn run_ignore(root: &Path, fix: bool) -> Result<()> {
    if fix {
        safety::require_project_policy(root, "doctor ignore --fix")?;
        safety::ensure_writable_path_allowed(&root.join(".gitignore"))?;
    }
    let (policy, _) = Policy::load_from_dir(root)?;
    let required = policy.doctor.ignore.effective_required_patterns().to_vec();
    let gi_path = root.join(".gitignore");
    let mut combined = String::new();
    if gi_path.is_file() {
        combined.push_str(&fs::read_to_string(&gi_path)?);
    }
    for p in IGNORE_CANDIDATES {
        if *p == ".gitignore" {
            continue;
        }
        let fp = root.join(p);
        if fp.is_file() {
            combined.push('\n');
            combined.push_str(&fs::read_to_string(&fp)?);
        }
    }
    let mut missing: Vec<&str> = Vec::new();
    for pat in &required {
        if !pattern_present(&combined, pat) {
            missing.push(pat.as_str());
        }
    }
    if missing.is_empty() {
        println!("ignore: OK (required patterns present in ignore files)");
    } else {
        println!("ignore: missing recommended patterns:");
        for m in &missing {
            println!("  - {m}");
        }
    }
    if fix && !missing.is_empty() {
        let path = root.join(".gitignore");
        let mut body = if path.is_file() {
            fs::read_to_string(&path)?
        } else {
            String::new()
        };
        if !body.is_empty() && !body.ends_with('\n') {
            body.push('\n');
        }
        body.push_str("\n# shk: appended required patterns\n");
        for m in &missing {
            body.push_str(m);
            body.push('\n');
        }
        fs::write(&path, body)?;
        println!("Wrote updates to {}", path.display());
    }
    run_claude_permissions_check(root);
    run_codex_config_check(root);
    Ok(())
}

fn run_claude_permissions_check(root: &Path) {
    let path = root.join(".claude/settings.json");
    if !path.is_file() {
        return;
    }

    let Ok(text) = fs::read_to_string(&path) else {
        println!("claude permissions: unable to read .claude/settings.json");
        return;
    };
    let Ok(value) = serde_json::from_str::<Value>(&text) else {
        println!("claude permissions: unable to parse .claude/settings.json");
        return;
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

    let required = claude_recommended_deny_entries();
    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|entry| !claude_deny_covers(&denies, entry))
        .collect();

    if missing.is_empty() {
        println!("claude permissions: OK (recommended action deny entries present)");
    } else {
        println!("claude permissions: missing recommended action deny entries:");
        for pat in missing {
            println!("  - {pat}");
        }
    }
}

fn claude_deny_covers(denies: &[&str], required: &str) -> bool {
    denies
        .iter()
        .any(|entry| claude_deny_entry_covers(entry, required))
}

fn run_codex_config_check(root: &Path) {
    let path = root.join(".codex/config.toml");
    if !path.is_file() {
        return;
    }

    let Ok(text) = fs::read_to_string(&path) else {
        println!("codex config: unable to read .codex/config.toml");
        return;
    };
    let Ok(value) = toml::from_str::<toml::Value>(&text) else {
        println!("codex config: unable to parse .codex/config.toml");
        return;
    };

    let hooks_enabled = value
        .get("features")
        .and_then(|features| features.get("codex_hooks"))
        .and_then(toml::Value::as_bool)
        .unwrap_or(false);
    if hooks_enabled {
        println!("codex config: hooks feature enabled");
    } else {
        println!("codex config: hooks feature not enabled (`features.codex_hooks = true`)");
    }

    print_codex_string_setting(&value, "sandbox_mode", Some(CODEX_RISKY_SANDBOX_MODE));
    print_codex_string_setting(&value, "approval_policy", Some(CODEX_RISKY_APPROVAL_POLICY));
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
    let (_policy, _) = Policy::load_from_dir(root)?;
    let mut env_files = Vec::new();
    let mut mixed_env_files = Vec::new();
    for e in fs::read_dir(root)? {
        let e = e?;
        let name = e.file_name().to_string_lossy().to_string();
        if (name == ".env" || (name.starts_with(".env.") && name != ".env.example"))
            && e.path().is_file()
        {
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
        println!("env: no plaintext .env / .env.* (except .env.example) at repo root");
    } else if !env_files.is_empty() {
        println!("env: plaintext env files detected (review + prefer dotenvx / secret manager):");
        for (name, _path, content) in env_files {
            let findings = scan_string(root, &name, &content, env_scan_options())?
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
    Ok(())
}

fn dotenv_encryption_state(content: &str) -> EnvFileEncryptionState {
    let mut saw_encrypted_value = false;
    let mut plaintext_keys = Vec::new();

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        let Some((raw_key, raw_value)) = line.split_once('=') else {
            return EnvFileEncryptionState::Plaintext;
        };
        let key = raw_key.trim();
        if key.is_empty() || is_dotenv_private_key_name(key) {
            return EnvFileEncryptionState::Plaintext;
        }
        if is_dotenv_public_key_name(key) {
            continue;
        }

        let Some(value) = dotenv_value_without_wrapping_quotes(raw_value.trim()) else {
            return EnvFileEncryptionState::Plaintext;
        };
        if value.starts_with(DOTENV_ENCRYPTED_VALUE_PREFIX) {
            saw_encrypted_value = true;
            continue;
        }

        plaintext_keys.push(key.to_string());
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

fn env_scan_options() -> ScanOptions {
    ScanOptions {
        staged: false,
        git_history: false,
        git_history_ref: None,
        git_history_since: None,
        git_history_max_commits: None,
        json: false,
        fail_on_override: None,
        use_pre_commit_threshold: false,
        include_context: false,
        include_binary: false,
        follow_symlinks: false,
    }
}

pub(crate) fn has_managed_ai_hooks(root: &Path) -> bool {
    let paths = [
        root.join(".claude/settings.json"),
        root.join(".cursor/hooks.json"),
        root.join(".codex/config.toml"),
    ];
    for p in paths {
        if let Ok(s) = fs::read_to_string(&p)
            && (s.contains(MANAGED_MARKER_JSON) || s.contains(MANAGED_MARKER_SH))
        {
            return true;
        }
    }
    false
}

pub(crate) fn has_shk_pre_commit(root: &Path) -> bool {
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

pub fn run_all(root: &Path, json: bool) -> Result<()> {
    let hook_ok = has_shk_pre_commit(root);
    let ai_managed = has_managed_ai_hooks(root);
    let npm = npm_hardening::status(root);
    if json {
        let v = serde_json::json!({
            "git_pre_commit_shk": hook_ok,
            "ai_managed_hooks": ai_managed,
            "npm_supply_chain_hardening": {
                "package_json_detected": npm.has_npm_projects(),
                "package_dirs": npm.package_dirs,
                "package_dirs_without_lockfile": npm.package_dirs_without_lockfile,
                "package_managers": npm.package_managers.iter().map(|manager| manager.as_str()).collect::<Vec<_>>(),
                "npmrc": npm.npmrc_path,
                "pnpm_workspace": npm.pnpm_workspace_path,
                "yarnrc": npm.yarnrc_path,
                "bunfig": npm.bunfig_path,
                "ignore_scripts": npm.ignore_scripts_ok,
                "min_release_age": npm.min_release_age,
                "min_release_age_ok": npm.min_release_age_ok,
                "pnpm_min_release_age_minutes": npm.pnpm_min_release_age_minutes,
                "pnpm_min_release_age_ok": npm.pnpm_min_release_age_ok,
                "yarn_min_release_age_minutes": npm.yarn_min_release_age_minutes,
                "yarn_min_release_age_ok": npm.yarn_min_release_age_ok,
                "bun_min_release_age_seconds": npm.bun_min_release_age_seconds,
                "bun_min_release_age_ok": npm.bun_min_release_age_ok,
                "package_scripts_ok": npm.package_scripts_ok(),
                "age_gates_ok": npm.age_gates_ok(),
                "dependabot": {
                    "configured": npm.dependabot.configured,
                    "config_path": npm.dependabot.config_path,
                    "cooldown_days": npm.dependabot.cooldown_days,
                    "cooldown_ok": npm.dependabot.cooldown_ok,
                },
                "renovate": {
                    "configured": npm.renovate.configured,
                    "config_path": npm.renovate.config_path,
                    "cooldown_days": npm.renovate.cooldown_days,
                    "cooldown_ok": npm.renovate.cooldown_ok,
                },
                "dependency_bot_cooldown_ok": npm.dependency_bot_cooldown_ok(),
                "ok": npm.ok(),
            },
        });
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(());
    }
    println!("doctor:");
    println!(
        "  Git pre-commit (shk): {}",
        if hook_ok { "detected" } else { "not installed" }
    );
    println!(
        "  AI managed hooks (shk): {}",
        if ai_managed {
            "present"
        } else {
            "not found — run `shk hooks install-ai`"
        }
    );
    println!();
    run_ignore(root, false)?;
    println!();
    run_env(root, false)?;
    println!();
    run_npm_hardening_check(root);
    Ok(())
}

pub fn doctor_ignore_path(path: Option<PathBuf>) -> PathBuf {
    path.unwrap_or_else(|| PathBuf::from("."))
}

fn run_npm_hardening_check(root: &Path) {
    let status = npm_hardening::status(root);
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
