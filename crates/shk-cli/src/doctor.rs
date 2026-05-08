use crate::safety;
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
const DOTENVX_ENCRYPTED_VALUE_PREFIX: &str = "encrypted:";
const DOTENVX_PUBLIC_KEY_PREFIX: &str = "DOTENV_PUBLIC_KEY";
const DOTENVX_PRIVATE_KEY_PREFIX: &str = "DOTENV_PRIVATE_KEY";
const CODEX_RISKY_SANDBOX_MODE: &str = "danger-full-access";
const CODEX_RISKY_APPROVAL_POLICY: &str = "never";
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
    for e in fs::read_dir(root)? {
        let e = e?;
        let name = e.file_name().to_string_lossy().to_string();
        if (name == ".env" || (name.starts_with(".env.") && name != ".env.example"))
            && e.path().is_file()
        {
            let content = fs::read_to_string(e.path()).unwrap_or_default();
            if !is_dotenvx_encrypted_env(&content) {
                env_files.push((name, e.path(), content));
            }
        }
    }
    if env_files.is_empty() {
        println!("env: no plaintext .env / .env.* (except .env.example) at repo root");
    } else {
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

    if dotenvx {
        run_dotenvx(root);
    }
    Ok(())
}

fn is_dotenvx_encrypted_env(content: &str) -> bool {
    let mut saw_encrypted_value = false;

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        let Some((raw_key, raw_value)) = line.split_once('=') else {
            return false;
        };
        let key = raw_key.trim();
        if key.is_empty() || is_dotenvx_private_key_name(key) {
            return false;
        }
        if is_dotenvx_public_key_name(key) {
            continue;
        }

        let Some(value) = dotenv_value_without_wrapping_quotes(raw_value.trim()) else {
            return false;
        };
        if value.starts_with(DOTENVX_ENCRYPTED_VALUE_PREFIX) {
            saw_encrypted_value = true;
            continue;
        }

        return false;
    }

    saw_encrypted_value
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

fn is_dotenvx_public_key_name(key: &str) -> bool {
    key == DOTENVX_PUBLIC_KEY_PREFIX
        || key
            .strip_prefix(&format!("{DOTENVX_PUBLIC_KEY_PREFIX}_"))
            .is_some_and(|suffix| !suffix.is_empty() && suffix.chars().all(is_env_key_char))
}

fn is_dotenvx_private_key_name(key: &str) -> bool {
    key == DOTENVX_PRIVATE_KEY_PREFIX
        || key
            .strip_prefix(&format!("{DOTENVX_PRIVATE_KEY_PREFIX}_"))
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
        json: false,
        fail_on_override: None,
        use_pre_commit_threshold: false,
        include_context: false,
        include_binary: false,
        follow_symlinks: false,
    }
}

fn has_managed_ai_hooks(root: &Path) -> bool {
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

pub fn run_all(root: &Path, json: bool) -> Result<()> {
    let repo = git::discover_repo_root(root);
    let hook_ok = repo
        .as_ref()
        .map(|r| r.join(".git/hooks/pre-commit"))
        .map(|p| {
            p.is_file()
                && fs::read_to_string(&p)
                    .unwrap_or_default()
                    .contains("shk scan --staged")
        })
        .unwrap_or(false);
    let ai_managed = has_managed_ai_hooks(root);
    if json {
        let v = serde_json::json!({
            "git_pre_commit_shk": hook_ok,
            "ai_managed_hooks": ai_managed,
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
    Ok(())
}

pub fn doctor_ignore_path(path: Option<PathBuf>) -> PathBuf {
    path.unwrap_or_else(|| PathBuf::from("."))
}
