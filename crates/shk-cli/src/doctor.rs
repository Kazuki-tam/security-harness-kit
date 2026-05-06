use anyhow::Result;
use serde_json::Value;
use shk_core::git;
use shk_core::policy::Policy;
use shk_core::scanner::{ScanOptions, scan_string};
use shk_integrations::{MANAGED_MARKER_JSON, MANAGED_MARKER_SH};
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
const CLAUDE_REQUIRED_DENY_PATTERNS: &[&str] = &[".env", ".env.*", "secrets/**", "credentials/**"];

pub fn run_ignore(root: &Path, fix: bool) -> Result<()> {
    let (policy, _) = Policy::load_from_dir(root)?;
    let required = policy.doctor.ignore.required_patterns.clone();
    let gi_path = root.join(".gitignore");
    let mut combined = String::new();
    if gi_path.is_file() {
        combined.push_str(&fs::read_to_string(&gi_path)?);
    }
    for p in IGNORE_CANDIDATES {
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

    let missing: Vec<&str> = CLAUDE_REQUIRED_DENY_PATTERNS
        .iter()
        .copied()
        .filter(|pattern| !claude_deny_covers(&denies, pattern))
        .collect();

    if missing.is_empty() {
        println!("claude permissions: OK (sensitive reads denied)");
    } else {
        println!("claude permissions: missing recommended Read deny entries:");
        for pat in missing {
            println!("  - Read(./{pat})");
        }
    }
}

fn claude_deny_covers(denies: &[&str], pattern: &str) -> bool {
    denies.iter().any(|entry| {
        let normalized = entry
            .trim()
            .trim_start_matches("Read(")
            .trim_end_matches(')')
            .trim_start_matches("./");
        normalized == pattern || normalized.trim_end_matches('/') == pattern.trim_end_matches('/')
    })
}

fn pattern_present(hay: &str, pat: &str) -> bool {
    let needle = pat.trim();
    hay.lines().any(|l| {
        l.trim() == needle || l.trim_end_matches('/').trim() == needle.trim_end_matches('/')
    })
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
            env_files.push((name, e.path()));
        }
    }
    if env_files.is_empty() {
        println!("env: no plaintext .env / .env.* (except .env.example) at repo root");
    } else {
        println!("env: plaintext env files detected (review + prefer dotenvx / secret manager):");
        for (name, path) in env_files {
            let content = fs::read_to_string(&path).unwrap_or_default();
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
        if let Ok(s) = fs::read_to_string(&p) {
            if s.contains(MANAGED_MARKER_JSON) || s.contains(MANAGED_MARKER_SH) {
                return true;
            }
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
            "not found — run `shk hooks install-ai` (see AGENTS.md)"
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
