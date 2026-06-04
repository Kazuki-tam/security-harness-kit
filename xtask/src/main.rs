use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::Deserialize;
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

const DEFAULT_SOURCE_REF: &str = "8863af47d64c3681422523e36837957c74d4af4b";
const DEFAULT_SOURCE: &str = concat!(
    "https://raw.githubusercontent.com/gitleaks/gitleaks/",
    "8863af47d64c3681422523e36837957c74d4af4b",
    "/config/gitleaks.toml"
);
const DEFAULT_OUTPUT: &str = "crates/shk-rules/src/gitleaks_rules.rs";
const SKIP_RULE_IDS: &[&str] = &[
    // shk keeps a tuned generic detector. The upstream version has a very large
    // false-positive allowlist and can exceed Rust regex's compiled-size limit.
    "generic-api-key",
    // shk keeps a tuned OpenAI detector; importing the upstream rule produces
    // duplicate findings for the same token value.
    "openai-api-key",
    // These upstream patterns allow very large repetitions that exceed Rust
    // regex's compiled-size limit in the generated static rule set.
    "pypi-upload-token",
    "vault-batch-token",
];

// Files where the bare version string (e.g. "0.3.7") appears.
const BARE_VERSION_FILES: &[&str] = &[
    "Cargo.toml",
    "crates/shk-cli/Cargo.toml",
    "crates/shk-core/Cargo.toml",
    "apps/shk-desktop/package.json",
    "apps/shk-desktop/src-tauri/tauri.conf.json",
    "apps/shk-desktop/src-tauri/Cargo.toml",
];

// Files where the v-prefixed version string (e.g. "v0.3.7") appears.
const V_VERSION_FILES: &[&str] = &[
    "README.md",
    "docs/installation.md",
    "docs/ci.md",
    "crates/shk-cli/src/skills/shk.md",
    ".claude/skills/shk.md",
];

#[derive(Debug, Deserialize)]
struct GitleaksConfig {
    #[serde(default)]
    rules: Vec<GitleaksTomlRule>,
}

#[derive(Debug, Deserialize)]
struct GitleaksTomlRule {
    id: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    regex: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default, rename = "secretGroup")]
    secret_group: Option<usize>,
    #[serde(default)]
    entropy: Option<f64>,
    #[serde(default)]
    keywords: Vec<String>,
    #[serde(default)]
    allowlists: Vec<GitleaksTomlAllowlist>,
}

#[derive(Debug, Deserialize)]
struct GitleaksTomlAllowlist {
    #[serde(default)]
    condition: Option<String>,
    #[serde(default, rename = "regexTarget")]
    regex_target: Option<String>,
    #[serde(default)]
    regexes: Vec<String>,
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    stopwords: Vec<String>,
}

struct ImportArgs {
    input: String,
    output: PathBuf,
    source_ref: String,
    check: bool,
}

fn main() -> Result<()> {
    let mut raw = env::args().skip(1);
    let command = match raw.next() {
        Some(c) => c,
        None => bail!(
            "usage: cargo xtask <command> [args...]\ncommands: import-gitleaks-rules, bump-version"
        ),
    };
    match command.as_str() {
        "import-gitleaks-rules" => {
            let args = parse_import_args(raw)?;
            import_gitleaks_rules(args)
        }
        "bump-version" => {
            let version = parse_bump_version_args(raw)?;
            bump_version(&version)
        }
        "--help" | "-h" => {
            println!(
                "usage: cargo xtask <command> [args...]\ncommands: import-gitleaks-rules, bump-version"
            );
            Ok(())
        }
        other => bail!("unknown xtask command `{other}`"),
    }
}

fn parse_import_args(mut raw: impl Iterator<Item = String>) -> Result<ImportArgs> {
    let mut args = ImportArgs {
        input: DEFAULT_SOURCE.to_string(),
        output: PathBuf::from(DEFAULT_OUTPUT),
        source_ref: DEFAULT_SOURCE_REF.to_string(),
        check: false,
    };

    while let Some(arg) = raw.next() {
        match arg.as_str() {
            "--check" => args.check = true,
            "--input" => {
                args.input = raw.next().context("--input requires a value")?;
            }
            "--output" => {
                args.output = PathBuf::from(raw.next().context("--output requires a value")?);
            }
            "--source-ref" => {
                args.source_ref = raw.next().context("--source-ref requires a value")?;
            }
            "--help" | "-h" => {
                println!(
                    "usage: cargo xtask import-gitleaks-rules [--check] [--input <path-or-url>] [--output <path>] [--source-ref <ref>]"
                );
                std::process::exit(0);
            }
            _ => bail!("unknown argument `{arg}`"),
        }
    }

    Ok(args)
}

fn parse_bump_version_args(mut raw: impl Iterator<Item = String>) -> Result<String> {
    let version = raw
        .next()
        .context("usage: cargo xtask bump-version <version>  (e.g. 0.3.7)")?;
    if let Some(extra) = raw.next() {
        bail!("unexpected argument `{extra}`");
    }
    Ok(version)
}

fn bump_version(new_version: &str) -> Result<()> {
    let new_version = new_version.strip_prefix('v').unwrap_or(new_version);
    let version_re = Regex::new(r"^\d+\.\d+\.\d+$").unwrap();
    if !version_re.is_match(new_version) {
        bail!("invalid version: expected X.Y.Z, got `{new_version}`");
    }

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("xtask has no parent directory")?
        .to_path_buf();

    let old_version = read_workspace_version(&root)?;
    if old_version == new_version {
        bail!("new version is the same as current ({old_version})");
    }

    println!("bumping {old_version} -> {new_version}");

    let mut total = 0usize;
    for file in BARE_VERSION_FILES {
        let n = replace_in_file(&root.join(file), &old_version, new_version)?;
        if n > 0 {
            println!("  {file} ({n})");
        }
        total += n;
    }
    for file in V_VERSION_FILES {
        let n = replace_in_file(
            &root.join(file),
            &format!("v{old_version}"),
            &format!("v{new_version}"),
        )?;
        if n > 0 {
            println!("  {file} ({n})");
        }
        total += n;
    }

    println!(
        "done - {total} replacement(s) across {} file(s)",
        BARE_VERSION_FILES.len() + V_VERSION_FILES.len()
    );
    Ok(())
}

fn read_workspace_version(root: &Path) -> Result<String> {
    let manifest =
        fs::read_to_string(root.join("Cargo.toml")).context("read workspace Cargo.toml")?;
    let manifest: toml::Value = toml::from_str(&manifest).context("parse workspace Cargo.toml")?;
    let version = manifest
        .get("workspace")
        .and_then(|workspace| workspace.get("package"))
        .and_then(|package| package.get("version"))
        .and_then(|version| version.as_str())
        .context("version not found in workspace Cargo.toml")?
        .to_string();
    Ok(version)
}

fn replace_in_file(path: &Path, old: &str, new: &str) -> Result<usize> {
    let content = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let count = content.matches(old).count();
    if count > 0 {
        fs::write(path, content.replace(old, new))
            .with_context(|| format!("write {}", path.display()))?;
    }
    Ok(count)
}

fn import_gitleaks_rules(args: ImportArgs) -> Result<()> {
    let input = read_input(&args.input)?;
    let (generated, skipped) = generate(&input, &args.input, &args.source_ref)?;
    let generated = rustfmt_generated(&generated)?;

    if args.check {
        let existing = fs::read_to_string(&args.output)
            .with_context(|| format!("read {}", args.output.display()))?;
        if existing != generated {
            bail!("{} is not up to date", args.output.display());
        }
    } else {
        if let Some(parent) = args.output.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create output directory {}", parent.display()))?;
        }
        fs::write(&args.output, generated)
            .with_context(|| format!("write {}", args.output.display()))?;
    }

    for item in skipped.iter().take(50) {
        eprintln!("{item}");
    }
    if skipped.len() > 50 {
        eprintln!("... {} more skipped items", skipped.len() - 50);
    }
    eprintln!(
        "generated {} gitleaks rules",
        count_generated_rules(&args.output)?
    );
    Ok(())
}

fn rustfmt_generated(source: &str) -> Result<String> {
    let path = env::temp_dir().join(format!(
        "shk-gitleaks-rules-{}-{}.rs",
        std::process::id(),
        chrono_like_counter()
    ));
    {
        let mut file =
            fs::File::create(&path).with_context(|| format!("create {}", path.display()))?;
        file.write_all(source.as_bytes())
            .with_context(|| format!("write {}", path.display()))?;
    }

    let output = Command::new("rustfmt")
        .args(["--edition", "2024", "--emit", "stdout"])
        .arg(&path)
        .output()
        .context("run rustfmt for generated gitleaks rules")?;
    let _ = fs::remove_file(&path);

    if !output.status.success() {
        bail!(
            "rustfmt failed for generated gitleaks rules: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let formatted = String::from_utf8(output.stdout).context("rustfmt output must be UTF-8")?;
    Ok(strip_rustfmt_stdout_header(&formatted).to_string())
}

fn strip_rustfmt_stdout_header(formatted: &str) -> &str {
    let Some((first, rest)) = formatted.split_once('\n') else {
        return formatted;
    };
    if first.starts_with('/') && first.ends_with(".rs:") {
        return rest.strip_prefix('\n').unwrap_or(rest);
    }
    formatted
}

fn chrono_like_counter() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default()
}

fn count_generated_rules(path: &Path) -> Result<usize> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    Ok(text.matches("GitleaksRule {").count())
}

fn read_input(source: &str) -> Result<String> {
    if source.starts_with("http://") || source.starts_with("https://") {
        return ureq::get(source)
            .call()
            .with_context(|| format!("fetch {source}"))?
            .body_mut()
            .read_to_string()
            .context("read response body");
    }
    fs::read_to_string(source).with_context(|| format!("read {source}"))
}

fn generate(toml_text: &str, source: &str, source_ref: &str) -> Result<(String, Vec<String>)> {
    let config: GitleaksConfig = toml::from_str(toml_text).context("parse gitleaks TOML")?;
    let mut skipped = Vec::new();
    let mut rules = Vec::new();

    for rule in &config.rules {
        if let Some(expr) = rule_expr(rule, &mut skipped) {
            rules.push(expr);
        }
    }

    let mut out = String::new();
    writeln!(
        out,
        "// This file is @generated by xtask import-gitleaks-rules. Do not edit manually."
    )?;
    writeln!(out, "//")?;
    writeln!(
        out,
        "// Rules adapted from gitleaks (https://github.com/gitleaks/gitleaks)."
    )?;
    writeln!(out, "// Copyright (c) 2019 Zachary Rice")?;
    writeln!(out, "// SPDX-License-Identifier: MIT")?;
    writeln!(out, "// Source: {source}")?;
    writeln!(out, "// Source ref: {source_ref}")?;
    writeln!(out, "// Generated rules: {}", rules.len())?;
    writeln!(out, "// Skipped rules/regexes: {}", skipped.len())?;
    writeln!(out)?;
    writeln!(out, "use super::{{")?;
    writeln!(
        out,
        "    AllowlistCondition, AllowlistTarget, GitleaksAllowlist, GitleaksRule,"
    )?;
    writeln!(out, "}};")?;
    writeln!(out, "use once_cell::sync::Lazy;")?;
    writeln!(out, "use regex::Regex;")?;
    writeln!(out)?;
    writeln!(out, "#[rustfmt::skip]")?;
    writeln!(
        out,
        "static GITLEAKS_RULES: Lazy<Vec<GitleaksRule>> = Lazy::new(|| {{"
    )?;
    writeln!(out, "    vec![")?;
    for rule in rules {
        writeln!(out, "{rule},")?;
    }
    writeln!(out, "    ]")?;
    writeln!(out, "}});")?;
    writeln!(out)?;
    writeln!(out, "pub(super) fn rules() -> &'static [GitleaksRule] {{")?;
    writeln!(out, "    &GITLEAKS_RULES")?;
    writeln!(out, "}}")?;

    Ok((out, skipped))
}

fn rule_expr(rule: &GitleaksTomlRule, skipped: &mut Vec<String>) -> Option<String> {
    if SKIP_RULE_IDS.contains(&rule.id.as_str()) {
        skipped.push(format!("rule skipped by policy: {}", rule.id));
        return None;
    }

    let Some(pattern) = &rule.regex else {
        skipped.push(format!("rule skipped without content regex: {}", rule.id));
        return None;
    };
    let pattern = adapt_regex(pattern);
    if let Some(reason) = validate_regex(&pattern) {
        skipped.push(format!("rule skipped ({reason}): {}", rule.id));
        return None;
    }

    let allowlists = if rule.allowlists.is_empty() {
        "Vec::new()".to_string()
    } else {
        let items: Vec<String> = rule
            .allowlists
            .iter()
            .map(|allowlist| allowlist_expr(allowlist, skipped))
            .collect();
        format!("vec![{}]", items.join(", "))
    };

    let mut out = String::new();
    writeln!(out, "        GitleaksRule {{").ok()?;
    writeln!(
        out,
        "            id: {},",
        rust_str(&normalize_rule_id(&rule.id))
    )
    .ok()?;
    writeln!(
        out,
        "            description: {},",
        rust_str(rule.description.as_deref().unwrap_or(&rule.id))
    )
    .ok()?;
    writeln!(
        out,
        "            re: Lazy::new(|| Regex::new({}).expect(\"valid generated gitleaks regex\")),",
        rust_str(&pattern)
    )
    .ok()?;
    writeln!(
        out,
        "            path: {},",
        option_regex(rule.path.as_deref(), skipped, "path")
    )
    .ok()?;
    writeln!(
        out,
        "            secret_group: {},",
        option_usize(rule.secret_group)
    )
    .ok()?;
    writeln!(out, "            entropy: {},", option_f32(rule.entropy)).ok()?;
    writeln!(
        out,
        "            keywords: {},",
        rust_str_array(&rule.keywords)
    )
    .ok()?;
    writeln!(out, "            allowlists: {allowlists},").ok()?;
    write!(out, "        }}").ok()?;
    Some(out)
}

fn allowlist_expr(allowlist: &GitleaksTomlAllowlist, skipped: &mut Vec<String>) -> String {
    format!(
        "GitleaksAllowlist {{ condition: {}, target: {}, regexes: {}, paths: {}, stopwords: {}, }}",
        condition_expr(allowlist.condition.as_deref()),
        target_expr(allowlist.regex_target.as_deref()),
        regex_vec_expr(&allowlist.regexes, skipped),
        regex_vec_expr(&allowlist.paths, skipped),
        rust_str_array(&allowlist.stopwords),
    )
}

fn regex_vec_expr(patterns: &[String], skipped: &mut Vec<String>) -> String {
    let mut parts = Vec::new();
    for pattern in patterns {
        let pattern = adapt_regex(pattern);
        if let Some(reason) = validate_regex(&pattern) {
            skipped.push(format!("allowlist regex skipped ({reason}): {pattern}"));
            continue;
        }
        parts.push(format!(
            "Lazy::new(|| Regex::new({}).expect(\"valid generated gitleaks allowlist regex\"))",
            rust_str(&pattern)
        ));
    }
    if parts.is_empty() {
        "Vec::new()".to_string()
    } else {
        format!("vec![{}]", parts.join(", "))
    }
}

fn option_regex(pattern: Option<&str>, skipped: &mut Vec<String>, label: &str) -> String {
    let Some(pattern) = pattern else {
        return "None".to_string();
    };
    let pattern = adapt_regex(pattern);
    if let Some(reason) = validate_regex(&pattern) {
        skipped.push(format!("{label} regex skipped ({reason}): {pattern}"));
        return "None".to_string();
    }
    format!(
        "Some(Lazy::new(|| Regex::new({}).expect(\"valid generated gitleaks path regex\")))",
        rust_str(&pattern)
    )
}

fn validate_regex(pattern: &str) -> Option<String> {
    for marker in ["(?=", "(?!", "(?<=", "(?<!", "(?>", "(?|", "\\K"] {
        if pattern.contains(marker) {
            return Some(marker.to_string());
        }
    }
    if has_backreference(pattern) {
        return Some("backreference".to_string());
    }
    if pattern.contains("(?P ") {
        return Some("malformed named group".to_string());
    }
    Regex::new(pattern).err().map(|err| err.to_string())
}

fn has_backreference(pattern: &str) -> bool {
    let mut escaped = false;
    for c in pattern.chars() {
        if escaped {
            if ('1'..='9').contains(&c) {
                return true;
            }
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
        }
    }
    false
}

fn adapt_regex(pattern: &str) -> String {
    let pattern = replace_unescaped(pattern, "{{", r"\{\{");
    replace_unescaped(&pattern, "}}", r"\}\}")
}

fn replace_unescaped(input: &str, needle: &str, replacement: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i..].starts_with(needle) && !is_escaped(input, i) {
            out.push_str(replacement);
            i += needle.len();
        } else {
            let c = input[i..].chars().next().expect("valid char boundary");
            out.push(c);
            i += c.len_utf8();
        }
    }
    out
}

fn is_escaped(input: &str, idx: usize) -> bool {
    let mut count = 0;
    for b in input[..idx].bytes().rev() {
        if b == b'\\' {
            count += 1;
        } else {
            break;
        }
    }
    count % 2 == 1
}

fn normalize_rule_id(upstream_id: &str) -> String {
    let mut out = String::from("secret.gitleaks.");
    let mut prev_dash = false;
    for c in upstream_id.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-') {
            out.push(c.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
}

fn condition_expr(value: Option<&str>) -> &'static str {
    match value {
        Some(value) if value.eq_ignore_ascii_case("AND") => "AllowlistCondition::And",
        _ => "AllowlistCondition::Or",
    }
}

fn target_expr(value: Option<&str>) -> &'static str {
    match value.unwrap_or("secret").to_ascii_lowercase().as_str() {
        "match" => "AllowlistTarget::Match",
        "line" => "AllowlistTarget::Line",
        _ => "AllowlistTarget::Secret",
    }
}

fn option_usize(value: Option<usize>) -> String {
    value
        .map(|value| format!("Some({value})"))
        .unwrap_or_else(|| "None".to_string())
}

fn option_f32(value: Option<f64>) -> String {
    value
        .map(|value| format!("Some({value:?}_f32)"))
        .unwrap_or_else(|| "None".to_string())
}

fn rust_str_array(values: &[String]) -> String {
    if values.is_empty() {
        return "&[]".to_string();
    }
    format!(
        "&[{}]",
        values
            .iter()
            .map(|value| rust_str(value))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn rust_str(value: &str) -> String {
    let mut hashes = String::new();
    while value.contains(&format!("\"{hashes}")) {
        hashes.push('#');
    }
    format!("r{hashes}\"{value}\"{hashes}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parse_bump_version_args_accepts_single_version() {
        let args = vec!["v1.2.3".to_string()].into_iter();

        let version = parse_bump_version_args(args).expect("valid version argument");

        assert_eq!(version, "v1.2.3");
    }

    #[test]
    fn parse_bump_version_args_rejects_extra_arguments() {
        let args = vec!["1.2.3".to_string(), "--extra".to_string()].into_iter();

        let err = parse_bump_version_args(args).expect_err("extra arguments should fail");

        assert!(err.to_string().contains("unexpected argument"));
    }

    #[test]
    fn read_workspace_version_uses_workspace_package_version() {
        let root = tempdir().expect("temp dir");
        fs::write(
            root.path().join("Cargo.toml"),
            r#"
[package]
version = "9.9.9"

[workspace]

[workspace.package]
version = "1.2.3"
"#,
        )
        .expect("write manifest");

        let version = read_workspace_version(root.path()).expect("read version");

        assert_eq!(version, "1.2.3");
    }

    #[test]
    fn generate_outputs_valid_super_import() {
        let input = r#"
[[rules]]
id = "demo-token"
regex = '''demo-[a-z]+'''
"#;

        let (generated, skipped) = generate(input, "test", "test-ref").expect("generate rules");

        assert!(skipped.is_empty(), "{skipped:?}");
        assert!(generated.contains("use super::{"));
    }

    #[test]
    fn strip_rustfmt_stdout_header_removes_path_prefix() {
        let formatted = "/tmp/foo.rs:\n\n// code\n";
        assert_eq!(strip_rustfmt_stdout_header(formatted), "// code\n");
        assert_eq!(
            strip_rustfmt_stdout_header("// no header\n"),
            "// no header\n"
        );
    }

    #[test]
    fn parse_import_args_defaults_and_check_flag() {
        let args = parse_import_args(["--check".to_string()].into_iter()).unwrap();
        assert!(args.check);
        assert_eq!(args.source_ref, DEFAULT_SOURCE_REF);
        assert_eq!(args.output, PathBuf::from(DEFAULT_OUTPUT));
    }

    #[test]
    fn generate_skips_policy_blocked_rules() {
        let input = r#"
[[rules]]
id = "generic-api-key"
regex = '''x+'''
[[rules]]
id = "demo-token"
regex = '''demo-[a-z]+'''
"#;
        let (_, skipped) = generate(input, "test", "ref").unwrap();
        assert!(
            skipped.iter().any(|line| line.contains("generic-api-key")),
            "{skipped:?}"
        );
    }

    #[test]
    fn import_gitleaks_rules_check_passes_when_output_matches() {
        let dir = tempdir().expect("tempdir");
        let input_path = dir.path().join("gitleaks.toml");
        let output = dir.path().join("gitleaks_rules.rs");
        fs::write(
            &input_path,
            r#"
[[rules]]
id = "demo-token"
regex = '''demo-[a-z]+'''
"#,
        )
        .unwrap();
        let args = ImportArgs {
            input: input_path.to_string_lossy().into_owned(),
            output: output.clone(),
            source_ref: "test-ref".into(),
            check: false,
        };
        import_gitleaks_rules(args).expect("write generated output");
        import_gitleaks_rules(ImportArgs {
            input: input_path.to_string_lossy().into_owned(),
            output,
            source_ref: "test-ref".into(),
            check: true,
        })
        .expect("check should pass for matching output");
    }

    #[test]
    fn bump_version_rejects_invalid_version_format() {
        let err = bump_version("not-semver").expect_err("invalid version");
        assert!(err.to_string().contains("invalid version"));
    }

    #[test]
    fn read_input_reads_local_file() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("rules.toml");
        fs::write(&path, "[[rules]]\nid = \"x\"\n").unwrap();
        let body = read_input(path.to_str().unwrap()).unwrap();
        assert!(body.contains("[[rules]]"));
    }
}
