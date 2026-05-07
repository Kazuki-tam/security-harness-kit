use crate::args::{SecretProviderArg, SecretsPushArgs, SecretsPushModeArg};
use crate::audit_log;
use crate::exit::CliExit;
use anyhow::{Context, Result, anyhow, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};
use shk_core::policy::{Policy, Severity};
use std::collections::BTreeSet;
use std::io::{IsTerminal, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tempfile::NamedTempFile;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Provider {
    Aws,
    Gcp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PushMode {
    Blob,
    PerKey,
}

#[derive(Debug)]
struct PushConfig {
    provider: Provider,
    mode: PushMode,
    target: Option<String>,
    target_prefix: Option<String>,
    source: PathBuf,
    region: Option<String>,
    project: Option<String>,
    location: Option<String>,
    audit: bool,
    confirm: bool,
    create_if_missing: bool,
    strict: bool,
    no_scan: bool,
    dry_run: bool,
    yes: bool,
    expected_env: Option<String>,
}

#[derive(Debug)]
struct SecretEntry {
    key: String,
    value: Zeroizing<Vec<u8>>,
}

#[derive(Debug)]
enum SecretPayload {
    Blob { bytes: Zeroizing<Vec<u8>> },
    PerKey { entries: Vec<SecretEntry> },
}

#[derive(Debug, Default)]
struct LintReport {
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct PushResult {
    operation: String,
    version_id: Option<String>,
    status: String,
    keys_total: Option<usize>,
    keys_succeeded: Option<usize>,
    failed_key: Option<String>,
    error: Option<String>,
}

trait SecretPusher {
    fn ensure_available(&self) -> Result<()>;
    fn exists(&self, cfg: &PushConfig, target: &str) -> Result<bool>;
    fn push_blob(
        &self,
        cfg: &PushConfig,
        target: &str,
        payload: &[u8],
        create: bool,
    ) -> Result<PushResult>;
}

pub fn push(cwd: &Path, args: SecretsPushArgs) -> Result<()> {
    let repo_root = project_root(cwd)?;
    let (policy, _) = Policy::load_from_dir(&repo_root)?;
    let cfg = resolve_config(&repo_root, &policy, args)?;
    let source_label = source_label(&repo_root, &cfg.source);
    let payload = load_payload(&cfg)?;
    let payload_sha256 = payload_sha256(&payload);
    let bytes = payload_bytes_len(&payload);
    let lint = lint_payload(&payload, cfg.expected_env.as_deref());

    for warning in &lint.warnings {
        eprintln!("warning: {warning}");
    }
    if cfg.strict && !lint.warnings.is_empty() {
        return Err(CliExit::message(1, "strict secret payload lint failed").into());
    }

    if !cfg.no_scan {
        run_pii_scan(&source_label, &payload)?;
    }

    validate_targets(&cfg, &payload)?;

    if cfg.dry_run {
        print_dry_run(&cfg, &source_label, bytes, &payload);
        return Ok(());
    }

    if cfg.confirm && !cfg.yes {
        confirm_write(&cfg, &source_label, &payload)?;
    }

    let pusher: Box<dyn SecretPusher> = match cfg.provider {
        Provider::Aws => Box::new(AwsCliPusher),
        Provider::Gcp => Box::new(GcpCliPusher),
    };
    pusher.ensure_available()?;

    let result = execute_push(pusher.as_ref(), &cfg, &payload)?;
    if cfg.audit {
        append_audit(
            &repo_root,
            &cfg,
            &source_label,
            bytes,
            &payload_sha256,
            &result,
        )?;
    }
    print_result(&cfg, &result);
    if result.status != "success" {
        return Err(CliExit::message(2, "secret push failed").into());
    }
    Ok(())
}

fn resolve_config(repo_root: &Path, policy: &Policy, args: SecretsPushArgs) -> Result<PushConfig> {
    let profile = args
        .profile
        .as_ref()
        .map(|name| {
            policy
                .secrets
                .profiles
                .get(name)
                .ok_or_else(|| anyhow!("invalid profile `{name}`"))
        })
        .transpose()?;
    let provider = match args.provider {
        Some(provider) => provider_from_arg(provider),
        None => profile
            .and_then(|p| p.provider.as_deref())
            .map(parse_provider)
            .transpose()?
            .ok_or_else(|| {
                anyhow!("missing provider; pass --provider or configure profile.provider")
            })?,
    };
    let cli_mode = if args.per_key {
        Some(PushMode::PerKey)
    } else {
        args.mode.map(mode_from_arg)
    };
    let mode = match cli_mode {
        Some(mode) => mode,
        None => profile
            .and_then(|p| p.mode.as_deref())
            .map(parse_mode)
            .transpose()?
            .unwrap_or(PushMode::Blob),
    };
    let source = args
        .source
        .or_else(|| profile.and_then(|p| p.source.as_ref().map(PathBuf::from)))
        .ok_or_else(|| anyhow!("missing source; pass --from or configure profile.source"))?;
    let source = if source.is_absolute() {
        source
    } else {
        repo_root.join(source)
    };
    Ok(PushConfig {
        provider,
        mode,
        target: args
            .target
            .or_else(|| profile.and_then(|p| p.target.clone())),
        target_prefix: args
            .target_prefix
            .or_else(|| profile.and_then(|p| p.target_prefix.clone())),
        source,
        region: args
            .region
            .or_else(|| profile.and_then(|p| p.region.clone())),
        project: args
            .project
            .or_else(|| profile.and_then(|p| p.project.clone())),
        location: args
            .location
            .or_else(|| profile.and_then(|p| p.location.clone())),
        audit: args.audit || profile.and_then(|p| p.audit).unwrap_or(false),
        confirm: args.confirm || profile.and_then(|p| p.confirm).unwrap_or(false),
        create_if_missing: args.create_if_missing
            || profile.and_then(|p| p.create_if_missing).unwrap_or(false),
        strict: args.strict,
        no_scan: args.no_scan,
        dry_run: args.dry_run,
        yes: args.yes,
        expected_env: args
            .expected_env
            .or_else(|| profile.and_then(|p| p.expected_env.clone())),
    })
}

fn provider_from_arg(arg: SecretProviderArg) -> Provider {
    match arg {
        SecretProviderArg::Aws => Provider::Aws,
        SecretProviderArg::Gcp => Provider::Gcp,
    }
}

fn parse_provider(raw: &str) -> Result<Provider> {
    match raw {
        "aws" => Ok(Provider::Aws),
        "gcp" => Ok(Provider::Gcp),
        _ => bail!("unsupported secrets provider `{raw}`; supported: aws, gcp"),
    }
}

fn mode_from_arg(arg: SecretsPushModeArg) -> PushMode {
    match arg {
        SecretsPushModeArg::Blob => PushMode::Blob,
        SecretsPushModeArg::PerKey => PushMode::PerKey,
    }
}

fn parse_mode(raw: &str) -> Result<PushMode> {
    match raw {
        "blob" => Ok(PushMode::Blob),
        "per-key" | "per_key" => Ok(PushMode::PerKey),
        _ => bail!("unsupported secrets push mode `{raw}`; supported: blob, per-key"),
    }
}

fn load_payload(cfg: &PushConfig) -> Result<SecretPayload> {
    let mut bytes = Zeroizing::new(
        std::fs::read(&cfg.source).with_context(|| format!("read {}", cfg.source.display()))?,
    );
    if bytes.is_empty() {
        bail!("source {} is empty", cfg.source.display());
    }
    match cfg.mode {
        PushMode::Blob => Ok(SecretPayload::Blob { bytes }),
        PushMode::PerKey => {
            let body = String::from_utf8(bytes.to_vec())
                .with_context(|| format!("parse {} as utf-8 dotenv", cfg.source.display()))?;
            bytes.zeroize();
            let entries = parse_dotenv_entries(&body)?;
            if entries.is_empty() {
                bail!("no dotenv entries found in {}", cfg.source.display());
            }
            Ok(SecretPayload::PerKey { entries })
        }
    }
}

fn parse_dotenv_entries(body: &str) -> Result<Vec<SecretEntry>> {
    let mut seen = BTreeSet::new();
    let mut entries = Vec::new();
    for (idx, raw_line) in body.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        let Some((raw_key, raw_value)) = line.split_once('=') else {
            bail!("invalid dotenv line {}: expected KEY=value", idx + 1);
        };
        let key = raw_key.trim();
        validate_env_key(key).with_context(|| format!("invalid key on line {}", idx + 1))?;
        if !seen.insert(key.to_string()) {
            bail!("duplicate dotenv key `{key}`");
        }
        let value = parse_env_value(raw_value)
            .with_context(|| format!("parse value for {key} on line {}", idx + 1))?;
        entries.push(SecretEntry {
            key: key.to_string(),
            value: Zeroizing::new(value.into_bytes()),
        });
    }
    Ok(entries)
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

fn validate_env_key(key: &str) -> Result<()> {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        bail!("empty dotenv key");
    };
    if !(first.is_ascii_uppercase() || first == '_') {
        bail!("dotenv key `{key}` must start with A-Z or _");
    }
    if !chars.all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_') {
        bail!("dotenv key `{key}` must match [A-Z_][A-Z0-9_]*");
    }
    Ok(())
}

fn validate_targets(cfg: &PushConfig, payload: &SecretPayload) -> Result<()> {
    match (cfg.mode, payload) {
        (PushMode::Blob, SecretPayload::Blob { .. }) => {
            if cfg.target.is_none() || cfg.target_prefix.is_some() {
                bail!("blob mode requires --target and must not use --target-prefix");
            }
        }
        (PushMode::PerKey, SecretPayload::PerKey { entries }) => {
            let Some(prefix) = &cfg.target_prefix else {
                bail!("per-key mode requires --target-prefix");
            };
            if cfg.target.is_some() {
                bail!("per-key mode must not use --target");
            }
            for entry in entries {
                validate_provider_target(cfg.provider, &format!("{prefix}{}", entry.key))?;
            }
        }
        _ => bail!("internal payload mode mismatch"),
    }
    if let Some(target) = &cfg.target {
        validate_provider_target(cfg.provider, target)?;
    }
    Ok(())
}

fn validate_provider_target(provider: Provider, target: &str) -> Result<()> {
    if target.is_empty() {
        bail!("target must not be empty");
    }
    match provider {
        Provider::Aws => {
            if !target
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || "/_+=.@-".contains(ch))
            {
                bail!("AWS secret target `{target}` contains unsupported characters");
            }
        }
        Provider::Gcp => {
            if target.len() > 255
                || !target
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
            {
                bail!(
                    "GCP secret target `{target}` must use letters, digits, hyphen, or underscore"
                );
            }
        }
    }
    Ok(())
}

fn lint_payload(payload: &SecretPayload, expected_env: Option<&str>) -> LintReport {
    let mut warnings = Vec::new();
    if let SecretPayload::PerKey { entries } = payload {
        let expected = expected_env.map(|s| s.to_ascii_lowercase());
        for entry in entries {
            if entry.value.is_empty() {
                warnings.push(format!("{} has an empty value", entry.key));
            }
            let value = String::from_utf8_lossy(&entry.value);
            if entry.key == "DEBUG" && value.eq_ignore_ascii_case("true") {
                warnings.push("DEBUG=true is usually not intended for production secrets".into());
            }
            if entry.key.starts_with("LOCAL_") {
                warnings.push(format!("{} looks local-only", entry.key));
            }
            if entry.key == "NODE_ENV" {
                if let Some(expected) = &expected {
                    if value.to_ascii_lowercase() != *expected {
                        warnings.push(format!("NODE_ENV does not match expected_env `{expected}`"));
                    }
                } else if value.eq_ignore_ascii_case("development") {
                    warnings
                        .push("NODE_ENV=development may not match the target environment".into());
                }
            }
        }
    }
    LintReport { warnings }
}

fn run_pii_scan(source_label: &str, payload: &SecretPayload) -> Result<()> {
    let text = Zeroizing::new(payload_scan_text(payload));
    let cfg = shk_rules::RuleEngineConfig {
        secrets: false,
        pii: true,
        pii_languages: vec!["en".into(), "ja".into()],
        env: false,
        internal_terms: false,
    };
    let findings: Vec<_> = shk_rules::scan_content(&text, source_label, &cfg)
        .into_iter()
        .filter(|m| Severity::from(m.severity).meets_threshold(Severity::Medium))
        .collect();
    if findings.is_empty() {
        return Ok(());
    }
    let ids = findings
        .iter()
        .map(|m| m.rule_id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(", ");
    Err(CliExit::message(1, format!("pre-push PII scan failed: {ids}")).into())
}

fn payload_scan_text(payload: &SecretPayload) -> String {
    match payload {
        SecretPayload::Blob { bytes } => String::from_utf8_lossy(bytes).into_owned(),
        SecretPayload::PerKey { entries } => entries
            .iter()
            .map(|entry| format!("{}={}", entry.key, String::from_utf8_lossy(&entry.value)))
            .collect::<Vec<_>>()
            .join("\n"),
    }
}

fn execute_push(
    pusher: &dyn SecretPusher,
    cfg: &PushConfig,
    payload: &SecretPayload,
) -> Result<PushResult> {
    match payload {
        SecretPayload::Blob { bytes } => {
            let target = cfg.target.as_deref().expect("validated target");
            push_one(pusher, cfg, target, bytes)
        }
        SecretPayload::PerKey { entries } => {
            let prefix = cfg
                .target_prefix
                .as_deref()
                .expect("validated target_prefix");
            let mut succeeded = 0usize;
            for entry in entries {
                let target = format!("{prefix}{}", entry.key);
                match push_one(pusher, cfg, &target, &entry.value) {
                    Ok(_) => succeeded += 1,
                    Err(err) => {
                        return Ok(PushResult {
                            operation: "per-key".into(),
                            version_id: None,
                            status: "partial_failure".into(),
                            keys_total: Some(entries.len()),
                            keys_succeeded: Some(succeeded),
                            failed_key: Some(entry.key.clone()),
                            error: Some(err.to_string()),
                        });
                    }
                }
            }
            Ok(PushResult {
                operation: "per-key".into(),
                version_id: None,
                status: "success".into(),
                keys_total: Some(entries.len()),
                keys_succeeded: Some(succeeded),
                failed_key: None,
                error: None,
            })
        }
    }
}

fn push_one(
    pusher: &dyn SecretPusher,
    cfg: &PushConfig,
    target: &str,
    payload: &[u8],
) -> Result<PushResult> {
    let exists = pusher.exists(cfg, target)?;
    if !exists && !cfg.create_if_missing {
        return Err(CliExit::message(
            2,
            format!(
                "secret target `{target}` does not exist; pass --create-if-missing to create it"
            ),
        )
        .into());
    }
    pusher.push_blob(cfg, target, payload, !exists)
}

struct AwsCliPusher;

impl SecretPusher for AwsCliPusher {
    fn ensure_available(&self) -> Result<()> {
        ensure_command_available("aws")
    }

    fn exists(&self, cfg: &PushConfig, target: &str) -> Result<bool> {
        let mut cmd = Command::new("aws");
        cmd.args(["secretsmanager", "describe-secret", "--secret-id", target]);
        if let Some(region) = &cfg.region {
            cmd.arg("--region").arg(region);
        }
        run_provider_status(&mut cmd)
    }

    fn push_blob(
        &self,
        cfg: &PushConfig,
        target: &str,
        payload: &[u8],
        create: bool,
    ) -> Result<PushResult> {
        let mut tmp = write_temp_payload(payload)?;
        let uri = format!("file://{}", tmp.path().display());
        let mut cmd = if create {
            let mut cmd = Command::new("aws");
            cmd.args(["secretsmanager", "create-secret", "--name", target]);
            cmd.arg("--secret-string").arg(&uri);
            cmd
        } else {
            let mut cmd = Command::new("aws");
            cmd.args(["secretsmanager", "put-secret-value", "--secret-id", target]);
            cmd.arg("--secret-string").arg(&uri);
            cmd
        };
        if let Some(region) = &cfg.region {
            cmd.arg("--region").arg(region);
        }
        let result = run_provider_command(&mut cmd);
        zero_temp_file(&mut tmp, payload.len())?;
        result?;
        Ok(PushResult {
            operation: if create { "created" } else { "updated" }.into(),
            version_id: None,
            status: "success".into(),
            keys_total: None,
            keys_succeeded: None,
            failed_key: None,
            error: None,
        })
    }
}

struct GcpCliPusher;

impl SecretPusher for GcpCliPusher {
    fn ensure_available(&self) -> Result<()> {
        ensure_command_available("gcloud")
    }

    fn exists(&self, cfg: &PushConfig, target: &str) -> Result<bool> {
        let mut cmd = Command::new("gcloud");
        cmd.args(["secrets", "describe", target]);
        add_gcp_read_flags(&mut cmd, cfg);
        run_provider_status(&mut cmd)
    }

    fn push_blob(
        &self,
        cfg: &PushConfig,
        target: &str,
        payload: &[u8],
        create: bool,
    ) -> Result<PushResult> {
        if create {
            let mut create_cmd = Command::new("gcloud");
            create_cmd.args([
                "secrets",
                "create",
                target,
                "--replication-policy",
                "automatic",
            ]);
            add_gcp_write_flags(&mut create_cmd, cfg);
            run_provider_command(&mut create_cmd)?;
        }
        let mut tmp = write_temp_payload(payload)?;
        let data_file = format!("--data-file={}", tmp.path().display());
        let mut cmd = Command::new("gcloud");
        cmd.args(["secrets", "versions", "add", target]);
        cmd.arg(data_file);
        add_gcp_write_flags(&mut cmd, cfg);
        let result = run_provider_command(&mut cmd);
        zero_temp_file(&mut tmp, payload.len())?;
        result?;
        Ok(PushResult {
            operation: if create { "created" } else { "updated" }.into(),
            version_id: None,
            status: "success".into(),
            keys_total: None,
            keys_succeeded: None,
            failed_key: None,
            error: None,
        })
    }
}

fn add_gcp_read_flags(cmd: &mut Command, cfg: &PushConfig) {
    add_gcp_project_flag(cmd, cfg);
    if let Some(location) = &cfg.location {
        cmd.arg("--location").arg(location);
    }
}

fn add_gcp_write_flags(cmd: &mut Command, cfg: &PushConfig) {
    add_gcp_project_flag(cmd, cfg);
    cmd.arg("--location")
        .arg(cfg.location.as_deref().unwrap_or("global"));
}

fn add_gcp_project_flag(cmd: &mut Command, cfg: &PushConfig) {
    if let Some(project) = &cfg.project {
        cmd.arg("--project").arg(project);
    }
}

fn ensure_command_available(bin: &str) -> Result<()> {
    let out = Command::new(bin)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("provider cli not found: `{bin}`"))?;
    if out.success() {
        Ok(())
    } else {
        Err(CliExit::message(2, format!("provider cli failed: `{bin} --version`")).into())
    }
}

fn run_provider_command(cmd: &mut Command) -> Result<()> {
    let output = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("run provider cli")?;
    if output.status.success() {
        return Ok(());
    }
    Err(CliExit::message(
        2,
        format!(
            "provider cli failed with exit code {}",
            output.status.code().unwrap_or(2)
        ),
    )
    .into())
}

fn run_provider_status(cmd: &mut Command) -> Result<bool> {
    let output = cmd
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .context("run provider cli")?;
    Ok(output.status.success())
}

fn write_temp_payload(payload: &[u8]) -> Result<NamedTempFile> {
    let mut tmp = NamedTempFile::new().context("create temporary secret payload file")?;
    tmp.write_all(payload)
        .context("write temporary secret payload file")?;
    tmp.flush().context("flush temporary secret payload file")?;
    Ok(tmp)
}

fn zero_temp_file(tmp: &mut NamedTempFile, len: usize) -> Result<()> {
    tmp.as_file_mut()
        .seek(SeekFrom::Start(0))
        .context("seek temporary secret payload file")?;
    let zeros = vec![0u8; len.min(8192)];
    let mut remaining = len;
    while remaining > 0 {
        let n = remaining.min(zeros.len());
        tmp.as_file_mut()
            .write_all(&zeros[..n])
            .context("zero temporary secret payload file")?;
        remaining -= n;
    }
    tmp.flush()
        .context("flush zeroed temporary secret payload file")
}

fn print_dry_run(cfg: &PushConfig, source_label: &str, bytes: usize, payload: &SecretPayload) {
    println!("Would push secret:");
    println!("  provider: {}", provider_str(cfg.provider));
    println!("  mode: {}", mode_str(cfg.mode));
    println!("  source: {source_label}");
    println!("  bytes: {bytes}");
    println!("  audit: {}", cfg.audit);
    println!("  create_if_missing: {}", cfg.create_if_missing);
    match payload {
        SecretPayload::Blob { .. } => {
            println!("  target: {}", cfg.target.as_deref().unwrap_or("<missing>"));
        }
        SecretPayload::PerKey { entries } => {
            println!(
                "  target_prefix: {}",
                cfg.target_prefix.as_deref().unwrap_or("<missing>")
            );
            println!("  keys: {}", entries.len());
            for entry in entries {
                println!(
                    "    - {}{}",
                    cfg.target_prefix.as_deref().unwrap_or(""),
                    entry.key
                );
            }
            println!("  prune: false");
        }
    }
}

fn confirm_write(cfg: &PushConfig, source_label: &str, payload: &SecretPayload) -> Result<()> {
    if !std::io::stdin().is_terminal() {
        return Err(
            CliExit::message(2, "confirmation requires a TTY; pass --yes or --dry-run").into(),
        );
    }
    print_dry_run(cfg, source_label, payload_bytes_len(payload), payload);
    eprint!("Proceed? Type `yes` to continue: ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("read confirmation")?;
    if line.trim() == "yes" {
        Ok(())
    } else {
        Err(CliExit::message(2, "secret push cancelled").into())
    }
}

fn append_audit(
    repo_root: &Path,
    cfg: &PushConfig,
    source_label: &str,
    bytes: usize,
    hash: &str,
    result: &PushResult,
) -> Result<()> {
    let mut value = serde_json::json!({
        "action": "secrets.push",
        "provider": provider_str(cfg.provider),
        "mode": mode_str(cfg.mode),
        "source_label": source_label,
        "bytes": bytes,
        "payload_sha256": hash,
        "operation": result.operation,
        "status": result.status,
    });
    let obj = value.as_object_mut().expect("object");
    if let Some(target) = &cfg.target {
        obj.insert("target".into(), target.clone().into());
    }
    if let Some(prefix) = &cfg.target_prefix {
        obj.insert("target_prefix".into(), prefix.clone().into());
    }
    if let Some(version) = &result.version_id {
        obj.insert("version_id".into(), version.clone().into());
    }
    if let Some(keys_total) = result.keys_total {
        obj.insert("keys_total".into(), keys_total.into());
    }
    if let Some(keys_succeeded) = result.keys_succeeded {
        obj.insert("keys_succeeded".into(), keys_succeeded.into());
    }
    if let Some(failed_key) = &result.failed_key {
        obj.insert("failed_key".into(), failed_key.clone().into());
    }
    if let Some(error) = &result.error {
        obj.insert("error".into(), error.clone().into());
    }
    audit_log::append_line(repo_root, value)
}

fn print_result(cfg: &PushConfig, result: &PushResult) {
    println!(
        "Pushed secret metadata: provider={} mode={} status={}",
        provider_str(cfg.provider),
        mode_str(cfg.mode),
        result.status
    );
}

fn payload_sha256(payload: &SecretPayload) -> String {
    let mut hasher = Sha256::new();
    match payload {
        SecretPayload::Blob { bytes } => hasher.update(bytes),
        SecretPayload::PerKey { entries } => {
            for entry in entries {
                hasher.update(entry.key.as_bytes());
                hasher.update(b"=");
                hasher.update(&entry.value);
                hasher.update(b"\n");
            }
        }
    }
    format!("{:x}", hasher.finalize())
}

fn payload_bytes_len(payload: &SecretPayload) -> usize {
    match payload {
        SecretPayload::Blob { bytes } => bytes.len(),
        SecretPayload::PerKey { entries } => entries.iter().map(|e| e.value.len()).sum(),
    }
}

fn project_root(cwd: &Path) -> Result<PathBuf> {
    let root = shk_core::git::discover_repo_root(cwd).unwrap_or_else(|| cwd.to_path_buf());
    std::fs::canonicalize(&root).with_context(|| format!("canonicalize {}", root.display()))
}

fn source_label(repo_root: &Path, source: &Path) -> String {
    let canonical = std::fs::canonicalize(source).unwrap_or_else(|_| source.to_path_buf());
    canonical
        .strip_prefix(repo_root)
        .unwrap_or(canonical.as_path())
        .to_string_lossy()
        .replace('\\', "/")
}

fn provider_str(provider: Provider) -> &'static str {
    match provider {
        Provider::Aws => "aws",
        Provider::Gcp => "gcp",
    }
}

fn mode_str(mode: PushMode) -> &'static str {
    match mode {
        PushMode::Blob => "blob",
        PushMode::PerKey => "per-key",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_key_rejects_duplicate_keys() {
        let err = parse_dotenv_entries("DOTENV_PRIVATE_KEY=a\nDOTENV_PRIVATE_KEY=b\n").unwrap_err();
        assert!(err.to_string().contains("duplicate dotenv key"), "{err}");
    }

    #[test]
    fn per_key_validates_charset_without_normalizing() {
        let err = parse_dotenv_entries("DOTENV.PRIVATE.KEY=value\n").unwrap_err();
        assert!(format!("{err:#}").contains("[A-Z_][A-Z0-9_]*"), "{err:#}");
    }

    #[test]
    fn per_key_payload_hash_includes_key_names() {
        let payload = SecretPayload::PerKey {
            entries: parse_dotenv_entries("A=one\nB=two\n").unwrap(),
        };
        let other = SecretPayload::PerKey {
            entries: parse_dotenv_entries("A=one\nC=two\n").unwrap(),
        };
        assert_ne!(payload_sha256(&payload), payload_sha256(&other));
    }

    #[test]
    fn pre_push_pii_scan_rejects_medium_findings() {
        let payload = SecretPayload::PerKey {
            entries: parse_dotenv_entries("SUPPORT_EMAIL=alice@example.com\n").unwrap(),
        };

        let err = run_pii_scan(".env.keys", &payload).unwrap_err();

        assert!(
            err.to_string().contains("pre-push PII scan failed"),
            "{err}"
        );
    }

    #[test]
    fn gcp_describe_does_not_default_location() {
        let cfg = PushConfig {
            provider: Provider::Gcp,
            project: Some("demo-project".into()),
            ..base_cfg(PushMode::Blob)
        };
        let mut cmd = Command::new("gcloud");

        add_gcp_read_flags(&mut cmd, &cfg);

        assert_eq!(command_args(&cmd), ["--project", "demo-project"]);
    }

    #[test]
    fn gcp_writes_default_location_to_global() {
        let cfg = PushConfig {
            provider: Provider::Gcp,
            project: Some("demo-project".into()),
            ..base_cfg(PushMode::Blob)
        };
        let mut cmd = Command::new("gcloud");

        add_gcp_write_flags(&mut cmd, &cfg);

        assert_eq!(
            command_args(&cmd),
            ["--project", "demo-project", "--location", "global"]
        );
    }

    #[derive(Default)]
    struct MockPusher {
        calls: std::cell::RefCell<Vec<(String, Vec<u8>, bool)>>,
    }

    impl SecretPusher for MockPusher {
        fn ensure_available(&self) -> Result<()> {
            Ok(())
        }

        fn exists(&self, _cfg: &PushConfig, _target: &str) -> Result<bool> {
            Ok(false)
        }

        fn push_blob(
            &self,
            _cfg: &PushConfig,
            target: &str,
            payload: &[u8],
            create: bool,
        ) -> Result<PushResult> {
            self.calls
                .borrow_mut()
                .push((target.to_string(), payload.to_vec(), create));
            Ok(PushResult {
                operation: "updated".into(),
                version_id: None,
                status: "success".into(),
                keys_total: None,
                keys_succeeded: None,
                failed_key: None,
                error: None,
            })
        }
    }

    fn base_cfg(mode: PushMode) -> PushConfig {
        PushConfig {
            provider: Provider::Aws,
            mode,
            target: (mode == PushMode::Blob).then(|| "app/prod".into()),
            target_prefix: (mode == PushMode::PerKey).then(|| "app/prod/".into()),
            source: PathBuf::from(".env.keys"),
            region: None,
            project: None,
            location: None,
            audit: false,
            confirm: false,
            create_if_missing: true,
            strict: false,
            no_scan: true,
            dry_run: false,
            yes: true,
            expected_env: None,
        }
    }

    fn command_args(cmd: &Command) -> Vec<&str> {
        cmd.get_args()
            .map(|arg| arg.to_str().unwrap_or("<non-utf8>"))
            .collect()
    }

    #[test]
    fn mock_pusher_receives_blob_once() {
        let pusher = MockPusher::default();
        let payload = SecretPayload::Blob {
            bytes: Zeroizing::new(b"DOTENV_PRIVATE_KEY=value\n".to_vec()),
        };
        let result = execute_push(&pusher, &base_cfg(PushMode::Blob), &payload).unwrap();
        assert_eq!(result.status, "success");
        let calls = pusher.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "app/prod");
        assert_eq!(calls[0].1, b"DOTENV_PRIVATE_KEY=value\n");
        assert!(calls[0].2);
    }

    #[test]
    fn mock_pusher_receives_per_key_values_without_key_prefix_in_payload() {
        let pusher = MockPusher::default();
        let payload = SecretPayload::PerKey {
            entries: parse_dotenv_entries(
                "DOTENV_PRIVATE_KEY_DEV=dev\nDOTENV_PRIVATE_KEY_PROD=prod\n",
            )
            .unwrap(),
        };
        let result = execute_push(&pusher, &base_cfg(PushMode::PerKey), &payload).unwrap();
        assert_eq!(result.keys_total, Some(2));
        let calls = pusher.calls.borrow();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, "app/prod/DOTENV_PRIVATE_KEY_DEV");
        assert_eq!(calls[0].1, b"dev");
        assert_eq!(calls[1].0, "app/prod/DOTENV_PRIVATE_KEY_PROD");
        assert_eq!(calls[1].1, b"prod");
    }
}
