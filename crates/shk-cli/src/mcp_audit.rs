//! Static, read-only auditing of MCP client configuration files.

use anyhow::{Context, Result};
use shk_core::finding::{Finding, ScanSummary};
use shk_core::policy::Severity;
use shk_core::scanner::{ScanOptions, scan_string};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_SERVERS_PER_CONFIG: usize = 1000;

const PROJECT_CONFIGS: &[(&str, &str, Format)] = &[
    ("claude-code", ".mcp.json", Format::JsonMcp),
    ("cursor", ".cursor/mcp.json", Format::JsonMcp),
    ("vscode", ".vscode/mcp.json", Format::JsonServers),
    ("codex", ".codex/config.toml", Format::Toml),
];

#[derive(Clone, Copy)]
enum Format {
    JsonMcp,
    JsonServers,
    ClaudeUser,
    Toml,
}

pub struct McpServerEntry {
    pub client: String,
    pub source_file: PathBuf,
    pub name: String,
    pub transport: McpTransport,
}

impl Drop for McpServerEntry {
    fn drop(&mut self) {
        self.client.zeroize();
        self.name.zeroize();
    }
}

pub enum McpTransport {
    Stdio {
        command: String,
        args: Vec<String>,
        env: BTreeMap<String, String>,
    },
    Http {
        url: String,
        headers: BTreeMap<String, String>,
    },
    Unknown,
}

impl Drop for McpTransport {
    fn drop(&mut self) {
        match self {
            Self::Stdio { command, args, env } => {
                command.zeroize();
                args.zeroize();
                for value in env.values_mut() {
                    value.zeroize();
                }
            }
            Self::Http { url, headers } => {
                url.zeroize();
                for value in headers.values_mut() {
                    value.zeroize();
                }
            }
            Self::Unknown => {}
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct McpServerInventory {
    pub client: String,
    pub source_file: String,
    pub name: String,
    pub transport: String,
}

#[derive(Debug, serde::Serialize)]
pub struct McpAuditReport {
    pub version: u32,
    pub config_files: Vec<String>,
    pub findings: Vec<Finding>,
    pub summary: ScanSummary,
    pub servers: Vec<McpServerInventory>,
    pub exit_threshold: String,
}

impl McpAuditReport {
    pub fn should_fail(&self) -> bool {
        let Some(threshold) = Severity::parse(&self.exit_threshold) else {
            return false;
        };
        self.findings.iter().any(|finding| {
            Severity::parse(&finding.severity)
                .is_some_and(|severity| severity.meets_threshold(threshold))
        })
    }
}

struct Candidate {
    client: &'static str,
    path: PathBuf,
    label: String,
    format: Format,
    scope_root: PathBuf,
}

pub fn audit(root: &Path, global: bool, fail_on: Severity) -> Result<McpAuditReport> {
    let root = fs::canonicalize(root)
        .with_context(|| format!("MCP audit path not found: {}", root.display()))?;
    if !root.is_dir() {
        anyhow::bail!("MCP audit path must be a directory: {}", root.display());
    }
    let mut candidates = project_candidates(&root);
    let home = dirs::home_dir();
    if global {
        let global_home = home
            .as_deref()
            .context("home directory is unavailable for --global")?;
        candidates.extend(global_candidates(global_home));
    }

    let mut config_files = Vec::new();
    let mut entries = Vec::new();
    let mut findings = Vec::new();
    let mut seen_config_paths = HashSet::new();
    for candidate in candidates {
        let (canonical, content) = match read_candidate(&candidate) {
            CandidateRead::Missing => continue,
            CandidateRead::Unreadable => {
                config_files.push(candidate.label.clone());
                findings.push(finding(
                    "mcp.config_unreadable",
                    Severity::Low,
                    &candidate.label,
                    "MCP configuration could not be safely read; the file was skipped",
                    1.0,
                ));
                continue;
            }
            CandidateRead::Content { canonical, content } => (canonical, content),
        };
        let mut content = content;
        if !seen_config_paths.insert(canonical) {
            content.zeroize();
            continue;
        }
        config_files.push(candidate.label.clone());
        let parsed = parse_config(
            candidate.client,
            &candidate.path,
            candidate.format,
            &content,
        );
        content.zeroize();
        if let Ok(mut parsed) = parsed {
            entries.append(&mut parsed);
        } else {
            findings.push(finding(
                "mcp.config_unreadable",
                Severity::Low,
                &candidate.label,
                "MCP configuration could not be read or parsed; the file was skipped",
                1.0,
            ));
        }
    }
    for entry in &entries {
        check_entry(&root, home.as_deref(), entry, &mut findings)?;
    }
    findings.sort_by(|a, b| {
        severity_rank(&b.severity)
            .cmp(&severity_rank(&a.severity))
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.rule_id.cmp(&b.rule_id))
            .then_with(|| a.message.cmp(&b.message))
    });

    let mut by_severity = BTreeMap::new();
    for finding in &findings {
        *by_severity.entry(finding.severity.clone()).or_insert(0) += 1;
    }
    let mut servers: Vec<_> = entries
        .iter()
        .map(|entry| McpServerInventory {
            client: escape_control(&entry.client),
            source_file: display_label(&root, home.as_deref(), &entry.source_file),
            name: safe_identifier(&entry.name),
            transport: match entry.transport {
                McpTransport::Stdio { .. } => "stdio",
                McpTransport::Http { .. } => "http",
                McpTransport::Unknown => "unknown",
            }
            .into(),
        })
        .collect();
    servers.sort_by(|a, b| {
        a.source_file
            .cmp(&b.source_file)
            .then_with(|| a.client.cmp(&b.client))
            .then_with(|| a.name.cmp(&b.name))
    });
    config_files.sort();
    config_files.dedup();

    Ok(McpAuditReport {
        version: 1,
        config_files,
        summary: ScanSummary {
            total: findings.len(),
            by_severity,
        },
        findings,
        servers,
        exit_threshold: fail_on.as_str().into(),
    })
}

fn project_candidates(root: &Path) -> Vec<Candidate> {
    PROJECT_CONFIGS
        .iter()
        .map(|(client, relative, format)| Candidate {
            client,
            path: root.join(relative),
            label: (*relative).into(),
            format: *format,
            scope_root: root.to_path_buf(),
        })
        .collect()
}

fn global_candidates(home: &Path) -> Vec<Candidate> {
    let scope_root = fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf());
    [
        ("claude-code", ".claude.json", Format::ClaudeUser),
        (
            "claude-desktop",
            "Library/Application Support/Claude/claude_desktop_config.json",
            Format::JsonMcp,
        ),
        ("cursor", ".cursor/mcp.json", Format::JsonMcp),
        ("codex", ".codex/config.toml", Format::Toml),
        (
            "windsurf",
            ".codeium/windsurf/mcp_config.json",
            Format::JsonMcp,
        ),
    ]
    .into_iter()
    .map(|(client, relative, format)| Candidate {
        client,
        path: home.join(relative),
        label: format!("~/{}", relative.replace('\\', "/")),
        format,
        scope_root: scope_root.clone(),
    })
    .collect()
}

enum CandidateRead {
    Missing,
    Unreadable,
    Content { canonical: PathBuf, content: String },
}

fn read_candidate(candidate: &Candidate) -> CandidateRead {
    match fs::symlink_metadata(&candidate.path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return CandidateRead::Missing;
        }
        Err(_) => return CandidateRead::Unreadable,
    }
    let Ok(canonical) = fs::canonicalize(&candidate.path) else {
        return CandidateRead::Unreadable;
    };
    if !canonical.starts_with(&candidate.scope_root) {
        return CandidateRead::Unreadable;
    }
    let Ok(metadata) = fs::metadata(&canonical) else {
        return CandidateRead::Unreadable;
    };
    if !metadata.is_file()
        || metadata.len() > MAX_CONFIG_BYTES
        || metadata_has_multiple_links(&metadata)
    {
        return CandidateRead::Unreadable;
    }
    let Ok(file) = fs::File::open(&canonical) else {
        return CandidateRead::Unreadable;
    };
    let mut bytes = Vec::new();
    if file
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() as u64 > MAX_CONFIG_BYTES
    {
        bytes.zeroize();
        return CandidateRead::Unreadable;
    }
    match String::from_utf8(bytes) {
        Ok(content) => CandidateRead::Content { canonical, content },
        Err(error) => {
            let mut invalid = error.into_bytes();
            invalid.zeroize();
            CandidateRead::Unreadable
        }
    }
}

#[cfg(unix)]
fn metadata_has_multiple_links(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.nlink() > 1
}

#[cfg(not(unix))]
fn metadata_has_multiple_links(_metadata: &fs::Metadata) -> bool {
    false
}

fn parse_config(
    client: &str,
    source: &Path,
    format: Format,
    content: &str,
) -> Result<Vec<McpServerEntry>> {
    let entries = match format {
        Format::JsonMcp | Format::JsonServers | Format::ClaudeUser => {
            let mut cleaned = clean_jsonc(content);
            let value = serde_json::from_str(&cleaned);
            cleaned.zeroize();
            let value: serde_json::Value = value?;
            let key = if matches!(format, Format::JsonServers) {
                "servers"
            } else {
                "mcpServers"
            };
            let mut entries = parse_json_map(client, source, value.get(key));
            if entries.len() > MAX_SERVERS_PER_CONFIG {
                anyhow::bail!("MCP configuration contains too many server entries");
            }
            if matches!(format, Format::ClaudeUser)
                && let Some(projects) = value.get("projects").and_then(serde_json::Value::as_object)
            {
                for project in projects.values() {
                    entries.extend(parse_json_map(client, source, project.get("mcpServers")));
                    if entries.len() > MAX_SERVERS_PER_CONFIG {
                        anyhow::bail!("MCP configuration contains too many server entries");
                    }
                }
            }
            entries
        }
        Format::Toml => {
            let value: toml::Value = toml::from_str(content)?;
            parse_toml_map(client, source, value.get("mcp_servers"))
        }
    };
    if entries.len() > MAX_SERVERS_PER_CONFIG {
        anyhow::bail!("MCP configuration contains too many server entries");
    }
    Ok(entries)
}

fn parse_json_map(
    client: &str,
    source: &Path,
    value: Option<&serde_json::Value>,
) -> Vec<McpServerEntry> {
    value
        .and_then(serde_json::Value::as_object)
        .into_iter()
        .flat_map(|servers| servers.iter())
        .take(MAX_SERVERS_PER_CONFIG + 1)
        .map(|(name, config)| McpServerEntry {
            client: client.into(),
            source_file: source.into(),
            name: name.clone(),
            transport: json_transport(config),
        })
        .collect()
}

fn json_transport(value: &serde_json::Value) -> McpTransport {
    let Some(config) = value.as_object() else {
        return McpTransport::Unknown;
    };
    if let Some(command) = config.get("command").and_then(serde_json::Value::as_str) {
        return McpTransport::Stdio {
            command: command.into(),
            args: json_array(config.get("args")),
            env: json_map(config.get("env")),
        };
    }
    if let Some(url) = config
        .get("url")
        .or_else(|| config.get("serverUrl"))
        .and_then(serde_json::Value::as_str)
    {
        return McpTransport::Http {
            url: url.into(),
            headers: json_map(config.get("headers")),
        };
    }
    McpTransport::Unknown
}

fn json_array(value: Option<&serde_json::Value>) -> Vec<String> {
    value
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flat_map(|values| values.iter())
        .filter_map(|value| value.as_str().map(str::to_string))
        .collect()
}

fn json_map(value: Option<&serde_json::Value>) -> BTreeMap<String, String> {
    value
        .and_then(serde_json::Value::as_object)
        .into_iter()
        .flat_map(|values| values.iter())
        .filter_map(|(key, value)| value.as_str().map(|value| (key.clone(), value.into())))
        .collect()
}

fn parse_toml_map(client: &str, source: &Path, value: Option<&toml::Value>) -> Vec<McpServerEntry> {
    value
        .and_then(toml::Value::as_table)
        .into_iter()
        .flat_map(|servers| servers.iter())
        .take(MAX_SERVERS_PER_CONFIG + 1)
        .map(|(name, config)| {
            let transport =
                if let Some(command) = config.get("command").and_then(toml::Value::as_str) {
                    McpTransport::Stdio {
                        command: command.into(),
                        args: toml_array(config.get("args")),
                        env: toml_map(config.get("env")),
                    }
                } else if let Some(url) = config.get("url").and_then(toml::Value::as_str) {
                    McpTransport::Http {
                        url: url.into(),
                        headers: toml_map(config.get("http_headers")),
                    }
                } else {
                    McpTransport::Unknown
                };
            McpServerEntry {
                client: client.into(),
                source_file: source.into(),
                name: name.clone(),
                transport,
            }
        })
        .collect()
}

fn toml_array(value: Option<&toml::Value>) -> Vec<String> {
    value
        .and_then(toml::Value::as_array)
        .into_iter()
        .flat_map(|values| values.iter())
        .filter_map(|value| value.as_str().map(str::to_string))
        .collect()
}

fn toml_map(value: Option<&toml::Value>) -> BTreeMap<String, String> {
    value
        .and_then(toml::Value::as_table)
        .into_iter()
        .flat_map(|values| values.iter())
        .filter_map(|(key, value)| value.as_str().map(|value| (key.clone(), value.into())))
        .collect()
}

fn check_entry(
    root: &Path,
    home: Option<&Path>,
    entry: &McpServerEntry,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    let file = display_label(root, home, &entry.source_file);
    let server = safe_identifier(&entry.name);
    let client = escape_control(&entry.client);
    match &entry.transport {
        McpTransport::Stdio { command, args, env } => {
            let command_name = executable_name(command);
            if command_name == "npx"
                && args
                    .iter()
                    .any(|arg| matches!(arg.as_str(), "-y" | "--yes"))
            {
                findings.push(context_finding(
                    "mcp.npx_auto_install",
                    Severity::Medium,
                    &file,
                    &server,
                    &client,
                    "npx auto-install is enabled",
                    0.95,
                ));
            }
            if let Some(package) = package_invocation(&command_name, args)
                && !package_is_pinned(package)
            {
                findings.push(context_finding(
                    "mcp.unpinned_package",
                    Severity::Medium,
                    &file,
                    &server,
                    &client,
                    "the package is not pinned to an exact version",
                    0.9,
                ));
            }
            if is_shell(&command_name)
                && args
                    .iter()
                    .any(|arg| arg == "-c" || arg.eq_ignore_ascii_case("/c"))
            {
                findings.push(context_finding(
                    "mcp.shell_wrapper",
                    Severity::Medium,
                    &file,
                    &server,
                    &client,
                    "a shell wrapper expands the command-injection surface",
                    0.9,
                ));
            }
            if is_unpinned_local_executable(root, command) {
                findings.push(context_finding(
                    "mcp.local_unpinned_executable",
                    Severity::Low,
                    &file,
                    &server,
                    &client,
                    "a local executable has no integrity-verification mechanism",
                    0.75,
                ));
            }
            if is_filesystem_server(&entry.name, command, args) {
                if args.iter().any(|arg| arg.trim() == "/") {
                    findings.push(context_finding(
                        "mcp.broad_filesystem_scope",
                        Severity::High,
                        &file,
                        &server,
                        &client,
                        "filesystem root is exposed",
                        1.0,
                    ));
                } else if args.iter().any(|arg| exposes_home(arg, home)) {
                    findings.push(context_finding(
                        "mcp.broad_filesystem_scope",
                        Severity::Medium,
                        &file,
                        &server,
                        &client,
                        "the user home directory is exposed",
                        0.95,
                    ));
                }
            }
            scan_literals(
                root,
                &file,
                env.values().map(String::as_str),
                &server,
                &client,
                "env",
                findings,
            )?;
            scan_literals(
                root,
                &file,
                args.iter().map(String::as_str),
                &server,
                &client,
                "args",
                findings,
            )?;
        }
        McpTransport::Http { url, headers } => {
            if is_insecure_remote_http(url) {
                findings.push(context_finding(
                    "mcp.http_no_tls",
                    Severity::High,
                    &file,
                    &server,
                    &client,
                    "a remote endpoint uses HTTP without TLS",
                    1.0,
                ));
            }
            if has_sensitive_url_key(url) {
                findings.push(context_finding(
                    "mcp.secret_in_url",
                    Severity::High,
                    &file,
                    &server,
                    &client,
                    "the URL contains a sensitive query parameter",
                    0.9,
                ));
            }
            scan_literals(
                root,
                &file,
                std::iter::once(url.as_str()),
                &server,
                &client,
                "url",
                findings,
            )?;
            scan_literals(
                root,
                &file,
                headers.values().map(String::as_str),
                &server,
                &client,
                "headers",
                findings,
            )?;
        }
        McpTransport::Unknown => findings.push(context_finding(
            "mcp.unknown_transport",
            Severity::Info,
            &file,
            &server,
            &client,
            "the transport could not be determined",
            0.8,
        )),
    }
    Ok(())
}

fn scan_literals<'a>(
    root: &Path,
    file: &str,
    values: impl IntoIterator<Item = &'a str>,
    server: &str,
    client: &str,
    field: &str,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    let literals = values
        .into_iter()
        .filter(|value| !is_reference(value))
        .collect::<Vec<_>>();
    if literals.is_empty() {
        return Ok(());
    }
    let mut content = literals.join("\n\n");
    let result = scan_string(root, file, &content, ScanOptions::default());
    content.zeroize();
    let result = result?;
    for mut finding in result
        .findings
        .into_iter()
        .filter(|finding| finding.kind == "secret")
    {
        finding.message = format!("plaintext secret in MCP server \"{server}\" ({client}) {field}");
        finding.file = file.into();
        finding.line = 1;
        finding.column = 1;
        finding.value_hash = None;
        finding.context_before.clear();
        finding.context_after.clear();
        findings.push(finding);
    }
    Ok(())
}

fn finding(
    rule_id: &str,
    severity: Severity,
    file: &str,
    message: &str,
    confidence: f32,
) -> Finding {
    Finding {
        rule_id: rule_id.into(),
        severity: severity.as_str().into(),
        kind: "mcp".into(),
        file: escape_control(file),
        line: 1,
        column: 1,
        message: message.into(),
        redacted_value: "[REDACTED]".into(),
        value_hash: None,
        confidence,
        context_before: Vec::new(),
        context_after: Vec::new(),
    }
}

fn context_finding(
    rule_id: &str,
    severity: Severity,
    file: &str,
    server: &str,
    client: &str,
    detail: &str,
    confidence: f32,
) -> Finding {
    finding(
        rule_id,
        severity,
        file,
        &format!("{detail}; MCP server \"{server}\" ({client})"),
        confidence,
    )
}

fn display_label(root: &Path, home: Option<&Path>, path: &Path) -> String {
    if let Ok(relative) = path.strip_prefix(root) {
        return escape_control(&relative.to_string_lossy().replace('\\', "/"));
    }
    if let Some(home) = home
        && let Ok(relative) = path.strip_prefix(home)
    {
        return escape_control(&format!(
            "~/{}",
            relative.to_string_lossy().replace('\\', "/")
        ));
    }
    escape_control(&path.to_string_lossy())
}

fn escape_control(value: &str) -> String {
    let mut escaped = String::new();
    for ch in value.chars() {
        if ch.is_control() {
            use std::fmt::Write as _;
            let _ = write!(escaped, "\\u{{{:x}}}", ch as u32);
        } else {
            escaped.push(ch);
        }
    }
    escaped
}

fn safe_identifier(value: &str) -> String {
    let redacted =
        shk_rules::redact_line_for_display(value, &shk_rules::RuleEngineConfig::default());
    escape_control(&redacted)
}

fn executable_name(command: &str) -> String {
    command
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(command)
        .to_ascii_lowercase()
}

fn package_invocation<'a>(command: &str, args: &'a [String]) -> Option<&'a str> {
    match command {
        "npx" => package_argument(args, &["-p", "--package"]),
        "uvx" => package_argument(args, &["--from"]),
        "pipx" => {
            let run = args.iter().position(|arg| arg == "run")?;
            package_argument(&args[run + 1..], &["--spec"])
        }
        _ => None,
    }
}

fn package_argument<'a>(args: &'a [String], package_options: &[&str]) -> Option<&'a str> {
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        for option in package_options {
            if arg == *option {
                return args.get(index + 1).map(String::as_str);
            }
            if let Some(value) = arg.strip_prefix(&format!("{option}=")) {
                return Some(value);
            }
        }
        if arg == "--" {
            return args.get(index + 1).map(String::as_str);
        }
        if !arg.starts_with('-') {
            return Some(arg);
        }
        index += 1;
    }
    None
}

fn package_is_pinned(package: &str) -> bool {
    package
        .rsplit_once("==")
        .or_else(|| package.rsplit_once('@'))
        .is_some_and(|(_, version)| exact_version(version))
}

fn exact_version(version: &str) -> bool {
    let core_end = version.find(['-', '+']).unwrap_or(version.len());
    let (core, suffix) = version.split_at(core_end);
    let mut parts = core.split('.');
    let core_is_exact = matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some(a), Some(b), Some(c), None)
            if [a, b, c].iter().all(|part| {
                !part.is_empty() && part.chars().all(|ch| ch.is_ascii_digit())
            })
    );
    if !core_is_exact {
        return false;
    }
    if suffix.is_empty() {
        return true;
    }

    let suffix = suffix.strip_prefix('-').unwrap_or(suffix);
    let (prerelease, build) = suffix
        .split_once('+')
        .map_or((suffix, None), |(pre, build)| (pre, Some(build)));
    let has_prerelease = version.as_bytes().get(core_end) == Some(&b'-');
    (!has_prerelease || valid_version_identifiers(prerelease))
        && build.is_none_or(valid_version_identifiers)
}

fn valid_version_identifiers(value: &str) -> bool {
    !value.is_empty()
        && value.split('.').all(|identifier| {
            !identifier.is_empty()
                && identifier
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
        })
}

fn is_shell(command: &str) -> bool {
    matches!(
        command,
        "sh" | "bash" | "zsh" | "cmd" | "cmd.exe" | "powershell" | "powershell.exe" | "pwsh"
    )
}

fn is_unpinned_local_executable(root: &Path, command: &str) -> bool {
    let path = Path::new(command);
    if !path.is_absolute() {
        return command.contains('/') || command.contains('\\');
    }
    !path_is_within(path, root) && !is_system_executable(path)
}

#[cfg(windows)]
fn path_is_within(path: &Path, root: &Path) -> bool {
    let path = path
        .to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase();
    let mut root = root
        .to_string_lossy()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase();
    root.push('\\');
    path == root.trim_end_matches('\\') || path.starts_with(&root)
}

#[cfg(not(windows))]
fn path_is_within(path: &Path, root: &Path) -> bool {
    path.starts_with(root)
}

#[cfg(unix)]
fn is_system_executable(path: &Path) -> bool {
    ["/bin", "/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"]
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

#[cfg(windows)]
fn is_system_executable(path: &Path) -> bool {
    std::env::var_os("SystemRoot")
        .map(|system_root| {
            let path = path
                .to_string_lossy()
                .replace('/', "\\")
                .to_ascii_lowercase();
            let mut system_root = PathBuf::from(system_root)
                .to_string_lossy()
                .replace('/', "\\")
                .to_ascii_lowercase();
            system_root.push('\\');
            path.starts_with(&system_root)
        })
        .unwrap_or(false)
}

#[cfg(not(any(unix, windows)))]
fn is_system_executable(_path: &Path) -> bool {
    false
}

fn is_filesystem_server(name: &str, command: &str, args: &[String]) -> bool {
    std::iter::once(name)
        .chain(std::iter::once(command))
        .chain(args.iter().map(String::as_str))
        .any(|value| {
            let value = value.to_ascii_lowercase();
            value == "filesystem"
                || value.contains("server-filesystem")
                || value.contains("filesystem-server")
                || value.contains("mcp-server-filesystem")
        })
}

fn exposes_home(value: &str, home: Option<&Path>) -> bool {
    let value = value.trim();
    value == "~"
        || value.starts_with("~/")
        || value == "$HOME"
        || value.starts_with("$HOME/")
        || value == "${HOME}"
        || value.starts_with("${HOME}/")
        || home.is_some_and(|home| path_is_within(Path::new(value), home))
}

fn is_insecure_remote_http(url: &str) -> bool {
    let Some(scheme) = url.get(..7) else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("http://") {
        return false;
    }
    let rest = &url[7..];
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host_port = authority.rsplit('@').next().unwrap_or_default();
    let host = if let Some(rest) = host_port.strip_prefix('[') {
        rest.split(']').next().unwrap_or_default()
    } else {
        host_port.split(':').next().unwrap_or_default()
    }
    .trim_end_matches('.');
    !matches!(
        host.to_ascii_lowercase().as_str(),
        "localhost" | "127.0.0.1" | "::1"
    )
}

fn has_sensitive_url_key(url: &str) -> bool {
    url.split_once('?')
        .map(|(_, query)| query.split('#').next().unwrap_or(query))
        .into_iter()
        .flat_map(|query| query.split('&'))
        .filter_map(|pair| pair.split('=').next())
        .any(|key| {
            let key = percent_decode_ascii(key);
            let key = key.trim_end_matches("[]");
            matches!(
                key.to_ascii_lowercase().as_str(),
                "access_token"
                    | "api-key"
                    | "api_key"
                    | "apikey"
                    | "auth"
                    | "authorization"
                    | "key"
                    | "password"
                    | "secret"
                    | "token"
            )
        })
}

fn percent_decode_ascii(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
        {
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn is_reference(value: &str) -> bool {
    let value = value.trim();
    if let Some(inner) = value
        .strip_prefix("${")
        .and_then(|value| value.strip_suffix('}'))
    {
        if let Some(input) = inner.strip_prefix("input:") {
            return valid_reference_name(input, true);
        }
        if let Some(variable) = inner.strip_prefix("env:") {
            return valid_reference_name(variable, false);
        }
        return valid_reference_name(inner, false);
    }
    value
        .strip_prefix('$')
        .is_some_and(|name| valid_reference_name(name, false))
}

fn valid_reference_name(value: &str, input: bool) -> bool {
    let mut chars = value.chars();
    chars.next().is_some_and(|first| {
        (first.is_ascii_alphabetic() || first == '_' || (input && first.is_ascii_digit()))
            && chars.all(|ch| {
                ch.is_ascii_alphanumeric() || ch == '_' || (input && matches!(ch, '-' | '.'))
            })
    })
}

fn severity_rank(value: &str) -> u8 {
    Severity::parse(value).map_or(0, |severity| match severity {
        Severity::Info => 1,
        Severity::Low => 2,
        Severity::Medium => 3,
        Severity::High => 4,
        Severity::Critical => 5,
    })
}

fn strip_json_comments(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    while let Some(ch) = chars.next() {
        if in_string {
            out.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
        } else if ch == '"' {
            in_string = true;
            out.push(ch);
        } else if ch == '/' && chars.peek() == Some(&'/') {
            chars.next();
            for comment in chars.by_ref() {
                if comment == '\n' {
                    out.push('\n');
                    break;
                }
            }
        } else if ch == '/' && chars.peek() == Some(&'*') {
            chars.next();
            let mut previous = '\0';
            for comment in chars.by_ref() {
                if comment == '\n' {
                    out.push('\n');
                }
                if previous == '*' && comment == '/' {
                    break;
                }
                previous = comment;
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn clean_jsonc(input: &str) -> String {
    let mut without_comments = strip_json_comments(input);
    let mut out = String::with_capacity(without_comments.len());
    let mut pending_whitespace = String::new();
    let mut pending_comma = false;
    let mut in_string = false;
    let mut escaped = false;
    for ch in without_comments.chars() {
        if in_string {
            out.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        if pending_comma {
            if ch.is_whitespace() {
                pending_whitespace.push(ch);
                continue;
            }
            if matches!(ch, '}' | ']') {
                out.push_str(&pending_whitespace);
                pending_whitespace.clear();
                pending_comma = false;
                out.push(ch);
                continue;
            }
            out.push(',');
            out.push_str(&pending_whitespace);
            pending_whitespace.clear();
            pending_comma = false;
        }
        if ch == '"' {
            in_string = true;
            out.push(ch);
            continue;
        }
        if ch == ',' {
            pending_comma = true;
            continue;
        }
        out.push(ch);
    }
    if pending_comma {
        out.push(',');
        out.push_str(&pending_whitespace);
    }
    without_comments.zeroize();
    pending_whitespace.zeroize();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn audit_entry(entry: McpServerEntry) -> Vec<Finding> {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut findings = Vec::new();
        check_entry(dir.path(), None, &entry, &mut findings).expect("audit");
        findings
    }

    fn stdio(command: &str, args: &[&str]) -> McpServerEntry {
        McpServerEntry {
            client: "test".into(),
            source_file: PathBuf::from(".mcp.json"),
            name: "demo".into(),
            transport: McpTransport::Stdio {
                command: command.into(),
                args: args.iter().map(|value| (*value).into()).collect(),
                env: BTreeMap::new(),
            },
        }
    }

    #[test]
    fn npx_auto_install_and_pin_checks_scoped_packages() {
        let findings = audit_entry(stdio("npx", &["-y", "@scope/pkg"]));
        assert!(findings.iter().any(|f| f.rule_id == "mcp.npx_auto_install"));
        assert!(findings.iter().any(|f| f.rule_id == "mcp.unpinned_package"));
        let findings = audit_entry(stdio("npx", &["-y", "@scope/pkg@1.2.3"]));
        assert!(!findings.iter().any(|f| f.rule_id == "mcp.unpinned_package"));
        let findings = audit_entry(stdio(
            "npx",
            &["--package=@scope/pkg@1.2.3", "server-command"],
        ));
        assert!(!findings.iter().any(|f| f.rule_id == "mcp.unpinned_package"));
        let findings = audit_entry(stdio("uvx", &["--from=demo==1.2.3", "server-command"]));
        assert!(!findings.iter().any(|f| f.rule_id == "mcp.unpinned_package"));
    }

    #[test]
    fn exact_versions_allow_prerelease_and_build_suffixes() {
        for version in [
            "1.2.3",
            "1.2.3-beta.1",
            "1.2.3+build.7",
            "1.2.3-beta.1+build.7",
        ] {
            assert!(exact_version(version), "{version}");
        }
        for version in [
            "1.2",
            "1.2.x",
            "^1.2.3",
            "1.2.3-",
            "1.2.3+",
            "1.2.3-beta..1",
        ] {
            assert!(!exact_version(version), "{version}");
        }

        let findings = audit_entry(stdio("npx", &["@scope/pkg@1.2.3-beta.1"]));
        assert!(!findings.iter().any(|f| f.rule_id == "mcp.unpinned_package"));
    }

    #[test]
    fn http_tls_allows_loopback_only() {
        assert!(!is_insecure_remote_http("http://localhost:8080/mcp"));
        assert!(!is_insecure_remote_http("HTTP://user@localhost./mcp"));
        assert!(!is_insecure_remote_http("http://127.0.0.1/mcp"));
        assert!(!is_insecure_remote_http("http://[::1]:8080/mcp"));
        assert!(is_insecure_remote_http("http://example.com/mcp"));
    }

    #[test]
    fn env_reference_is_safe_but_literal_secret_is_reported() {
        let mut reference = stdio("node", &["server.js"]);
        let McpTransport::Stdio { env, .. } = &mut reference.transport else {
            unreachable!();
        };
        env.insert("TOKEN".into(), "${GITHUB_TOKEN}".into());
        assert!(audit_entry(reference).is_empty());
        assert!(is_reference("${input:github-token}"));
        assert!(is_reference("${env:GITHUB_TOKEN}"));
        assert!(!is_reference("${GITHUB_TOKEN:-literal-default}"));

        let mut literal = stdio("node", &["server.js"]);
        let McpTransport::Stdio { env, .. } = &mut literal.transport else {
            unreachable!();
        };
        let synthetic = format!("{}{}", "sk-proj-", "zbcdefghijklmnopqrstuvwxyz0123456789");
        env.insert("TOKEN".into(), synthetic.clone());
        let findings = audit_entry(literal);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "secret.openai_api_key")
        );
        assert!(
            !serde_json::to_string(&findings)
                .unwrap()
                .contains(&synthetic)
        );

        let mut default_literal = stdio("node", &["server.js"]);
        let McpTransport::Stdio { env, .. } = &mut default_literal.transport else {
            unreachable!();
        };
        env.insert("TOKEN".into(), format!("${{TOKEN:-{synthetic}}}"));
        assert!(
            audit_entry(default_literal)
                .iter()
                .any(|f| f.rule_id == "secret.openai_api_key")
        );
    }

    #[test]
    fn parses_vscode_and_codex_formats() {
        let vscode = parse_config(
            "vscode",
            Path::new(".vscode/mcp.json"),
            Format::JsonServers,
            r#"{"servers":{"demo":{"command":"npx","args":["pkg"]}}}"#,
        )
        .unwrap();
        assert!(matches!(vscode[0].transport, McpTransport::Stdio { .. }));
        let codex = parse_config(
            "codex",
            Path::new(".codex/config.toml"),
            Format::Toml,
            "[mcp_servers.remote]\nurl = \"https://example.com/mcp\"\n",
        )
        .unwrap();
        assert!(matches!(codex[0].transport, McpTransport::Http { .. }));
    }

    #[test]
    fn broken_json_becomes_finding_and_other_configs_continue() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".mcp.json"), "{broken").unwrap();
        fs::create_dir_all(dir.path().join(".cursor")).unwrap();
        fs::write(
            dir.path().join(".cursor/mcp.json"),
            r#"{"mcpServers":{"ok":{"command":"node","args":["server.js"]}}}"#,
        )
        .unwrap();
        let report = audit(dir.path(), false, Severity::High).unwrap();
        assert_eq!(report.servers.len(), 1);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule_id == "mcp.config_unreadable")
        );
    }

    #[test]
    fn jsonc_comments_are_accepted() {
        let entries = parse_config(
            "vscode",
            Path::new(".vscode/mcp.json"),
            Format::JsonServers,
            "{\n// comment\n\"servers\":{\"demo\":{\"command\":\"node\",},},\n}",
        )
        .unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn shell_local_executable_and_unknown_transport_rules() {
        let shell = audit_entry(stdio("bash", &["-c", "echo safe"]));
        assert!(shell.iter().any(|f| f.rule_id == "mcp.shell_wrapper"));

        let local = audit_entry(stdio("./bin/server", &[]));
        assert!(
            local
                .iter()
                .any(|f| f.rule_id == "mcp.local_unpinned_executable")
        );
        #[cfg(unix)]
        let system = audit_entry(stdio("/usr/bin/python3", &["server.py"]));
        #[cfg(windows)]
        let system = {
            let command = std::env::var("SystemRoot")
                .map(|root| format!(r"{root}\System32\cmd.exe"))
                .unwrap_or_else(|_| r"C:\Windows\System32\cmd.exe".into());
            audit_entry(stdio(&command, &["server.py"]))
        };
        assert!(
            !system
                .iter()
                .any(|f| f.rule_id == "mcp.local_unpinned_executable")
        );

        let mut unknown = stdio("node", &[]);
        unknown.transport = McpTransport::Unknown;
        assert!(
            audit_entry(unknown)
                .iter()
                .any(|f| f.rule_id == "mcp.unknown_transport")
        );
    }

    #[test]
    fn filesystem_scope_and_sensitive_url_rules() {
        let root = audit_entry(stdio(
            "npx",
            &["@modelcontextprotocol/server-filesystem@1.2.3", "/"],
        ));
        assert!(
            root.iter()
                .any(|f| { f.rule_id == "mcp.broad_filesystem_scope" && f.severity == "high" })
        );
        let home = audit_entry(stdio(
            "npx",
            &["@modelcontextprotocol/server-filesystem@1.2.3", "~"],
        ));
        assert!(
            home.iter()
                .any(|f| { f.rule_id == "mcp.broad_filesystem_scope" && f.severity == "medium" })
        );
        let mut binary = stdio("/opt/tools/mcp-server-filesystem", &["/"]);
        binary.name = "files".into();
        assert!(
            audit_entry(binary)
                .iter()
                .any(|f| f.rule_id == "mcp.broad_filesystem_scope")
        );

        let entry = McpServerEntry {
            client: "test".into(),
            source_file: PathBuf::from(".mcp.json"),
            name: "remote".into(),
            transport: McpTransport::Http {
                url: "http://example.com/mcp?token=${TOKEN}".into(),
                headers: BTreeMap::new(),
            },
        };
        let findings = audit_entry(entry);
        assert!(findings.iter().any(|f| f.rule_id == "mcp.http_no_tls"));
        assert!(findings.iter().any(|f| f.rule_id == "mcp.secret_in_url"));
        assert!(has_sensitive_url_key(
            "https://example.com/mcp?api%5Fkey=value"
        ));
    }

    #[test]
    fn project_allowlist_suppresses_scanner_findings() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("shk.toml"),
            "[[allowlist]]\nrule_id = \"secret.openai_api_key\"\npath = \".mcp.json\"\nreason = \"test fixture\"\n",
        )
        .unwrap();
        let mut entry = stdio("node", &[]);
        entry.source_file = dir.path().join(".mcp.json");
        let McpTransport::Stdio { env, .. } = &mut entry.transport else {
            unreachable!();
        };
        env.insert(
            "TOKEN".into(),
            format!("{}{}", "sk-proj-", "qbcdefghijklmnopqrstuvwxyz0123456789"),
        );
        let mut findings = Vec::new();
        check_entry(dir.path(), None, &entry, &mut findings).unwrap();
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == "secret.openai_api_key")
        );
    }

    #[cfg(unix)]
    #[test]
    fn project_scan_does_not_follow_config_symlinks_outside_root() {
        use std::os::unix::fs::symlink;

        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(
            outside.path().join("external.json"),
            r#"{"mcpServers":{"outside":{"command":"node"}}}"#,
        )
        .unwrap();
        symlink(
            outside.path().join("external.json"),
            project.path().join(".mcp.json"),
        )
        .unwrap();

        let report = audit(project.path(), false, Severity::High).unwrap();
        assert!(report.servers.is_empty());
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule_id == "mcp.config_unreadable")
        );
    }

    #[cfg(unix)]
    #[test]
    fn project_scan_rejects_hard_linked_config_files() {
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(
            outside.path().join("external.json"),
            r#"{"mcpServers":{"outside":{"command":"node"}}}"#,
        )
        .unwrap();
        fs::hard_link(
            outside.path().join("external.json"),
            project.path().join(".mcp.json"),
        )
        .unwrap();

        let report = audit(project.path(), false, Severity::High).unwrap();
        assert!(report.servers.is_empty());
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule_id == "mcp.config_unreadable")
        );
    }

    #[test]
    fn oversized_and_excessive_configs_are_rejected_as_findings() {
        let project = tempfile::tempdir().unwrap();
        fs::write(
            project.path().join(".mcp.json"),
            vec![b' '; MAX_CONFIG_BYTES as usize + 1],
        )
        .unwrap();
        let report = audit(project.path(), false, Severity::High).unwrap();
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule_id == "mcp.config_unreadable")
        );

        let servers = (0..=MAX_SERVERS_PER_CONFIG)
            .map(|index| format!("\"server-{index}\":{{\"command\":\"node\"}}"))
            .collect::<Vec<_>>()
            .join(",");
        let content = format!("{{\"mcpServers\":{{{servers}}}}}");
        assert!(parse_config("test", Path::new(".mcp.json"), Format::JsonMcp, &content,).is_err());
    }
}
