//! Pre-tool action guard for AI hook payloads.

use anyhow::{Context, Result};
use serde_json::Value;

const SECRET_PATH_PATTERNS: &[&str] = &[
    ".env",
    "./.env",
    ".env.*",
    "./.env.*",
    "tokens/*.json",
    "./tokens/*.json",
    "**/*token*",
    "**/*key*",
    "**/*secret*",
    "**/*password*",
    "**/*credential*",
];

const SECRET_READ_COMMANDS: &[&str] = &["cat", "head", "tail", "less", "more", "source"];
const EXTERNAL_TRANSFER_COMMANDS: &[&str] = &[
    "curl", "wget", "nc", "netcat", "ssh", "scp", "rsync", "ftp", "sftp",
];
const PRIVILEGE_SYSTEM_COMMANDS: &[&str] = &[
    "sudo",
    "su",
    "chown",
    "chgrp",
    "mount",
    "umount",
    "systemctl",
    "service",
];
const PACKAGE_MANAGER_COMMANDS: &[&str] = &["apt", "yum", "dnf", "pacman", "brew"];
const DB_CLIENT_COMMANDS: &[&str] = &[
    "psql",
    "mysql",
    "mongosh",
    "mongo",
    "redis-cli",
    "sqlite3",
    "sqlite",
];
const DB_MUTATION_WORDS: &[&str] = &[
    "drop", "delete", "update", "insert", "truncate", "alter", "create", "replace", "merge",
    "grant", "revoke", "flushall", "flushdb", "set", "del", "hset", "hmset", "lpush", "rpush",
    "sadd", "zadd",
];

const CLAUDE_SECRET_DENY_ENTRIES: &[&str] = &[
    "Read(.env)",
    "Write(.env)",
    "Read(.env.*)",
    "Write(.env.*)",
    "Write(tokens/*.json)",
    "Read(tokens/*.json)",
    "Read(**/*token*)",
    "Read(**/*key*)",
    "Read(**/*secret*)",
    "Read(**/*password*)",
    "Read(**/*credential*)",
    "Write(**/*token*)",
    "Write(**/*key*)",
    "Write(**/*secret*)",
    "Write(**/*password*)",
    "Write(**/*credential*)",
    "Bash(cat .env:*)",
    "Bash(cat ./.env:*)",
    "Bash(head .env:*)",
    "Bash(head ./.env:*)",
    "Bash(tail .env:*)",
    "Bash(tail ./.env:*)",
    "Bash(less .env:*)",
    "Bash(more .env:*)",
    "Bash(source .env:*)",
    "Bash(cat tokens/:*)",
    "Bash(cat ./tokens/:*)",
    "Bash(head tokens/:*)",
    "Bash(tail tokens/:*)",
    "Bash(less tokens/:*)",
    "Bash(more tokens/:*)",
];

const CLAUDE_ACTION_DENY_ENTRIES: &[&str] = &[
    "Bash(rm -rf /)",
    "Bash(rm -rf ~)",
    "Bash(rm -rf ~/*)",
    "Bash(rm -rf /*)",
    "Bash(rm -rf .)",
    "Bash(rm -rf ..)",
    "Bash(sudo:*)",
    "Bash(su:*)",
    "Bash(curl:*)",
    "Bash(wget:*)",
    "Bash(nc:*)",
    "Bash(netcat:*)",
    "Bash(ssh:*)",
    "Bash(scp:*)",
    "Bash(rsync:*)",
    "Bash(ftp:*)",
    "Bash(sftp:*)",
    "Bash(psql:*)",
    "Bash(mysql:*)",
    "Bash(mongosh:*)",
    "Bash(mongo:*)",
    "Bash(redis-cli:*)",
    "Bash(sqlite3:*)",
    "Bash(sqlite:*)",
    "Bash(chmod 777:*)",
    "Bash(chown:*)",
    "Bash(chgrp:*)",
    "Bash(mount:*)",
    "Bash(umount:*)",
    "Bash(systemctl:*)",
    "Bash(service:*)",
    "Bash(apt:*)",
    "Bash(yum:*)",
    "Bash(dnf:*)",
    "Bash(pacman:*)",
    "Bash(brew:*)",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionGuardMatch {
    pub category: &'static str,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionGuardConfig {
    pub enabled: bool,
    pub profile: String,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

impl Default for ActionGuardConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            profile: "recommended".into(),
            allow: Vec::new(),
            deny: Vec::new(),
        }
    }
}

#[derive(Clone, Copy)]
enum ActionCategory {
    SecretFileAccess,
    SecretDumpCommand,
    DestructiveFilesystem,
    DirectDbMutation,
    PrivilegeSystemChange,
    ExternalTransfer,
    SystemInstall,
    OpaqueExecution,
    CustomPolicy,
}

impl ActionCategory {
    fn as_str(self) -> &'static str {
        match self {
            Self::SecretFileAccess => "secret_file_access",
            Self::SecretDumpCommand => "secret_dump_command",
            Self::DestructiveFilesystem => "destructive_filesystem",
            Self::DirectDbMutation => "direct_db_mutation",
            Self::PrivilegeSystemChange => "privilege_system_change",
            Self::ExternalTransfer => "external_transfer",
            Self::SystemInstall => "system_install",
            Self::OpaqueExecution => "opaque_execution",
            Self::CustomPolicy => "custom_policy",
        }
    }
}

pub fn claude_recommended_deny_entries() -> Vec<&'static str> {
    CLAUDE_SECRET_DENY_ENTRIES
        .iter()
        .chain(CLAUDE_ACTION_DENY_ENTRIES.iter())
        .copied()
        .collect()
}

pub fn detect_dangerous_action(stdin: &str) -> Result<Option<ActionGuardMatch>> {
    detect_dangerous_action_with_config(stdin, &ActionGuardConfig::default())
}

pub fn detect_dangerous_action_with_config(
    stdin: &str,
    config: &ActionGuardConfig,
) -> Result<Option<ActionGuardMatch>> {
    if !config.enabled {
        return Ok(None);
    }

    let v: Value = serde_json::from_str(stdin).context("hook stdin must be valid JSON")?;
    let profile = ActionGuardProfile::parse(&config.profile);

    for path in candidate_paths(&v) {
        if let Some(access) = access_kind_for_path(&v) {
            let action = format!("{}({path})", action_access_name(access));
            if action_allowed(&action, &config.allow) {
                continue;
            }
            if action_denied(&action, &config.deny) {
                return Ok(Some(guard_match(
                    ActionCategory::CustomPolicy,
                    format!("shk action guard: `{action}` denied by project policy"),
                )));
            }
            if !is_secret_path(&path) || !profile.includes(ActionCategory::SecretFileAccess) {
                continue;
            }
            return Ok(Some(guard_match(
                ActionCategory::SecretFileAccess,
                format!("shk action guard: {access} of sensitive path `{path}`"),
            )));
        }
    }

    for command in candidate_commands(&v) {
        let action = format!("Bash({command})");
        if action_allowed(&action, &config.allow) {
            continue;
        }
        if action_denied(&action, &config.deny) {
            return Ok(Some(guard_match(
                ActionCategory::CustomPolicy,
                format!("shk action guard: `{action}` denied by project policy"),
            )));
        }
        if let Some(m) = detect_dangerous_command(&command, profile) {
            return Ok(Some(m));
        }
    }

    Ok(None)
}

fn guard_match(category: ActionCategory, reason: impl Into<String>) -> ActionGuardMatch {
    ActionGuardMatch {
        category: category.as_str(),
        reason: reason.into(),
    }
}

fn action_access_name(access: &str) -> &'static str {
    if access == "write" { "Write" } else { "Read" }
}

#[derive(Clone, Copy)]
enum ActionGuardProfile {
    Minimal,
    Recommended,
    Strict,
}

impl ActionGuardProfile {
    fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "minimal" => Self::Minimal,
            "strict" => Self::Strict,
            _ => Self::Recommended,
        }
    }

    fn includes(self, category: ActionCategory) -> bool {
        match self {
            Self::Minimal => matches!(
                category,
                ActionCategory::SecretFileAccess
                    | ActionCategory::SecretDumpCommand
                    | ActionCategory::DestructiveFilesystem
                    | ActionCategory::DirectDbMutation
            ),
            Self::Recommended => true,
            Self::Strict => true,
        }
    }
}

fn access_kind_for_path(v: &Value) -> Option<&'static str> {
    let hay = compact_json_text(v);
    if contains_any(&hay, &["write", "edit", "create", "update", "delete"]) {
        Some("write")
    } else if contains_any(&hay, &["read", "open"]) {
        Some("read")
    } else {
        None
    }
}

fn candidate_paths(v: &Value) -> Vec<String> {
    let mut out = Vec::new();
    collect_strings_for_keys(
        v,
        &[
            "path",
            "file_path",
            "filePath",
            "target_file",
            "targetPath",
            "uri",
            "fileName",
        ],
        &mut out,
    );
    out.sort();
    out.dedup();
    out
}

fn candidate_commands(v: &Value) -> Vec<String> {
    let mut out = Vec::new();
    collect_strings_for_keys(
        v,
        &["command", "shell_command", "cmd", "args", "input"],
        &mut out,
    );
    out.sort();
    out.dedup();
    out
}

fn collect_strings_for_keys(v: &Value, keys: &[&str], acc: &mut Vec<String>) {
    match v {
        Value::Object(map) => {
            for (key, value) in map {
                if keys.iter().any(|candidate| candidate == &key.as_str()) {
                    push_string_values(value, acc);
                }
                collect_strings_for_keys(value, keys, acc);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_strings_for_keys(item, keys, acc);
            }
        }
        _ => {}
    }
}

fn push_string_values(v: &Value, acc: &mut Vec<String>) {
    match v {
        Value::String(s) => acc.push(s.clone()),
        Value::Array(items) => {
            let joined = items
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" ");
            if !joined.is_empty() {
                acc.push(joined);
            }
            for item in items {
                push_string_values(item, acc);
            }
        }
        Value::Object(map) => {
            for value in map.values() {
                push_string_values(value, acc);
            }
        }
        _ => {}
    }
}

fn detect_dangerous_command(
    command: &str,
    profile: ActionGuardProfile,
) -> Option<ActionGuardMatch> {
    let normalized = normalize_shell(command);
    let words = shell_words(&normalized);
    let cmd = words.first().copied().unwrap_or_default();

    if profile.includes(ActionCategory::SecretDumpCommand) && secret_dump_command(cmd, &words) {
        return Some(guard_match(
            ActionCategory::SecretDumpCommand,
            "shk action guard: command reads sensitive local files",
        ));
    }

    if profile.includes(ActionCategory::DestructiveFilesystem) && destructive_rm(&words) {
        return Some(guard_match(
            ActionCategory::DestructiveFilesystem,
            "shk action guard: destructive recursive removal",
        ));
    }

    if profile.includes(ActionCategory::PrivilegeSystemChange)
        && cmd == "chmod"
        && words.contains(&"777")
    {
        return Some(guard_match(
            ActionCategory::PrivilegeSystemChange,
            "shk action guard: world-writable permission change",
        ));
    }

    if profile.includes(ActionCategory::PrivilegeSystemChange)
        && PRIVILEGE_SYSTEM_COMMANDS.contains(&cmd)
    {
        return Some(guard_match(
            ActionCategory::PrivilegeSystemChange,
            format!("shk action guard: `{cmd}` requires explicit review"),
        ));
    }

    if profile.includes(ActionCategory::ExternalTransfer)
        && EXTERNAL_TRANSFER_COMMANDS.contains(&cmd)
    {
        return Some(guard_match(
            ActionCategory::ExternalTransfer,
            format!("shk action guard: `{cmd}` can transfer data externally"),
        ));
    }

    if profile.includes(ActionCategory::SystemInstall) && PACKAGE_MANAGER_COMMANDS.contains(&cmd) {
        return Some(guard_match(
            ActionCategory::SystemInstall,
            format!("shk action guard: `{cmd}` can change system packages"),
        ));
    }

    if matches!(profile, ActionGuardProfile::Strict) && opaque_execution(&words) {
        return Some(guard_match(
            ActionCategory::OpaqueExecution,
            "shk action guard: strict profile blocks opaque command execution",
        ));
    }

    if profile.includes(ActionCategory::DirectDbMutation)
        && DB_CLIENT_COMMANDS.contains(&cmd)
        && (has_db_mutation(&normalized) || matches!(profile, ActionGuardProfile::Strict))
    {
        return Some(guard_match(
            ActionCategory::DirectDbMutation,
            format!("shk action guard: direct_db_mutation (`{cmd}` appears to mutate a database)"),
        ));
    }

    None
}

fn action_allowed(action: &str, allow: &[String]) -> bool {
    action_list_matches(action, allow)
}

fn action_denied(action: &str, deny: &[String]) -> bool {
    action_list_matches(action, deny)
}

fn action_list_matches(action: &str, patterns: &[String]) -> bool {
    let action = normalize_action_pattern(action);
    patterns
        .iter()
        .map(|pattern| normalize_action_pattern(pattern))
        .any(|pattern| wildcard_match(&pattern, &action))
}

fn normalize_action_pattern(raw: &str) -> String {
    raw.trim()
        .trim_end_matches(":*")
        .replace(":*)", "*)")
        .replace("(./", "(")
        .replace("(file://", "(")
        .to_ascii_lowercase()
}

fn secret_dump_command(cmd: &str, words: &[&str]) -> bool {
    SECRET_READ_COMMANDS.contains(&cmd) && words.iter().skip(1).any(|w| is_secret_path(w))
}

fn destructive_rm(words: &[&str]) -> bool {
    if words.first() != Some(&"rm") || !words.iter().any(|w| w.contains('r') && w.contains('f')) {
        return false;
    }

    words
        .iter()
        .skip(1)
        .filter(|w| !w.starts_with('-'))
        .any(|target| matches!(*target, "/" | "~" | "~/*" | "/*" | "." | ".."))
}

fn has_db_mutation(command: &str) -> bool {
    let words = shell_words(command);
    words.iter().any(|word| DB_MUTATION_WORDS.contains(word))
}

fn opaque_execution(words: &[&str]) -> bool {
    matches!(
        words,
        ["bash", "-c", ..]
            | ["sh", "-c", ..]
            | ["zsh", "-c", ..]
            | ["python", "-c", ..]
            | ["python3", "-c", ..]
            | ["node", "-e", ..]
            | ["node", "--eval", ..]
            | ["ruby", "-e", ..]
            | ["perl", "-e", ..]
    )
}

fn is_secret_path(raw: &str) -> bool {
    let path = raw
        .trim_matches(|c: char| c == '"' || c == '\'' || c == '`' || c == ':' || c == ';')
        .trim_start_matches("file://");
    let lower = path.to_ascii_lowercase();
    if lower.ends_with("/.env")
        || lower.contains("/.env.")
        || lower.ends_with("/tokens")
        || (lower.contains("/tokens/") && lower.ends_with(".json"))
    {
        return true;
    }
    SECRET_PATH_PATTERNS
        .iter()
        .any(|pattern| wildcard_match(&pattern.to_ascii_lowercase(), &lower))
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    if pattern == text {
        return true;
    }
    let parts = pattern.split('*').collect::<Vec<_>>();
    if parts.len() == 1 {
        return pattern == text;
    }

    let mut rest = text;
    if let Some(first) = parts.first()
        && !first.is_empty()
    {
        let Some(stripped) = rest.strip_prefix(first) else {
            return false;
        };
        rest = stripped;
    }

    for part in parts
        .iter()
        .skip(1)
        .take(parts.len().saturating_sub(2))
        .filter(|part| !part.is_empty())
    {
        let Some(idx) = rest.find(part) else {
            return false;
        };
        rest = &rest[idx + part.len()..];
    }

    if let Some(last) = parts.last()
        && !last.is_empty()
    {
        return rest.ends_with(last);
    }
    true
}

fn normalize_shell(command: &str) -> String {
    command
        .trim()
        .trim_start_matches("Bash(")
        .trim_end_matches(')')
        .trim_end_matches(":*")
        .to_ascii_lowercase()
}

fn shell_words(command: &str) -> Vec<&str> {
    command
        .split(|c: char| {
            c.is_whitespace()
                || matches!(
                    c,
                    '"' | '\'' | '`' | ';' | '|' | '&' | '(' | ')' | ',' | '='
                )
        })
        .filter(|s| !s.is_empty())
        .collect()
}

fn compact_json_text(v: &Value) -> String {
    v.to_string().to_ascii_lowercase()
}

fn contains_any(hay: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| hay.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_db_mutation_but_not_select() {
        let drop = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {
                "command": "psql -c \"DROP TABLE users\""
            }
        })
        .to_string();
        assert_eq!(
            detect_dangerous_action(&drop).unwrap().unwrap().category,
            "direct_db_mutation"
        );

        let select = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {
                "command": "psql -c \"SELECT 1\""
            }
        })
        .to_string();
        assert!(detect_dangerous_action(&select).unwrap().is_none());
    }

    #[test]
    fn blocks_secret_reads() {
        let input = r#"{"tool_name":"Read","tool_input":{"file_path":".env"}}"#;
        assert_eq!(
            detect_dangerous_action(input).unwrap().unwrap().category,
            "secret_file_access"
        );
    }

    #[test]
    fn config_can_disable_or_allow_actions() {
        let drop = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {
                "command": "psql -c \"DROP TABLE users\""
            }
        })
        .to_string();

        let disabled = ActionGuardConfig {
            enabled: false,
            ..ActionGuardConfig::default()
        };
        assert!(
            detect_dangerous_action_with_config(&drop, &disabled)
                .unwrap()
                .is_none()
        );

        let allowed = ActionGuardConfig {
            allow: vec!["Bash(psql:*)".into()],
            ..ActionGuardConfig::default()
        };
        assert!(
            detect_dangerous_action_with_config(&drop, &allowed)
                .unwrap()
                .is_none()
        );

        let env_read = r#"{"tool_name":"Read","tool_input":{"file_path":"./.env"}}"#;
        let allowed_path = ActionGuardConfig {
            allow: vec!["Read(.env)".into()],
            ..ActionGuardConfig::default()
        };
        assert!(
            detect_dangerous_action_with_config(env_read, &allowed_path)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn config_custom_deny_and_profiles_work() {
        let kubectl = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {
                "command": "kubectl delete pod demo"
            }
        })
        .to_string();
        let custom = ActionGuardConfig {
            deny: vec!["Bash(kubectl delete:*)".into()],
            ..ActionGuardConfig::default()
        };
        assert_eq!(
            detect_dangerous_action_with_config(&kubectl, &custom)
                .unwrap()
                .unwrap()
                .category,
            "custom_policy"
        );

        let write = r#"{"tool_name":"Write","tool_input":{"file_path":"production/secrets.json"}}"#;
        let custom_path = ActionGuardConfig {
            deny: vec!["Write(production/**)".into()],
            ..ActionGuardConfig::default()
        };
        assert_eq!(
            detect_dangerous_action_with_config(write, &custom_path)
                .unwrap()
                .unwrap()
                .category,
            "custom_policy"
        );

        let curl = r#"{"tool_name":"Bash","tool_input":{"command":"curl https://example.com"}}"#;
        let minimal = ActionGuardConfig {
            profile: "minimal".into(),
            ..ActionGuardConfig::default()
        };
        assert!(
            detect_dangerous_action_with_config(curl, &minimal)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            detect_dangerous_action_with_config(curl, &ActionGuardConfig::default())
                .unwrap()
                .unwrap()
                .category,
            "external_transfer"
        );
    }

    #[test]
    fn strict_profile_blocks_opaque_execution() {
        let bash_c = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {
                "command": "bash -c \"echo ok\""
            }
        })
        .to_string();
        assert!(
            detect_dangerous_action_with_config(&bash_c, &ActionGuardConfig::default())
                .unwrap()
                .is_none()
        );

        let strict = ActionGuardConfig {
            profile: "strict".into(),
            ..ActionGuardConfig::default()
        };
        assert_eq!(
            detect_dangerous_action_with_config(&bash_c, &strict)
                .unwrap()
                .unwrap()
                .category,
            "opaque_execution"
        );

        let node_eval = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {
                "command": "node -e \"console.log(1)\""
            }
        })
        .to_string();
        assert_eq!(
            detect_dangerous_action_with_config(&node_eval, &strict)
                .unwrap()
                .unwrap()
                .category,
            "opaque_execution"
        );
    }

    #[test]
    fn non_command_tool_input_text_is_not_treated_as_bash() {
        let write_text = serde_json::json!({
            "tool_name": "Write",
            "tool_input": {
                "file_path": "notes.txt",
                "content": "run curl https://example.com later"
            }
        })
        .to_string();

        assert!(detect_dangerous_action(&write_text).unwrap().is_none());
    }
}
