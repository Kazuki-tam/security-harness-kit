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
const ENVIRONMENT_DUMP_COMMANDS: &[&str] = &["printenv"];
const PYTHON_ENV_READ_PATTERNS: &[&str] = &[
    "os.environ",
    "os.getenv",
    "import environ",
    "print(environ",
    "environ[",
    "environ.get",
];
const NODE_ENV_READ_PATTERNS: &[&str] = &["process.env"];
const RUBY_ENV_READ_PATTERNS: &[&str] = &[
    "puts env",
    "p env",
    "env[",
    "env.fetch",
    "env.each",
    "env.to_h",
];
const PERL_ENV_READ_PATTERNS: &[&str] = &["%env", "$env{"];
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
    EnvironmentDump,
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
            Self::EnvironmentDump => "environment_dump",
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

pub fn normalize_claude_deny_entry(entry: &str) -> String {
    entry
        .trim()
        .replace("(./", "(")
        .replace(" ./.env", " .env")
        .replace(" ./tokens/", " tokens/")
        .trim_end_matches('/')
        .to_string()
}

pub fn claude_deny_entry_covers(existing: &str, required: &str) -> bool {
    normalize_claude_deny_entry(existing) == normalize_claude_deny_entry(required)
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
                    | ActionCategory::EnvironmentDump
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

    if profile.includes(ActionCategory::EnvironmentDump)
        && environment_dump_command(&normalized, &words)
    {
        return Some(guard_match(
            ActionCategory::EnvironmentDump,
            "shk action guard: command can expose process environment variables",
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

fn environment_dump_command(command: &str, words: &[&str]) -> bool {
    let Some(cmd) = words.first().copied() else {
        return false;
    };
    let base = command_basename(cmd);
    if ENVIRONMENT_DUMP_COMMANDS.contains(&base) {
        return true;
    }

    if base == "env" {
        return env_invocation_dumps(command, cmd);
    }

    if base == "export" {
        return shell_builtin_dumps(command, cmd, &["-p"]);
    }

    if base == "set" {
        return shell_builtin_dumps(command, cmd, &[]);
    }

    interpreter_environment_read(command, base, words) || command.contains("/proc/self/environ")
}

fn command_basename(cmd: &str) -> &str {
    cmd.rsplit('/').next().unwrap_or(cmd)
}

fn env_invocation_dumps(command: &str, cmd: &str) -> bool {
    let Some(after) = command_tail_after_invocation(command, cmd) else {
        return false;
    };
    let after = after.trim_start();
    if after.is_empty() || starts_with_shell_output_operator(after) {
        return true;
    }

    if let Some(token) = first_env_command_token(after) {
        return matches!(command_basename(token), "env" | "printenv");
    }

    true
}

fn shell_builtin_dumps(command: &str, name: &str, dump_flags: &[&str]) -> bool {
    let Some(after) = command_tail_after_invocation(command, name) else {
        return false;
    };
    let after = after.trim_start();
    after.is_empty()
        || starts_with_shell_output_operator(after)
        || dump_flags.iter().any(|flag| after.starts_with(flag))
}

fn first_env_command_token(after_env: &str) -> Option<&str> {
    for token in after_env.split_whitespace() {
        let token = token.trim_matches(|c: char| matches!(c, '"' | '\'' | '`'));
        if token.is_empty() {
            continue;
        }
        if starts_with_shell_output_operator(token) {
            return None;
        }
        if token.starts_with('-') || is_env_assignment(token) {
            continue;
        }
        return Some(token);
    }
    None
}

fn command_tail_after_invocation<'a>(command: &'a str, invoked: &str) -> Option<&'a str> {
    command.strip_prefix(invoked).or_else(|| {
        let base = command_basename(invoked);
        command.strip_prefix(base)
    })
}

fn starts_with_shell_output_operator(s: &str) -> bool {
    matches!(s.chars().next(), Some('|' | '>' | ';' | '&'))
}

fn is_env_assignment(token: &str) -> bool {
    let Some((key, _value)) = token.split_once('=') else {
        return false;
    };
    !key.is_empty()
        && key
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn interpreter_environment_read(command: &str, base: &str, words: &[&str]) -> bool {
    match base {
        "bash" | "sh" | "zsh" => {
            has_eval_flag(words, &["-c"]) && shell_eval_environment_dump(command, words)
        }
        "node" => eval_contains(words, &["-e", "--eval"], command, NODE_ENV_READ_PATTERNS),
        "ruby" => eval_contains(words, &["-e"], command, RUBY_ENV_READ_PATTERNS),
        "perl" => eval_contains(words, &["-e"], command, PERL_ENV_READ_PATTERNS),
        _ if base.starts_with("python") => {
            eval_contains(words, &["-c"], command, PYTHON_ENV_READ_PATTERNS)
        }
        _ => false,
    }
}

fn eval_contains(words: &[&str], flags: &[&str], command: &str, patterns: &[&str]) -> bool {
    has_eval_flag(words, flags) && contains_any(command, patterns)
}

fn has_eval_flag(words: &[&str], flags: &[&str]) -> bool {
    words.iter().any(|word| flags.contains(word))
}

fn shell_eval_environment_dump(command: &str, words: &[&str]) -> bool {
    if command.contains("/proc/self/environ") {
        return true;
    }

    let Some(eval_pos) = words.iter().position(|word| *word == "-c") else {
        return false;
    };
    let Some(eval_cmd) = words.get(eval_pos + 1).copied().map(command_basename) else {
        return false;
    };

    match eval_cmd {
        "printenv" => true,
        "env" => env_words_dump(&words[eval_pos + 1..]),
        "set" => shell_builtin_words_dump(command, &words[eval_pos + 1..], &[]),
        "export" => shell_builtin_words_dump(command, &words[eval_pos + 1..], &["-p"]),
        _ => false,
    }
}

fn env_words_dump(words: &[&str]) -> bool {
    for token in words.iter().skip(1) {
        if token.starts_with('-') || is_env_assignment(token) {
            continue;
        }
        return matches!(command_basename(token), "env" | "printenv");
    }
    true
}

fn shell_builtin_words_dump(command: &str, words: &[&str], dump_flags: &[&str]) -> bool {
    let Some(first_arg) = words.get(1).copied() else {
        return true;
    };
    dump_flags.contains(&first_arg)
        || command.contains(" set |")
        || command.contains(";set |")
        || command.contains(" export |")
        || command.contains(";export |")
        || command.contains(" export -p")
        || command.contains(";export -p")
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

    fn bash_payload(command: &str) -> String {
        serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {
                "command": command
            }
        })
        .to_string()
    }

    #[test]
    fn blocks_db_mutation_but_not_select() {
        let drop = bash_payload("psql -c \"DROP TABLE users\"");
        assert_eq!(
            detect_dangerous_action(&drop).unwrap().unwrap().category,
            "direct_db_mutation"
        );

        let select = bash_payload("psql -c \"SELECT 1\"");
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
    fn blocks_environment_dump_commands() {
        for command in [
            "printenv | grep API_KEY",
            "/usr/bin/printenv",
            "env | grep API_KEY",
            "/usr/bin/env",
            "env -- printenv",
            "env FOO=bar",
            "export -p",
            "set | grep API_KEY",
            "python -c \"import os; print(os.environ)\"",
            "python3 -c \"import os; print(os.getenv('API_KEY'))\"",
            "python -c \"from os import environ; print(environ)\"",
            "node -e \"console.log(process.env.API_KEY)\"",
            "node --eval \"console.log(process.env)\"",
            "ruby -e \"puts ENV.to_h\"",
            "ruby -e \"puts ENV\"",
            "ruby -e \"puts ENV.fetch('API_KEY')\"",
            "perl -e \"print $ENV{API_KEY}\"",
            "bash -c \"printenv | grep API_KEY\"",
            "sh -c \"env\"",
            "cat /proc/self/environ",
        ] {
            let input = bash_payload(command);
            assert_eq!(
                detect_dangerous_action(&input).unwrap().unwrap().category,
                "environment_dump",
                "{command}"
            );
        }
    }

    #[test]
    fn allows_non_dump_environment_helpers() {
        for command in [
            "env FOO=bar cargo test",
            "export FOO=bar",
            "set -e; cargo test",
            "python -c \"print('ok')\"",
            "node -e \"console.log(1)\"",
            "node --eval \"console.log(1)\"",
            "ruby -e \"puts 1\"",
            "perl -e \"print 1\"",
            "bash -c \"echo ok\"",
            "bash -c \"set -e; cargo test\"",
            "bash -c \"export FOO=bar; cargo test\"",
            "bash -c \"env FOO=bar cargo test\"",
        ] {
            let input = bash_payload(command);
            assert!(
                detect_dangerous_action(&input).unwrap().is_none(),
                "{command}"
            );
        }
    }

    #[test]
    fn config_can_disable_or_allow_actions() {
        let drop = bash_payload("psql -c \"DROP TABLE users\"");

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

        let allowed_env_dump = ActionGuardConfig {
            allow: vec!["Bash(printenv:*)".into()],
            ..ActionGuardConfig::default()
        };
        assert!(
            detect_dangerous_action_with_config(
                &bash_payload("printenv | grep API_KEY"),
                &allowed_env_dump
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn config_custom_deny_and_profiles_work() {
        let kubectl = bash_payload("kubectl delete pod demo");
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

        let curl = bash_payload("curl https://example.com");
        let minimal = ActionGuardConfig {
            profile: "minimal".into(),
            ..ActionGuardConfig::default()
        };
        assert!(
            detect_dangerous_action_with_config(&curl, &minimal)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            detect_dangerous_action_with_config(&curl, &ActionGuardConfig::default())
                .unwrap()
                .unwrap()
                .category,
            "external_transfer"
        );
    }

    #[test]
    fn strict_profile_blocks_opaque_execution() {
        let bash_c = bash_payload("bash -c \"echo ok\"");
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

        let node_eval = bash_payload("node -e \"console.log(1)\"");
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

    #[test]
    fn claude_deny_entry_covers_normalized_relative_paths() {
        assert!(claude_deny_entry_covers("Read(./.env)", "Read(.env)"));
        assert!(claude_deny_entry_covers(
            "Bash(cat ./.env:*)",
            "Bash(cat .env:*)"
        ));
        assert!(!claude_deny_entry_covers("Write(.env)", "Read(.env)"));
    }
}
