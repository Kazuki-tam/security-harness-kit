use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const VALID_VALUES: &'static str = "info, low, medium, high, critical";

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Some(Self::Info),
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn meets_threshold(&self, fail_on: Severity) -> bool {
        *self >= fail_on
    }
}

impl From<shk_rules::Severity> for Severity {
    fn from(s: shk_rules::Severity) -> Self {
        match s {
            shk_rules::Severity::Info => Self::Info,
            shk_rules::Severity::Low => Self::Low,
            shk_rules::Severity::Medium => Self::Medium,
            shk_rules::Severity::High => Self::High,
            shk_rules::Severity::Critical => Self::Critical,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ColorMode {
    #[default]
    Auto,
    Always,
    Never,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ScanSection {
    /// `None` = absent from shk.toml → `effective_include()` returns `["**/*"]`.
    /// `Some([])` = explicit empty in shk.toml → scan no files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include: Option<Vec<String>>,
    /// `None` = absent from shk.toml → `effective_exclude()` returns built-in defaults.
    /// `Some([])` = explicit empty in shk.toml → no exclude patterns (scan everything).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude: Option<Vec<String>>,
    #[serde(default = "default_max_file")]
    pub max_file_size_bytes: u64,
    #[serde(default = "default_binary_detection")]
    pub binary_detection_bytes: usize,
    #[serde(default)]
    pub follow_symlinks: bool,
    #[serde(default)]
    pub include_binary: bool,
}

impl ScanSection {
    pub fn effective_include(&self) -> &[String] {
        match &self.include {
            Some(v) => v,
            None => static_default_include(),
        }
    }

    pub fn effective_exclude(&self) -> &[String] {
        match &self.exclude {
            Some(v) => v,
            None => static_default_excludes(),
        }
    }
}

fn static_default_include() -> &'static [String] {
    use std::sync::OnceLock;
    static CELL: OnceLock<Vec<String>> = OnceLock::new();
    CELL.get_or_init(default_include)
}

fn static_default_excludes() -> &'static [String] {
    use std::sync::OnceLock;
    static CELL: OnceLock<Vec<String>> = OnceLock::new();
    CELL.get_or_init(default_excludes)
}

fn default_include() -> Vec<String> {
    vec!["**/*".into()]
}

fn default_excludes() -> Vec<String> {
    vec![
        ".git/**".into(),
        "node_modules/**".into(),
        "dist/**".into(),
        "build/**".into(),
        "coverage/**".into(),
        "**/*.svg".into(),
        "**/*.png".into(),
        "**/*.jpg".into(),
        "**/*.jpeg".into(),
        "**/*.gif".into(),
        "**/*.webp".into(),
        "**/*.ico".into(),
        "**/*.icns".into(),
        "**/*.avif".into(),
        "**/*.bmp".into(),
        "**/*.tif".into(),
        "**/*.tiff".into(),
        "**/*.mp4".into(),
        "**/*.m4v".into(),
        "**/*.mov".into(),
        "**/*.webm".into(),
        "**/*.mkv".into(),
        "**/*.avi".into(),
        "**/*.ogv".into(),
        "**/*.mp3".into(),
        "**/*.m4a".into(),
        "**/*.wav".into(),
        "**/*.flac".into(),
        "**/*.aac".into(),
        "**/*.ogg".into(),
        "**/*.opus".into(),
        "**/*.woff".into(),
        "**/*.woff2".into(),
        "**/*.ttf".into(),
        "**/*.otf".into(),
        "**/*.eot".into(),
    ]
}

fn default_max_file() -> u64 {
    1_048_576
}

fn default_binary_detection() -> usize {
    8192
}

impl Default for ScanSection {
    fn default() -> Self {
        Self {
            include: None,
            exclude: None,
            max_file_size_bytes: default_max_file(),
            binary_detection_bytes: default_binary_detection(),
            follow_symlinks: false,
            include_binary: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RulesSection {
    #[serde(default = "default_true")]
    pub secrets: bool,
    #[serde(default = "default_true")]
    pub pii: bool,
    #[serde(default = "default_pii_langs")]
    pub pii_languages: Vec<String>,
    #[serde(default = "default_true")]
    pub env: bool,
    #[serde(default)]
    pub internal_terms: bool,
    #[serde(default = "default_true")]
    pub ai_context: bool,
}

impl Default for RulesSection {
    fn default() -> Self {
        Self {
            secrets: true,
            pii: true,
            pii_languages: default_pii_langs(),
            env: true,
            internal_terms: false,
            ai_context: true,
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_pii_langs() -> Vec<String> {
    vec!["en".into(), "ja".into()]
}

fn default_custom_kind() -> String {
    "internal".into()
}

fn default_custom_severity() -> String {
    "medium".into()
}

fn default_custom_confidence() -> Option<f32> {
    Some(1.0)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CustomRule {
    pub id: String,
    pub pattern: String,
    #[serde(default = "default_custom_severity")]
    pub severity: String,
    #[serde(default = "default_custom_kind")]
    pub kind: String,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default = "default_custom_confidence")]
    pub confidence: Option<f32>,
    #[serde(default)]
    pub case_insensitive: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn allowlist_all_paths() -> String {
    "**/*".into()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AllowlistEntry {
    #[serde(default)]
    pub rule_id: Option<String>,
    #[serde(default = "allowlist_all_paths")]
    pub path: String,
    #[serde(default)]
    pub value_hash: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub expires: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ThresholdsSection {
    #[serde(default = "default_fail_high")]
    pub default_fail_on: String,
    #[serde(default = "default_fail_high")]
    pub scan_fail_on: String,
    #[serde(default = "default_fail_high")]
    pub pre_commit_fail_on: String,
}

fn default_fail_high() -> String {
    "high".into()
}

impl Default for ThresholdsSection {
    fn default() -> Self {
        Self {
            default_fail_on: default_fail_high(),
            scan_fail_on: default_fail_high(),
            pre_commit_fail_on: default_fail_high(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MaskSection {
    #[serde(default = "default_mask_mode")]
    pub mode: String,
    #[serde(default = "default_mask_min_severity")]
    pub min_severity: String,
    #[serde(default = "default_redaction")]
    pub redaction: String,
    #[serde(default = "default_preserve")]
    pub preserve_prefix: usize,
    #[serde(default = "default_preserve")]
    pub preserve_suffix: usize,
}

fn default_mask_mode() -> String {
    "strict".into()
}

fn default_mask_min_severity() -> String {
    "medium".into()
}

fn default_redaction() -> String {
    "match".into()
}

fn default_preserve() -> usize {
    4
}

impl Default for MaskSection {
    fn default() -> Self {
        Self {
            mode: default_mask_mode(),
            min_severity: default_mask_min_severity(),
            redaction: default_redaction(),
            preserve_prefix: default_preserve(),
            preserve_suffix: default_preserve(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ActionGuardSection {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_action_guard_profile")]
    pub profile: String,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

fn default_action_guard_profile() -> String {
    "recommended".into()
}

impl Default for ActionGuardSection {
    fn default() -> Self {
        Self {
            enabled: true,
            profile: default_action_guard_profile(),
            allow: Vec::new(),
            deny: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct DoctorIgnoreSection {
    /// `None` = absent from shk.toml → `effective_required_patterns()` returns built-in defaults.
    /// `Some([])` = explicit empty in shk.toml → no required patterns checked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_patterns: Option<Vec<String>>,
}

impl DoctorIgnoreSection {
    pub fn effective_required_patterns(&self) -> &[String] {
        match &self.required_patterns {
            Some(v) => v,
            None => static_default_required_patterns(),
        }
    }
}

fn static_default_required_patterns() -> &'static [String] {
    use std::sync::OnceLock;
    static CELL: OnceLock<Vec<String>> = OnceLock::new();
    CELL.get_or_init(default_required_patterns)
}

fn default_required_patterns() -> Vec<String> {
    vec![
        ".env".into(),
        ".env.*".into(),
        "!.env.example".into(),
        "secrets/**".into(),
        "credentials/**".into(),
        "*.pem".into(),
        "*.key".into(),
        "*.p12".into(),
        "*.mobileprovision".into(),
        "*.log".into(),
    ]
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Policy {
    #[serde(default)]
    pub scan: ScanSection,
    #[serde(default)]
    pub rules: RulesSection,
    #[serde(default)]
    pub thresholds: ThresholdsSection,
    #[serde(default)]
    pub mask: MaskSection,
    #[serde(default)]
    pub action_guard: ActionGuardSection,
    #[serde(default)]
    pub doctor: DoctorSection,
    #[serde(default)]
    pub env: EnvSection,
    #[serde(default)]
    pub secrets: SecretsSection,
    /// Path-based / hash-based suppression (also see inline `# shk-ignore` in scanner).
    #[serde(default)]
    pub allowlist: Vec<AllowlistEntry>,
    /// Project-specific sensitive words or regexes.
    #[serde(default)]
    pub custom_rules: Vec<CustomRule>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct DoctorSection {
    #[serde(default)]
    pub ignore: DoctorIgnoreSection,
}

fn default_env_secret_store() -> String {
    "keyring".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct EnvSection {
    #[serde(default = "default_env_secret_store")]
    pub secret_store: String,
    #[serde(default)]
    pub project_id: Option<String>,
    #[serde(default)]
    pub onepassword: OnePasswordSection,
}

impl Default for EnvSection {
    fn default() -> Self {
        Self {
            secret_store: default_env_secret_store(),
            project_id: None,
            onepassword: OnePasswordSection::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct OnePasswordSection {
    #[serde(default)]
    pub vault: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct SecretsSection {
    #[serde(default)]
    pub profiles: BTreeMap<String, SecretProfile>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SecretProfile {
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub target_prefix: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub location: Option<String>,
    #[serde(default)]
    pub audit: Option<bool>,
    #[serde(default)]
    pub confirm: Option<bool>,
    #[serde(default)]
    pub create_if_missing: Option<bool>,
    #[serde(default)]
    pub expected_env: Option<String>,
}

impl Policy {
    pub fn load_from_dir(root: &Path) -> Result<(Self, Option<std::path::PathBuf>)> {
        let p = root.join("shk.toml");
        if p.is_file() {
            let s = std::fs::read_to_string(&p).with_context(|| format!("read {}", p.display()))?;
            let policy: Policy = toml::from_str(&s).with_context(|| "parse shk.toml")?;
            Ok((policy, Some(p)))
        } else {
            Ok((Self::default(), None))
        }
    }

    pub fn scan_fail_on(&self) -> Severity {
        Severity::parse(&self.thresholds.scan_fail_on)
            .or_else(|| Severity::parse(&self.thresholds.default_fail_on))
            .unwrap_or(Severity::High)
    }

    pub fn pre_commit_fail_on(&self) -> Severity {
        Severity::parse(&self.thresholds.pre_commit_fail_on)
            .or_else(|| Severity::parse(&self.thresholds.default_fail_on))
            .unwrap_or(Severity::High)
    }

    pub fn mask_min_severity(&self) -> Result<Severity> {
        Severity::parse(&self.mask.min_severity).with_context(|| {
            format!(
                "unsupported mask.min_severity `{}` (supported: {})",
                self.mask.min_severity,
                Severity::VALID_VALUES
            )
        })
    }

    pub fn rule_engine_config(&self) -> shk_rules::RuleEngineConfig {
        shk_rules::RuleEngineConfig {
            secrets: self.rules.secrets,
            pii: self.rules.pii,
            pii_languages: self.rules.pii_languages.clone(),
            env: self.rules.env,
            internal_terms: self.rules.internal_terms,
            ai_context: self.rules.ai_context,
        }
    }

    /// Validate `[env]` settings for the configured secret store backend.
    pub fn validate_env_config(&self, root: &Path) -> Result<()> {
        match self.env.secret_store.as_str() {
            "keyring" => Ok(()),
            "1password" => {
                if self
                    .env
                    .project_id
                    .as_ref()
                    .is_none_or(|value| value.trim().is_empty())
                {
                    let hint = suggest_env_project_id(root)
                        .map(|candidate| format!("; suggested project_id = \"{candidate}\""))
                        .unwrap_or_default();
                    anyhow::bail!(
                        "env.project_id is required when env.secret_store = \"1password\"{hint}"
                    );
                }
                if self
                    .env
                    .onepassword
                    .vault
                    .as_ref()
                    .is_none_or(|value| value.trim().is_empty())
                {
                    anyhow::bail!(
                        "env.onepassword.vault is required when env.secret_store = \"1password\""
                    );
                }
                if self
                    .env
                    .project_id
                    .as_ref()
                    .is_some_and(|value| value.contains(':'))
                {
                    anyhow::bail!(
                        "env.project_id must not contain ':' when env.secret_store = \"1password\"; use '/', '-', or '_' instead"
                    );
                }
                if self
                    .env
                    .project_id
                    .as_ref()
                    .is_some_and(|value| value != value.trim())
                {
                    anyhow::bail!(
                        "env.project_id must not have leading or trailing whitespace when env.secret_store = \"1password\""
                    );
                }
                Ok(())
            }
            other => anyhow::bail!(
                "unsupported env.secret_store `{other}`; supported: keyring, 1password"
            ),
        }
    }
}

/// Derive a stable, machine-independent project identifier suggestion from git metadata.
pub fn suggest_env_project_id(root: &Path) -> Option<String> {
    let repo_root = crate::git::discover_repo_root(root)?;
    let output = std::process::Command::new("git")
        .args(["remote", "get-url", "origin"])
        .current_dir(&repo_root)
        .output()
        .ok()?;
    if !output.status.success() {
        return repo_root
            .file_name()
            .and_then(|name| name.to_str())
            .map(sanitize_project_id);
    }
    let remote = String::from_utf8_lossy(&output.stdout).trim().to_string();
    project_id_from_git_remote(&remote).or_else(|| {
        repo_root
            .file_name()
            .and_then(|name| name.to_str())
            .map(sanitize_project_id)
    })
}

fn project_id_from_git_remote(remote: &str) -> Option<String> {
    let trimmed = remote.trim();
    if trimmed.is_empty() {
        return None;
    }
    let path = trimmed
        .strip_prefix("git@")
        .and_then(|rest| rest.split_once(':'))
        .map(|(host, repo)| format!("{host}/{repo}"))
        .or_else(|| {
            trimmed
                .strip_prefix("ssh://")
                .or_else(|| trimmed.strip_prefix("https://"))
                .or_else(|| trimmed.strip_prefix("http://"))
                .and_then(|rest| rest.split_once('/'))
                .map(|(authority, repo)| {
                    let host = authority
                        .rsplit_once('@')
                        .map(|(_, host)| host)
                        .unwrap_or(authority);
                    format!("{host}/{repo}")
                })
        })?;
    let mut normalized = path.trim_end_matches(".git").replace('\\', "/");
    while normalized.starts_with('/') {
        normalized.remove(0);
    }
    if normalized.is_empty() {
        return None;
    }
    Some(sanitize_project_id(&normalized))
}

fn sanitize_project_id(raw: &str) -> String {
    raw.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '/' | '-' | '_' | '.') {
                ch
            } else {
                '-'
            }
        })
        .collect()
}

pub fn default_policy_toml(strict: bool) -> String {
    if strict {
        return r#"[scan]
include = ["**/*"]
exclude = [
  ".git/**",
  "node_modules/**",
  "dist/**",
  "build/**",
  "coverage/**",
  "**/*.svg",
  "**/*.png",
  "**/*.jpg",
  "**/*.jpeg",
  "**/*.gif",
  "**/*.webp",
  "**/*.ico",
  "**/*.icns",
  "**/*.avif",
  "**/*.bmp",
  "**/*.tif",
  "**/*.tiff",
  "**/*.mp4",
  "**/*.m4v",
  "**/*.mov",
  "**/*.webm",
  "**/*.mkv",
  "**/*.avi",
  "**/*.ogv",
  "**/*.mp3",
  "**/*.m4a",
  "**/*.wav",
  "**/*.flac",
  "**/*.aac",
  "**/*.ogg",
  "**/*.opus",
  "**/*.woff",
  "**/*.woff2",
  "**/*.ttf",
  "**/*.otf",
  "**/*.eot"
]
max_file_size_bytes = 1048576
binary_detection_bytes = 8192
follow_symlinks = false
include_binary = false

[rules]
secrets = true
pii = true
pii_languages = ["en", "ja"]
env = true
internal_terms = false
ai_context = true

[thresholds]
default_fail_on = "medium"
scan_fail_on = "medium"
pre_commit_fail_on = "medium"

[mask]
mode = "strict"
min_severity = "medium"
redaction = "match"
# preserve_prefix = 4 # only when redaction = "partial"
# preserve_suffix = 4

[action_guard]
enabled = true
profile = "recommended" # minimal | recommended | strict
allow = []
deny = []

# Project-specific sensitive terms. Patterns use Rust regex syntax.
# [[custom_rules]]
# id = "internal.codename"
# pattern = "ProjectNebula|社外秘|CONFIDENTIAL_CLIENT_X"
# severity = "high"
# kind = "internal"
# message = "Internal confidential term detected"

[doctor.ignore]
required_patterns = [
  ".env",
  ".env.*",
  "!.env.example",
  "secrets/**",
  "credentials/**",
  "*.pem",
  "*.key",
  "*.p12",
  "*.mobileprovision",
  "*.log"
]

# Native env secret store (default: OS keyring). Opt in to 1Password for team vault sharing.
# [env]
# secret_store = "keyring" # keyring | 1password
# project_id = "acme/backend-api" # required when secret_store = "1password"
# [env.onepassword]
# vault = "shk-project-keys" # required when secret_store = "1password"

# Allowlist / inline suppressions (spec §5.3). Prefer path-scoped rows; use value_hash only as an equality fingerprint.
# Inline: # shk-ignore-next-line <rule_id>
# Markdown: <!-- shk-ignore-next-line <rule_id> -->
# [[allowlist]]
# rule_id = "secret.openai_api_key"
# path = "fixtures/**"
# reason = "demo fixture"
"#
        .to_string();
    }
    r#"[scan]
include = ["**/*"]
exclude = [
  ".git/**",
  "node_modules/**",
  "dist/**",
  "build/**",
  "coverage/**",
  "**/*.svg",
  "**/*.png",
  "**/*.jpg",
  "**/*.jpeg",
  "**/*.gif",
  "**/*.webp",
  "**/*.ico",
  "**/*.icns",
  "**/*.avif",
  "**/*.bmp",
  "**/*.tif",
  "**/*.tiff",
  "**/*.mp4",
  "**/*.m4v",
  "**/*.mov",
  "**/*.webm",
  "**/*.mkv",
  "**/*.avi",
  "**/*.ogv",
  "**/*.mp3",
  "**/*.m4a",
  "**/*.wav",
  "**/*.flac",
  "**/*.aac",
  "**/*.ogg",
  "**/*.opus",
  "**/*.woff",
  "**/*.woff2",
  "**/*.ttf",
  "**/*.otf",
  "**/*.eot"
]
max_file_size_bytes = 1048576
binary_detection_bytes = 8192
follow_symlinks = false
include_binary = false

[rules]
secrets = true
pii = true
pii_languages = ["en", "ja"]
env = true
internal_terms = false
ai_context = true

[thresholds]
default_fail_on = "high"
scan_fail_on = "high"
pre_commit_fail_on = "high"

[mask]
mode = "strict"
min_severity = "medium"
redaction = "match"
# preserve_prefix = 4 # only when redaction = "partial"
# preserve_suffix = 4

[action_guard]
enabled = true
profile = "recommended" # minimal | recommended | strict
allow = []
deny = []

# Project-specific sensitive terms. Patterns use Rust regex syntax.
# [[custom_rules]]
# id = "internal.codename"
# pattern = "ProjectNebula|社外秘|CONFIDENTIAL_CLIENT_X"
# severity = "high"
# kind = "internal"
# message = "Internal confidential term detected"

[doctor.ignore]
required_patterns = [
  ".env",
  ".env.*",
  "!.env.example",
  "secrets/**",
  "credentials/**",
  "*.pem",
  "*.key",
  "*.p12",
  "*.mobileprovision",
  "*.log"
]

# Native env secret store (default: OS keyring). Opt in to 1Password for team vault sharing.
# [env]
# secret_store = "keyring" # keyring | 1password
# project_id = "acme/backend-api" # required when secret_store = "1password"
# [env.onepassword]
# vault = "shk-project-keys" # required when secret_store = "1password"

# Allowlist / inline suppressions (spec §5.3). Prefer path-scoped rows; use value_hash only as an equality fingerprint.
# Inline: # shk-ignore-next-line <rule_id>
# Markdown: <!-- shk-ignore-next-line <rule_id> -->
# [[allowlist]]
# rule_id = "secret.openai_api_key"
# path = "fixtures/**"
# reason = "demo fixture"
"#
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_parse_string_and_threshold_order_are_stable() {
        assert_eq!(Severity::parse("INFO"), Some(Severity::Info));
        assert_eq!(Severity::parse("low"), Some(Severity::Low));
        assert_eq!(Severity::parse("Medium"), Some(Severity::Medium));
        assert_eq!(Severity::parse("high"), Some(Severity::High));
        assert_eq!(Severity::parse("critical"), Some(Severity::Critical));
        assert_eq!(Severity::parse("urgent"), None);

        assert_eq!(Severity::High.as_str(), "high");
        assert!(Severity::Critical.meets_threshold(Severity::High));
        assert!(Severity::High.meets_threshold(Severity::High));
        assert!(!Severity::Medium.meets_threshold(Severity::High));
    }

    #[test]
    fn rules_section_defaults_true_for_security_rule_groups() {
        let policy: Policy = toml::from_str("").unwrap();

        assert!(policy.rules.secrets);
        assert!(policy.rules.pii);
        assert!(policy.rules.env);
        assert!(policy.rules.ai_context);
        assert_eq!(policy.rules.pii_languages, ["en", "ja"]);
    }

    #[test]
    fn custom_rule_defaults_are_applied_during_deserialization() {
        let policy: Policy = toml::from_str(
            r#"
[[custom_rules]]
id = "internal.codename"
pattern = "ProjectNebula"
"#,
        )
        .unwrap();

        let rule = &policy.custom_rules[0];
        assert_eq!(rule.severity, "medium");
        assert_eq!(rule.kind, "internal");
        assert_eq!(rule.confidence, Some(1.0));
        assert!(rule.enabled);
    }

    #[test]
    fn scan_patterns_distinguish_missing_from_explicit_empty() {
        let missing: Policy = toml::from_str("[scan]\n").unwrap();
        assert_eq!(missing.scan.include, None);
        assert_eq!(missing.scan.exclude, None);
        assert_eq!(missing.scan.effective_include(), ["**/*"]);
        assert!(
            missing
                .scan
                .effective_exclude()
                .iter()
                .any(|pattern| pattern == ".git/**")
        );

        let explicit_empty: Policy =
            toml::from_str("[scan]\ninclude = []\nexclude = []\n").unwrap();
        assert_eq!(explicit_empty.scan.include, Some(vec![]));
        assert_eq!(explicit_empty.scan.exclude, Some(vec![]));
        assert!(explicit_empty.scan.effective_include().is_empty());
        assert!(explicit_empty.scan.effective_exclude().is_empty());
    }

    #[test]
    fn doctor_ignore_patterns_distinguish_missing_from_explicit_empty() {
        let missing: Policy = toml::from_str("[doctor.ignore]\n").unwrap();
        assert_eq!(missing.doctor.ignore.required_patterns, None);
        assert!(
            missing
                .doctor
                .ignore
                .effective_required_patterns()
                .iter()
                .any(|pattern| pattern == ".env")
        );

        let explicit_empty: Policy =
            toml::from_str("[doctor.ignore]\nrequired_patterns = []\n").unwrap();
        assert_eq!(explicit_empty.doctor.ignore.required_patterns, Some(vec![]));
        assert!(
            explicit_empty
                .doctor
                .ignore
                .effective_required_patterns()
                .is_empty()
        );
    }

    #[test]
    fn action_guard_defaults_and_overrides_parse() {
        let defaulted: Policy = toml::from_str("").unwrap();
        assert!(defaulted.action_guard.enabled);
        assert_eq!(defaulted.action_guard.profile, "recommended");
        assert!(defaulted.action_guard.allow.is_empty());
        assert!(defaulted.action_guard.deny.is_empty());

        let overridden: Policy = toml::from_str(
            r#"[action_guard]
enabled = false
profile = "minimal"
allow = ["Bash(psql:*)"]
deny = ["Bash(kubectl delete:*)"]
"#,
        )
        .unwrap();
        assert!(!overridden.action_guard.enabled);
        assert_eq!(overridden.action_guard.profile, "minimal");
        assert_eq!(overridden.action_guard.allow, ["Bash(psql:*)"]);
        assert_eq!(overridden.action_guard.deny, ["Bash(kubectl delete:*)"]);
    }

    #[test]
    fn secret_profiles_reject_unknown_fields() {
        let err = toml::from_str::<Policy>(
            r#"[secrets.profiles.prod]
provider = "aws"
format = "dotenv"
"#,
        )
        .unwrap_err();

        assert!(err.to_string().contains("unknown field `format`"), "{err}");
    }

    #[test]
    fn rule_engine_config_includes_policy_rule_switches() {
        let mut policy = Policy::default();
        policy.rules.secrets = false;
        policy.rules.pii = false;
        policy.rules.pii_languages = vec!["ja".into()];
        policy.rules.env = false;
        policy.rules.internal_terms = true;
        policy.rules.ai_context = false;

        let cfg = policy.rule_engine_config();
        assert!(!cfg.secrets);
        assert!(!cfg.pii);
        assert_eq!(cfg.pii_languages, vec!["ja"]);
        assert!(!cfg.env);
        assert!(cfg.internal_terms);
        assert!(!cfg.ai_context);
    }

    #[test]
    fn default_mask_min_severity_is_medium() {
        let policy = Policy::default();
        assert_eq!(policy.mask_min_severity().unwrap(), Severity::Medium);
    }

    #[test]
    fn load_from_dir_rejects_invalid_toml() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("shk.toml"), "not = [valid").unwrap();
        let err = Policy::load_from_dir(dir.path()).unwrap_err();
        assert!(err.to_string().contains("parse"), "{err}");
    }

    #[test]
    fn load_from_dir_uses_defaults_when_policy_missing() {
        let dir = tempfile::tempdir().unwrap();
        let (policy, path) = Policy::load_from_dir(dir.path()).unwrap();
        assert!(path.is_none());
        assert!(policy.rules.secrets);
        assert_eq!(policy.thresholds.scan_fail_on, "high");
        assert_eq!(policy.env.secret_store, "keyring");
    }

    #[test]
    fn env_section_defaults_to_keyring() {
        let policy: Policy = toml::from_str("").unwrap();
        assert_eq!(policy.env.secret_store, "keyring");
        assert!(policy.env.project_id.is_none());
        assert!(policy.env.onepassword.vault.is_none());
    }

    #[test]
    fn validate_env_config_requires_onepassword_fields() {
        let mut policy = Policy::default();
        policy.env.secret_store = "1password".to_string();
        let dir = tempfile::tempdir().unwrap();
        let err = policy.validate_env_config(dir.path()).unwrap_err();
        assert!(
            err.to_string().contains("env.project_id is required"),
            "{err}"
        );

        policy.env.project_id = Some("acme/backend".to_string());
        let err = policy.validate_env_config(dir.path()).unwrap_err();
        assert!(
            err.to_string()
                .contains("env.onepassword.vault is required"),
            "{err}"
        );

        policy.env.onepassword.vault = Some("shk-project-keys".to_string());
        policy.validate_env_config(dir.path()).unwrap();

        policy.env.project_id = Some("team:env".to_string());
        let err = policy.validate_env_config(dir.path()).unwrap_err();
        assert!(err.to_string().contains("must not contain ':'"), "{err}");

        policy.env.project_id = Some(" acme/backend ".to_string());
        let err = policy.validate_env_config(dir.path()).unwrap_err();
        assert!(
            err.to_string()
                .contains("must not have leading or trailing whitespace"),
            "{err}"
        );
    }

    #[test]
    fn suggest_env_project_id_sanitizes_git_remote() {
        assert_eq!(
            project_id_from_git_remote("git@github.com:acme/backend-api.git"), // shk-ignore pii.email
            Some("github.com/acme/backend-api".to_string())
        );
        assert_eq!(
            project_id_from_git_remote("https://github.com/acme/backend-api.git"),
            Some("github.com/acme/backend-api".to_string())
        );
        assert_eq!(
            project_id_from_git_remote(
                "https://alice:github-token-value@github.com/acme/backend-api.git" // shk-ignore pii.email
            ),
            Some("github.com/acme/backend-api".to_string())
        );
        assert_eq!(
            project_id_from_git_remote("ssh://git@github.com/acme/backend-api.git"), // shk-ignore pii.email
            Some("github.com/acme/backend-api".to_string())
        );
        assert_eq!(
            project_id_from_git_remote("/Users/alice/repos/backend-api.git"),
            None
        );
        assert_eq!(
            project_id_from_git_remote("file:///Users/alice/repos/backend-api.git"),
            None
        );
    }
}
