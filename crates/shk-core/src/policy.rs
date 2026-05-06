use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
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
    #[serde(default = "default_include")]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default = "default_max_file")]
    pub max_file_size_bytes: u64,
    #[serde(default = "default_binary_detection")]
    pub binary_detection_bytes: usize,
    #[serde(default)]
    pub follow_symlinks: bool,
    #[serde(default)]
    pub include_binary: bool,
    #[serde(default = "default_fancy_timeout")]
    pub fancy_regex_timeout_ms_per_file: u64,
}

fn default_include() -> Vec<String> {
    vec!["**/*".into()]
}

fn default_max_file() -> u64 {
    1_048_576
}

fn default_binary_detection() -> usize {
    8192
}

fn default_fancy_timeout() -> u64 {
    100
}

impl Default for ScanSection {
    fn default() -> Self {
        Self {
            include: default_include(),
            exclude: default_excludes(),
            max_file_size_bytes: default_max_file(),
            binary_detection_bytes: default_binary_detection(),
            follow_symlinks: false,
            include_binary: false,
            fancy_regex_timeout_ms_per_file: default_fancy_timeout(),
        }
    }
}

fn default_excludes() -> Vec<String> {
    vec![
        ".git/**".into(),
        "node_modules/**".into(),
        "dist/**".into(),
        "build/**".into(),
        "coverage/**".into(),
    ]
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RulesSection {
    #[serde(default = "default_true")]
    pub secrets: bool,
    #[serde(default = "default_true")]
    pub pii: bool,
    #[serde(default = "default_pii_langs")]
    pub pii_languages: Vec<String>,
    #[serde(default)]
    pub env: bool,
    #[serde(default)]
    pub internal_terms: bool,
}

impl Default for RulesSection {
    fn default() -> Self {
        Self {
            secrets: true,
            pii: true,
            pii_languages: default_pii_langs(),
            env: true,
            internal_terms: false,
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_pii_langs() -> Vec<String> {
    vec!["en".into(), "ja".into()]
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
    #[serde(default = "default_redaction")]
    pub redaction: String,
}

fn default_mask_mode() -> String {
    "strict".into()
}

fn default_redaction() -> String {
    "full".into()
}

impl Default for MaskSection {
    fn default() -> Self {
        Self {
            mode: default_mask_mode(),
            redaction: default_redaction(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DoctorIgnoreSection {
    #[serde(default = "default_required_patterns")]
    pub required_patterns: Vec<String>,
}

impl Default for DoctorIgnoreSection {
    fn default() -> Self {
        Self {
            required_patterns: default_required_patterns(),
        }
    }
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
    pub doctor: DoctorSection,
    /// Path-based / hash-based suppression (also see inline `# shk-ignore` in scanner).
    #[serde(default)]
    pub allowlist: Vec<AllowlistEntry>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct DoctorSection {
    #[serde(default)]
    pub ignore: DoctorIgnoreSection,
}

impl Policy {
    pub fn load_from_dir(root: &Path) -> Result<(Self, Option<std::path::PathBuf>)> {
        let p = root.join("shk.toml");
        if p.is_file() {
            let s = std::fs::read_to_string(&p).with_context(|| format!("read {}", p.display()))?;
            let base: Policy = toml::from_str(&s).with_context(|| "parse shk.toml")?;
            Ok((merge_defaults(base), Some(p)))
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

    pub fn rule_engine_config(&self) -> shk_rules::RuleEngineConfig {
        shk_rules::RuleEngineConfig {
            secrets: self.rules.secrets,
            pii: self.rules.pii,
            pii_languages: self.rules.pii_languages.clone(),
        }
    }
}

fn merge_defaults(mut p: Policy) -> Policy {
    if p.scan.include.is_empty() {
        p.scan.include = default_include();
    }
    if p.scan.exclude.is_empty() {
        p.scan.exclude = default_excludes();
    }
    if p.doctor.ignore.required_patterns.is_empty() {
        p.doctor.ignore.required_patterns = default_required_patterns();
    }
    p
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
  "coverage/**"
]
max_file_size_bytes = 1048576
binary_detection_bytes = 8192
follow_symlinks = false
include_binary = false
fancy_regex_timeout_ms_per_file = 100

[rules]
secrets = true
pii = true
pii_languages = ["en", "ja"]
env = true
internal_terms = false

[thresholds]
default_fail_on = "medium"
scan_fail_on = "medium"
pre_commit_fail_on = "medium"

[mask]
mode = "strict"
redaction = "full"

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

# Allowlist / inline suppressions (spec §5.3). Prefer path-scoped rows; use value_hash for value-specific cases.
# Inline: # shk-ignore-next-line <rule_id>
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
  "coverage/**"
]
max_file_size_bytes = 1048576
binary_detection_bytes = 8192
follow_symlinks = false
include_binary = false
fancy_regex_timeout_ms_per_file = 100

[rules]
secrets = true
pii = true
pii_languages = ["en", "ja"]
env = true
internal_terms = false

[thresholds]
default_fail_on = "high"
scan_fail_on = "high"
pre_commit_fail_on = "high"

[mask]
mode = "strict"
redaction = "full"

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

# Allowlist / inline suppressions (spec §5.3). Prefer path-scoped rows; use value_hash for value-specific cases.
# Inline: # shk-ignore-next-line <rule_id>
# [[allowlist]]
# rule_id = "secret.openai_api_key"
# path = "fixtures/**"
# reason = "demo fixture"
"#
    .to_string()
}
