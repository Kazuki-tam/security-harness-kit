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
    /// Config-reserved until a fancy-regex based rule is added.
    #[serde(default = "default_fancy_timeout")]
    pub fancy_regex_timeout_ms_per_file: u64,
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

fn default_fancy_timeout() -> u64 {
    100
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
            fancy_regex_timeout_ms_per_file: default_fancy_timeout(),
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

fn default_redaction() -> String {
    "full".into()
}

fn default_preserve() -> usize {
    4
}

impl Default for MaskSection {
    fn default() -> Self {
        Self {
            mode: default_mask_mode(),
            redaction: default_redaction(),
            preserve_prefix: default_preserve(),
            preserve_suffix: default_preserve(),
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
    pub doctor: DoctorSection,
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

    pub fn rule_engine_config(&self) -> shk_rules::RuleEngineConfig {
        shk_rules::RuleEngineConfig {
            secrets: self.rules.secrets,
            pii: self.rules.pii,
            pii_languages: self.rules.pii_languages.clone(),
            env: self.rules.env,
            internal_terms: self.rules.internal_terms,
        }
    }
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
# preserve_prefix = 4 # only when redaction = "partial"
# preserve_suffix = 4

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
  "coverage/**",
  "**/*.svg",
  "**/*.png",
  "**/*.jpg",
  "**/*.jpeg",
  "**/*.gif",
  "**/*.webp",
  "**/*.ico",
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
# preserve_prefix = 4 # only when redaction = "partial"
# preserve_suffix = 4

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

# Allowlist / inline suppressions (spec §5.3). Prefer path-scoped rows; use value_hash for value-specific cases.
# Inline: # shk-ignore-next-line <rule_id>
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
    fn rule_engine_config_includes_policy_rule_switches() {
        let mut policy = Policy::default();
        policy.rules.secrets = false;
        policy.rules.pii = false;
        policy.rules.pii_languages = vec!["ja".into()];
        policy.rules.env = false;
        policy.rules.internal_terms = true;

        let cfg = policy.rule_engine_config();
        assert!(!cfg.secrets);
        assert!(!cfg.pii);
        assert_eq!(cfg.pii_languages, vec!["ja"]);
        assert!(!cfg.env);
        assert!(cfg.internal_terms);
    }
}
