//! Built-in rules: secrets, PII (en/ja subset), env hints.

use once_cell::sync::Lazy;
use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Secret,
    Pii,
    Env,
    AiContext,
    Ignore,
    Git,
}

#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub rule_id: &'static str,
    pub severity: Severity,
    pub kind: Kind,
    pub line: usize,
    pub column: usize,
    pub message: &'static str,
    pub confidence: f32,
    /// Exact substring matched by the rule (used for hashed allowlists).
    pub matched_text: String,
}

#[derive(Debug, Clone)]
pub struct RuleEngineConfig {
    pub secrets: bool,
    pub pii: bool,
    pub pii_languages: Vec<String>,
}

impl Default for RuleEngineConfig {
    fn default() -> Self {
        Self {
            secrets: true,
            pii: true,
            pii_languages: vec!["en".into(), "ja".into()],
        }
    }
}

struct CompiledRule {
    id: &'static str,
    severity: Severity,
    kind: Kind,
    re: Regex,
    message: &'static str,
    confidence: f32,
}

static RULES: Lazy<Vec<CompiledRule>> = Lazy::new(|| {
    vec![
        CompiledRule {
            id: "secret.openai_api_key",
            severity: Severity::High,
            kind: Kind::Secret,
            re: Regex::new(r"(?i)\bsk-(?:proj-)?[a-zA-Z0-9_-]{20,}\b")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Possible OpenAI API key detected",
            confidence: 0.9,
        },
        CompiledRule {
            id: "secret.aws_access_key",
            severity: Severity::High,
            kind: Kind::Secret,
            re: Regex::new(r"(?m)\b(AKIA|ASIA)[0-9A-Z]{16}\b")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Possible AWS access key id",
            confidence: 0.88,
        },
        CompiledRule {
            id: "secret.generic_api_key",
            severity: Severity::Medium,
            kind: Kind::Secret,
            re: Regex::new(
                r#"(?i)(api[_-]?key|apikey|secret[_-]?key)\s*[=:]\s*['"]?([a-zA-Z0-9_-]{16,})['"]?\b"#,
            )
            .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Possible API key assignment",
            confidence: 0.55,
        },
        CompiledRule {
            id: "secret.private_key_block",
            severity: Severity::Critical,
            kind: Kind::Secret,
            re: Regex::new(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Private key PEM block detected",
            confidence: 0.99,
        },
        CompiledRule {
            id: "pii.email",
            severity: Severity::Medium,
            kind: Kind::Pii,
            re: Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Email address detected",
            confidence: 0.85,
        },
        CompiledRule {
            id: "pii.en.ssn",
            severity: Severity::Medium,
            kind: Kind::Pii,
            re: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "US SSN pattern detected",
            confidence: 0.7,
        },
        CompiledRule {
            id: "pii.ja.phone",
            severity: Severity::Medium,
            kind: Kind::Pii,
            re: Regex::new(r"0\d{1,4}-\d{1,4}-\d{4}")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Japanese phone number pattern detected",
            confidence: 0.75,
        },
        CompiledRule {
            id: "pii.ja.postal_code",
            severity: Severity::Medium,
            kind: Kind::Pii,
            re: Regex::new(r"(?:〒)?\d{3}-\d{4}\b")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Japanese postal code pattern detected",
            confidence: 0.8,
        },
    ]
});

fn line_col(content: &str, byte_idx: usize) -> (usize, usize) {
    let prefix = &content[..byte_idx.min(content.len())];
    let line = prefix.bytes().filter(|&b| b == b'\n').count() + 1;
    let last_nl = prefix.rfind('\n').map(|i| i + 1).unwrap_or(0);
    let col = content[last_nl..byte_idx.min(content.len())]
        .chars()
        .count()
        + 1;
    (line, col)
}

fn rule_applies(rule_id: &str, cfg: &RuleEngineConfig) -> bool {
    if rule_id.starts_with("secret.") && !cfg.secrets {
        return false;
    }
    if rule_id.starts_with("pii.") && !cfg.pii {
        return false;
    }
    if rule_id.starts_with("pii.en.") && !cfg.pii_languages.iter().any(|l| l == "en") {
        return false;
    }
    if rule_id.starts_with("pii.ja.") && !cfg.pii_languages.iter().any(|l| l == "ja") {
        return false;
    }
    if (rule_id == "pii.email" || rule_id == "pii.credit_card" || rule_id == "pii.ipv4") && !cfg.pii
    {
        return false;
    }
    true
}

/// Apply the same patterns used for detection, replacing hits with `[REDACTED]`.
/// Used for JSON context lines so adjacent code does not leak secrets (spec §6).
pub fn redact_line_for_display(line: &str, cfg: &RuleEngineConfig) -> String {
    let mut s = line.to_string();
    for r in RULES.iter() {
        if !rule_applies(r.id, cfg) {
            continue;
        }
        s = r.re.replace_all(&s, "[REDACTED]").to_string();
    }
    const MAX: usize = 200;
    if s.chars().count() > MAX {
        let t: String = s.chars().take(MAX).collect();
        format!("{t}…")
    } else {
        s
    }
}

/// Scan full file content; `rel_path` used only for env heuristics (skip .env.example noise).
pub fn scan_content(content: &str, rel_path: &str, cfg: &RuleEngineConfig) -> Vec<RuleMatch> {
    let mut out = Vec::new();
    let skip_env_heavy = rel_path.ends_with(".env.example") || rel_path.contains(".env.sample");
    for r in RULES.iter() {
        if !rule_applies(r.id, cfg) {
            continue;
        }
        if r.kind == Kind::Env && skip_env_heavy {
            continue;
        }
        for m in r.re.find_iter(content) {
            let (line, column) = line_col(content, m.start());
            out.push(RuleMatch {
                rule_id: r.id,
                severity: r.severity,
                kind: r.kind,
                line,
                column,
                message: r.message,
                confidence: r.confidence,
                matched_text: m.as_str().to_string(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_openai_style_key() {
        let s = r#"const demo = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";"#;
        let cfg = RuleEngineConfig::default();
        let m = scan_content(s, "demo.ts", &cfg);
        assert!(
            m.iter().any(|x| x.rule_id == "secret.openai_api_key"),
            "{m:?}"
        );
    }

    #[test]
    fn redact_line_strips_email() {
        let cfg = RuleEngineConfig::default();
        let out = redact_line_for_display("user: admin@example.com ok", &cfg);
        assert!(!out.contains("example.com"));
        assert!(out.contains("[REDACTED]"));
    }
}
