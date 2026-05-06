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
    validator: Option<fn(&str) -> bool>,
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
            validator: None,
        },
        CompiledRule {
            id: "secret.aws_access_key",
            severity: Severity::High,
            kind: Kind::Secret,
            re: Regex::new(r"(?m)\b(AKIA|ASIA)[0-9A-Z]{16}\b")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Possible AWS access key id",
            confidence: 0.88,
            validator: None,
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
            validator: None,
        },
        CompiledRule {
            id: "secret.private_key_block",
            severity: Severity::Critical,
            kind: Kind::Secret,
            re: Regex::new(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Private key PEM block detected",
            confidence: 0.99,
            validator: None,
        },
        CompiledRule {
            id: "pii.email",
            severity: Severity::Medium,
            kind: Kind::Pii,
            re: Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Email address detected",
            confidence: 0.85,
            validator: None,
        },
        CompiledRule {
            id: "pii.credit_card",
            severity: Severity::Medium,
            kind: Kind::Pii,
            re: Regex::new(r"\b(?:\d[ -]?){13,19}\b")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Credit card number pattern detected",
            confidence: 0.9,
            validator: Some(luhn_valid),
        },
        CompiledRule {
            id: "pii.ipv4",
            severity: Severity::Low,
            kind: Kind::Pii,
            re: Regex::new(
                r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b",
            )
            .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "IPv4 address detected",
            confidence: 0.65,
            validator: None,
        },
        CompiledRule {
            id: "pii.ipv6",
            severity: Severity::Low,
            kind: Kind::Pii,
            re: Regex::new(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "IPv6 address detected",
            confidence: 0.6,
            validator: None,
        },
        CompiledRule {
            id: "pii.en.phone",
            severity: Severity::Medium,
            kind: Kind::Pii,
            re: Regex::new(r"(?:\+1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]\d{3}[-.\s]\d{4}\b")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "US/international phone number pattern detected",
            confidence: 0.75,
            validator: None,
        },
        CompiledRule {
            id: "pii.en.ein",
            severity: Severity::Low,
            kind: Kind::Pii,
            re: Regex::new(r"(?i)\b(?:ein|employer identification number)\s*[:#]?\s*\d{2}-\d{7}\b")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "US EIN pattern detected",
            confidence: 0.7,
            validator: None,
        },
        CompiledRule {
            id: "pii.en.postal_code",
            severity: Severity::Low,
            kind: Kind::Pii,
            re: Regex::new(r"(?i)\b(?:zip|postal(?: code)?)\s*[:#]?\s*\d{5}(?:-\d{4})?\b")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "US ZIP/postal code pattern detected",
            confidence: 0.6,
            validator: None,
        },
        CompiledRule {
            id: "pii.en.passport",
            severity: Severity::Low,
            kind: Kind::Pii,
            re: Regex::new(r"(?i)\bpassport(?:\s+(?:no|number))?\s*[:#]?\s*[A-Z0-9]{9}\b")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "US passport number pattern detected",
            confidence: 0.65,
            validator: None,
        },
        CompiledRule {
            id: "pii.en.name",
            severity: Severity::Info,
            kind: Kind::Pii,
            re: Regex::new(r"(?i)\b(?:name|full name|author|by)\s*[:#]\s*[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3}\b")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "English personal name label detected",
            confidence: 0.45,
            validator: None,
        },
        CompiledRule {
            id: "pii.en.ssn",
            severity: Severity::Medium,
            kind: Kind::Pii,
            re: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "US SSN pattern detected",
            confidence: 0.7,
            validator: None,
        },
        CompiledRule {
            id: "pii.ja.phone",
            severity: Severity::Medium,
            kind: Kind::Pii,
            re: Regex::new(r"0\d{1,4}-\d{1,4}-\d{4}")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Japanese phone number pattern detected",
            confidence: 0.75,
            validator: Some(japanese_phone_valid),
        },
        CompiledRule {
            id: "pii.ja.postal_code",
            severity: Severity::Medium,
            kind: Kind::Pii,
            re: Regex::new(r"(?i)(?:〒\d{3}-\d{4}\b|(?:郵便番号|郵便|postal(?: code)?)\s*[:：]?\s*\d{3}-\d{4}\b)")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Japanese postal code pattern detected",
            confidence: 0.8,
            validator: Some(japanese_postal_code_valid),
        },
        CompiledRule {
            id: "pii.ja.passport",
            severity: Severity::Medium,
            kind: Kind::Pii,
            re: Regex::new(r"\b[A-Z]{2}\d{7}\b").unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Japanese passport number pattern detected",
            confidence: 0.75,
            validator: None,
        },
        CompiledRule {
            id: "pii.ja.my_number",
            severity: Severity::Medium,
            kind: Kind::Pii,
            re: Regex::new(r"(?:マイナンバー|個人番号)\s*[:：]?\s*\d{12}")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Japanese My Number pattern detected",
            confidence: 0.8,
            validator: None,
        },
        CompiledRule {
            id: "pii.ja.corporate_number",
            severity: Severity::Medium,
            kind: Kind::Pii,
            re: Regex::new(r"(?:法人番号)\s*[:：]?\s*\d{13}")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Japanese corporate number pattern detected",
            confidence: 0.8,
            validator: None,
        },
        CompiledRule {
            id: "pii.ja.drivers_license",
            severity: Severity::Medium,
            kind: Kind::Pii,
            re: Regex::new(r"(?:運転免許証番号|免許証番号|運転免許番号)\s*[:：]?\s*\d{12}")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Japanese driver license number pattern detected",
            confidence: 0.75,
            validator: None,
        },
        CompiledRule {
            id: "pii.ja.bank_account",
            severity: Severity::Low,
            kind: Kind::Pii,
            re: Regex::new(
                r"(?:銀行|金融機関|支店|口座番号|口座)\s*[:：]?\s*[^\n]{0,40}\d{7}\b",
            )
            .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Japanese bank account pattern detected",
            confidence: 0.65,
            validator: None,
        },
        CompiledRule {
            id: "pii.ja.name",
            severity: Severity::Info,
            kind: Kind::Pii,
            re: Regex::new(r"(?:氏名|名前)\s*[:：]?\s*[\p{Han}\p{Hiragana}\p{Katakana}ー]{2,12}")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Japanese personal name label detected",
            confidence: 0.45,
            validator: None,
        },
    ]
});

fn luhn_valid(candidate: &str) -> bool {
    let digits: Vec<u32> = candidate.chars().filter_map(|c| c.to_digit(10)).collect();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }

    let mut sum = 0;
    let mut double = false;
    for d in digits.iter().rev() {
        let mut n = *d;
        if double {
            n *= 2;
            if n > 9 {
                n -= 9;
            }
        }
        sum += n;
        double = !double;
    }
    sum % 10 == 0
}

fn japanese_phone_valid(candidate: &str) -> bool {
    let groups: Vec<&str> = candidate.split('-').collect();
    if groups.len() < 3 {
        return true;
    }
    !groups[1..]
        .iter()
        .all(|group| group.chars().all(|c| c == '0'))
}

fn japanese_postal_code_valid(candidate: &str) -> bool {
    candidate.chars().any(|c| c.is_ascii_digit() && c != '0')
}

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
            if let Some(validate) = r.validator {
                if !validate(m.as_str()) {
                    continue;
                }
            }
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

    #[test]
    fn detects_luhn_valid_credit_card() {
        let cfg = RuleEngineConfig::default();
        let m = scan_content("card: 4111 1111 1111 1111", "demo.txt", &cfg);
        assert!(m.iter().any(|x| x.rule_id == "pii.credit_card"), "{m:?}");
    }

    #[test]
    fn ignores_luhn_invalid_credit_card_like_number() {
        let cfg = RuleEngineConfig::default();
        let m = scan_content("card: 4111 1111 1111 1112", "demo.txt", &cfg);
        assert!(!m.iter().any(|x| x.rule_id == "pii.credit_card"), "{m:?}");
    }

    #[test]
    fn applies_language_specific_pii_rules() {
        let cfg = RuleEngineConfig {
            pii_languages: vec!["en".into()],
            ..RuleEngineConfig::default()
        };
        let m = scan_content(
            "phone: (555) 555-5555\npassport AB1234567",
            "demo.txt",
            &cfg,
        );
        assert!(m.iter().any(|x| x.rule_id == "pii.en.phone"), "{m:?}");
        assert!(!m.iter().any(|x| x.rule_id == "pii.ja.passport"), "{m:?}");
    }

    #[test]
    fn detects_label_anchored_japanese_pii_rules() {
        let cfg = RuleEngineConfig::default();
        let text = "個人番号: 123456789012\n法人番号：1234567890123\n免許証番号 123456789012\n氏名: 山田太郎";
        let m = scan_content(text, "demo.txt", &cfg);
        for id in [
            "pii.ja.my_number",
            "pii.ja.corporate_number",
            "pii.ja.drivers_license",
            "pii.ja.name",
        ] {
            assert!(m.iter().any(|x| x.rule_id == id), "missing {id}: {m:?}");
        }
    }

    #[test]
    fn japanese_name_requires_label() {
        let cfg = RuleEngineConfig::default();
        let m = scan_content("山田太郎", "demo.txt", &cfg);
        assert!(!m.iter().any(|x| x.rule_id == "pii.ja.name"), "{m:?}");
    }
}
