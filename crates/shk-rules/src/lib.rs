//! Built-in rules: secrets, PII (en/ja subset), env hints.

mod gitleaks_rules;

use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;

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
    pub env: bool,
    pub internal_terms: bool,
    pub ai_context: bool,
}

impl Default for RuleEngineConfig {
    fn default() -> Self {
        Self {
            secrets: true,
            pii: true,
            pii_languages: vec!["en".into(), "ja".into()],
            env: true,
            internal_terms: false,
            ai_context: true,
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

type LazyRegex = Lazy<Regex>;

struct GitleaksRule {
    id: &'static str,
    description: &'static str,
    re: LazyRegex,
    path: Option<LazyRegex>,
    secret_group: Option<usize>,
    entropy: Option<f32>,
    keywords: &'static [&'static str],
    allowlists: Vec<GitleaksAllowlist>,
}

struct GitleaksAllowlist {
    condition: AllowlistCondition,
    target: AllowlistTarget,
    regexes: Vec<LazyRegex>,
    paths: Vec<LazyRegex>,
    stopwords: &'static [&'static str],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum AllowlistCondition {
    Or,
    // Generated from upstream gitleaks rules when an allowlist declares
    // `condition = "AND"`. The current pinned rules may not exercise it.
    And,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum AllowlistTarget {
    Secret,
    Match,
    Line,
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
            validator: Some(openai_key_valid),
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
            id: "secret.anthropic_api_key",
            severity: Severity::High,
            kind: Kind::Secret,
            re: Regex::new(r"\bsk-ant-[a-zA-Z0-9_-]{20,}\b")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Possible Anthropic API key detected",
            confidence: 0.9,
            validator: None,
        },
        CompiledRule {
            id: "secret.google_api_key",
            severity: Severity::High,
            kind: Kind::Secret,
            re: Regex::new(r"\bAIza[a-zA-Z0-9_-]{30,}\b")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Possible Google API key detected",
            confidence: 0.9,
            validator: None,
        },
        CompiledRule {
            id: "secret.github_token",
            severity: Severity::High,
            kind: Kind::Secret,
            re: Regex::new(r"\bgh[ps]_[a-zA-Z0-9]{30,}\b")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Possible GitHub token detected",
            confidence: 0.9,
            validator: None,
        },
        CompiledRule {
            id: "secret.slack_token",
            severity: Severity::High,
            kind: Kind::Secret,
            re: Regex::new(r"\bxox[bprs]-[a-zA-Z0-9-]{20,}\b")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Possible Slack token detected",
            confidence: 0.9,
            validator: None,
        },
        CompiledRule {
            id: "secret.stripe_api_key",
            severity: Severity::High,
            kind: Kind::Secret,
            re: Regex::new(r"\b[rs]k_(?:live|test)_[a-zA-Z0-9]{20,}\b")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Possible Stripe API key detected",
            confidence: 0.9,
            validator: None,
        },
        CompiledRule {
            id: "secret.huggingface_token",
            severity: Severity::High,
            kind: Kind::Secret,
            re: Regex::new(r"\bhf_[A-Za-z0-9]{34,}\b")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Possible Hugging Face token detected",
            confidence: 0.9,
            validator: None,
        },
        CompiledRule {
            id: "secret.twilio_auth_token",
            severity: Severity::High,
            kind: Kind::Secret,
            re: Regex::new(
                r#"(?i)\btwilio[_-]?auth[_-]?token\s*[=:]\s*['"]?[0-9a-f]{32}\b"#,
            )
            .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Possible Twilio auth token detected",
            confidence: 0.88,
            validator: Some(labelled_token_valid),
        },
        CompiledRule {
            id: "secret.sendgrid_api_key",
            severity: Severity::High,
            kind: Kind::Secret,
            re: Regex::new(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Possible SendGrid API key detected",
            confidence: 0.9,
            validator: None,
        },
        CompiledRule {
            id: "secret.shopify_token",
            severity: Severity::High,
            kind: Kind::Secret,
            re: Regex::new(r"\bshp(?:at|ca|ss|ua)_[a-fA-F0-9]{32}\b")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Possible Shopify token detected",
            confidence: 0.9,
            validator: None,
        },
        CompiledRule {
            id: "secret.supabase_service_role_key",
            severity: Severity::High,
            kind: Kind::Secret,
            re: Regex::new(
                r#"(?i)\b(?:supabase[_-]?)?service[_-]?role(?:[_-]?key)?\s*[=:]\s*['"]?eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b"#,
            )
            .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Possible Supabase service role key detected",
            confidence: 0.9,
            validator: None,
        },
        CompiledRule {
            id: "secret.vercel_token",
            severity: Severity::High,
            kind: Kind::Secret,
            re: Regex::new(
                r#"(?i)\bvercel(?:[_-]?(?:api[_-]?)?token|[_-]?auth[_-]?token)\s*[=:]\s*['"]?[A-Za-z0-9_-]{24,}\b"#,
            )
            .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Possible Vercel token detected",
            confidence: 0.82,
            validator: Some(labelled_token_valid),
        },
        CompiledRule {
            id: "secret.npm_token",
            severity: Severity::High,
            kind: Kind::Secret,
            re: Regex::new(r"\bnpm_[A-Za-z0-9]{36}\b")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Possible npm token detected",
            confidence: 0.9,
            validator: None,
        },
        CompiledRule {
            id: "secret.gitlab_pat",
            severity: Severity::High,
            kind: Kind::Secret,
            re: Regex::new(r"\bglpat-[A-Za-z0-9_-]{20,}\b")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Possible GitLab personal access token detected",
            confidence: 0.9,
            validator: None,
        },
        CompiledRule {
            id: "secret.discord_webhook_url",
            severity: Severity::High,
            kind: Kind::Secret,
            re: Regex::new(r"https://discord(?:app)?\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_-]{60,}")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Possible Discord webhook URL detected",
            confidence: 0.9,
            validator: None,
        },
        CompiledRule {
            id: "secret.cloudflare_api_token",
            severity: Severity::High,
            kind: Kind::Secret,
            re: Regex::new(
                r#"(?i)\bcloudflare[_-]?(?:api[_-]?)?token\s*[=:]\s*['"]?[A-Za-z0-9_-]{30,}\b"#,
            )
            .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Possible Cloudflare API token detected",
            confidence: 0.82,
            validator: Some(labelled_token_valid),
        },
        CompiledRule {
            id: "secret.notion_integration_token",
            severity: Severity::High,
            kind: Kind::Secret,
            re: Regex::new(
                r#"(?i)\bnotion(?:[_-]?(?:integration[_-]?)?token|[_-]?secret)\s*[=:]\s*['"]?secret_[A-Za-z0-9]{43}\b"#,
            )
            .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Possible Notion integration token detected",
            confidence: 0.86,
            validator: Some(labelled_token_valid),
        },
        CompiledRule {
            id: "secret.linear_api_key",
            severity: Severity::High,
            kind: Kind::Secret,
            re: Regex::new(r"\blin_api_[A-Za-z0-9]{40,}\b")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Possible Linear API key detected",
            confidence: 0.9,
            validator: None,
        },
        CompiledRule {
            id: "secret.database_url",
            severity: Severity::High,
            kind: Kind::Secret,
            re: Regex::new(
                r#"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?)://[^@\s"']+@[^\s"'<>]+"#,
            )
            .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Possible database connection URL detected",
            confidence: 0.85,
            validator: None,
        },
        CompiledRule {
            id: "secret.jwt",
            severity: Severity::Medium,
            kind: Kind::Secret,
            re: Regex::new(r"\beyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\b")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Possible JWT detected",
            confidence: 0.75,
            validator: None,
        },
        CompiledRule {
            id: "secret.bearer_token",
            severity: Severity::Medium,
            kind: Kind::Secret,
            re: Regex::new(r"(?i)\bBearer\s+[a-zA-Z0-9._~+/=-]{20,}\b")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Possible bearer token detected",
            confidence: 0.7,
            validator: None,
        },
        CompiledRule {
            id: "secret.dotenvx_private_key",
            severity: Severity::High,
            kind: Kind::Secret,
            re: Regex::new(r##"(?m)\bDOTENV_PRIVATE_KEY(?:_[A-Z0-9_]+)?\s*=\s*['"]?[^\s'"#]+"##)
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "dotenvx private key detected",
            confidence: 0.95,
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
            validator: Some(generic_api_key_valid),
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
            id: "env.sensitive_assignment",
            severity: Severity::Medium,
            kind: Kind::Env,
            re: Regex::new(
                r"(?m)^\s*(?:export\s+)?[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY|CREDENTIAL)[A-Z0-9_]*\s*=\s*\S+",
            )
            .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Sensitive environment variable assignment detected",
            confidence: 0.6,
            validator: Some(env_assignment_valid),
        },
        CompiledRule {
            id: "pii.email",
            severity: Severity::Medium,
            kind: Kind::Pii,
            re: Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Email address detected",
            confidence: 0.85,
            validator: Some(email_valid),
        },
        CompiledRule {
            id: "pii.credit_card",
            severity: Severity::Medium,
            kind: Kind::Pii,
            // Ends on a digit so the matched text (and thus allowlist value
            // hashes) never carries a trailing separator.
            re: Regex::new(r"\b\d(?:[ -]?\d){12,18}\b")
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
            // Label is case-insensitive, but name words must be Title Case and stay on
            // one line; otherwise structural config keys like `- name: build` in
            // YAML/CI files produce false positives.
            re: Regex::new(
                r"\b(?i:name|full name|author|by)[ \t]*[:#][ \t]*[A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+){1,3}\b",
            )
            .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "English personal name label detected",
            confidence: 0.45,
            validator: None,
        },
        CompiledRule {
            id: "pii.en.address",
            severity: Severity::Info,
            kind: Kind::Pii,
            re: Regex::new(
                r"\b(?i:address|street address|mailing address)[ \t]*[:#][ \t]*\d{1,6}[ \t]+[A-Z][A-Za-z0-9.'-]*(?:[ \t]+[A-Z][A-Za-z0-9.'-]*){0,5}[ \t]+(?i:street|st|avenue|ave|road|rd|drive|dr|lane|ln|boulevard|blvd|court|ct|way)\b",
            )
            .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "English street address label detected",
            confidence: 0.45,
            validator: None,
        },
        CompiledRule {
            id: "pii.en.ssn",
            severity: Severity::Medium,
            kind: Kind::Pii,
            re: Regex::new(
                r"(?i)\b(?:ssn|social security(?: number)?|social security no\.?)\s*[:#]?\s*\d{3}-\d{2}-\d{4}\b",
            )
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
            re: Regex::new(
                r"(?i)(?:旅券番号|パスポート(?:番号|ナンバー)?|passport(?:\s+(?:no|number))?)\s*[:：#]?\s*[A-Z]{2}\d{7}\b",
            )
            .unwrap_or_else(|_| Regex::new("^$").unwrap()),
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
            id: "pii.ja.health_insurance",
            severity: Severity::Low,
            kind: Kind::Pii,
            re: Regex::new(
                r"(?:健康保険証|保険証|被保険者証)\s*[:：]?\s*[^\n]{0,40}(?:記号|番号)\s*[:：]?\s*[A-Za-z0-9\-]{4,20}",
            )
            .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Japanese health insurance card pattern detected",
            confidence: 0.6,
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
        CompiledRule {
            id: "pii.ja.address",
            severity: Severity::Low,
            kind: Kind::Pii,
            // Requires prefecture + municipality + block number together, so
            // prose mentions of places (東京都内で開催, 愛知県名古屋市は人口…)
            // do not match without a 1-2-3 / 2丁目3番5号 style block suffix.
            // The block-number tail consumes the whole chain so masking does
            // not leave a partial address behind, and hyphens must be
            // followed by digits to avoid matching dangling "2023-" tokens.
            // `ja_address_valid` rejects prose where a particle or 第
            // directly precedes the number (…区で3番目, …区の条例第5号) and
            // date-like tails (…区では2024-04-01).
            re: Regex::new(
                r"(?:北海道|東京都|京都府|大阪府|[\p{Han}]{2,3}県)[\p{Han}\p{Hiragana}\p{Katakana}]{1,8}[市区町村郡][\p{Han}\p{Hiragana}\p{Katakana}ー]{0,20}(?:[0-9０-９一二三四五六七八九十]{1,4}(?:丁目|番地|番|号)|[0-9０-９]{1,4}(?:[-‐－−][0-9０-９]{1,4}){1,3}){1,4}",
            )
            .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Japanese address pattern detected",
            confidence: 0.55,
            validator: Some(ja_address_valid),
        },
    ]
});

/// Reject `pii.ja.address` regex matches that are prose rather than
/// addresses: a particle (で/は/に/…) or counter prefix (第) directly before
/// the block number, or a date-like `YYYY-…` numeric tail.
fn ja_address_valid(candidate: &str) -> bool {
    let chars: Vec<char> = candidate.chars().collect();
    let is_numeral = |c: &char| {
        c.is_ascii_digit() || ('０'..='９').contains(c) || "一二三四五六七八九十".contains(*c)
    };
    let Some(first_digit) = chars.iter().position(is_numeral) else {
        return false;
    };
    if first_digit == 0 {
        return false;
    }
    if matches!(
        chars[first_digit - 1],
        'で' | 'は' | 'に' | 'を' | 'と' | 'や' | 'も' | 'へ' | '第'
    ) {
        return false;
    }
    // A 4-digit group followed by a hyphen is a year (2024-04-01), not a
    // 丁目-番-号 chain, which starts with 1-2 digit groups.
    let ascii_run = chars[first_digit..]
        .iter()
        .take_while(|c| c.is_ascii_digit())
        .count();
    if ascii_run == 4
        && matches!(
            chars.get(first_digit + ascii_run),
            Some('-' | '‐' | '－' | '−')
        )
    {
        return false;
    }
    true
}

/// `char::to_digit` only handles ASCII; the card regex's Unicode `\d` also
/// matches full-width digits (４１１１…), so normalize those before validating.
fn decimal_digit_value(c: char) -> Option<u32> {
    match c {
        '0'..='9' => c.to_digit(10),
        '０'..='９' => Some(c as u32 - '０' as u32),
        _ => None,
    }
}

fn luhn_valid(candidate: &str) -> bool {
    let digits: Vec<u32> = candidate.chars().filter_map(decimal_digit_value).collect();
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

/// Asset/media file extensions that commonly follow retina-style names like
/// `128x128@2x.png`, which the email regex would otherwise treat as a domain TLD.
/// Extensions containing digits (e.g. `woff2`) cannot match the `[a-zA-Z]{2,}`
/// TLD group, so only alphabetic extensions are listed.
const RETINA_ASSET_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "svg", "ico", "avif", "bmp", "tif", "tiff", "heic",
    "heif", "mp4", "mov", "webm", "mkv", "avi", "ogv", "mp3", "wav", "flac", "aac", "ogg", "opus",
    "woff", "ttf", "otf", "eot", "pdf",
];

fn email_valid(candidate: &str) -> bool {
    !looks_like_retina_asset(candidate)
}

fn looks_like_retina_asset(candidate: &str) -> bool {
    let Some((before_ext, ext)) = candidate.rsplit_once('.') else {
        return false;
    };
    if !RETINA_ASSET_EXTENSIONS
        .iter()
        .any(|asset_ext| ext.eq_ignore_ascii_case(asset_ext))
    {
        return false;
    }

    let Some((_, scale_suffix)) = before_ext.rsplit_once('@') else {
        return false;
    };
    matches!(scale_suffix, "2x" | "3x")
}

fn openai_key_valid(candidate: &str) -> bool {
    !candidate
        .get(..7)
        .map(|prefix| prefix.eq_ignore_ascii_case("sk-ant-"))
        .unwrap_or(false)
}

fn value_after_assignment(candidate: &str) -> &str {
    let value = candidate
        .split(['=', ':'])
        .next_back()
        .unwrap_or(candidate)
        .trim();
    value.trim_matches(|c| c == '"' || c == '\'')
}

fn labelled_token_valid(candidate: &str) -> bool {
    token_value_valid(value_after_assignment(candidate))
}

fn token_value_valid(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if [
        "example",
        "sample",
        "dummy",
        "placeholder",
        "changeme",
        "change_me",
        "change-me",
        "your_",
        "your-",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
    {
        return false;
    }

    let unique = value
        .chars()
        .collect::<std::collections::HashSet<_>>()
        .len();
    unique >= 8
}

fn char_class_count(value: &str) -> usize {
    [
        value.chars().any(|c| c.is_ascii_lowercase()),
        value.chars().any(|c| c.is_ascii_uppercase()),
        value.chars().any(|c| c.is_ascii_digit()),
        value.chars().any(|c| matches!(c, '_' | '-')),
    ]
    .into_iter()
    .filter(|present| *present)
    .count()
}

fn is_hex_like(value: &str) -> bool {
    value.chars().all(|c| c.is_ascii_hexdigit())
}

fn has_long_ascii_sequence(value: &str, min_run: usize) -> bool {
    let mut inc = 1usize;
    let mut dec = 1usize;
    let mut prev: Option<u8> = None;

    for b in value.bytes().filter(|b| b.is_ascii_alphanumeric()) {
        if let Some(p) = prev {
            inc = if b == p.saturating_add(1) { inc + 1 } else { 1 };
            dec = if p == b.saturating_add(1) { dec + 1 } else { 1 };
            if inc >= min_run || dec >= min_run {
                return true;
            }
        }
        prev = Some(b);
    }

    false
}

fn env_assignment_valid(candidate: &str) -> bool {
    // Dotenv semantics: the value is everything after the first `=`, so
    // base64 padding (`=`) and URL values containing `:` stay intact.
    let value = match candidate.split_once('=') {
        Some((_, v)) => v.trim().trim_matches(|c| c == '"' || c == '\''),
        None => return false,
    };
    let lower = value.to_ascii_lowercase();

    // Placeholder / non-secret values common in templates and docs.
    // dotenvx-encrypted values (`shk env encrypt` output) carry no plaintext.
    if value.len() < 8
        || value.starts_with("encrypted:")
        || value.starts_with('$')
        || value.starts_with('<')
        || value.starts_with("%(")
        || value.starts_with("{{")
        || lower.contains("xxxx")
        || matches!(
            lower.as_str(),
            "true" | "false" | "null" | "none" | "undefined" | "disabled" | "enabled"
        )
    {
        return false;
    }

    token_value_valid(value)
}

fn generic_api_key_valid(candidate: &str) -> bool {
    if !labelled_token_valid(candidate) {
        return false;
    }

    let value = value_after_assignment(candidate);
    let classes = char_class_count(value);
    let hex_like = is_hex_like(value);

    if classes <= 1 && (!hex_like || value.len() < 32) {
        return false;
    }
    if has_long_ascii_sequence(value, 8) && !hex_like {
        return false;
    }

    true
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

/// Pre-computed newline offsets for a single `&str`, enabling O(log N) line/column lookup.
///
/// Bound to the lifetime of the source content so the borrow checker prevents callers from
/// accidentally querying a different buffer than the one used to build the index. Shared
/// across `shk-core` and `shk-rules` so any scanner can reuse the same index per file.
pub struct LineIndex<'a> {
    content: &'a str,
    newline_offsets: Vec<usize>,
}

impl<'a> LineIndex<'a> {
    pub fn new(content: &'a str) -> Self {
        Self {
            content,
            newline_offsets: content.match_indices('\n').map(|(idx, _)| idx).collect(),
        }
    }

    /// Returns `(zero_based_line_idx, line_start_byte, line_end_byte_exclusive_of_newline)`
    /// for the line containing `byte_idx`.
    pub fn bounds(&self, byte_idx: usize) -> (usize, usize, usize) {
        let byte_idx = byte_idx.min(self.content.len());
        let line_idx = self.newline_offsets.partition_point(|&idx| idx < byte_idx);
        let line_start = if line_idx == 0 {
            0
        } else {
            self.newline_offsets[line_idx - 1] + 1
        };
        let line_end = self
            .newline_offsets
            .get(line_idx)
            .copied()
            .unwrap_or(self.content.len());
        (line_idx, line_start, line_end)
    }

    /// Returns 1-based `(line, column)` for `byte_idx`. Column is counted in `char`s.
    pub fn line_col(&self, byte_idx: usize) -> (usize, usize) {
        let (line_idx, line_start, _) = self.bounds(byte_idx);
        let clamped = byte_idx.min(self.content.len());
        let col = self.content[line_start..clamped].chars().count() + 1;
        (line_idx + 1, col)
    }

    /// Returns the source line containing `byte_idx`, excluding the trailing `\n`.
    pub fn line_at(&self, byte_idx: usize) -> &'a str {
        let (_, start, end) = self.bounds(byte_idx);
        &self.content[start..end]
    }
}

fn shannon_entropy(value: &str) -> f32 {
    if value.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<char, usize> = HashMap::new();
    for c in value.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    let len = value.chars().count() as f32;
    counts
        .values()
        .map(|count| {
            let p = *count as f32 / len;
            -p * p.log2()
        })
        .sum()
}

fn rule_applies(rule: &CompiledRule, cfg: &RuleEngineConfig) -> bool {
    let rule_id = rule.id;
    if rule.kind == Kind::Env && !cfg.env {
        return false;
    }
    if rule.kind == Kind::AiContext && !cfg.ai_context {
        return false;
    }
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
    true
}

fn is_code_path(rel_path: &str) -> bool {
    let file_name = rel_path
        .rsplit('/')
        .next()
        .unwrap_or(rel_path)
        .rsplit('\\')
        .next()
        .unwrap_or(rel_path);
    let lowercase_file_name = file_name.to_ascii_lowercase();
    if matches!(
        lowercase_file_name.as_str(),
        "dockerfile"
            | "gnumakefile"
            | "justfile"
            | "makefile"
            | "rakefile"
            | "gemfile"
            | "vagrantfile"
            | "procfile"
    ) || lowercase_file_name.starts_with("dockerfile.")
        || lowercase_file_name.starts_with("makefile.")
    {
        return true;
    }

    let Some(ext) = rel_path.rsplit('.').next() else {
        return false;
    };
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "c" | "cc"
            | "cpp"
            | "cs"
            | "css"
            | "go"
            | "h"
            | "hpp"
            | "java"
            | "js"
            | "jsx"
            | "kt"
            | "mjs"
            | "py"
            | "rb"
            | "rs"
            | "sh"
            | "swift"
            | "ts"
            | "tsx"
            | "vue"
    )
}

fn ai_tag_chars_re() -> &'static Regex {
    static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"[\x{E0000}-\x{E007F}]").unwrap());
    &RE
}

fn ai_bidi_controls_re() -> &'static Regex {
    static RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"[\x{202A}-\x{202E}\x{2066}-\x{2069}]").unwrap());
    &RE
}

fn ai_embedded_bom_re() -> &'static Regex {
    static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\x{FEFF}").unwrap());
    &RE
}

fn ai_invisible_format_chars_re() -> &'static Regex {
    static RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"[\x{00AD}\x{034F}\x{061C}\x{180E}\x{200B}\x{2060}]").unwrap());
    &RE
}

fn ai_variation_selectors_re() -> &'static Regex {
    static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"[\x{E0100}-\x{E01EF}]").unwrap());
    &RE
}

fn ai_unsafe_uri_re() -> &'static Regex {
    static RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"(?i)\b(?:javascript\s*:|data\s*:\s*(?:text/html|text/javascript|application/(?:javascript|x-javascript)))",
        )
        .unwrap()
    });
    &RE
}

fn ai_svg_data_uri_re() -> &'static Regex {
    static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bdata\s*:\s*image/svg\+xml").unwrap());
    &RE
}

#[derive(Clone, Copy)]
struct AiContextMatchSpec {
    rule_id: &'static str,
    severity: Severity,
    message: &'static str,
    confidence: f32,
}

fn push_ai_context_match(
    out: &mut Vec<RuleMatch>,
    index: &LineIndex<'_>,
    spec: AiContextMatchSpec,
    byte_idx: usize,
    matched_text: String,
) {
    let (line, column) = index.line_col(byte_idx);
    out.push(RuleMatch {
        rule_id: spec.rule_id,
        severity: spec.severity,
        kind: Kind::AiContext,
        line,
        column,
        message: spec.message,
        confidence: spec.confidence,
        matched_text,
    });
}

fn push_ai_context_regex_matches<'a>(
    out: &mut Vec<RuleMatch>,
    content: &'a str,
    line_index: &mut Option<LineIndex<'a>>,
    re: &Regex,
    spec: AiContextMatchSpec,
) {
    for m in re.find_iter(content) {
        let index = line_index.get_or_insert_with(|| LineIndex::new(content));
        push_ai_context_match(out, index, spec, m.start(), m.as_str().to_string());
    }
}

fn redact_ai_context_line(line: &str) -> String {
    let mut s = line.to_string();
    for re in [
        ai_tag_chars_re(),
        ai_bidi_controls_re(),
        ai_embedded_bom_re(),
        ai_invisible_format_chars_re(),
        ai_variation_selectors_re(),
        ai_unsafe_uri_re(),
        ai_svg_data_uri_re(),
    ] {
        s = re.replace_all(&s, "[REDACTED]").to_string();
    }
    s
}

fn scan_ai_context_content<'a>(
    content: &'a str,
    rel_path: &str,
    cfg: &RuleEngineConfig,
    line_index: &mut Option<LineIndex<'a>>,
) -> Vec<RuleMatch> {
    if !cfg.ai_context {
        return Vec::new();
    }

    let mut out = Vec::new();
    push_ai_context_regex_matches(
        &mut out,
        content,
        line_index,
        ai_tag_chars_re(),
        AiContextMatchSpec {
            rule_id: "ai_context.unicode_tag_chars",
            severity: Severity::High,
            message: "Unicode tag character detected in AI-visible context",
            confidence: 0.95,
        },
    );

    let bidi_severity = if is_code_path(rel_path) {
        Severity::High
    } else {
        Severity::Low
    };
    let bidi_message = if bidi_severity == Severity::High {
        "Bidirectional control character detected in source code"
    } else {
        "Bidirectional control character detected in document text"
    };
    push_ai_context_regex_matches(
        &mut out,
        content,
        line_index,
        ai_bidi_controls_re(),
        AiContextMatchSpec {
            rule_id: "ai_context.bidi_control",
            severity: bidi_severity,
            message: bidi_message,
            confidence: 0.9,
        },
    );

    for m in ai_embedded_bom_re().find_iter(content) {
        if m.start() == 0 {
            continue;
        }
        let index = line_index.get_or_insert_with(|| LineIndex::new(content));
        push_ai_context_match(
            &mut out,
            index,
            AiContextMatchSpec {
                rule_id: "ai_context.embedded_bom",
                severity: Severity::Medium,
                message: "Byte order mark found after the start of the file",
                confidence: 0.9,
            },
            m.start(),
            m.as_str().to_string(),
        );
    }

    push_ai_context_regex_matches(
        &mut out,
        content,
        line_index,
        ai_invisible_format_chars_re(),
        AiContextMatchSpec {
            rule_id: "ai_context.invisible_format_chars",
            severity: Severity::High,
            message: "Invisible Unicode format character detected in AI-visible context",
            confidence: 0.9,
        },
    );

    push_ai_context_regex_matches(
        &mut out,
        content,
        line_index,
        ai_variation_selectors_re(),
        AiContextMatchSpec {
            rule_id: "ai_context.variation_selector",
            severity: Severity::Medium,
            message: "Unicode variation selector detected in AI-visible context",
            confidence: 0.75,
        },
    );

    push_ai_context_regex_matches(
        &mut out,
        content,
        line_index,
        ai_unsafe_uri_re(),
        AiContextMatchSpec {
            rule_id: "ai_context.unsafe_uri",
            severity: Severity::High,
            message: "Unsafe JavaScript-scheme or executable data URI detected",
            confidence: 0.9,
        },
    );

    push_ai_context_regex_matches(
        &mut out,
        content,
        line_index,
        ai_svg_data_uri_re(),
        AiContextMatchSpec {
            rule_id: "ai_context.unsafe_uri",
            severity: Severity::Medium,
            message: "SVG data URI detected in AI-visible context",
            confidence: 0.75,
        },
    );

    out
}

fn any_keyword_matches(lowercase_content: &str, keywords: &[&str]) -> bool {
    if keywords.is_empty() {
        return true;
    }
    keywords.iter().any(|keyword| {
        if keyword.bytes().any(|b| b.is_ascii_uppercase()) {
            lowercase_content.contains(&keyword.to_ascii_lowercase())
        } else {
            lowercase_content.contains(keyword)
        }
    })
}

fn allowlist_regex_target<'a>(
    target: AllowlistTarget,
    secret: &'a str,
    whole_match: &'a str,
    line: &'a str,
) -> &'a str {
    match target {
        AllowlistTarget::Secret => secret,
        AllowlistTarget::Match => whole_match,
        AllowlistTarget::Line => line,
    }
}

fn allowlist_matches(
    allowlist: &GitleaksAllowlist,
    rel_path: &str,
    secret: &str,
    whole_match: &str,
    line: &str,
) -> bool {
    let target = allowlist_regex_target(allowlist.target, secret, whole_match, line);
    let regex_hit =
        !allowlist.regexes.is_empty() && allowlist.regexes.iter().any(|re| re.is_match(target));
    let path_hit =
        !allowlist.paths.is_empty() && allowlist.paths.iter().any(|re| re.is_match(rel_path));
    let stopword_hit = !allowlist.stopwords.is_empty()
        && allowlist
            .stopwords
            .iter()
            .any(|stopword| secret.contains(stopword));

    match allowlist.condition {
        AllowlistCondition::Or => regex_hit || path_hit || stopword_hit,
        AllowlistCondition::And => {
            (allowlist.regexes.is_empty() || regex_hit)
                && (allowlist.paths.is_empty() || path_hit)
                && (allowlist.stopwords.is_empty() || stopword_hit)
        }
    }
}

fn gitleaks_rule_allows(
    rule: &GitleaksRule,
    rel_path: &str,
    secret: &str,
    whole_match: &str,
    line: &str,
) -> bool {
    rule.allowlists
        .iter()
        .any(|allowlist| allowlist_matches(allowlist, rel_path, secret, whole_match, line))
}

fn scan_gitleaks_content<'a>(
    content: &'a str,
    rel_path: &str,
    cfg: &RuleEngineConfig,
    line_index: &mut Option<LineIndex<'a>>,
) -> Vec<RuleMatch> {
    if !cfg.secrets {
        return Vec::new();
    }
    let mut out = Vec::new();
    let lowercase_content = content.to_ascii_lowercase();
    for r in gitleaks_rules::rules().iter() {
        if !any_keyword_matches(&lowercase_content, r.keywords) {
            continue;
        }
        if let Some(path) = &r.path
            && !path.is_match(rel_path)
        {
            continue;
        }
        for captures in r.re.captures_iter(content) {
            let Some(whole) = captures.get(0) else {
                continue;
            };
            let secret_match = r
                .secret_group
                .and_then(|group| captures.get(group))
                .unwrap_or(whole);
            let secret = secret_match.as_str();
            if let Some(min_entropy) = r.entropy
                && shannon_entropy(secret) < min_entropy
            {
                continue;
            }
            let index = line_index.get_or_insert_with(|| LineIndex::new(content));
            let line = index.line_at(whole.start());
            if gitleaks_rule_allows(r, rel_path, secret, whole.as_str(), line) {
                continue;
            }
            let (line, column) = index.line_col(secret_match.start());
            out.push(RuleMatch {
                rule_id: r.id,
                severity: Severity::High,
                kind: Kind::Secret,
                line,
                column,
                message: r.description,
                confidence: if r.entropy.is_some() { 0.88 } else { 0.82 },
                matched_text: secret.to_string(),
            });
        }
    }
    out
}

/// Apply the same patterns used for detection, replacing hits with `[REDACTED]`.
/// Used for JSON context lines so adjacent code does not leak secrets (spec §6).
pub fn redact_line_for_display(line: &str, cfg: &RuleEngineConfig) -> String {
    let mut s = line.to_string();
    for r in RULES.iter() {
        if !rule_applies(r, cfg) {
            continue;
        }
        s = r.re.replace_all(&s, "[REDACTED]").to_string();
    }
    if cfg.secrets {
        let lowercase_line = s.to_ascii_lowercase();
        for r in gitleaks_rules::rules().iter() {
            if !any_keyword_matches(&lowercase_line, r.keywords) {
                continue;
            }
            s = r.re.replace_all(&s, "[REDACTED]").to_string();
        }
    }
    if cfg.ai_context {
        s = redact_ai_context_line(&s);
    }
    const MAX: usize = 200;
    if s.chars().count() > MAX {
        let t: String = s.chars().take(MAX).collect();
        format!("{t}…")
    } else {
        s
    }
}

/// Env rules only fire on dotenv-style files (`.env`, `.env.local`, `dev.env`, ...);
/// in source code, uppercase constants reading from the environment
/// (`DB_PASSWORD = os.environ[...]`) would otherwise false-positive.
/// `.env.example` / `.env.sample` templates are excluded.
fn env_rules_apply_to(rel_path: &str) -> bool {
    let file_name = rel_path.rsplit(['/', '\\']).next().unwrap_or(rel_path);
    (file_name.starts_with(".env") || file_name.ends_with(".env"))
        && !file_name.ends_with(".env.example")
        && !file_name.ends_with(".env.sample")
}

/// Scan full file content; `rel_path` used only for env-rule file gating.
pub fn scan_content(content: &str, rel_path: &str, cfg: &RuleEngineConfig) -> Vec<RuleMatch> {
    let mut out = Vec::new();
    let mut line_index = None;
    let env_rules_apply = env_rules_apply_to(rel_path);
    for r in RULES.iter() {
        if !rule_applies(r, cfg) {
            continue;
        }
        if r.kind == Kind::Env && !env_rules_apply {
            continue;
        }
        for m in r.re.find_iter(content) {
            if let Some(validate) = r.validator
                && !validate(m.as_str())
            {
                continue;
            }
            let index = line_index.get_or_insert_with(|| LineIndex::new(content));
            let (line, column) = index.line_col(m.start());
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
    out.extend(scan_gitleaks_content(
        content,
        rel_path,
        cfg,
        &mut line_index,
    ));
    out.extend(scan_ai_context_content(
        content,
        rel_path,
        cfg,
        &mut line_index,
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_index_handles_empty_content() {
        let idx = LineIndex::new("");
        assert_eq!(idx.line_col(0), (1, 1));
        assert_eq!(idx.line_at(0), "");
        assert_eq!(idx.line_col(usize::MAX), (1, 1));
    }

    #[test]
    fn line_index_matches_legacy_scan_for_ascii() {
        let content = "abc\ndef\nghi";
        let idx = LineIndex::new(content);
        assert_eq!(idx.line_col(0), (1, 1));
        assert_eq!(idx.line_col(2), (1, 3));
        assert_eq!(idx.line_col(3), (1, 4));
        assert_eq!(idx.line_col(4), (2, 1));
        assert_eq!(idx.line_col(7), (2, 4));
        assert_eq!(idx.line_col(8), (3, 1));
        assert_eq!(idx.line_col(11), (3, 4));
        assert_eq!(idx.line_col(usize::MAX), (3, 4));
    }

    #[test]
    fn line_index_line_at_returns_full_line_without_newline() {
        let content = "first\nsecond\nthird";
        let idx = LineIndex::new(content);
        assert_eq!(idx.line_at(0), "first");
        assert_eq!(idx.line_at(5), "first");
        assert_eq!(idx.line_at(6), "second");
        assert_eq!(idx.line_at(13), "third");
        assert_eq!(idx.line_at(usize::MAX), "third");
    }

    #[test]
    fn line_index_handles_trailing_newline() {
        let content = "alpha\nbeta\n";
        let idx = LineIndex::new(content);
        assert_eq!(idx.line_at(0), "alpha");
        assert_eq!(idx.line_at(6), "beta");
        assert_eq!(idx.line_at(11), "");
        assert_eq!(idx.line_col(11), (3, 1));
    }

    #[test]
    fn line_index_counts_columns_in_chars_for_multibyte() {
        let content = "あいう\nえお";
        let idx = LineIndex::new(content);
        assert_eq!("あ".len(), 3);
        assert_eq!(idx.line_col(0), (1, 1));
        assert_eq!(idx.line_col(3), (1, 2));
        assert_eq!(idx.line_col(6), (1, 3));
        assert_eq!(idx.line_col(10), (2, 1));
        assert_eq!(idx.line_col(13), (2, 2));
        assert_eq!(idx.line_at(0), "あいう");
        assert_eq!(idx.line_at(10), "えお");
    }

    #[test]
    fn line_index_clamps_byte_idx_to_content_length() {
        let content = "x";
        let idx = LineIndex::new(content);
        assert_eq!(idx.line_col(usize::MAX), (1, 2));
        assert_eq!(idx.line_at(usize::MAX), "x");
    }

    #[test]
    fn detects_openai_style_key() {
        // not real credential: synthetic detector fixture value only
        let s = r#"const demo = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";"#;
        let cfg = RuleEngineConfig::default();
        let m = scan_content(s, "demo.ts", &cfg);
        assert!(
            m.iter().any(|x| x.rule_id == "secret.openai_api_key"),
            "{m:?}"
        );
    }

    #[test]
    fn detects_common_saas_provider_tokens() {
        let cfg = RuleEngineConfig::default();
        // not real credentials: synthetic detector fixture values only
        for (id, sample) in [
            (
                "secret.huggingface_token",
                ["hf_", "abcdefghijklmnopqrstuvwxyzABCDEFGH123456"].concat(),
            ),
            (
                "secret.twilio_auth_token",
                ["TWILIO_AUTH_TOKEN=", "0123456789abcdef", "0123456789abcdef"].concat(),
            ),
            (
                "secret.sendgrid_api_key",
                [
                    "SG.",
                    "abcdefghijklmnopQRSTUV",
                    ".abcdefghijklmnopqrstuvwxyz0123456789",
                ]
                .concat(),
            ),
            (
                "secret.shopify_token",
                ["sh", "pat_", "0123456789abcdef", "0123456789abcdef"].concat(),
            ),
            (
                "secret.supabase_service_role_key",
                [
                    "SERVICE_ROLE_KEY=",
                    "eyJabcdefghijklmnopqrstuvwxyz",
                    ".ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
                    ".abcdefghijklmnopqrstuvwxyz0123456789",
                ]
                .concat(),
            ),
            (
                "secret.vercel_token",
                ["VERCEL_TOKEN=", "vercelSyntheticToken", "0123456789"].concat(),
            ),
            (
                "secret.npm_token",
                ["npm_", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"].concat(),
            ),
            (
                "secret.gitlab_pat",
                ["glpat-", "abcdefghijklmnopQRSTUV012345"].concat(),
            ),
            (
                "secret.discord_webhook_url",
                [
                    "https://discord.com/api/webhooks/",
                    "123456789012345678",
                    "/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_ab",
                ]
                .concat(),
            ),
            (
                "secret.cloudflare_api_token",
                [
                    "CLOUDFLARE_API_TOKEN=",
                    "cloudflareSyntheticToken",
                    "0123456789AB",
                ]
                .concat(),
            ),
            (
                "secret.notion_integration_token",
                [
                    "NOTION_TOKEN=",
                    "sec",
                    "ret_",
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO12",
                ]
                .concat(),
            ),
            (
                "secret.linear_api_key",
                ["lin", "_api_", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN"].concat(),
            ),
        ] {
            let m = scan_content(&sample, "providers.txt", &cfg);
            assert!(m.iter().any(|x| x.rule_id == id), "missing {id}: {m:?}");
        }
    }

    #[test]
    fn twilio_key_sid_is_not_treated_as_secret() {
        let cfg = RuleEngineConfig::default();
        let sample = ["SK", "0123456789abcdef", "0123456789abcdef"].concat();
        let m = scan_content(&sample, "demo.txt", &cfg);
        assert!(
            !m.iter().any(|x| x.rule_id == "secret.twilio_auth_token"),
            "{m:?}"
        );
    }

    #[test]
    fn notion_secret_prefix_requires_context_label() {
        let cfg = RuleEngineConfig::default();
        let sample = [
            "fixture id: ",
            "sec",
            "ret_",
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO12",
        ]
        .concat();
        let m = scan_content(&sample, "demo.txt", &cfg);
        assert!(
            !m.iter()
                .any(|x| x.rule_id == "secret.notion_integration_token"),
            "{m:?}"
        );
    }

    #[test]
    fn detects_sensitive_env_assignment() {
        let cfg = RuleEngineConfig::default();
        // not real credentials: synthetic detector fixture values only
        let text = "export DB_PASSWORD=hunter2-Prod98\nSTRIPE_TOKEN=\"tok-aB3dE5gH7jK9mN2p\"\n";
        let m = scan_content(text, ".env", &cfg);
        let hits = m
            .iter()
            .filter(|x| x.rule_id == "env.sensitive_assignment")
            .count();
        assert_eq!(hits, 2, "{m:?}");
    }

    #[test]
    fn env_assignment_keeps_base64_padding_and_url_values() {
        let cfg = RuleEngineConfig::default();
        // not real credentials: synthetic detector fixture values only
        let text = concat!(
            "SESSION_SECRET=c2VjcmV0LXZhbHVlLTEyMw==\n",
            "DB_CREDENTIALS=postgres://app:hunter2-Prod98@db.internal:5432/app\n",
        );
        let m = scan_content(text, ".env", &cfg);
        let hits = m
            .iter()
            .filter(|x| x.rule_id == "env.sensitive_assignment")
            .count();
        assert_eq!(hits, 2, "{m:?}");
    }

    #[test]
    fn env_assignment_rejects_placeholders_and_short_values() {
        let cfg = RuleEngineConfig::default();
        let text = concat!(
            "DB_PASSWORD=${DB_PASSWORD}\n",
            "API_KEY=<your-api-key>\n",
            "SECRET_TOKEN=changeme\n",
            "AUTH_TOKEN=xxxxxxxxxxxxxxxx\n",
            "MY_PASSWORD=abc\n",
            "FEATURE_TOKEN_ENABLED=true\n",
        );
        let m = scan_content(text, ".env", &cfg);
        assert!(
            !m.iter().any(|x| x.rule_id == "env.sensitive_assignment"),
            "{m:?}"
        );
    }

    #[test]
    fn env_assignment_skips_dotenvx_encrypted_values() {
        let cfg = RuleEngineConfig::default();
        // not real credentials: synthetic detector fixture values only
        let text = concat!(
            "API_KEY=\"encrypted:BDqDBibm4wsYqMpCjTQ6BsO3f3hxgMRcrqaQRWcDCNX\"\n",
            "DB_PASSWORD=encrypted:BFs2mCkE6Z9XJqL2vRtY8wAeS5cD7hF1gK4mN6pQ\n",
        );
        let m = scan_content(text, ".env", &cfg);
        assert!(
            !m.iter().any(|x| x.rule_id == "env.sensitive_assignment"),
            "{m:?}"
        );
    }

    #[test]
    fn env_assignment_skips_env_example_files() {
        let cfg = RuleEngineConfig::default();
        let text = "DB_PASSWORD=hunter2-Prod98\n";
        let m = scan_content(text, "config/.env.example", &cfg);
        assert!(
            !m.iter().any(|x| x.rule_id == "env.sensitive_assignment"),
            "{m:?}"
        );
        // The skip is exact-suffix only: derived names like `.env.sample.bak`
        // may hold real values and must still be scanned.
        let m = scan_content(text, ".env.sample", &cfg);
        assert!(
            !m.iter().any(|x| x.rule_id == "env.sensitive_assignment"),
            "{m:?}"
        );
        let m = scan_content(text, ".env.sample.bak", &cfg);
        assert!(
            m.iter().any(|x| x.rule_id == "env.sensitive_assignment"),
            "{m:?}"
        );
    }

    #[test]
    fn env_assignment_only_applies_to_dotenv_files() {
        let cfg = RuleEngineConfig::default();
        // Uppercase constants reading the environment in source code must not match.
        let code = concat!(
            "DB_PASSWORD = os.environ[\"DB_PASSWORD\"]\n",
            "API_KEY = os.getenv(\"API_KEY\", \"\")\n",
            "SECRET_TOKEN = fetch_secret_from_vault()\n",
        );
        for path in ["config.py", "settings.rb", "src/setup.sh", "Makefile"] {
            let m = scan_content(code, path, &cfg);
            assert!(
                !m.iter().any(|x| x.rule_id == "env.sensitive_assignment"),
                "{path}: {m:?}"
            );
        }
        // Dotenv-style files still detect.
        let text = "DB_PASSWORD=hunter2-Prod98\n";
        for path in [
            ".env",
            ".env.local",
            "config/.env.production",
            "deploy/dev.env",
        ] {
            let m = scan_content(text, path, &cfg);
            assert!(
                m.iter().any(|x| x.rule_id == "env.sensitive_assignment"),
                "{path}: {m:?}"
            );
        }
    }

    #[test]
    fn env_rules_can_be_disabled() {
        let cfg = RuleEngineConfig {
            env: false,
            ..RuleEngineConfig::default()
        };
        let m = scan_content("DB_PASSWORD=hunter2-Prod98\n", ".env", &cfg);
        assert!(
            !m.iter().any(|x| x.rule_id == "env.sensitive_assignment"),
            "{m:?}"
        );
    }

    #[test]
    fn generic_api_key_rejects_low_signal_examples() {
        let cfg = RuleEngineConfig::default();
        let m = scan_content(
            r#"api_key = "aaaaaaaaaaaaaaaaaaaaaaaa"
secret_key = "your-placeholder-token-value"
api_key = "abcdefghijklmnop""#,
            "demo.txt",
            &cfg,
        );
        assert!(
            !m.iter().any(|x| x.rule_id == "secret.generic_api_key"),
            "{m:?}"
        );
    }

    #[test]
    fn generic_api_key_keeps_high_signal_assignments() {
        let cfg = RuleEngineConfig::default();
        // not real credential: synthetic detector fixture value only
        let text = r#"api_key = "aB3dE5gH7jK9mN2pQ4rS"
secret_key = "0123456789abcdef0123456789abcdef""#;
        let m = scan_content(text, "demo.txt", &cfg);
        let hits = m
            .iter()
            .filter(|x| x.rule_id == "secret.generic_api_key")
            .count();
        assert_eq!(hits, 2, "{m:?}");
    }

    #[test]
    fn detects_ai_context_unicode_tag_chars() {
        let cfg = RuleEngineConfig::default();
        let m = scan_content("prompt\u{E0000}tail", "demo.md", &cfg);
        assert!(
            m.iter().any(
                |x| x.rule_id == "ai_context.unicode_tag_chars" && x.severity == Severity::High
            ),
            "{m:?}"
        );
    }

    #[test]
    fn detects_bidi_controls_with_path_sensitive_severity() {
        let cfg = RuleEngineConfig::default();
        let code = scan_content("let label = \"abc\u{202E}def\";", "demo.rs", &cfg);
        assert!(
            code.iter()
                .any(|x| x.rule_id == "ai_context.bidi_control" && x.severity == Severity::High),
            "{code:?}"
        );

        let doc = scan_content("text \u{202E} text", "demo.md", &cfg);
        assert!(
            doc.iter()
                .any(|x| x.rule_id == "ai_context.bidi_control" && x.severity == Severity::Low),
            "{doc:?}"
        );
    }

    #[test]
    fn treats_common_extensionless_build_files_as_code() {
        let cfg = RuleEngineConfig::default();
        for path in ["Dockerfile", "Dockerfile.dev", "Makefile", "build/Makefile"] {
            let m = scan_content("RUN echo safe\u{202E}tail", path, &cfg);
            assert!(
                m.iter()
                    .any(|x| x.rule_id == "ai_context.bidi_control"
                        && x.severity == Severity::High),
                "expected high severity for {path}: {m:?}"
            );
        }
    }

    #[test]
    fn detects_embedded_bom_but_allows_leading_bom() {
        let cfg = RuleEngineConfig::default();
        let leading = scan_content("\u{FEFF}title", "demo.txt", &cfg);
        assert!(
            !leading
                .iter()
                .any(|x| x.rule_id == "ai_context.embedded_bom"),
            "{leading:?}"
        );

        let embedded = scan_content("title\u{FEFF}tail", "demo.txt", &cfg);
        assert!(
            embedded
                .iter()
                .any(|x| x.rule_id == "ai_context.embedded_bom" && x.severity == Severity::Medium),
            "{embedded:?}"
        );
    }

    #[test]
    fn detects_invisible_format_chars_as_high_signal_ai_context() {
        let cfg = RuleEngineConfig::default();
        for (sample, path) in [
            ("ignore\u{200B} previous instruction", "prompt.md"),
            ("let name = \"safe\u{00AD}tail\";", "demo.rs"),
            ("word\u{2060}joiner", "notes.txt"),
        ] {
            let m = scan_content(sample, path, &cfg);
            assert!(
                m.iter()
                    .any(|x| x.rule_id == "ai_context.invisible_format_chars"
                        && x.severity == Severity::High),
                "missing invisible format char finding for {path}: {m:?}"
            );
        }
    }

    #[test]
    fn detects_variation_selectors_without_high_severity() {
        let cfg = RuleEngineConfig::default();
        let m = scan_content("selector\u{E0100}tail", "prompt.md", &cfg);
        assert!(
            m.iter()
                .any(|x| x.rule_id == "ai_context.variation_selector"
                    && x.severity == Severity::Medium),
            "{m:?}"
        );
        assert!(
            !m.iter()
                .any(|x| x.rule_id == "ai_context.variation_selector"
                    && x.severity == Severity::High),
            "{m:?}"
        );
    }

    #[test]
    fn common_emoji_sequences_do_not_trigger_ai_context_rules() {
        let cfg = RuleEngineConfig::default();
        let line = "status: ❤️ Rust 👨‍👩‍👧‍👦 ☺️";
        let m = scan_content(line, "notes.md", &cfg);
        assert!(
            !m.iter().any(|x| x.rule_id.starts_with("ai_context.")),
            "{m:?}"
        );

        let redacted = redact_line_for_display(line, &cfg);
        assert!(redacted.contains("❤️"), "{redacted}");
        assert!(redacted.contains("👨‍👩‍👧‍👦"), "{redacted}");
        assert!(redacted.contains("☺️"), "{redacted}");
    }

    #[test]
    fn detects_unsafe_javascript_and_executable_data_uri() {
        let cfg = RuleEngineConfig::default();
        let m = scan_content(
            concat!(
                "[run](java",
                "script:alert(1))\n",
                r#"<a href="data"#,
                r#":text/html,<script></script>">x</a>"#
            ),
            "demo.md",
            &cfg,
        );
        let hits = m
            .iter()
            .filter(|x| x.rule_id == "ai_context.unsafe_uri")
            .count();
        assert_eq!(hits, 2, "{m:?}");
    }

    #[test]
    fn svg_data_uri_is_not_reported_as_high_unsafe_uri() {
        let cfg = RuleEngineConfig::default();
        let m = scan_content(
            r#"background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 1 1'%3E%3C/svg%3E");"#,
            "style.css",
            &cfg,
        );
        assert!(
            !m.iter()
                .any(|x| x.rule_id == "ai_context.unsafe_uri" && x.severity == Severity::High),
            "{m:?}"
        );
        assert!(
            m.iter()
                .any(|x| x.rule_id == "ai_context.unsafe_uri" && x.severity == Severity::Medium),
            "{m:?}"
        );
    }

    #[test]
    fn ai_context_rules_can_be_disabled() {
        let cfg = RuleEngineConfig {
            ai_context: false,
            ..RuleEngineConfig::default()
        };
        let m = scan_content(
            concat!(
                "prompt\u{E0000}\n",
                "zero\u{200B} selector\u{E0100}\n",
                "url = \"java",
                "script:alert(1)\""
            ),
            "demo.js",
            &cfg,
        );
        assert!(
            !m.iter().any(|x| x.rule_id.starts_with("ai_context.")),
            "{m:?}"
        );
    }

    #[test]
    fn internal_terms_does_not_gate_ai_context_rules() {
        for internal_terms in [false, true] {
            let cfg = RuleEngineConfig {
                internal_terms,
                ..RuleEngineConfig::default()
            };
            let m = scan_content("prompt\u{E0000}tail", "demo.md", &cfg);
            assert!(
                m.iter()
                    .any(|x| x.rule_id == "ai_context.unicode_tag_chars"),
                "internal_terms={internal_terms}: {m:?}"
            );
        }
    }

    #[test]
    fn ai_context_columns_count_multibyte_chars() {
        let cfg = RuleEngineConfig::default();
        let m = scan_content("あい\u{E0000}tail", "demo.md", &cfg);
        let hit = m
            .iter()
            .find(|x| x.rule_id == "ai_context.unicode_tag_chars")
            .expect("tag char hit");
        assert_eq!((hit.line, hit.column), (1, 3), "{m:?}");
    }

    #[test]
    fn redact_line_handles_ai_context_patterns() {
        let cfg = RuleEngineConfig::default();
        let line = concat!(
            "prompt\u{E0000} bidi\u{202E} ",
            "zero\u{200B}width selector\u{E0100} ",
            r#"<a href="java"#,
            r#"script:alert(1)">x</a> "#,
            r#"<a href="data:text/html,<script></script>">x</a>"#
        );
        let redacted = redact_line_for_display(line, &cfg);
        assert!(redacted.contains("[REDACTED]"), "{redacted}");
        assert!(!redacted.contains('\u{E0000}'), "{redacted}");
        assert!(!redacted.contains('\u{202E}'), "{redacted}");
        assert!(!redacted.contains('\u{200B}'), "{redacted}");
        assert!(!redacted.contains('\u{E0100}'), "{redacted}");
        assert!(
            !redacted.to_ascii_lowercase().contains("javascript:"),
            "{redacted}"
        );
        assert!(
            !redacted.to_ascii_lowercase().contains("data:text/html"),
            "{redacted}"
        );

        let disabled = redact_line_for_display(
            "prompt\u{E0000} bidi\u{202E} zero\u{200B} selector\u{E0100} javascript:alert(1)",
            &RuleEngineConfig {
                ai_context: false,
                ..RuleEngineConfig::default()
            },
        );
        assert!(disabled.contains('\u{E0000}'), "{disabled}");
        assert!(disabled.contains('\u{202E}'), "{disabled}");
        assert!(disabled.contains('\u{200B}'), "{disabled}");
        assert!(disabled.contains('\u{E0100}'), "{disabled}");
        assert!(disabled.contains("javascript:"), "{disabled}");
    }

    #[test]
    fn redact_line_strips_email() {
        let cfg = RuleEngineConfig::default();
        // not real credential or personal data: synthetic detector fixture value only
        let out = redact_line_for_display("user: admin@example.com ok", &cfg);
        assert!(!out.contains("example.com"));
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn english_name_rule_ignores_structural_config_keys() {
        let cfg = RuleEngineConfig::default();
        let yaml = "\
jobs:
  build:
    steps:
      - uses: actions/checkout@v6
      - name: build
        run: echo hi
      - name: checkout
        uses: actions/checkout@v6
";
        let m = scan_content(yaml, "ci.yml", &cfg);
        assert!(!m.iter().any(|x| x.rule_id == "pii.en.name"), "{m:?}");
    }

    #[test]
    fn english_name_rule_still_detects_title_case_names() {
        let cfg = RuleEngineConfig::default();
        // not real personal data: synthetic detector fixture value only
        let m = scan_content("author: Ada Lovelace", "notes.txt", &cfg);
        assert!(m.iter().any(|x| x.rule_id == "pii.en.name"), "{m:?}");
    }

    #[test]
    fn email_rule_ignores_asset_filename_matches() {
        let cfg = RuleEngineConfig::default();
        let m = scan_content(
            r#"icons: ["icons/128x128@2x.png", "logo@3x.jpeg", "splash@2x.webp", "icon@2x.svg"]"#,
            "tauri.conf.json",
            &cfg,
        );
        assert!(!m.iter().any(|x| x.rule_id == "pii.email"), "{m:?}");
    }

    #[test]
    fn email_rule_still_detects_real_addresses() {
        let cfg = RuleEngineConfig::default();
        // not real personal data: synthetic detector fixture value only
        let m = scan_content(
            "contact: alice@example.com\nasset team: image-team@assets.png",
            "notes.txt",
            &cfg,
        );
        let email_findings = m.iter().filter(|x| x.rule_id == "pii.email").count();
        assert_eq!(email_findings, 2, "{m:?}");
    }

    #[test]
    fn detects_luhn_valid_credit_card() {
        let cfg = RuleEngineConfig::default();
        // not real credential or personal data: synthetic detector fixture value only
        let m = scan_content("card: 4111 1111 1111 1111", "demo.txt", &cfg);
        assert!(m.iter().any(|x| x.rule_id == "pii.credit_card"), "{m:?}");
    }

    #[test]
    fn ignores_luhn_invalid_credit_card_like_number() {
        let cfg = RuleEngineConfig::default();
        // not real credential or personal data: synthetic detector fixture value only
        let m = scan_content("card: 4111 1111 1111 1112", "demo.txt", &cfg);
        assert!(!m.iter().any(|x| x.rule_id == "pii.credit_card"), "{m:?}");
    }

    #[test]
    fn detects_full_width_digit_credit_card() {
        let cfg = RuleEngineConfig::default();
        // not real credential or personal data: synthetic detector fixture value only
        let m = scan_content(
            "カード番号: ４１１１１１１１１１１１１１１１",
            "demo.txt",
            &cfg,
        );
        assert!(m.iter().any(|x| x.rule_id == "pii.credit_card"), "{m:?}");
    }

    #[test]
    fn credit_card_match_excludes_trailing_separator() {
        let re = Regex::new(r"\b\d(?:[ -]?\d){12,18}\b").unwrap();
        // not real credential or personal data: synthetic detector fixture value only
        let text = "card: 4111 1111 1111 1111 ok";
        let m = re.find(text).expect("card pattern should match");
        assert_eq!(m.as_str(), "4111 1111 1111 1111");
        assert!(!m.as_str().ends_with(' '));
        assert!(!m.as_str().ends_with('-'));
    }

    #[test]
    fn applies_language_specific_pii_rules() {
        let cfg = RuleEngineConfig {
            pii_languages: vec!["en".into()],
            ..RuleEngineConfig::default()
        };
        // not real credential or personal data: synthetic detector fixture value only
        let m = scan_content(
            "phone: (555) 555-5555\npassport AB1234567",
            "demo.txt",
            &cfg,
        );
        assert!(m.iter().any(|x| x.rule_id == "pii.en.phone"), "{m:?}");
        assert!(!m.iter().any(|x| x.rule_id == "pii.ja.passport"), "{m:?}");
    }

    #[test]
    fn detects_label_anchored_english_ssn() {
        let cfg = RuleEngineConfig::default();
        // not real personal data: synthetic detector fixture value only
        let m = scan_content("SSN: 123-45-6789", "demo.txt", &cfg);
        assert!(m.iter().any(|x| x.rule_id == "pii.en.ssn"), "{m:?}");

        let m = scan_content("social security no 123-45-6789", "demo.txt", &cfg);
        assert!(m.iter().any(|x| x.rule_id == "pii.en.ssn"), "{m:?}");
    }

    #[test]
    fn english_ssn_requires_context_label() {
        let cfg = RuleEngineConfig::default();
        let m = scan_content("release-id 123-45-6789", "demo.txt", &cfg);
        assert!(!m.iter().any(|x| x.rule_id == "pii.en.ssn"), "{m:?}");
    }

    #[test]
    fn detects_label_anchored_japanese_passport() {
        let cfg = RuleEngineConfig::default();
        // not real personal data: synthetic detector fixture value only
        let m = scan_content("旅券番号: AB1234567", "demo.txt", &cfg);
        assert!(m.iter().any(|x| x.rule_id == "pii.ja.passport"), "{m:?}");
    }

    #[test]
    fn japanese_passport_requires_context_label() {
        let cfg = RuleEngineConfig::default();
        let m = scan_content("product-code AB1234567", "demo.txt", &cfg);
        assert!(!m.iter().any(|x| x.rule_id == "pii.ja.passport"), "{m:?}");
    }

    #[test]
    fn detects_dotenvx_private_key_assignment() {
        let cfg = RuleEngineConfig::default();
        let m = scan_content(
            "DOTENV_PRIVATE_KEY_PRODUCTION=dotenvx-secret-demo-value",
            ".env.keys",
            &cfg,
        );
        assert!(
            m.iter().any(|x| x.rule_id == "secret.dotenvx_private_key"),
            "{m:?}"
        );
    }

    #[test]
    fn detects_gitleaks_rule_and_extracts_secret_group() {
        let cfg = RuleEngineConfig::default();
        let token = "squ_abcdefghijklmnopqrstuvwxyz0123456789ABCD";
        let text = format!(r#"sonar_token = "{token}""#);
        let m = scan_content(&text, "demo.toml", &cfg);
        let hit = m
            .iter()
            .find(|x| x.rule_id == "secret.gitleaks.sonar-api-token")
            .expect("sonar token match");
        assert_eq!(hit.matched_text, token);
        assert_eq!(hit.column, text.find(token).unwrap() + 1);
    }

    #[test]
    fn gitleaks_path_filter_limits_rule_scope() {
        let cfg = RuleEngineConfig::default();
        let sample = r#""secret_key" => "sk_abcdefghijklmnopqrstuvwxyz123""#;
        let php = scan_content(sample, "plugin.php", &cfg);
        let txt = scan_content(sample, "plugin.txt", &cfg);
        assert!(
            php.iter()
                .any(|x| x.rule_id == "secret.gitleaks.freemius-secret-key"),
            "{php:?}"
        );
        assert!(
            !txt.iter()
                .any(|x| x.rule_id == "secret.gitleaks.freemius-secret-key"),
            "{txt:?}"
        );
    }

    #[test]
    fn gitleaks_entropy_and_allowlist_filter_low_signal_values() {
        let cfg = RuleEngineConfig::default();
        let low_entropy = scan_content("AKIAAAAAAAAAAAAAAAAA", "demo.txt", &cfg);
        assert!(
            !low_entropy
                .iter()
                .any(|x| x.rule_id == "secret.gitleaks.aws-access-token"),
            "{low_entropy:?}"
        );

        let allowlisted = scan_content("AKIAAAAAAAAAAEXAMPLE", "demo.txt", &cfg);
        assert!(
            !allowlisted
                .iter()
                .any(|x| x.rule_id == "secret.gitleaks.aws-access-token"),
            "{allowlisted:?}"
        );
    }

    #[test]
    fn gitleaks_keyword_filter_is_case_insensitive() {
        assert!(any_keyword_matches(
            &"token AKIA0123456789ABCDEF".to_ascii_lowercase(),
            &["akia"]
        ));
        assert!(any_keyword_matches(
            &"token AKIA0123456789ABCDEF".to_ascii_lowercase(),
            &["AKIA"]
        ));
        assert!(!any_keyword_matches(
            &"token without marker".to_ascii_lowercase(),
            &["akia"]
        ));
    }

    #[test]
    fn detects_label_anchored_japanese_pii_rules() {
        let cfg = RuleEngineConfig::default();
        // not real credential or personal data: synthetic detector fixture value only
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

    #[test]
    fn detects_structured_japanese_address() {
        let cfg = RuleEngineConfig::default();
        // not real personal data: synthetic detector fixture values only
        for (text, expected) in [
            (
                "住所: 東京都千代田区丸の内1-1-1",
                "東京都千代田区丸の内1-1-1",
            ),
            (
                "神奈川県横浜市西区みなとみらい2丁目3番5号",
                "神奈川県横浜市西区みなとみらい2丁目3番5号",
            ),
            ("大阪府大阪市北区梅田３−１", "大阪府大阪市北区梅田３−１"),
            (
                "北海道河東郡音更町木野西通12番地",
                "北海道河東郡音更町木野西通12番地",
            ),
            ("鹿児島県鹿児島市山下町11-1", "鹿児島県鹿児島市山下町11-1"),
            (
                "京都府京都市中京区寺町通1丁目2-3",
                "京都府京都市中京区寺町通1丁目2-3",
            ),
        ] {
            let m = scan_content(text, "demo.txt", &cfg);
            let hit = m.iter().find(|x| x.rule_id == "pii.ja.address");
            assert!(hit.is_some(), "should match {text}: {m:?}");
            // The whole address must be consumed so masking does not leave a
            // partial block number (e.g. "1-1") behind.
            assert_eq!(hit.unwrap().matched_text, expected, "for {text}");
        }
    }

    #[test]
    fn japanese_address_requires_block_number() {
        let cfg = RuleEngineConfig::default();
        for text in [
            "東京都内で開催されたイベント",
            "東京都渋谷区で開催されたカンファレンス",
            "愛知県名古屋市は人口230万人の都市です",
            "千葉県内には54の市町村があります",
            "京都府に出張します",
            "東京都新宿区では2023-年度の予算を審議",
            "東京都新宿区では2024-04-01に審議された",
            "東京都品川区で3番目に大きい施設",
            "東京都港区の条例第5号が施行された",
        ] {
            let m = scan_content(text, "demo.txt", &cfg);
            assert!(
                !m.iter().any(|x| x.rule_id == "pii.ja.address"),
                "should not match {text}: {m:?}"
            );
        }
    }
}
