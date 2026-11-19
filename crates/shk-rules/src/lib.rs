//! Built-in rules: secrets, PII (en/ja subset), env hints.

mod gitleaks_rules;

use aho_corasick::AhoCorasick;
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

/// Header of any PEM / armored private key block: PKCS#8 (plain and
/// encrypted), the legacy `RSA` / `EC` / `DSA` forms, OpenSSH and PGP.
const PRIVATE_KEY_HEADER_PATTERN: &str = r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----";

static PRIVATE_KEY_HEADER_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(PRIVATE_KEY_HEADER_PATTERN).expect("private key header regex"));

static PRIVATE_KEY_FOOTER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")
        .expect("private key footer regex")
});

/// Byte ranges of private key blocks in `content`, each running from the
/// start of a `-----BEGIN … PRIVATE KEY-----` header through the end of its
/// footer. Ranges are sorted and do not overlap.
///
/// A header without a footer (before the next header, if any) is either a
/// truncated key or a header that is merely quoted in source code, command
/// output or prose. Its range covers the rest of the header's line and then
/// only the following lines that look like armor body — see
/// [`unterminated_key_block_end`] — so a truncated key is still covered while
/// ordinary text after a quoted header is left alone.
///
/// Line-oriented callers (masking, context redaction) use this to treat the
/// base64 body and footer as part of the secret, which per-line rules miss.
pub fn private_key_block_ranges(content: &str) -> Vec<std::ops::Range<usize>> {
    let mut out = Vec::new();
    let mut cursor = 0;
    while let Some(header) = PRIVATE_KEY_HEADER_RE.find_at(content, cursor) {
        let next_header = PRIVATE_KEY_HEADER_RE
            .find_at(content, header.end())
            .map_or(content.len(), |next| next.start());
        let end = PRIVATE_KEY_FOOTER_RE
            .find_at(content, header.end())
            .filter(|footer| footer.start() < next_header)
            .map_or_else(
                || unterminated_key_block_end(content, header.end()).min(next_header),
                |footer| footer.end(),
            );
        out.push(header.start()..end);
        if end >= content.len() {
            break;
        }
        cursor = end;
    }
    out
}

/// End of a private key block whose header ends at `header_end` and that has
/// no footer. The block always covers the rest of the header's line. When
/// nothing but whitespace or line decoration (see [`strip_line_decoration`])
/// follows the header on that line, it also covers the following lines for
/// as long as they look like armor body: blank lines, armor header lines
/// (`Proc-Type: …`, `Comment: …`), lines made of base64 characters only, and
/// decorated lines whose remainder is a base64 run of at least
/// [`MIN_DECORATED_BODY_LEN`] characters — a key pasted into a shell or
/// Makefile continuation, a string concatenation or a quoted reply. Trailing
/// blank lines are not part of the block.
fn unterminated_key_block_end(content: &str, header_end: usize) -> usize {
    let rest = &content[header_end..];
    let header_line_len = rest.find('\n').unwrap_or(rest.len());
    let header_tail = &rest[..header_line_len];
    let mut end = header_end + header_tail.trim_end().len();
    if !strip_line_decoration(header_tail).is_empty() {
        return end;
    }
    let mut line_start = header_end + header_line_len;
    while line_start < content.len() {
        // `line_start` sits on the terminator of the previous line.
        line_start += 1;
        let line_len = content[line_start..]
            .find('\n')
            .unwrap_or(content.len() - line_start);
        let raw = &content[line_start..line_start + line_len];
        let line = raw.trim();
        let body = strip_line_decoration(raw);
        if body.is_empty() {
            // Blank or decoration only: kept only if more armor body follows.
        } else if is_armor_body_line(line) {
            end = line_start + raw.trim_end().len();
        } else if body.len() >= MIN_DECORATED_BODY_LEN && is_base64_text(body) {
            // `body` is a subslice of `raw`: stop right after it, leaving the
            // closing quote or continuation mark alone.
            let body_start = body.as_ptr() as usize - raw.as_ptr() as usize;
            end = line_start + body_start + body.len();
        } else {
            break;
        }
        line_start += line_len;
    }
    end
}

/// Whether a trimmed, non-empty line can belong to the body of an armored
/// key: an armor header such as `Proc-Type: 4,ENCRYPTED`, or base64 text
/// (including the `=XXXX` checksum line of PGP armor).
fn is_armor_body_line(line: &str) -> bool {
    const ARMOR_HEADER_KEYS: &[&str] = &[
        "Proc-Type",
        "DEK-Info",
        "Comment",
        "Version",
        "Hash",
        "Charset",
        "MessageID",
    ];
    if let Some((key, _)) = line.split_once(':') {
        return ARMOR_HEADER_KEYS.contains(&key.trim_end());
    }
    is_base64_text(line)
}

fn is_base64_text(text: &str) -> bool {
    text.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
}

/// Shortest base64 run that counts as armor body on a decorated line, so a
/// short quoted word or an ordinary statement still ends the block.
const MIN_DECORATED_BODY_LEN: usize = 16;

/// `line` without the decoration that surrounds key material embedded in
/// other text: leading whitespace, `>` quote markers, `+` and quotes; and
/// trailing whitespace, quotes, `\`, `,`, `+`, `;` and escaped line breaks
/// (`\n`, `\r`), in any combination. The result is a subslice of `line`.
fn strip_line_decoration(line: &str) -> &str {
    let mut body = line
        .trim_start_matches(|ch: char| ch.is_whitespace() || matches!(ch, '>' | '+' | '"' | '\''));
    loop {
        let trimmed = body.trim_end();
        let trimmed = trimmed
            .strip_suffix("\\n")
            .or_else(|| trimmed.strip_suffix("\\r"))
            .or_else(|| trimmed.strip_suffix(['\\', ',', '+', ';', '"', '\'']))
            .unwrap_or(trimmed);
        if trimmed.len() == body.len() {
            return body;
        }
        body = trimmed;
    }
}

/// Hand-tuned rules.
///
/// Word boundaries are written out instead of using a bare `\b`, because
/// Rust's `\b` is Unicode-aware: kana, kanji and full-width letters count as
/// word characters, so `キーはAKIA…です` has no boundary on either side of the
/// token and a bare `\b` misses it.
///
/// - `(?-u:\b)` (ASCII boundary) where the neighbouring pattern element
///   only matches ASCII, such as a token prefix or an `[A-Za-z0-9]` class.
///   Japanese text next to the value then behaves like whitespace.
/// - `(?:\b|(?-u:\b))` (either boundary) where the neighbouring element is
///   `\d`, which also matches full-width digits. The ASCII boundary alone
///   would stop matching `４１１１…` followed by a space, and the Unicode
///   boundary alone misses ASCII digits followed by `です`.
///
/// Rules whose edge is a Japanese label or a literal such as `〒` carry no
/// boundary on that side.
static RULES: Lazy<Vec<CompiledRule>> = Lazy::new(|| {
    vec![
        CompiledRule {
            id: "secret.openai_api_key",
            severity: Severity::High,
            kind: Kind::Secret,
            re: Regex::new(r"(?i)(?-u:\b)sk-(?:proj-)?[a-zA-Z0-9_-]{20,}(?-u:\b)")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Possible OpenAI API key detected",
            confidence: 0.9,
            validator: Some(openai_key_valid),
        },
        CompiledRule {
            id: "secret.aws_access_key",
            severity: Severity::High,
            kind: Kind::Secret,
            re: Regex::new(r"(?m)(?-u:\b)(AKIA|ASIA)[0-9A-Z]{16}(?-u:\b)")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Possible AWS access key id",
            confidence: 0.88,
            validator: None,
        },
        CompiledRule {
            id: "secret.anthropic_api_key",
            severity: Severity::High,
            kind: Kind::Secret,
            re: Regex::new(r"(?-u:\b)sk-ant-[a-zA-Z0-9_-]{20,}(?-u:\b)")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Possible Anthropic API key detected",
            confidence: 0.9,
            validator: None,
        },
        CompiledRule {
            id: "secret.google_api_key",
            severity: Severity::High,
            kind: Kind::Secret,
            re: Regex::new(r"(?-u:\b)AIza[a-zA-Z0-9_-]{30,}(?-u:\b)")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Possible Google API key detected",
            confidence: 0.9,
            validator: None,
        },
        CompiledRule {
            id: "secret.github_token",
            severity: Severity::High,
            kind: Kind::Secret,
            re: Regex::new(r"(?-u:\b)gh[ps]_[a-zA-Z0-9]{30,}(?-u:\b)")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Possible GitHub token detected",
            confidence: 0.9,
            validator: None,
        },
        CompiledRule {
            id: "secret.slack_token",
            severity: Severity::High,
            kind: Kind::Secret,
            re: Regex::new(r"(?-u:\b)xox[bprs]-[a-zA-Z0-9-]{20,}(?-u:\b)")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Possible Slack token detected",
            confidence: 0.9,
            validator: None,
        },
        CompiledRule {
            id: "secret.stripe_api_key",
            severity: Severity::High,
            kind: Kind::Secret,
            re: Regex::new(r"(?-u:\b)[rs]k_(?:live|test)_[a-zA-Z0-9]{20,}(?-u:\b)")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Possible Stripe API key detected",
            confidence: 0.9,
            validator: None,
        },
        CompiledRule {
            id: "secret.huggingface_token",
            severity: Severity::High,
            kind: Kind::Secret,
            re: Regex::new(r"(?-u:\b)hf_[A-Za-z0-9]{34,}(?-u:\b)")
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
                r#"(?i)(?-u:\b)twilio[_-]?auth[_-]?token\s*[=:]\s*['"]?[0-9a-f]{32}(?-u:\b)"#,
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
            re: Regex::new(r"(?-u:\b)SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}(?-u:\b)")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Possible SendGrid API key detected",
            confidence: 0.9,
            validator: None,
        },
        CompiledRule {
            id: "secret.shopify_token",
            severity: Severity::High,
            kind: Kind::Secret,
            re: Regex::new(r"(?-u:\b)shp(?:at|ca|ss|ua)_[a-fA-F0-9]{32}(?-u:\b)")
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
                r#"(?i)(?-u:\b)(?:supabase[_-]?)?service[_-]?role(?:[_-]?key)?\s*[=:]\s*['"]?eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}(?-u:\b)"#,
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
                r#"(?i)(?-u:\b)vercel(?:[_-]?(?:api[_-]?)?token|[_-]?auth[_-]?token)\s*[=:]\s*['"]?[A-Za-z0-9_-]{24,}(?-u:\b)"#,
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
            re: Regex::new(r"(?-u:\b)npm_[A-Za-z0-9]{36}(?-u:\b)")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Possible npm token detected",
            confidence: 0.9,
            validator: None,
        },
        CompiledRule {
            id: "secret.gitlab_pat",
            severity: Severity::High,
            kind: Kind::Secret,
            re: Regex::new(r"(?-u:\b)glpat-[A-Za-z0-9_-]{20,}(?-u:\b)")
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
                r#"(?i)(?-u:\b)cloudflare[_-]?(?:api[_-]?)?token\s*[=:]\s*['"]?[A-Za-z0-9_-]{30,}(?-u:\b)"#,
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
                r#"(?i)(?-u:\b)notion(?:[_-]?(?:integration[_-]?)?token|[_-]?secret)\s*[=:]\s*['"]?secret_[A-Za-z0-9]{43}(?-u:\b)"#,
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
            re: Regex::new(r"(?-u:\b)lin_api_[A-Za-z0-9]{40,}(?-u:\b)")
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
                r#"(?i)(?-u:\b)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?)://[^@\s"']+@[^\s"'<>]+"#,
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
            re: Regex::new(r"(?-u:\b)eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}(?-u:\b)")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Possible JWT detected",
            confidence: 0.75,
            validator: None,
        },
        CompiledRule {
            id: "secret.bearer_token",
            severity: Severity::Medium,
            kind: Kind::Secret,
            re: Regex::new(r"(?i)(?-u:\b)Bearer\s+[a-zA-Z0-9._~+/=-]{20,}(?-u:\b)")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Possible bearer token detected",
            confidence: 0.7,
            validator: None,
        },
        CompiledRule {
            id: "secret.dotenvx_private_key",
            severity: Severity::High,
            kind: Kind::Secret,
            re: Regex::new(r##"(?m)(?-u:\b)DOTENV_PRIVATE_KEY(?:_[A-Z0-9_]+)?\s*=\s*['"]?[^\s'"#]+"##)
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
                r#"(?i)(api[_-]?key|apikey|secret[_-]?key)\s*[=:]\s*['"]?([a-zA-Z0-9_-]{16,})['"]?(?-u:\b)"#,
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
            re: Regex::new(PRIVATE_KEY_HEADER_PATTERN)
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
            id: "pii.shk_plaintext_map",
            severity: Severity::High,
            kind: Kind::Pii,
            // A whole pseudonymize token (13-26 base32 chars for 64-128 bit
            // widths, word-bounded so identifiers like `email_template` do not
            // match) on the same line as a real email or a delimited phone.
            re: Regex::new(
                r"(?-u:\b)(?:email|phone|name)_[a-z2-7]{13,26}(?-u:\b)[^\n]{0,240}?(?:[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}|\+[1-9][0-9]{7,14}(?-u:\b)|0[0-9]{1,4}-[0-9]{1,4}-[0-9]{4}(?-u:\b))|(?:[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}|\+[1-9][0-9]{7,14}(?-u:\b)|0[0-9]{1,4}-[0-9]{1,4}-[0-9]{4}(?-u:\b))[^\n]{0,240}?(?-u:\b)(?:email|phone|name)_[a-z2-7]{13,26}(?-u:\b)",
            )
            .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Possible plaintext restore map (token plus original value)",
            confidence: 0.8,
            validator: None,
        },
        CompiledRule {
            id: "pii.credit_card",
            severity: Severity::Medium,
            kind: Kind::Pii,
            // Ends on a digit so the matched text (and thus allowlist value
            // hashes) never carries a trailing separator.
            re: Regex::new(r"(?:\b|(?-u:\b))\d(?:[ -]?\d){12,18}(?:\b|(?-u:\b))")
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
                r"(?:\b|(?-u:\b))(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\b|(?-u:\b))",
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
            re: Regex::new(r"(?-u:\b)(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}(?-u:\b)")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "IPv6 address detected",
            confidence: 0.6,
            validator: None,
        },
        CompiledRule {
            id: "pii.en.phone",
            severity: Severity::Medium,
            kind: Kind::Pii,
            re: Regex::new(r"(?:\+1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]\d{3}[-.\s]\d{4}(?:\b|(?-u:\b))")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "US/international phone number pattern detected",
            confidence: 0.75,
            validator: None,
        },
        CompiledRule {
            id: "pii.en.ein",
            severity: Severity::Low,
            kind: Kind::Pii,
            re: Regex::new(r"(?i)(?-u:\b)(?:ein|employer identification number)\s*[:#]?\s*\d{2}-\d{7}(?:\b|(?-u:\b))")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "US EIN pattern detected",
            confidence: 0.7,
            validator: None,
        },
        CompiledRule {
            id: "pii.en.postal_code",
            severity: Severity::Low,
            kind: Kind::Pii,
            re: Regex::new(r"(?i)(?-u:\b)(?:zip|postal(?: code)?)\s*[:#]?\s*\d{5}(?:-\d{4})?(?:\b|(?-u:\b))")
                .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "US ZIP/postal code pattern detected",
            confidence: 0.6,
            validator: None,
        },
        CompiledRule {
            id: "pii.en.passport",
            severity: Severity::Low,
            kind: Kind::Pii,
            re: Regex::new(r"(?i)(?-u:\b)passport(?:\s+(?:no|number))?\s*[:#]?\s*[A-Z0-9]{9}(?-u:\b)")
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
                r"(?-u:\b)(?i:name|full name|author|by)[ \t]*[:#][ \t]*[A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+){1,3}(?-u:\b)",
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
                r"(?-u:\b)(?i:address|street address|mailing address)[ \t]*[:#][ \t]*\d{1,6}[ \t]+[A-Z][A-Za-z0-9.'-]*(?:[ \t]+[A-Z][A-Za-z0-9.'-]*){0,5}[ \t]+(?i:street|st|avenue|ave|road|rd|drive|dr|lane|ln|boulevard|blvd|court|ct|way)(?-u:\b)",
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
                r"(?i)(?-u:\b)(?:ssn|social security(?: number)?|social security no\.?)\s*[:#]?\s*\d{3}-\d{2}-\d{4}(?:\b|(?-u:\b))",
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
            // Covers ordinary 10/11-digit numbers, six-digit-suffix 0AB0
            // services, and the documented 11/14-digit M2M groupings. Phone
            // syntax is deliberately ASCII-only; mixed digit scripts are
            // ambiguous identifiers rather than supported phone notation.
            re: Regex::new(
                r"(?:020-0[0-9]{5}-[0-9]{5}|020-[1-35-9][0-9]{2}-[0-9]{5}|0(?:120|170|180|570|990)-[0-9]{3}-[0-9]{3}|0[0-9]{1,4}-[0-9]{1,4}-[0-9]{4})",
            )
            .unwrap_or_else(|_| Regex::new("^$").unwrap()),
            message: "Japanese phone number pattern detected",
            confidence: 0.75,
            validator: Some(japanese_phone_valid),
        },
        CompiledRule {
            id: "pii.ja.postal_code",
            severity: Severity::Medium,
            kind: Kind::Pii,
            re: Regex::new(r"(?i)(?:〒\d{3}-\d{4}(?:\b|(?-u:\b))|(?:郵便番号|郵便|postal(?: code)?)\s*[:：]?\s*\d{3}-\d{4}(?:\b|(?-u:\b)))")
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
                r"(?i)(?:旅券番号|パスポート(?:番号|ナンバー)?|passport(?:\s+(?:no|number))?)\s*[:：#]?\s*[A-Z]{2}\d{7}(?:\b|(?-u:\b))",
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
                r"(?:銀行|金融機関|支店|口座番号|口座)\s*[:：]?\s*[^\n]{0,40}\d{7}(?:\b|(?-u:\b))",
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

/// Prefixes bundlers inline into client-side JavaScript at build time. A value
/// so named ships in the public bundle by construction (Vite's own docs say
/// these "should not contain sensitive information").
const BROWSER_PUBLIC_ENV_PREFIXES: &[&str] = &[
    "NEXT_PUBLIC_",
    "VITE_",
    "REACT_APP_",
    "EXPO_PUBLIC_",
    "GATSBY_",
    "NUXT_PUBLIC_",
    "VUE_APP_",
    "PUBLIC_",
];

/// Name-based guard for name-heuristic rules (`env.sensitive_assignment`,
/// `secret.generic_api_key`); vendor-format rules keep matching the value
/// independently of what the variable is called.
///
/// - `*_PATH` / `*_FILE` / `*_DIR` names hold a location, not the secret
///   itself: `SSH_KEY_PATH` is a filename, and the key it points at is
///   covered by the private-key rules when that file is scanned.
/// - Browser-public build prefixes are excluded unless the name also says
///   SECRET/PASSWORD/PRIVATE — `NEXT_PUBLIC_STRIPE_SECRET_KEY` is a
///   misconfiguration worth reporting, not a public value.
fn env_key_is_public_by_construction(key: &str) -> bool {
    let key = key.to_ascii_uppercase();
    if ["_PATH", "_FILE", "_DIR"]
        .iter()
        .any(|suffix| key.ends_with(suffix))
    {
        return true;
    }
    ["SECRET", "PASSWORD", "PASSWD", "PRIVATE"]
        .iter()
        .all(|marker| !key.contains(marker))
        && BROWSER_PUBLIC_ENV_PREFIXES
            .iter()
            .any(|prefix| key.starts_with(prefix))
}

/// Numeric values are benign only when the name identifies metadata about a
/// credential. A numeric password or API key can still be a real credential
/// and must not be suppressed merely because it contains one character class.
fn env_numeric_value_is_metadata(key: &str) -> bool {
    let key = key.to_ascii_uppercase();
    [
        "_EXPIRY",
        "_EXPIRES",
        "_EXPIRATION",
        "_TTL",
        "_PORT",
        "_TIMEOUT",
        "_TIMESTAMP",
        "_VERSION",
    ]
    .iter()
    .any(|suffix| key.ends_with(suffix))
}

/// The identifier characters immediately before `match_start`, for rules whose
/// regex starts matching mid-identifier (`API_KEY` inside `NEXT_PUBLIC_API_KEY`).
fn identifier_prefix(content: &str, match_start: usize) -> &str {
    let head = &content[..match_start];
    let start = head
        .char_indices()
        .rev()
        .find(|(_, c)| !(c.is_ascii_alphanumeric() || *c == '_'))
        .map_or(0, |(index, c)| index + c.len_utf8());
    &head[start..]
}

fn generic_api_key_name_is_public(content: &str, match_start: usize, matched: &str) -> bool {
    let key_in_match: String = matched
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    let full_key = format!(
        "{}{}",
        identifier_prefix(content, match_start),
        key_in_match
    );
    env_key_is_public_by_construction(&full_key)
}

fn env_assignment_valid(candidate: &str) -> bool {
    // Dotenv semantics: the value is everything after the first `=`, so
    // base64 padding (`=`) and URL values containing `:` stay intact.
    let (key, value) = match candidate.split_once('=') {
        Some((k, v)) => (k, v.trim().trim_matches(|c| c == '"' || c == '\'')),
        None => return false,
    };
    // The key is the last word before `=` (skipping an `export` prefix).
    let key = key.split_whitespace().next_back().unwrap_or("");
    if env_key_is_public_by_construction(key) {
        return false;
    }
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
    // Credential metadata often contains only a port, timestamp, or duration.
    // Do not generalize this to the credential itself: numeric secrets exist.
    if value.chars().all(|c| c.is_ascii_digit()) && env_numeric_value_is_metadata(key) {
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
    // The Japanese numbering plan uses 10/11-digit subscriber numbers plus
    // 14-digit 0200 M2M numbers. Exact lengths reject date-like and arbitrary
    // hyphenated numeric IDs without excluding the longer M2M allocation.
    let digits: Vec<u32> = candidate.chars().filter_map(decimal_digit_value).collect();
    let digit_count = digits.len();
    if !matches!(digit_count, 10 | 11 | 14) {
        return false;
    }

    let groups: Vec<&str> = candidate.split('-').collect();
    if groups.len() != 3 {
        return false;
    }
    let group_lengths: Vec<usize> = groups
        .iter()
        .map(|group| group.chars().filter_map(decimal_digit_value).count())
        .collect();

    // 0AB0 service allocations are always 10 digits, written either 4-3-3 or
    // 4-2-4. Without this check, the broad ordinary-number branch would accept
    // an 11-digit e.g. 0120-123-4567.
    const TEN_DIGIT_0AB0_PREFIXES: [[u32; 4]; 5] = [
        [0, 1, 2, 0],
        [0, 1, 7, 0],
        [0, 1, 8, 0],
        [0, 5, 7, 0],
        [0, 9, 9, 0],
    ];
    if TEN_DIGIT_0AB0_PREFIXES
        .iter()
        .any(|prefix| digits.starts_with(prefix))
        && (digit_count != 10 || !matches!(group_lengths[..], [4, 3, 3] | [4, 2, 4]))
    {
        return false;
    }
    if digits.starts_with(&[0, 8, 0, 0]) && (digit_count != 11 || group_lengths != [4, 3, 4]) {
        return false;
    }

    // 0200 is the canonical 3-6-5, 14-digit M2M allocation. Legacy 020C
    // M2M numbers use 3-3-5 (C excludes 0 and 4), while 0204 paging numbers
    // use 4-3-4. Validate grouping so moving a hyphen cannot bypass the
    // allocation-specific constraints.
    if digits.starts_with(&[0, 2, 0, 0]) {
        if digit_count != 14 || group_lengths != [3, 6, 5] {
            return false;
        }
    } else if digits.starts_with(&[0, 2, 0, 4]) {
        if digit_count != 11 || group_lengths != [4, 3, 4] {
            return false;
        }
    } else if digits.starts_with(&[0, 2, 0])
        && (digit_count != 11 || group_lengths != [3, 3, 5] || matches!(digits.get(3), Some(0 | 4)))
    {
        return false;
    }

    !groups[1..]
        .iter()
        .all(|group| group.chars().all(|c| c == '0'))
}

fn japanese_phone_embedded_in_numeric_chain(content: &str, start: usize, end: usize) -> bool {
    let left = &content[..start];
    let right = &content[end..];

    // The phone syntax itself is ASCII-only, but any adjacent Unicode numeric
    // character means the regex found a substring of a larger numeric token.
    let preceded_by_digit = left.chars().next_back().is_some_and(char::is_numeric);
    let preceded_by_hyphenated_digit = left
        .strip_suffix('-')
        .and_then(|prefix| prefix.chars().next_back())
        .is_some_and(char::is_numeric);
    let followed_by_digit = right.chars().next().is_some_and(char::is_numeric);
    let followed_by_hyphenated_digit = right
        .strip_prefix('-')
        .and_then(|suffix| suffix.chars().next())
        .is_some_and(char::is_numeric);

    preceded_by_digit
        || preceded_by_hyphenated_digit
        || followed_by_digit
        || followed_by_hyphenated_digit
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

/// Every gitleaks keyword in one automaton, with the rule each belongs to.
struct GitleaksKeywordIndex {
    automaton: AhoCorasick,
    /// Rule index (into `gitleaks_rules::rules()`) per automaton pattern.
    pattern_rule: Vec<usize>,
    /// Rules without keywords always run.
    always: Vec<bool>,
}

static GITLEAKS_KEYWORDS: Lazy<GitleaksKeywordIndex> = Lazy::new(|| {
    let rules = gitleaks_rules::rules();
    let mut patterns = Vec::new();
    let mut pattern_rule = Vec::new();
    let mut always = vec![false; rules.len()];
    for (idx, rule) in rules.iter().enumerate() {
        if rule.keywords.is_empty() {
            always[idx] = true;
        }
        for keyword in rule.keywords {
            patterns.push(*keyword);
            pattern_rule.push(idx);
        }
    }
    let automaton = AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(&patterns)
        .expect("gitleaks keywords build into an automaton");
    GitleaksKeywordIndex {
        automaton,
        pattern_rule,
        always,
    }
});

/// The gitleaks rules worth running on `content`: those with a keyword in it
/// (ASCII case-insensitive), in rule order. One pass over the content instead
/// of one substring search per keyword.
fn gitleaks_candidate_rules(content: &str) -> Vec<&'static GitleaksRule> {
    let index = &*GITLEAKS_KEYWORDS;
    let mut hits = index.always.clone();
    // Overlapping search: keywords can be substrings of one another, and
    // each rule must see its own.
    for found in index.automaton.find_overlapping_iter(content) {
        hits[index.pattern_rule[found.pattern().as_usize()]] = true;
    }
    gitleaks_rules::rules()
        .iter()
        .zip(hits)
        .filter_map(|(rule, hit)| hit.then_some(rule))
        .collect()
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
    for r in gitleaks_candidate_rules(content) {
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

fn built_in_rule_match_is_valid(
    rule: &CompiledRule,
    content: &str,
    matched: regex::Match<'_>,
) -> bool {
    if let Some(validate) = rule.validator
        && !validate(matched.as_str())
    {
        return false;
    }
    // This rule matches mid-identifier (`API_KEY` inside
    // `NEXT_PUBLIC_API_KEY`), so the browser-public name guard needs the
    // characters before the match; validators only see the matched text.
    if rule.id == "secret.generic_api_key"
        && generic_api_key_name_is_public(content, matched.start(), matched.as_str())
    {
        return false;
    }
    if rule.id == "pii.ja.phone"
        && japanese_phone_embedded_in_numeric_chain(content, matched.start(), matched.end())
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
        if !rule_applies(r, cfg) {
            continue;
        }
        let redacted = r.re.replace_all(&s, |captures: &regex::Captures<'_>| {
            let matched = captures.get(0).expect("capture zero always exists");
            if built_in_rule_match_is_valid(r, &s, matched) {
                "[REDACTED]".to_string()
            } else {
                matched.as_str().to_string()
            }
        });
        s = redacted.into_owned();
    }
    if cfg.secrets {
        for r in gitleaks_candidate_rules(&s) {
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
            if !built_in_rule_match_is_valid(r, content, m) {
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
    fn env_assignment_skips_browser_public_prefixes() {
        let cfg = RuleEngineConfig::default();
        // not real credentials: synthetic detector fixture values only
        let text = concat!(
            "NEXT_PUBLIC_ANALYTICS_TOKEN=phc-aB3dE5gH7jK9mN2pQ4sT\n",
            "VITE_API_KEY=vk-aB3dE5gH7jK9mN2pQ4sT\n",
            "REACT_APP_MAPS_TOKEN=maps-aB3dE5gH7jK9mN2p\n",
        );
        let m = scan_content(text, ".env", &cfg);
        assert!(
            !m.iter().any(|x| x.rule_id == "env.sensitive_assignment"),
            "{m:?}"
        );
        assert!(
            !m.iter().any(|x| x.rule_id == "secret.generic_api_key"),
            "{m:?}"
        );
    }

    #[test]
    fn env_assignment_public_prefix_with_secret_name_still_fires() {
        let cfg = RuleEngineConfig::default();
        // NEXT_PUBLIC_ + SECRET is a misconfiguration, not a public value.
        // not real credentials: synthetic detector fixture values only
        let text = "NEXT_PUBLIC_STRIPE_SECRET_KEY=sk-aB3dE5gH7jK9mN2pQ4sT\n";
        let m = scan_content(text, ".env", &cfg);
        assert!(
            m.iter().any(|x| x.rule_id == "env.sensitive_assignment"),
            "{m:?}"
        );
        assert!(
            m.iter().any(|x| x.rule_id == "secret.generic_api_key"),
            "{m:?}"
        );
    }

    #[test]
    fn generic_api_key_guard_sees_prefix_outside_dotenv_files() {
        let cfg = RuleEngineConfig::default();
        // In source files the env rule is gated off, but the generic rule
        // still runs; the name guard must look left of the match.
        let code = "const config = { NEXT_PUBLIC_API_KEY: \"pk19d8e37a6c45bf28\" };\n";
        let m = scan_content(code, "src/config.ts", &cfg);
        assert!(
            !m.iter().any(|x| x.rule_id == "secret.generic_api_key"),
            "{m:?}"
        );
        // Without a public prefix the same shape still matches.
        let code = "const config = { STRIPE_API_KEY: \"pk19d8e37a6c45bf28\" };\n";
        let m = scan_content(code, "src/config.ts", &cfg);
        assert!(
            m.iter().any(|x| x.rule_id == "secret.generic_api_key"),
            "{m:?}"
        );
    }

    #[test]
    fn env_assignment_skips_path_file_dir_names() {
        let cfg = RuleEngineConfig::default();
        let text = concat!(
            "TOKEN_FILE=/run/secrets/github-token\n",
            "SSH_PRIVATE_KEY_PATH=/home/ci/keys/deploy.pem\n",
            "SECRETS_DIR=/etc/app/secrets-store\n",
        );
        let m = scan_content(text, ".env", &cfg);
        assert!(
            !m.iter().any(|x| x.rule_id == "env.sensitive_assignment"),
            "{m:?}"
        );
    }

    #[test]
    fn env_assignment_skips_pure_numeric_values() {
        let cfg = RuleEngineConfig::default();
        let text = "API_KEY_EXPIRY=1928374650\n";
        let m = scan_content(text, ".env", &cfg);
        assert!(
            !m.iter().any(|x| x.rule_id == "env.sensitive_assignment"),
            "{m:?}"
        );

        let numeric_credential = concat!("API", "_KEY", "=1928374650\n");
        let m = scan_content(numeric_credential, ".env", &cfg);
        assert!(
            m.iter().any(|x| x.rule_id == "env.sensitive_assignment"),
            "numeric credentials must not be suppressed: {m:?}"
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
    fn redact_line_uses_japanese_phone_validation_and_context_guards() {
        let cfg = RuleEngineConfig::default();

        let date = redact_line_for_display("release date: 04-01-2024", &cfg);
        assert_eq!(date, "release date: 04-01-2024");

        let numeric_id = redact_line_for_display("id: 7-090-1234-5678-9", &cfg);
        assert_eq!(numeric_id, "id: 7-090-1234-5678-9");

        let phone = redact_line_for_display("電話090-1234-5678です", &cfg);
        assert_eq!(phone, "電話[REDACTED]です");
    }

    fn rule_hits(text: &str, rule_id: &str) -> Vec<String> {
        let cfg = RuleEngineConfig::default();
        scan_content(text, "notes.md", &cfg)
            .into_iter()
            .filter(|x| x.rule_id == rule_id)
            .map(|x| x.matched_text)
            .collect()
    }

    #[test]
    fn aws_access_key_between_kana_is_detected_and_redacted() {
        // not real credential: synthetic detector fixture value only
        let key = ["AKIA", "QRSTUVWX", "23456789"].concat();
        let line = format!("キーは{key}です");
        assert_eq!(rule_hits(&line, "secret.aws_access_key"), vec![key.clone()]);

        let cfg = RuleEngineConfig::default();
        let shown = redact_line_for_display(&line, &cfg);
        assert_eq!(shown, "キーは[REDACTED]です");
    }

    /// Text that touches a value with no space: kana, kanji, full-width
    /// letters and digits (all Unicode word characters), and full-width
    /// punctuation (never a word character).
    const JAPANESE_WRAPPERS: [(&str, &str); 5] = [
        ("キーは", "です"),
        ("鍵", "漏洩"),
        ("ＡＢ", "１２"),
        ("「", "」"),
        ("：", "、"),
    ];

    #[test]
    fn secret_tokens_touching_japanese_text_are_detected() {
        // not real credentials: synthetic detector fixture values only
        let samples = [
            (
                "secret.openai_api_key",
                ["sk-", "proj-", "abcdefghijklmnopqrstuvwxyz0123456789"].concat(),
            ),
            (
                "secret.aws_access_key",
                ["ASIA", "QRSTUVWX", "23456789"].concat(),
            ),
            (
                "secret.anthropic_api_key",
                ["sk-", "ant-", "api03AbcdefghijKLMNOPqrstu"].concat(),
            ),
            (
                "secret.google_api_key",
                ["AI", "za", "SyAbcdefghijklmnopqrstuvwxyz0123456"].concat(),
            ),
            (
                "secret.github_token",
                ["gh", "p_", "abcdefghijklmnopqrstuvwxyzABCDEF0123"].concat(),
            ),
            (
                "secret.slack_token",
                ["xo", "xb-", "123456789012-abcdefghijklmnop"].concat(),
            ),
            (
                "secret.stripe_api_key",
                ["sk", "_live_", "abcdefghijklmnopqrstuvwx"].concat(),
            ),
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
            (
                "secret.jwt",
                [
                    "eyJ",
                    "abcdefghijklmnopqrstuvwxyz",
                    ".ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
                    ".abcdefghijklmnopqrstuvwxyz0123456789",
                ]
                .concat(),
            ),
            (
                "secret.bearer_token",
                ["Bearer ", "abcdefghijklmnop", "QRSTUVWX01234567"].concat(),
            ),
            (
                "secret.generic_api_key",
                ["api_key=", "Ab3dEf7hIj1kLm5n", "Op9qRs2t"].concat(),
            ),
        ];
        let cfg = RuleEngineConfig::default();
        for (id, sample) in &samples {
            for (before, after) in JAPANESE_WRAPPERS {
                let line = format!("{before}{sample}{after}");
                assert_eq!(
                    rule_hits(&line, id),
                    vec![sample.clone()],
                    "{id} in {before}…{after}"
                );
                let shown = redact_line_for_display(&line, &cfg);
                let value = sample.rsplit(['=', ' ']).next().unwrap_or(sample);
                assert!(!shown.contains(value), "{id} left in context line: {shown}");
            }
        }
    }

    #[test]
    fn secret_rules_with_open_ended_values_start_after_japanese_text() {
        // These two patterns end on "anything but whitespace or a quote", so
        // only the leading boundary is in play.
        // not real credentials: synthetic detector fixture values only
        let url = [
            "postgres",
            "://",
            "app:",
            "pw4Synthetic",
            "@",
            "db.internal/app",
        ]
        .concat();
        for before in ["接続先は", "鍵", "：", "ＡＢ"] {
            let hits = rule_hits(&format!("{before}{url}"), "secret.database_url");
            assert_eq!(hits, vec![url.clone()], "{before}");
        }
        let assignment = ["DOTENV_", "PRIVATE_KEY", "=", "dotenvx-secret-demo-value"].concat();
        for before in ["設定は", "鍵", "：", "ＡＢ"] {
            let hits = rule_hits(
                &format!("{before}{assignment}"),
                "secret.dotenvx_private_key",
            );
            assert_eq!(hits, vec![assignment.clone()], "{before}");
        }
    }

    #[test]
    fn secret_token_boundaries_still_reject_ascii_word_neighbours() {
        // not real credentials: synthetic detector fixture values only
        let aws = ["AKIA", "QRSTUVWX", "23456789"].concat();
        for line in [
            format!("x{aws}"),
            format!("_{aws}"),
            format!("9{aws}"),
            format!("{aws}Z"),
            format!("{aws}_suffix"),
            format!("キーはx{aws}です"),
            format!("キーは{aws}0です"),
        ] {
            assert!(
                rule_hits(&line, "secret.aws_access_key").is_empty(),
                "{line}"
            );
        }
        let github = ["gh", "p_", "abcdefghijklmnopqrstuvwxyzABCDEF0123"].concat();
        for line in [format!("my{github}"), format!("キーはmy{github}です")] {
            assert!(rule_hits(&line, "secret.github_token").is_empty(), "{line}");
        }
        let npm = ["npm_", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"].concat();
        for line in [format!("{npm}K"), format!("キーは{npm}Kです")] {
            assert!(rule_hits(&line, "secret.npm_token").is_empty(), "{line}");
        }
    }

    #[test]
    fn pii_values_touching_japanese_text_are_detected() {
        // not real personal data: synthetic detector fixture values only
        let token = ["email_", "abcdefghijklm"].concat();
        let map_line = format!("対応表{token}は090-1234-5678です");
        let cases: [(&str, &str, &str); 17] = [
            (
                "pii.credit_card",
                "カード番号は4111111111111111です",
                "4111111111111111",
            ),
            (
                "pii.credit_card",
                "カード4111 1111 1111 1111まで",
                "4111 1111 1111 1111",
            ),
            ("pii.ipv4", "サーバー192.168.10.5に接続", "192.168.10.5"),
            (
                "pii.ipv6",
                "宛先2001:db8:0:0:0:0:0:1へ",
                "2001:db8:0:0:0:0:0:1",
            ),
            ("pii.en.phone", "電話は415-555-0123です", "415-555-0123"),
            ("pii.en.ein", "番号EIN: 12-3456789です", "EIN: 12-3456789"),
            ("pii.en.postal_code", "住所ZIP: 94105です", "ZIP: 94105"),
            (
                "pii.en.passport",
                "旅券passport number: A12345678を確認",
                "passport number: A12345678",
            ),
            (
                "pii.en.name",
                "担当name: John Smithさん",
                "name: John Smith",
            ),
            (
                "pii.en.address",
                "住所address: 123 Main Streetです",
                "address: 123 Main Street",
            ),
            ("pii.en.ssn", "本人SSN: 123-45-6789です", "SSN: 123-45-6789"),
            (
                "pii.ja.postal_code",
                "〒100-0001東京都千代田区",
                "〒100-0001",
            ),
            (
                "pii.ja.postal_code",
                "郵便番号100-0001です",
                "郵便番号100-0001",
            ),
            (
                "pii.ja.passport",
                "旅券番号TK1234567を確認",
                "旅券番号TK1234567",
            ),
            (
                "pii.ja.bank_account",
                "口座番号1234567です",
                "口座番号1234567",
            ),
            ("pii.shk_plaintext_map", map_line.as_str(), ""),
            ("pii.ja.phone", "電話090-1234-5678です", "090-1234-5678"),
        ];
        let cfg = RuleEngineConfig::default();
        for (id, line, expected) in cases {
            let hits = rule_hits(line, id);
            assert_eq!(hits.len(), 1, "{id}: {line} -> {hits:?}");
            if !expected.is_empty() {
                assert_eq!(hits[0], expected, "{id}: {line}");
            }
            let shown = redact_line_for_display(line, &cfg);
            assert!(
                !shown.contains(hits[0].as_str()),
                "{id} left in context line: {shown}"
            );
        }
    }

    #[test]
    fn full_width_digits_keep_their_unicode_boundary() {
        // `\d` also matches full-width digits, which are not ASCII word
        // characters: an ASCII-only boundary would drop these.
        // not real personal data: synthetic detector fixture values only
        for (id, line) in [
            (
                "pii.credit_card",
                "カード番号: ４１１１１１１１１１１１１１１１ です",
            ),
            (
                "pii.credit_card",
                "card ４１１１ １１１１ １１１１ １１１１.",
            ),
            ("pii.ja.passport", "旅券番号: TK１２３４５６７ を確認"),
            ("pii.ja.bank_account", "口座番号: １２３４５６７ です"),
            ("pii.en.ssn", "SSN: １２３-４５-６７８９ ok"),
            ("pii.en.postal_code", "ZIP: １２３４５ ok"),
            ("pii.en.ein", "EIN: １２-３４５６７８９ ok"),
            ("pii.en.phone", "call ４１５-５５５-０１２３ now"),
        ] {
            assert_eq!(rule_hits(line, id).len(), 1, "{id}: {line}");
        }
    }

    #[test]
    fn pii_boundaries_still_reject_longer_runs_and_identifiers() {
        // not real personal data: synthetic detector fixture values only
        for (id, line) in [
            // Part of a longer digit run or an identifier, with and without
            // Japanese text around it.
            ("pii.credit_card", "id_4111111111111111"),
            ("pii.credit_card", "x4111111111111111"),
            ("pii.credit_card", "番号はx4111111111111111です"),
            ("pii.credit_card", "41111111111111111111111"),
            ("pii.credit_card", "番号は41111111111111111111111です"),
            ("pii.ipv4", "v192.168.10.5"),
            ("pii.ipv4", "192.168.10.5000"),
            ("pii.ipv4", "版192.168.10.5000です"),
            ("pii.en.phone", "415-555-01234"),
            ("pii.en.phone", "電話は415-555-01234です"),
            ("pii.en.ssn", "SSN: 123-45-67890"),
            ("pii.en.ssn", "myssn: 123-45-6789"),
            ("pii.en.ein", "protein: 12-3456789"),
            ("pii.en.postal_code", "unzip: 94105"),
            ("pii.en.postal_code", "ZIP: 941050"),
            ("pii.en.passport", "passport A123456789"),
            ("pii.en.name", "filename: John Smith"),
            ("pii.en.name", "担当name: John Smithson3"),
            ("pii.ja.postal_code", "〒100-00012"),
            ("pii.ja.postal_code", "郵便番号100-00012です"),
            ("pii.ja.passport", "旅券番号TK12345678"),
            ("pii.ja.bank_account", "口座番号1234567a"),
            ("pii.shk_plaintext_map", "email_template_id = 12345678"),
            (
                "pii.shk_plaintext_map",
                "テンプレemail_template_idは12345678",
            ),
        ] {
            let hits = rule_hits(line, id);
            assert!(hits.is_empty(), "{id}: {line} -> {hits:?}");
        }
    }

    /// The pattern as it was before the boundaries were written out.
    fn unicode_boundary_pattern(rule: &CompiledRule) -> String {
        rule.re
            .as_str()
            .replace(r"(?:\b|(?-u:\b))", r"\b")
            .replace(r"(?-u:\b)", r"\b")
    }

    fn fixture_texts(dir: &std::path::Path, out: &mut Vec<(String, String)>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                fixture_texts(&path, out);
            } else if let Ok(text) = std::fs::read_to_string(&path) {
                out.push((path.display().to_string(), text));
            }
        }
    }

    #[test]
    fn written_out_boundaries_keep_every_fixture_match() {
        let mut texts = Vec::new();
        let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
        fixture_texts(&fixtures, &mut texts);
        assert!(!texts.is_empty(), "no fixtures under {fixtures:?}");
        // Sample values of the other tests, in plain ASCII surroundings.
        texts.push((
            "inline".to_string(),
            "card: 4111 1111 1111 1111 ok\nSSN: 123-45-6789\nphone: (555) 555-5555\n\
             passport AB1234567\nName: John Smith\nhost 192.168.10.5 up\n"
                .to_string(),
        ));

        let mut compared = 0usize;
        for rule in RULES.iter() {
            let pattern = unicode_boundary_pattern(rule);
            if pattern == rule.re.as_str() {
                continue;
            }
            let legacy = Regex::new(&pattern).expect("legacy pattern compiles");
            for (name, text) in &texts {
                let old: Vec<_> = legacy.find_iter(text).map(|m| m.range()).collect();
                let new: Vec<_> = rule.re.find_iter(text).map(|m| m.range()).collect();
                compared += old.len();
                if text.is_ascii() {
                    // Both boundaries agree on ASCII text.
                    assert_eq!(old, new, "{} in {name}", rule.id);
                    continue;
                }
                for range in &old {
                    assert!(
                        new.iter()
                            .any(|n| n.start <= range.start && range.end <= n.end),
                        "{} lost {:?} in {name}",
                        rule.id,
                        &text[range.clone()]
                    );
                }
            }
        }
        assert!(compared > 0, "fixtures exercised no rewritten rule");
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
    fn detects_plaintext_restore_map_on_one_line() {
        let cfg = RuleEngineConfig::default();
        let token = ["email_", "abcdefghijklm"].concat();
        let addr = ["ada", "@", "example.com"].concat();
        let hits = |text: &str| {
            scan_content(text, "map.json", &cfg)
                .iter()
                .filter(|x| x.rule_id == "pii.shk_plaintext_map")
                .count()
        };
        assert_eq!(hits(&format!("{token} {addr}")), 1);
        assert_eq!(hits(&format!("{addr}\t{token}")), 1);
        assert_eq!(hits(&format!("{token}, 090-1234-5678")), 1);
        // Tokens alone, identifiers that merely start with a prefix, and
        // numbers that are not delimited phones must stay quiet.
        assert_eq!(hits(&token), 0);
        assert_eq!(hits("email_template_id = 12345678"), 0);
        assert_eq!(hits("email_verified_at = 1694412345"), 0);
        assert_eq!(
            hits(&format!("let user_email_verified = true; // {addr}")),
            0
        );
        assert_eq!(hits(&format!("email_provider = \"{addr}\"")), 0);
        assert_eq!(hits("name_validator = \"2024-01-01 12:00:00\""), 0);
        // 26 base32 characters is a 128-bit token; 27 is not a token at all.
        assert_eq!(hits(&format!("email_abcdefghijklmnopqrstuvwxyz {addr}")), 1);
        assert_eq!(
            hits(&format!("email_abcdefghijklmnopqrstuvwxyz2 {addr}")),
            0
        );
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
        let re = &RULES
            .iter()
            .find(|rule| rule.id == "pii.credit_card")
            .expect("credit card rule exists")
            .re;
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
    fn japanese_phone_rejects_hyphenated_dates() {
        let cfg = RuleEngineConfig::default();
        let m = scan_content(
            "US date: 04-01-2024\nEuropean date: 01-04-2024",
            "dates.txt",
            &cfg,
        );
        assert!(!m.iter().any(|x| x.rule_id == "pii.ja.phone"), "{m:?}");
    }

    #[test]
    fn japanese_phone_still_detects_ten_and_eleven_digit_numbers() {
        let cfg = RuleEngineConfig::default();
        // Synthetic detector fixtures only.
        let m = scan_content(
            concat!(
                "fixed: 03-1234-5678\n",
                "mobile: 090-1234-5678\n",
                "toll-free: 0120-123-456\n",
                "toll-free 4-2-4: 0120-86-2222\n",
                "navigation: 0570-123-456\n",
                "navigation 4-2-4: 0570-06-4964\n",
                "telegong 4-2-4: 0180-99-1234\n",
                "dial-q2 4-2-4: 0990-51-1234\n",
                "toll-free-long: 0800-123-4567\n",
                "電話090-2345-6789\n",
                "phone_070-3456-7890",
            ),
            "contacts.txt",
            &cfg,
        );
        assert_eq!(
            m.iter().filter(|x| x.rule_id == "pii.ja.phone").count(),
            11,
            "{m:?}"
        );
    }

    #[test]
    fn japanese_phone_detects_documented_m2m_lengths() {
        let cfg = RuleEngineConfig::default();
        // Synthetic detector fixtures only. 020C excludes C=0 and C=4.
        let m = scan_content(
            concat!(
                "legacy M2M: 020-123-45678\n",
                "14-digit M2M: 020-012345-67890\n",
                "paging: 0204-123-4567",
            ),
            "devices.txt",
            &cfg,
        );
        assert_eq!(
            m.iter().filter(|x| x.rule_id == "pii.ja.phone").count(),
            3,
            "{m:?}"
        );
    }

    #[test]
    fn japanese_phone_does_not_match_prefix_of_longer_number() {
        let cfg = RuleEngineConfig::default();
        let m = scan_content(
            concat!(
                "long suffix: 090-1234-56789\n",
                "long prefix: 1090-1234-5678\n",
                "hyphen chain: 7-090-1234-5678-9\n",
                "full-width suffix: 090-1234-5678１\n",
                "Arabic-Indic suffix: 090-1234-5678١",
            ),
            "ids.txt",
            &cfg,
        );
        assert!(!m.iter().any(|x| x.rule_id == "pii.ja.phone"), "{m:?}");
    }

    #[test]
    fn japanese_phone_rejects_non_ascii_and_mixed_digit_scripts() {
        let cfg = RuleEngineConfig::default();
        let m = scan_content(
            concat!(
                "full-width: ０９０-１２３４-５６７８\n",
                "mixed: 0９０-００００-００００\n",
                "Arabic-Indic: ٠٩٠-١٢٣٤-٥٦٧٨",
            ),
            "ids.txt",
            &cfg,
        );
        assert!(!m.iter().any(|x| x.rule_id == "pii.ja.phone"), "{m:?}");
    }

    #[test]
    fn japanese_phone_rejects_unsupported_lengths_and_m2m_prefixes() {
        let cfg = RuleEngineConfig::default();
        let m = scan_content(
            concat!(
                "short id: 012-34-5678\n",
                "twelve-digit id: 0123-1234-5678\n",
                "overlong 0120: 0120-123-4567\n",
                "overlong 0570: 0570-123-4567\n",
                "short 0800: 0800-123-456\n",
                "reserved legacy M2M: 020-012-45678\n",
                "reserved pager prefix: 020-412-45678\n",
                "regrouped pager: 020-4123-4567\n",
                "invalid 14-digit M2M: 020-112345-67890\n",
                "short 0200: 0200-123-4567",
            ),
            "ids.txt",
            &cfg,
        );
        assert!(!m.iter().any(|x| x.rule_id == "pii.ja.phone"), "{m:?}");
    }

    #[test]
    fn japanese_phone_rejects_zero_padded_calendar_date_matrix() {
        let rule = RULES
            .iter()
            .find(|rule| rule.id == "pii.ja.phone")
            .expect("Japanese phone rule");
        let validate = rule.validator.expect("Japanese phone validator");

        for year in 1900..=2100 {
            for month in 1..=12 {
                for day in 1..=31 {
                    for candidate in [
                        format!("{month:02}-{day:02}-{year:04}"),
                        format!("{day:02}-{month:02}-{year:04}"),
                    ] {
                        assert!(
                            !rule
                                .re
                                .find_iter(&candidate)
                                .any(|matched| validate(matched.as_str())),
                            "date matched Japanese phone rule: {candidate}"
                        );
                    }
                }
            }
        }
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
        let is_candidate = |content: &str| {
            gitleaks_candidate_rules(content)
                .iter()
                .any(|r| r.id == "secret.gitleaks.aws-access-token")
        };
        assert!(is_candidate("token AKIA0123456789ABCDEF"));
        assert!(is_candidate("token akia0123456789abcdef"));
        assert!(!is_candidate("token without marker"));
    }

    #[test]
    fn gitleaks_word_boundary_is_ascii_like_upstream() {
        // gitleaks patterns are written for Go's RE2, where `\b` is
        // ASCII-only: kana and kanji next to a token are not word characters,
        // so the token still starts and ends at a word boundary.
        let cfg = RuleEngineConfig::default();
        // not real credential: synthetic detector fixture value only
        let key = ["AKIA", "Q7RT2MXB", "4NZP6WKD"].concat();
        for content in [
            format!("key {key} here"),
            format!("キーは{key}です"),
            format!("鍵{key}。"),
        ] {
            let m = scan_content(&content, "notes.md", &cfg);
            assert!(
                m.iter()
                    .any(|x| x.rule_id == "secret.gitleaks.aws-access-token"),
                "{content:?}: {m:?}"
            );
        }
        // A full-width letter is not an ASCII word character either, so it
        // does not extend the token into something the pattern rejects.
        let m = scan_content(&format!("Ａ{key}Ｚ"), "notes.md", &cfg);
        assert!(
            m.iter()
                .any(|x| x.rule_id == "secret.gitleaks.aws-access-token"),
            "{m:?}"
        );
    }

    #[test]
    fn gitleaks_generic_rules_keep_matching_around_non_ascii_text() {
        // The generated patterns no longer use the Unicode word table; text
        // that it let through between a service name and its value, and
        // Unicode whitespace around the value, must keep matching.
        let cfg = RuleEngineConfig::default();
        // not real credential: synthetic detector fixture value only
        let value = ["q7rt2mxb4nzp6wkd", "h3vy9cse5jfa8gu1"].concat();
        for content in [
            format!("adafruit_key = {value}"),
            format!("adafruitのキー: {value}"),
            format!("adafruit_clé = \"{value}\""),
            format!("adafruit_key:\u{3000}{value}\u{3000}次の文"),
            format!("adafruit_key = {value}\u{a0}"),
        ] {
            let m = scan_content(&content, "notes.md", &cfg);
            assert!(
                m.iter()
                    .any(|x| x.rule_id == "secret.gitleaks.adafruit-api-key"),
                "{content:?}: {m:?}"
            );
        }
    }

    #[test]
    fn gitleaks_private_key_block_spans_unicode_whitespace() {
        let cfg = RuleEngineConfig::default();
        // not real key material: synthetic detector fixture value only
        let body = "MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEAq7BFUpkGp3";
        let content = [
            "-----BEGIN PRIVATE",
            " KEY-----\n",
            body,
            "\u{3000}\u{a0}\u{2028}",
            body,
            "\n",
            "-----END PRIVATE",
            " KEY-----\n",
        ]
        .concat();
        let m = scan_content(&content, "notes.md", &cfg);
        assert!(
            m.iter().any(|x| x.rule_id == "secret.gitleaks.private-key"),
            "{m:?}"
        );
    }

    #[test]
    fn gitleaks_candidate_rules_agree_with_per_keyword_search() {
        // Keywords that are substrings of other keywords, mixed case, and
        // multibyte neighbours.
        let every_keyword: String = gitleaks_rules::rules()
            .iter()
            .flat_map(|r| r.keywords.iter())
            .map(|k| format!("{k}\n"))
            .collect();
        for content in [
            "",
            "plain text with nothing in it",
            "日本語のSK と Ey と TEST_ と hooks.slack.com",
            "curl -H 'Authorization: Bearer x' https://api.github.com ghp_ glpat-",
            every_keyword.as_str(),
            every_keyword.to_ascii_uppercase().as_str(),
        ] {
            let candidates: Vec<&str> = gitleaks_candidate_rules(content)
                .iter()
                .map(|r| r.id)
                .collect();
            let lowercase = content.to_ascii_lowercase();
            let expected: Vec<&str> = gitleaks_rules::rules()
                .iter()
                .filter(|rule| {
                    rule.keywords.is_empty()
                        || rule
                            .keywords
                            .iter()
                            .any(|k| lowercase.contains(&k.to_ascii_lowercase()))
                })
                .map(|r| r.id)
                .collect();
            assert_eq!(candidates, expected, "on {content:?}");
        }
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

    fn synthetic_key_block(label: &str) -> String {
        let dashes = "-".repeat(5);
        format!(
            "{dashes}BEGIN {label}{dashes}\n{}\n{dashes}END {label}{dashes}",
            "Q1w2".repeat(12)
        )
    }

    #[test]
    fn private_key_header_rule_covers_all_block_variants() {
        let cfg = RuleEngineConfig::default();
        for label in [
            "PRIVATE KEY",
            "RSA PRIVATE KEY",
            "EC PRIVATE KEY",
            "DSA PRIVATE KEY",
            "ENCRYPTED PRIVATE KEY",
            "OPENSSH PRIVATE KEY",
            "PGP PRIVATE KEY BLOCK",
        ] {
            let header = synthetic_key_block(label);
            let header = header.lines().next().unwrap();
            let m = scan_content(header, "x.txt", &cfg);
            assert!(
                m.iter().any(|x| x.rule_id == "secret.private_key_block"),
                "{label}"
            );
        }
        let public = synthetic_key_block("PUBLIC KEY");
        assert!(
            !scan_content(&public, "x.txt", &cfg)
                .iter()
                .any(|x| x.rule_id == "secret.private_key_block")
        );
    }

    #[test]
    fn private_key_block_ranges_cover_header_through_footer() {
        let first = synthetic_key_block("RSA PRIVATE KEY");
        let second = synthetic_key_block("PGP PRIVATE KEY BLOCK");
        let content = format!("intro\n{first}\nmiddle\n{second}\noutro\n");
        let ranges = private_key_block_ranges(&content);
        assert_eq!(ranges.len(), 2);
        assert_eq!(&content[ranges[0].clone()], first);
        assert_eq!(&content[ranges[1].clone()], second);
        assert!(private_key_block_ranges("no keys here\n").is_empty());
    }

    /// Header line plus `body_lines` base64 lines, without a footer.
    fn unterminated_key_block(label: &str, body_lines: usize) -> String {
        let block = synthetic_key_block(label);
        let header = block.lines().next().unwrap();
        let mut out = header.to_string();
        for seed in ["Q1w2", "E3r4", "T5y6"].iter().take(body_lines) {
            out.push('\n');
            out.push_str(&seed.repeat(12));
        }
        out
    }

    #[test]
    fn unterminated_private_key_block_range_covers_only_the_armor_body() {
        let block = unterminated_key_block("OPENSSH PRIVATE KEY", 3);
        // No footer and nothing after the body: the block runs to the end.
        let content = format!("intro\n{block}");
        assert_eq!(private_key_block_ranges(&content), vec![6..content.len()]);
        // Text that is not armor body ends the block.
        let content = format!("intro\n{block}\n\ntrailing words\nmore text\n");
        assert_eq!(private_key_block_ranges(&content), vec![6..6 + block.len()]);
        // CRLF line endings and indentation do not end the body early.
        let crlf = block.replace('\n', "\r\n  ");
        let content = format!("intro\r\n{crlf}\r\ntrailing words\r\n");
        assert_eq!(private_key_block_ranges(&content), vec![7..7 + crlf.len()]);
    }

    #[test]
    fn unterminated_private_key_block_range_keeps_armor_headers_and_blank_lines() {
        let block = unterminated_key_block("RSA PRIVATE KEY", 2);
        let (header, body) = block.split_once('\n').unwrap();
        let armored = format!(
            "{header}\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,00FF\nComment: test\n\n{body}"
        );
        let content = format!("{armored}\n\nNote: not an armor header\n{body}\n");
        assert_eq!(private_key_block_ranges(&content), vec![0..armored.len()]);
    }

    #[test]
    fn private_key_header_quoted_in_source_code_covers_only_its_line() {
        let header = unterminated_key_block("RSA PRIVATE KEY", 0);
        let first_line = format!("const HEADER: &str = \"{header}\";");
        let content = format!("{first_line}\nfn main() {{\n    run();\n}}\n");
        let start = content.find(&header).unwrap();
        assert_eq!(
            private_key_block_ranges(&content),
            vec![start..first_line.len()]
        );
        // A bare header line followed by ordinary code covers the header only.
        let content = format!("{header}\nlet x = compute(1, 2);\n");
        assert_eq!(private_key_block_ranges(&content), vec![0..header.len()]);
    }

    /// The header and two body lines of an unterminated block.
    fn unterminated_key_block_lines() -> (String, String, String) {
        let block = unterminated_key_block("RSA PRIVATE KEY", 2);
        let mut lines = block.lines().map(str::to_string);
        (
            lines.next().unwrap(),
            lines.next().unwrap(),
            lines.next().unwrap(),
        )
    }

    /// Asserts that the single block range in `content` starts at the header
    /// and ends right after the last occurrence of `last_body`.
    fn assert_block_covers_decorated_body(content: &str, header: &str, last_body: &str) {
        let start = content.find(header).unwrap();
        let end = content.rfind(last_body).unwrap() + last_body.len();
        let ranges = private_key_block_ranges(content);
        assert_eq!(ranges.len(), 1, "{ranges:?}");
        assert_eq!(ranges[0].start, start);
        assert!(
            ranges[0].end >= end,
            "body left uncovered: {:?} in {content:?}",
            ranges[0]
        );
        let next_line = content[end..]
            .find('\n')
            .map_or(content.len(), |at| end + at);
        assert!(
            ranges[0].end <= next_line,
            "range runs past the body: {:?} in {content:?}",
            ranges[0]
        );
    }

    #[test]
    fn unterminated_private_key_block_in_a_shell_continuation_is_covered() {
        let (header, first, second) = unterminated_key_block_lines();
        let content =
            format!("KEY = {header} \\\n\t{first} \\\n\t{second}\n\nall: build\n\techo done\n");
        assert_block_covers_decorated_body(&content, &header, &second);
    }

    #[test]
    fn unterminated_private_key_block_in_string_concatenation_is_covered() {
        let (header, first, second) = unterminated_key_block_lines();
        // Trailing `+` with escaped line breaks inside the literals.
        let content = format!(
            "const key = \"{header}\\n\" +\n    \"{first}\\n\" +\n    \"{second}\";\nconsole.log(key.length);\n"
        );
        assert_block_covers_decorated_body(&content, &header, &second);
        // Leading `+`, single quotes.
        let content =
            format!("key = '{header}'\n    + '{first}'\n    + '{second}';\nprint(len(key))\n");
        assert_block_covers_decorated_body(&content, &header, &second);
    }

    #[test]
    fn unterminated_private_key_block_in_a_quoted_list_is_covered() {
        let (header, first, second) = unterminated_key_block_lines();
        let content = format!(
            "lines = [\n  \"{header}\",\n  \"{first}\",\n  \"{second}\",\n]\nprint(lines)\n"
        );
        assert_block_covers_decorated_body(&content, &header, &second);
    }

    #[test]
    fn unterminated_private_key_block_behind_quote_markers_is_covered() {
        let (header, first, second) = unterminated_key_block_lines();
        let content = format!("> {header}\n> {first}\n>\n> {second}\n\nThanks for the report.\n");
        assert_block_covers_decorated_body(&content, &header, &second);
    }

    #[test]
    fn decorated_lines_that_are_not_armor_body_end_the_block() {
        let (header, first, _) = unterminated_key_block_lines();
        // Short quoted strings and ordinary statements are not key material.
        for tail in [
            "    \"short\",\n    \"values\",\n",
            "    + offset;\n",
            "> thanks, will check\n",
            "    call(a, b) \\\n",
        ] {
            let content = format!("x = \"{header}\" +\n{tail}");
            let start = content.find(&header).unwrap();
            let first_line = content.find('\n').unwrap();
            assert_eq!(
                private_key_block_ranges(&content),
                vec![start..first_line],
                "{content:?}"
            );
            let content = format!("x = \"{header}\" +\n    \"{first}\" +\n{tail}");
            let end = content.find(&first).unwrap() + first.len();
            let ranges = private_key_block_ranges(&content);
            assert_eq!(ranges.len(), 1);
            assert!(
                ranges[0].end >= end && ranges[0].end <= end + 3,
                "{:?} in {content:?}",
                ranges[0]
            );
        }
    }

    #[test]
    fn private_key_header_inside_a_sentence_covers_only_its_line() {
        let header = unterminated_key_block("PRIVATE KEY", 0);
        let first_line = format!("A key file starts with {header} on its first line.");
        let content = format!("{first_line}\nThe rest of this paragraph is prose.\n");
        let start = content.find(&header).unwrap();
        assert_eq!(
            private_key_block_ranges(&content),
            vec![start..first_line.len()]
        );
    }

    #[test]
    fn quoted_private_key_header_does_not_reach_a_later_key_block() {
        let header = unterminated_key_block("RSA PRIVATE KEY", 0);
        let block = synthetic_key_block("RSA PRIVATE KEY");
        let content = format!("grep {header} *.pem\nsome output\n{block}\ndone\n");
        let ranges = private_key_block_ranges(&content);
        assert_eq!(ranges.len(), 2);
        assert_eq!(&content[ranges[0].clone()], format!("{header} *.pem"));
        assert_eq!(&content[ranges[1].clone()], block);
    }
}
