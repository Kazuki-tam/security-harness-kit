//! Inline comments and policy allowlists (spec §5.3).

use crate::finding::Finding;
use crate::policy::AllowlistEntry;
use anyhow::{Context, Result};
use globset::{Glob, GlobMatcher};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};

type HmacSha256 = Hmac<Sha256>;

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `HMAC-SHA256(raw_value, rule_id)` as `sha256-hmac:<hex>` (spec §5.3).
pub fn compute_value_hmac(rule_id: &str, raw_value: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(rule_id.as_bytes()).expect("HMAC accepts key lengths");
    mac.update(raw_value.as_bytes());
    let digest = mac.finalize().into_bytes();
    format!("sha256-hmac:{}", hex_lower(&digest))
}

fn parse_expire_date(exp: &str) -> Option<chrono::NaiveDate> {
    chrono::NaiveDate::parse_from_str(exp.trim(), "%Y-%m-%d").ok()
}

fn is_expired(exp: &str) -> bool {
    parse_expire_date(exp)
        .map(|d| d < chrono::Utc::now().date_naive())
        .unwrap_or(false)
}

#[derive(Clone, Debug, Default)]
pub struct InlineSuppressions {
    pub line_all_rules: HashSet<usize>,
    pub line_rules: HashMap<usize, HashSet<String>>,
}

impl InlineSuppressions {
    pub fn is_suppressed(&self, line: usize, rule_id: &str) -> bool {
        if self.line_all_rules.contains(&line) {
            return true;
        }
        self.line_rules
            .get(&line)
            .map(|rs| rs.iter().any(|r| r == rule_id))
            .unwrap_or(false)
    }

    fn suppress_line(&mut self, line: usize, rest_after_kw: &str) {
        match first_rule_token(rest_after_kw) {
            Some(id) => {
                self.line_rules.entry(line).or_default().insert(id);
            }
            None => {
                self.line_all_rules.insert(line);
            }
        }
    }
}

fn strip_ignore_keyword<'a>(inner: &'a str, keyword: &str) -> Option<&'a str> {
    let rest = inner.strip_prefix(keyword)?;
    if rest
        .chars()
        .next()
        .map(|c| c.is_whitespace())
        .unwrap_or(true)
    {
        Some(rest.trim_start())
    } else {
        None
    }
}

fn rest_after_ignore_keywords(inner: &str) -> Option<&str> {
    let inner = inner.trim_start();
    if let Some(rest) = strip_ignore_keyword(inner, "shk-ignore-next-line") {
        Some(rest)
    } else if let Some(rest) = strip_ignore_keyword(inner, "shk-ignore") {
        Some(rest)
    } else {
        None
    }
}

fn html_comment_inner(text: &str) -> Option<&str> {
    text.strip_prefix("<!--")
        .and_then(|rest| rest.trim_end().strip_suffix("-->"))
        .map(str::trim_start)
}

fn parse_standalone_ignore_line(trimmed_full_line: &str) -> Option<&str> {
    let tl = trimmed_full_line.trim();
    let inner = if let Some(rest) = tl.strip_prefix('#') {
        rest.trim_start()
    } else if let Some(rest) = tl.strip_prefix("//") {
        rest.trim_start()
    } else if let Some(rest) = html_comment_inner(tl) {
        rest
    } else {
        return None;
    };
    rest_after_ignore_keywords(inner)
}

fn first_rule_token(rest_after_kw: &str) -> Option<String> {
    let t = rest_after_kw.split_whitespace().next()?.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

fn trailing_hash_ignore(trimmed_end: &str) -> Option<&str> {
    let (body, cmt) = trimmed_end.rsplit_once('#')?;
    if body.trim().is_empty() {
        return None;
    }
    rest_after_ignore_keywords(cmt.trim())
}

fn trailing_slash_ignore(trimmed_end: &str) -> Option<&str> {
    let idx = trimmed_end.rfind("//")?;
    let body = &trimmed_end[..idx];
    if body.trim().is_empty() {
        return None;
    }
    rest_after_ignore_keywords(trimmed_end[idx + 2..].trim_start())
}

fn trailing_html_ignore(trimmed_end: &str) -> Option<&str> {
    let idx = trimmed_end.rfind("<!--")?;
    let body = &trimmed_end[..idx];
    if body.trim().is_empty() {
        return None;
    }
    rest_after_ignore_keywords(html_comment_inner(&trimmed_end[idx..])?)
}

/// Parse `#`, `//`, and HTML standalone/trailing `shk-ignore` comments.
pub fn parse_inline_suppressions(content: &str) -> InlineSuppressions {
    let mut out = InlineSuppressions::default();

    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed_end = raw_line.trim_end();

        if let Some(rest_kw) = parse_standalone_ignore_line(trimmed_end) {
            out.suppress_line(line_no.saturating_add(1), rest_kw);
            continue;
        }

        if let Some(rest_kw) = trailing_hash_ignore(trimmed_end) {
            out.suppress_line(line_no, rest_kw);
            continue;
        }

        if let Some(rest_kw) = trailing_slash_ignore(trimmed_end) {
            out.suppress_line(line_no, rest_kw);
            continue;
        }

        if let Some(rest_kw) = trailing_html_ignore(trimmed_end) {
            out.suppress_line(line_no, rest_kw);
        }
    }

    out
}

#[derive(Debug)]
pub struct CompiledAllowlist {
    pub matcher: GlobMatcher,
    pub rule_filter: Option<String>,
    pub value_hash: Option<String>,
}

impl CompiledAllowlist {
    pub fn from_entry(e: &AllowlistEntry) -> Result<Self> {
        let g = Glob::new(&e.path)
            .with_context(|| format!("invalid allowlist path glob {}", e.path))?;
        Ok(Self {
            matcher: g.compile_matcher(),
            rule_filter: e.rule_id.clone(),
            value_hash: e.value_hash.clone(),
        })
    }
}

pub fn compile_allowlist(entries: &[AllowlistEntry]) -> Result<Vec<CompiledAllowlist>> {
    entries.iter().map(CompiledAllowlist::from_entry).collect()
}

pub fn suppressed_by_allowlist(
    rel_path: &str,
    rule_id: &str,
    matched_text: &str,
    entries: &[AllowlistEntry],
    compiled: &[CompiledAllowlist],
) -> bool {
    for (e, c) in entries.iter().zip(compiled.iter()) {
        if let Some(exp) = &e.expires
            && is_expired(exp)
        {
            continue;
        }
        if !c.matcher.is_match(rel_path) {
            continue;
        }
        if let Some(ref rf) = c.rule_filter
            && rf != rule_id
        {
            continue;
        }
        if let Some(ref expected) = c.value_hash {
            let actual = compute_value_hmac(rule_id, matched_text);
            if expected.trim().eq_ignore_ascii_case(&actual) {
                return true;
            }
            continue;
        }
        return true;
    }
    false
}

pub fn expired_allowlist_warnings(entries: &[AllowlistEntry]) -> Vec<Finding> {
    let mut out = Vec::new();
    for e in entries {
        let Some(exp) = &e.expires else { continue };
        if !is_expired(exp) {
            continue;
        }
        let rid = e.rule_id.as_deref().unwrap_or("(any rule)");
        out.push(Finding {
            rule_id: "policy.allowlist_expired".into(),
            severity: "low".into(),
            kind: "ignore".into(),
            file: "shk.toml".into(),
            line: 1,
            column: 1,
            message: format!(
                "Expired [[allowlist]] entry (rule_id={rid}, path={}, expires={exp}) — remove or update",
                e.path
            ),
            redacted_value: "[REDACTED]".into(),
            confidence: 1.0,
            context_before: vec![],
            context_after: vec![],
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_next_line_all_rules() {
        // not real credential: synthetic detector fixture value only
        let s = "# shk-ignore\nsk-proj-abcdefghijklmnopqrstuvwxyz0123456789\n";
        let ig = parse_inline_suppressions(s);
        assert!(ig.is_suppressed(2, "secret.openai_api_key"));
    }

    #[test]
    fn inline_next_line_rule_id() {
        // not real credential or personal data: synthetic detector fixture value only
        let s = "# shk-ignore-next-line pii.email\nuser@example.com\n";
        let ig = parse_inline_suppressions(s);
        assert!(ig.is_suppressed(2, "pii.email"));
        assert!(!ig.is_suppressed(2, "secret.openai_api_key"));
    }

    #[test]
    fn inline_html_comment_next_line_rule_id() {
        let s = "<!-- shk-ignore-next-line pii.email -->\nuser@example.com\n";
        let ig = parse_inline_suppressions(s);
        assert!(ig.is_suppressed(2, "pii.email"));
        assert!(!ig.is_suppressed(2, "secret.openai_api_key"));
    }

    #[test]
    fn inline_html_comment_same_line_all_rules() {
        let s = "placeholder <!-- shk-ignore -->\n";
        let ig = parse_inline_suppressions(s);
        assert!(ig.is_suppressed(1, "secret.openai_api_key"));
    }

    #[test]
    fn inline_ignore_keyword_requires_boundary() {
        let s =
            "# shk-ignorement pii.email\nuser@example.com\nplaceholder <!-- shk-ignorement -->\n";
        let ig = parse_inline_suppressions(s);
        assert!(!ig.is_suppressed(2, "pii.email"));
        assert!(!ig.is_suppressed(3, "secret.openai_api_key"));
    }
}
