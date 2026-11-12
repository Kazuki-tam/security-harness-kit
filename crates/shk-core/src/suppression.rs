//! Inline comments and policy allowlists (spec §5.3).

use crate::finding::Finding;
use crate::policy::AllowlistEntry;
use anyhow::{Context, Result};
use globset::{Glob, GlobMatcher};
use hmac::{Hmac, KeyInit, Mac};
use sha2_hmac::Sha256;
use std::collections::{HashMap, HashSet};

type HmacSha256 = Hmac<Sha256>;

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
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

/// An `expires` value that is not a `YYYY-MM-DD` date counts as expired: the
/// entry stops suppressing (fail-safe) rather than never expiring, and the
/// policy still loads.
fn is_expired(exp: &str) -> bool {
    parse_expire_date(exp).is_none_or(|d| d < chrono::Utc::now().date_naive())
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

/// Where an ignore comment points when it trails code on its own line.
#[derive(Clone, Copy, PartialEq, Eq)]
enum IgnoreTarget {
    /// `shk-ignore`: the line carrying the comment.
    SameLine,
    /// `shk-ignore-next-line`: the line after the comment.
    NextLine,
}

struct IgnoreDirective<'a> {
    target: IgnoreTarget,
    /// Text after the keyword (optional rule id).
    rest: &'a str,
}

fn ignore_directive(inner: &str) -> Option<IgnoreDirective<'_>> {
    let inner = inner.trim_start();
    if let Some(rest) = strip_ignore_keyword(inner, "shk-ignore-next-line") {
        Some(IgnoreDirective {
            target: IgnoreTarget::NextLine,
            rest,
        })
    } else {
        strip_ignore_keyword(inner, "shk-ignore").map(|rest| IgnoreDirective {
            target: IgnoreTarget::SameLine,
            rest,
        })
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
    } else {
        html_comment_inner(tl)?
    };
    // A comment on a line of its own has nothing to suppress there, so both
    // keywords point at the next line.
    ignore_directive(inner).map(|directive| directive.rest)
}

fn first_rule_token(rest_after_kw: &str) -> Option<String> {
    let t = rest_after_kw.split_whitespace().next()?.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

fn trailing_hash_ignore(trimmed_end: &str) -> Option<IgnoreDirective<'_>> {
    let (body, cmt) = trimmed_end.rsplit_once('#')?;
    if body.trim().is_empty() {
        return None;
    }
    ignore_directive(cmt.trim())
}

fn trailing_slash_ignore(trimmed_end: &str) -> Option<IgnoreDirective<'_>> {
    let idx = trimmed_end.rfind("//")?;
    let body = &trimmed_end[..idx];
    if body.trim().is_empty() {
        return None;
    }
    ignore_directive(trimmed_end[idx + 2..].trim_start())
}

fn trailing_html_ignore(trimmed_end: &str) -> Option<IgnoreDirective<'_>> {
    let idx = trimmed_end.rfind("<!--")?;
    let body = &trimmed_end[..idx];
    if body.trim().is_empty() {
        return None;
    }
    ignore_directive(html_comment_inner(&trimmed_end[idx..])?)
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

        let trailing = trailing_hash_ignore(trimmed_end)
            .or_else(|| trailing_slash_ignore(trimmed_end))
            .or_else(|| trailing_html_ignore(trimmed_end));
        if let Some(directive) = trailing {
            let target_line = match directive.target {
                IgnoreTarget::SameLine => line_no,
                IgnoreTarget::NextLine => line_no.saturating_add(1),
            };
            out.suppress_line(target_line, directive.rest);
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

/// Low-severity warning findings about `[[allowlist]]` entries that do not
/// do what they say: `policy.allowlist_expired` for an entry past its
/// `expires` date or with an `expires` that is not a date (either way it no
/// longer suppresses), and `policy.allowlist_unknown_key` for each key `shk`
/// does not know, which is ignored. The unknown-key message names the key and
/// the entry's position, never a value.
pub fn expired_allowlist_warnings(entries: &[AllowlistEntry]) -> Vec<Finding> {
    let warning = |rule_id: &str, message: String| Finding {
        rule_id: rule_id.into(),
        severity: "low".into(),
        kind: "ignore".into(),
        file: "shk.toml".into(),
        line: 1,
        column: 1,
        message,
        redacted_value: "[REDACTED]".into(),
        value_hash: None,
        confidence: 1.0,
        context_before: vec![],
        context_after: vec![],
    };
    let mut out = Vec::new();
    for (idx, e) in entries.iter().enumerate() {
        let number = idx + 1;
        for key in e.unknown.keys() {
            out.push(warning(
                "policy.allowlist_unknown_key",
                format!(
                    "[[allowlist]] entry {number} has an unknown key `{key}`, which is ignored — fix a misspelled `rule_id`, `value_hash`, `path`, `reason` or `expires`, or remove the key"
                ),
            ));
        }
        let Some(exp) = &e.expires else { continue };
        if !is_expired(exp) {
            continue;
        }
        let rid = e.rule_id.as_deref().unwrap_or("(any rule)");
        let message = if parse_expire_date(exp).is_some() {
            format!(
                "Expired [[allowlist]] entry (rule_id={rid}, path={}, expires={exp}) — remove or update",
                e.path
            )
        } else {
            format!(
                "[[allowlist]] entry {number} (rule_id={rid}, path={}) has an `expires` value that could not be parsed as a YYYY-MM-DD date; the entry is treated as expired and no longer suppresses — fix the date or remove the entry",
                e.path
            )
        };
        out.push(warning("policy.allowlist_expired", message));
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

    #[test]
    fn compute_value_hmac_is_stable_and_rule_scoped() {
        let h1 = compute_value_hmac("pii.email", "user@example.com");
        assert!(h1.starts_with("sha256-hmac:"));
        assert_eq!(h1, compute_value_hmac("pii.email", "user@example.com"));
        assert_ne!(h1, compute_value_hmac("pii.email", "other@example.com"));
        assert_ne!(h1, compute_value_hmac("pii.phone", "user@example.com"));
    }

    #[test]
    fn allowlist_suppresses_by_path_and_rule() {
        use crate::policy::AllowlistEntry;

        let entries = vec![AllowlistEntry {
            rule_id: Some("secret.generic_api_key".into()),
            path: "fixtures/**".into(),
            value_hash: None,
            reason: None,
            expires: None,
            unknown: Default::default(),
        }];
        let compiled = compile_allowlist(&entries).unwrap();
        assert!(suppressed_by_allowlist(
            "fixtures/demo.txt",
            "secret.generic_api_key",
            "any",
            &entries,
            &compiled,
        ));
        assert!(!suppressed_by_allowlist(
            "src/demo.txt",
            "secret.generic_api_key",
            "any",
            &entries,
            &compiled,
        ));
        assert!(!suppressed_by_allowlist(
            "fixtures/demo.txt",
            "pii.email",
            "any",
            &entries,
            &compiled,
        ));
    }

    #[test]
    fn allowlist_value_hash_must_match() {
        use crate::policy::AllowlistEntry;

        let rule = "pii.email";
        let value = "user@example.com";
        let hash = compute_value_hmac(rule, value);
        let entries = vec![AllowlistEntry {
            rule_id: Some(rule.into()),
            path: "**".into(),
            value_hash: Some(hash),
            reason: None,
            expires: None,
            unknown: Default::default(),
        }];
        let compiled = compile_allowlist(&entries).unwrap();
        assert!(suppressed_by_allowlist(
            "a.txt", rule, value, &entries, &compiled
        ));
        assert!(!suppressed_by_allowlist(
            "a.txt",
            rule,
            "wrong@example.com",
            &entries,
            &compiled
        ));
    }

    #[test]
    fn expired_allowlist_entries_are_ignored_and_warn() {
        use crate::policy::AllowlistEntry;

        let entries = vec![AllowlistEntry {
            rule_id: Some("pii.email".into()),
            path: "**".into(),
            value_hash: None,
            reason: None,
            expires: Some("2000-01-01".into()),
            unknown: Default::default(),
        }];
        let compiled = compile_allowlist(&entries).unwrap();
        assert!(!suppressed_by_allowlist(
            "a.txt",
            "pii.email",
            "user@example.com",
            &entries,
            &compiled,
        ));
        let warnings = expired_allowlist_warnings(&entries);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].rule_id, "policy.allowlist_expired");
    }

    #[test]
    fn unparseable_expires_is_treated_as_expired_and_warns() {
        use crate::policy::AllowlistEntry;

        for bad in ["2026/12/31", "next year", "2026-13-01", ""] {
            let entries = vec![AllowlistEntry {
                rule_id: Some("pii.email".into()),
                path: "**".into(),
                value_hash: None,
                reason: None,
                expires: Some(bad.into()),
                unknown: Default::default(),
            }];
            let compiled = compile_allowlist(&entries).unwrap();
            assert!(
                !suppressed_by_allowlist("a.txt", "pii.email", "value", &entries, &compiled),
                "{bad}"
            );
            let warnings = expired_allowlist_warnings(&entries);
            assert_eq!(warnings.len(), 1, "{bad}");
            assert_eq!(warnings[0].rule_id, "policy.allowlist_expired");
            assert_eq!(warnings[0].severity, "low");
            let message = &warnings[0].message;
            assert!(message.contains("could not be parsed"), "{message}");
            assert!(message.contains("entry 1"), "{message}");
            assert!(bad.is_empty() || !message.contains(bad), "{message}");
        }
    }

    #[test]
    fn unknown_allowlist_keys_warn_by_name_without_values() {
        use crate::policy::AllowlistEntry;

        let entry = |unknown: &[(&str, &str)]| AllowlistEntry {
            rule_id: Some("pii.email".into()),
            path: "docs/**".into(),
            value_hash: None,
            reason: None,
            expires: None,
            unknown: unknown
                .iter()
                .map(|(key, value)| (key.to_string(), toml::Value::String(value.to_string())))
                .collect(),
        };
        let entries = vec![
            entry(&[]),
            entry(&[("owner", "platform-team"), ("ticket", "SEC-1234")]),
        ];
        // The entry still suppresses: only the unknown keys are ignored.
        let compiled = compile_allowlist(&entries).unwrap();
        assert!(suppressed_by_allowlist(
            "docs/a.md",
            "pii.email",
            "value",
            &entries[1..],
            &compiled[1..],
        ));
        let warnings = expired_allowlist_warnings(&entries);
        assert_eq!(warnings.len(), 2);
        for (warning, key) in warnings.iter().zip(["owner", "ticket"]) {
            assert_eq!(warning.rule_id, "policy.allowlist_unknown_key");
            assert_eq!(warning.severity, "low");
            assert_eq!(warning.file, "shk.toml");
            assert!(warning.message.contains("entry 2"), "{}", warning.message);
            assert!(
                warning.message.contains(&format!("`{key}`")),
                "{}",
                warning.message
            );
            assert!(
                !warning.message.contains("platform-team") && !warning.message.contains("SEC-1234"),
                "{}",
                warning.message
            );
        }
    }

    #[test]
    fn compile_allowlist_rejects_invalid_glob() {
        use crate::policy::AllowlistEntry;

        let entries = vec![AllowlistEntry {
            rule_id: None,
            path: "[invalid".into(),
            value_hash: None,
            reason: None,
            expires: None,
            unknown: Default::default(),
        }];
        assert!(compile_allowlist(&entries).is_err());
    }

    #[test]
    fn inline_trailing_hash_and_slash_ignore() {
        let hash_line = "x = 1 # shk-ignore secret.foo\n";
        let slash_line = "// shk-ignore-next-line pii.email\nnext\n";
        let ig_hash = parse_inline_suppressions(hash_line);
        let ig_slash = parse_inline_suppressions(slash_line);
        assert!(ig_hash.is_suppressed(1, "secret.foo"));
        assert!(ig_slash.is_suppressed(2, "pii.email"));
        assert!(!ig_slash.is_suppressed(1, "pii.email"));
    }

    #[test]
    fn trailing_next_line_comment_suppresses_the_following_line() {
        for src in [
            "x = 1 # shk-ignore-next-line pii.email\nnext\n",
            "x = 1 // shk-ignore-next-line pii.email\nnext\n",
            "x = 1 <!-- shk-ignore-next-line pii.email -->\nnext\n",
        ] {
            let ig = parse_inline_suppressions(src);
            assert!(ig.is_suppressed(2, "pii.email"), "{src}");
            assert!(!ig.is_suppressed(1, "pii.email"), "{src}");
        }
    }

    #[test]
    fn standalone_ignore_comment_still_targets_the_next_line() {
        let ig = parse_inline_suppressions("// shk-ignore pii.email\nnext\n");
        assert!(ig.is_suppressed(2, "pii.email"));
        assert!(!ig.is_suppressed(1, "pii.email"));
    }
}
