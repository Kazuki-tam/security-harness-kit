//! Making strings from advisories, lockfiles and settings safe to print.

use std::fmt::Write as _;

/// Longest advisory summary shown in a message, in characters.
pub const SUMMARY_MAX_CHARS: usize = 80;

/// Replaces every control character with `\u{..}`, so text taken from
/// outside cannot move the cursor, colour the terminal or forge extra lines.
/// Same behaviour as the function of that name in `shk mcp audit`.
pub fn escape_control(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_control() {
            let _ = write!(escaped, "\\u{{{:x}}}", ch as u32);
        } else {
            escaped.push(ch);
        }
    }
    escaped
}

/// An advisory summary for a message: the first [`SUMMARY_MAX_CHARS`]
/// characters, with control characters escaped. `None` when there is nothing
/// to show.
pub fn display_summary(summary: &str) -> Option<String> {
    let cut: String = summary.trim().chars().take(SUMMARY_MAX_CHARS).collect();
    let cut = cut.trim_end();
    (!cut.is_empty()).then(|| escape_control(cut))
}

/// `https://osv.dev/vulnerability/<id>`, with anything in the id that is not
/// plainly part of an advisory id percent-encoded.
pub fn advisory_url(id: &str) -> String {
    let mut url = String::from("https://osv.dev/vulnerability/");
    for byte in id.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.') {
            url.push(byte as char);
        } else {
            let _ = write!(url, "%{byte:02X}");
        }
    }
    url
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_characters_are_escaped() {
        assert_eq!(escape_control("plain é 日本"), "plain é 日本");
        assert_eq!(
            escape_control("a\u{1b}[31mb\r\nc\u{7f}\u{85}"),
            "a\\u{1b}[31mb\\u{d}\\u{a}c\\u{7f}\\u{85}"
        );
    }

    #[test]
    fn summaries_are_cut_by_characters() {
        assert_eq!(display_summary("  short  ").as_deref(), Some("short"));
        assert_eq!(display_summary(" \n "), None);
        assert_eq!(display_summary(""), None);

        let long = "日".repeat(81);
        assert_eq!(display_summary(&long).unwrap(), "日".repeat(80));

        // Cut first, escaped afterwards: an escape is never split.
        let controls = format!("{}\u{1b}\u{1b}", "x".repeat(79));
        assert_eq!(
            display_summary(&controls).unwrap(),
            format!("{}\\u{{1b}}", "x".repeat(79))
        );
        // No trailing blank left by the cut.
        let spaced = format!("{} tail", "x".repeat(79));
        assert_eq!(display_summary(&spaced).unwrap(), "x".repeat(79));
    }

    #[test]
    fn advisory_urls_encode_unexpected_characters() {
        assert_eq!(
            advisory_url("RUSTSEC-2020-0071"),
            "https://osv.dev/vulnerability/RUSTSEC-2020-0071"
        );
        assert_eq!(
            advisory_url("a/b?c é"),
            "https://osv.dev/vulnerability/a%2Fb%3Fc%20%C3%A9"
        );
    }
}
