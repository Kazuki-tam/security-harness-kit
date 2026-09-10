use super::kind::Kind;
use unicode_normalization::UnicodeNormalization;

const MISSING: &[&str] = &["", "NULL", "null", "N/A", "#N/A", "-", "—"];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NormalizeSettings {
    pub email_strip_subaddress: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormalizeOutcome {
    Missing,
    Unparsed,
    Value(String),
}

pub fn normalize_value(kind: &Kind, raw: &str, settings: NormalizeSettings) -> NormalizeOutcome {
    let common = normalize_common(raw);
    if is_missing(&common) {
        return NormalizeOutcome::Missing;
    }
    match kind {
        Kind::Email => normalize_email(&common, settings.email_strip_subaddress),
        Kind::Phone => normalize_phone(&common),
        Kind::Name | Kind::Custom(_) => NormalizeOutcome::Value(common),
    }
}

pub fn is_missing(value: &str) -> bool {
    MISSING.contains(&value)
}

fn normalize_common(input: &str) -> String {
    let nfkc: String = input.nfkc().collect();
    collapse_whitespace(&nfkc).trim().to_string()
}

fn collapse_whitespace(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut prev_space = false;
    for ch in input.chars() {
        if ch.is_whitespace() {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else {
            prev_space = false;
            out.push(ch);
        }
    }
    out
}

fn normalize_email(value: &str, strip_subaddress: bool) -> NormalizeOutcome {
    let lowered = value.to_ascii_lowercase();
    let Some((local, domain)) = lowered.split_once('@') else {
        return NormalizeOutcome::Unparsed;
    };
    if local.is_empty() || !valid_email_domain(domain) {
        return NormalizeOutcome::Unparsed;
    }
    let local = if strip_subaddress {
        local.split_once('+').map(|(head, _)| head).unwrap_or(local)
    } else {
        local
    };
    if local.is_empty() {
        return NormalizeOutcome::Unparsed;
    }
    NormalizeOutcome::Value(format!("{local}@{domain}"))
}

fn valid_email_domain(domain: &str) -> bool {
    let Some((head, tld)) = domain.rsplit_once('.') else {
        return false;
    };
    !head.is_empty()
        && tld.len() >= 2
        && tld.bytes().all(|byte| byte.is_ascii_alphabetic())
        && domain
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
}

fn normalize_phone(value: &str) -> NormalizeOutcome {
    let has_plus = value.starts_with('+');
    let digits: String = value.chars().filter(|ch| ch.is_ascii_digit()).collect();
    if has_plus {
        return normalize_plus_e164(&digits);
    }
    if valid_jp_domestic(&digits) {
        return NormalizeOutcome::Value(format!("+81{}", &digits[1..]));
    }
    NormalizeOutcome::Unparsed
}

fn normalize_plus_e164(digits: &str) -> NormalizeOutcome {
    if let Some(rest) = digits.strip_prefix("81") {
        let domestic = if rest.starts_with('0') {
            rest.to_string()
        } else {
            format!("0{rest}")
        };
        if valid_jp_domestic(&domestic) {
            return NormalizeOutcome::Value(format!("+81{}", &domestic[1..]));
        }
        return NormalizeOutcome::Unparsed;
    }
    if is_generic_e164(digits) {
        return NormalizeOutcome::Value(format!("+{digits}"));
    }
    NormalizeOutcome::Unparsed
}

fn is_generic_e164(digits: &str) -> bool {
    (8..=15).contains(&digits.len())
        && digits.starts_with(|ch: char| ch.is_ascii_digit() && ch != '0')
}

fn valid_jp_domestic(digits: &str) -> bool {
    let n = digits.len();
    if !matches!(n, 10 | 11 | 14) || !digits.starts_with('0') {
        return false;
    }
    if let Some(rest) = digits
        .strip_prefix("0120")
        .or_else(|| digits.strip_prefix("0170"))
        .or_else(|| digits.strip_prefix("0180"))
        .or_else(|| digits.strip_prefix("0570"))
        .or_else(|| digits.strip_prefix("0990"))
    {
        return n == 10 && !all_zero(rest);
    }
    if let Some(rest) = digits.strip_prefix("0800") {
        return n == 11 && !all_zero(rest);
    }
    if let Some(rest) = digits.strip_prefix("0200") {
        return n == 14 && !all_zero(rest);
    }
    if let Some(rest) = digits.strip_prefix("0204") {
        return n == 11 && !all_zero(rest);
    }
    if let Some(rest) = digits.strip_prefix("020") {
        let fourth = rest.as_bytes().first();
        return n == 11 && !matches!(fourth, Some(b'0' | b'4')) && !all_zero(rest);
    }
    !all_zero(&digits[1..])
}

fn all_zero(digits: &str) -> bool {
    !digits.is_empty() && digits.bytes().all(|byte| byte == b'0')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn email(raw: &str) -> NormalizeOutcome {
        normalize_value(&Kind::Email, raw, NormalizeSettings::default())
    }

    fn phone(raw: &str) -> NormalizeOutcome {
        normalize_value(&Kind::Phone, raw, NormalizeSettings::default())
    }

    fn sample_email() -> String {
        ["Foo", "@", "Example.COM"].concat()
    }

    fn sample_email_lower() -> String {
        ["foo", "@", "example.com"].concat()
    }

    fn jp_mobile_hyphen() -> String {
        ["090", "-", "1234", "-", "5678"].concat()
    }

    fn jp_mobile_plain() -> String {
        ["090", "1234", "5678"].concat()
    }

    fn jp_mobile_plus() -> String {
        ["+", "81", "90", "1234", "5678"].concat()
    }

    #[test]
    fn email_case_and_whitespace_collapse() {
        let padded = format!(" {} ", sample_email());
        assert_eq!(
            email(&padded),
            NormalizeOutcome::Value(sample_email_lower())
        );
        assert_eq!(email(&padded), email(&sample_email_lower()));
    }

    #[test]
    fn email_keeps_subaddress_by_default() {
        let tagged = ["foo+tag", "@", "example.com"].concat();
        assert_eq!(email(&tagged), NormalizeOutcome::Value(tagged.clone()));
        let stripped = normalize_value(
            &Kind::Email,
            &tagged,
            NormalizeSettings {
                email_strip_subaddress: true,
            },
        );
        assert_eq!(stripped, NormalizeOutcome::Value(sample_email_lower()));
    }

    #[test]
    fn phone_jp_forms_converge() {
        let expected = NormalizeOutcome::Value(["+", "819012345678"].concat());
        assert_eq!(phone(&jp_mobile_hyphen()), expected);
        assert_eq!(phone(&jp_mobile_plain()), expected);
        assert_eq!(phone(&jp_mobile_plus()), expected);
        assert_eq!(
            phone(&["+", "81", "-", "090", "-", "1234", "-", "5678"].concat()),
            expected
        );
    }

    #[test]
    fn phone_rejects_garbage() {
        assert_eq!(phone("12345"), NormalizeOutcome::Unparsed);
        assert_eq!(phone("abcd"), NormalizeOutcome::Unparsed);
    }

    #[test]
    fn missing_values_are_detected_after_trim() {
        assert_eq!(
            normalize_value(
                &Kind::Custom("id".into()),
                " NULL ",
                NormalizeSettings::default()
            ),
            NormalizeOutcome::Missing
        );
        assert_eq!(
            normalize_value(&Kind::Email, "-", NormalizeSettings::default()),
            NormalizeOutcome::Missing
        );
        assert_eq!(
            normalize_value(&Kind::Phone, "—", NormalizeSettings::default()),
            NormalizeOutcome::Missing
        );
    }

    #[test]
    fn custom_uses_common_rules_only() {
        let value = normalize_value(
            &Kind::Custom("member_id".into()),
            "  ＡＢＣ  １２３  ",
            NormalizeSettings::default(),
        );
        assert_eq!(value, NormalizeOutcome::Value("ABC 123".into()));
    }
}
