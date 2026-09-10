use super::kind::{Kind, ParseKindError};
use super::{INFER_MATCH_THRESHOLD, INFER_SAMPLE_ROWS};
use shk_rules::{RuleEngineConfig, scan_content};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ColumnSource {
    Config,
    Cli,
    Inferred,
    /// Text mode: the kind came from a detection rule, not a column.
    Rule,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ResolvedColumn {
    pub index: usize,
    pub name: String,
    pub kind: Kind,
    pub source: ColumnSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_rate: Option<f64>,
}

#[derive(Debug, Clone, Default)]
pub struct ColumnOverrides {
    pub entries: Vec<(String, Kind)>,
}

pub fn parse_columns_spec(spec: &str) -> Result<ColumnOverrides, ParseKindError> {
    let mut entries = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for raw in spec.split(',') {
        let item = raw.trim();
        if item.is_empty() {
            continue;
        }
        let Some((name, kind_raw)) = item.split_once(':') else {
            return Err(ParseKindError(format!(
                "invalid --columns entry `{item}` (expected Name:kind)"
            )));
        };
        let name = name.trim();
        if name.is_empty() {
            return Err(ParseKindError(format!(
                "invalid --columns entry `{item}` (empty column name)"
            )));
        }
        let key = normalize_header_key(name);
        if !seen.insert(key) {
            return Err(ParseKindError(format!(
                "duplicate --columns entry after case folding: `{name}`"
            )));
        }
        entries.push((name.to_string(), Kind::parse(kind_raw.trim())?));
    }
    if entries.is_empty() {
        return Err(ParseKindError(
            "--columns did not contain any Name:kind entries".into(),
        ));
    }
    Ok(ColumnOverrides { entries })
}

/// A first row that holds any PII is data; anything else is the header.
/// Misreading data as a header would print the raw value in the column plan
/// and record it in the metadata sidecar.
pub fn infer_header(first_row: &[String]) -> bool {
    if first_row.is_empty() {
        return true;
    }
    let pii_hits = first_row
        .iter()
        .filter(|cell| classify_cell(cell).is_some())
        .count();
    pii_hits == 0
}

pub fn resolve_columns(
    headers: &[String],
    sample_rows: &[Vec<String>],
    config: &BTreeMap<String, String>,
    cli: Option<&ColumnOverrides>,
) -> Result<Vec<ResolvedColumn>, String> {
    let mut explicit: BTreeMap<String, (Kind, ColumnSource)> = BTreeMap::new();
    for (name, kind_raw) in config {
        let kind = Kind::parse(kind_raw).map_err(|err| err.0)?;
        let key = normalize_header_key(name);
        if explicit.insert(key, (kind, ColumnSource::Config)).is_some() {
            return Err(format!(
                "duplicate [pseudonymize.columns] entry after case folding: `{name}`"
            ));
        }
    }
    if let Some(cli) = cli {
        for (name, kind) in &cli.entries {
            explicit.insert(
                normalize_header_key(name),
                (kind.clone(), ColumnSource::Cli),
            );
        }
    }

    let mut resolved = Vec::new();
    let mut matched_explicit = std::collections::BTreeSet::new();
    for (index, header) in headers.iter().enumerate() {
        let key = normalize_header_key(header);
        if let Some((kind, source)) = explicit.get(&key) {
            matched_explicit.insert(key);
            resolved.push(ResolvedColumn {
                index,
                name: header.clone(),
                kind: kind.clone(),
                source: *source,
                match_rate: None,
            });
            continue;
        }
        if let Some((kind, rate)) = infer_column(header, index, sample_rows) {
            resolved.push(ResolvedColumn {
                index,
                name: header.clone(),
                kind,
                source: ColumnSource::Inferred,
                match_rate: Some(rate),
            });
        }
    }
    // Config columns are project-wide and may not apply to every file, but a
    // CLI entry that matches nothing is almost certainly a typo.
    let unmatched: Vec<&str> = cli
        .map(|cli| {
            cli.entries
                .iter()
                .map(|(name, _)| name.as_str())
                .filter(|name| !matched_explicit.contains(&normalize_header_key(name)))
                .collect()
        })
        .unwrap_or_default();
    if !unmatched.is_empty() {
        return Err(format!(
            "--columns entries did not match any header: {}",
            unmatched.join(", ")
        ));
    }
    Ok(resolved)
}

fn infer_column(header: &str, index: usize, sample_rows: &[Vec<String>]) -> Option<(Kind, f64)> {
    let header_guess = header_kind(header);
    let sample = sample_rows.iter().take(INFER_SAMPLE_ROWS);
    let mut scored = 0usize;
    let mut email_hits = 0usize;
    let mut phone_hits = 0usize;
    for row in sample {
        let Some(cell) = row.get(index) else {
            continue;
        };
        if cell_is_missing(cell) {
            continue;
        }
        scored += 1;
        match classify_cell(cell) {
            Some(Kind::Email) => email_hits += 1,
            Some(Kind::Phone) => phone_hits += 1,
            _ => {}
        }
    }
    let sample_guess = if scored == 0 {
        None
    } else {
        let email_rate = email_hits as f64 / scored as f64;
        let phone_rate = phone_hits as f64 / scored as f64;
        if email_rate >= INFER_MATCH_THRESHOLD && email_rate >= phone_rate {
            Some((Kind::Email, email_rate))
        } else if phone_rate >= INFER_MATCH_THRESHOLD {
            Some((Kind::Phone, phone_rate))
        } else {
            None
        }
    };
    match (header_guess, sample_guess) {
        (_, Some(sample)) => Some(sample),
        (Some(kind), None) => Some((kind, 0.0)),
        (None, None) => None,
    }
}

fn cell_is_missing(cell: &str) -> bool {
    super::normalize::is_missing_raw(cell)
}

fn classify_cell(value: &str) -> Option<Kind> {
    let matches = scan_content(value, "column.csv", &pii_config());
    let mut email = false;
    let mut phone = false;
    for item in matches {
        if item.rule_id == "pii.email" {
            email = true;
        }
        if item.rule_id == "pii.ja.phone" || item.rule_id == "pii.en.phone" {
            phone = true;
        }
    }
    match (email, phone) {
        (true, false) => Some(Kind::Email),
        (false, true) => Some(Kind::Phone),
        _ => None,
    }
}

fn pii_config() -> RuleEngineConfig {
    RuleEngineConfig {
        secrets: false,
        env: false,
        ai_context: false,
        ..RuleEngineConfig::default()
    }
}

fn header_kind(header: &str) -> Option<Kind> {
    let folded = normalize_header_key(header);
    const EMAIL: &[&str] = &[
        "email",
        "e-mail",
        "e_mail",
        "mail",
        "mailaddress",
        "emailaddress",
        "email_address",
        "メール",
        "メールアドレス",
        "メアド",
    ];
    const PHONE: &[&str] = &[
        "phone",
        "tel",
        "telephone",
        "mobile",
        "cellphone",
        "cell",
        "phonenumber",
        "phone_number",
        "tel_no",
        "電話",
        "電話番号",
        "携帯",
        "携帯電話",
        "携帯番号",
    ];
    if EMAIL.contains(&folded.as_str()) {
        return Some(Kind::Email);
    }
    if PHONE.contains(&folded.as_str()) {
        return Some(Kind::Phone);
    }
    None
}

fn normalize_header_key(name: &str) -> String {
    name.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_columns_supports_spaces_and_custom() {
        let parsed = parse_columns_spec("Email:email, Member ID:custom:member_id,0:phone").unwrap();
        assert_eq!(parsed.entries.len(), 3);
        assert_eq!(parsed.entries[0].0, "Email");
        assert_eq!(parsed.entries[1].1, Kind::Custom("member_id".into()));
        assert_eq!(parsed.entries[2].0, "0");
    }

    #[test]
    fn parse_columns_reports_malformed_entries() {
        assert!(parse_columns_spec("Email").is_err());
        assert!(parse_columns_spec(":email").is_err());
        assert!(parse_columns_spec("").is_err());
        assert!(parse_columns_spec(" , ").is_err());
        assert!(parse_columns_spec("Email:bogus").is_err());
        assert!(parse_columns_spec("Email:email,email:phone").is_err());
        assert_eq!(parse_columns_spec("Email:email,").unwrap().entries.len(), 1);
        assert!(infer_header(&[]));
        assert!(!infer_header(&[["ada", "@", "example.com"].concat()]));
        assert!(!infer_header(&[
            "row-1".into(),
            ["ada", "@", "example.com"].concat(),
            "ordinary".into(),
            "values".into(),
        ]));
        assert!(!infer_header(&[
            "Email".into(),
            ["ada", "@", "example.com"].concat()
        ]));
    }

    #[test]
    fn explicit_columns_win_over_inference() {
        let headers = vec!["contact".into(), "phone".into()];
        let rows = vec![vec![
            ["ada", "@", "example.com"].concat(),
            ["090", "-", "1234", "-", "5678"].concat(),
        ]];
        let mut config = BTreeMap::new();
        config.insert("contact".into(), "custom:member_id".into());
        let resolved = resolve_columns(&headers, &rows, &config, None).unwrap();
        assert_eq!(resolved[0].kind, Kind::Custom("member_id".into()));
        assert_eq!(resolved[0].source, ColumnSource::Config);
        assert_eq!(resolved[1].kind, Kind::Phone);
        assert_eq!(resolved[1].source, ColumnSource::Inferred);
    }

    #[test]
    fn unmatched_cli_columns_are_rejected_but_config_columns_are_not() {
        let headers = vec!["Email".into()];
        let rows: Vec<Vec<String>> = Vec::new();
        let cli = parse_columns_spec("Emial:email").unwrap();
        let err = resolve_columns(&headers, &rows, &BTreeMap::new(), Some(&cli)).unwrap_err();
        assert!(err.contains("Emial"), "{err}");
        let mut config = BTreeMap::new();
        config.insert("Phone".into(), "phone".into());
        let resolved = resolve_columns(&headers, &rows, &config, None).unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].source, ColumnSource::Inferred);

        let mut duplicate_config = BTreeMap::new();
        duplicate_config.insert("Email".into(), "email".into());
        duplicate_config.insert("email".into(), "phone".into());
        assert!(
            resolve_columns(&headers, &rows, &duplicate_config, None)
                .unwrap_err()
                .contains("duplicate")
        );
    }

    #[test]
    fn header_dictionary_detects_japanese_labels() {
        assert_eq!(header_kind("メール"), Some(Kind::Email));
        assert_eq!(header_kind("電話番号"), Some(Kind::Phone));
        assert_eq!(header_kind("氏名"), None);
    }
}
