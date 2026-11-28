//! The `[deps]` settings of `shk.toml`.
//!
//! `shk-core` keeps `[deps]` and `[thresholds].deps_fail_on` as raw TOML so
//! that a mistake in them cannot stop a scan or an AI hook. They are
//! interpreted here, for the `deps` commands only: a mistake that cannot be
//! worked around is an error, anything else becomes a warning finding.

use crate::model::Rule;
use anyhow::{Result, bail};
use chrono::NaiveDate;
use shk_core::policy::{Policy, Severity};
use std::collections::BTreeSet;

pub const DEFAULT_STALE_AFTER_HOURS: u64 = 24;

const IGNORE_KEYS: [&str; 4] = ["id", "reason", "package", "expires"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepsConfig {
    /// `[thresholds].deps_fail_on`, else `default_fail_on`, else `high`.
    pub fail_on: Severity,
    pub stale_after_hours: u64,
    pub ignore: Vec<IgnoreEntry>,
    /// Keys that are not known and are ignored.
    pub unknown_keys: Vec<UnknownKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownKey {
    /// `[deps]` or `[[deps.ignore]] entry <n>`.
    pub table: String,
    pub key: String,
}

/// One `[[deps.ignore]]` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgnoreEntry {
    /// An advisory id or alias.
    pub id: String,
    pub reason: String,
    pub package: Option<String>,
    /// As written; it may not be a date.
    pub expires: Option<String>,
}

impl IgnoreEntry {
    /// `Some(date)` when `expires` is a `YYYY-MM-DD` date.
    fn expiry_date(&self) -> Option<NaiveDate> {
        let expires = self.expires.as_deref()?;
        NaiveDate::parse_from_str(expires.trim(), "%Y-%m-%d").ok()
    }

    /// Whether the entry no longer suppresses: its `expires` date has passed
    /// (the entry still applies on the day itself) or cannot be read.
    pub fn is_expired(&self, today: NaiveDate) -> bool {
        self.expires.is_some() && self.expiry_date().is_none_or(|date| date < today)
    }

    fn names(&self, package: &str, advisory_id: &str, aliases: &[String]) -> bool {
        let id_matches = self.id.eq_ignore_ascii_case(advisory_id)
            || aliases
                .iter()
                .any(|alias| self.id.eq_ignore_ascii_case(alias));
        id_matches && self.package.as_deref().is_none_or(|name| name == package)
    }
}

impl Default for DepsConfig {
    fn default() -> Self {
        Self {
            fail_on: Severity::High,
            stale_after_hours: DEFAULT_STALE_AFTER_HOURS,
            ignore: Vec::new(),
            unknown_keys: Vec::new(),
        }
    }
}

impl DepsConfig {
    /// Interprets the raw `[deps]` settings of a loaded policy.
    pub fn from_policy(policy: &Policy) -> Result<Self> {
        let mut config = Self {
            fail_on: fail_on(policy)?,
            ..Self::default()
        };
        let Some(deps) = &policy.deps else {
            return Ok(config);
        };
        let Some(deps) = deps.as_table() else {
            bail!("`deps` in shk.toml must be a table");
        };
        for (key, value) in deps {
            match key.as_str() {
                "stale_after_hours" => {
                    config.stale_after_hours = value
                        .as_integer()
                        .and_then(|hours| u64::try_from(hours).ok())
                        .filter(|hours| *hours >= 1)
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "[deps].stale_after_hours in shk.toml must be an integer of 1 or more"
                            )
                        })?;
                }
                "ignore" => config.read_ignore(value)?,
                _ => config.unknown_keys.push(UnknownKey {
                    table: "[deps]".into(),
                    key: key.clone(),
                }),
            }
        }
        Ok(config)
    }

    fn read_ignore(&mut self, value: &toml::Value) -> Result<()> {
        let entries = value
            .as_array()
            .filter(|entries| entries.iter().all(toml::Value::is_table))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "`deps.ignore` in shk.toml must be an array of tables ([[deps.ignore]])"
                )
            })?;
        for (index, entry) in entries.iter().enumerate() {
            let number = index + 1;
            let table = entry.as_table().expect("checked above");
            let required = |key: &str| -> Result<String> {
                match table.get(key).and_then(toml::Value::as_str) {
                    Some(text) if !text.trim().is_empty() => Ok(text.to_string()),
                    _ => bail!(
                        "[[deps.ignore]] entry {number} in shk.toml needs a non-empty string `{key}`"
                    ),
                }
            };
            let optional = |key: &str| -> Result<Option<String>> {
                match table.get(key) {
                    None => Ok(None),
                    Some(toml::Value::String(text)) => Ok(Some(text.clone())),
                    Some(_) => {
                        bail!(
                            "`{key}` of [[deps.ignore]] entry {number} in shk.toml must be a string"
                        )
                    }
                }
            };
            self.ignore.push(IgnoreEntry {
                id: required("id")?.trim().to_string(),
                reason: required("reason")?,
                package: optional("package")?,
                expires: optional("expires")?,
            });
            for key in table.keys() {
                if !IGNORE_KEYS.contains(&key.as_str()) {
                    self.unknown_keys.push(UnknownKey {
                        table: format!("[[deps.ignore]] entry {number}"),
                        key: key.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    /// The ignore entries as they stand on `today`.
    pub fn ignores(&self, today: NaiveDate) -> Ignores<'_> {
        Ignores {
            entries: &self.ignore,
            expired: self
                .ignore
                .iter()
                .map(|entry| entry.is_expired(today))
                .collect(),
            ineffective: BTreeSet::new(),
        }
    }
}

fn fail_on(policy: &Policy) -> Result<Severity> {
    match &policy.thresholds.deps_fail_on {
        // Like the other thresholds, an unreadable `default_fail_on` means
        // `high`.
        None => Ok(Severity::parse(&policy.thresholds.default_fail_on).unwrap_or(Severity::High)),
        Some(value) => value.as_str().and_then(Severity::parse).ok_or_else(|| {
            anyhow::anyhow!(
                "[thresholds].deps_fail_on in shk.toml must be one of: {}",
                Severity::VALID_VALUES
            )
        }),
    }
}

/// Applies `[[deps.ignore]]` to the findings of one audit.
#[derive(Debug)]
pub struct Ignores<'a> {
    entries: &'a [IgnoreEntry],
    expired: Vec<bool>,
    /// Entries without `expires` that named a malicious-package finding.
    ineffective: BTreeSet<usize>,
}

impl<'a> Ignores<'a> {
    /// Whether an entry in force suppresses this advisory finding. An entry
    /// names it by the representative id or by any alias, and by package when
    /// it has one. A malicious-package finding is suppressed only by an
    /// entry with an `expires` date: upstream withdraws false reports, so no
    /// exception to them may be permanent.
    pub fn suppresses(
        &mut self,
        rule: Rule,
        package: &str,
        advisory_id: &str,
        aliases: &[String],
    ) -> bool {
        let mut suppressed = false;
        for (index, entry) in self.entries.iter().enumerate() {
            if self.expired[index] || !entry.names(package, advisory_id, aliases) {
                continue;
            }
            if rule == Rule::Malicious && entry.expires.is_none() {
                self.ineffective.insert(index);
            } else {
                suppressed = true;
            }
        }
        suppressed
    }

    /// Entries past their `expires` date or with one that is not a date.
    pub fn expired(&self) -> impl Iterator<Item = &'a IgnoreEntry> + '_ {
        self.entries
            .iter()
            .zip(&self.expired)
            .filter_map(|(entry, expired)| expired.then_some(entry))
    }

    /// Entries that named a malicious-package finding and did not suppress
    /// it for want of an `expires` date.
    pub fn ineffective(&self) -> impl Iterator<Item = &'a IgnoreEntry> + '_ {
        self.ineffective.iter().map(|index| &self.entries[*index])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(toml_text: &str) -> Policy {
        toml::from_str(toml_text).unwrap()
    }

    fn config(toml_text: &str) -> DepsConfig {
        DepsConfig::from_policy(&policy(toml_text)).unwrap()
    }

    fn error(toml_text: &str) -> String {
        DepsConfig::from_policy(&policy(toml_text))
            .unwrap_err()
            .to_string()
    }

    fn day(text: &str) -> NaiveDate {
        NaiveDate::parse_from_str(text, "%Y-%m-%d").unwrap()
    }

    #[test]
    fn defaults_apply_without_settings() {
        assert_eq!(config(""), DepsConfig::default());
        assert_eq!(config("[deps]\n"), DepsConfig::default());
        assert_eq!(DepsConfig::default().stale_after_hours, 24);
        assert_eq!(DepsConfig::default().fail_on, Severity::High);
    }

    #[test]
    fn threshold_falls_back_to_the_default_threshold() {
        assert_eq!(
            config("[thresholds]\ndeps_fail_on = \"medium\"\ndefault_fail_on = \"low\"\n").fail_on,
            Severity::Medium
        );
        assert_eq!(
            config("[thresholds]\ndefault_fail_on = \"low\"\n").fail_on,
            Severity::Low
        );
        // `scan_fail_on` is not consulted.
        assert_eq!(
            config("[thresholds]\nscan_fail_on = \"critical\"\n").fail_on,
            Severity::High
        );
        assert_eq!(
            config("[thresholds]\ndefault_fail_on = \"loud\"\n").fail_on,
            Severity::High
        );
        assert_eq!(
            config("[thresholds]\ndeps_fail_on = \"CRITICAL\"\n").fail_on,
            Severity::Critical
        );
    }

    #[test]
    fn a_bad_threshold_is_an_error() {
        for text in [
            "[thresholds]\ndeps_fail_on = 5\n",
            "[thresholds]\ndeps_fail_on = \"loud\"\n",
            "[thresholds]\ndeps_fail_on = \"\"\n",
            "[thresholds]\ndeps_fail_on = [\"high\"]\n",
        ] {
            assert_eq!(
                error(text),
                "[thresholds].deps_fail_on in shk.toml must be one of: info, low, medium, high, critical",
                "{text}"
            );
        }
    }

    #[test]
    fn wrong_shapes_are_errors() {
        assert_eq!(error("deps = 1\n"), "`deps` in shk.toml must be a table");
        assert_eq!(
            error("deps = [{ ignore = [] }]\n"),
            "`deps` in shk.toml must be a table"
        );
        for text in [
            "[deps]\nignore = 1\n",
            "[deps]\nignore = [1]\n",
            "[deps.ignore]\nid = \"A\"\nreason = \"r\"\n",
        ] {
            assert_eq!(
                error(text),
                "`deps.ignore` in shk.toml must be an array of tables ([[deps.ignore]])",
                "{text}"
            );
        }
    }

    #[test]
    fn stale_after_hours_must_be_a_positive_integer() {
        assert_eq!(
            config("[deps]\nstale_after_hours = 1\n").stale_after_hours,
            1
        );
        assert_eq!(
            config("[deps]\nstale_after_hours = 720\n").stale_after_hours,
            720
        );
        for value in ["0", "-1", "1.5", "\"24\"", "true"] {
            assert_eq!(
                error(&format!("[deps]\nstale_after_hours = {value}\n")),
                "[deps].stale_after_hours in shk.toml must be an integer of 1 or more",
                "{value}"
            );
        }
    }

    #[test]
    fn ignore_entries_need_id_and_reason() {
        let read = config(
            "[[deps.ignore]]\nid = \" RUSTSEC-9999-0001 \"\nreason = \"why\"\n\n[[deps.ignore]]\nid = \"CVE-9999-0001\"\nreason = \"why\"\npackage = \"fx-simple\"\nexpires = \"2027-05-31\"\n",
        );
        assert_eq!(
            read.ignore,
            [
                IgnoreEntry {
                    id: "RUSTSEC-9999-0001".into(),
                    reason: "why".into(),
                    package: None,
                    expires: None,
                },
                IgnoreEntry {
                    id: "CVE-9999-0001".into(),
                    reason: "why".into(),
                    package: Some("fx-simple".into()),
                    expires: Some("2027-05-31".into()),
                },
            ]
        );
        assert!(read.unknown_keys.is_empty());

        for (entry, key) in [
            ("reason = \"r\"", "id"),
            ("id = \"\"\nreason = \"r\"", "id"),
            ("id = \"  \"\nreason = \"r\"", "id"),
            ("id = 7\nreason = \"r\"", "id"),
            ("id = \"A\"", "reason"),
            ("id = \"A\"\nreason = \"\"", "reason"),
            ("id = \"A\"\nreason = [\"r\"]", "reason"),
        ] {
            assert_eq!(
                error(&format!(
                    "[[deps.ignore]]\nid = \"OK\"\nreason = \"r\"\n\n[[deps.ignore]]\n{entry}\n"
                )),
                format!("[[deps.ignore]] entry 2 in shk.toml needs a non-empty string `{key}`"),
                "{entry}"
            );
        }
        for (entry, key) in [
            ("package = 1", "package"),
            ("expires = 2027-05-31", "expires"),
            ("expires = 20270531", "expires"),
        ] {
            assert_eq!(
                error(&format!(
                    "[[deps.ignore]]\nid = \"A\"\nreason = \"r\"\n{entry}\n"
                )),
                format!("`{key}` of [[deps.ignore]] entry 1 in shk.toml must be a string"),
                "{entry}"
            );
        }
    }

    #[test]
    fn unknown_keys_are_collected_not_refused() {
        let read = config(
            "[deps]\nstale_after_hours = 48\nfuture = { a = 1 }\n\n[[deps.ignore]]\nid = \"A\"\nreason = \"r\"\n\n[[deps.ignore]]\nid = \"B\"\nreason = \"r\"\nowner = \"team\"\nticket = 12\n",
        );
        assert_eq!(read.stale_after_hours, 48);
        assert_eq!(read.ignore.len(), 2);
        let unknown: Vec<(&str, &str)> = read
            .unknown_keys
            .iter()
            .map(|unknown| (unknown.table.as_str(), unknown.key.as_str()))
            .collect();
        assert_eq!(
            unknown,
            [
                ("[deps]", "future"),
                ("[[deps.ignore]] entry 2", "owner"),
                ("[[deps.ignore]] entry 2", "ticket"),
            ]
        );
    }

    fn entry(id: &str, package: Option<&str>, expires: Option<&str>) -> IgnoreEntry {
        IgnoreEntry {
            id: id.into(),
            reason: "r".into(),
            package: package.map(String::from),
            expires: expires.map(String::from),
        }
    }

    fn with_entries(entries: Vec<IgnoreEntry>) -> DepsConfig {
        DepsConfig {
            ignore: entries,
            ..DepsConfig::default()
        }
    }

    #[test]
    fn entries_expire_the_day_after_their_date() {
        let dated = entry("A", None, Some("2026-11-28"));
        assert!(!dated.is_expired(day("2026-11-27")));
        assert!(!dated.is_expired(day("2026-11-28")));
        assert!(dated.is_expired(day("2026-11-29")));
        assert!(!entry("A", None, None).is_expired(day("2099-01-01")));
        assert!(!entry("A", None, Some(" 2026-11-28 ")).is_expired(day("2026-11-28")));
        for unreadable in [
            "",
            "soon",
            "2026-13-01",
            "28/11/2026",
            "2026-11-28T00:00:00Z",
        ] {
            assert!(
                entry("A", None, Some(unreadable)).is_expired(day("2000-01-01")),
                "{unreadable}"
            );
        }
    }

    #[test]
    fn entries_match_by_id_alias_and_package() {
        let config = with_entries(vec![
            entry("RUSTSEC-9999-0001", None, None),
            entry("cve-9999-0002", None, None),
            entry("GHSA-fx03-0003-cccc", Some("fx-multi-a"), None),
        ]);
        let today = day("2026-11-28");
        let aliases = vec!["CVE-9999-0002".to_string(), "GHSA-x".to_string()];
        let suppresses = |package: &str, id: &str, aliases: &[String]| {
            config
                .ignores(today)
                .suppresses(Rule::Vulnerable, package, id, aliases)
        };
        // Representative id.
        assert!(suppresses("fx-simple", "RUSTSEC-9999-0001", &[]));
        // Alias, in any letter case.
        assert!(suppresses("fx-merge", "RUSTSEC-9999-0002", &aliases));
        assert!(!suppresses("fx-merge", "RUSTSEC-9999-0002", &[]));
        // Package restriction.
        assert!(suppresses("fx-multi-a", "GHSA-fx03-0003-cccc", &[]));
        assert!(!suppresses("fx-multi-b", "GHSA-fx03-0003-cccc", &[]));
        assert!(!suppresses("FX-MULTI-A", "GHSA-fx03-0003-cccc", &[]));
        // No partial ids.
        assert!(!suppresses("fx-simple", "RUSTSEC-9999-00011", &[]));
    }

    #[test]
    fn expired_entries_do_not_suppress() {
        let config = with_entries(vec![
            entry("A", None, Some("2026-11-27")),
            entry("B", None, Some("never")),
            entry("C", None, Some("2026-11-28")),
            entry("D", None, None),
        ]);
        let mut ignores = config.ignores(day("2026-11-28"));
        assert!(!ignores.suppresses(Rule::Vulnerable, "p", "A", &[]));
        assert!(!ignores.suppresses(Rule::Unsound, "p", "B", &[]));
        assert!(ignores.suppresses(Rule::Unmaintained, "p", "C", &[]));
        assert!(ignores.suppresses(Rule::Notice, "p", "D", &[]));
        let expired: Vec<&str> = ignores.expired().map(|entry| entry.id.as_str()).collect();
        assert_eq!(expired, ["A", "B"]);
        assert_eq!(ignores.ineffective().count(), 0);
    }

    #[test]
    fn malicious_findings_need_an_entry_with_an_expiry() {
        let config = with_entries(vec![
            entry("MAL-9999-0001", None, None),
            entry("MAL-9999-0002", None, Some("2027-01-01")),
            entry("MAL-9999-0003", None, None),
            entry("MAL-9999-0003", Some("fx-malware"), Some("2027-01-01")),
            entry("MAL-9999-0004", None, Some("2026-01-01")),
        ]);
        let mut ignores = config.ignores(day("2026-11-28"));
        // No expiry: not suppressed, and reported once however often it hits.
        assert!(!ignores.suppresses(Rule::Malicious, "a", "MAL-9999-0001", &[]));
        assert!(!ignores.suppresses(Rule::Malicious, "b", "MAL-9999-0001", &[]));
        // The same entry still suppresses other rules.
        assert!(ignores.suppresses(Rule::Vulnerable, "a", "MAL-9999-0001", &[]));
        // With an expiry in the future.
        assert!(ignores.suppresses(Rule::Malicious, "a", "MAL-9999-0002", &[]));
        // A dated entry suppresses even when an undated one names the same id.
        assert!(ignores.suppresses(Rule::Malicious, "fx-malware", "MAL-9999-0003", &[]));
        // Expired.
        assert!(!ignores.suppresses(Rule::Malicious, "a", "MAL-9999-0004", &[]));

        let ineffective: Vec<&str> = ignores
            .ineffective()
            .map(|entry| entry.id.as_str())
            .collect();
        assert_eq!(ineffective, ["MAL-9999-0001", "MAL-9999-0003"]);
    }
}
