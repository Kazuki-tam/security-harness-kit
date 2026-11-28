//! Types shared by the advisory index, the matcher and the reports.

use serde::{Deserialize, Serialize};
use shk_core::finding::Finding;
use shk_core::policy::Severity;
use std::collections::BTreeMap;

/// Version of the on-disk index format. An index with another value is
/// treated as missing.
pub const INDEX_SCHEMA_VERSION: u32 = 1;
/// Data source id of the OSV crates.io dump.
pub const SOURCE_OSV_CRATES_IO: &str = "osv:crates.io";
/// OSV ecosystem name for crates.io packages.
pub const ECOSYSTEM_CRATES_IO: &str = "crates.io";

/// A finding of `shk deps audit`: a regular [`Finding`] plus, for findings
/// tied to an advisory, what the advisory says about the dependency.
#[derive(Debug, Clone, Serialize)]
pub struct DepsFinding {
    #[serde(flatten)]
    pub finding: Finding,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dependency: Option<DependencyInfo>,
    /// What makes this finding the same alert from one run to the next: the
    /// file and what the finding is about, without line or version, so that
    /// an alert survives the lockfile shifting and closes once it is fixed.
    /// SARIF output hashes it into the result's fingerprint.
    #[serde(skip)]
    pub alert_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DependencyInfo {
    /// OSV ecosystem name (`crates.io`).
    pub ecosystem: String,
    pub package: String,
    pub version: String,
    /// Representative advisory id.
    pub advisory_id: String,
    pub aliases: Vec<String>,
    /// `fixed` versions above the installed one, ascending.
    pub fixed: Vec<String>,
    /// `https://osv.dev/vulnerability/<advisory_id>`.
    pub url: String,
}

/// Rules for findings tied to an advisory, in priority order: when the
/// records of one advisory group classify differently, the first one wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rule {
    Malicious,
    Vulnerable,
    Unsound,
    Unmaintained,
    Notice,
}

impl Rule {
    pub fn id(self) -> &'static str {
        match self {
            Self::Malicious => "deps.malicious",
            Self::Vulnerable => "deps.vulnerable",
            Self::Unsound => "deps.unsound",
            Self::Unmaintained => "deps.unmaintained",
            Self::Notice => "deps.notice",
        }
    }

    pub fn kind(self) -> &'static str {
        match self {
            Self::Malicious => "supply_chain",
            _ => "dependency",
        }
    }

    /// The severity of every finding of this rule, or `None` for
    /// `deps.vulnerable`, whose severity comes from CVSS.
    pub fn fixed_severity(self) -> Option<Severity> {
        match self {
            Self::Malicious => Some(Severity::Critical),
            Self::Vulnerable => None,
            Self::Unsound => Some(Severity::Medium),
            Self::Unmaintained => Some(Severity::Low),
            Self::Notice => Some(Severity::Info),
        }
    }
}

/// The local advisory index: per package, the fields of each advisory that
/// matching and display need.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Index {
    pub schema_version: u32,
    pub source: String,
    pub packages: BTreeMap<String, Vec<IndexEntry>>,
}

/// One advisory as it applies to one package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexEntry {
    pub id: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub severity: Vec<SeverityVector>,
    /// RustSec `informational` value (`unsound`, `unmaintained`, `notice`).
    #[serde(default)]
    pub informational: Option<String>,
    #[serde(default)]
    pub categories: Vec<String>,
    /// Exact affected versions.
    #[serde(default)]
    pub versions: Vec<String>,
    #[serde(default)]
    pub ranges: Vec<Range>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeverityVector {
    /// OSV severity type (`CVSS_V3`, `CVSS_V4`).
    #[serde(rename = "type")]
    pub kind: String,
    /// The vector string.
    pub score: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Range {
    /// OSV range type. Only `SEMVER` and `ECOSYSTEM` ranges are indexed.
    #[serde(rename = "type")]
    pub kind: String,
    pub events: Vec<Event>,
}

/// One OSV range event, serialized as `{"introduced": "1.0.0"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    Introduced(String),
    Fixed(String),
    LastAffected(String),
}

impl Event {
    pub fn value(&self) -> &str {
        match self {
            Self::Introduced(v) | Self::Fixed(v) | Self::LastAffected(v) => v,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_are_ordered_by_priority() {
        let mut rules = [
            Rule::Notice,
            Rule::Vulnerable,
            Rule::Unmaintained,
            Rule::Malicious,
            Rule::Unsound,
        ];
        rules.sort();
        let ids: Vec<&str> = rules.iter().map(|rule| rule.id()).collect();
        assert_eq!(
            ids,
            [
                "deps.malicious",
                "deps.vulnerable",
                "deps.unsound",
                "deps.unmaintained",
                "deps.notice"
            ]
        );
        let kinds: Vec<&str> = rules.iter().map(|rule| rule.kind()).collect();
        assert_eq!(
            kinds,
            [
                "supply_chain",
                "dependency",
                "dependency",
                "dependency",
                "dependency"
            ]
        );
        let severities: Vec<Option<Severity>> =
            rules.iter().map(|rule| rule.fixed_severity()).collect();
        assert_eq!(
            severities,
            [
                Some(Severity::Critical),
                None,
                Some(Severity::Medium),
                Some(Severity::Low),
                Some(Severity::Info)
            ]
        );
    }

    #[test]
    fn index_entry_uses_the_documented_json_shape() {
        let entry = IndexEntry {
            id: "RUSTSEC-9999-0001".into(),
            aliases: vec!["CVE-9999-0001".into()],
            summary: Some("Out-of-bounds read".into()),
            severity: vec![SeverityVector {
                kind: "CVSS_V3".into(),
                score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".into(),
            }],
            informational: None,
            categories: vec!["memory-corruption".into()],
            versions: vec![],
            ranges: vec![Range {
                kind: "SEMVER".into(),
                events: vec![
                    Event::Introduced("0.0.0-0".into()),
                    Event::Fixed("1.2.0".into()),
                    Event::LastAffected("1.1.9".into()),
                ],
            }],
        };
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "id": "RUSTSEC-9999-0001",
                "aliases": ["CVE-9999-0001"],
                "summary": "Out-of-bounds read",
                "severity": [{
                    "type": "CVSS_V3",
                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                }],
                "informational": null,
                "categories": ["memory-corruption"],
                "versions": [],
                "ranges": [{
                    "type": "SEMVER",
                    "events": [
                        { "introduced": "0.0.0-0" },
                        { "fixed": "1.2.0" },
                        { "last_affected": "1.1.9" }
                    ]
                }]
            })
        );
        assert_eq!(
            serde_json::from_value::<IndexEntry>(json).unwrap(),
            entry.clone()
        );
        assert_eq!(entry.ranges[0].events[2].value(), "1.1.9");
    }

    #[test]
    fn deps_finding_flattens_the_finding_and_omits_a_missing_dependency() {
        let finding = Finding {
            rule_id: "deps.data_stale".into(),
            severity: "low".into(),
            kind: "dependency".into(),
            file: "shk.toml".into(),
            line: 1,
            column: 1,
            message: "stale".into(),
            redacted_value: "[REDACTED]".into(),
            value_hash: None,
            confidence: 1.0,
            context_before: vec![],
            context_after: vec![],
        };
        let plain = serde_json::to_value(DepsFinding {
            finding: finding.clone(),
            dependency: None,
            alert_key: "shk.toml:deps.data_stale".into(),
        })
        .unwrap();
        assert_eq!(plain["rule_id"], "deps.data_stale");
        assert!(plain.get("dependency").is_none());
        assert!(plain.get("finding").is_none());

        let with_dependency = serde_json::to_value(DepsFinding {
            finding,
            dependency: Some(DependencyInfo {
                ecosystem: ECOSYSTEM_CRATES_IO.into(),
                package: "fx-simple".into(),
                version: "1.1.9".into(),
                advisory_id: "RUSTSEC-9999-0001".into(),
                aliases: vec!["CVE-9999-0001".into()],
                fixed: vec!["1.2.0".into()],
                url: "https://osv.dev/vulnerability/RUSTSEC-9999-0001".into(),
            }),
            alert_key: String::new(),
        })
        .unwrap();
        assert_eq!(with_dependency["dependency"]["package"], "fx-simple");
        assert_eq!(with_dependency["dependency"]["fixed"][0], "1.2.0");
    }
}
