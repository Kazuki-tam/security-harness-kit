//! `shk deps audit`: lockfiles in, findings and inventory out.

use crate::cargo_lock::{self, LockedPackage, LockfileRef, PackageSource};
use crate::config::{DepsConfig, Ignores};
use crate::model::{DependencyInfo, DepsFinding, ECOSYSTEM_CRATES_IO, Rule, SOURCE_OSV_CRATES_IO};
use crate::osv::{AdvisoryDb, AdvisoryMatch};
use crate::text::{advisory_url, display_summary, escape_control};
use anyhow::{Result, bail};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use shk_core::finding::Finding;
use shk_core::policy::{Policy, Severity};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;

pub const REPORT_VERSION: u32 = 1;
/// Ecosystem name in the inventory, as users know it. Advisory data uses the
/// OSV name ([`ECOSYSTEM_CRATES_IO`]).
pub const INVENTORY_ECOSYSTEM_CARGO: &str = "cargo";
const POLICY_FILE: &str = "shk.toml";

pub const RULE_SOURCE_UNREADABLE: &str = "deps.source_unreadable";
pub const RULE_DATA_STALE: &str = "deps.data_stale";
pub const RULE_IGNORE_EXPIRED: &str = "policy.deps_ignore_expired";
pub const RULE_IGNORE_INVALID: &str = "policy.deps_ignore_invalid";
pub const RULE_UNKNOWN_KEY: &str = "policy.deps_unknown_key";

/// The JSON report of `shk deps audit`.
#[derive(Debug, Clone, Serialize)]
pub struct DepsAuditReport {
    pub version: u32,
    /// The lockfiles that were audited.
    pub sources: Vec<String>,
    pub findings: Vec<DepsFinding>,
    pub summary: DepsSummary,
    pub inventory: Inventory,
    /// Per data source id.
    pub data: BTreeMap<String, DataStatus>,
    pub exit_threshold: String,
    /// Lockfiles found, including the ones that could not be read.
    #[serde(skip)]
    pub lockfiles_found: usize,
    /// Directories that could not be read while looking for lockfiles.
    #[serde(skip)]
    pub walk_errors: Vec<String>,
}

impl DepsAuditReport {
    /// Whether a finding reaches the exit threshold.
    pub fn should_fail(&self) -> bool {
        let Some(threshold) = Severity::parse(&self.exit_threshold) else {
            return false;
        };
        self.findings.iter().any(|finding| {
            Severity::parse(&finding.finding.severity)
                .is_some_and(|severity| severity.meets_threshold(threshold))
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DepsSummary {
    pub total: usize,
    pub by_severity: BTreeMap<String, usize>,
    /// Findings left out by `[[deps.ignore]]`.
    pub suppressed: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Inventory {
    pub packages: Vec<PackageInventory>,
}

/// What one lockfile lists and how much of it was audited.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PackageInventory {
    pub ecosystem: String,
    pub source_file: String,
    pub total: usize,
    pub audited: usize,
    pub skipped: Skipped,
}

/// Packages that were not audited, by reason.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Skipped {
    pub git: usize,
    pub registry: usize,
    pub local: usize,
}

impl Skipped {
    pub fn total(&self) -> usize {
        self.git + self.registry + self.local
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DataStatus {
    /// When the data was last fetched, RFC 3339 UTC.
    pub checked_at: Option<String>,
    /// `Last-Modified` of the dump, RFC 3339 UTC.
    pub modified_at: Option<String>,
    pub stale: bool,
}

/// What is known about the freshness of the advisory index.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DataState {
    pub checked_at: Option<DateTime<Utc>>,
    pub modified_at: Option<DateTime<Utc>>,
    /// Why the `--update` of this run failed, if it did.
    pub update_error: Option<String>,
}

pub struct AuditRequest<'a> {
    /// Directory to look for lockfiles in.
    pub target: &'a Path,
    /// Directory whose `shk.toml` applies; finding paths are relative to it.
    pub policy_root: &'a Path,
    pub policy: &'a Policy,
    /// Whether `policy` was read from a `shk.toml`.
    pub has_policy_file: bool,
    pub config: &'a DepsConfig,
    /// Exit threshold, after `--fail-on`.
    pub threshold: Severity,
    /// `None` when there is no usable index.
    pub db: Option<&'a AdvisoryDb>,
    pub data: &'a DataState,
    pub now: DateTime<Utc>,
}

/// Audits the lockfiles below `request.target`.
///
/// Fails when the target is not a directory, when `[scan].exclude` holds an
/// invalid pattern, and when a lockfile lists crates.io packages but there is
/// no index to check them against. A lockfile that cannot be read is a
/// finding, not a failure: the others are still audited.
///
/// With no lockfile at all the report is empty: there is nothing the
/// settings or the data could be wrong about.
pub fn audit(request: &AuditRequest<'_>) -> Result<DepsAuditReport> {
    let discovery = cargo_lock::discover(request.target, request.policy_root, request.policy)?;
    let today = request.now.date_naive();
    let mut ignores = request.config.ignores(today);
    let mut findings = Vec::new();
    let mut sources = Vec::new();
    let mut inventory = Inventory::default();
    let mut suppressed = 0;

    for lockfile in &discovery.lockfiles {
        let read = if lockfile.unfollowed_symlink {
            Err("the file is a symbolic link, and [scan].follow_symlinks is off".to_string())
        } else {
            cargo_lock::read(&lockfile.path)
        };
        let packages = match read {
            Ok(packages) => packages,
            Err(reason) => {
                findings.push(plain_finding(
                    RULE_SOURCE_UNREADABLE,
                    Severity::High,
                    "dependency",
                    &lockfile.display,
                    format!("lockfile could not be audited: {reason}"),
                ));
                continue;
            }
        };
        let entry = inventory_of(lockfile, &packages);
        if entry.audited > 0 {
            let Some(db) = request.db else {
                bail!("no advisory data to audit against; run `shk deps update` first");
            };
            suppressed += audit_packages(db, lockfile, &packages, &mut ignores, &mut findings);
        }
        sources.push(lockfile.display.clone());
        inventory.packages.push(entry);
    }

    let found = !discovery.lockfiles.is_empty();
    let data = data_status(request);
    if found {
        // Findings that belong to no package sit on `shk.toml`, or on the
        // first lockfile when there is no `shk.toml`.
        let anchor = if request.has_policy_file {
            POLICY_FILE
        } else {
            sources
                .first()
                .unwrap_or(&discovery.lockfiles[0].display)
                .as_str()
        };
        if let Some(message) = stale_message(request) {
            findings.push(plain_finding(
                RULE_DATA_STALE,
                Severity::Low,
                "dependency",
                anchor,
                message,
            ));
        }
        findings.extend(policy_findings(request.config, &ignores, anchor));
    }
    sort_findings(&mut findings);

    let mut by_severity = BTreeMap::new();
    for finding in &findings {
        *by_severity
            .entry(finding.finding.severity.clone())
            .or_insert(0) += 1;
    }
    Ok(DepsAuditReport {
        version: REPORT_VERSION,
        sources,
        summary: DepsSummary {
            total: findings.len(),
            by_severity,
            suppressed,
        },
        findings,
        inventory,
        data: BTreeMap::from([(SOURCE_OSV_CRATES_IO.to_string(), data)]),
        exit_threshold: request.threshold.as_str().to_string(),
        lockfiles_found: discovery.lockfiles.len(),
        walk_errors: discovery.walk_errors,
    })
}

fn inventory_of(lockfile: &LockfileRef, packages: &[LockedPackage]) -> PackageInventory {
    let mut audited = 0;
    let mut skipped = Skipped::default();
    for package in packages {
        match package.source {
            PackageSource::CratesIo => audited += 1,
            PackageSource::Git => skipped.git += 1,
            PackageSource::OtherRegistry => skipped.registry += 1,
            PackageSource::Local => skipped.local += 1,
        }
    }
    PackageInventory {
        ecosystem: INVENTORY_ECOSYSTEM_CARGO.to_string(),
        source_file: lockfile.display.clone(),
        total: packages.len(),
        audited,
        skipped,
    }
}

/// Adds the findings of one lockfile and returns how many were suppressed.
fn audit_packages(
    db: &AdvisoryDb,
    lockfile: &LockfileRef,
    packages: &[LockedPackage],
    ignores: &mut Ignores<'_>,
    findings: &mut Vec<DepsFinding>,
) -> usize {
    let mut suppressed = 0;
    // A lockfile lists a package version once; a repeated entry must not
    // repeat its findings.
    let mut seen: HashSet<(&str, &str)> = HashSet::new();
    for package in packages {
        if package.source != PackageSource::CratesIo
            || !seen.insert((&package.name, &package.version))
        {
            continue;
        }
        for advisory in db.matches(&package.name, &package.version) {
            if ignores.suppresses(
                advisory.rule,
                &package.name,
                &advisory.advisory_id,
                &advisory.aliases,
            ) {
                suppressed += 1;
            } else {
                findings.push(advisory_finding(lockfile, package, advisory));
            }
        }
    }
    suppressed
}

fn advisory_finding(
    lockfile: &LockfileRef,
    package: &LockedPackage,
    advisory: AdvisoryMatch,
) -> DepsFinding {
    let mut message = format!(
        "{} {}: {}",
        escape_control(&package.name),
        escape_control(&package.version),
        escape_control(&advisory.advisory_id)
    );
    if let Some(summary) = advisory.summary.as_deref().and_then(display_summary) {
        message.push(' ');
        message.push_str(&summary);
    }
    if matches!(advisory.rule, Rule::Vulnerable | Rule::Unsound)
        && let Some(fixed) = &advisory.fixed_label
    {
        message.push_str(&format!(" (fixed: >={})", escape_control(fixed)));
    }
    DepsFinding {
        finding: Finding {
            rule_id: advisory.rule.id().to_string(),
            severity: advisory.severity.as_str().to_string(),
            kind: advisory.rule.kind().to_string(),
            file: lockfile.display.clone(),
            line: package.line,
            column: package.column,
            message,
            redacted_value: "[REDACTED]".into(),
            value_hash: None,
            confidence: 1.0,
            context_before: vec![],
            context_after: vec![],
        },
        alert_key: format!(
            "{}:{ECOSYSTEM_CRATES_IO}:{}:{}",
            lockfile.display, package.name, advisory.advisory_id
        ),
        dependency: Some(DependencyInfo {
            ecosystem: ECOSYSTEM_CRATES_IO.to_string(),
            package: package.name.clone(),
            version: package.version.clone(),
            url: advisory_url(&advisory.advisory_id),
            advisory_id: advisory.advisory_id,
            aliases: advisory.aliases,
            fixed: advisory.fixed,
        }),
    }
}

/// A finding on the first line of a file, not tied to a package.
fn plain_finding(
    rule_id: &str,
    severity: Severity,
    kind: &str,
    file: &str,
    message: String,
) -> DepsFinding {
    DepsFinding {
        finding: Finding {
            rule_id: rule_id.to_string(),
            severity: severity.as_str().to_string(),
            kind: kind.to_string(),
            file: file.to_string(),
            line: 1,
            column: 1,
            message,
            redacted_value: "[REDACTED]".into(),
            value_hash: None,
            confidence: 1.0,
            context_before: vec![],
            context_after: vec![],
        },
        dependency: None,
        alert_key: format!("{file}:{rule_id}"),
    }
}

/// A warning about one `[[deps.ignore]]` entry. Entries are told apart by
/// their id in the alert key.
fn ignore_warning(rule_id: &str, file: &str, entry_id: &str, message: String) -> DepsFinding {
    let mut finding = plain_finding(rule_id, Severity::Low, "ignore", file, message);
    finding.alert_key = format!("{file}:{rule_id}:{entry_id}");
    finding
}

/// The fixed description of a rule, for SARIF rule metadata: the message of
/// a `deps` finding differs per finding and cannot stand in for it.
pub fn short_description(rule_id: &str) -> Option<&'static str> {
    Some(match rule_id {
        "deps.malicious" => "Dependency reported as malicious",
        "deps.vulnerable" => "Dependency with a known vulnerability",
        "deps.unsound" => "Dependency with a soundness advisory",
        "deps.unmaintained" => "Unmaintained dependency",
        "deps.notice" => "Dependency with an informational advisory",
        RULE_SOURCE_UNREADABLE => "Lockfile could not be audited",
        RULE_DATA_STALE => "Advisory data is stale",
        RULE_IGNORE_EXPIRED => "Expired dependency ignore entry",
        RULE_IGNORE_INVALID => "Ineffective dependency ignore entry",
        RULE_UNKNOWN_KEY => "Unknown dependency policy key",
        _ => return None,
    })
}

/// Time since the data was last fetched; `None` without a record. A check
/// time in the future (a clock that moved) counts as just now.
fn since_check(request: &AuditRequest<'_>) -> Option<chrono::Duration> {
    // Without an index, a leftover freshness record describes nothing.
    request.db?;
    let checked_at = request.data.checked_at?;
    Some((request.now - checked_at).max(chrono::Duration::zero()))
}

fn is_stale(request: &AuditRequest<'_>) -> bool {
    // Capped so the duration cannot overflow: this is over eleven thousand
    // years.
    let limit = i64::try_from(request.config.stale_after_hours)
        .unwrap_or(i64::MAX)
        .min(100_000_000);
    request.data.update_error.is_some()
        || since_check(request).is_none_or(|elapsed| elapsed > chrono::Duration::hours(limit))
}

fn data_status(request: &AuditRequest<'_>) -> DataStatus {
    // Without an index or a check time there is no freshness record, and
    // the dump's own date says nothing.
    let recorded = request.db.is_some() && request.data.checked_at.is_some();
    let format = |time: Option<DateTime<Utc>>| {
        time.filter(|_| recorded)
            .map(|time| time.to_rfc3339_opts(SecondsFormat::Secs, true))
    };
    DataStatus {
        checked_at: format(request.data.checked_at),
        modified_at: format(request.data.modified_at),
        stale: is_stale(request),
    }
}

fn stale_message(request: &AuditRequest<'_>) -> Option<String> {
    if !is_stale(request) {
        return None;
    }
    let checked = match since_check(request) {
        Some(elapsed) => format!("was last checked {} hours ago", elapsed.num_hours()),
        None => "has no recorded check time".to_string(),
    };
    let mut message =
        format!("advisory data for {SOURCE_OSV_CRATES_IO} {checked}; run `shk deps update`");
    if let Some(error) = &request.data.update_error {
        message.push_str(&format!(" (update failed: {})", escape_control(error)));
    }
    Some(message)
}

fn policy_findings(config: &DepsConfig, ignores: &Ignores<'_>, file: &str) -> Vec<DepsFinding> {
    let mut findings = Vec::new();
    for unknown in &config.unknown_keys {
        // The key only: a value may be anything, a credential included.
        findings.push(plain_finding(
            RULE_UNKNOWN_KEY,
            Severity::Low,
            "ignore",
            file,
            format!(
                "Unknown key `{}` in {} is ignored",
                escape_control(&unknown.key),
                unknown.table
            ),
        ));
    }
    for entry in ignores.expired() {
        findings.push(ignore_warning(
            RULE_IGNORE_EXPIRED,
            file,
            &entry.id,
            format!(
                "Expired [[deps.ignore]] entry (id={}, expires={}) — remove or update",
                escape_control(&entry.id),
                escape_control(entry.expires.as_deref().unwrap_or_default())
            ),
        ));
    }
    for entry in ignores.ineffective() {
        findings.push(ignore_warning(
            RULE_IGNORE_INVALID,
            file,
            &entry.id,
            format!(
                "[[deps.ignore]] entry for {} has no expires; malicious-package findings are not suppressed",
                escape_control(&entry.id)
            ),
        ));
    }
    findings
}

/// Severity (highest first), file, line, rule id, representative id; the
/// message settles what is left, so the order never depends on the input
/// order.
fn sort_findings(findings: &mut [DepsFinding]) {
    fn advisory_id(finding: &DepsFinding) -> &str {
        finding
            .dependency
            .as_ref()
            .map_or("", |dependency| dependency.advisory_id.as_str())
    }
    findings.sort_by(|a, b| {
        let severity = |finding: &DepsFinding| Severity::parse(&finding.finding.severity);
        severity(b)
            .cmp(&severity(a))
            .then_with(|| a.finding.file.cmp(&b.finding.file))
            .then_with(|| a.finding.line.cmp(&b.finding.line))
            .then_with(|| a.finding.rule_id.cmp(&b.finding.rule_id))
            .then_with(|| advisory_id(a).cmp(advisory_id(b)))
            .then_with(|| a.finding.message.cmp(&b.finding.message))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IgnoreEntry;
    use crate::testutil::{lockfile_text, real_index, synthetic_index, write_file};
    use std::path::PathBuf;

    const NOW: &str = "2026-11-28T12:00:00Z";

    fn time(text: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(text).unwrap().to_utc()
    }

    /// One audit over a temporary project. The data counts as checked an
    /// hour ago unless a test says otherwise.
    struct Case {
        dir: tempfile::TempDir,
        db: Option<AdvisoryDb>,
        config: DepsConfig,
        policy: Policy,
        has_policy_file: bool,
        data: DataState,
        threshold: Severity,
        target: Option<PathBuf>,
    }

    impl Case {
        fn new() -> Self {
            Self {
                dir: tempfile::tempdir().unwrap(),
                db: Some(AdvisoryDb::new(synthetic_index())),
                config: DepsConfig::default(),
                policy: Policy::default(),
                has_policy_file: false,
                data: DataState {
                    checked_at: Some(time("2026-11-28T11:00:00Z")),
                    modified_at: Some(time("2026-11-28T10:30:15Z")),
                    update_error: None,
                },
                threshold: Severity::High,
                target: None,
            }
        }

        fn with_lockfile(case: &str) -> Self {
            Self::new().lockfile("Cargo.lock", case)
        }

        fn lockfile(self, relative: &str, case: &str) -> Self {
            self.file(relative, &lockfile_text(case))
        }

        fn file(self, relative: &str, content: &str) -> Self {
            write_file(self.dir.path(), relative, content.as_bytes());
            self
        }

        fn ignore(mut self, id: &str, package: Option<&str>, expires: Option<&str>) -> Self {
            self.config.ignore.push(IgnoreEntry {
                id: id.into(),
                reason: "test".into(),
                package: package.map(String::from),
                expires: expires.map(String::from),
            });
            self
        }

        fn try_run(&self) -> Result<DepsAuditReport> {
            audit(&AuditRequest {
                target: self.target.as_deref().unwrap_or(self.dir.path()),
                policy_root: self.dir.path(),
                policy: &self.policy,
                has_policy_file: self.has_policy_file,
                config: &self.config,
                threshold: self.threshold,
                db: self.db.as_ref(),
                data: &self.data,
                now: time(NOW),
            })
        }

        fn run(&self) -> DepsAuditReport {
            self.try_run().unwrap()
        }
    }

    fn lines(report: &DepsAuditReport) -> Vec<String> {
        report
            .findings
            .iter()
            .map(|finding| {
                let f = &finding.finding;
                format!(
                    "{} {} {} {}:{}:{} {}",
                    f.severity, f.rule_id, f.kind, f.file, f.line, f.column, f.message
                )
            })
            .collect()
    }

    fn messages(report: &DepsAuditReport, rule_id: &str) -> Vec<String> {
        report
            .findings
            .iter()
            .filter(|finding| finding.finding.rule_id == rule_id)
            .map(|finding| finding.finding.message.clone())
            .collect()
    }

    fn finding_for<'a>(report: &'a DepsAuditReport, package: &str) -> &'a DepsFinding {
        report
            .findings
            .iter()
            .find(|finding| {
                finding
                    .dependency
                    .as_ref()
                    .is_some_and(|dependency| dependency.package == package)
            })
            .unwrap()
    }

    #[test]
    fn synthetic_lockfile_findings_in_order() {
        let report = Case::with_lockfile("affected").run();
        let long = "長い要約のテスト。".repeat(7);
        let expected = [
            "critical deps.malicious supply_chain Cargo.lock:54:8 fx-mal-alias 0.0.1: RUSTSEC-9999-0014 fx-mal-alias was removed for malware".to_string(),
            "critical deps.malicious supply_chain Cargo.lock:59:8 fx-malicious-category 1.0.0: RUSTSEC-9999-0013 fx-malicious-category steals credentials".into(),
            "critical deps.malicious supply_chain Cargo.lock:64:8 fx-malware 0.1.1: MAL-9999-0001 Malicious code in fx-malware (crates.io)".into(),
            "critical deps.vulnerable dependency Cargo.lock:69:8 fx-merge 1.9.9: RUSTSEC-9999-0002 fx-merge accepts forged tokens (fixed: >=2.0.0)".into(),
            "critical deps.vulnerable dependency Cargo.lock:119:8 fx-simple 1.1.9: RUSTSEC-9999-0001 Out-of-bounds read in fx-simple (fixed: >=1.2.0)".into(),
            "high deps.vulnerable dependency Cargo.lock:39:8 fx-bad-semver 0.3.1: GHSA-fx08-0008-dddd fx-bad-semver has an unusual range".into(),
            "high deps.vulnerable dependency Cargo.lock:44:8 fx-last-affected 1.4.2: RUSTSEC-9999-0004 fx-last-affected leaks memory".into(),
            "high deps.vulnerable dependency Cargo.lock:109:8 fx-prerelease 1.0.0-beta.1: RUSTSEC-9999-0007 fx-prerelease pre-release bug (fixed: >=1.0.0-rc.1)".into(),
            "medium deps.vulnerable dependency Cargo.lock:34:8 fx-affected-severity 0.4.9: RUSTSEC-9999-0015 fx-affected-severity overflows a buffer (fixed: >=0.5.0)".into(),
            "medium deps.vulnerable dependency Cargo.lock:89:8 fx-multi-introduced 0.1.9: RUSTSEC-9999-0003 Segfault in fx-multi-introduced (fixed: >=0.3.5)".into(),
            "medium deps.vulnerable dependency Cargo.lock:94:8 fx-multi-introduced 0.3.4: RUSTSEC-9999-0003 Segfault in fx-multi-introduced (fixed: >=0.3.5)".into(),
            "medium deps.vulnerable dependency Cargo.lock:104:8 fx-orphan 0.9.0: CVE-9999-0009 fx-orphan (CVE entry) (fixed: >=1.0.0)".into(),
            "medium deps.unsound dependency Cargo.lock:134:8 fx-unsound 0.8.0: RUSTSEC-9999-0010 fx-unsound exposes an unsound API (fixed: >=0.9.0)".into(),
            // 80 characters of the summary, counted before escaping.
            format!("low deps.vulnerable dependency Cargo.lock:49:8 fx-long-summary 3.9.0: RUSTSEC-9999-0016 \\u{{1b}}[31m警告\\u{{1b}}[0m {long}長い要約の (fixed: >=4.0.0)"),
            "low deps.vulnerable dependency Cargo.lock:74:8 fx-multi-a 2.9.9: GHSA-fx03-0003-cccc Shared parser bug in fx-multi-a and fx-multi-b (fixed: >=3.0.0)".into(),
            "low deps.vulnerable dependency Cargo.lock:79:8 fx-multi-b 1.0.5: GHSA-fx03-0003-cccc Shared parser bug in fx-multi-a and fx-multi-b (fixed: >=1.1.0)".into(),
            "low deps.vulnerable dependency Cargo.lock:84:8 fx-multi-b 2.0.2: GHSA-fx03-0003-cccc Shared parser bug in fx-multi-a and fx-multi-b (fixed: >=2.0.3)".into(),
            "low deps.vulnerable dependency Cargo.lock:114:8 fx-same-version 2.0.5: RUSTSEC-9999-0006 fx-same-version panics on empty input (fixed: >=2.1.0)".into(),
            "low deps.unmaintained dependency Cargo.lock:129:8 fx-unmaintained 0.1.0: RUSTSEC-9999-0011 fx-unmaintained is unmaintained".into(),
            "info deps.notice dependency Cargo.lock:99:8 fx-notice 1.0.0: RUSTSEC-9999-0012 fx-notice was renamed".into(),
            "info deps.vulnerable dependency Cargo.lock:124:8 fx-two-ranges 2.2.0: RUSTSEC-9999-0005 fx-two-ranges mishandles input (fixed: >=2.3.0)".into(),
        ];
        assert_eq!(lines(&report), expected);

        assert_eq!(report.version, 1);
        assert_eq!(report.sources, ["Cargo.lock"]);
        assert_eq!(report.lockfiles_found, 1);
        assert_eq!(report.exit_threshold, "high");
        assert!(report.should_fail());
        assert_eq!(report.summary.total, 21);
        assert_eq!(report.summary.suppressed, 0);
        assert_eq!(
            report.summary.by_severity,
            BTreeMap::from([
                ("critical".to_string(), 5),
                ("high".to_string(), 3),
                ("medium".to_string(), 5),
                ("low".to_string(), 6),
                ("info".to_string(), 2),
            ])
        );
        assert_eq!(
            report.inventory.packages,
            [PackageInventory {
                ecosystem: "cargo".into(),
                source_file: "Cargo.lock".into(),
                total: 23,
                audited: 22,
                skipped: Skipped {
                    git: 0,
                    registry: 0,
                    local: 1
                },
            }]
        );
        for finding in &report.findings {
            assert_eq!(finding.finding.redacted_value, "[REDACTED]");
            assert_eq!(finding.finding.value_hash, None);
            assert_eq!(finding.finding.confidence, 1.0);
            assert!(finding.dependency.is_some());
        }
    }

    #[test]
    fn real_advisories_against_a_lockfile() {
        let mut case = Case::with_lockfile("real");
        case.db = Some(AdvisoryDb::new(real_index()));
        let report = case.run();
        assert_eq!(
            lines(&report),
            [
                "critical deps.malicious supply_chain Cargo.lock:41:8 jfrog_quotes 0.1.0: RUSTSEC-2025-0158 `jfrog_quotes` was removed from crates.io for malicious code",
                "critical deps.malicious supply_chain Cargo.lock:51:8 replit_ruspty 1.0.0: RUSTSEC-2025-0154 `replit_ruspty` was removed from crates.io for malicious code",
                "high deps.vulnerable dependency Cargo.lock:16:8 ckb 0.39.0: RUSTSEC-2021-0109 Process crashes when the cell used as DepGroup is not alive (fixed: >=0.40.0)",
                "high deps.vulnerable dependency Cargo.lock:31:8 hickory-recursor 0.25.0: GHSA-83hf-93m4-rgwq Hickory DNS's Record Cache Accepts AUTHORITY-Section NS from Sibling Zone via Pa (fixed: >=0.26.0)",
                "medium deps.vulnerable dependency Cargo.lock:6:8 cggmp21 0.3.0: RUSTSEC-2024-0393 Ambiguous challenge derivation (fixed: >=0.4.0)",
                "medium deps.vulnerable dependency Cargo.lock:26:8 glib 0.18.5: RUSTSEC-2024-0429 Unsoundness in `Iterator` and `DoubleEndedIterator` impls for `glib::VariantStrI (fixed: >=0.20.0)",
                "medium deps.vulnerable dependency Cargo.lock:56:8 rtvm-interpreter 4.0.0: RUSTSEC-2025-0131 Lack of sufficient checks in public API",
                // 0.2.23 fixes it: the last `fixed` of the range, not the first.
                "medium deps.vulnerable dependency Cargo.lock:61:8 time 0.1.45: RUSTSEC-2020-0071 Potential segfault in the time crate (fixed: >=0.2.23)",
                "medium deps.vulnerable dependency Cargo.lock:66:8 time 0.2.0: GHSA-wcg3-cvx6-7396 Segmentation fault in time (fixed: >=0.2.23)",
                "medium deps.vulnerable dependency Cargo.lock:71:8 time 0.2.22: RUSTSEC-2020-0071 Potential segfault in the time crate (fixed: >=0.2.23)",
                "medium deps.unsound dependency Cargo.lock:81:8 totally-safe 0.1.0: RUSTSEC-2025-0029 totally-safe introduces memory vulnerabilities in safe Rust",
                "medium deps.vulnerable dependency Cargo.lock:86:8 wasm3 0.5.0: GHSA-gq4p-4hxv-5rg9 WASM3 segmentation fault",
                "low deps.unmaintained dependency Cargo.lock:11:8 chrono 0.4.45: RUSTSEC-2026-0543 chrono is unmaintained",
                "low deps.unmaintained dependency Cargo.lock:46:8 proc-macro-error 1.0.4: RUSTSEC-2024-0370 proc-macro-error is unmaintained",
                "info deps.notice dependency Cargo.lock:36:8 inconceivable 0.9.0: RUSTSEC-2022-0058 Library exclusively intended to inject UB into safe Rust.",
            ]
        );
    }

    #[test]
    fn dependency_details_come_from_the_advisory_group() {
        let report = Case::with_lockfile("affected").run();
        assert_eq!(
            finding_for(&report, "fx-merge")
                .dependency
                .as_ref()
                .unwrap(),
            &DependencyInfo {
                ecosystem: "crates.io".into(),
                package: "fx-merge".into(),
                version: "1.9.9".into(),
                advisory_id: "RUSTSEC-9999-0002".into(),
                aliases: vec!["GHSA-fx02-0002-bbbb".into()],
                fixed: vec!["2.0.0".into()],
                url: "https://osv.dev/vulnerability/RUSTSEC-9999-0002".into(),
            }
        );
    }

    #[test]
    fn only_crates_io_packages_are_audited() {
        let report = Case::with_lockfile("sources").run();
        // `fx-malware` (local) and `fx-merge` (git) share a name with an
        // affected crate and are not reported.
        assert_eq!(
            lines(&report),
            [
                "critical deps.vulnerable dependency Cargo.lock:31:8 fx-simple 1.1.9: RUSTSEC-9999-0001 Out-of-bounds read in fx-simple (fixed: >=1.2.0)",
                "medium deps.unsound dependency Cargo.lock:36:8 fx-unsound 0.8.0: RUSTSEC-9999-0010 fx-unsound exposes an unsound API (fixed: >=0.9.0)",
            ]
        );
        let inventory = &report.inventory.packages[0];
        assert_eq!((inventory.total, inventory.audited), (8, 2));
        assert_eq!(
            inventory.skipped,
            Skipped {
                git: 2,
                registry: 1,
                local: 3
            }
        );
        assert_eq!(inventory.skipped.total(), 6);
    }

    #[test]
    fn versions_outside_every_range_are_clean() {
        let report = Case::with_lockfile("unaffected").run();
        assert_eq!(lines(&report), [] as [&str; 0]);
        assert!(!report.should_fail());
        assert_eq!(report.summary, DepsSummary::default());
        assert_eq!(report.inventory.packages[0].audited, 18);
    }

    #[test]
    fn lockfiles_are_audited_independently() {
        let report = Case::new()
            .lockfile("Cargo.lock", "sources")
            .lockfile("a/Cargo.lock", "invalid-toml")
            .lockfile("b/Cargo.lock", "unsupported-version")
            .lockfile("c/Cargo.lock", "v3")
            .lockfile("d/Cargo.lock", "empty")
            .run();
        assert_eq!(report.lockfiles_found, 5);
        assert_eq!(
            report.sources,
            ["Cargo.lock", "c/Cargo.lock", "d/Cargo.lock"]
        );
        let files: Vec<&str> = report
            .inventory
            .packages
            .iter()
            .map(|inventory| inventory.source_file.as_str())
            .collect();
        assert_eq!(files, report.sources);
        assert_eq!(report.inventory.packages[2].total, 0);

        let unreadable: Vec<String> = lines(&report)
            .into_iter()
            .filter(|line| line.contains(RULE_SOURCE_UNREADABLE))
            .collect();
        assert_eq!(unreadable.len(), 2);
        assert!(
            unreadable[0].starts_with(
                "high deps.source_unreadable dependency a/Cargo.lock:1:1 lockfile could not be audited: not a valid lockfile (line 5)"
            ),
            "{unreadable:?}"
        );
        assert_eq!(
            unreadable[1],
            "high deps.source_unreadable dependency b/Cargo.lock:1:1 lockfile could not be audited: unsupported lockfile version 5"
        );
        assert!(report.findings.iter().any(|finding| {
            finding.finding.file == "c/Cargo.lock" && finding.dependency.is_some()
        }));
        assert!(report.should_fail());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_lockfile_is_reported_not_skipped() {
        let mut case = Case::new().lockfile("locks/deps.txt", "affected");
        std::os::unix::fs::symlink(
            case.dir.path().join("locks/deps.txt"),
            case.dir.path().join("Cargo.lock"),
        )
        .unwrap();
        let report = case.run();
        assert_eq!(
            lines(&report),
            [
                "high deps.source_unreadable dependency Cargo.lock:1:1 lockfile could not be audited: the file is a symbolic link, and [scan].follow_symlinks is off"
            ]
        );
        assert!(report.sources.is_empty());

        case.policy.scan.follow_symlinks = true;
        let report = case.run();
        assert_eq!(report.sources, ["Cargo.lock"]);
        assert_eq!(report.summary.total, 21);
    }

    #[test]
    fn a_repeated_package_entry_is_reported_once() {
        let entry = "[[package]]\nname = \"fx-simple\"\nversion = \"1.1.9\"\nsource = \"sparse+https://index.crates.io/\"\n\n";
        let report = Case::new()
            .file("Cargo.lock", &format!("version = 4\n\n{}", entry.repeat(3)))
            .run();
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].finding.line, 4);
        assert_eq!(report.inventory.packages[0].audited, 3);
    }

    #[test]
    fn text_from_the_lockfile_is_escaped_in_messages_only() {
        let lock = "[[package]]\nname = \"fx-simple\"\nversion = \"1.1.9\\u001b[2J\"\nsource = \"sparse+https://index.crates.io/\"\n";
        let mut case = Case::new().file("Cargo.lock", lock);
        // An exact `versions` entry is the only way a version that is not
        // semver can match.
        let mut index = synthetic_index();
        index.packages.get_mut("fx-simple").unwrap()[0]
            .versions
            .push("1.1.9\u{1b}[2J".into());
        case.db = Some(AdvisoryDb::new(index));
        let report = case.run();
        assert_eq!(report.findings.len(), 1);
        assert!(
            report.findings[0]
                .finding
                .message
                .starts_with("fx-simple 1.1.9\\u{1b}[2J: GHSA-fx01-0001-aaaa "),
            "{}",
            report.findings[0].finding.message
        );
        assert_eq!(
            report.findings[0].dependency.as_ref().unwrap().version,
            "1.1.9\u{1b}[2J"
        );
    }

    #[test]
    fn no_lockfile_gives_an_empty_report() {
        let mut case = Case::new().file("src/main.rs", "fn main() {}\n");
        case.has_policy_file = true;
        case.data = DataState::default();
        case.config.unknown_keys.push(crate::config::UnknownKey {
            table: "[deps]".into(),
            key: "future".into(),
        });
        case = case.ignore("A", None, Some("2000-01-01"));
        let report = case.run();
        assert_eq!(report.lockfiles_found, 0);
        assert!(report.findings.is_empty());
        assert!(report.sources.is_empty());
        assert!(report.inventory.packages.is_empty());
        assert!(!report.should_fail());
        assert_eq!(
            report.data["osv:crates.io"],
            DataStatus {
                checked_at: None,
                modified_at: None,
                stale: true
            }
        );

        // Nor is a missing index a problem when nothing needs it.
        case.db = None;
        assert!(case.run().findings.is_empty());
    }

    #[test]
    fn a_missing_index_fails_only_when_packages_need_it() {
        let mut case = Case::with_lockfile("sources");
        case.db = None;
        assert_eq!(
            case.try_run().unwrap_err().to_string(),
            "no advisory data to audit against; run `shk deps update` first"
        );

        // A lockfile without crates.io packages is audited without data. The
        // leftover freshness record is not reported as the data's.
        let mut case = Case::new().file(
            "Cargo.lock",
            "version = 4\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n",
        );
        case.db = None;
        let report = case.run();
        assert_eq!(
            lines(&report),
            [
                "low deps.data_stale dependency Cargo.lock:1:1 advisory data for osv:crates.io has no recorded check time; run `shk deps update`"
            ]
        );
        assert_eq!(
            report.data["osv:crates.io"],
            DataStatus {
                checked_at: None,
                modified_at: None,
                stale: true
            }
        );
    }

    #[test]
    fn target_must_be_a_directory() {
        let mut case = Case::with_lockfile("sources");
        case.target = Some(case.dir.path().join("Cargo.lock"));
        assert!(case.try_run().is_err());
        case.target = Some(case.dir.path().join("missing"));
        assert!(case.try_run().is_err());
    }

    #[test]
    fn a_subdirectory_target_keeps_root_relative_paths() {
        let mut case = Case::new()
            .lockfile("Cargo.lock", "affected")
            .lockfile("sub/Cargo.lock", "sources");
        case.target = Some(case.dir.path().join("sub"));
        let report = case.run();
        assert_eq!(report.sources, ["sub/Cargo.lock"]);
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.finding.file == "sub/Cargo.lock")
        );
    }

    fn stale_messages(case: &Case) -> Vec<String> {
        messages(&case.run(), RULE_DATA_STALE)
    }

    #[test]
    fn data_goes_stale_after_the_configured_hours() {
        let mut case = Case::with_lockfile("unaffected");
        let report = case.run();
        assert_eq!(
            report.data["osv:crates.io"],
            DataStatus {
                checked_at: Some("2026-11-28T11:00:00Z".into()),
                modified_at: Some("2026-11-28T10:30:15Z".into()),
                stale: false
            }
        );

        // Exactly 24 hours is still fresh.
        case.data.checked_at = Some(time("2026-11-27T12:00:00Z"));
        assert!(stale_messages(&case).is_empty());
        case.data.checked_at = Some(time("2026-11-27T11:59:59Z"));
        assert_eq!(
            stale_messages(&case),
            [
                "advisory data for osv:crates.io was last checked 24 hours ago; run `shk deps update`"
            ]
        );
        let report = case.run();
        assert!(report.data["osv:crates.io"].stale);
        assert_eq!(
            lines(&report),
            [
                "low deps.data_stale dependency Cargo.lock:1:1 advisory data for osv:crates.io was last checked 24 hours ago; run `shk deps update`"
            ]
        );
        assert!(report.findings[0].dependency.is_none());

        case.config.stale_after_hours = 1;
        case.data.checked_at = Some(time("2026-11-28T11:00:00Z"));
        assert!(stale_messages(&case).is_empty());
        case.data.checked_at = Some(time("2026-11-28T09:30:00Z"));
        assert_eq!(
            stale_messages(&case),
            ["advisory data for osv:crates.io was last checked 2 hours ago; run `shk deps update`"]
        );

        // A setting too large to be a duration, and a check in the future.
        case.config.stale_after_hours = u64::MAX;
        case.data.checked_at = Some(time("1970-01-01T00:00:00Z"));
        assert!(stale_messages(&case).is_empty());
        case.config.stale_after_hours = 1;
        case.data.checked_at = Some(time("2026-12-25T00:00:00Z"));
        assert!(stale_messages(&case).is_empty());
    }

    #[test]
    fn data_without_a_check_time_or_with_a_failed_update_is_stale() {
        let mut case = Case::with_lockfile("unaffected");
        case.data.checked_at = None;
        assert_eq!(
            stale_messages(&case),
            ["advisory data for osv:crates.io has no recorded check time; run `shk deps update`"]
        );
        let status = &case.run().data["osv:crates.io"];
        assert_eq!(status.checked_at, None);
        assert_eq!(status.modified_at, None);
        assert!(status.stale);

        // A failed update is reported however fresh the data is.
        case.data.checked_at = Some(time("2026-11-28T11:00:00Z"));
        case.data.update_error = Some("HTTP 503\r\nretry\u{1b}[0m".into());
        assert_eq!(
            stale_messages(&case),
            [
                "advisory data for osv:crates.io was last checked 1 hours ago; run `shk deps update` (update failed: HTTP 503\\u{d}\\u{a}retry\\u{1b}[0m)"
            ]
        );
        case.data.checked_at = None;
        assert_eq!(
            stale_messages(&case),
            [
                "advisory data for osv:crates.io has no recorded check time; run `shk deps update` (update failed: HTTP 503\\u{d}\\u{a}retry\\u{1b}[0m)"
            ]
        );
    }

    #[test]
    fn findings_without_a_package_sit_on_the_policy_file_or_first_lockfile() {
        let file_of = |case: &Case| {
            let report = case.run();
            report
                .findings
                .iter()
                .find(|finding| finding.finding.rule_id == RULE_DATA_STALE)
                .map(|finding| {
                    let f = &finding.finding;
                    format!("{}:{}:{}", f.file, f.line, f.column)
                })
                .unwrap()
        };
        let mut case = Case::new()
            .lockfile("a/Cargo.lock", "invalid-toml")
            .lockfile("b/Cargo.lock", "unaffected")
            .lockfile("c/Cargo.lock", "unaffected");
        case.data.checked_at = None;
        // The first lockfile that was audited.
        assert_eq!(file_of(&case), "b/Cargo.lock:1:1");
        case.has_policy_file = true;
        assert_eq!(file_of(&case), "shk.toml:1:1");

        // None audited: the first one found.
        let mut case = Case::new()
            .lockfile("a/Cargo.lock", "invalid-toml")
            .lockfile("b/Cargo.lock", "unsupported-version");
        case.data.checked_at = None;
        assert_eq!(file_of(&case), "a/Cargo.lock:1:1");
    }

    #[test]
    fn ignore_entries_suppress_by_id_alias_and_package() {
        let case = Case::with_lockfile("affected")
            // Representative id.
            .ignore("RUSTSEC-9999-0001", None, None)
            // Alias: the other record of the group, in another letter case.
            .ignore("ghsa-FX02-0002-bbbb", None, Some("2026-11-28"))
            // One package of an advisory that covers two.
            .ignore("GHSA-fx03-0003-cccc", Some("fx-multi-b"), None)
            // Names nothing in this lockfile.
            .ignore("RUSTSEC-0000-0000", None, None)
            .ignore("RUSTSEC-9999-0011", Some("another-crate"), None);
        let report = case.run();
        let reported: Vec<&str> = report
            .findings
            .iter()
            .filter_map(|finding| finding.dependency.as_ref())
            .map(|dependency| dependency.package.as_str())
            .collect();
        for gone in ["fx-simple", "fx-merge", "fx-multi-b"] {
            assert!(!reported.contains(&gone), "{gone}");
        }
        for kept in ["fx-multi-a", "fx-unmaintained", "fx-malware"] {
            assert!(reported.contains(&kept), "{kept}");
        }
        // fx-simple, fx-merge and both versions of fx-multi-b.
        assert_eq!(report.summary.suppressed, 4);
        assert_eq!(report.summary.total, 17);
        assert_eq!(report.findings.len(), 17);
        assert_eq!(report.summary.by_severity["critical"], 3);
        assert!(
            report
                .findings
                .iter()
                .all(|finding| !finding.finding.rule_id.starts_with("policy."))
        );
    }

    #[test]
    fn expired_and_ineffective_entries_are_reported() {
        let mut case = Case::with_lockfile("affected")
            .ignore("RUSTSEC-9999-0001", None, Some("2026-11-27"))
            .ignore("RUSTSEC-9999-0010\u{7}", None, Some("next\tyear"))
            .ignore("MAL-9999-0001", None, None)
            .ignore("RUSTSEC-9999-0013", None, Some("2027-01-01"))
            .ignore("RUSTSEC-9999-0014", None, None);
        case.has_policy_file = true;
        let report = case.run();

        assert_eq!(
            messages(&report, RULE_IGNORE_EXPIRED),
            [
                "Expired [[deps.ignore]] entry (id=RUSTSEC-9999-0001, expires=2026-11-27) — remove or update",
                "Expired [[deps.ignore]] entry (id=RUSTSEC-9999-0010\\u{7}, expires=next\\u{9}year) — remove or update",
            ]
        );
        assert_eq!(
            messages(&report, RULE_IGNORE_INVALID),
            [
                "[[deps.ignore]] entry for MAL-9999-0001 has no expires; malicious-package findings are not suppressed",
                "[[deps.ignore]] entry for RUSTSEC-9999-0014 has no expires; malicious-package findings are not suppressed",
            ]
        );
        for finding in &report.findings {
            if finding.finding.rule_id.starts_with("policy.") {
                let f = &finding.finding;
                assert_eq!(
                    (f.severity.as_str(), f.kind.as_str(), f.file.as_str()),
                    ("low", "ignore", "shk.toml")
                );
                assert_eq!((f.line, f.column), (1, 1));
                assert!(finding.dependency.is_none());
            }
        }
        // Only the dated malicious-package entry suppressed anything.
        assert_eq!(report.summary.suppressed, 1);
        let malicious: Vec<&str> = report
            .findings
            .iter()
            .filter(|finding| finding.finding.rule_id == "deps.malicious")
            .map(|finding| finding.dependency.as_ref().unwrap().package.as_str())
            .collect();
        assert_eq!(malicious, ["fx-mal-alias", "fx-malware"]);
        assert!(report.findings.iter().any(|finding| {
            finding
                .dependency
                .as_ref()
                .is_some_and(|d| d.package == "fx-simple")
        }));
    }

    #[test]
    fn unknown_keys_are_reported_by_name() {
        let policy: Policy = toml::from_str(
            "[deps]\n\"fu\\u001bture\" = \"value-not-shown\"\n\n[[deps.ignore]]\nid = \"A\"\nreason = \"r\"\nowner = \"value-not-shown\"\n",
        )
        .unwrap();
        let mut case = Case::with_lockfile("unaffected");
        case.config = DepsConfig::from_policy(&policy).unwrap();
        case.has_policy_file = true;
        let report = case.run();
        assert_eq!(
            lines(&report),
            [
                "low policy.deps_unknown_key ignore shk.toml:1:1 Unknown key `fu\\u{1b}ture` in [deps] is ignored",
                "low policy.deps_unknown_key ignore shk.toml:1:1 Unknown key `owner` in [[deps.ignore]] entry 1 is ignored",
            ]
        );
    }

    #[test]
    fn alert_keys_leave_out_line_and_version() {
        let mut case = Case::with_lockfile("affected")
            .ignore("RUSTSEC-9999-0001", None, Some("2026-11-27"))
            .ignore("MAL-9999-0001", None, None);
        case.has_policy_file = true;
        case.data.checked_at = None;
        case.config.unknown_keys.push(crate::config::UnknownKey {
            table: "[deps]".into(),
            key: "future".into(),
        });
        let case = case.lockfile("broken/Cargo.lock", "invalid-toml");
        let report = case.run();
        let key = |rule: &str, package: Option<&str>| -> Vec<&str> {
            report
                .findings
                .iter()
                .filter(|finding| {
                    finding.finding.rule_id == rule
                        && package.is_none_or(|package| {
                            finding
                                .dependency
                                .as_ref()
                                .is_some_and(|dependency| dependency.package == package)
                        })
                })
                .map(|finding| finding.alert_key.as_str())
                .collect()
        };
        assert_eq!(
            key("deps.vulnerable", Some("fx-simple")),
            ["Cargo.lock:crates.io:fx-simple:RUSTSEC-9999-0001"]
        );
        // Two versions of one crate under one advisory share an alert.
        assert_eq!(
            key("deps.vulnerable", Some("fx-multi-introduced")),
            ["Cargo.lock:crates.io:fx-multi-introduced:RUSTSEC-9999-0003"; 2]
        );
        assert_eq!(
            key(RULE_SOURCE_UNREADABLE, None),
            ["broken/Cargo.lock:deps.source_unreadable"]
        );
        assert_eq!(key(RULE_DATA_STALE, None), ["shk.toml:deps.data_stale"]);
        assert_eq!(
            key(RULE_UNKNOWN_KEY, None),
            ["shk.toml:policy.deps_unknown_key"]
        );
        assert_eq!(
            key(RULE_IGNORE_EXPIRED, None),
            ["shk.toml:policy.deps_ignore_expired:RUSTSEC-9999-0001"]
        );
        assert_eq!(
            key(RULE_IGNORE_INVALID, None),
            ["shk.toml:policy.deps_ignore_invalid:MAL-9999-0001"]
        );
        // Not part of the JSON report.
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("alert_key"));
    }

    #[test]
    fn every_rule_has_a_fixed_description() {
        for rule in [
            Rule::Malicious,
            Rule::Vulnerable,
            Rule::Unsound,
            Rule::Unmaintained,
            Rule::Notice,
        ] {
            assert!(short_description(rule.id()).is_some(), "{}", rule.id());
        }
        for rule_id in [
            RULE_SOURCE_UNREADABLE,
            RULE_DATA_STALE,
            RULE_IGNORE_EXPIRED,
            RULE_IGNORE_INVALID,
            RULE_UNKNOWN_KEY,
        ] {
            assert!(short_description(rule_id).is_some(), "{rule_id}");
        }
        assert_eq!(
            short_description("deps.vulnerable"),
            Some("Dependency with a known vulnerability")
        );
        assert_eq!(short_description("secret.generic_api_key"), None);
    }

    #[test]
    fn findings_sort_by_severity_file_line_rule_and_id() {
        let finding =
            |severity: &str, file: &str, line: usize, rule: &str, id: &str, message: &str| {
                let mut finding = plain_finding(
                    rule,
                    Severity::parse(severity).unwrap(),
                    "dependency",
                    file,
                    message.to_string(),
                );
                finding.finding.line = line;
                if !id.is_empty() {
                    finding.dependency = Some(DependencyInfo {
                        ecosystem: "crates.io".into(),
                        package: "p".into(),
                        version: "1.0.0".into(),
                        advisory_id: id.into(),
                        aliases: vec![],
                        fixed: vec![],
                        url: String::new(),
                    });
                }
                finding
            };
        let sorted = vec![
            finding("critical", "z/Cargo.lock", 9, "deps.vulnerable", "B", ""),
            finding("high", "a/Cargo.lock", 2, "deps.vulnerable", "Z", ""),
            finding("high", "a/Cargo.lock", 10, "deps.unsound", "A", ""),
            finding("high", "a/Cargo.lock", 10, "deps.vulnerable", "A", ""),
            finding("high", "a/Cargo.lock", 10, "deps.vulnerable", "B", ""),
            finding("high", "b/Cargo.lock", 1, "deps.source_unreadable", "", ""),
            finding("low", "shk.toml", 1, "deps.data_stale", "", ""),
            finding("low", "shk.toml", 1, "policy.deps_unknown_key", "", "a"),
            finding("low", "shk.toml", 1, "policy.deps_unknown_key", "", "b"),
            finding("info", "a/Cargo.lock", 1, "deps.notice", "A", ""),
        ];
        let key = |findings: &[DepsFinding]| -> Vec<String> {
            findings
                .iter()
                .map(|finding| serde_json::to_string(finding).unwrap())
                .collect()
        };
        let mut reversed: Vec<DepsFinding> = sorted.iter().rev().cloned().collect();
        sort_findings(&mut reversed);
        assert_eq!(key(&reversed), key(&sorted));
        let mut rotated = sorted.clone();
        rotated.rotate_left(4);
        sort_findings(&mut rotated);
        assert_eq!(key(&rotated), key(&sorted));
    }

    #[test]
    fn the_threshold_decides_failure() {
        let mut case = Case::with_lockfile("sources");
        for (threshold, fails) in [
            (Severity::Critical, true),
            (Severity::High, true),
            (Severity::Info, true),
        ] {
            case.threshold = threshold;
            let report = case.run();
            assert_eq!(report.exit_threshold, threshold.as_str());
            assert_eq!(report.should_fail(), fails);
        }
        // Only the medium unsound finding is left.
        let mut case = case.ignore("RUSTSEC-9999-0001", None, None);
        for (threshold, fails) in [
            (Severity::Critical, false),
            (Severity::High, false),
            (Severity::Medium, true),
            (Severity::Low, true),
        ] {
            case.threshold = threshold;
            assert_eq!(case.run().should_fail(), fails, "{threshold:?}");
        }
        let mut report = case.run();
        report.exit_threshold = "loud".into();
        assert!(!report.should_fail());
    }

    #[test]
    fn report_serializes_to_the_documented_shape() {
        let mut case = Case::with_lockfile("sources").ignore("RUSTSEC-9999-0010", None, None);
        case.threshold = Severity::Medium;
        let json = serde_json::to_value(case.run()).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "version": 1,
                "sources": ["Cargo.lock"],
                "findings": [{
                    "rule_id": "deps.vulnerable",
                    "severity": "critical",
                    "kind": "dependency",
                    "file": "Cargo.lock",
                    "line": 31,
                    "column": 8,
                    "message": "fx-simple 1.1.9: RUSTSEC-9999-0001 Out-of-bounds read in fx-simple (fixed: >=1.2.0)",
                    "redacted_value": "[REDACTED]",
                    "confidence": 1.0,
                    "dependency": {
                        "ecosystem": "crates.io",
                        "package": "fx-simple",
                        "version": "1.1.9",
                        "advisory_id": "RUSTSEC-9999-0001",
                        "aliases": ["CVE-9999-0001", "GHSA-fx01-0001-aaaa"],
                        "fixed": ["1.2.0"],
                        "url": "https://osv.dev/vulnerability/RUSTSEC-9999-0001",
                    },
                }],
                "summary": { "total": 1, "by_severity": { "critical": 1 }, "suppressed": 1 },
                "inventory": { "packages": [{
                    "ecosystem": "cargo",
                    "source_file": "Cargo.lock",
                    "total": 8,
                    "audited": 2,
                    "skipped": { "git": 2, "registry": 1, "local": 3 },
                }]},
                "data": { "osv:crates.io": {
                    "checked_at": "2026-11-28T11:00:00Z",
                    "modified_at": "2026-11-28T10:30:15Z",
                    "stale": false,
                }},
                "exit_threshold": "medium",
            })
        );
    }
}
