//! The part of the OSV schema `shk deps` uses: reading records, deciding
//! whether a version is affected, joining records that describe the same
//! advisory, and turning CVSS vectors into a severity.

use crate::model::{ECOSYSTEM_CRATES_IO, Event, Index, IndexEntry, Range, Rule, SeverityVector};
use semver::Version;
use serde::{Deserialize, Deserializer};
use shk_core::policy::Severity;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;

fn null_as_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

/// One OSV record, reduced to the fields that end up in the index. Unknown
/// fields are ignored and `schema_version` is not required.
#[derive(Debug, Deserialize)]
pub struct OsvRecord {
    pub id: String,
    #[serde(default, deserialize_with = "null_as_default")]
    aliases: Vec<String>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default, deserialize_with = "null_as_default")]
    severity: Vec<serde_json::Value>,
    #[serde(default)]
    withdrawn: Option<serde_json::Value>,
    #[serde(default, deserialize_with = "null_as_default")]
    affected: Vec<OsvAffected>,
}

#[derive(Debug, Deserialize)]
struct OsvAffected {
    #[serde(default)]
    package: Option<OsvPackage>,
    #[serde(default, deserialize_with = "null_as_default")]
    ranges: Vec<OsvRange>,
    #[serde(default, deserialize_with = "null_as_default")]
    versions: Vec<String>,
    #[serde(default, deserialize_with = "null_as_default")]
    severity: Vec<serde_json::Value>,
    #[serde(default)]
    database_specific: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct OsvPackage {
    #[serde(default)]
    ecosystem: String,
    #[serde(default)]
    name: String,
}

#[derive(Debug, Deserialize)]
struct OsvRange {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default, deserialize_with = "null_as_default")]
    events: Vec<BTreeMap<String, serde_json::Value>>,
}

fn severity_vectors(raw: &[serde_json::Value]) -> Vec<SeverityVector> {
    raw.iter()
        .filter_map(|value| {
            Some(SeverityVector {
                kind: value.get("type")?.as_str()?.to_owned(),
                score: value.get("score")?.as_str()?.to_owned(),
            })
        })
        .collect()
}

/// The indexed form of a range, or `None` for a range that cannot be used:
/// not a version range, no events, or a bound that is not a string. Dropping
/// only the malformed event would turn `introduced .. fixed` into a range
/// that never ends, or never starts.
fn index_range(range: OsvRange) -> Option<Range> {
    if !is_version_range(&range.kind) {
        return None;
    }
    let mut events = Vec::new();
    for (key, value) in range.events.iter().flat_map(|event| event.iter()) {
        let event: fn(String) -> Event = match key.as_str() {
            "introduced" => Event::Introduced,
            "fixed" => Event::Fixed,
            "last_affected" => Event::LastAffected,
            _ => continue,
        };
        events.push(event(value.as_str()?.to_owned()));
    }
    (!events.is_empty()).then_some(Range {
        kind: range.kind,
        events,
    })
}

fn categories_of(affected: &OsvAffected) -> impl Iterator<Item = &str> {
    affected
        .database_specific
        .as_ref()
        .and_then(|specific| specific.get("categories"))
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
        .filter_map(|category| category.as_str())
}

impl OsvRecord {
    pub fn is_withdrawn(&self) -> bool {
        self.withdrawn.is_some()
    }

    /// The size of what this record adds to the index: the bytes of its
    /// strings as stored, with an allowance for the JSON around them. Every
    /// package a record names gets a copy of its id, aliases, summary and
    /// severity, so a small hostile record can ask for a very large index;
    /// the builder adds these up before expanding a record. The written
    /// index can exceed the sum by a small constant factor (JSON escaping),
    /// never by a factor that grows with the input.
    pub fn index_bytes(&self) -> u64 {
        // Room for the JSON around each string and each entry.
        const PER_STRING: usize = 16;
        const PER_ENTRY: usize = 128;
        let text = |value: &serde_json::Value| value.as_str().map_or(0, str::len) + PER_STRING;
        let vectors = |vectors: &[serde_json::Value]| -> usize {
            vectors
                .iter()
                .map(|vector| {
                    vector.get("type").map_or(0, text) + vector.get("score").map_or(0, text)
                })
                .sum()
        };
        let strings = |values: &[String]| -> usize {
            values.iter().map(|value| value.len() + PER_STRING).sum()
        };
        let shared = PER_ENTRY
            + self.id.len()
            + self.summary.as_ref().map_or(0, String::len)
            + strings(&self.aliases)
            + vectors(&self.severity);
        self.affected
            .iter()
            .map(|affected| {
                let name = affected.package.as_ref().map_or(0, |p| p.name.len());
                let events: usize = affected
                    .ranges
                    .iter()
                    .map(|range| {
                        range.kind.len()
                            + PER_STRING
                            + range
                                .events
                                .iter()
                                .flat_map(|e| e.values())
                                .map(text)
                                .sum::<usize>()
                    })
                    .sum();
                let specific = affected.database_specific.as_ref();
                let informational = specific
                    .and_then(|specific| specific.get("informational"))
                    .map_or(0, text);
                let categories: usize = categories_of(affected)
                    .map(|category| category.len() + PER_STRING)
                    .sum();
                (shared
                    + name
                    + strings(&affected.versions)
                    + vectors(&affected.severity)
                    + events
                    + informational
                    + categories) as u64
            })
            .sum()
    }

    /// The index entries of this record: one per crates.io package it names,
    /// with the ranges of repeated `affected[]` entries for the same package
    /// combined. A withdrawn record has none.
    pub fn into_index_entries(self) -> Vec<(String, IndexEntry)> {
        if self.is_withdrawn() {
            return Vec::new();
        }
        let Self {
            id,
            aliases,
            summary,
            severity,
            affected,
            ..
        } = self;
        let summary = summary.filter(|summary| !summary.trim().is_empty());
        let record_severity = severity_vectors(&severity);

        let mut by_package: BTreeMap<String, IndexEntry> = BTreeMap::new();
        for mut affected in affected {
            let Some(package) = affected.package.take() else {
                continue;
            };
            if package.ecosystem != ECOSYSTEM_CRATES_IO || package.name.is_empty() {
                continue;
            }
            let entry = by_package
                .entry(package.name)
                .or_insert_with(|| IndexEntry {
                    id: id.clone(),
                    aliases: aliases.clone(),
                    summary: summary.clone(),
                    severity: record_severity.clone(),
                    informational: None,
                    categories: Vec::new(),
                    versions: Vec::new(),
                    ranges: Vec::new(),
                });
            if entry.severity.is_empty() {
                entry.severity = severity_vectors(&affected.severity);
            }
            if entry.informational.is_none() {
                entry.informational = affected
                    .database_specific
                    .as_ref()
                    .and_then(|specific| specific.get("informational"))
                    .and_then(|value| value.as_str())
                    .map(str::to_owned);
            }
            entry
                .categories
                .extend(categories_of(&affected).map(str::to_owned));
            entry.versions.extend(affected.versions);
            entry
                .ranges
                .extend(affected.ranges.into_iter().filter_map(index_range));
        }
        by_package
            .into_iter()
            .map(|(package, mut entry)| {
                for list in [&mut entry.categories, &mut entry.versions] {
                    list.sort();
                    list.dedup();
                }
                (package, entry)
            })
            .collect()
    }
}

fn is_version_range(kind: &str) -> bool {
    matches!(kind, "SEMVER" | "ECOSYSTEM")
}

/// A range bound: `"0"` (before every version) or a semver version.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Bound {
    Zero,
    At(Version),
}

impl Bound {
    fn parse(value: &str) -> Option<Self> {
        if value == "0" {
            Some(Self::Zero)
        } else {
            Version::parse(value).ok().map(Self::At)
        }
    }

    fn cmp_bound(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Zero, Self::Zero) => Ordering::Equal,
            (Self::Zero, Self::At(_)) => Ordering::Less,
            (Self::At(_), Self::Zero) => Ordering::Greater,
            (Self::At(a), Self::At(b)) => a.cmp_precedence(b),
        }
    }

    fn cmp_version(&self, version: &Version) -> Ordering {
        match self {
            Self::Zero => Ordering::Less,
            Self::At(bound) => bound.cmp_precedence(version),
        }
    }
}

fn event_order(event: &Event) -> u8 {
    match event {
        Event::Introduced(_) => 0,
        Event::Fixed(_) => 1,
        Event::LastAffected(_) => 2,
    }
}

/// A `fixed` value together with its parsed form, for ordering.
type FixedVersion = (Version, String);

/// How one range applies to an installed version that falls into it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RangeHit {
    /// The range's last event, when that event is `fixed`.
    last_fixed: Option<FixedVersion>,
    /// The range's `fixed` values above the installed version.
    fixed_after: Vec<FixedVersion>,
}

/// Evaluates one range the way the OSV schema describes: events are sorted
/// by version and walked in order. `None` when the version is not affected,
/// or when the range cannot be evaluated because it is not a version range
/// or holds a value that is not semver.
fn evaluate_range(range: &Range, version: &Version) -> Option<RangeHit> {
    if !is_version_range(&range.kind) {
        return None;
    }
    let mut events = range
        .events
        .iter()
        .map(|event| Bound::parse(event.value()).map(|bound| (bound, event)))
        .collect::<Option<Vec<_>>>()?;
    events.sort_by(|(a, a_event), (b, b_event)| {
        a.cmp_bound(b)
            .then(event_order(a_event).cmp(&event_order(b_event)))
    });

    let mut affected = false;
    for (bound, event) in &events {
        let position = bound.cmp_version(version);
        match event {
            Event::Introduced(_) if position != Ordering::Greater => affected = true,
            Event::Fixed(_) if position != Ordering::Greater => affected = false,
            Event::LastAffected(_) if position == Ordering::Less => affected = false,
            _ => {}
        }
    }
    if !affected {
        return None;
    }
    let fixed = |(bound, event): &(Bound, &Event)| match (bound, event) {
        (Bound::At(bound), Event::Fixed(value)) => Some((bound.clone(), value.clone())),
        _ => None,
    };
    Some(RangeHit {
        last_fixed: events.last().and_then(fixed),
        fixed_after: events
            .iter()
            .filter_map(fixed)
            .filter(|(bound, _)| bound.cmp_precedence(version).is_gt())
            .collect(),
    })
}

/// How one index entry applies to an installed version.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EntryHit {
    /// The last `fixed` of the ranges the version falls into.
    fixed_label: Option<String>,
    /// The `fixed` values of those ranges above the version, ascending.
    fixed_after: Vec<String>,
}

fn entry_hit(entry: &IndexEntry, version: &str) -> Option<EntryHit> {
    let mut hit = entry.versions.iter().any(|listed| listed == version);
    let mut label: Option<FixedVersion> = None;
    let mut after: Vec<FixedVersion> = Vec::new();
    // Without a semver version only the exact `versions` list can match.
    if let Ok(parsed) = Version::parse(version) {
        for range_hit in entry
            .ranges
            .iter()
            .filter_map(|range| evaluate_range(range, &parsed))
        {
            hit = true;
            if let Some(fixed) = range_hit.last_fixed
                && label
                    .as_ref()
                    .is_none_or(|(current, _)| fixed.0.cmp_precedence(current).is_gt())
            {
                label = Some(fixed);
            }
            after.extend(range_hit.fixed_after);
        }
    }
    if !hit {
        return None;
    }
    after.sort_by(|(a, _), (b, _)| a.cmp_precedence(b));
    after.dedup_by(|(a, _), (b, _)| a.cmp_precedence(b).is_eq());
    Some(EntryHit {
        fixed_label: label.map(|(_, value)| value),
        fixed_after: after.into_iter().map(|(_, value)| value).collect(),
    })
}

/// The rule one record falls under, before records are joined. A record
/// that aliases a `MAL-` id is malicious whether or not that `MAL-` record
/// is in the index: most of the ones RustSec points to are not.
pub fn classify(entry: &IndexEntry) -> Rule {
    let is_malicious_id = |id: &str| id.starts_with("MAL-");
    if is_malicious_id(&entry.id)
        || entry.aliases.iter().any(|alias| is_malicious_id(alias))
        || entry
            .categories
            .iter()
            .any(|category| category == "malicious")
    {
        return Rule::Malicious;
    }
    match entry.informational.as_deref() {
        Some("unsound") => Rule::Unsound,
        Some("unmaintained") => Rule::Unmaintained,
        Some("notice") => Rule::Notice,
        _ => Rule::Vulnerable,
    }
}

const CVSS_V3_BASE: &[&str] = &["AV", "AC", "PR", "UI", "S", "C", "I", "A"];
const CVSS_V4_BASE: &[&str] = &[
    "AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA",
];

/// A CVSS vector reduced to its base metrics, or `None` unless each of them
/// appears exactly once. The `cvss` crate scores a vector with base metrics
/// missing (as if they had no impact) and folds threat and environmental
/// metrics into a v4 score; neither is the base score.
fn base_vector(vector: &str, base_metrics: &[&str]) -> Option<String> {
    let mut parts = vector.split('/');
    let mut base = vec![parts.next()?];
    let mut seen: Vec<&str> = Vec::new();
    for part in parts {
        let (metric, _) = part.split_once(':')?;
        if base_metrics.contains(&metric) {
            if seen.contains(&metric) {
                return None;
            }
            seen.push(metric);
            base.push(part);
        }
    }
    (seen.len() == base_metrics.len()).then(|| base.join("/"))
}

fn vector_base_score(vector: &SeverityVector) -> Option<f64> {
    let base_metrics = match vector.kind.as_str() {
        "CVSS_V4" => CVSS_V4_BASE,
        "CVSS_V3" => CVSS_V3_BASE,
        _ => return None,
    };
    let parsed = cvss::Cvss::from_str(&base_vector(&vector.score, base_metrics)?).ok()?;
    let version_matches = match parsed {
        cvss::Cvss::CvssV40(_) => vector.kind == "CVSS_V4",
        cvss::Cvss::CvssV30(_) | cvss::Cvss::CvssV31(_) => vector.kind == "CVSS_V3",
        _ => false,
    };
    version_matches.then(|| parsed.score())
}

/// The CVSS base score of one record: from its `CVSS_V4` vector if one is
/// usable, otherwise from its `CVSS_V3` vector.
pub fn base_score(vectors: &[SeverityVector]) -> Option<f64> {
    ["CVSS_V4", "CVSS_V3"].iter().find_map(|kind| {
        vectors
            .iter()
            .filter(|vector| vector.kind == *kind)
            .find_map(vector_base_score)
    })
}

pub fn severity_for_score(score: f64) -> Severity {
    if score >= 9.0 {
        Severity::Critical
    } else if score >= 7.0 {
        Severity::High
    } else if score >= 4.0 {
        Severity::Medium
    } else if score >= 0.1 {
        Severity::Low
    } else {
        Severity::Info
    }
}

/// Severity of a `deps.vulnerable` finding whose records carry no usable
/// CVSS vector. Nearly half of the RustSec vulnerability advisories have no
/// CVSS, and a lower default would let them pass the default threshold.
pub const SEVERITY_WITHOUT_CVSS: Severity = Severity::High;

/// Records joined through their `aliases`, transitively and through ids that
/// have no record of their own (a shared CVE, for instance).
#[derive(Debug)]
struct AliasGroups {
    /// Group number of every record id in the index.
    group_of: HashMap<String, usize>,
}

impl AliasGroups {
    fn build(index: &Index) -> Self {
        let mut sets = DisjointSets::default();
        let mut record_nodes: Vec<(&str, usize)> = Vec::new();
        for entry in index.packages.values().flatten() {
            let id = sets.node(&entry.id);
            record_nodes.push((&entry.id, id));
            for alias in &entry.aliases {
                let alias = sets.node(alias);
                sets.union(id, alias);
            }
        }
        let group_of = record_nodes
            .into_iter()
            .map(|(id, node)| (id.to_owned(), sets.find(node)))
            .collect();
        Self { group_of }
    }

    /// The group of a record id, or `None` for an id without a record in
    /// the index this was built from.
    fn group(&self, id: &str) -> Option<usize> {
        self.group_of.get(id).copied()
    }
}

/// Union-find over advisory ids.
#[derive(Default)]
struct DisjointSets<'a> {
    node_of: HashMap<&'a str, usize>,
    parent: Vec<usize>,
}

impl<'a> DisjointSets<'a> {
    fn node(&mut self, name: &'a str) -> usize {
        *self.node_of.entry(name).or_insert_with(|| {
            self.parent.push(self.parent.len());
            self.parent.len() - 1
        })
    }

    fn find(&mut self, mut node: usize) -> usize {
        while self.parent[node] != node {
            self.parent[node] = self.parent[self.parent[node]];
            node = self.parent[node];
        }
        node
    }

    fn union(&mut self, a: usize, b: usize) {
        let (a, b) = (self.find(a), self.find(b));
        self.parent[a] = b;
    }
}

/// One advisory group that applies to an installed package version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvisoryMatch {
    pub rule: Rule,
    pub severity: Severity,
    /// Representative id: a RUSTSEC record if one matched, else a GHSA
    /// record, else the smallest id.
    pub advisory_id: String,
    /// The other ids of the records that matched, and their aliases, sorted.
    pub aliases: Vec<String>,
    pub summary: Option<String>,
    /// `X` of the `(fixed: >=X)` message suffix.
    pub fixed_label: Option<String>,
    /// `fixed` versions above the installed one, ascending.
    pub fixed: Vec<String>,
}

fn representative_rank(id: &str) -> u8 {
    if id.starts_with("RUSTSEC-") {
        0
    } else if id.starts_with("GHSA-") {
        1
    } else {
        2
    }
}

/// An advisory index together with the alias groups derived from it, so the
/// two cannot get out of step.
#[derive(Debug)]
pub struct AdvisoryDb {
    index: Index,
    groups: AliasGroups,
}

impl AdvisoryDb {
    pub fn new(index: Index) -> Self {
        let groups = AliasGroups::build(&index);
        Self { index, groups }
    }

    pub fn index(&self) -> &Index {
        &self.index
    }

    /// The advisory groups that apply to `name` at `version`, one match per
    /// group, sorted by representative id.
    ///
    /// Only the records of a group that name this package and match this
    /// version take part: a group can span several crates and its records
    /// can disagree on ranges, so the rule, the severity, the representative
    /// and the message fields all come from the records that actually
    /// matched.
    pub fn matches(&self, name: &str, version: &str) -> Vec<AdvisoryMatch> {
        match_package(&self.index, &self.groups, name, version)
    }
}

fn match_package(
    index: &Index,
    groups: &AliasGroups,
    name: &str,
    version: &str,
) -> Vec<AdvisoryMatch> {
    let Some(entries) = index.packages.get(name) else {
        return Vec::new();
    };
    let mut by_group: BTreeMap<usize, Vec<(&IndexEntry, EntryHit)>> = BTreeMap::new();
    let mut ungrouped = usize::MAX;
    for entry in entries {
        if let Some(hit) = entry_hit(entry, version) {
            // Every indexed id has a group; a stray one stands alone.
            let group = groups.group(&entry.id).unwrap_or_else(|| {
                ungrouped -= 1;
                ungrouped
            });
            by_group.entry(group).or_default().push((entry, hit));
        }
    }

    let mut matches: Vec<AdvisoryMatch> = by_group
        .into_values()
        .map(|mut members| {
            members.sort_by(|(a, _), (b, _)| {
                (representative_rank(&a.id), &a.id).cmp(&(representative_rank(&b.id), &b.id))
            });
            let (representative, representative_hit) = &members[0];
            // After the representative, fall back in id order.
            let mut fallback: Vec<&(&IndexEntry, EntryHit)> = members.iter().collect();
            fallback[1..].sort_by(|(a, _), (b, _)| a.id.cmp(&b.id));

            let rule = members
                .iter()
                .map(|(entry, _)| classify(entry))
                .min()
                .unwrap_or(Rule::Vulnerable);
            let severity = rule.fixed_severity().unwrap_or_else(|| {
                members
                    .iter()
                    .filter_map(|(entry, _)| base_score(&entry.severity))
                    .reduce(f64::max)
                    .map(severity_for_score)
                    .unwrap_or(SEVERITY_WITHOUT_CVSS)
            });
            let fixed_source = fallback
                .iter()
                .find(|(_, hit)| hit.fixed_label.is_some())
                .map(|(_, hit)| hit)
                .unwrap_or(representative_hit);
            // Bounded by what the matching records themselves hold: the ids
            // of a whole group can be far more than one finding should carry.
            let mut aliases: Vec<String> = members
                .iter()
                .flat_map(|(entry, _)| std::iter::once(&entry.id).chain(&entry.aliases))
                .filter(|id| **id != representative.id)
                .cloned()
                .collect();
            aliases.sort();
            aliases.dedup();
            AdvisoryMatch {
                rule,
                severity,
                advisory_id: representative.id.clone(),
                aliases,
                summary: fallback.iter().find_map(|(entry, _)| entry.summary.clone()),
                fixed_label: fixed_source.fixed_label.clone(),
                fixed: fixed_source.fixed_after.clone(),
            }
        })
        .collect();
    matches.sort_by(|a, b| a.advisory_id.cmp(&b.advisory_id));
    matches
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{real_index, synthetic_index};

    struct Fixture {
        db: AdvisoryDb,
    }

    impl Fixture {
        fn new(index: Index) -> Self {
            Self {
                db: AdvisoryDb::new(index),
            }
        }

        fn matches(&self, name: &str, version: &str) -> Vec<AdvisoryMatch> {
            self.db.matches(name, version)
        }

        /// The single match of a package version.
        fn one(&self, name: &str, version: &str) -> AdvisoryMatch {
            let mut matches = self.matches(name, version);
            assert_eq!(matches.len(), 1, "{name} {version}: {matches:?}");
            matches.remove(0)
        }

        fn affected(&self, name: &str, version: &str) -> bool {
            !self.matches(name, version).is_empty()
        }

        fn entries(&self, name: &str) -> &[IndexEntry] {
            &self.db.index().packages[name]
        }
    }

    fn synthetic() -> Fixture {
        Fixture::new(synthetic_index())
    }

    fn real() -> Fixture {
        Fixture::new(real_index())
    }

    fn range(kind: &str, events: &[Event]) -> Range {
        Range {
            kind: kind.into(),
            events: events.to_vec(),
        }
    }

    fn entry(id: &str) -> IndexEntry {
        IndexEntry {
            id: id.into(),
            aliases: vec![],
            summary: None,
            severity: vec![],
            informational: None,
            categories: vec![],
            versions: vec![],
            ranges: vec![],
        }
    }

    fn introduced(value: &str) -> Event {
        Event::Introduced(value.into())
    }

    fn fixed(value: &str) -> Event {
        Event::Fixed(value.into())
    }

    fn vector(kind: &str, score: &str) -> SeverityVector {
        SeverityVector {
            kind: kind.into(),
            score: score.into(),
        }
    }

    const V31_CRITICAL: &str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
    const V30_MEDIUM: &str = "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H";
    const V31_ZERO: &str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N";
    const V4_CRITICAL: &str = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";

    #[test]
    fn introduced_and_fixed_bound_a_range() {
        let fx = synthetic();
        assert!(fx.affected("fx-simple", "0.0.1"));
        assert!(fx.affected("fx-simple", "1.1.9"));
        assert!(!fx.affected("fx-simple", "1.2.0"));
        assert!(!fx.affected("fx-simple", "2.0.0"));
        // Build metadata does not take part in ordering.
        assert!(fx.affected("fx-simple", "1.1.9+build.5"));
        assert!(!fx.affected("fx-simple", "1.2.0+build.5"));
        // Unknown packages and versions that are not semver match nothing.
        assert!(!fx.affected("fx-unknown", "1.0.0"));
        assert!(!fx.affected("fx-simple", "1.1"));
    }

    #[test]
    fn last_affected_is_inclusive() {
        let fx = synthetic();
        assert!(!fx.affected("fx-last-affected", "0.9.9"));
        assert!(fx.affected("fx-last-affected", "1.0.0"));
        assert!(fx.affected("fx-last-affected", "1.4.2"));
        assert!(!fx.affected("fx-last-affected", "1.4.3"));
        assert_eq!(fx.one("fx-last-affected", "1.4.2").fixed_label, None);
    }

    #[test]
    fn several_ranges_are_alternatives_and_git_ranges_are_ignored() {
        let fx = synthetic();
        for (version, affected) in [
            ("0.9.0", false),
            ("1.0.4", true),
            ("1.0.5", false),
            ("1.9.0", false),
            ("2.2.0", true),
            ("2.3.0", false),
        ] {
            assert_eq!(fx.affected("fx-two-ranges", version), affected, "{version}");
        }
        // The GIT range is dropped when the index is built.
        let kinds: Vec<&str> = fx.entries("fx-two-ranges")[0]
            .ranges
            .iter()
            .map(|range| range.kind.as_str())
            .collect();
        assert_eq!(kinds, ["SEMVER", "SEMVER"]);

        let first = fx.one("fx-two-ranges", "1.0.4");
        assert_eq!(first.fixed_label.as_deref(), Some("1.0.5"));
        assert_eq!(first.fixed, ["1.0.5"]);
        let second = fx.one("fx-two-ranges", "2.2.0");
        assert_eq!(second.fixed_label.as_deref(), Some("2.3.0"));
        assert_eq!(second.fixed, ["2.3.0"]);
    }

    #[test]
    fn events_are_sorted_before_a_range_with_several_introduced_is_walked() {
        let fx = synthetic();
        for (version, affected) in [
            ("0.1.9", true),
            ("0.2.0", false),
            ("0.2.1-alpha.1", true),
            ("0.2.1", false),
            ("0.2.2", false),
            ("0.2.3", false),
            ("0.3.0-rc.1", true),
            ("0.3.4", true),
            ("0.3.5", false),
        ] {
            assert_eq!(
                fx.affected("fx-multi-introduced", version),
                affected,
                "{version}"
            );
        }
        // The message names the last `fixed` of the range, not the first.
        let hit = fx.one("fx-multi-introduced", "0.1.9");
        assert_eq!(hit.fixed_label.as_deref(), Some("0.3.5"));
        assert_eq!(hit.fixed, ["0.2.0", "0.2.1", "0.2.2", "0.3.5"]);
    }

    #[test]
    fn real_time_advisory_with_several_introduced_events() {
        let fx = real();
        let rustsec = &fx
            .entries("time")
            .iter()
            .find(|entry| entry.id == "RUSTSEC-2020-0071")
            .unwrap()
            .ranges[0];
        let version = |text: &str| Version::parse(text).unwrap();
        for (text, affected) in [
            ("0.1.45", true),
            ("0.2.0", false),
            ("0.2.6", false),
            ("0.2.7-alpha.1", true),
            ("0.2.7", true),
            ("0.2.22", true),
            ("0.2.23", false),
            ("0.3.36", false),
        ] {
            assert_eq!(
                evaluate_range(rustsec, &version(text)).is_some(),
                affected,
                "{text}"
            );
        }

        let old = fx.one("time", "0.1.45");
        assert_eq!(old.advisory_id, "RUSTSEC-2020-0071");
        assert_eq!(old.aliases, ["CVE-2020-26235", "GHSA-wcg3-cvx6-7396"]);
        assert_eq!(old.rule, Rule::Vulnerable);
        assert_eq!(old.severity, Severity::Medium);
        assert_eq!(
            old.summary.as_deref(),
            Some("Potential segfault in the time crate")
        );
        assert_eq!(old.fixed_label.as_deref(), Some("0.2.23"));
        assert_eq!(fx.one("time", "0.2.22").advisory_id, "RUSTSEC-2020-0071");
        assert!(!fx.affected("time", "0.2.23"));

        // The GHSA record covers 0.2.0 and the RUSTSEC record does not: the
        // records that match decide, so the GHSA record represents the group.
        let ghsa_only = fx.one("time", "0.2.0");
        assert_eq!(ghsa_only.advisory_id, "GHSA-wcg3-cvx6-7396");
        assert_eq!(ghsa_only.aliases, ["CVE-2020-26235", "RUSTSEC-2020-0071"]);
        assert_eq!(
            ghsa_only.summary.as_deref(),
            Some("Segmentation fault in time")
        );
        assert_eq!(ghsa_only.fixed_label.as_deref(), Some("0.2.23"));
    }

    #[test]
    fn introduced_and_fixed_on_the_same_version_leave_it_unaffected() {
        let fx = synthetic();
        for (version, affected) in [
            ("1.0.0", false),
            ("1.5.0", false),
            ("2.0.0", true),
            ("2.0.5", true),
            ("2.1.0", false),
        ] {
            assert_eq!(
                fx.affected("fx-same-version", version),
                affected,
                "{version}"
            );
        }

        // Whatever the stored order, `introduced` is handled before `fixed`
        // and `fixed` before `last_affected` on one version.
        let version = Version::parse("1.0.0").unwrap();
        for events in [
            [fixed("1.0.0"), introduced("1.0.0")],
            [introduced("1.0.0"), fixed("1.0.0")],
        ] {
            assert_eq!(evaluate_range(&range("SEMVER", &events), &version), None);
        }
        let last_affected = range(
            "SEMVER",
            &[Event::LastAffected("1.0.0".into()), introduced("1.0.0")],
        );
        assert_eq!(
            evaluate_range(&last_affected, &version),
            Some(RangeHit {
                last_fixed: None,
                fixed_after: vec![],
            })
        );
    }

    #[test]
    fn zero_bounds_come_before_every_version() {
        let earliest = Version::parse("0.0.0-0").unwrap();
        let prerelease = Version::parse("0.0.0-alpha").unwrap();
        let zero = range("ECOSYSTEM", &[introduced("0"), fixed("1.0.0")]);
        let rustsec_zero = range("SEMVER", &[introduced("0.0.0-0"), fixed("1.0.0")]);
        for range in [&zero, &rustsec_zero] {
            assert!(evaluate_range(range, &earliest).is_some());
            assert!(evaluate_range(range, &prerelease).is_some());
            assert!(evaluate_range(range, &Version::parse("0.0.0").unwrap()).is_some());
            assert!(evaluate_range(range, &Version::parse("1.0.0").unwrap()).is_none());
        }
        // "0.0.0-0" is an ordinary semver value below 0.0.0.
        assert_eq!(
            Bound::parse("0.0.0-0")
                .unwrap()
                .cmp_bound(&Bound::parse("0.0.0").unwrap()),
            Ordering::Less
        );
        assert_eq!(
            Bound::Zero.cmp_bound(&Bound::parse("0.0.0-0").unwrap()),
            Ordering::Less
        );
        assert_eq!(Bound::Zero.cmp_bound(&Bound::Zero), Ordering::Equal);
        assert_eq!(
            Bound::parse("0.0.0-0").unwrap().cmp_bound(&Bound::Zero),
            Ordering::Greater
        );
        // A range fixed at "0" affects nothing and yields no fixed label.
        let fixed_at_zero = range("SEMVER", &[introduced("0"), fixed("0")]);
        assert_eq!(evaluate_range(&fixed_at_zero, &earliest), None);
    }

    #[test]
    fn prereleases_follow_semver_ordering() {
        let fx = synthetic();
        for (version, affected) in [
            ("1.0.0-alpha.1", false),
            ("1.0.0-alpha.2", true),
            ("1.0.0-beta.1", true),
            ("1.0.0-rc.1", false),
            ("1.0.0", false),
        ] {
            assert_eq!(fx.affected("fx-prerelease", version), affected, "{version}");
        }
    }

    #[test]
    fn a_range_with_a_value_that_is_not_semver_is_not_evaluated() {
        let fx = synthetic();
        // The range `0 .. 0.4` cannot be evaluated; `versions` still matches.
        assert!(!fx.affected("fx-bad-semver", "0.1.0"));
        assert!(!fx.affected("fx-bad-semver", "0.3.2"));
        let hit = fx.one("fx-bad-semver", "0.3.1");
        assert_eq!(hit.fixed_label, None);
        assert!(hit.fixed.is_empty());
        // A CVSS vector that does not parse counts as no CVSS.
        assert_eq!(hit.severity, Severity::High);

        // An installed version that is not semver can only match exactly.
        let real = real();
        let exact = real.one("hickory-recursor", "0.1");
        assert_eq!(exact.advisory_id, "GHSA-83hf-93m4-rgwq");
        assert!(real.affected("hickory-recursor", "0.25.0"));
        assert!(!real.affected("hickory-recursor", "0.26.0"));
    }

    #[test]
    fn exact_versions_match_without_ranges() {
        let fx = synthetic();
        assert!(fx.affected("fx-malware", "0.1.0"));
        assert!(fx.affected("fx-malware", "0.1.1"));
        assert!(!fx.affected("fx-malware", "0.1.2"));
    }

    #[test]
    fn withdrawn_records_are_not_indexed() {
        assert!(!synthetic().db.index().packages.contains_key("fx-withdrawn"));
        let real = real();
        assert!(!real.db.index().packages.contains_key("dirs"));
        assert!(!real.affected("dirs", "3.0.0"));
    }

    #[test]
    fn records_are_classified_in_table_order() {
        assert_eq!(classify(&entry("MAL-9999-0001")), Rule::Malicious);
        assert_eq!(classify(&entry("RUSTSEC-9999-0001")), Rule::Vulnerable);

        let mut alias = entry("RUSTSEC-9999-0014");
        alias.aliases = vec!["GHSA-aaaa".into(), "MAL-9999-0002".into()];
        assert_eq!(classify(&alias), Rule::Malicious);

        // `malicious` wins over `informational`.
        let mut category = entry("RUSTSEC-9999-0013");
        category.categories = vec!["code-execution".into(), "malicious".into()];
        category.informational = Some("unmaintained".into());
        assert_eq!(classify(&category), Rule::Malicious);

        for (informational, rule) in [
            ("unsound", Rule::Unsound),
            ("unmaintained", Rule::Unmaintained),
            ("notice", Rule::Notice),
            ("something-new", Rule::Vulnerable),
        ] {
            let mut record = entry("RUSTSEC-9999-0010");
            record.informational = Some(informational.into());
            assert_eq!(classify(&record), rule, "{informational}");
        }
    }

    #[test]
    fn synthetic_records_get_their_rule_and_severity() {
        let fx = synthetic();
        for (name, version, rule, severity) in [
            ("fx-malware", "0.1.1", Rule::Malicious, Severity::Critical),
            (
                "fx-malicious-category",
                "1.0.0",
                Rule::Malicious,
                Severity::Critical,
            ),
            ("fx-mal-alias", "0.0.1", Rule::Malicious, Severity::Critical),
            ("fx-unsound", "0.8.0", Rule::Unsound, Severity::Medium),
            (
                "fx-unmaintained",
                "0.1.0",
                Rule::Unmaintained,
                Severity::Low,
            ),
            ("fx-notice", "1.0.0", Rule::Notice, Severity::Info),
            // CVSS v3.1, v3.0, base score 0.0, and no CVSS at all.
            ("fx-simple", "1.1.9", Rule::Vulnerable, Severity::Critical),
            (
                "fx-multi-introduced",
                "0.3.4",
                Rule::Vulnerable,
                Severity::Medium,
            ),
            ("fx-two-ranges", "2.2.0", Rule::Vulnerable, Severity::Info),
            (
                "fx-last-affected",
                "1.4.2",
                Rule::Vulnerable,
                Severity::High,
            ),
            ("fx-same-version", "2.0.5", Rule::Vulnerable, Severity::Low),
            // Severity found only under `affected[].severity`.
            (
                "fx-affected-severity",
                "0.4.9",
                Rule::Vulnerable,
                Severity::Medium,
            ),
        ] {
            let hit = fx.one(name, version);
            assert_eq!((hit.rule, hit.severity), (rule, severity), "{name}");
        }
        assert_eq!(fx.one("fx-malware", "0.1.1").advisory_id, "MAL-9999-0001");
        assert!(
            fx.one("fx-mal-alias", "0.0.1")
                .aliases
                .contains(&"MAL-9999-0002".to_owned())
        );
        assert_eq!(
            fx.one("fx-unsound", "0.8.0").fixed_label.as_deref(),
            Some("0.9.0")
        );
        assert_eq!(fx.one("fx-unmaintained", "0.1.0").fixed_label, None);
    }

    #[test]
    fn real_records_get_their_rule() {
        let fx = real();
        for (name, version, id, rule, severity) in [
            (
                "chrono",
                "0.4.45",
                "RUSTSEC-2026-0543",
                Rule::Unmaintained,
                Severity::Low,
            ),
            (
                "proc-macro-error",
                "1.0.4",
                "RUSTSEC-2024-0370",
                Rule::Unmaintained,
                Severity::Low,
            ),
            (
                "totally-safe",
                "0.1.0",
                "RUSTSEC-2025-0029",
                Rule::Unsound,
                Severity::Medium,
            ),
            (
                "inconceivable",
                "0.9.0",
                "RUSTSEC-2022-0058",
                Rule::Notice,
                Severity::Info,
            ),
            (
                "jfrog_quotes",
                "0.1.0",
                "RUSTSEC-2025-0158",
                Rule::Malicious,
                Severity::Critical,
            ),
            // Reported by OpenSSF (MAL) and RustSec: one group, RUSTSEC id.
            (
                "replit_ruspty",
                "1.0.0",
                "RUSTSEC-2025-0154",
                Rule::Malicious,
                Severity::Critical,
            ),
        ] {
            let hit = fx.one(name, version);
            assert_eq!(
                (hit.advisory_id.as_str(), hit.rule, hit.severity),
                (id, rule, severity),
                "{name}"
            );
        }
        assert!(
            fx.one("replit_ruspty", "1.0.0")
                .aliases
                .contains(&"MAL-2025-49350".to_owned())
        );
        // `affected[]` entries for other ecosystems are dropped.
        assert!(fx.affected("wasm3", "0.5.0"));
        assert!(!fx.affected("wasm3", "0.5.1"));
        assert!(!fx.db.index().packages.contains_key("pywasm3"));
    }

    #[test]
    fn cvss_vectors_become_base_scores() {
        assert_eq!(base_score(&[vector("CVSS_V3", V31_CRITICAL)]), Some(9.8));
        assert_eq!(base_score(&[vector("CVSS_V3", V30_MEDIUM)]), Some(6.2));
        assert_eq!(base_score(&[vector("CVSS_V3", V31_ZERO)]), Some(0.0));
        assert_eq!(base_score(&[vector("CVSS_V4", V4_CRITICAL)]), Some(9.3));
        assert_eq!(base_score(&[]), None);
        assert_eq!(
            base_score(&[vector("CVSS_V3", "CVSS:3.1/not-a-vector")]),
            None
        );
        assert_eq!(
            base_score(&[vector("CVSS_V2", "AV:N/AC:L/Au:N/C:P/I:P/A:P")]),
            None
        );
        // v4 is preferred; a v4 vector that does not parse falls back to v3.
        assert_eq!(
            base_score(&[
                vector("CVSS_V3", V30_MEDIUM),
                vector("CVSS_V4", V4_CRITICAL)
            ]),
            Some(9.3)
        );
        assert_eq!(
            base_score(&[
                vector("CVSS_V4", "CVSS:4.0/broken"),
                vector("CVSS_V3", V30_MEDIUM)
            ]),
            Some(6.2)
        );
    }

    #[test]
    fn only_complete_base_vectors_are_scored() {
        // Base metrics missing: the crate would score these 0.0 and 5.9.
        for partial in ["CVSS:3.1/AV:N", "CVSS:3.1/C:H/I:H/A:H", "CVSS:3.1"] {
            assert_eq!(base_score(&[vector("CVSS_V3", partial)]), None, "{partial}");
        }
        assert_eq!(
            base_score(&[vector("CVSS_V4", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N")]),
            None
        );
        // A metric given twice, a metric without a value, a mislabelled type.
        let repeated = format!("{V31_CRITICAL}/AV:L");
        assert_eq!(base_score(&[vector("CVSS_V3", &repeated)]), None);
        assert_eq!(base_score(&[vector("CVSS_V3", "CVSS:3.1/AV")]), None);
        assert_eq!(base_score(&[vector("CVSS_V4", V31_CRITICAL)]), None);
        assert_eq!(base_score(&[vector("CVSS_V3", V4_CRITICAL)]), None);

        // Threat, temporal and environmental metrics do not change the
        // base score.
        let with_threat = format!("{V4_CRITICAL}/E:U");
        assert_eq!(base_score(&[vector("CVSS_V4", &with_threat)]), Some(9.3));
        let with_environment = format!("{V4_CRITICAL}/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N");
        assert_eq!(
            base_score(&[vector("CVSS_V4", &with_environment)]),
            Some(9.3)
        );
        let with_temporal = format!("{V31_CRITICAL}/E:U/RL:O/RC:C");
        assert_eq!(base_score(&[vector("CVSS_V3", &with_temporal)]), Some(9.8));
    }

    #[test]
    fn fixed_versions_are_ascending_without_duplicates() {
        let mut record = entry("RUSTSEC-9999-0400");
        record.ranges = vec![
            range(
                "SEMVER",
                &[introduced("0"), fixed("3.0.0"), fixed("2.0.0+b")],
            ),
            range("SEMVER", &[introduced("1.0.0"), fixed("2.0.0+a")]),
            // Not matched at 1.5.0: its `fixed` is left out.
            range("SEMVER", &[introduced("4.0.0"), fixed("4.2.0")]),
        ];
        let hit = entry_hit(&record, "1.5.0").unwrap();
        assert_eq!(hit.fixed_label.as_deref(), Some("3.0.0"));
        assert_eq!(hit.fixed_after.len(), 2);
        assert!(hit.fixed_after[0].starts_with("2.0.0+"));
        assert_eq!(hit.fixed_after[1], "3.0.0");
    }

    #[test]
    fn index_bytes_bound_what_a_record_adds() {
        let json = serde_json::json!({
            "id": "RUSTSEC-9999-0500",
            "aliases": ["CVE-9999-0001", "CVE-9999-0002"],
            "summary": "A summary that every package entry repeats",
            "severity": [{ "type": "CVSS_V3", "score": V30_MEDIUM }],
            "affected": [
                {
                    "package": { "ecosystem": "crates.io", "name": "a" },
                    "versions": ["1.0.0"],
                    "severity": [{ "type": "CVSS_V3", "score": V31_ZERO }],
                    "ranges": [{ "type": "SEMVER", "events": [
                        { "introduced": "0", "fixed": "2.0.0" }, { "last_affected": "1.9.0" }
                    ] }],
                    "database_specific": { "categories": ["malicious"], "informational": "notice" }
                },
                { "package": { "ecosystem": "crates.io", "name": "b" } },
                { "package": { "ecosystem": "npm", "name": "c" } }
            ]
        });
        let bound = serde_json::from_value::<OsvRecord>(json.clone())
            .unwrap()
            .index_bytes();
        let entries = serde_json::from_value::<OsvRecord>(json)
            .unwrap()
            .into_index_entries();
        let stored = serde_json::to_vec(&entries).unwrap().len() as u64;
        assert!(stored <= bound, "{stored} > {bound}");
        assert!(
            bound < stored * 4,
            "{bound} is not a tight bound for {stored}"
        );

        // A long string copied to many packages is counted once per copy.
        let affected: Vec<serde_json::Value> = (0..100)
            .map(|n| serde_json::json!({ "package": { "ecosystem": "crates.io", "name": format!("p{n}") } }))
            .collect();
        let long = "x".repeat(10_000);
        let record: OsvRecord = serde_json::from_value(serde_json::json!({
            "id": "GHSA-long", "aliases": [long], "summary": long, "affected": affected
        }))
        .unwrap();
        assert!(record.index_bytes() >= 100 * 20_000);
    }

    #[test]
    fn scores_map_to_severity_bands() {
        for (score, severity) in [
            (10.0, Severity::Critical),
            (9.0, Severity::Critical),
            (8.9, Severity::High),
            (7.0, Severity::High),
            (6.9, Severity::Medium),
            (4.0, Severity::Medium),
            (3.9, Severity::Low),
            (0.1, Severity::Low),
            (0.0, Severity::Info),
        ] {
            assert_eq!(severity_for_score(score), severity, "{score}");
        }
    }

    #[test]
    fn records_joined_through_a_shared_cve_form_one_group() {
        let fx = synthetic();
        // Neither record names the other: both alias CVE-9999-0001.
        let hit = fx.one("fx-simple", "1.1.9");
        assert_eq!(hit.advisory_id, "RUSTSEC-9999-0001");
        assert_eq!(hit.aliases, ["CVE-9999-0001", "GHSA-fx01-0001-aaaa"]);
        // Only the RUSTSEC record has CVSS.
        assert_eq!(hit.severity, Severity::Critical);
        assert_eq!(
            hit.summary.as_deref(),
            Some("Out-of-bounds read in fx-simple")
        );
        assert_eq!(hit.fixed_label.as_deref(), Some("1.2.0"));
        assert_eq!(hit.fixed, ["1.2.0"]);

        let group = |id: &str| fx.db.groups.group(id);
        assert!(group("RUSTSEC-9999-0001").is_some());
        assert_eq!(group("RUSTSEC-9999-0001"), group("GHSA-fx01-0001-aaaa"));
        assert_ne!(group("RUSTSEC-9999-0001"), group("RUSTSEC-9999-0002"));
        // Ids without a record of their own have no group to look up.
        assert_eq!(group("CVE-9999-0001"), None);

        // When only one of the two records matches, the other record's id
        // is not reported: it is reachable only through the shared CVE.
        let mut index = synthetic_index();
        index
            .packages
            .get_mut("fx-simple")
            .unwrap()
            .retain(|entry| entry.id.starts_with("GHSA-"));
        let ghsa_only = Fixture::new(index).one("fx-simple", "1.1.9");
        assert_eq!(ghsa_only.advisory_id, "GHSA-fx01-0001-aaaa");
        assert_eq!(ghsa_only.aliases, ["CVE-9999-0001"]);
    }

    #[test]
    fn a_representative_without_summary_fixed_or_cvss_borrows_them() {
        let fx = synthetic();
        let hit = fx.one("fx-merge", "1.9.9");
        assert_eq!(hit.advisory_id, "RUSTSEC-9999-0002");
        assert_eq!(hit.aliases, ["GHSA-fx02-0002-bbbb"]);
        assert_eq!(
            hit.summary.as_deref(),
            Some("fx-merge accepts forged tokens")
        );
        assert_eq!(hit.fixed_label.as_deref(), Some("2.0.0"));
        assert_eq!(hit.fixed, ["2.0.0"]);
        // CVSS v4 from the GHSA record beats the no-CVSS default.
        assert_eq!(hit.severity, Severity::Critical);
        assert!(!fx.affected("fx-merge", "2.0.0"));
    }

    #[test]
    fn real_groups_take_cvss_from_the_ghsa_record() {
        let fx = real();
        for (name, version, id, ghsa) in [
            ("glib", "0.18.5", "RUSTSEC-2024-0429", "GHSA-wrw7-89jp-8q8g"),
            (
                "cggmp21",
                "0.3.0",
                "RUSTSEC-2024-0393",
                "GHSA-rm66-9gh4-4gp8",
            ),
        ] {
            let entries = fx.entries(name);
            let score = |id: &str| {
                base_score(
                    &entries
                        .iter()
                        .find(|entry| entry.id == id)
                        .unwrap()
                        .severity,
                )
            };
            assert_eq!(score(id), None, "{name}");
            let ghsa_score = score(ghsa).expect("GHSA record has CVSS");
            let hit = fx.one(name, version);
            assert_eq!(hit.advisory_id, id);
            assert_eq!(hit.severity, severity_for_score(ghsa_score), "{name}");
        }

        // One RUSTSEC record joined to two GHSA records.
        let ckb = fx.one("ckb", "0.39.0");
        assert_eq!(ckb.advisory_id, "RUSTSEC-2021-0109");
        assert_eq!(
            ckb.aliases,
            [
                "CVE-2021-45700",
                "GHSA-45p7-c959-rgcm",
                "GHSA-cw98-cx2m-9qqg"
            ]
        );
        assert_eq!(ckb.fixed_label.as_deref(), Some("0.40.0"));
        assert!(!fx.affected("ckb", "0.40.0"));
    }

    #[test]
    fn only_matching_records_of_a_group_take_part() {
        let fx = real();
        // RustSec files this advisory as `unsound`, GitHub as a
        // vulnerability with a CVSS v4 vector. Both records cover 4.0.0, so
        // the group is `deps.vulnerable` there and takes the CVSS severity.
        let both = fx.one("rtvm-interpreter", "4.0.0");
        assert_eq!(both.advisory_id, "RUSTSEC-2025-0131");
        assert_eq!(both.rule, Rule::Vulnerable);
        let ghsa_score = base_score(&fx.entries("rtvm-interpreter")[0].severity).unwrap();
        assert_eq!(both.severity, severity_for_score(ghsa_score));
        // Above it only the open-ended RUSTSEC range matches: the GHSA
        // record's classification and CVSS no longer apply.
        let rustsec_only = fx.one("rtvm-interpreter", "4.0.1");
        assert_eq!(rustsec_only.advisory_id, "RUSTSEC-2025-0131");
        assert_eq!(rustsec_only.aliases, ["GHSA-pq5v-rwp8-p7gm"]);
        assert_eq!(
            (rustsec_only.rule, rustsec_only.severity),
            (Rule::Unsound, Severity::Medium)
        );
    }

    #[test]
    fn group_rule_is_the_highest_priority_among_matching_records() {
        let mut vulnerable = entry("GHSA-aaaa-0001");
        vulnerable.aliases = vec!["RUSTSEC-9999-0100".into()];
        vulnerable.severity = vec![vector("CVSS_V3", V30_MEDIUM)];
        vulnerable.ranges = vec![range("SEMVER", &[introduced("0")])];
        let mut unmaintained = entry("RUSTSEC-9999-0100");
        unmaintained.informational = Some("unmaintained".into());
        unmaintained.ranges = vec![range("SEMVER", &[introduced("0.0.0-0"), fixed("2.0.0")])];
        let mut malicious = entry("MAL-9999-0100");
        malicious.aliases = vec!["GHSA-aaaa-0001".into()];
        malicious.versions = vec!["1.0.0".into()];

        let index = Index {
            schema_version: crate::model::INDEX_SCHEMA_VERSION,
            source: crate::model::SOURCE_OSV_CRATES_IO.into(),
            packages: [("pkg".to_owned(), vec![vulnerable, unmaintained, malicious])].into(),
        };
        let fx = Fixture::new(index);

        // 1.0.0: all three match; malicious wins and the RUSTSEC id leads.
        let all = fx.one("pkg", "1.0.0");
        assert_eq!(all.advisory_id, "RUSTSEC-9999-0100");
        assert_eq!(
            (all.rule, all.severity),
            (Rule::Malicious, Severity::Critical)
        );
        assert_eq!(all.aliases, ["GHSA-aaaa-0001", "MAL-9999-0100"]);
        // 1.5.0: vulnerable beats unmaintained; severity comes from CVSS.
        let two = fx.one("pkg", "1.5.0");
        assert_eq!(
            (two.rule, two.severity),
            (Rule::Vulnerable, Severity::Medium)
        );
        assert_eq!(two.fixed_label.as_deref(), Some("2.0.0"));
        // 2.5.0: only the GHSA record matches and represents the group.
        let one = fx.one("pkg", "2.5.0");
        assert_eq!(one.advisory_id, "GHSA-aaaa-0001");
        // The MAL record aliases this one, not the other way round.
        assert_eq!(one.aliases, ["RUSTSEC-9999-0100"]);
        assert_eq!(one.rule, Rule::Vulnerable);
    }

    #[test]
    fn a_group_without_rustsec_or_ghsa_uses_the_smallest_id() {
        let fx = synthetic();
        let hit = fx.one("fx-orphan", "0.9.0");
        assert_eq!(hit.advisory_id, "CVE-9999-0009");
        assert_eq!(hit.aliases, ["OSV-9999-0002"]);
        assert_eq!(hit.summary.as_deref(), Some("fx-orphan (CVE entry)"));
        assert_eq!(hit.severity, Severity::Medium);
    }

    #[test]
    fn separate_groups_on_one_package_are_separate_matches() {
        let mut first = entry("RUSTSEC-9999-0201");
        first.ranges = vec![range("SEMVER", &[introduced("0.0.0-0")])];
        let mut second = entry("GHSA-bbbb-0002");
        second.ranges = vec![range("SEMVER", &[introduced("0")])];
        let index = Index {
            schema_version: crate::model::INDEX_SCHEMA_VERSION,
            source: crate::model::SOURCE_OSV_CRATES_IO.into(),
            packages: [("pkg".to_owned(), vec![first, second])].into(),
        };
        let ids: Vec<String> = Fixture::new(index)
            .matches("pkg", "1.0.0")
            .into_iter()
            .map(|hit| hit.advisory_id)
            .collect();
        assert_eq!(ids, ["GHSA-bbbb-0002", "RUSTSEC-9999-0201"]);
    }

    #[test]
    fn repeated_affected_entries_for_one_package_are_combined() {
        let fx = synthetic();
        for (name, version, affected) in [
            ("fx-multi-a", "2.9.9", true),
            // The npm entry of the same name (fixed in 9.9.9) is not used.
            ("fx-multi-a", "3.0.0", false),
            ("fx-multi-b", "1.0.5", true),
            ("fx-multi-b", "1.1.0", false),
            ("fx-multi-b", "2.0.2", true),
            ("fx-multi-b", "2.0.3", false),
        ] {
            assert_eq!(fx.affected(name, version), affected, "{name} {version}");
        }
        assert_eq!(fx.entries("fx-multi-b").len(), 1);
        assert_eq!(fx.entries("fx-multi-b")[0].ranges.len(), 2);
    }

    #[test]
    fn osv_records_are_read_leniently() {
        // No schema_version, null lists, unknown fields and event keys.
        let record: OsvRecord = serde_json::from_value(serde_json::json!({
            "id": "RUSTSEC-9999-0300",
            "aliases": null,
            "summary": "  ",
            "severity": [{ "type": "CVSS_V3" }, 7, { "type": "CVSS_V3", "score": V30_MEDIUM }],
            "future_field": { "nested": true },
            "affected": [
                { "ranges": [{ "type": "SEMVER", "events": [{ "introduced": "0" }] }] },
                { "package": { "ecosystem": "crates.io", "name": "" } },
                {
                    "package": { "ecosystem": "crates.io", "name": "pkg" },
                    "versions": null,
                    "ranges": [
                        { "type": "SEMVER", "events": [
                            { "introduced": "0" }, { "limit": "2.0.0" }
                        ] },
                        { "type": "SEMVER", "events": [{ "limit": "1.0.0" }] },
                        // A bound of the wrong type drops the whole range.
                        { "type": "SEMVER", "events": [{ "introduced": "0" }, { "fixed": 3 }] },
                        { "type": "SEMVER", "events": [{ "introduced": 0 }, { "fixed": "1.0.0" }] },
                        { "type": "GIT", "events": [{ "introduced": "0" }] }
                    ],
                    "database_specific": { "categories": null, "informational": null }
                },
                {
                    "package": { "ecosystem": "crates.io", "name": "pkg" },
                    "versions": ["1.0.0", "0.9.0", "1.0.0"],
                    "database_specific": {
                        "categories": ["malicious", "malicious", 4],
                        "informational": "notice"
                    }
                }
            ]
        }))
        .unwrap();
        assert!(!record.is_withdrawn());
        let entries = record.into_index_entries();
        assert_eq!(entries.len(), 1);
        let (package, entry) = &entries[0];
        assert_eq!(package, "pkg");
        assert_eq!(entry.summary, None);
        assert_eq!(entry.severity, [vector("CVSS_V3", V30_MEDIUM)]);
        assert_eq!(entry.ranges, [range("SEMVER", &[introduced("0")])]);
        assert_eq!(entry.versions, ["0.9.0", "1.0.0"]);
        assert_eq!(entry.categories, ["malicious"]);
        assert_eq!(entry.informational.as_deref(), Some("notice"));

        let withdrawn: OsvRecord = serde_json::from_value(serde_json::json!({
            "id": "RUSTSEC-9999-0301",
            "withdrawn": "2026-02-01T00:00:00Z",
            "affected": [{ "package": { "ecosystem": "crates.io", "name": "pkg" } }]
        }))
        .unwrap();
        assert!(withdrawn.is_withdrawn());
        assert!(withdrawn.into_index_entries().is_empty());

        let not_withdrawn: OsvRecord =
            serde_json::from_value(serde_json::json!({ "id": "X-1", "withdrawn": null })).unwrap();
        assert!(!not_withdrawn.is_withdrawn());
        assert!(
            serde_json::from_value::<OsvRecord>(serde_json::json!({ "summary": "x" })).is_err()
        );
    }
}
