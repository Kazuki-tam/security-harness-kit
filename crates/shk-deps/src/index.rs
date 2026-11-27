//! Builds the local advisory index from an OSV dump (a ZIP archive holding
//! one JSON record per entry). The dump is read from a reader someone else
//! filled; nothing here fetches it or unpacks it to disk.

use crate::model::{INDEX_SCHEMA_VERSION, Index, IndexEntry, SOURCE_OSV_CRATES_IO};
use crate::osv::OsvRecord;
use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::io::{Read, Seek, Write};

/// Upper bounds on a dump. Exceeding any of them fails the whole build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexLimits {
    pub max_entries: usize,
    /// Total size of all entries after decompression.
    pub max_total_bytes: u64,
    /// Size of one entry after decompression.
    pub max_entry_bytes: u64,
    /// Size of the index. A record copies its id, aliases and summary to
    /// every package it names, so the limits on the dump alone do not bound
    /// the index.
    pub max_index_bytes: u64,
}

impl Default for IndexLimits {
    fn default() -> Self {
        Self {
            max_entries: 50_000,
            max_total_bytes: 256 * 1024 * 1024,
            max_entry_bytes: 8 * 1024 * 1024,
            max_index_bytes: 64 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltIndex {
    pub index: Index,
    /// Records stored in the index (withdrawn records are not).
    pub records: u64,
    /// Entries that could not be read as an OSV record.
    pub skipped_records: u64,
}

/// Builds the crates.io index from an OSV `all.zip` dump.
pub fn build_index<R: Read + Seek>(dump: R) -> Result<BuiltIndex> {
    build_index_with_limits(dump, &IndexLimits::default())
}

pub fn build_index_with_limits<R: Read + Seek>(
    dump: R,
    limits: &IndexLimits,
) -> Result<BuiltIndex> {
    let mut archive =
        zip::ZipArchive::new(dump).context("advisory dump is not a readable ZIP archive")?;
    if archive.len() > limits.max_entries {
        bail!(
            "advisory dump has {} entries (limit {})",
            archive.len(),
            limits.max_entries
        );
    }

    let mut packages: BTreeMap<String, Vec<IndexEntry>> = BTreeMap::new();
    let (mut files, mut records, mut skipped_records) = (0u64, 0u64, 0u64);
    let (mut total_bytes, mut index_bytes) = (0u64, 0u64);
    for number in 0..archive.len() {
        // Entry names come from the dump: errors name the entry by position.
        let mut entry = archive
            .by_index(number)
            .with_context(|| format!("read advisory dump entry {number}"))?;
        if entry.is_dir() {
            continue;
        }
        files += 1;
        // The size in the entry header is a claim; count what is read.
        let mut bytes = Vec::new();
        (&mut entry)
            .take(limits.max_entry_bytes + 1)
            .read_to_end(&mut bytes)
            .with_context(|| format!("read advisory dump entry {number}"))?;
        if bytes.len() as u64 > limits.max_entry_bytes {
            bail!(
                "advisory dump entry {number} is larger than {} bytes",
                limits.max_entry_bytes
            );
        }
        total_bytes += bytes.len() as u64;
        if total_bytes > limits.max_total_bytes {
            bail!(
                "advisory dump is larger than {} bytes when unpacked",
                limits.max_total_bytes
            );
        }

        // One bad record upstream must not stop every update.
        let Ok(record) = serde_json::from_slice::<OsvRecord>(&bytes) else {
            skipped_records += 1;
            continue;
        };
        if record.is_withdrawn() {
            continue;
        }
        index_bytes = index_bytes.saturating_add(record.index_bytes());
        if index_bytes > limits.max_index_bytes {
            bail!(
                "advisory dump would need an index larger than {} bytes",
                limits.max_index_bytes
            );
        }
        let entries = record.into_index_entries();
        if entries.is_empty() {
            continue;
        }
        records += 1;
        for (package, entry) in entries {
            packages.entry(package).or_default().push(entry);
        }
    }

    if skipped_records * 100 > files {
        bail!("{skipped_records} of {files} advisory records could not be read (more than 1%)");
    }
    // An index without advisories would silently pass every audit.
    if records == 0 {
        bail!("advisory dump holds no crates.io advisories");
    }
    // Entry order must not depend on the order of the dump, even when two
    // dump entries carry the same id.
    for entries in packages.values_mut() {
        entries.sort_by(|a, b| {
            a.id.cmp(&b.id).then_with(|| {
                let text = |entry| serde_json::to_string(entry).unwrap_or_default();
                text(a).cmp(&text(b))
            })
        });
    }
    Ok(BuiltIndex {
        index: Index {
            schema_version: INDEX_SCHEMA_VERSION,
            source: SOURCE_OSV_CRATES_IO.into(),
            packages,
        },
        records,
        skipped_records,
    })
}

impl Index {
    /// Writes the index in its on-disk JSON form.
    pub fn write_to<W: Write>(&self, writer: W) -> Result<()> {
        serde_json::to_writer(writer, self).context("write advisory index")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{fixture_files, synthetic_files, zip_of, zip_with};
    use std::io::Cursor;

    fn record(id: &str, package: &str) -> (String, Vec<u8>) {
        let body = serde_json::json!({
            "id": id,
            "affected": [{
                "package": { "ecosystem": "crates.io", "name": package },
                "ranges": [{ "type": "SEMVER", "events": [{ "introduced": "0" }] }]
            }]
        });
        (format!("{id}.json"), serde_json::to_vec(&body).unwrap())
    }

    fn records(count: usize) -> Vec<(String, Vec<u8>)> {
        (0..count)
            .map(|number| record(&format!("RUSTSEC-9999-{number:04}"), "pkg"))
            .collect()
    }

    fn broken(count: usize) -> Vec<(String, Vec<u8>)> {
        (0..count)
            .map(|number| (format!("broken-{number}.json"), b"{\"id\": ".to_vec()))
            .collect()
    }

    fn error_of(result: Result<BuiltIndex>) -> String {
        format!("{:#}", result.expect_err("build must fail"))
    }

    #[test]
    fn default_limits_match_the_documented_bounds() {
        assert_eq!(
            IndexLimits::default(),
            IndexLimits {
                max_entries: 50_000,
                max_total_bytes: 256 * 1024 * 1024,
                max_entry_bytes: 8 * 1024 * 1024,
                max_index_bytes: 64 * 1024 * 1024,
            }
        );
    }

    #[test]
    fn builds_an_index_from_real_records() {
        let built = build_index(zip_of(&fixture_files("osv/real"))).unwrap();
        // 21 records, one of them withdrawn.
        assert_eq!((built.records, built.skipped_records), (20, 0));
        let index = &built.index;
        assert_eq!(index.schema_version, INDEX_SCHEMA_VERSION);
        assert_eq!(index.source, "osv:crates.io");

        let time: Vec<&str> = index.packages["time"]
            .iter()
            .map(|entry| entry.id.as_str())
            .collect();
        assert_eq!(time, ["GHSA-wcg3-cvx6-7396", "RUSTSEC-2020-0071"]);
        let rustsec = &index.packages["time"][1];
        assert_eq!(rustsec.aliases, ["CVE-2020-26235", "GHSA-wcg3-cvx6-7396"]);
        assert_eq!(
            rustsec.summary.as_deref(),
            Some("Potential segfault in the time crate")
        );
        assert_eq!(rustsec.severity[0].kind, "CVSS_V3");
        assert_eq!(rustsec.informational, None);
        assert_eq!(rustsec.categories, ["code-execution", "memory-corruption"]);
        assert_eq!(rustsec.ranges.len(), 1);
        assert_eq!(rustsec.ranges[0].events.len(), 16);
        // The GHSA record lists `time` twice.
        assert_eq!(index.packages["time"][0].ranges.len(), 2);
        assert_eq!(
            index.packages["chrono"][0].informational.as_deref(),
            Some("unmaintained")
        );
        assert_eq!(index.packages["replit_ruspty"].len(), 2);

        // The on-disk form reads back unchanged and drops unused fields.
        let mut bytes = Vec::new();
        index.write_to(&mut bytes).unwrap();
        assert_eq!(&serde_json::from_slice::<Index>(&bytes).unwrap(), index);
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.contains("\"details\""));
        assert!(!text.contains("\"references\""));
    }

    #[test]
    fn building_is_deterministic() {
        let mut files = synthetic_files();
        // Two dump entries with the same id and different content.
        let (_, first) = record("RUSTSEC-9999-0700", "pkg");
        let (_, second) = record("RUSTSEC-9999-0700", "pkg");
        let second = String::from_utf8(second)
            .unwrap()
            .replace("\"0\"", "\"1.0.0\"");
        files.push(("a.json".into(), first));
        files.push(("b.json".into(), second.into_bytes()));

        let forward = build_index(zip_of(&files)).unwrap();
        assert_eq!(forward.index.packages["pkg"].len(), 2);
        files.reverse();
        assert_eq!(build_index(zip_of(&files)).unwrap(), forward);
    }

    #[test]
    fn unreadable_records_are_skipped_and_counted_up_to_one_percent() {
        // 1 of 100 is exactly 1%: allowed.
        let mut files = records(99);
        files.extend(broken(1));
        let built = build_index(zip_of(&files)).unwrap();
        assert_eq!((built.records, built.skipped_records), (99, 1));
        assert_eq!(built.index.packages["pkg"].len(), 99);

        // Valid JSON that is not an OSV record is skipped the same way.
        let mut files = records(199);
        files.push(("no-id.json".into(), b"{\"summary\": \"x\"}".to_vec()));
        files.push(("list.json".into(), b"[1, 2]".to_vec()));
        let built = build_index(zip_of(&files)).unwrap();
        assert_eq!((built.records, built.skipped_records), (199, 2));

        // 2 of 100 is more than 1%: the whole build fails.
        let mut files = records(98);
        files.extend(broken(2));
        let error = error_of(build_index(zip_of(&files)));
        assert!(
            error.contains("2 of 100 advisory records could not be read"),
            "{error}"
        );

        // The fixture directory with its broken entry: 1 of 23.
        let error = error_of(build_index(zip_of(&fixture_files("osv/synthetic"))));
        assert!(error.contains("1 of 23"), "{error}");
    }

    #[test]
    fn withdrawn_and_foreign_records_are_not_counted() {
        let mut files = records(3);
        files.push((
            "withdrawn.json".into(),
            br#"{"id":"RUSTSEC-9999-9000","withdrawn":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"crates.io","name":"gone"}}]}"#.to_vec(),
        ));
        files.push((
            "npm.json".into(),
            br#"{"id":"GHSA-npm","affected":[{"package":{"ecosystem":"npm","name":"left-pad"}}]}"#
                .to_vec(),
        ));
        let built = build_index(zip_of(&files)).unwrap();
        assert_eq!((built.records, built.skipped_records), (3, 0));
        assert_eq!(built.index.packages.keys().collect::<Vec<_>>(), ["pkg"]);
    }

    #[test]
    fn a_dump_without_advisories_is_rejected() {
        let error = error_of(build_index(zip_of(&[])));
        assert!(error.contains("holds no crates.io advisories"), "{error}");
        let only_withdrawn = [(
            "withdrawn.json".to_owned(),
            br#"{"id":"RUSTSEC-9999-9000","withdrawn":"2026-01-01T00:00:00Z"}"#.to_vec(),
        )];
        let error = error_of(build_index(zip_of(&only_withdrawn)));
        assert!(error.contains("holds no crates.io advisories"), "{error}");
    }

    #[test]
    fn directories_are_ignored() {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default();
        writer.add_directory("advisories/", options).unwrap();
        let (name, content) = record("RUSTSEC-9999-0001", "pkg");
        writer
            .start_file(format!("advisories/{name}"), options)
            .unwrap();
        std::io::Write::write_all(&mut writer, &content).unwrap();
        let mut archive = writer.finish().unwrap();
        archive.set_position(0);
        let built = build_index(archive).unwrap();
        assert_eq!((built.records, built.skipped_records), (1, 0));
    }

    #[test]
    fn limits_fail_the_whole_build() {
        let files = records(3);
        let limits = |max_entries, max_total_bytes, max_entry_bytes| IndexLimits {
            max_entries,
            max_total_bytes,
            max_entry_bytes,
            ..IndexLimits::default()
        };
        let size = files[0].1.len() as u64;

        assert!(build_index_with_limits(zip_of(&files), &limits(3, size * 3, size)).is_ok());

        let error = error_of(build_index_with_limits(
            zip_of(&files),
            &limits(2, size * 3, size),
        ));
        assert!(error.contains("has 3 entries (limit 2)"), "{error}");

        let error = error_of(build_index_with_limits(
            zip_of(&files),
            &limits(3, size * 3, size - 1),
        ));
        assert!(error.contains("entry 0 is larger than"), "{error}");

        let error = error_of(build_index_with_limits(
            zip_of(&files),
            &limits(3, size * 3 - 1, size),
        ));
        assert!(error.contains("when unpacked"), "{error}");
    }

    #[test]
    fn an_entry_header_that_understates_its_size_does_not_lift_the_limit() {
        let files = records(1);
        let size = files[0].1.len() as u64;
        let mut archive = zip_of(&files).into_inner();
        // Rewrite the uncompressed size in the local header (offset 22) and
        // in the central directory (offset 24) to claim a single byte.
        for (signature, offset) in [(b"PK\x03\x04", 22), (b"PK\x01\x02", 24)] {
            let at = archive
                .windows(4)
                .position(|window| window == signature)
                .unwrap();
            archive[at + offset..at + offset + 4].copy_from_slice(&1u32.to_le_bytes());
        }
        let limits = IndexLimits {
            max_entry_bytes: size - 1,
            ..IndexLimits::default()
        };
        assert!(build_index_with_limits(Cursor::new(archive), &limits).is_err());
    }

    #[test]
    fn a_record_that_multiplies_its_strings_is_stopped_by_the_index_limit() {
        // One long alias and summary, copied to every package named: a
        // 60 KB record that asks for a 100 MB index.
        let long = "x".repeat(25_000);
        let affected: Vec<serde_json::Value> = (0..2_000)
            .map(|n| serde_json::json!({ "package": { "ecosystem": "crates.io", "name": format!("p{n}") } }))
            .collect();
        let hostile = serde_json::json!({
            "id": "GHSA-big", "aliases": [long], "summary": long, "affected": affected
        });
        let hostile = serde_json::to_vec(&hostile).unwrap();
        assert!(hostile.len() < 200_000);
        let error = error_of(build_index(zip_of(&[("big.json".into(), hostile)])));
        assert!(
            error.contains("an index larger than 67108864 bytes"),
            "{error}"
        );

        // For ordinary records the limit follows the size of the index
        // that would be written.
        let files = records(50);
        let built = build_index(zip_of(&files)).unwrap();
        let mut written = Vec::new();
        built.index.write_to(&mut written).unwrap();
        let bound: u64 = files
            .iter()
            .map(|(_, bytes)| {
                serde_json::from_slice::<OsvRecord>(bytes)
                    .unwrap()
                    .index_bytes()
            })
            .sum();
        assert!(written.len() as u64 <= bound, "{} > {bound}", written.len());
        let limits = |max_index_bytes| IndexLimits {
            max_index_bytes,
            ..IndexLimits::default()
        };
        assert!(build_index_with_limits(zip_of(&files), &limits(bound)).is_ok());
        assert!(build_index_with_limits(zip_of(&files), &limits(bound - 1)).is_err());
    }

    #[test]
    fn broken_archives_fail() {
        let error = error_of(build_index(Cursor::new(b"not a zip archive".to_vec())));
        assert!(error.contains("not a readable ZIP archive"), "{error}");

        let whole = zip_of(&records(3)).into_inner();
        let truncated = whole[..whole.len() / 2].to_vec();
        assert!(build_index(Cursor::new(truncated)).is_err());

        // A stored entry whose content no longer matches its checksum.
        let files = records(1);
        let mut damaged = zip_with(&files, zip::CompressionMethod::Stored).into_inner();
        let content = &files[0].1;
        let at = damaged
            .windows(content.len())
            .position(|window| window == content.as_slice())
            .unwrap();
        damaged[at + 2] ^= 0x20;
        let error = error_of(build_index(Cursor::new(damaged)));
        assert!(error.contains("read advisory dump entry 0"), "{error}");
    }
}
