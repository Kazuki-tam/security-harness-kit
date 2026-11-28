//! The on-disk advisory index and its freshness record.
//!
//! ```text
//! <cache dir>/
//!   osv-crates.io.json   the index
//!   manifest.json        when it was fetched
//! ```
//!
//! An audit only reads these files. An update writes each through a
//! temporary file in the same directory and renames it into place, so a
//! reader sees the old file or the new one, never part of one, and updates
//! that run at the same time cannot corrupt the index: the last to finish
//! wins.

use crate::audit::DataState;
use crate::index::BuiltIndex;
use crate::model::{INDEX_SCHEMA_VERSION, Index, SOURCE_OSV_CRATES_IO};
use crate::osv::AdvisoryDb;
use anyhow::{Context, Result, bail};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use tempfile::NamedTempFile;

pub const INDEX_FILE: &str = "osv-crates.io.json";
pub const MANIFEST_FILE: &str = "manifest.json";
pub const MANIFEST_SCHEMA_VERSION: u32 = 1;
/// Prefix of every temporary file an update creates in the cache directory.
pub const TEMP_PREFIX: &str = ".tmp-";
/// Age after which a temporary file is taken to be left over from an update
/// that died.
pub const STALE_TEMP_AGE: Duration = Duration::from_secs(60 * 60);

/// Largest index or manifest that is read back. The index an update writes
/// is a few megabytes; a larger file is not one of ours.
const MAX_CACHE_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// The cache directory: `override_dir` (the `SHK_DEPS_CACHE_DIR` variable)
/// when set and not empty, else `shk/deps` in the user's cache directory.
pub fn resolve_dir(override_dir: Option<&OsStr>) -> Result<PathBuf> {
    if let Some(dir) = override_dir.filter(|dir| !dir.is_empty()) {
        return Ok(PathBuf::from(dir));
    }
    match dirs::cache_dir() {
        Some(base) => Ok(base.join("shk").join("deps")),
        None => bail!("cannot find the user cache directory; set SHK_DEPS_CACHE_DIR"),
    }
}

/// The freshness record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub schema_version: u32,
    /// Per data source id.
    #[serde(default)]
    pub sources: BTreeMap<String, SourceRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRecord {
    pub records: u64,
    pub skipped_records: u64,
    /// When the data was last fetched, RFC 3339 UTC.
    pub checked_at: String,
    /// `Last-Modified` of the dump, RFC 3339 UTC.
    #[serde(default)]
    pub modified_at: Option<String>,
}

fn read_limited(path: &Path, limit: u64) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .ok()?
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() as u64 <= limit).then_some(bytes)
}

/// The index, or `None` when there is none to use: the file is missing, is
/// not JSON of the expected shape, or was written by another version of the
/// format.
pub fn load_index(dir: &Path) -> Option<Index> {
    let bytes = read_limited(&dir.join(INDEX_FILE), MAX_CACHE_FILE_BYTES)?;
    let index: Index = serde_json::from_slice(&bytes).ok()?;
    (index.schema_version == INDEX_SCHEMA_VERSION && index.source == SOURCE_OSV_CRATES_IO)
        .then_some(index)
}

/// The freshness record, or `None` when it is missing or unreadable.
pub fn load_manifest(dir: &Path) -> Option<Manifest> {
    let bytes = read_limited(&dir.join(MANIFEST_FILE), MAX_CACHE_FILE_BYTES)?;
    let manifest: Manifest = serde_json::from_slice(&bytes).ok()?;
    (manifest.schema_version == MANIFEST_SCHEMA_VERSION).then_some(manifest)
}

/// What an audit needs from the cache.
pub struct Loaded {
    /// `None` when there is no usable index.
    pub db: Option<AdvisoryDb>,
    /// Freshness of the index. Empty without an index, and when the record
    /// is missing: the data is then of unknown age.
    pub data: DataState,
}

pub fn load(dir: &Path) -> Loaded {
    let Some(index) = load_index(dir) else {
        return Loaded {
            db: None,
            data: DataState::default(),
        };
    };
    let record = load_manifest(dir).and_then(|mut manifest| manifest.sources.remove(&index.source));
    let time = |text: Option<&str>| {
        DateTime::parse_from_rfc3339(text?)
            .ok()
            .map(|time| time.to_utc())
    };
    let data = DataState {
        checked_at: time(record.as_ref().map(|record| record.checked_at.as_str())),
        modified_at: time(
            record
                .as_ref()
                .and_then(|record| record.modified_at.as_deref()),
        ),
        update_error: None,
    };
    Loaded {
        db: Some(AdvisoryDb::new(index)),
        data,
    }
}

/// Deletes temporary files that an earlier update left behind. Files younger
/// than [`STALE_TEMP_AGE`] may belong to an update that is still running.
pub fn remove_stale_temp_files(dir: &Path, now: SystemTime) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if !entry.file_name().to_string_lossy().starts_with(TEMP_PREFIX) {
            continue;
        }
        // `DirEntry::metadata` does not follow links.
        let stale = entry.metadata().is_ok_and(|metadata| {
            !metadata.is_dir()
                && metadata.modified().is_ok_and(|modified| {
                    now.duration_since(modified)
                        .is_ok_and(|age| age >= STALE_TEMP_AGE)
                })
        });
        if stale {
            let _ = fs::remove_file(entry.path());
        }
    }
}

/// A temporary file in the cache directory, created with the directory if
/// need be. It is deleted when dropped; its name differs per process and
/// call.
pub fn temp_file(dir: &Path) -> Result<NamedTempFile> {
    fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    tempfile::Builder::new()
        .prefix(TEMP_PREFIX)
        .tempfile_in(dir)
        .with_context(|| format!("create a temporary file in {}", dir.display()))
}

fn rfc3339(time: DateTime<Utc>) -> String {
    time.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Replaces the index and then the freshness record. Both are written out
/// in full before either is put in place; when that fails, the existing
/// files are left as they were.
pub fn store(
    dir: &Path,
    built: &BuiltIndex,
    checked_at: DateTime<Utc>,
    modified_at: Option<DateTime<Utc>>,
) -> Result<()> {
    let mut index_file = temp_file(dir)?;
    let mut writer = BufWriter::new(index_file.as_file_mut());
    built.index.write_to(&mut writer)?;
    writer.flush().context("write advisory index")?;
    drop(writer);

    // Records of other sources, which later versions may add, are kept.
    let mut manifest = load_manifest(dir).unwrap_or(Manifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        sources: BTreeMap::new(),
    });
    manifest.sources.insert(
        built.index.source.clone(),
        SourceRecord {
            records: built.records,
            skipped_records: built.skipped_records,
            checked_at: rfc3339(checked_at),
            modified_at: modified_at.map(rfc3339),
        },
    );
    let mut manifest_file = temp_file(dir)?;
    serde_json::to_writer_pretty(manifest_file.as_file_mut(), &manifest)
        .context("write the advisory data manifest")?;
    manifest_file
        .as_file_mut()
        .flush()
        .context("write the advisory data manifest")?;

    let persist = |file: NamedTempFile, name: &str| {
        let path = dir.join(name);
        file.persist(&path)
            .map(|_| ())
            .map_err(|err| anyhow::anyhow!("write {}: {}", path.display(), err.error))
    };
    persist(index_file, INDEX_FILE)?;
    persist(manifest_file, MANIFEST_FILE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{synthetic_files, zip_of};

    fn time(text: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(text).unwrap().to_utc()
    }

    fn built() -> BuiltIndex {
        crate::build_index(zip_of(&synthetic_files())).unwrap()
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn the_cache_directory_can_be_overridden() {
        assert_eq!(
            resolve_dir(Some(OsStr::new("some/dir"))).unwrap(),
            PathBuf::from("some/dir")
        );
        for unset in [None, Some(OsStr::new(""))] {
            let dir = resolve_dir(unset).unwrap();
            assert!(dir.ends_with("shk/deps"), "{}", dir.display());
            assert!(dir.is_absolute());
        }
    }

    #[test]
    fn a_stored_index_loads_with_its_freshness() {
        let dir = tempfile::tempdir().unwrap();
        // The directory is created on the first update.
        let cache = dir.path().join("shk").join("deps");
        let built = built();
        store(
            &cache,
            &built,
            time("2026-11-27T09:12:00.750Z"),
            Some(time("2026-11-27T08:55:31Z")),
        )
        .unwrap();
        assert_eq!(names(&cache), [MANIFEST_FILE, INDEX_FILE]);

        assert_eq!(load_index(&cache).unwrap(), built.index);
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(cache.join(MANIFEST_FILE)).unwrap()).unwrap();
        assert_eq!(
            manifest,
            serde_json::json!({
                "schema_version": 1,
                "sources": { "osv:crates.io": {
                    "records": built.records,
                    "skipped_records": 0,
                    "checked_at": "2026-11-27T09:12:00Z",
                    "modified_at": "2026-11-27T08:55:31Z",
                }},
            })
        );

        let loaded = load(&cache);
        assert!(!loaded.db.unwrap().matches("fx-simple", "1.1.9").is_empty());
        assert_eq!(
            loaded.data,
            DataState {
                checked_at: Some(time("2026-11-27T09:12:00Z")),
                modified_at: Some(time("2026-11-27T08:55:31Z")),
                update_error: None,
            }
        );
    }

    #[test]
    fn storing_again_replaces_both_files_and_keeps_other_sources() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path();
        let mut built = built();
        store(cache, &built, time("2026-11-27T09:00:00Z"), None).unwrap();
        assert_eq!(load(cache).data.modified_at, None);

        let mut manifest = load_manifest(cache).unwrap();
        let other = SourceRecord {
            records: 1,
            skipped_records: 0,
            checked_at: "2026-01-01T00:00:00Z".into(),
            modified_at: None,
        };
        manifest.sources.insert("osv:npm".into(), other.clone());
        fs::write(
            cache.join(MANIFEST_FILE),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();

        built.index.packages.remove("fx-simple");
        built.records = 7;
        built.skipped_records = 2;
        store(cache, &built, time("2026-11-28T09:00:00Z"), None).unwrap();
        assert_eq!(names(cache), [MANIFEST_FILE, INDEX_FILE]);
        assert!(
            !load_index(cache)
                .unwrap()
                .packages
                .contains_key("fx-simple")
        );
        let manifest = load_manifest(cache).unwrap();
        assert_eq!(manifest.sources["osv:npm"], other);
        let record = &manifest.sources["osv:crates.io"];
        assert_eq!((record.records, record.skipped_records), (7, 2));
        assert_eq!(record.checked_at, "2026-11-28T09:00:00Z");
    }

    #[test]
    fn an_unusable_index_counts_as_missing() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path();
        assert!(load_index(cache).is_none());
        assert!(load(cache).db.is_none());
        assert!(load_index(&cache.join("missing")).is_none());

        store(cache, &built(), time("2026-11-27T09:00:00Z"), None).unwrap();
        let good = fs::read_to_string(cache.join(INDEX_FILE)).unwrap();
        for broken in [
            String::new(),
            "not json".to_string(),
            good[..good.len() / 2].to_string(),
            "[]".to_string(),
            good.replacen("\"schema_version\":1", "\"schema_version\":2", 1),
            good.replacen("osv:crates.io", "osv:npm", 1),
        ] {
            fs::write(cache.join(INDEX_FILE), &broken).unwrap();
            assert!(load_index(cache).is_none(), "{:.40}", broken);
            // The freshness record of an index that cannot be used says
            // nothing.
            let loaded = load(cache);
            assert!(loaded.db.is_none());
            assert_eq!(loaded.data, DataState::default());
        }
        fs::write(cache.join(INDEX_FILE), &good).unwrap();
        assert!(load_index(cache).is_some());
    }

    #[test]
    fn an_index_without_a_readable_record_is_of_unknown_age() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path();
        store(cache, &built(), time("2026-11-27T09:00:00Z"), None).unwrap();
        let good = fs::read_to_string(cache.join(MANIFEST_FILE)).unwrap();

        let unknown = |content: Option<String>| {
            match content {
                Some(content) => fs::write(cache.join(MANIFEST_FILE), content).unwrap(),
                None => fs::remove_file(cache.join(MANIFEST_FILE)).unwrap(),
            }
            let loaded = load(cache);
            assert!(loaded.db.is_some());
            loaded.data
        };
        assert_eq!(unknown(None), DataState::default());
        for broken in [
            "{".to_string(),
            good.replacen("\"schema_version\": 1", "\"schema_version\": 9", 1),
            good.replacen("osv:crates.io", "osv:other", 1),
            good.replacen("2026-11-27T09:00:00Z", "yesterday", 1),
            "{\"schema_version\": 1}".to_string(),
        ] {
            assert_eq!(
                unknown(Some(broken.clone())),
                DataState::default(),
                "{broken}"
            );
        }
        // An offset is read as the same instant.
        let offset = good.replacen("2026-11-27T09:00:00Z", "2026-11-27T18:00:00+09:00", 1);
        assert_eq!(
            unknown(Some(offset)).checked_at,
            Some(time("2026-11-27T09:00:00Z"))
        );
    }

    #[test]
    fn a_failed_store_leaves_the_cache_as_it_was() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path();
        let built = built();
        store(cache, &built, time("2026-11-27T09:00:00Z"), None).unwrap();
        let before = fs::read(cache.join(MANIFEST_FILE)).unwrap();

        // The index cannot be put in place: a directory has its name.
        fs::remove_file(cache.join(INDEX_FILE)).unwrap();
        fs::create_dir(cache.join(INDEX_FILE)).unwrap();
        fs::write(cache.join(INDEX_FILE).join("keep"), b"").unwrap();
        let error = store(cache, &built, time("2026-11-28T09:00:00Z"), None).unwrap_err();
        assert!(error.to_string().starts_with("write "), "{error}");
        // The manifest is untouched and no temporary file is left.
        assert_eq!(fs::read(cache.join(MANIFEST_FILE)).unwrap(), before);
        assert_eq!(names(cache), [MANIFEST_FILE, INDEX_FILE]);

        // A cache directory that cannot be created.
        let blocked = cache.join(MANIFEST_FILE).join("sub");
        assert!(store(&blocked, &built, time("2026-11-28T09:00:00Z"), None).is_err());
        assert!(temp_file(&blocked).is_err());
    }

    #[test]
    fn only_old_temporary_files_are_removed() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path();
        store(cache, &built(), time("2026-11-27T09:00:00Z"), None).unwrap();
        for name in [".tmp-old", ".tmp-new", "tmp-other", ".tmpx"] {
            fs::write(cache.join(name), b"x").unwrap();
        }
        fs::create_dir(cache.join(".tmp-dir")).unwrap();
        let written = fs::metadata(cache.join(".tmp-old"))
            .unwrap()
            .modified()
            .unwrap();

        // Nothing is an hour old yet.
        remove_stale_temp_files(cache, written + Duration::from_secs(59 * 60));
        assert_eq!(names(cache).len(), 7);
        // A clock that went backwards removes nothing either.
        remove_stale_temp_files(cache, written - Duration::from_secs(7200));
        assert_eq!(names(cache).len(), 7);

        remove_stale_temp_files(cache, written + Duration::from_secs(2 * 60 * 60));
        assert_eq!(
            names(cache),
            [".tmp-dir", ".tmpx", MANIFEST_FILE, INDEX_FILE, "tmp-other"]
        );
        // A missing directory is not an error.
        remove_stale_temp_files(&cache.join("missing"), SystemTime::now());
    }

    #[test]
    fn temporary_files_are_named_apart_and_removed_when_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let first = temp_file(dir.path()).unwrap();
        let second = temp_file(dir.path()).unwrap();
        assert_ne!(first.path(), second.path());
        for file in [&first, &second] {
            let name = file.path().file_name().unwrap().to_string_lossy();
            assert!(name.starts_with(TEMP_PREFIX), "{name}");
        }
        drop((first, second));
        assert!(names(dir.path()).is_empty());
    }

    #[test]
    fn oversized_cache_files_are_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(INDEX_FILE);
        fs::write(&path, b"12345").unwrap();
        assert_eq!(read_limited(&path, 5).unwrap(), b"12345");
        assert!(read_limited(&path, 4).is_none());
        assert!(read_limited(&dir.path().join("missing"), 4).is_none());
    }
}
