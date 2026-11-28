//! Fetching the advisory data for `shk deps` and rebuilding the local index.
//!
//! This is the only place `shk deps` touches the network, and only
//! `shk deps update` and `shk deps audit --update` come here. The request
//! carries nothing about the project: the whole dump is downloaded and
//! matched locally.

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use shk_deps::cache;
use std::io::{BufReader, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::{Duration, SystemTime};

const DEFAULT_OSV_BASE_URL: &str = "https://storage.googleapis.com/osv-vulnerabilities";
const DUMP_PATH: &str = "crates.io/all.zip";
const USER_AGENT: &str = concat!("shk/", env!("CARGO_PKG_VERSION"));
/// Largest dump that is downloaded. The real one is about 4 MiB.
pub(crate) const MAX_DUMP_BYTES: u64 = 64 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(60);
pub(crate) const BAD_BASE_URL: &str =
    "SHK_DEPS_OSV_URL must be an https:// base URL without a query or fragment";

/// What a fetch returns besides the body it wrote.
#[derive(Debug, Default)]
pub(crate) struct Fetched {
    /// The `Last-Modified` response header.
    pub(crate) last_modified: Option<String>,
}

/// Downloads a URL into a writer. A parameter so that tests never need a
/// server.
pub(crate) type Fetcher<'a> = &'a dyn Fn(&str, &mut dyn Write) -> Result<Fetched>;

/// The URL of the crates.io dump below `base` (the `SHK_DEPS_OSV_URL`
/// variable, for a mirror), or below the OSV bucket. Only HTTPS is accepted.
pub(crate) fn dump_url(base: Option<&str>) -> Result<String> {
    let base = base
        .map(str::trim)
        .filter(|base| !base.is_empty())
        .unwrap_or(DEFAULT_OSV_BASE_URL);
    let is_https = base
        .get(..8)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"));
    // A query or fragment would swallow the path that is appended.
    if !is_https || base.len() == 8 || base.contains(['?', '#']) {
        bail!(BAD_BASE_URL);
    }
    Ok(format!("{}/{DUMP_PATH}", base.trim_end_matches('/')))
}

/// Anything but a plain 200 is a failure. Redirects are not followed: the
/// source is not expected to redirect, and a redirect is how a download gets
/// steered somewhere else.
fn check_status(status: u16) -> Result<()> {
    if status != 200 {
        bail!("unexpected HTTP status {status}");
    }
    Ok(())
}

/// HTTPS only, and no redirect is followed: a 3xx comes back as the response
/// for [`check_status`] to refuse.
fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(TIMEOUT))
        .https_only(true)
        .max_redirects(0)
        .max_redirects_will_error(false)
        .user_agent(USER_AGENT)
        .build()
        .into()
}

/// The real [`Fetcher`]. `url` must come from [`dump_url`]: for a URL that
/// is not HTTPS, the error names the URL, which may carry a token.
pub(crate) fn fetch_https(url: &str, out: &mut dyn Write) -> Result<Fetched> {
    let mut response = agent().get(url).call()?;
    check_status(response.status().as_u16())?;
    let last_modified = response
        .headers()
        .get("last-modified")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    // The convenience readers stop at 10 MB without saying so in the type;
    // this limit is explicit and an error when exceeded.
    let mut body = response
        .body_mut()
        .with_config()
        .limit(MAX_DUMP_BYTES)
        .reader();
    std::io::copy(&mut body, out)?;
    Ok(Fetched { last_modified })
}

fn parse_last_modified(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc2822(value.trim())
        .ok()
        .map(|time| time.to_utc())
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct UpdateOutcome {
    pub(crate) records: u64,
    pub(crate) skipped_records: u64,
}

/// Downloads the dump and replaces the index in `cache_dir`. On any failure
/// the existing index and its freshness record stay as they were and no
/// temporary file is left behind.
pub(crate) fn update(
    cache_dir: &Path,
    url: &str,
    fetch: Fetcher<'_>,
    now: DateTime<Utc>,
) -> Result<UpdateOutcome> {
    update_with_limit(cache_dir, url, fetch, now, MAX_DUMP_BYTES)
}

/// [`fetch_https`] stops at the limit itself; the size is checked again here
/// so that the limit holds for any fetcher.
fn update_with_limit(
    cache_dir: &Path,
    url: &str,
    fetch: Fetcher<'_>,
    now: DateTime<Utc>,
    max_dump_bytes: u64,
) -> Result<UpdateOutcome> {
    cache::remove_stale_temp_files(cache_dir, SystemTime::now());
    // Deleted when dropped, on success and on every early return.
    let mut dump = cache::temp_file(cache_dir)?;
    // The URL is left out of the message: a mirror URL may carry a token.
    // (Nor do the fetcher's own errors name a URL that `dump_url` accepted.)
    let fetched = fetch(url, dump.as_file_mut()).context("could not download the advisory data")?;
    let file = dump.as_file_mut();
    let size = file
        .seek(SeekFrom::End(0))
        .context("read the advisory data")?;
    if size > max_dump_bytes {
        bail!(
            "the advisory data is larger than {} MiB",
            max_dump_bytes / (1024 * 1024)
        );
    }
    file.rewind().context("read the advisory data")?;
    let built = shk_deps::build_index(BufReader::new(&mut *file))
        .context("could not read the advisory data")?;
    let modified_at = fetched
        .last_modified
        .as_deref()
        .and_then(parse_last_modified);
    cache::store(cache_dir, &built, now, modified_at)?;
    Ok(UpdateOutcome {
        records: built.records,
        skipped_records: built.skipped_records,
    })
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::io::Cursor;

    pub(crate) fn zip_of(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default();
        for (name, content) in files {
            writer.start_file(*name, options).unwrap();
            writer.write_all(content).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    /// The synthetic OSV records of `fixtures/deps`, zipped like the dump.
    pub(crate) fn fixture_dump() -> Vec<u8> {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/deps/osv/synthetic");
        let mut files: Vec<(String, Vec<u8>)> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (
                    entry.file_name().to_string_lossy().into_owned(),
                    std::fs::read(entry.path()).unwrap(),
                )
            })
            .filter(|(name, _)| !name.starts_with("BROKEN"))
            .collect();
        files.sort();
        let files: Vec<(&str, &[u8])> = files
            .iter()
            .map(|(name, content)| (name.as_str(), content.as_slice()))
            .collect();
        zip_of(&files)
    }

    /// A fetcher that serves `body`.
    pub(crate) fn serving(
        body: Vec<u8>,
        last_modified: Option<&'static str>,
    ) -> impl Fn(&str, &mut dyn Write) -> Result<Fetched> {
        move |_url, out| {
            out.write_all(&body)?;
            Ok(Fetched {
                last_modified: last_modified.map(String::from),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use shk_deps::cache::{INDEX_FILE, MANIFEST_FILE};
    use std::cell::RefCell;

    fn time(text: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(text).unwrap().to_utc()
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    const NOW: &str = "2026-11-28T12:00:00Z";

    #[test]
    fn the_dump_url_is_https_only() {
        assert_eq!(
            dump_url(None).unwrap(),
            "https://storage.googleapis.com/osv-vulnerabilities/crates.io/all.zip"
        );
        for unset in ["", "  "] {
            assert_eq!(dump_url(Some(unset)).unwrap(), dump_url(None).unwrap());
        }
        assert_eq!(
            dump_url(Some(" https://mirror.example.invalid/osv// ")).unwrap(),
            "https://mirror.example.invalid/osv/crates.io/all.zip"
        );
        assert_eq!(
            dump_url(Some("HTTPS://mirror.example.invalid")).unwrap(),
            "HTTPS://mirror.example.invalid/crates.io/all.zip"
        );
        for refused in [
            "http://mirror.example.invalid/osv",
            "file:///tmp/osv",
            "mirror.example.invalid/osv",
            "ftp://mirror.example.invalid",
            "https://",
            "https:/",
            "é",
            "https://mirror.example.invalid/osv?sig=abc",
            "https://mirror.example.invalid/osv#part",
        ] {
            assert_eq!(
                dump_url(Some(refused)).unwrap_err().to_string(),
                BAD_BASE_URL,
                "{refused}"
            );
        }
    }

    #[test]
    fn only_a_plain_200_is_accepted() {
        assert!(check_status(200).is_ok());
        for status in [204, 206, 301, 302, 303, 307, 308, 304] {
            assert_eq!(
                check_status(status).unwrap_err().to_string(),
                format!("unexpected HTTP status {status}")
            );
        }
    }

    #[test]
    fn the_agent_is_https_only_and_follows_no_redirect() {
        let agent = agent();
        let config = agent.config();
        assert!(config.https_only());
        assert_eq!(config.max_redirects(), 0);
        // With this off, a 3xx is returned as a response, not as an error
        // some caller might treat as retryable.
        assert!(!config.max_redirects_will_error());
        assert_eq!(config.timeouts().global, Some(Duration::from_secs(60)));
        assert!(matches!(
            config.user_agent(),
            ureq::config::AutoHeaderValue::Provided(value)
                if value.as_str() == concat!("shk/", env!("CARGO_PKG_VERSION"))
        ));
    }

    #[test]
    fn the_real_fetcher_refuses_plain_http_without_connecting() {
        let mut out = Vec::new();
        // shk-ignore-next-line pii.ipv4
        let error = fetch_https("http://127.0.0.1:9/crates.io/all.zip", &mut out).unwrap_err();
        assert!(
            error.to_string().to_lowercase().contains("https"),
            "{error}"
        );
        assert!(out.is_empty());
    }

    #[test]
    fn last_modified_is_read_as_an_http_date() {
        assert_eq!(
            // shk-ignore-next-line pii.ipv6
            parse_last_modified("Fri, 27 Nov 2026 08:55:31 GMT"),
            // shk-ignore-next-line pii.ipv6
            Some(time("2026-11-27T08:55:31Z"))
        );
        assert_eq!(parse_last_modified("yesterday"), None);
        assert_eq!(parse_last_modified(""), None);
    }

    #[test]
    fn an_update_writes_the_index_and_the_freshness_record() {
        let dir = tempfile::tempdir().unwrap();
        let cache_dir = dir.path().join("shk").join("deps");
        let seen_url = RefCell::new(String::new());
        // shk-ignore-next-line pii.ipv6
        let serve = serving(fixture_dump(), Some("Fri, 27 Nov 2026 08:55:31 GMT"));
        let fetch = |url: &str, out: &mut dyn Write| {
            *seen_url.borrow_mut() = url.to_string();
            serve(url, out)
        };
        let outcome = update(
            &cache_dir,
            "https://example.invalid/all.zip",
            &fetch,
            time(NOW),
        )
        .unwrap();
        assert_eq!(*seen_url.borrow(), "https://example.invalid/all.zip");
        assert_eq!(outcome.skipped_records, 0);
        assert!(outcome.records > 15, "{outcome:?}");
        // The downloaded archive is gone.
        assert_eq!(names(&cache_dir), [MANIFEST_FILE, INDEX_FILE]);

        let loaded = cache::load(&cache_dir);
        assert!(!loaded.db.unwrap().matches("fx-simple", "1.1.9").is_empty());
        assert_eq!(loaded.data.checked_at, Some(time(NOW)));
        assert_eq!(loaded.data.modified_at, Some(time("2026-11-27T08:55:31Z")));
        let manifest = cache::load_manifest(&cache_dir).unwrap();
        assert_eq!(manifest.sources["osv:crates.io"].records, outcome.records);

        // Without a usable Last-Modified header.
        for header in [None, Some("soon")] {
            update(&cache_dir, "u", &serving(fixture_dump(), header), time(NOW)).unwrap();
            assert_eq!(cache::load(&cache_dir).data.modified_at, None);
        }
    }

    #[test]
    fn unreadable_records_are_skipped_and_counted() {
        let dir = tempfile::tempdir().unwrap();
        let record = |n: usize| {
            format!(
                r#"{{"id":"RUSTSEC-9999-{n:04}","affected":[{{"package":{{"ecosystem":"crates.io","name":"fx-{n}"}},"versions":["1.0.0"]}}]}}"#
            )
        };
        let mut files: Vec<(String, Vec<u8>)> = (0..200)
            .map(|n| (format!("RUSTSEC-9999-{n:04}.json"), record(n).into_bytes()))
            .collect();
        files.push(("BROKEN.json".into(), b"{not json".to_vec()));
        let borrowed: Vec<(&str, &[u8])> = files
            .iter()
            .map(|(name, content)| (name.as_str(), content.as_slice()))
            .collect();
        let outcome = update(
            dir.path(),
            "u",
            &serving(zip_of(&borrowed), None),
            time(NOW),
        )
        .unwrap();
        assert_eq!(
            outcome,
            UpdateOutcome {
                records: 200,
                skipped_records: 1
            }
        );
        let manifest = cache::load_manifest(dir.path()).unwrap();
        assert_eq!(manifest.sources["osv:crates.io"].skipped_records, 1);
    }

    #[test]
    fn a_failed_update_keeps_the_existing_index() {
        let dir = tempfile::tempdir().unwrap();
        let cache_dir = dir.path();
        update(cache_dir, "u", &serving(fixture_dump(), None), time(NOW)).unwrap();
        let before = (
            std::fs::read(cache_dir.join(INDEX_FILE)).unwrap(),
            std::fs::read(cache_dir.join(MANIFEST_FILE)).unwrap(),
        );
        let later = time("2026-11-29T12:00:00Z");
        let unchanged = |what: &str| {
            assert_eq!(names(cache_dir), [MANIFEST_FILE, INDEX_FILE], "{what}");
            assert_eq!(
                (
                    std::fs::read(cache_dir.join(INDEX_FILE)).unwrap(),
                    std::fs::read(cache_dir.join(MANIFEST_FILE)).unwrap(),
                ),
                before,
                "{what}"
            );
        };

        // The download fails, after writing part of the body.
        let failing = |_: &str, out: &mut dyn Write| -> Result<Fetched> {
            out.write_all(b"PK partial")?;
            bail!("connection reset")
        };
        let error = update(
            cache_dir,
            // shk-ignore-next-line pii.email
            "https://user:token@example.invalid",
            &failing,
            later,
        )
        .unwrap_err();
        assert_eq!(
            format!("{error:#}"),
            "could not download the advisory data: connection reset"
        );
        unchanged("download");

        // Not a ZIP archive, an archive with nothing usable, and one where
        // too many records are unreadable.
        let broken_record: &[u8] = b"{";
        for (what, body) in [
            ("not a zip", b"<html>error</html>".to_vec()),
            ("empty body", Vec::new()),
            ("empty archive", zip_of(&[])),
            ("no advisories", zip_of(&[("README.txt", b"hello")])),
            (
                "mostly broken",
                zip_of(&[("a.json", broken_record), ("b.json", broken_record)]),
            ),
        ] {
            let error = update(cache_dir, "u", &serving(body, None), later).unwrap_err();
            assert!(
                format!("{error:#}").starts_with("could not read the advisory data: "),
                "{what}: {error:#}"
            );
            unchanged(what);
        }
    }

    #[test]
    fn an_oversized_download_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let dump = fixture_dump();
        let size = dump.len() as u64;
        let fetch = serving(dump, None);
        let error = update_with_limit(dir.path(), "u", &fetch, time(NOW), size - 1).unwrap_err();
        assert_eq!(error.to_string(), "the advisory data is larger than 0 MiB");
        assert!(names(dir.path()).is_empty());
        // Exactly the limit is accepted.
        update_with_limit(dir.path(), "u", &fetch, time(NOW), size).unwrap();
    }

    #[test]
    fn leftovers_of_a_dead_update_are_cleaned_up() {
        let dir = tempfile::tempdir().unwrap();
        let old = dir.path().join(".tmp-dead");
        std::fs::write(&old, b"x").unwrap();
        let two_hours_ago = SystemTime::now() - Duration::from_secs(2 * 60 * 60);
        std::fs::File::options()
            .write(true)
            .open(&old)
            .unwrap()
            .set_modified(two_hours_ago)
            .unwrap();
        std::fs::write(dir.path().join(".tmp-running"), b"x").unwrap();
        update(dir.path(), "u", &serving(fixture_dump(), None), time(NOW)).unwrap();
        assert_eq!(
            names(dir.path()),
            [".tmp-running", MANIFEST_FILE, INDEX_FILE]
        );
    }

    #[test]
    fn a_cache_directory_that_cannot_be_created_fails() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        std::fs::write(&file, b"").unwrap();
        let fetch = |_: &str, _: &mut dyn Write| -> Result<Fetched> {
            panic!("nothing is downloaded without a place to put it")
        };
        assert!(update(&file.join("cache"), "u", &fetch, time(NOW)).is_err());
    }
}
