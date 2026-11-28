//! `shk deps` (experimental).

use crate::deps_fetch::{self, Fetcher, UpdateOutcome};
use crate::exit::CliExit;
use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use shk_deps::cache;
use std::ffi::OsString;

/// The `SHK_DEPS_*` environment variables.
#[derive(Debug, Default)]
pub(crate) struct DepsEnv {
    /// `SHK_DEPS_CACHE_DIR`: where the index lives.
    pub(crate) cache_dir: Option<OsString>,
    /// `SHK_DEPS_OSV_URL`: base URL of an OSV mirror.
    pub(crate) osv_url: Option<OsString>,
    /// `SHK_DEPS_NOW`: the current time, for tests.
    pub(crate) now: Option<OsString>,
}

impl DepsEnv {
    pub(crate) fn from_process() -> Self {
        Self {
            cache_dir: std::env::var_os("SHK_DEPS_CACHE_DIR"),
            osv_url: std::env::var_os("SHK_DEPS_OSV_URL"),
            now: std::env::var_os("SHK_DEPS_NOW"),
        }
    }

    fn now(&self) -> Result<DateTime<Utc>> {
        let Some(value) = self.now.as_ref().filter(|value| !value.is_empty()) else {
            return Ok(Utc::now());
        };
        value
            .to_str()
            .and_then(|text| DateTime::parse_from_rfc3339(text.trim()).ok())
            .map(|time| time.to_utc())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "SHK_DEPS_NOW must be an RFC 3339 time such as 2026-11-27T09:12:00Z"
                )
            })
    }

    fn dump_url(&self) -> Result<String> {
        match &self.osv_url {
            None => deps_fetch::dump_url(None),
            Some(value) => match value.to_str() {
                Some(text) => deps_fetch::dump_url(Some(text)),
                None => bail!(deps_fetch::BAD_BASE_URL),
            },
        }
    }
}

/// `1234567` as `1,234,567`.
fn with_thousands(value: u64) -> String {
    let digits = value.to_string();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    grouped
}

fn update_with(env: &DepsEnv, fetch: Fetcher<'_>) -> Result<UpdateOutcome> {
    let now = env.now()?;
    let url = env.dump_url()?;
    let cache_dir = cache::resolve_dir(env.cache_dir.as_deref())?;
    deps_fetch::update(&cache_dir, &url, fetch, now)
}

fn update_line(outcome: &UpdateOutcome) -> String {
    let mut line = format!(
        "{}  updated  {} records",
        shk_deps::model::SOURCE_OSV_CRATES_IO,
        with_thousands(outcome.records)
    );
    if outcome.skipped_records > 0 {
        line.push_str(&format!(
            " ({} unreadable skipped)",
            with_thousands(outcome.skipped_records)
        ));
    }
    line
}

/// `shk deps update`: exit 0 on success, 2 on any failure, in which case the
/// existing index stays in place and nothing is written to standard output.
pub fn update() -> Result<()> {
    run_update(&DepsEnv::from_process(), &deps_fetch::fetch_https)
}

fn run_update(env: &DepsEnv, fetch: Fetcher<'_>) -> Result<()> {
    match update_with(env, fetch) {
        Ok(outcome) => {
            println!("{}", update_line(&outcome));
            Ok(())
        }
        Err(error) => Err(CliExit::message(2, format!("shk deps update: {error:#}")).into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deps_fetch::Fetched;
    use crate::deps_fetch::testing::{fixture_dump, serving};
    use std::io::Write;

    fn env(cache_dir: &std::path::Path) -> DepsEnv {
        DepsEnv {
            cache_dir: Some(cache_dir.into()),
            osv_url: None,
            now: Some("2026-11-28T12:00:00Z".into()),
        }
    }

    fn never(_: &str, _: &mut dyn Write) -> Result<Fetched> {
        panic!("nothing should be downloaded")
    }

    #[test]
    fn numbers_are_grouped_by_thousands() {
        for (value, text) in [
            (0, "0"),
            (999, "999"),
            (1000, "1,000"),
            (2104, "2,104"),
            (123456, "123,456"),
            (1234567, "1,234,567"),
        ] {
            assert_eq!(with_thousands(value), text);
        }
    }

    #[test]
    fn the_update_line_names_the_source_and_the_record_count() {
        let line = |records, skipped_records| {
            update_line(&UpdateOutcome {
                records,
                skipped_records,
            })
        };
        assert_eq!(line(2104, 0), "osv:crates.io  updated  2,104 records");
        assert_eq!(
            line(3099, 2),
            "osv:crates.io  updated  3,099 records (2 unreadable skipped)"
        );
    }

    #[test]
    fn an_update_fills_the_cache_named_by_the_environment() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = env(dir.path());
        env.osv_url = Some("https://mirror.example.invalid/osv/".into());
        let seen = std::cell::RefCell::new(String::new());
        let serve = serving(fixture_dump(), None);
        let fetch = |url: &str, out: &mut dyn Write| {
            *seen.borrow_mut() = url.to_string();
            serve(url, out)
        };
        let outcome = update_with(&env, &fetch).unwrap();
        assert_eq!(
            *seen.borrow(),
            "https://mirror.example.invalid/osv/crates.io/all.zip"
        );
        assert!(outcome.records > 15);
        let loaded = cache::load(dir.path());
        assert!(loaded.db.is_some());
        assert_eq!(
            loaded.data.checked_at.unwrap().to_rfc3339(),
            "2026-11-28T12:00:00+00:00"
        );
        assert!(run_update(&env, &fetch).is_ok());
    }

    #[test]
    fn bad_settings_fail_before_anything_is_downloaded() {
        let dir = tempfile::tempdir().unwrap();
        let exit = |env: &DepsEnv| {
            let error = run_update(env, &never).unwrap_err();
            assert_eq!(crate::exit::code_for(&error), 2);
            error.to_string()
        };

        let mut bad_url = env(dir.path());
        bad_url.osv_url = Some("http://mirror.example.invalid".into());
        assert_eq!(
            exit(&bad_url),
            "shk deps update: SHK_DEPS_OSV_URL must be an https:// base URL without a query or fragment"
        );

        for now in ["tomorrow", "2026-11-28", "2026-11-28 12:00:00"] {
            let mut bad_now = env(dir.path());
            bad_now.now = Some(now.into());
            assert_eq!(
                exit(&bad_now),
                "shk deps update: SHK_DEPS_NOW must be an RFC 3339 time such as 2026-11-27T09:12:00Z",
                "{now}"
            );
        }
        assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn values_that_are_not_unicode_are_refused() {
        use std::os::unix::ffi::OsStringExt;
        let dir = tempfile::tempdir().unwrap();
        let garbage = OsString::from_vec(vec![b'h', 0xff]);
        let mut bad = env(dir.path());
        bad.osv_url = Some(garbage.clone());
        assert!(run_update(&bad, &never).is_err());
        let mut bad = env(dir.path());
        bad.now = Some(garbage);
        assert!(run_update(&bad, &never).is_err());
    }

    #[test]
    fn the_clock_is_used_when_no_time_is_given() {
        for unset in [None, Some(OsString::new())] {
            let env = DepsEnv {
                now: unset,
                ..DepsEnv::default()
            };
            let before = Utc::now();
            let now = env.now().unwrap();
            assert!(now >= before && now <= Utc::now());
        }
        let env = DepsEnv {
            now: Some("2026-11-28T21:00:00+09:00".into()),
            ..DepsEnv::default()
        };
        assert_eq!(env.now().unwrap().to_rfc3339(), "2026-11-28T12:00:00+00:00");
    }

    #[test]
    fn a_failed_download_is_exit_two_and_keeps_the_index() {
        let dir = tempfile::tempdir().unwrap();
        let env = env(dir.path());
        update_with(&env, &serving(fixture_dump(), None)).unwrap();
        let before = std::fs::read(dir.path().join(cache::INDEX_FILE)).unwrap();

        let failing =
            |_: &str, _: &mut dyn Write| -> Result<Fetched> { bail!("unexpected HTTP status 302") };
        let error = run_update(&env, &failing).unwrap_err();
        assert_eq!(crate::exit::code_for(&error), 2);
        assert_eq!(
            error.to_string(),
            "shk deps update: could not download the advisory data: unexpected HTTP status 302"
        );
        assert_eq!(
            std::fs::read(dir.path().join(cache::INDEX_FILE)).unwrap(),
            before
        );
    }
}
