//! `shk deps` (experimental).

use crate::args::SeverityArg;
use crate::deps_fetch::{self, Fetcher, UpdateOutcome};
use crate::exit::CliExit;
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use shk_core::finding::Finding;
use shk_core::policy::{Policy, Severity};
use shk_deps::audit::{AuditRequest, DepsAuditReport};
use shk_deps::model::SOURCE_OSV_CRATES_IO;
use shk_deps::text::escape_control;
use shk_deps::{DepsConfig, cache};
use std::ffi::OsString;
use std::path::PathBuf;

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
        SOURCE_OSV_CRATES_IO,
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

pub struct DepsAuditInvocation {
    pub path: PathBuf,
    pub json: bool,
    pub sarif: bool,
    pub fail_on: Option<SeverityArg>,
    pub update: bool,
    pub verbose: bool,
    pub color_enabled: bool,
}

/// What `shk deps audit` prints and how it exits.
#[derive(Debug)]
struct AuditOutput {
    stdout: String,
    /// Lines for standard error.
    warnings: Vec<String>,
    /// A finding reached the threshold: exit 1.
    fail: bool,
}

/// `shk deps audit`: exit 0 when no finding reaches the threshold (also when
/// there is no lockfile), 1 when one does, 2 when the audit could not run.
pub fn audit(inv: DepsAuditInvocation) -> Result<()> {
    run_audit(&inv, &DepsEnv::from_process(), &deps_fetch::fetch_https)
}

fn run_audit(inv: &DepsAuditInvocation, env: &DepsEnv, fetch: Fetcher<'_>) -> Result<()> {
    match audit_with(inv, env, fetch) {
        Ok(output) => {
            for warning in &output.warnings {
                eprintln!("warning: {warning}");
            }
            print!("{}", output.stdout);
            if output.fail {
                return Err(CliExit::silent(1).into());
            }
            Ok(())
        }
        // Nothing goes to standard output, whatever the format.
        Err(error) => Err(CliExit::message(2, format!("shk deps audit: {error:#}")).into()),
    }
}

fn audit_with(inv: &DepsAuditInvocation, env: &DepsEnv, fetch: Fetcher<'_>) -> Result<AuditOutput> {
    if inv.json && inv.sarif {
        bail!("`--json` and `--sarif` cannot be used together");
    }
    if !inv.path.is_dir() {
        bail!("{} is not a directory", inv.path.display());
    }
    // The same rule as `shk scan`: a local policy never applies to a
    // project outside the working directory.
    let policy_root = shk_core::scanner::policy_root_for_scan(&inv.path);
    let (policy, policy_file) = Policy::load_from_dir(&policy_root)?;
    let config = DepsConfig::from_policy(&policy)?;
    let threshold = inv.fail_on.map(Severity::from).unwrap_or(config.fail_on);
    let now = env.now()?;
    let cache_dir = cache::resolve_dir(env.cache_dir.as_deref())?;

    // A failed download is not the end: the audit goes on with the index
    // already there and says that the data may be old.
    let update_error = if inv.update {
        let url = env.dump_url()?;
        deps_fetch::update(&cache_dir, &url, fetch, now)
            .err()
            .map(|error| format!("{error:#}"))
    } else {
        None
    };
    let mut loaded = cache::load(&cache_dir);
    loaded.data.update_error = update_error;

    let report = shk_deps::audit(&AuditRequest {
        target: &inv.path,
        policy_root: &policy_root,
        policy: &policy,
        has_policy_file: policy_file.is_some(),
        config: &config,
        threshold,
        db: loaded.db.as_ref(),
        data: &loaded.data,
        now,
    })
    .with_context(|| match &loaded.data.update_error {
        Some(error) => format!("the update failed ({})", escape_control(error)),
        None => "the audit could not run".to_string(),
    })?;

    let stdout = if inv.sarif {
        let sarif = crate::sarif::report_deps(
            &report.findings,
            serde_json::json!({
                "sources": report.sources,
                "inventory": report.inventory,
                "data": report.data,
                "suppressed": report.summary.suppressed,
                "exitThreshold": report.exit_threshold,
            }),
        );
        format!("{}\n", serde_json::to_string_pretty(&sarif)?)
    } else if inv.json {
        format!("{}\n", serde_json::to_string_pretty(&report)?)
    } else {
        human_report(&report, inv.verbose, inv.color_enabled)
    };
    Ok(AuditOutput {
        stdout,
        warnings: report
            .walk_errors
            .iter()
            .map(|error| format!("could not read part of the tree: {}", escape_control(error)))
            .collect(),
        fail: report.should_fail(),
    })
}

fn plural(count: usize, noun: &str) -> String {
    if count == 1 {
        format!("{count} {noun}")
    } else {
        format!("{count} {noun}s")
    }
}

/// `2026-11-27T09:12:00Z` as `2026-11-27 09:12 UTC`.
fn checked_label(report: &DepsAuditReport) -> String {
    report
        .data
        .get(SOURCE_OSV_CRATES_IO)
        .and_then(|status| status.checked_at.as_deref())
        .and_then(|text| DateTime::parse_from_rfc3339(text).ok())
        .map(|time| {
            format!(
                "data checked {}",
                time.to_utc().format("%Y-%m-%d %H:%M UTC")
            )
        })
        .unwrap_or_else(|| "data checked: unknown".to_string())
}

fn human_report(report: &DepsAuditReport, verbose: bool, color: bool) -> String {
    if report.lockfiles_found == 0 {
        return "Dependency audit: no lockfiles found\n".to_string();
    }
    let packages: usize = report
        .inventory
        .packages
        .iter()
        .map(|entry| entry.total)
        .sum();
    let skipped: usize = report
        .inventory
        .packages
        .iter()
        .map(|entry| entry.skipped.total())
        .sum();
    let mut out = format!(
        "Dependency audit: {}, {} ({skipped} skipped), {}\n\n",
        plural(report.sources.len(), "lockfile"),
        plural(packages, "package"),
        checked_label(report)
    );
    // Info findings are left out here, not by the formatter, whose
    // `verbose` flag is about skipped files.
    let visible: Vec<Finding> = report
        .findings
        .iter()
        .map(|finding| &finding.finding)
        .filter(|finding| verbose || finding.severity != "info")
        .map(|finding| Finding {
            // A directory name is the one part of a finding not yet made
            // safe for a terminal.
            file: escape_control(&finding.file),
            ..finding.clone()
        })
        .collect();
    out.push_str(&crate::output::format_human_findings(
        &visible, color, true, 0,
    ));
    let count = |severity: &str| {
        report
            .summary
            .by_severity
            .get(severity)
            .copied()
            .unwrap_or(0)
    };
    out.push_str(&format!(
        "{} critical, {} high, {} medium, {} low, {} info{}\n",
        count("critical"),
        count("high"),
        count("medium"),
        count("low"),
        count("info"),
        if !verbose && count("info") > 0 {
            " (use --verbose to show info)"
        } else {
            ""
        }
    ));
    if report.summary.suppressed > 0 {
        out.push_str(&format!(
            "Suppressed {} finding(s) by [[deps.ignore]].\n",
            report.summary.suppressed
        ));
    }
    out
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

    // --- audit ---

    const SOURCES_LOCK: &str = "../../fixtures/deps/lockfiles/sources.lock";

    struct Project {
        dir: tempfile::TempDir,
        cache: tempfile::TempDir,
    }

    impl Project {
        /// A project outside the working directory, so it is its own policy
        /// root, with an index fetched an hour before `SHK_DEPS_NOW`.
        fn new(lockfile: Option<&str>, policy: &str) -> Self {
            let project = Self {
                dir: tempfile::tempdir().unwrap(),
                cache: tempfile::tempdir().unwrap(),
            };
            if let Some(lockfile) = lockfile {
                let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(lockfile);
                std::fs::copy(path, project.dir.path().join("Cargo.lock")).unwrap();
            }
            if !policy.is_empty() {
                std::fs::write(project.dir.path().join("shk.toml"), policy).unwrap();
            }
            let mut env = project.env();
            env.now = Some("2026-11-28T11:00:00Z".into());
            update_with(&env, &serving(fixture_dump(), None)).unwrap();
            project
        }

        fn env(&self) -> DepsEnv {
            env(self.cache.path())
        }

        fn inv(&self) -> DepsAuditInvocation {
            DepsAuditInvocation {
                path: self.dir.path().to_path_buf(),
                json: false,
                sarif: false,
                fail_on: None,
                update: false,
                verbose: false,
                color_enabled: false,
            }
        }

        fn run(&self, inv: &DepsAuditInvocation) -> AuditOutput {
            audit_with(inv, &self.env(), &never).unwrap()
        }

        fn error(&self, inv: &DepsAuditInvocation) -> String {
            let error = run_audit(inv, &self.env(), &never).unwrap_err();
            assert_eq!(crate::exit::code_for(&error), 2);
            error.to_string()
        }
    }

    const HEADER: &str = "Dependency audit: 1 lockfile, 8 packages (6 skipped), data checked 2026-11-28 11:00 UTC\n\n";
    const SIMPLE: &str = "CRIT  deps.vulnerable  Cargo.lock:31    fx-simple 1.1.9: RUSTSEC-9999-0001 Out-of-bounds read in fx-simple (fixed: >=1.2.0)\n";
    const UNSOUND: &str = "MED   deps.unsound  Cargo.lock:36    fx-unsound 0.8.0: RUSTSEC-9999-0010 fx-unsound exposes an unsound API (fixed: >=0.9.0)\n";

    #[test]
    fn human_output_lists_findings_then_counts() {
        let project = Project::new(Some(SOURCES_LOCK), "[deps]\nfuture = 1\n");
        let output = project.run(&project.inv());
        assert_eq!(
            output.stdout,
            format!(
                "{HEADER}3 findings\n\n{SIMPLE}{UNSOUND}LOW   policy.deps_unknown_key  shk.toml:1    Unknown key `future` in [deps] is ignored\n1 critical, 0 high, 1 medium, 1 low, 0 info\n"
            )
        );
        assert!(output.fail);
        assert!(output.warnings.is_empty());
        assert!(run_audit(&project.inv(), &project.env(), &never).is_err());
    }

    #[test]
    fn ignored_findings_are_counted_and_thresholds_apply() {
        let policy = "[thresholds]\ndeps_fail_on = \"critical\"\n\n[[deps.ignore]]\nid = \"RUSTSEC-9999-0001\"\nreason = \"test\"\n";
        let project = Project::new(Some(SOURCES_LOCK), policy);
        let mut inv = project.inv();
        let output = project.run(&inv);
        assert_eq!(
            output.stdout,
            format!(
                "{HEADER}1 findings\n\n{UNSOUND}0 critical, 0 high, 1 medium, 0 low, 0 info\nSuppressed 1 finding(s) by [[deps.ignore]].\n"
            )
        );
        assert!(!output.fail);
        assert!(run_audit(&inv, &project.env(), &never).is_ok());

        // `--fail-on` wins over the policy.
        inv.fail_on = Some(SeverityArg::Medium);
        assert!(project.run(&inv).fail);
        let error = run_audit(&inv, &project.env(), &never).unwrap_err();
        assert_eq!(crate::exit::code_for(&error), 1);
        assert!(crate::exit::is_silent(&error));
    }

    #[test]
    fn info_findings_show_only_with_verbose() {
        let project = Project::new(Some("../../fixtures/deps/lockfiles/affected.lock"), "");
        let mut inv = project.inv();
        let quiet = project.run(&inv).stdout;
        assert!(quiet.contains("\n19 findings\n\n"), "{quiet}");
        assert!(!quiet.contains("deps.notice"), "{quiet}");
        assert!(
            quiet.ends_with(
                "5 critical, 3 high, 5 medium, 6 low, 2 info (use --verbose to show info)\n"
            ),
            "{quiet}"
        );
        inv.verbose = true;
        let verbose = project.run(&inv).stdout;
        assert!(verbose.contains("\n21 findings\n\n"), "{verbose}");
        assert!(
            verbose.contains("INFO  deps.notice  Cargo.lock:99 "),
            "{verbose}"
        );
        assert!(
            verbose.ends_with("5 critical, 3 high, 5 medium, 6 low, 2 info\n"),
            "{verbose}"
        );
    }

    #[test]
    fn no_lockfile_is_not_a_failure() {
        let project = Project::new(None, "[deps]\nfuture = 1\n");
        let mut inv = project.inv();
        let output = project.run(&inv);
        assert_eq!(output.stdout, "Dependency audit: no lockfiles found\n");
        assert!(!output.fail);
        // Nor does it need an index.
        std::fs::remove_file(project.cache.path().join(cache::INDEX_FILE)).unwrap();
        inv.fail_on = Some(SeverityArg::Info);
        assert!(run_audit(&inv, &project.env(), &never).is_ok());
        inv.json = true;
        let json: serde_json::Value = serde_json::from_str(&project.run(&inv).stdout).unwrap();
        assert_eq!(json["findings"], serde_json::json!([]));
        assert_eq!(json["sources"], serde_json::json!([]));
    }

    #[test]
    fn data_of_unknown_age_is_said_to_be_so() {
        let project = Project::new(Some(SOURCES_LOCK), "");
        std::fs::remove_file(project.cache.path().join(cache::MANIFEST_FILE)).unwrap();
        let stdout = project.run(&project.inv()).stdout;
        assert!(
            stdout.starts_with(
                "Dependency audit: 1 lockfile, 8 packages (6 skipped), data checked: unknown\n\n3 findings\n"
            ),
            "{stdout}"
        );
        assert!(
            stdout.contains("LOW   deps.data_stale  Cargo.lock:1    advisory data for osv:crates.io has no recorded check time; run `shk deps update`\n"),
            "{stdout}"
        );
    }

    #[test]
    fn several_lockfiles_are_counted_together() {
        let project = Project::new(Some(SOURCES_LOCK), "");
        let sub = project.dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::copy(
            project.dir.path().join("Cargo.lock"),
            sub.join("Cargo.lock"),
        )
        .unwrap();
        let stdout = project.run(&project.inv()).stdout;
        assert!(
            stdout.starts_with(
                "Dependency audit: 2 lockfiles, 16 packages (12 skipped), data checked "
            ),
            "{stdout}"
        );
        assert!(stdout.contains("  sub/Cargo.lock:31  "), "{stdout}");
        assert_eq!(plural(1, "package"), "1 package");
        assert_eq!(plural(0, "package"), "0 packages");
    }

    #[cfg(unix)]
    #[test]
    fn control_characters_in_paths_are_escaped_for_people() {
        let project = Project::new(None, "");
        let sub = project.dir.path().join("a\u{1b}[2Jb");
        std::fs::create_dir(&sub).unwrap();
        let lock = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(SOURCES_LOCK);
        std::fs::copy(lock, sub.join("Cargo.lock")).unwrap();
        let mut inv = project.inv();
        let stdout = project.run(&inv).stdout;
        assert!(!stdout.contains('\u{1b}'), "{stdout:?}");
        assert!(
            stdout.contains("  a\\u{1b}[2Jb/Cargo.lock:31  "),
            "{stdout:?}"
        );
        // Machine output keeps the real path, encoded by the format.
        inv.json = true;
        let json: serde_json::Value = serde_json::from_str(&project.run(&inv).stdout).unwrap();
        assert_eq!(json["sources"][0], "a\u{1b}[2Jb/Cargo.lock");
    }

    #[test]
    fn what_cannot_run_is_exit_two() {
        let project = Project::new(Some(SOURCES_LOCK), "");
        let mut inv = project.inv();

        inv.path = project.dir.path().join("missing");
        assert!(project.error(&inv).ends_with("is not a directory"));
        inv.path = project.dir.path().join("Cargo.lock");
        assert!(project.error(&inv).ends_with("is not a directory"));

        let mut inv = project.inv();
        inv.json = true;
        inv.sarif = true;
        assert_eq!(
            project.error(&inv),
            "shk deps audit: `--json` and `--sarif` cannot be used together"
        );

        let inv = project.inv();
        let mut bad_now = project.env();
        bad_now.now = Some("tomorrow".into());
        let error = run_audit(&inv, &bad_now, &never).unwrap_err();
        assert_eq!(crate::exit::code_for(&error), 2);

        for (policy, message) in [
            ("[scan", "parse shk.toml"),
            (
                "[thresholds]\ndeps_fail_on = 5\n",
                "[thresholds].deps_fail_on in shk.toml must be one of",
            ),
            (
                "[deps]\nstale_after_hours = 0\n",
                "[deps].stale_after_hours in shk.toml must be an integer of 1 or more",
            ),
            (
                "[[deps.ignore]]\nid = \"A\"\n",
                "[[deps.ignore]] entry 1 in shk.toml needs a non-empty string `reason`",
            ),
            ("[scan]\nexclude = [\"[\"]\n", "invalid exclude glob"),
        ] {
            std::fs::write(project.dir.path().join("shk.toml"), policy).unwrap();
            let error = project.error(&inv);
            assert!(error.starts_with("shk deps audit: "), "{error}");
            assert!(error.contains(message), "{policy}: {error}");
        }
    }

    #[test]
    fn packages_without_an_index_are_exit_two() {
        let project = Project::new(Some(SOURCES_LOCK), "");
        let index = project.cache.path().join(cache::INDEX_FILE);
        for broken in [Some("not json"), None] {
            match broken {
                Some(content) => std::fs::write(&index, content).unwrap(),
                None => std::fs::remove_file(&index).unwrap(),
            }
            assert_eq!(
                project.error(&project.inv()),
                "shk deps audit: the audit could not run: no advisory data to audit against; run `shk deps update` first"
            );
        }
    }

    #[test]
    fn update_before_the_audit_fetches_the_data() {
        let project = Project::new(Some(SOURCES_LOCK), "");
        for name in [cache::INDEX_FILE, cache::MANIFEST_FILE] {
            std::fs::remove_file(project.cache.path().join(name)).unwrap();
        }
        let mut inv = project.inv();
        inv.update = true;
        let output = audit_with(&inv, &project.env(), &serving(fixture_dump(), None)).unwrap();
        assert!(
            output.stdout.starts_with(
                "Dependency audit: 1 lockfile, 8 packages (6 skipped), data checked 2026-11-28 12:00 UTC\n\n2 findings\n"
            ),
            "{}",
            output.stdout
        );
        assert!(cache::load(project.cache.path()).db.is_some());
    }

    fn failing(_: &str, _: &mut dyn Write) -> Result<Fetched> {
        bail!("connection\u{1b} reset")
    }

    #[test]
    fn a_failed_update_falls_back_to_the_existing_index() {
        let project = Project::new(Some(SOURCES_LOCK), "");
        let mut inv = project.inv();
        inv.update = true;
        let output = audit_with(&inv, &project.env(), &failing).unwrap();
        assert_eq!(
            output.stdout,
            format!(
                "{HEADER}3 findings\n\n{SIMPLE}{UNSOUND}LOW   deps.data_stale  Cargo.lock:1    advisory data for osv:crates.io was last checked 1 hours ago; run `shk deps update` (update failed: could not download the advisory data: connection\\u{{1b}} reset)\n1 critical, 0 high, 1 medium, 1 low, 0 info\n"
            )
        );
        inv.json = true;
        let json: serde_json::Value =
            serde_json::from_str(&audit_with(&inv, &project.env(), &failing).unwrap().stdout)
                .unwrap();
        assert_eq!(json["data"]["osv:crates.io"]["stale"], true);
        assert_eq!(
            json["data"]["osv:crates.io"]["checked_at"],
            "2026-11-28T11:00:00Z"
        );
    }

    #[test]
    fn a_failed_update_without_an_index_is_exit_two() {
        let project = Project::new(Some(SOURCES_LOCK), "");
        std::fs::remove_file(project.cache.path().join(cache::INDEX_FILE)).unwrap();
        let mut inv = project.inv();
        inv.update = true;
        let error = run_audit(&inv, &project.env(), &failing).unwrap_err();
        assert_eq!(crate::exit::code_for(&error), 2);
        assert_eq!(
            error.to_string(),
            "shk deps audit: the update failed (could not download the advisory data: connection\\u{1b} reset): no advisory data to audit against; run `shk deps update` first"
        );

        // A setting that makes the update impossible is an error, not a
        // reason to fall back.
        let project = Project::new(Some(SOURCES_LOCK), "");
        let mut bad_url = project.env();
        bad_url.osv_url = Some("http://mirror.example.invalid".into());
        let error = run_audit(&inv_with_update(&project), &bad_url, &never).unwrap_err();
        assert_eq!(crate::exit::code_for(&error), 2);
        assert!(error.to_string().contains("SHK_DEPS_OSV_URL"), "{error}");
        // Without `--update` the variable is not looked at.
        assert!(audit_with(&project.inv(), &bad_url, &never).is_ok());
    }

    fn inv_with_update(project: &Project) -> DepsAuditInvocation {
        DepsAuditInvocation {
            update: true,
            ..project.inv()
        }
    }

    #[test]
    fn json_output_is_the_report() {
        let project = Project::new(Some(SOURCES_LOCK), "");
        let mut inv = project.inv();
        inv.json = true;
        inv.fail_on = Some(SeverityArg::Low);
        let output = project.run(&inv);
        assert!(output.stdout.ends_with("}\n"));
        let json: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
        assert_eq!(json["version"], 1);
        assert_eq!(json["exit_threshold"], "low");
        assert_eq!(json["summary"]["total"], 2);
        assert_eq!(json["findings"][0]["dependency"]["package"], "fx-simple");
        assert_eq!(json["inventory"]["packages"][0]["ecosystem"], "cargo");
    }

    fn sha256_hex(text: &str) -> String {
        use sha2::{Digest, Sha256};
        Sha256::digest(text.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[test]
    fn sarif_output_splits_vulnerable_rules_and_fingerprints_results() {
        let policy = "[deps]\nfuture = 1\n\n[[deps.ignore]]\nid = \"OLD-1\"\nreason = \"r\"\nexpires = \"2020-01-01\"\n";
        let project = Project::new(Some("../../fixtures/deps/lockfiles/affected.lock"), policy);
        let mut inv = project.inv();
        inv.sarif = true;
        let output = project.run(&inv);
        assert!(output.fail);
        let sarif: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
        assert_eq!(sarif["version"], "2.1.0");
        let run = &sarif["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "shk");

        let rules: Vec<(&str, &str, &str, &str)> = run["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|rule| {
                (
                    rule["id"].as_str().unwrap(),
                    rule["name"].as_str().unwrap(),
                    rule["shortDescription"]["text"].as_str().unwrap(),
                    rule["properties"]["security-severity"].as_str().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            rules,
            [
                (
                    "deps.malicious",
                    "deps.malicious",
                    "Dependency reported as malicious",
                    "9.0"
                ),
                (
                    "deps.notice",
                    "deps.notice",
                    "Dependency with an informational advisory",
                    "0.0"
                ),
                (
                    "deps.unmaintained",
                    "deps.unmaintained",
                    "Unmaintained dependency",
                    "2.0"
                ),
                (
                    "deps.unsound",
                    "deps.unsound",
                    "Dependency with a soundness advisory",
                    "5.0"
                ),
                (
                    "deps.vulnerable/critical",
                    "deps.vulnerable",
                    "Dependency with a known vulnerability",
                    "9.0"
                ),
                (
                    "deps.vulnerable/high",
                    "deps.vulnerable",
                    "Dependency with a known vulnerability",
                    "8.0"
                ),
                (
                    "deps.vulnerable/info",
                    "deps.vulnerable",
                    "Dependency with a known vulnerability",
                    "0.0"
                ),
                (
                    "deps.vulnerable/low",
                    "deps.vulnerable",
                    "Dependency with a known vulnerability",
                    "2.0"
                ),
                (
                    "deps.vulnerable/medium",
                    "deps.vulnerable",
                    "Dependency with a known vulnerability",
                    "5.0"
                ),
                (
                    "policy.deps_ignore_expired",
                    "policy.deps_ignore_expired",
                    "Expired dependency ignore entry",
                    "2.0"
                ),
                (
                    "policy.deps_unknown_key",
                    "policy.deps_unknown_key",
                    "Unknown dependency policy key",
                    "2.0"
                ),
            ]
        );

        let results = run["results"].as_array().unwrap();
        assert_eq!(results.len(), 23);
        let result_for = |needle: &str| {
            results
                .iter()
                .find(|result| result["message"]["text"].as_str().unwrap().contains(needle))
                .unwrap()
        };
        let fingerprint = |result: &serde_json::Value| {
            result["partialFingerprints"]["primaryLocationLineHash"].clone()
        };

        let simple = result_for("fx-simple 1.1.9");
        assert_eq!(simple["ruleId"], "deps.vulnerable/critical");
        assert_eq!(simple["level"], "error");
        assert_eq!(
            fingerprint(simple),
            sha256_hex("Cargo.lock:crates.io:fx-simple:RUSTSEC-9999-0001")
        );
        assert_eq!(
            simple["properties"]["dependency"]["advisory_id"],
            "RUSTSEC-9999-0001"
        );
        assert!(simple["properties"].get("valueHash").is_none());
        // Two versions of a crate under one advisory are one alert.
        assert_eq!(
            fingerprint(result_for("fx-multi-introduced 0.1.9")),
            fingerprint(result_for("fx-multi-introduced 0.3.4"))
        );
        let expired = result_for("Expired [[deps.ignore]] entry");
        assert_eq!(expired["ruleId"], "policy.deps_ignore_expired");
        assert_eq!(
            fingerprint(expired),
            sha256_hex("shk.toml:policy.deps_ignore_expired:OLD-1")
        );
        assert!(expired["properties"].get("dependency").is_none());
        assert_eq!(
            fingerprint(result_for("Unknown key")),
            sha256_hex("shk.toml:policy.deps_unknown_key")
        );

        assert_eq!(run["properties"]["exitThreshold"], "high");
        assert_eq!(run["properties"]["suppressed"], 0);
        assert_eq!(
            run["properties"]["sources"],
            serde_json::json!(["Cargo.lock"])
        );
        assert_eq!(run["properties"]["inventory"]["packages"][0]["audited"], 22);
        assert_eq!(
            run["properties"]["data"]["osv:crates.io"]["checked_at"],
            "2026-11-28T11:00:00Z"
        );
    }
}
