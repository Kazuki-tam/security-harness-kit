//! Finding and reading `Cargo.lock` files.

use anyhow::{Context, Result, bail};
use ignore::WalkBuilder;
use serde::Deserialize;
use shk_core::policy::Policy;
use shk_core::scanner;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

pub const LOCKFILE_NAME: &str = "Cargo.lock";

/// Largest lockfile that is read. Real lockfiles are a few hundred kilobytes,
/// and parsing takes tens of times the file size in memory, so the limit
/// stays far below what a planted file would need to exhaust it.
pub const MAX_LOCKFILE_BYTES: u64 = 8 * 1024 * 1024;

/// Directories whose lockfiles are never audited: build output and vendored
/// JavaScript packages, which hold copies of other projects' lockfiles.
const ALWAYS_EXCLUDED_DIRS: [&str; 2] = ["target", "node_modules"];

const CRATES_IO_SOURCES: [&str; 2] = [
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
];

/// A lockfile to audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockfileRef {
    pub path: PathBuf,
    /// Path relative to the policy root, with `/` separators.
    pub display: String,
    /// A symbolic link that `[scan].follow_symlinks` does not allow
    /// following. It is listed, not dropped, so that a link cannot take a
    /// lockfile out of the audit unnoticed; it is never read.
    pub unfollowed_symlink: bool,
}

#[derive(Debug, Default)]
pub struct Discovery {
    /// Sorted by `display`.
    pub lockfiles: Vec<LockfileRef>,
    /// Directories that could not be read; lockfiles below them are missed.
    pub walk_errors: Vec<String>,
}

/// Finds the `Cargo.lock` files below `target`.
///
/// Files are listed the way `shk scan` lists them, so neither an `.ignore`
/// file nor a `.gitignore` rule over a tracked file hides a lockfile. A
/// `Cargo.lock` directly in `target` is taken even when Git ignores it, as
/// libraries usually do. Only `[scan].exclude` filters the result, matched
/// against the path relative to `policy_root`; `[scan].include` does not
/// apply. `target/` and `node_modules/` below `target` are always skipped.
/// The name is matched without regard to ASCII case, as file systems that
/// ignore case open `cargo.lock` for Cargo too.
pub fn discover(target: &Path, policy_root: &Path, policy: &Policy) -> Result<Discovery> {
    if !target.is_dir() {
        bail!("{} is not a directory", target.display());
    }
    let target =
        fs::canonicalize(target).with_context(|| format!("cannot resolve {}", target.display()))?;
    let policy_root = fs::canonicalize(policy_root).unwrap_or_else(|_| policy_root.to_path_buf());
    let follow_symlinks = policy.scan.follow_symlinks;

    let is_lockfile = |path: &Path| {
        path.file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|name| name.eq_ignore_ascii_case(LOCKFILE_NAME))
    };
    let listing = scanner::list_files(&target, follow_symlinks, is_lockfile);
    let mut paths: Vec<(PathBuf, bool)> = listing
        .files
        .into_iter()
        .map(|path| (path, false))
        .collect();
    let mut walk_errors = listing.walk_errors;
    let direct = target.join(LOCKFILE_NAME);
    // Where case is ignored, a listed `cargo.lock` is this same file.
    let listed = paths
        .iter()
        .any(|(path, _)| path.parent() == Some(target.as_path()));
    match fs::symlink_metadata(&direct) {
        Ok(_) if listed => {}
        Ok(metadata) if metadata.is_file() => paths.push((direct, false)),
        Ok(metadata) if metadata.is_symlink() => {
            if !follow_symlinks {
                paths.push((direct, true));
            } else if direct.is_file() {
                paths.push((direct, false));
            }
        }
        _ => {}
    }
    if !follow_symlinks {
        let (links, errors) = unfollowed_symlinks(&target, is_lockfile);
        paths.extend(links.into_iter().map(|path| (path, true)));
        // The same directories were walked twice; report each problem once.
        for error in errors {
            if !walk_errors.contains(&error) {
                walk_errors.push(error);
            }
        }
    }

    let mut seen = HashSet::new();
    let mut lockfiles = Vec::new();
    for (path, unfollowed_symlink) in paths {
        if in_always_excluded_dir(&path, &target) {
            continue;
        }
        let display = relative_display(&path, &policy_root);
        if scanner::path_matches_exclude(policy, &display)? || !seen.insert(display.clone()) {
            continue;
        }
        lockfiles.push(LockfileRef {
            path,
            display,
            unfollowed_symlink,
        });
    }
    lockfiles.sort_by(|a, b| a.display.cmp(&b.display));
    Ok(Discovery {
        lockfiles,
        walk_errors,
    })
}

/// Symbolic links below `root` that `keep` accepts, found with the walker
/// settings of [`scanner::list_files`], which leaves links out when they are
/// not followed.
fn unfollowed_symlinks(root: &Path, keep: impl Fn(&Path) -> bool) -> (Vec<PathBuf>, Vec<String>) {
    let mut walk = WalkBuilder::new(root);
    walk.standard_filters(true)
        .hidden(false)
        .git_ignore(true)
        .git_exclude(true)
        .ignore(false)
        .filter_entry(|entry| entry.file_name() != OsStr::new(".git"));
    let mut links = Vec::new();
    let mut errors = Vec::new();
    for entry in walk.build() {
        match entry {
            Ok(entry) if entry.path_is_symlink() && keep(entry.path()) => {
                links.push(entry.into_path());
            }
            Ok(_) => {}
            Err(error) => errors.push(error.to_string()),
        }
    }
    (links, errors)
}

/// Whether a directory between `target` and the file is one of
/// [`ALWAYS_EXCLUDED_DIRS`]. The components of `target` itself do not count,
/// so a directory inside `target/` can still be audited by naming it.
fn in_always_excluded_dir(path: &Path, target: &Path) -> bool {
    let relative = path.strip_prefix(target).unwrap_or(path);
    relative.parent().is_some_and(|parent| {
        parent.components().any(|component| {
            ALWAYS_EXCLUDED_DIRS
                .iter()
                .any(|dir| component.as_os_str() == OsStr::new(dir))
        })
    })
}

fn relative_display(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Where a locked package comes from, which decides whether it is audited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageSource {
    /// crates.io, through the Git index or the sparse index.
    CratesIo,
    Git,
    /// Another registry.
    OtherRegistry,
    /// No `source`: a workspace member, a path dependency or a crate
    /// `[patch]`ed to a path.
    Local,
}

impl PackageSource {
    fn classify(source: Option<&str>) -> Self {
        match source {
            None => Self::Local,
            Some(source) if CRATES_IO_SOURCES.contains(&source) => Self::CratesIo,
            Some(source) if source.starts_with("git+") => Self::Git,
            Some(_) => Self::OtherRegistry,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedPackage {
    pub name: String,
    pub version: String,
    pub source: PackageSource,
    /// 1-based position of the `name` value.
    pub line: usize,
    pub column: usize,
}

#[derive(Deserialize)]
struct RawLockfile {
    #[serde(default)]
    version: Option<toml::Value>,
    #[serde(default)]
    package: Vec<RawPackage>,
}

#[derive(Deserialize)]
struct RawPackage {
    name: toml::Spanned<String>,
    version: String,
    #[serde(default)]
    source: Option<String>,
}

/// Reads and parses a lockfile. The error is the reason the file could not
/// be audited. It never quotes the file.
pub fn read(path: &Path) -> Result<Vec<LockedPackage>, String> {
    let file = fs::File::open(path).map_err(|err| format!("cannot open the file ({err})"))?;
    let mut bytes = Vec::new();
    file.take(MAX_LOCKFILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| format!("cannot read the file ({err})"))?;
    if bytes.len() as u64 > MAX_LOCKFILE_BYTES {
        return Err(format!(
            "the file is larger than {} MiB",
            MAX_LOCKFILE_BYTES / (1024 * 1024)
        ));
    }
    let text = String::from_utf8(bytes).map_err(|_| "the file is not UTF-8".to_string())?;
    parse(&text)
}

/// Parses the text of a lockfile. Lockfile versions 3 and 4 and files
/// without a version (versions 1 and 2) list packages the same way; any
/// other version is refused instead of guessed at.
pub fn parse(text: &str) -> Result<Vec<LockedPackage>, String> {
    // The parser's own message quotes the offending value, which may be
    // anything a file named `Cargo.lock` holds: only the line is reported.
    let raw: RawLockfile = toml::from_str(text).map_err(|err| match err.span() {
        Some(span) => format!(
            "not a valid lockfile (line {})",
            LinePositions::new(text).locate(span.start).0
        ),
        None => "not a valid lockfile".to_string(),
    })?;
    match &raw.version {
        None => {}
        Some(toml::Value::Integer(3 | 4)) => {}
        Some(toml::Value::Integer(other)) => {
            return Err(format!("unsupported lockfile version {other}"));
        }
        // Not echoed: the value can be anything of any size.
        Some(_) => return Err("the lockfile version is not a number".to_string()),
    }
    let mut positions = LinePositions::new(text);
    Ok(raw
        .package
        .into_iter()
        .map(|package| {
            let (line, column) = positions.locate(package.name.span().start);
            LockedPackage {
                name: package.name.into_inner(),
                version: package.version,
                source: PackageSource::classify(package.source.as_deref()),
                line,
                column,
            }
        })
        .collect())
}

/// Turns byte offsets into 1-based line and column (in characters).
/// Offsets are expected in ascending order, as packages appear in the file,
/// so that the text is walked once; an earlier offset restarts from the top.
struct LinePositions<'a> {
    text: &'a str,
    offset: usize,
    line: usize,
    /// Characters between the start of the line and `offset`.
    column: usize,
}

impl<'a> LinePositions<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            text,
            offset: 0,
            line: 1,
            column: 0,
        }
    }

    fn locate(&mut self, offset: usize) -> (usize, usize) {
        let offset = offset.min(self.text.len());
        if offset < self.offset {
            *self = Self::new(self.text);
        }
        for byte in &self.text.as_bytes()[self.offset..offset] {
            if *byte == b'\n' {
                self.line += 1;
                self.column = 0;
            } else if byte & 0xC0 != 0x80 {
                // Not a UTF-8 continuation byte: a new character.
                self.column += 1;
            }
        }
        self.offset = offset;
        (self.line, self.column + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{lockfile_text, write_file};
    use std::process::Command;

    fn names(packages: &[LockedPackage], source: PackageSource) -> Vec<&str> {
        packages
            .iter()
            .filter(|package| package.source == source)
            .map(|package| package.name.as_str())
            .collect()
    }

    #[test]
    fn sources_decide_what_is_audited() {
        let packages = parse(&lockfile_text("sources")).unwrap();
        assert_eq!(
            names(&packages, PackageSource::CratesIo),
            ["fx-simple", "fx-unsound"]
        );
        assert_eq!(names(&packages, PackageSource::Git), ["fx-git", "fx-merge"]);
        assert_eq!(
            names(&packages, PackageSource::OtherRegistry),
            ["fx-other-registry"]
        );
        assert_eq!(
            names(&packages, PackageSource::Local),
            ["fx-app", "fx-local", "fx-malware"]
        );
    }

    #[test]
    fn unknown_source_kinds_are_not_audited() {
        for source in [
            "sparse+https://registry.example.invalid/",
            "registry+https://github.com/rust-lang/crates.io-index/",
            "path+file:///tmp/x",
            "",
        ] {
            assert_eq!(
                PackageSource::classify(Some(source)),
                PackageSource::OtherRegistry,
                "{source}"
            );
        }
    }

    #[test]
    fn lockfile_versions_three_four_and_none_read_alike() {
        let v4 = parse(&lockfile_text("affected")).unwrap();
        assert!(!v4.is_empty());
        for case in ["v3", "no-version"] {
            let packages = parse(&lockfile_text(case)).unwrap();
            assert!(
                packages
                    .iter()
                    .any(|package| package.source == PackageSource::CratesIo),
                "{case}"
            );
        }
        assert_eq!(parse(&lockfile_text("empty")).unwrap(), []);
    }

    #[test]
    fn other_lockfile_versions_are_refused() {
        assert_eq!(
            parse(&lockfile_text("unsupported-version")).unwrap_err(),
            "unsupported lockfile version 5"
        );
        assert_eq!(
            parse("version = -3\n").unwrap_err(),
            "unsupported lockfile version -3"
        );
        for text in ["version = \"4\"\n", "version = [4]\n", "version = 4.0\n"] {
            assert_eq!(
                parse(text).unwrap_err(),
                "the lockfile version is not a number",
                "{text}"
            );
        }
    }

    #[test]
    fn parse_errors_do_not_quote_the_file() {
        assert_eq!(
            parse(&lockfile_text("invalid-toml")).unwrap_err(),
            "not a valid lockfile (line 5)"
        );
        // A package without a version, a name of the wrong type, and a
        // value the parser would quote in its own message.
        for (text, line) in [
            ("[[package]]\nname = \"a\"\n", 1),
            ("\n[[package]]\nname = 1\nversion = \"1.0.0\"\n", 3),
            ("\n\npackage = \"quoted-by-the-parser\"\n", 3),
            ("package = 123456789\n", 1),
        ] {
            assert_eq!(
                parse(text).unwrap_err(),
                format!("not a valid lockfile (line {line})"),
                "{text}"
            );
        }
    }

    #[test]
    fn many_packages_on_one_line_are_located_in_one_pass() {
        let entries: Vec<String> = (0..50_000)
            .map(|n| format!("{{name=\"p{n}\",version=\"1.0.0\"}}"))
            .collect();
        let text = format!("package = [{}]\n", entries.join(","));
        let started = std::time::Instant::now();
        let packages = parse(&text).unwrap();
        assert_eq!(packages.len(), 50_000);
        assert_eq!((packages[0].line, packages[0].column), (1, 18));
        assert_eq!(packages[1].column, 18 + entries[0].len() + 1);
        assert!(packages.iter().all(|package| package.line == 1));
        // Recounting the line for every package took minutes here.
        assert!(started.elapsed() < std::time::Duration::from_secs(20));
    }

    #[test]
    fn positions_point_at_the_name_value() {
        let text = "version = 4\n\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n\n[[package]]\nversion = \"2.0.0\"\n  \"name\" = 'b'\n";
        let packages = parse(text).unwrap();
        assert_eq!((packages[0].line, packages[0].column), (4, 8));
        assert_eq!((packages[1].line, packages[1].column), (9, 12));

        // Windows line endings, multi-byte text before the value on its
        // line, and a key the lockfile format does not have.
        let text = "# é\r\n[[package]]\r\n\"名前\" = 1\r\n\"名\" = { name = \"x\" }\r\nname = \"a\"\r\nversion = \"1\"\r\n";
        let packages = parse(text).unwrap();
        assert_eq!((packages[0].line, packages[0].column), (5, 8));
        let text = "[[package]]\nversion = \"1\"\n\"n\\u0061me\"   =   \"é\"\n";
        let packages = parse(text).unwrap();
        assert_eq!(packages[0].name, "é");
        assert_eq!((packages[0].line, packages[0].column), (3, 19));
    }

    #[test]
    fn positions_handle_offsets_out_of_order() {
        let mut positions = LinePositions::new("ab\ncé\nf");
        assert_eq!(positions.locate(5), (2, 3));
        assert_eq!(positions.locate(0), (1, 1));
        assert_eq!(positions.locate(7), (3, 1));
        assert_eq!(positions.locate(99), (3, 2));
    }

    #[test]
    fn read_reports_why_a_file_cannot_be_audited() {
        let dir = tempfile::tempdir().unwrap();
        let missing = read(&dir.path().join("Cargo.lock")).unwrap_err();
        assert!(missing.starts_with("cannot open the file"), "{missing}");

        let path = write_file(dir.path(), "Cargo.lock", b"\xff\xfe");
        assert_eq!(read(&path).unwrap_err(), "the file is not UTF-8");

        let path = write_file(
            dir.path(),
            "Cargo.lock",
            lockfile_text("affected").as_bytes(),
        );
        assert!(!read(&path).unwrap().is_empty());

        // Reading a directory fails after it opens (or fails to open).
        let error = read(dir.path()).unwrap_err();
        assert!(error.starts_with("cannot "), "{error}");
    }

    #[test]
    fn oversized_lockfiles_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Cargo.lock");
        let file = fs::File::create(&path).unwrap();
        file.set_len(MAX_LOCKFILE_BYTES + 1).unwrap();
        assert_eq!(read(&path).unwrap_err(), "the file is larger than 8 MiB");
    }

    fn displays(discovery: &Discovery) -> Vec<&str> {
        discovery
            .lockfiles
            .iter()
            .map(|lockfile| lockfile.display.as_str())
            .collect()
    }

    fn discover_in(root: &Path, policy: &Policy) -> Vec<String> {
        let discovery = discover(root, root, policy).unwrap();
        displays(&discovery).into_iter().map(String::from).collect()
    }

    fn git(root: &Path, args: &[&str]) {
        let status = Command::new("git")
            .args(args)
            .current_dir(root)
            .output()
            .unwrap();
        assert!(status.status.success(), "git {args:?}: {status:?}");
    }

    #[test]
    fn finds_every_lockfile_outside_build_output() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for path in [
            "Cargo.lock",
            "crates/a/Cargo.lock",
            "target/package/x/Cargo.lock",
            "crates/a/target/debug/Cargo.lock",
            "web/node_modules/pkg/Cargo.lock",
            "crates/b/cargo.lock.bak",
            "crates/c/CARGO.LOCK",
            "crates/b/Cargo.lock.orig",
        ] {
            write_file(root, path, b"version = 4\n");
        }
        assert_eq!(
            discover_in(root, &Policy::default()),
            ["Cargo.lock", "crates/a/Cargo.lock", "crates/c/CARGO.LOCK"]
        );

        // A directory inside build output can still be audited by naming it.
        let inner = root.join("target/package/x");
        let discovery = discover(&inner, &inner, &Policy::default()).unwrap();
        assert_eq!(displays(&discovery), ["Cargo.lock"]);
        // Displayed relative to the policy root when the target lies below it.
        let discovery = discover(&root.join("crates"), root, &Policy::default()).unwrap();
        assert_eq!(
            displays(&discovery),
            ["crates/a/Cargo.lock", "crates/c/CARGO.LOCK"]
        );
    }

    #[test]
    fn exclude_applies_and_include_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_file(root, "Cargo.lock", b"");
        write_file(root, "vendor/x/Cargo.lock", b"");
        write_file(root, "tools/Cargo.lock", b"");

        let mut policy = Policy::default();
        policy.scan.include = Some(vec!["src/**".into()]);
        assert_eq!(
            discover_in(root, &policy),
            ["Cargo.lock", "tools/Cargo.lock", "vendor/x/Cargo.lock"]
        );

        policy.scan.exclude = Some(vec!["vendor/**".into(), "Cargo.lock".into()]);
        assert_eq!(discover_in(root, &policy), ["tools/Cargo.lock"]);

        // Patterns are matched from the policy root, whatever the target.
        policy.scan.exclude = Some(vec!["vendor/**".into()]);
        let discovery = discover(&root.join("vendor"), root, &policy).unwrap();
        assert!(discovery.lockfiles.is_empty());
        policy.scan.exclude = Some(vec!["x/**".into()]);
        let discovery = discover(&root.join("vendor"), root, &policy).unwrap();
        assert_eq!(displays(&discovery), ["vendor/x/Cargo.lock"]);

        policy.scan.exclude = Some(vec!["[".into()]);
        assert!(discover(root, root, &policy).is_err());
    }

    #[test]
    fn ignore_rules_do_not_hide_lockfiles() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        git(root, &["init", "-q"]);
        write_file(root, ".gitignore", b"/Cargo.lock\nuntracked/\ntracked/\n");
        write_file(root, ".ignore", b"Cargo.lock\n");
        // Ignored and untracked, directly in the target: taken.
        write_file(root, "Cargo.lock", b"");
        // Ignored and untracked, in a subdirectory: not found.
        write_file(root, "untracked/Cargo.lock", b"");
        // Ignored but tracked: found.
        write_file(root, "tracked/Cargo.lock", b"");
        git(root, &["add", "-f", "tracked/Cargo.lock"]);
        // Hidden by the `.ignore` file only: found.
        write_file(root, "dotignore/Cargo.lock", b"");

        assert_eq!(
            discover_in(root, &Policy::default()),
            ["Cargo.lock", "dotignore/Cargo.lock", "tracked/Cargo.lock"]
        );
        // The untracked one is audited by naming its directory.
        let sub = root.join("untracked");
        let discovery = discover(&sub, root, &Policy::default()).unwrap();
        assert_eq!(displays(&discovery), ["untracked/Cargo.lock"]);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_lockfiles_are_listed_and_read_only_when_followed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("project");
        let real = write_file(&root, "locks/deps.txt", b"version = 4\n");
        fs::create_dir_all(root.join("sub")).unwrap();
        std::os::unix::fs::symlink(&real, root.join("Cargo.lock")).unwrap();
        std::os::unix::fs::symlink(&real, root.join("sub/Cargo.lock")).unwrap();
        std::os::unix::fs::symlink(root.join("gone"), root.join("sub/cargo.lock.bak")).unwrap();
        write_file(&root, "plain/Cargo.lock", b"");

        let flags = |policy: &Policy| -> Vec<(String, bool)> {
            discover(&root, &root, policy)
                .unwrap()
                .lockfiles
                .into_iter()
                .map(|lockfile| (lockfile.display, lockfile.unfollowed_symlink))
                .collect()
        };
        let mut policy = Policy::default();
        assert_eq!(
            flags(&policy),
            [
                ("Cargo.lock".to_string(), true),
                ("plain/Cargo.lock".to_string(), false),
                ("sub/Cargo.lock".to_string(), true),
            ]
        );
        policy.scan.follow_symlinks = true;
        assert_eq!(
            flags(&policy),
            [
                ("Cargo.lock".to_string(), false),
                ("plain/Cargo.lock".to_string(), false),
                ("sub/Cargo.lock".to_string(), false),
            ]
        );

        // A dangling link is listed when links are not followed, and is not
        // a file when they are.
        fs::remove_file(&real).unwrap();
        assert_eq!(flags(&policy), [("plain/Cargo.lock".to_string(), false)]);
        policy.scan.follow_symlinks = false;
        assert_eq!(flags(&policy).len(), 3);
    }

    #[test]
    fn target_must_be_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let file = write_file(dir.path(), "Cargo.lock", b"");
        let policy = Policy::default();
        for target in [file, dir.path().join("missing")] {
            let error = discover(&target, dir.path(), &policy).unwrap_err();
            assert!(error.to_string().ends_with("is not a directory"), "{error}");
        }
    }
}
