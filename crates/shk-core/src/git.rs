use anyhow::{Context, Result, bail};
use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Clone, Debug)]
pub struct GitHistoryBlob {
    pub commit: String,
    pub oid: String,
    pub path: PathBuf,
}

#[derive(Clone, Debug, Default)]
pub struct GitHistoryOptions {
    pub rev: Option<String>,
    pub since: Option<String>,
    pub max_commits: Option<usize>,
}

impl GitHistoryOptions {
    pub fn scope_label(&self) -> String {
        self.rev.clone().unwrap_or_else(|| "--all".into())
    }
}

#[derive(Clone, Debug)]
pub struct GitHistoryInventory {
    pub candidate_commits: usize,
    pub candidate_paths: usize,
    pub blobs: Vec<GitHistoryBlob>,
}

impl GitHistoryBlob {
    pub fn short_commit(&self) -> &str {
        self.commit.get(..12).unwrap_or(&self.commit)
    }
}

pub fn is_inside_git_work_tree(cwd: &Path) -> bool {
    Command::new("git")
        .args(["rev-parse", "--is-inside-work-tree"])
        .current_dir(cwd)
        .output()
        .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "true")
        .unwrap_or(false)
}

/// Staged file paths relative to repo root, normalized with `/`.
///
/// Gitlink entries (submodule bumps, mode `160000`) are excluded: their staged
/// object is a commit in the submodule's object database, so `git show :<path>`
/// in the superproject would fail with "bad object".
pub fn staged_files(repo_root: &Path) -> Result<Vec<PathBuf>> {
    let out = Command::new("git")
        .args(["diff", "--cached", "--raw", "--diff-filter=ACMR", "-z"])
        .current_dir(repo_root)
        .output()
        .context("failed to run git")?;
    if !out.status.success() {
        bail!("git diff --cached failed");
    }
    parse_staged_raw_entries(&out.stdout)
}

const GITLINK_MODE: &str = "160000";

/// Parses `git diff --raw -z` output: records of
/// `:<old-mode> <new-mode> <old-oid> <new-oid> <status>\0<path>\0`, where
/// rename/copy records carry two path tokens (source, then destination).
fn parse_staged_raw_entries(stdout: &[u8]) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    let mut tokens = stdout.split(|&b| b == 0);
    while let Some(meta) = tokens.next() {
        if meta.is_empty() {
            continue;
        }
        let meta = std::str::from_utf8(meta).context("git diff meta utf-8")?;
        let mut fields = meta.trim_start_matches(':').split(' ');
        let _old_mode = fields.next();
        let new_mode = fields.next().unwrap_or("");
        let _old_oid = fields.next();
        let _new_oid = fields.next();
        let status = fields.next().unwrap_or("");

        let path_tokens = if status.starts_with('R') || status.starts_with('C') {
            2
        } else {
            1
        };
        let mut dest = None;
        for _ in 0..path_tokens {
            dest = tokens.next();
        }
        let Some(dest) = dest else {
            break;
        };
        if new_mode == GITLINK_MODE {
            continue;
        }
        let s = std::str::from_utf8(dest).context("git path utf-8")?;
        if !s.is_empty() {
            paths.push(PathBuf::from(s));
        }
    }
    Ok(paths)
}

pub fn staged_file_bytes(repo_root: &Path, rel_path: &Path) -> Result<Vec<u8>> {
    let spec = format!(":{}", rel_path.to_string_lossy().replace('\\', "/"));
    let out = Command::new("git")
        .args(["show", &spec])
        .current_dir(repo_root)
        .output()
        .with_context(|| format!("failed to read staged blob {}", rel_path.display()))?;
    if !out.status.success() {
        bail!("git show failed for staged blob {}", rel_path.display());
    }
    Ok(out.stdout)
}

/// Changed file paths relative to repo root, normalized by Git.
///
/// Uses Git's triple-dot range so CI can scan files changed on the current
/// branch relative to a merge base, e.g. `origin/main...HEAD`.
pub fn changed_files_since(repo_root: &Path, base: &str) -> Result<Vec<PathBuf>> {
    if base.starts_with('-') {
        bail!("--changed-since must be a Git revision, not an option");
    }
    let range = format!("{base}...HEAD");
    let out = Command::new("git")
        .args(["diff", "--name-only", "--diff-filter=ACMR", "-z", &range])
        .current_dir(repo_root)
        .output()
        .with_context(|| format!("failed to run git diff {range}"))?;
    if !out.status.success() {
        bail!("git diff failed for range {range}");
    }
    Ok(out
        .stdout
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .map(PathBuf::from)
        .collect())
}

pub fn history_blobs(repo_root: &Path, opts: &GitHistoryOptions) -> Result<Vec<GitHistoryBlob>> {
    Ok(history_inventory(repo_root, opts)?.blobs)
}

pub fn history_inventory(
    repo_root: &Path,
    opts: &GitHistoryOptions,
) -> Result<GitHistoryInventory> {
    if let Some(rev) = &opts.rev
        && rev.starts_with('-')
    {
        bail!("--ref must be a revision or revision range, not an option");
    }
    if let Some(since) = &opts.since
        && since.starts_with('-')
    {
        bail!("--since must be a Git date expression, not an option");
    }

    let mut args = vec![
        "log".to_string(),
        "--diff-filter=ACMR".into(),
        "--name-only".into(),
        "--format=%x1e%H".into(),
        "-z".into(),
    ];
    if let Some(since) = &opts.since {
        args.push(format!("--since={since}"));
    }
    if let Some(max) = opts.max_commits {
        args.push(format!("--max-count={max}"));
    }
    args.push(opts.rev.clone().unwrap_or_else(|| "--all".into()));

    let out = Command::new("git")
        .args(args.iter().map(String::as_str))
        .current_dir(repo_root)
        .output()
        .context("failed to run git log")?;
    if !out.status.success() {
        bail!("git log for history scan failed");
    }

    let candidates = parse_history_candidates(&out.stdout)?;
    let candidate_commits = candidates
        .iter()
        .map(|(commit, _)| commit.as_str())
        .collect::<HashSet<_>>()
        .len();
    let candidate_paths = candidates.len();
    if candidates.is_empty() {
        return Ok(GitHistoryInventory {
            candidate_commits,
            candidate_paths,
            blobs: vec![],
        });
    }
    let blobs = resolve_history_blobs(repo_root, candidates)?;
    Ok(GitHistoryInventory {
        candidate_commits,
        candidate_paths,
        blobs,
    })
}

fn parse_history_candidates(stdout: &[u8]) -> Result<Vec<(String, PathBuf)>> {
    let mut candidates = Vec::new();

    for record in stdout.split(|&b| b == 0x1e) {
        if record.is_empty() {
            continue;
        }
        let mut fields = record.split(|&b| b == 0);
        let Some(commit_chunk) = fields.next() else {
            continue;
        };
        let commit = std::str::from_utf8(commit_chunk)
            .context("git log commit utf-8")?
            .trim_start_matches('\n');
        if !is_full_hex_oid(commit) {
            continue;
        }
        for path_chunk in fields {
            if path_chunk.is_empty() {
                continue;
            }
            let path = std::str::from_utf8(path_chunk)
                .context("git log path utf-8")?
                .trim_start_matches('\n');
            if !path.is_empty() {
                candidates.push((commit.to_string(), PathBuf::from(path)));
            }
        }
    }

    Ok(candidates)
}

fn resolve_history_blobs(
    repo_root: &Path,
    candidates: Vec<(String, PathBuf)>,
) -> Result<Vec<GitHistoryBlob>> {
    let mut child = Command::new("git")
        .args(["cat-file", "--batch-check=%(objectname) %(objecttype)"])
        .current_dir(repo_root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .context("failed to run git cat-file --batch-check")?;

    // Feed queries from a separate thread while draining stdout on this one.
    // Writing everything before reading would deadlock once the queries and
    // responses both exceed the OS pipe buffer (large histories).
    let mut stdin = child.stdin.take().context("git cat-file stdin")?;
    let queries: String = candidates
        .iter()
        .map(|(commit, path)| format!("{}:{}\n", commit, path.to_string_lossy().replace('\\', "/")))
        .collect();
    let writer = std::thread::spawn(move || -> std::io::Result<()> {
        stdin.write_all(queries.as_bytes())?;
        // Drop stdin to close the pipe so git can finish.
        Ok(())
    });

    let out = child
        .wait_with_output()
        .context("wait for git cat-file --batch-check")?;
    let write_result = writer
        .join()
        .map_err(|_| anyhow::anyhow!("git cat-file writer thread panicked"))?;
    if !out.status.success() {
        bail!("git cat-file --batch-check failed");
    }
    write_result.context("write git cat-file query")?;

    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut seen_oids = HashSet::new();
    let mut blobs = Vec::new();
    for ((commit, path), line) in candidates.into_iter().zip(stdout.lines()) {
        let mut parts = line.split_whitespace();
        let Some(oid) = parts.next() else {
            continue;
        };
        let Some(kind) = parts.next() else {
            continue;
        };
        if kind != "blob" {
            continue;
        }
        // History scanning is content-oriented: scan each unique blob once, while
        // retaining one representative commit/path label for the emitted finding.
        if seen_oids.insert(oid.to_string()) {
            blobs.push(GitHistoryBlob {
                commit,
                oid: oid.to_string(),
                path,
            });
        }
    }
    Ok(blobs)
}

fn is_full_hex_oid(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn history_blob_bytes(repo_root: &Path, oid: &str) -> Result<Vec<u8>> {
    let out = Command::new("git")
        .args(["cat-file", "-p", oid])
        .current_dir(repo_root)
        .output()
        .with_context(|| format!("failed to read git blob {oid}"))?;
    if !out.status.success() {
        bail!("git cat-file failed for blob {oid}");
    }
    Ok(out.stdout)
}

pub fn discover_repo_root(start: &Path) -> Option<PathBuf> {
    let start = if start.is_absolute() {
        start.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(start)
    };
    let mut cur = std::fs::canonicalize(&start).unwrap_or(start);
    loop {
        if cur.join(".git").exists() {
            return Some(cur);
        }
        if !cur.pop() {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_commit_uses_twelve_chars_when_available() {
        let blob = GitHistoryBlob {
            commit: "1234567890abcdef".into(),
            oid: "abc".into(),
            path: PathBuf::from("secret.txt"),
        };

        assert_eq!(blob.short_commit(), "1234567890ab");
    }

    #[test]
    fn short_commit_keeps_short_values() {
        let blob = GitHistoryBlob {
            commit: "abc123".into(),
            oid: "abc".into(),
            path: PathBuf::from("secret.txt"),
        };

        assert_eq!(blob.short_commit(), "abc123");
    }

    #[test]
    fn parse_history_candidates_handles_multiple_records() {
        let commit1 = "1111111111111111111111111111111111111111";
        let commit2 = "2222222222222222222222222222222222222222";
        let raw = format!("\x1e{commit1}\0\nsrc/a.txt\0src/b.txt\0\x1e{commit2}\0\nREADME.md\0");

        let candidates = parse_history_candidates(raw.as_bytes()).unwrap();

        assert_eq!(
            candidates,
            vec![
                (commit1.to_string(), PathBuf::from("src/a.txt")),
                (commit1.to_string(), PathBuf::from("src/b.txt")),
                (commit2.to_string(), PathBuf::from("README.md")),
            ]
        );
    }

    #[test]
    fn parse_history_candidates_allows_hex_looking_paths() {
        let commit = "1111111111111111111111111111111111111111";
        let hex_path = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let raw = format!("\x1e{commit}\0\n{hex_path}\0normal.txt\0");

        let candidates = parse_history_candidates(raw.as_bytes()).unwrap();

        assert_eq!(
            candidates,
            vec![
                (commit.to_string(), PathBuf::from(hex_path)),
                (commit.to_string(), PathBuf::from("normal.txt")),
            ]
        );
    }

    #[test]
    fn parse_history_candidates_skips_malformed_records() {
        let commit = "1111111111111111111111111111111111111111";
        let raw = format!("\x1enot-a-commit\0ignored.txt\0\x1e{commit}\0\nkept.txt\0");

        let candidates = parse_history_candidates(raw.as_bytes()).unwrap();

        assert_eq!(
            candidates,
            vec![(commit.to_string(), PathBuf::from("kept.txt"))]
        );
    }

    #[test]
    fn parse_staged_raw_entries_skips_gitlinks() {
        let raw = concat!(
            ":100644 100644 1111111 2222222 M\0src/app.rs\0",
            ":160000 160000 3333333 4444444 M\0vendor/submodule\0",
            ":000000 160000 0000000 5555555 A\0vendor/new-submodule\0",
            ":000000 100644 0000000 6666666 A\0new.txt\0",
        );

        let paths = parse_staged_raw_entries(raw.as_bytes()).unwrap();

        assert_eq!(
            paths,
            vec![PathBuf::from("src/app.rs"), PathBuf::from("new.txt")]
        );
    }

    #[test]
    fn parse_staged_raw_entries_uses_rename_destination() {
        let raw = concat!(
            ":100644 100644 1111111 1111111 R100\0old/name.txt\0new/name.txt\0",
            ":100644 100644 2222222 2222222 C75\0base.txt\0copy.txt\0",
        );

        let paths = parse_staged_raw_entries(raw.as_bytes()).unwrap();

        assert_eq!(
            paths,
            vec![PathBuf::from("new/name.txt"), PathBuf::from("copy.txt")]
        );
    }

    #[test]
    fn is_full_hex_oid_requires_forty_hex_chars() {
        assert!(is_full_hex_oid("abcdefabcdefabcdefabcdefabcdefabcdefabcd"));
        assert!(!is_full_hex_oid("abcdef"));
        assert!(!is_full_hex_oid("gggggggggggggggggggggggggggggggggggggggg"));
    }
}
