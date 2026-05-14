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
pub fn staged_files(repo_root: &Path) -> Result<Vec<PathBuf>> {
    let out = Command::new("git")
        .args([
            "diff",
            "--cached",
            "--name-only",
            "--diff-filter=ACMR",
            "-z",
        ])
        .current_dir(repo_root)
        .output()
        .context("failed to run git")?;
    if !out.status.success() {
        bail!("git diff --cached failed");
    }
    let mut paths = Vec::new();
    for chunk in out.stdout.split(|&b| b == 0) {
        if chunk.is_empty() {
            continue;
        }
        let s = std::str::from_utf8(chunk).context("git path utf-8")?;
        paths.push(PathBuf::from(s));
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

    {
        let stdin = child.stdin.as_mut().context("git cat-file stdin")?;
        for (commit, path) in &candidates {
            writeln!(
                stdin,
                "{}:{}",
                commit,
                path.to_string_lossy().replace('\\', "/")
            )
            .context("write git cat-file query")?;
        }
    }

    let out = child
        .wait_with_output()
        .context("wait for git cat-file --batch-check")?;
    if !out.status.success() {
        bail!("git cat-file --batch-check failed");
    }

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
    fn is_full_hex_oid_requires_forty_hex_chars() {
        assert!(is_full_hex_oid("abcdefabcdefabcdefabcdefabcdefabcdefabcd"));
        assert!(!is_full_hex_oid("abcdef"));
        assert!(!is_full_hex_oid("gggggggggggggggggggggggggggggggggggggggg"));
    }
}
