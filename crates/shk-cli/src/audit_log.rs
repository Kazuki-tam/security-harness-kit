use crate::safety;
use anyhow::{Context, Result, bail};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const MAX_AUDIT_LOG_BYTES: u64 = 8 * 1024 * 1024;
const AUDIT_LOG_ROTATIONS: usize = 3;

/// Longest line `read_entries` hands to the JSON parser. Entries written by
/// `append_line` are a few hundred bytes, so anything larger is malformed or
/// hostile (a cloned repository can ship its own `.shk/audit.log`). Matches the
/// desktop watcher's limit.
const MAX_READ_LINE_BYTES: usize = 64 * 1024;

/// Path to the project metadata-only audit log.
pub fn log_path(repo_root: &Path) -> PathBuf {
    repo_root.join(".shk/audit.log")
}

/// Append NDJSON-compatible line(s) — **no secret values**.
pub fn append_line(repo_root: &Path, value: serde_json::Value) -> Result<()> {
    let dir = repo_root.join(".shk");
    safety::ensure_write_path_within(repo_root, &dir)?;
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let log = dir.join("audit.log");
    safety::ensure_write_path_within(repo_root, &log)?;
    ensure_append_target_safe(&log)?;
    let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let mut map = serde_json::Map::new();
    map.insert("ts".into(), serde_json::Value::String(ts));
    match value {
        serde_json::Value::Object(m) => {
            map.extend(m);
        }
        other => {
            map.insert("payload".into(), other);
        }
    }
    let mut line = serde_json::Value::Object(map).to_string();
    line.push('\n');
    if line.len() as u64 > MAX_AUDIT_LOG_BYTES {
        bail!("audit entry exceeds maximum log size");
    }
    rotate_if_needed(repo_root, &log, line.len() as u64, MAX_AUDIT_LOG_BYTES)?;
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut f = options
        .open(&log)
        .with_context(|| format!("open {}", log.display()))?;
    f.write_all(line.as_bytes())?;
    Ok(())
}

fn rotated_log_path(log: &Path, index: usize) -> PathBuf {
    let mut path = log.as_os_str().to_os_string();
    path.push(format!(".{index}"));
    PathBuf::from(path)
}

fn ensure_append_target_safe(log: &Path) -> Result<()> {
    ensure_regular_audit_file(log)
}

/// Refuse to mutate non-regular / hard-linked audit log targets.
fn ensure_regular_audit_file(log: &Path) -> Result<()> {
    let metadata = match std::fs::symlink_metadata(log) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err).with_context(|| format!("inspect {}", log.display())),
    };
    if !metadata.file_type().is_file() {
        bail!(
            "refusing to mutate non-regular audit log file {}",
            log.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() > 1 {
            bail!(
                "refusing to mutate hard-linked audit log file {}",
                log.display()
            );
        }
    }
    Ok(())
}

fn rotated_and_current_log_paths(log: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = (1..=AUDIT_LOG_ROTATIONS)
        .rev()
        .map(|index| rotated_log_path(log, index))
        .collect();
    paths.push(log.to_path_buf());
    paths
}

fn rotate_if_needed(
    repo_root: &Path,
    log: &Path,
    incoming_bytes: u64,
    max_bytes: u64,
) -> Result<()> {
    let current_bytes = match std::fs::metadata(log) {
        Ok(meta) => meta.len(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => 0,
        Err(err) => return Err(err).with_context(|| format!("metadata {}", log.display())),
    };
    if current_bytes.saturating_add(incoming_bytes) <= max_bytes {
        return Ok(());
    }

    for index in (1..=AUDIT_LOG_ROTATIONS).rev() {
        let source = if index == 1 {
            log.to_path_buf()
        } else {
            rotated_log_path(log, index - 1)
        };
        if !source.exists() {
            continue;
        }
        let destination = rotated_log_path(log, index);
        safety::ensure_write_path_within(repo_root, &source)?;
        safety::ensure_write_path_within(repo_root, &destination)?;
        if destination.exists() {
            std::fs::remove_file(&destination)
                .with_context(|| format!("remove {}", destination.display()))?;
        }
        std::fs::rename(&source, &destination)
            .with_context(|| format!("rotate {} to {}", source.display(), destination.display()))?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadAuditLogResult {
    pub entries: Vec<serde_json::Value>,
    pub parse_errors: usize,
}

/// Remove `.shk/audit.log` and any rotated archives (`.1` … `.N`).
///
/// Returns the number of files removed. Missing files are ignored.
pub fn clear_log(repo_root: &Path) -> Result<usize> {
    let path = log_path(repo_root);
    let mut removed = 0usize;
    for target in rotated_and_current_log_paths(&path) {
        if !target.exists() {
            continue;
        }
        safety::ensure_write_path_within(repo_root, &target)?;
        ensure_regular_audit_file(&target)?;
        std::fs::remove_file(&target).with_context(|| format!("remove {}", target.display()))?;
        removed += 1;
    }
    Ok(removed)
}

/// Read all parseable NDJSON lines from `.shk/audit.log` and its rotations.
///
/// The log is untrusted input: a cloned repository can ship its own. Reading
/// therefore holds the same line as `append_line` (no symlinked `.shk`, no
/// symlinked, non-regular or hard-linked log file) and is bounded: at most
/// `MAX_AUDIT_LOG_BYTES` — the rotation threshold, so a log written by shk is
/// always read in full — from the end of each file, and lines longer than
/// `MAX_READ_LINE_BYTES` are skipped and counted as parse errors.
pub fn read_entries(repo_root: &Path) -> Result<ReadAuditLogResult> {
    let mut result = ReadAuditLogResult {
        entries: Vec::new(),
        parse_errors: 0,
    };
    if !audit_dir_is_readable(repo_root)? {
        return Ok(result);
    }
    for path in rotated_and_current_log_paths(&log_path(repo_root)) {
        let Some(file) = open_log_for_read(&path)? else {
            continue;
        };
        read_log_tail(file, &path, &mut result)?;
    }
    Ok(result)
}

/// `Ok(false)` when there is no `.shk` directory; an error when `.shk` is
/// anything but a real directory.
fn audit_dir_is_readable(repo_root: &Path) -> Result<bool> {
    let dir = repo_root.join(".shk");
    match std::fs::symlink_metadata(&dir) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(true),
        Ok(_) => bail!(
            "refusing to read audit log through non-directory {}",
            dir.display()
        ),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err).with_context(|| format!("inspect {}", dir.display())),
    }
}

/// Open one audit log file without following symlinks. `Ok(None)` when absent.
fn open_log_for_read(log: &Path) -> Result<Option<std::fs::File>> {
    match std::fs::symlink_metadata(log) {
        Ok(metadata) => ensure_readable_audit_metadata(&metadata, log)?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).with_context(|| format!("inspect {}", log.display())),
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = match options.open(log) {
        Ok(file) => file,
        // Removed by `clear_log` or a rotation since the check above.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).with_context(|| format!("read {}", log.display())),
    };
    // Re-check the opened descriptor so a path swap between the inspection
    // and `open` cannot turn an unsafe target into a readable one.
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect {}", log.display()))?;
    ensure_readable_audit_metadata(&metadata, log)?;
    Ok(Some(file))
}

fn ensure_readable_audit_metadata(metadata: &std::fs::Metadata, log: &Path) -> Result<()> {
    if !metadata.file_type().is_file() {
        bail!(
            "refusing to read non-regular audit log file {}",
            log.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() > 1 {
            bail!(
                "refusing to read hard-linked audit log file {}",
                log.display()
            );
        }
    }
    Ok(())
}

/// Parse the newest `MAX_AUDIT_LOG_BYTES` of `file` into `result`.
fn read_log_tail(
    mut file: std::fs::File,
    path: &Path,
    result: &mut ReadAuditLogResult,
) -> Result<()> {
    let read_error = || format!("read {}", path.display());
    let len = file.metadata().with_context(read_error)?.len();
    let start = len.saturating_sub(MAX_AUDIT_LOG_BYTES);
    // When the file is over the cap, begin one byte early and drop everything
    // through the first newline: that is exactly the entry the cap cut into, or
    // just the previous entry's terminator when the cap fell on a boundary.
    let mut skip_first_line = start > 0;
    if skip_first_line {
        file.seek(SeekFrom::Start(start - 1))
            .with_context(read_error)?;
    }
    let mut reader = BufReader::new(file.take(MAX_AUDIT_LOG_BYTES + 1));
    let mut line = Vec::new();
    loop {
        let over_long = match read_bounded_line(&mut reader, &mut line) {
            Ok(Some(over_long)) => over_long,
            Ok(None) => break,
            Err(err) => return Err(err).with_context(read_error),
        };
        if std::mem::take(&mut skip_first_line) {
            continue;
        }
        if over_long {
            result.parse_errors += 1;
            continue;
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        match serde_json::from_slice(&line) {
            Ok(value) => result.entries.push(value),
            Err(_) => result.parse_errors += 1,
        }
    }
    Ok(())
}

/// Read one line into `line` without ever buffering more than
/// `MAX_READ_LINE_BYTES` of it. Returns `None` at end of input, otherwise
/// whether the line exceeded the limit (in which case `line` is empty).
fn read_bounded_line(
    reader: &mut impl BufRead,
    line: &mut Vec<u8>,
) -> std::io::Result<Option<bool>> {
    line.clear();
    let mut over_long = false;
    let mut read_any = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(read_any.then_some(over_long));
        }
        read_any = true;
        let newline = available.iter().position(|byte| *byte == b'\n');
        let content = &available[..newline.unwrap_or(available.len())];
        if !over_long && line.len() + content.len() <= MAX_READ_LINE_BYTES {
            line.extend_from_slice(content);
        } else {
            over_long = true;
            line.clear();
        }
        let consumed = newline.map_or(available.len(), |index| index + 1);
        reader.consume(consumed);
        if newline.is_some() {
            return Ok(Some(over_long));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_entries_returns_empty_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let result = read_entries(dir.path()).unwrap();
        assert!(result.entries.is_empty());
        assert_eq!(result.parse_errors, 0);
    }

    #[test]
    fn read_entries_skips_invalid_lines() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".shk")).unwrap();
        std::fs::write(log_path(dir.path()), "{\"seq\":1}\nnot-json\n{\"seq\":2}\n").unwrap();

        let result = read_entries(dir.path()).unwrap();
        assert_eq!(result.entries.len(), 2);
        assert_eq!(result.parse_errors, 1);
    }

    #[test]
    fn clear_log_removes_current_and_rotated_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".shk")).unwrap();
        let log = log_path(dir.path());
        std::fs::write(&log, "{\"seq\":1}\n").unwrap();
        std::fs::write(rotated_log_path(&log, 1), "{\"seq\":0}\n").unwrap();

        let removed = clear_log(dir.path()).unwrap();
        assert_eq!(removed, 2);
        assert!(!log.exists());
        assert!(!rotated_log_path(&log, 1).exists());
        assert_eq!(clear_log(dir.path()).unwrap(), 0);
    }

    #[test]
    fn append_line_writes_ndjson_with_timestamp() {
        let dir = tempfile::tempdir().unwrap();
        append_line(
            dir.path(),
            serde_json::json!({
                "event": "blocked",
                "tool": "cursor",
            }),
        )
        .unwrap();

        let log = std::fs::read_to_string(dir.path().join(".shk/audit.log")).unwrap();
        let line = log.lines().next().expect("one line");
        let entry: serde_json::Value = serde_json::from_str(line).unwrap();
        assert!(entry["ts"].as_str().unwrap_or_default().contains('T'));
        assert_eq!(entry["event"], "blocked");
        assert_eq!(entry["tool"], "cursor");
    }

    #[test]
    fn append_line_appends_multiple_entries() {
        let dir = tempfile::tempdir().unwrap();
        append_line(dir.path(), serde_json::json!({"seq": 1})).unwrap();
        append_line(dir.path(), serde_json::json!({"seq": 2})).unwrap();

        let lines: Vec<_> = std::fs::read_to_string(dir.path().join(".shk/audit.log"))
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["seq"], 1);
        assert_eq!(lines[1]["seq"], 2);
    }

    #[test]
    fn rotation_keeps_bounded_archives_and_read_order() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".shk")).unwrap();
        let log = log_path(dir.path());
        std::fs::write(&log, "{\"seq\":1}\n{\"seq\":2}\n").unwrap();

        rotate_if_needed(dir.path(), &log, 20, 24).unwrap();
        std::fs::write(&log, "{\"seq\":3}\n").unwrap();

        let result = read_entries(dir.path()).unwrap();
        let seqs = result
            .entries
            .iter()
            .filter_map(|entry| entry["seq"].as_u64())
            .collect::<Vec<_>>();
        assert_eq!(seqs, vec![1, 2, 3]);
        assert!(rotated_log_path(&log, 1).is_file());
    }

    #[cfg(unix)]
    #[test]
    fn append_line_rejects_symlinked_audit_directory() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join(".shk")).unwrap();

        let err = append_line(root.path(), serde_json::json!({"seq": 1})).unwrap_err();
        assert!(err.to_string().contains("symbolic link"));
        assert!(!outside.path().join("audit.log").exists());
    }

    #[cfg(unix)]
    #[test]
    fn append_line_rejects_hard_linked_audit_file() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(".shk")).unwrap();
        let outside_file = outside.path().join("target.log");
        std::fs::write(&outside_file, b"keep\n").unwrap();
        std::fs::hard_link(&outside_file, log_path(root.path())).unwrap();

        let err = append_line(root.path(), serde_json::json!({"seq": 1})).unwrap_err();
        assert!(err.to_string().contains("hard-linked"));
        assert_eq!(std::fs::read(&outside_file).unwrap(), b"keep\n");
    }

    fn seqs(result: &ReadAuditLogResult) -> Vec<u64> {
        result
            .entries
            .iter()
            .filter_map(|entry| entry["seq"].as_u64())
            .collect()
    }

    #[cfg(unix)]
    #[test]
    fn read_entries_refuses_a_symlinked_audit_log() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(".shk")).unwrap();
        let outside_file = outside.path().join("target.log");
        std::fs::write(&outside_file, "{\"seq\":1}\n").unwrap();
        std::os::unix::fs::symlink(&outside_file, log_path(root.path())).unwrap();

        let err = read_entries(root.path()).unwrap_err();
        assert!(err.to_string().contains("refusing to read"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn read_entries_refuses_a_symlinked_rotated_log() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(".shk")).unwrap();
        let log = log_path(root.path());
        std::fs::write(&log, "{\"seq\":2}\n").unwrap();
        let outside_file = outside.path().join("target.log");
        std::fs::write(&outside_file, "{\"seq\":1}\n").unwrap();
        std::os::unix::fs::symlink(&outside_file, rotated_log_path(&log, 1)).unwrap();

        let err = read_entries(root.path()).unwrap_err();
        assert!(err.to_string().contains("refusing to read"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn read_entries_refuses_a_symlinked_audit_directory() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("audit.log"), "{\"seq\":1}\n").unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join(".shk")).unwrap();

        let err = read_entries(root.path()).unwrap_err();
        assert!(err.to_string().contains("refusing to read"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn read_entries_refuses_a_hard_linked_audit_log() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(".shk")).unwrap();
        let outside_file = outside.path().join("target.log");
        std::fs::write(&outside_file, "{\"seq\":1}\n").unwrap();
        std::fs::hard_link(&outside_file, log_path(root.path())).unwrap();

        let err = read_entries(root.path()).unwrap_err();
        assert!(err.to_string().contains("refusing to read"), "{err}");
    }

    #[test]
    fn read_entries_skips_over_long_lines() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".shk")).unwrap();
        let long = format!(
            "{{\"seq\":2,\"pad\":\"{}\"}}",
            "x".repeat(MAX_READ_LINE_BYTES)
        );
        std::fs::write(
            log_path(dir.path()),
            format!("{{\"seq\":1}}\n{long}\n{{\"seq\":3}}\n"),
        )
        .unwrap();

        let result = read_entries(dir.path()).unwrap();
        assert_eq!(seqs(&result), vec![1, 3]);
        assert_eq!(result.parse_errors, 1);
    }

    #[test]
    fn read_entries_counts_invalid_utf8_as_a_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".shk")).unwrap();
        std::fs::write(
            log_path(dir.path()),
            b"{\"seq\":1}\n\xff\xfe\n{\"seq\":2}\n",
        )
        .unwrap();

        let result = read_entries(dir.path()).unwrap();
        assert_eq!(seqs(&result), vec![1, 2]);
        assert_eq!(result.parse_errors, 1);
    }

    #[test]
    fn read_entries_reads_only_the_newest_bytes_of_an_oversized_log() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".shk")).unwrap();
        let pad = "x".repeat(1000);
        let mut content = String::new();
        let mut count = 0u64;
        while content.len() as u64 <= MAX_AUDIT_LOG_BYTES + 4096 {
            count += 1;
            content.push_str(&format!("{{\"seq\":{count},\"pad\":\"{pad}\"}}\n"));
        }
        std::fs::write(log_path(dir.path()), &content).unwrap();

        let result = read_entries(dir.path()).unwrap();
        let seqs = seqs(&result);
        assert_eq!(seqs.last(), Some(&count));
        assert!(seqs[0] > 1, "oldest entries are beyond the byte cap");
        assert!(seqs.windows(2).all(|pair| pair[1] == pair[0] + 1));
        // The entry cut by the cap is dropped, not reported as malformed.
        assert_eq!(result.parse_errors, 0);
        let kept_bytes = content.len() / count as usize * seqs.len();
        assert!(kept_bytes as u64 <= MAX_AUDIT_LOG_BYTES);
    }

    #[test]
    fn read_entries_keeps_a_log_that_fills_the_rotation_limit_exactly() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".shk")).unwrap();
        let line = format!("{{\"pad\":\"{}\"}}\n", "x".repeat(1013));
        assert_eq!(line.len(), 1024);
        let lines = (MAX_AUDIT_LOG_BYTES / 1024) as usize;
        std::fs::write(log_path(dir.path()), line.repeat(lines)).unwrap();

        let result = read_entries(dir.path()).unwrap();
        assert_eq!(result.entries.len(), lines);
        assert_eq!(result.parse_errors, 0);
    }
}
