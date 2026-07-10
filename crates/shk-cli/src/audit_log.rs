use crate::safety;
use anyhow::{Context, Result, bail};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

const MAX_AUDIT_LOG_BYTES: u64 = 8 * 1024 * 1024;
const AUDIT_LOG_ROTATIONS: usize = 3;

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
    let metadata = match std::fs::symlink_metadata(log) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err).with_context(|| format!("inspect {}", log.display())),
    };
    if !metadata.file_type().is_file() {
        bail!(
            "refusing to append audit data to non-regular file {}",
            log.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() > 1 {
            bail!(
                "refusing to append audit data to hard-linked file {}",
                log.display()
            );
        }
    }
    Ok(())
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

/// Read all parseable NDJSON lines from `.shk/audit.log`.
pub fn read_entries(repo_root: &Path) -> Result<ReadAuditLogResult> {
    let path = log_path(repo_root);
    let mut entries = Vec::new();
    let mut parse_errors = 0;
    let paths = (1..=AUDIT_LOG_ROTATIONS)
        .rev()
        .map(|index| rotated_log_path(&path, index))
        .chain(std::iter::once(path.clone()));
    for path in paths {
        if !path.is_file() {
            continue;
        }
        let file =
            std::fs::File::open(&path).with_context(|| format!("read {}", path.display()))?;
        for line in BufReader::new(file).lines() {
            let line = line.with_context(|| format!("read line from {}", path.display()))?;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str(&line) {
                Ok(value) => entries.push(value),
                Err(_) => parse_errors += 1,
            }
        }
    }
    Ok(ReadAuditLogResult {
        entries,
        parse_errors,
    })
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
}
