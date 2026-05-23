use anyhow::{Context, Result};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Path to the project metadata-only audit log.
pub fn log_path(repo_root: &Path) -> PathBuf {
    repo_root.join(".shk/audit.log")
}

/// Append NDJSON-compatible line(s) — **no secret values**.
pub fn append_line(repo_root: &Path, value: serde_json::Value) -> Result<()> {
    let dir = repo_root.join(".shk");
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let log = dir.join("audit.log");
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
    let line = serde_json::Value::Object(map).to_string();
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log)
        .with_context(|| format!("open {}", log.display()))?;
    writeln!(f, "{line}")?;
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
    if !path.is_file() {
        return Ok(ReadAuditLogResult {
            entries: Vec::new(),
            parse_errors: 0,
        });
    }

    let content =
        std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let mut entries = Vec::new();
    let mut parse_errors = 0;
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str(line) {
            Ok(value) => entries.push(value),
            Err(_) => parse_errors += 1,
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
}
