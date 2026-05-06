use anyhow::{Context, Result};
use std::io::Write;
use std::path::Path;

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
