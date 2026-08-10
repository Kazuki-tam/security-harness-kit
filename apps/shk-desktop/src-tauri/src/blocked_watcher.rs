//! Tails `.shk/audit.log` for the projects the UI has registered and forwards
//! newly appended `blocked` entries so the frontend can raise an OS
//! notification while the app is running.
//!
//! Polling (rather than filesystem events) keeps this cross-platform and
//! avoids watching `.shk/` directories that do not exist until the first hook
//! fires. Blocks are rare and human-paced, so a couple of seconds of latency is
//! not worth a filesystem-notification dependency.

use serde::Serialize;
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Frontend event name carrying a batch of freshly appended blocks.
pub const BLOCKED_EVENT: &str = "shk://blocked";

/// Upper bound on bytes consumed from a single log in one poll. The audit log
/// rotates at 8 MiB, so this only caps pathological catch-up reads.
const MAX_READ_BYTES: u64 = 1024 * 1024;

const EVENT_FIELD: &str = "event";
const EVENT_BLOCKED: &str = "blocked";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BlockedEvent {
    /// The project path exactly as the frontend registered it, so the UI can
    /// match the event back to a project id.
    pub project_path: String,
    pub ts: Option<String>,
    pub tool: Option<String>,
    pub hook: Option<String>,
    pub reason: Option<String>,
    pub action_category: Option<String>,
    pub display_path: Option<String>,
    pub max_severity: Option<String>,
}

#[derive(Default)]
pub struct BlockedWatcher {
    /// Project path → byte offset already consumed from its audit log.
    cursors: Mutex<HashMap<String, u64>>,
}

impl BlockedWatcher {
    /// Replace the watched set. Newly watched projects start at end-of-file so
    /// blocks recorded before the app opened do not produce notifications.
    pub fn set_watched(&self, paths: Vec<String>) {
        let mut cursors = self.cursors.lock().unwrap_or_else(|err| err.into_inner());
        let mut next = HashMap::with_capacity(paths.len());
        for path in paths {
            if path.trim().is_empty() {
                continue;
            }
            let offset = match cursors.get(&path) {
                Some(offset) => *offset,
                None => current_log_len(&audit_log_path(&path)),
            };
            next.insert(path, offset);
        }
        *cursors = next;
    }

    /// Consume everything appended since the last call across all watched logs.
    pub fn drain_new_events(&self) -> Vec<BlockedEvent> {
        let mut cursors = self.cursors.lock().unwrap_or_else(|err| err.into_inner());
        let mut events = Vec::new();
        for (project_path, offset) in cursors.iter_mut() {
            let log = audit_log_path(project_path);
            for value in read_new_blocked_entries(&log, offset) {
                events.push(blocked_event_from_value(project_path, &value));
            }
        }
        events
    }
}

fn audit_log_path(project_path: &str) -> PathBuf {
    Path::new(project_path).join(".shk").join("audit.log")
}

fn current_log_len(log: &Path) -> u64 {
    std::fs::metadata(log).map(|meta| meta.len()).unwrap_or(0)
}

/// Read complete NDJSON lines appended after `offset` and keep only `blocked`
/// entries. `offset` advances past the consumed lines; a trailing partial line
/// is left for the next poll so a half-written entry is never dropped.
fn read_new_blocked_entries(log: &Path, offset: &mut u64) -> Vec<serde_json::Value> {
    let Ok(metadata) = std::fs::metadata(log) else {
        // The log may be cleared from the UI or not exist yet; restart from the
        // beginning so a recreated file is read in full.
        *offset = 0;
        return Vec::new();
    };
    let len = metadata.len();
    if len < *offset {
        // Truncated by `Reset log`, or rotated to `audit.log.1` and recreated.
        *offset = 0;
    }
    if len == *offset {
        return Vec::new();
    }

    let Ok(mut file) = std::fs::File::open(log) else {
        return Vec::new();
    };
    if file.seek(SeekFrom::Start(*offset)).is_err() {
        return Vec::new();
    }
    let mut buf = Vec::new();
    if file.take(MAX_READ_BYTES).read_to_end(&mut buf).is_err() {
        return Vec::new();
    }

    let mut consumed = 0u64;
    let mut entries = Vec::new();
    for line in buf.split_inclusive(|byte| *byte == b'\n') {
        if !line.ends_with(b"\n") {
            break;
        }
        consumed += line.len() as u64;
        let Ok(text) = std::str::from_utf8(line) else {
            continue;
        };
        let trimmed = text.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) else {
            continue;
        };
        if value.get(EVENT_FIELD).and_then(serde_json::Value::as_str) == Some(EVENT_BLOCKED) {
            entries.push(value);
        }
    }
    *offset += consumed;
    entries
}

fn blocked_event_from_value(project_path: &str, value: &serde_json::Value) -> BlockedEvent {
    let field = |name: &str| {
        value
            .get(name)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
    };
    BlockedEvent {
        project_path: project_path.to_string(),
        ts: field("ts"),
        tool: field("tool"),
        hook: field("hook"),
        reason: field("reason"),
        action_category: field("action_category"),
        display_path: field("display_path"),
        max_severity: field("max_severity"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_log(root: &Path, contents: &str) {
        let dir = root.join(".shk");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("audit.log"), contents).unwrap();
    }

    fn append_log(root: &Path, contents: &str) {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(root.join(".shk").join("audit.log"))
            .unwrap();
        file.write_all(contents.as_bytes()).unwrap();
    }

    #[test]
    fn reads_only_blocked_entries_appended_after_the_offset() {
        let dir = tempfile::tempdir().unwrap();
        write_log(
            dir.path(),
            "{\"event\":\"blocked\",\"reason\":\"action_guard\"}\n",
        );
        let mut offset = 0;
        let log = audit_log_path(dir.path().to_str().unwrap());

        let first = read_new_blocked_entries(&log, &mut offset);
        assert_eq!(first.len(), 1);
        assert!(offset > 0);

        // A hook audit (non-blocked) entry must not notify.
        append_log(dir.path(), "{\"tool\":\"cursor\",\"finding_count\":0}\n");
        assert!(read_new_blocked_entries(&log, &mut offset).is_empty());

        append_log(
            dir.path(),
            "{\"event\":\"blocked\",\"reason\":\"finding_threshold\"}\n",
        );
        let third = read_new_blocked_entries(&log, &mut offset);
        assert_eq!(third.len(), 1);
        assert_eq!(third[0]["reason"], "finding_threshold");
    }

    #[test]
    fn leaves_a_partially_written_line_for_the_next_poll() {
        let dir = tempfile::tempdir().unwrap();
        write_log(dir.path(), "{\"event\":\"blocked\",\"reason\":\"acti");
        let log = audit_log_path(dir.path().to_str().unwrap());
        let mut offset = 0;

        assert!(read_new_blocked_entries(&log, &mut offset).is_empty());
        assert_eq!(offset, 0);

        append_log(dir.path(), "on_guard\"}\n");
        let entries = read_new_blocked_entries(&log, &mut offset);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["reason"], "action_guard");
    }

    #[test]
    fn resets_the_offset_when_the_log_is_truncated_or_rotated() {
        let dir = tempfile::tempdir().unwrap();
        write_log(dir.path(), "{\"event\":\"blocked\",\"tool\":\"cursor\"}\n");
        let log = audit_log_path(dir.path().to_str().unwrap());
        let mut offset = 0;
        assert_eq!(read_new_blocked_entries(&log, &mut offset).len(), 1);

        // Rotation renames the log away and starts a fresh, shorter file.
        write_log(dir.path(), "{\"event\":\"blocked\",\"tool\":\"codex\"}\n");
        let entries = read_new_blocked_entries(&log, &mut offset);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["tool"], "codex");
    }

    #[test]
    fn missing_log_rewinds_so_a_recreated_file_is_read_in_full() {
        let dir = tempfile::tempdir().unwrap();
        write_log(dir.path(), "{\"event\":\"blocked\"}\n");
        let log = audit_log_path(dir.path().to_str().unwrap());
        let mut offset = 0;
        assert_eq!(read_new_blocked_entries(&log, &mut offset).len(), 1);

        std::fs::remove_file(&log).unwrap();
        assert!(read_new_blocked_entries(&log, &mut offset).is_empty());
        assert_eq!(offset, 0);
    }

    #[test]
    fn newly_watched_projects_start_at_end_of_file() {
        let dir = tempfile::tempdir().unwrap();
        write_log(dir.path(), "{\"event\":\"blocked\",\"tool\":\"cursor\"}\n");
        let path = dir.path().to_str().unwrap().to_string();

        let watcher = BlockedWatcher::default();
        watcher.set_watched(vec![path.clone()]);
        assert!(watcher.drain_new_events().is_empty());

        append_log(dir.path(), "{\"event\":\"blocked\",\"tool\":\"codex\"}\n");
        let events = watcher.drain_new_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].tool.as_deref(), Some("codex"));
        assert_eq!(events[0].project_path, path);
    }

    #[test]
    fn set_watched_keeps_offsets_for_projects_that_stay_watched() {
        let dir = tempfile::tempdir().unwrap();
        write_log(dir.path(), "{\"event\":\"blocked\"}\n");
        let path = dir.path().to_str().unwrap().to_string();

        let watcher = BlockedWatcher::default();
        watcher.set_watched(vec![path.clone()]);
        append_log(dir.path(), "{\"event\":\"blocked\",\"tool\":\"cursor\"}\n");
        // Re-registering the same project must not replay the pending entry
        // twice, nor skip it.
        watcher.set_watched(vec![path.clone(), "  ".to_string()]);

        assert_eq!(watcher.drain_new_events().len(), 1);
        assert!(watcher.drain_new_events().is_empty());
    }

    #[test]
    fn dropping_a_project_stops_reporting_its_blocks() {
        let dir = tempfile::tempdir().unwrap();
        write_log(dir.path(), "");
        let path = dir.path().to_str().unwrap().to_string();

        let watcher = BlockedWatcher::default();
        watcher.set_watched(vec![path.clone()]);
        watcher.set_watched(Vec::new());
        append_log(dir.path(), "{\"event\":\"blocked\"}\n");

        assert!(watcher.drain_new_events().is_empty());
    }

    #[test]
    fn maps_action_guard_fields_onto_the_frontend_payload() {
        let value = serde_json::json!({
            "ts": "2026-08-10T01:02:03Z",
            "event": "blocked",
            "tool": "cursor",
            "hook": "pre",
            "reason": "action_guard",
            "action_category": "environment_dump",
        });
        let event = blocked_event_from_value("/tmp/demo", &value);
        assert_eq!(event.project_path, "/tmp/demo");
        assert_eq!(event.reason.as_deref(), Some("action_guard"));
        assert_eq!(event.action_category.as_deref(), Some("environment_dump"));
        assert_eq!(event.display_path, None);
    }
}
