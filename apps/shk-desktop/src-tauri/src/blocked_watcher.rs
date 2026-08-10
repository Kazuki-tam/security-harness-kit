//! Tails `.shk/audit.log` for the projects the UI has registered and forwards
//! newly appended `blocked` entries so the frontend can raise an OS
//! notification while the app is running.
//!
//! Polling (rather than filesystem events) keeps this cross-platform and
//! avoids watching `.shk/` directories that do not exist until the first hook
//! fires. In steady state each project costs one `stat` per poll, so the idle
//! cost is negligible and a filesystem-notification dependency would buy
//! nothing measurable.
//!
//! The log is treated as untrusted input: a cloned repository can ship an
//! arbitrary `.shk/audit.log`, and anything read here can end up in an OS
//! notification that renders on a lock screen.

use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::io::{ErrorKind, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Frontend event name carrying a batch of freshly appended blocks.
pub const BLOCKED_EVENT: &str = "shk://blocked";

/// Upper bound on bytes consumed from a single log in one poll. The audit log
/// rotates at 8 MiB, so this only caps pathological catch-up reads.
const MAX_READ_BYTES: u64 = 1024 * 1024;

/// Longest line worth handing to the JSON parser. Entries written by the CLI
/// are a few hundred bytes, so anything larger is malformed or hostile. An
/// unterminated run longer than this is skipped rather than waited on, so a
/// log that never gets its closing newline cannot stall a project forever.
const MAX_LINE_BYTES: usize = 64 * 1024;

/// Longest field value forwarded to the webview. The UI renders short
/// identifiers, so a longer value is not something we should be showing;
/// dropping it (rather than truncating) keeps crafted text out of the
/// notification entirely.
const MAX_FIELD_BYTES: usize = 200;

/// Most events forwarded per project per poll. Only the newest is described in
/// the notification, so a backlog is capped instead of shipped across the IPC
/// boundary in full.
const MAX_EVENTS_PER_POLL: usize = 50;

const EVENT_FIELD: &str = "event";
const EVENT_BLOCKED: &str = "blocked";

/// The subset of a `blocked` audit entry the UI actually consumes.
///
/// Deliberately narrow: `display_path` is **not** forwarded. The audit report
/// can hide paths on request (`AuditReportOptions::hide_paths`), and an OS
/// notification renders on the lock screen and is persisted by the
/// notification centre, so file names stay inside the app window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BlockedEvent {
    /// The project path exactly as the frontend registered it, so the UI can
    /// match the event back to a project id.
    pub project_path: String,
    pub tool: Option<String>,
    pub reason: Option<String>,
    pub action_category: Option<String>,
}

#[derive(Default)]
pub struct BlockedWatcher {
    /// Project path → byte offset already consumed from its audit log.
    cursors: Mutex<HashMap<String, LogCursor>>,
}

/// Position in an audit log plus whether it sits inside a hostile oversized
/// line. Keeping the discard state is what lets the reader make progress when
/// one line spans multiple bounded reads.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct LogCursor {
    offset: u64,
    discard_until_newline: bool,
}

impl BlockedWatcher {
    /// Replace the watched set. Newly watched projects start at end-of-file so
    /// blocks recorded before the app opened do not produce notifications.
    pub fn set_watched(&self, paths: Vec<String>) {
        let mut cursors = self.lock();
        let mut next = HashMap::with_capacity(paths.len());
        for path in paths {
            if path.trim().is_empty() {
                continue;
            }
            let offset = match cursors.get(&path) {
                Some(offset) => *offset,
                None => current_log_cursor(&path),
            };
            next.insert(path, offset);
        }
        *cursors = next;
    }

    /// Consume everything appended since the last call across all watched logs.
    ///
    /// File I/O runs outside the lock: a project on an unresponsive network
    /// volume can block for seconds in `stat`, and holding the cursor lock
    /// across that would stall whichever thread is registering projects.
    pub fn drain_new_events(&self) -> Vec<BlockedEvent> {
        let snapshot: Vec<(String, LogCursor)> = {
            let cursors = self.lock();
            cursors
                .iter()
                .map(|(path, offset)| (path.clone(), *offset))
                .collect()
        };
        if snapshot.is_empty() {
            return Vec::new();
        }

        let mut drained = Vec::with_capacity(snapshot.len());
        for (project_path, offset) in snapshot {
            let mut next = offset;
            let entries = read_new_blocked_entries(&project_path, &mut next);
            let events = entries
                .iter()
                .map(|value| blocked_event_from_value(&project_path, value))
                .collect::<Vec<_>>();
            drained.push((project_path, offset, next, events));
        }

        let mut events = Vec::new();
        let mut cursors = self.lock();
        for (path, expected, next, project_events) in drained {
            // Skip projects that `set_watched` unregistered or re-initialized
            // while the read was in flight. This both prevents a fresh cursor
            // from being rewound and keeps stale events from reaching the UI.
            // It also deduplicates two drains that raced from the same cursor.
            if let Some(current) = cursors.get_mut(&path)
                && *current == expected
            {
                *current = next;
                events.extend(project_events);
            }
        }
        events
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, LogCursor>> {
        // A panic in a cursor update must not disable notifications for the
        // rest of the session; the map is plain data and stays consistent.
        self.cursors.lock().unwrap_or_else(|err| err.into_inner())
    }
}

fn audit_log_path(project_path: &str) -> PathBuf {
    Path::new(project_path).join(".shk").join("audit.log")
}

fn current_log_cursor(project_path: &str) -> LogCursor {
    if audit_log_is_readable(project_path) != Some(true) {
        return LogCursor::default();
    }
    let Some(mut file) = open_audit_log(&audit_log_path(project_path)) else {
        return LogCursor::default();
    };
    let Ok(metadata) = file.metadata() else {
        return LogCursor::default();
    };
    let offset = metadata.len();
    LogCursor {
        offset,
        // If the app starts while a hook is midway through an entry, consume
        // only the rest of that entry. Rewinding would replay old blocks.
        discard_until_newline: offset > 0 && !offset_follows_newline(&mut file, offset),
    }
}

/// Reject a `.shk` or `.shk/audit.log` that is not a real directory/file.
///
/// `audit_log::append_line` refuses to write through a symlinked `.shk` or to
/// a non-regular log; reading holds the same line so a cloned repository
/// cannot point the watcher at a file outside the project. Returns `None` when
/// there is nothing safe to read, and `Some(false)` when the log is simply
/// absent (no hook has fired yet).
fn audit_log_is_readable(project_path: &str) -> Option<bool> {
    let shk_dir = Path::new(project_path).join(".shk");
    match std::fs::symlink_metadata(&shk_dir) {
        Ok(meta) if meta.file_type().is_dir() => {}
        Ok(_) => return None,
        Err(err) if err.kind() == ErrorKind::NotFound => return Some(false),
        Err(_) => return None,
    }
    match std::fs::symlink_metadata(shk_dir.join("audit.log")) {
        Ok(meta) if meta.file_type().is_file() => Some(true),
        Ok(_) => None,
        Err(err) if err.kind() == ErrorKind::NotFound => Some(false),
        Err(_) => None,
    }
}

fn open_audit_log(log: &Path) -> Option<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(log).ok()
}

/// Whether the byte before `offset` is a newline, i.e. whether the cursor
/// still lines up with entry boundaries in this file.
fn offset_follows_newline(file: &mut std::fs::File, offset: u64) -> bool {
    let mut byte = [0u8; 1];
    file.seek(SeekFrom::Start(offset - 1)).is_ok()
        && file.read_exact(&mut byte).is_ok()
        && byte[0] == b'\n'
}

/// Read complete NDJSON lines appended after `offset` and keep only `blocked`
/// entries. `offset` advances past the consumed lines; a trailing partial line
/// is left for the next poll so a half-written entry is never dropped.
///
/// Entries written between the last poll and a rotation live only in
/// `audit.log.1` and are not announced; with 2 s polls and an 8 MiB rotation
/// threshold that window is vanishingly rare, and the audit panel still lists
/// them.
fn read_new_blocked_entries(project_path: &str, cursor: &mut LogCursor) -> Vec<serde_json::Value> {
    let exists = match audit_log_is_readable(project_path) {
        Some(exists) => exists,
        None => return Vec::new(),
    };
    if !exists {
        // Cleared from the UI, or no hook has written one yet. Rewind so a
        // recreated log is read from the top.
        *cursor = LogCursor::default();
        return Vec::new();
    }

    let log = audit_log_path(project_path);
    // Any error other than "absent" (a permissions blip, an unresponsive
    // volume) must leave the cursor alone: rewinding would replay the whole
    // log as fresh notifications once the error clears.
    let Some(mut file) = open_audit_log(&log) else {
        return Vec::new();
    };
    let Ok(metadata) = file.metadata() else {
        return Vec::new();
    };
    let len = metadata.len();
    if len < cursor.offset {
        // Truncated by `Reset log`, or rotated to `audit.log.1` and recreated.
        *cursor = LogCursor::default();
    }
    if len == cursor.offset {
        return Vec::new();
    }

    // Our cursor always sits just past a newline. When it does not, this is not
    // the file we were reading: `clear_log` deletes the log and the next hook
    // recreates it, and a poll can miss that window entirely — leaving a stale
    // offset pointing into the middle of a fresh, longer file. The one valid
    // exception is a cursor deliberately discarding an oversized line.
    if cursor.offset > 0
        && !cursor.discard_until_newline
        && !offset_follows_newline(&mut file, cursor.offset)
    {
        *cursor = LogCursor::default();
    }
    if file.seek(SeekFrom::Start(cursor.offset)).is_err() {
        return Vec::new();
    }
    let mut buf = Vec::new();
    if file.take(MAX_READ_BYTES).read_to_end(&mut buf).is_err() {
        return Vec::new();
    }

    let mut consumed = 0u64;
    let mut discard_until_newline = cursor.discard_until_newline;
    let mut entries = VecDeque::with_capacity(MAX_EVENTS_PER_POLL);
    for line in buf.split_inclusive(|byte| *byte == b'\n') {
        let complete = line.ends_with(b"\n");
        if discard_until_newline {
            consumed += line.len() as u64;
            discard_until_newline = !complete;
            continue;
        }
        if !complete && line.len() < MAX_LINE_BYTES {
            // Half-written entry: wait for the rest.
            break;
        }
        consumed += line.len() as u64;
        if !complete {
            // Longer than any real entry and still unterminated — skip it
            // rather than re-reading the same bytes on every poll forever.
            // Its continuation is discarded on later bounded reads until the
            // terminating newline arrives.
            discard_until_newline = true;
            break;
        }
        if line.len() > MAX_LINE_BYTES {
            continue;
        }
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
            if entries.len() == MAX_EVENTS_PER_POLL {
                entries.pop_front();
            }
            entries.push_back(value);
        }
    }
    cursor.offset += consumed;
    cursor.discard_until_newline = discard_until_newline;
    entries.into()
}

fn blocked_event_from_value(project_path: &str, value: &serde_json::Value) -> BlockedEvent {
    BlockedEvent {
        project_path: project_path.to_string(),
        tool: short_field(value, "tool"),
        reason: short_field(value, "reason"),
        action_category: short_field(value, "action_category"),
    }
}

/// Read a string field, dropping values too long to be one of the short
/// identifiers the UI knows how to label.
fn short_field(value: &serde_json::Value, name: &str) -> Option<String> {
    let raw = value.get(name)?.as_str()?;
    (raw.len() <= MAX_FIELD_BYTES).then(|| raw.to_string())
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

    fn read_from(root: &Path, cursor: &mut LogCursor) -> Vec<serde_json::Value> {
        read_new_blocked_entries(root.to_str().unwrap(), cursor)
    }

    #[test]
    fn reads_only_blocked_entries_appended_after_the_offset() {
        let dir = tempfile::tempdir().unwrap();
        write_log(
            dir.path(),
            "{\"event\":\"blocked\",\"reason\":\"action_guard\"}\n",
        );
        let mut cursor = LogCursor::default();

        let first = read_from(dir.path(), &mut cursor);
        assert_eq!(first.len(), 1);
        assert!(cursor.offset > 0);

        // A hook audit (non-blocked) entry must not notify.
        append_log(dir.path(), "{\"tool\":\"cursor\",\"finding_count\":0}\n");
        assert!(read_from(dir.path(), &mut cursor).is_empty());

        append_log(
            dir.path(),
            "{\"event\":\"blocked\",\"reason\":\"finding_threshold\"}\n",
        );
        let third = read_from(dir.path(), &mut cursor);
        assert_eq!(third.len(), 1);
        assert_eq!(third[0]["reason"], "finding_threshold");
    }

    #[test]
    fn leaves_a_partially_written_line_for_the_next_poll() {
        let dir = tempfile::tempdir().unwrap();
        write_log(dir.path(), "{\"event\":\"blocked\",\"reason\":\"acti");
        let mut cursor = LogCursor::default();

        assert!(read_from(dir.path(), &mut cursor).is_empty());
        assert_eq!(cursor.offset, 0);

        append_log(dir.path(), "on_guard\"}\n");
        let entries = read_from(dir.path(), &mut cursor);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["reason"], "action_guard");
    }

    #[test]
    fn skips_past_an_unterminated_line_longer_than_any_real_entry() {
        let dir = tempfile::tempdir().unwrap();
        let giant = "x".repeat(MAX_LINE_BYTES + 10);
        write_log(dir.path(), &giant);
        let mut cursor = LogCursor::default();

        assert!(read_from(dir.path(), &mut cursor).is_empty());
        // Without the skip the cursor would sit at 0 forever and the project
        // would never notify again.
        assert_eq!(cursor.offset, giant.len() as u64);
        assert!(cursor.discard_until_newline);

        append_log(
            dir.path(),
            "\n{\"event\":\"blocked\",\"tool\":\"cursor\"}\n",
        );
        let entries = read_from(dir.path(), &mut cursor);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["tool"], "cursor");
    }

    #[test]
    fn skips_an_oversized_line_that_spans_multiple_bounded_reads() {
        let dir = tempfile::tempdir().unwrap();
        let giant = "x".repeat(MAX_READ_BYTES as usize + MAX_LINE_BYTES + 10);
        write_log(
            dir.path(),
            &format!("{giant}\n{{\"event\":\"blocked\",\"tool\":\"codex\"}}\n"),
        );
        let mut cursor = LogCursor::default();

        // The first bounded read enters discard mode without rewinding on the
        // next poll. The second reaches the newline and resumes normal parsing.
        assert!(read_from(dir.path(), &mut cursor).is_empty());
        assert_eq!(cursor.offset, MAX_READ_BYTES);
        assert!(cursor.discard_until_newline);

        let entries = read_from(dir.path(), &mut cursor);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["tool"], "codex");
        assert!(!cursor.discard_until_newline);
    }

    #[test]
    fn consumes_but_does_not_parse_an_oversized_complete_line() {
        let dir = tempfile::tempdir().unwrap();
        let mut contents = "y".repeat(MAX_LINE_BYTES + 1);
        contents.push('\n');
        contents.push_str("{\"event\":\"blocked\",\"tool\":\"codex\"}\n");
        write_log(dir.path(), &contents);
        let mut cursor = LogCursor::default();

        let entries = read_from(dir.path(), &mut cursor);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["tool"], "codex");
        assert_eq!(cursor.offset, contents.len() as u64);
    }

    #[test]
    fn resets_the_offset_when_the_log_is_truncated_or_rotated() {
        let dir = tempfile::tempdir().unwrap();
        write_log(dir.path(), "{\"event\":\"blocked\",\"tool\":\"cursor\"}\n");
        let mut cursor = LogCursor::default();
        assert_eq!(read_from(dir.path(), &mut cursor).len(), 1);

        // Rotation renames the log away and starts a fresh, shorter file.
        write_log(dir.path(), "{\"event\":\"blocked\",\"tool\":\"codex\"}\n");
        let entries = read_from(dir.path(), &mut cursor);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["tool"], "codex");
    }

    #[test]
    fn rewinds_when_a_replacement_log_is_longer_than_the_stale_cursor() {
        let dir = tempfile::tempdir().unwrap();
        write_log(dir.path(), "{\"event\":\"blocked\",\"tool\":\"cursor\"}\n");
        let mut cursor = LogCursor::default();
        assert_eq!(read_from(dir.path(), &mut cursor).len(), 1);

        // `Reset log` deletes the file; the next hook recreates it. If a poll
        // misses the gap, only the length check would leave the cursor mid-line
        // in a fresh, longer file and silently skip the blocks before it.
        std::fs::remove_file(dir.path().join(".shk").join("audit.log")).unwrap();
        write_log(
            dir.path(),
            "{\"event\":\"blocked\",\"tool\":\"codex\"}\n{\"event\":\"blocked\",\"tool\":\"copilot\"}\n",
        );

        let entries = read_from(dir.path(), &mut cursor);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["tool"], "codex");
        assert_eq!(entries[1]["tool"], "copilot");
    }

    #[test]
    fn missing_log_rewinds_so_a_recreated_file_is_read_in_full() {
        let dir = tempfile::tempdir().unwrap();
        write_log(dir.path(), "{\"event\":\"blocked\"}\n");
        let mut cursor = LogCursor::default();
        assert_eq!(read_from(dir.path(), &mut cursor).len(), 1);

        std::fs::remove_file(dir.path().join(".shk").join("audit.log")).unwrap();
        assert!(read_from(dir.path(), &mut cursor).is_empty());
        assert_eq!(cursor, LogCursor::default());
    }

    #[test]
    fn an_unreadable_log_keeps_its_cursor_instead_of_replaying_history() {
        let dir = tempfile::tempdir().unwrap();
        write_log(dir.path(), "{\"event\":\"blocked\"}\n");
        let mut cursor = LogCursor::default();
        assert_eq!(read_from(dir.path(), &mut cursor).len(), 1);
        let settled = cursor;

        // A directory where the log should be stands in for any non-regular
        // target: it must not look like "cleared, start over".
        std::fs::remove_file(dir.path().join(".shk").join("audit.log")).unwrap();
        std::fs::create_dir(dir.path().join(".shk").join("audit.log")).unwrap();

        assert!(read_from(dir.path(), &mut cursor).is_empty());
        assert_eq!(cursor, settled);
    }

    #[cfg(unix)]
    #[test]
    fn refuses_to_read_through_a_symlinked_shk_directory() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(
            outside.path().join("audit.log"),
            "{\"event\":\"blocked\",\"tool\":\"cursor\"}\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join(".shk")).unwrap();

        let mut cursor = LogCursor::default();
        assert!(read_from(root.path(), &mut cursor).is_empty());
        assert_eq!(cursor, LogCursor::default());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_to_read_through_a_symlinked_audit_log() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("target.log");
        std::fs::write(&target, "{\"event\":\"blocked\",\"tool\":\"cursor\"}\n").unwrap();
        std::fs::create_dir_all(root.path().join(".shk")).unwrap();
        std::os::unix::fs::symlink(&target, root.path().join(".shk").join("audit.log")).unwrap();

        let mut cursor = LogCursor::default();
        assert!(read_from(root.path(), &mut cursor).is_empty());
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
    fn newly_watched_project_does_not_replay_when_last_line_is_partial() {
        let dir = tempfile::tempdir().unwrap();
        write_log(
            dir.path(),
            "{\"event\":\"blocked\",\"tool\":\"historic\"}\n{\"event\":\"blocked\",\"tool\":\"partial",
        );
        let path = dir.path().to_str().unwrap().to_string();

        let watcher = BlockedWatcher::default();
        watcher.set_watched(vec![path]);
        append_log(
            dir.path(),
            "\"}\n{\"event\":\"blocked\",\"tool\":\"fresh\"}\n",
        );

        let events = watcher.drain_new_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].tool.as_deref(), Some("fresh"));
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
    fn caps_the_backlog_forwarded_for_one_project_in_a_single_poll() {
        let dir = tempfile::tempdir().unwrap();
        write_log(dir.path(), "");
        let path = dir.path().to_str().unwrap().to_string();
        let watcher = BlockedWatcher::default();
        watcher.set_watched(vec![path]);

        for index in 0..(MAX_EVENTS_PER_POLL + 20) {
            append_log(
                dir.path(),
                &format!("{{\"event\":\"blocked\",\"tool\":\"t{index}\"}}\n"),
            );
        }

        let events = watcher.drain_new_events();
        assert_eq!(events.len(), MAX_EVENTS_PER_POLL);
        // The newest block is the one the notification describes, so it is the
        // end of the backlog that must survive the cap.
        let last = format!("t{}", MAX_EVENTS_PER_POLL + 19);
        assert_eq!(events.last().unwrap().tool.as_deref(), Some(last.as_str()));
        assert!(watcher.drain_new_events().is_empty());
    }

    #[test]
    fn drops_fields_too_long_to_be_a_known_identifier() {
        let value = serde_json::json!({
            "event": "blocked",
            "tool": "cursor",
            "reason": "x".repeat(MAX_FIELD_BYTES + 1),
            "action_category": "environment_dump",
        });
        let event = blocked_event_from_value("/tmp/demo", &value);
        assert_eq!(event.tool.as_deref(), Some("cursor"));
        assert_eq!(event.reason, None);
        assert_eq!(event.action_category.as_deref(), Some("environment_dump"));
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
            "display_path": "src/.env",
        });
        let event = blocked_event_from_value("/tmp/demo", &value);
        assert_eq!(event.project_path, "/tmp/demo");
        assert_eq!(event.reason.as_deref(), Some("action_guard"));
        assert_eq!(event.action_category.as_deref(), Some("environment_dump"));
    }
}
