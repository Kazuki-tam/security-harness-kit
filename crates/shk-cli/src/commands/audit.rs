use crate::args::{AiTool, AuditReasonArg};
use crate::audit_log::{self, log_path};
use crate::hook_audit_log::{EVENT_BLOCKED, REASON_ACTION_GUARD, REASON_FINDING_THRESHOLD};
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use shk_core::policy::Severity;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct AuditInvocation {
    pub path: PathBuf,
    pub json: bool,
    pub since: Option<String>,
    pub tool: Option<AiTool>,
    pub reason: Option<AuditReasonArg>,
    pub limit: usize,
    pub hide_paths: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditReport {
    pub version: u32,
    pub log_path: String,
    pub log_exists: bool,
    pub parse_errors: usize,
    pub filters: AuditFilters,
    pub summary: AuditSummary,
    pub by_rule: Vec<CountRow>,
    pub by_tool: Vec<CountRow>,
    pub by_reason: Vec<CountRow>,
    pub by_action_category: Vec<CountRow>,
    pub recent: Vec<AuditRecentRow>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditFilters {
    pub since: Option<String>,
    pub tool: Option<String>,
    pub reason: Option<String>,
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditSummary {
    pub total_entries: usize,
    pub blocked_events: usize,
    pub hook_audit_events: usize,
    pub secrets_push_events: usize,
    pub max_severity: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CountRow {
    pub label: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditRecentRow {
    pub ts: String,
    pub tool: Option<String>,
    pub hook: Option<String>,
    pub reason: Option<String>,
    pub max_severity: Option<String>,
    pub action_category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_path: Option<String>,
    pub finding_count: Option<usize>,
}

pub fn run(inv: AuditInvocation) -> Result<()> {
    let root = std::fs::canonicalize(&inv.path).unwrap_or_else(|_| inv.path.clone());
    let read = audit_log::read_entries(&root)?;
    let report = build_report(&root, read.entries, read.parse_errors, &inv)?;

    if inv.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    print_human(&report, inv.hide_paths);
    Ok(())
}

fn build_report(
    root: &Path,
    entries: Vec<serde_json::Value>,
    parse_errors: usize,
    inv: &AuditInvocation,
) -> Result<AuditReport> {
    let since_cutoff = inv
        .since
        .as_deref()
        .map(parse_since)
        .transpose()
        .context("invalid --since value")?;

    let filtered = entries
        .into_iter()
        .filter(|entry| entry_matches_filters(entry, inv, since_cutoff))
        .collect::<Vec<_>>();

    let summary = summarize(&filtered);
    let by_rule = count_rule_ids(&filtered);
    let by_tool = count_field(&filtered, "tool");
    let by_reason = count_field(&filtered, "reason");
    let by_action_category = count_field(&filtered, "action_category");
    let recent = recent_rows(&filtered, inv.limit, inv.hide_paths);

    Ok(AuditReport {
        version: 1,
        log_path: log_path(root).display().to_string(),
        log_exists: log_path(root).is_file(),
        parse_errors,
        filters: AuditFilters {
            since: inv.since.clone(),
            tool: inv.tool.map(|t| t.kebab_str().to_string()),
            reason: inv.reason.map(reason_label),
            limit: inv.limit,
        },
        summary,
        by_rule,
        by_tool,
        by_reason,
        by_action_category,
        recent,
    })
}

fn entry_matches_filters(
    entry: &serde_json::Value,
    inv: &AuditInvocation,
    since_cutoff: Option<DateTime<Utc>>,
) -> bool {
    if let Some(tool) = inv.tool {
        if entry.get("tool").and_then(serde_json::Value::as_str) != Some(tool.kebab_str()) {
            return false;
        }
    }

    if let Some(reason) = inv.reason {
        if !matches_reason_filter(entry, reason) {
            return false;
        }
    }

    if let Some(cutoff) = since_cutoff {
        let Some(ts) = entry.get("ts").and_then(serde_json::Value::as_str) else {
            return false;
        };
        let Ok(parsed) = DateTime::parse_from_rfc3339(ts) else {
            return false;
        };
        if parsed.with_timezone(&Utc) < cutoff {
            return false;
        }
    }

    true
}

fn matches_reason_filter(entry: &serde_json::Value, reason: AuditReasonArg) -> bool {
    match reason {
        AuditReasonArg::Blocked => {
            entry.get("event").and_then(serde_json::Value::as_str) == Some(EVENT_BLOCKED)
        }
        AuditReasonArg::FindingThreshold => {
            entry.get("reason").and_then(serde_json::Value::as_str)
                == Some(REASON_FINDING_THRESHOLD)
        }
        AuditReasonArg::ActionGuard => {
            entry.get("reason").and_then(serde_json::Value::as_str) == Some(REASON_ACTION_GUARD)
        }
    }
}

fn summarize(entries: &[serde_json::Value]) -> AuditSummary {
    let mut blocked_events = 0;
    let mut hook_audit_events = 0;
    let mut secrets_push_events = 0;
    let mut max_severity: Option<Severity> = None;

    for entry in entries {
        match entry.get("event").and_then(serde_json::Value::as_str) {
            Some(EVENT_BLOCKED) => blocked_events += 1,
            _ if entry.get("action").and_then(serde_json::Value::as_str)
                == Some("secrets.push") =>
            {
                secrets_push_events += 1;
            }
            _ if entry.get("tool").is_some() && entry.get("hook").is_some() => {
                hook_audit_events += 1;
            }
            _ => {}
        }

        if let Some(sev) = entry
            .get("max_severity")
            .and_then(serde_json::Value::as_str)
            .and_then(Severity::parse)
        {
            max_severity = Some(max_severity.map_or(sev, |current| current.max(sev)));
        }
    }

    AuditSummary {
        total_entries: entries.len(),
        blocked_events,
        hook_audit_events,
        secrets_push_events,
        max_severity: max_severity.map(|s| s.as_str().to_string()),
    }
}

fn count_rule_ids(entries: &[serde_json::Value]) -> Vec<CountRow> {
    let mut counts = BTreeMap::<String, usize>::new();
    for entry in entries {
        if let Some(ids) = entry.get("rule_ids").and_then(serde_json::Value::as_array) {
            for id in ids.iter().filter_map(serde_json::Value::as_str) {
                *counts.entry(id.to_string()).or_default() += 1;
            }
        }
    }
    counts_into_rows(counts)
}

fn count_field(entries: &[serde_json::Value], field: &str) -> Vec<CountRow> {
    let mut counts = BTreeMap::<String, usize>::new();
    for entry in entries {
        if let Some(value) = entry.get(field).and_then(serde_json::Value::as_str) {
            *counts.entry(value.to_string()).or_default() += 1;
        }
    }
    counts_into_rows(counts)
}

fn counts_into_rows(counts: BTreeMap<String, usize>) -> Vec<CountRow> {
    let mut rows: Vec<_> = counts
        .into_iter()
        .map(|(label, count)| CountRow { label, count })
        .collect();
    rows.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.label.cmp(&b.label)));
    rows
}

fn recent_rows(
    entries: &[serde_json::Value],
    limit: usize,
    hide_paths: bool,
) -> Vec<AuditRecentRow> {
    let mut rows: Vec<_> = entries
        .iter()
        .filter(|entry| is_recent_candidate(entry))
        .map(|entry| to_recent_row(entry, hide_paths))
        .collect();

    rows.sort_by(|a, b| b.ts.cmp(&a.ts));
    rows.truncate(limit);
    rows
}

fn is_recent_candidate(entry: &serde_json::Value) -> bool {
    entry.get("event").and_then(serde_json::Value::as_str) == Some(EVENT_BLOCKED)
        || (entry.get("tool").is_some() && entry.get("hook").is_some())
        || entry.get("action").and_then(serde_json::Value::as_str) == Some("secrets.push")
}

fn to_recent_row(entry: &serde_json::Value, hide_paths: bool) -> AuditRecentRow {
    AuditRecentRow {
        ts: entry
            .get("ts")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("-")
            .to_string(),
        tool: entry
            .get("tool")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        hook: entry
            .get("hook")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        reason: entry_reason(entry),
        max_severity: entry
            .get("max_severity")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        action_category: entry
            .get("action_category")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        display_path: if hide_paths {
            None
        } else {
            entry
                .get("display_path")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        },
        finding_count: entry
            .get("finding_count")
            .and_then(serde_json::Value::as_u64)
            .map(|n| n as usize),
    }
}

fn entry_reason(entry: &serde_json::Value) -> Option<String> {
    if let Some(reason) = entry.get("reason").and_then(serde_json::Value::as_str) {
        return Some(reason.to_string());
    }
    if entry.get("action").and_then(serde_json::Value::as_str) == Some("secrets.push") {
        return Some("secrets.push".into());
    }
    if entry.get("tool").is_some() && entry.get("hook").is_some() {
        return Some("hook_audit".into());
    }
    None
}

fn parse_since(raw: &str) -> Result<DateTime<Utc>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("--since value must not be empty");
    }

    let (num, unit) = trimmed
        .char_indices()
        .find(|(_, ch)| !ch.is_ascii_digit())
        .map(|(idx, _)| trimmed.split_at(idx))
        .ok_or_else(|| anyhow::anyhow!("--since must look like 7d, 24h, or 30m"))?;

    let amount: i64 = num
        .parse()
        .with_context(|| format!("invalid duration number in --since `{raw}`"))?;
    if amount <= 0 {
        bail!("--since duration must be positive");
    }

    let unit = unit.to_ascii_lowercase();
    let duration = match unit.as_str() {
        "m" | "min" | "mins" => Duration::minutes(amount),
        "h" | "hr" | "hrs" => Duration::hours(amount),
        "d" | "day" | "days" => Duration::days(amount),
        "w" | "wk" | "week" | "weeks" => Duration::weeks(amount),
        _ => bail!("unsupported --since unit `{unit}` (use m, h, d, or w)"),
    };

    Ok(Utc::now() - duration)
}

fn reason_label(reason: AuditReasonArg) -> String {
    match reason {
        AuditReasonArg::Blocked => EVENT_BLOCKED.into(),
        AuditReasonArg::FindingThreshold => REASON_FINDING_THRESHOLD.into(),
        AuditReasonArg::ActionGuard => REASON_ACTION_GUARD.into(),
    }
}

fn print_human(report: &AuditReport, hide_paths: bool) {
    println!("shk audit log: {}", report.log_path);

    if !report.log_exists {
        println!();
        println!("No audit log found.");
        println!(
            "Enable logging with `shk hooks install-ai --log-blocked` or `shk scan --hook-mode <tool> --audit`."
        );
        return;
    }

    if report.parse_errors > 0 {
        println!();
        println!(
            "[warn] skipped {} invalid line(s) while parsing audit log",
            report.parse_errors
        );
    }

    if report.summary.total_entries == 0 {
        println!();
        if report.filters.since.is_some()
            || report.filters.tool.is_some()
            || report.filters.reason.is_some()
        {
            println!("No entries match the current filters.");
        } else {
            println!("No audit entries yet.");
            println!(
                "Enable logging with `shk hooks install-ai --log-blocked` or `shk scan --hook-mode <tool> --audit`."
            );
        }
        return;
    }

    println!();
    println!("Summary");
    println!("  total entries:   {}", report.summary.total_entries);
    println!("  blocked events:  {}", report.summary.blocked_events);
    println!("  hook audit:      {}", report.summary.hook_audit_events);
    println!("  secrets push:    {}", report.summary.secrets_push_events);
    if let Some(max) = &report.summary.max_severity {
        println!("  max severity:    {max}");
    }

    print_count_section("By rule", &report.by_rule);
    print_count_section("By tool", &report.by_tool);
    print_count_section("By reason", &report.by_reason);
    print_count_section("By action category", &report.by_action_category);

    if report.recent.is_empty() {
        return;
    }

    println!();
    println!("Recent events");
    for row in &report.recent {
        let ts = format_ts_short(&row.ts);
        let tool = row.tool.as_deref().unwrap_or("-");
        let hook = row.hook.as_deref().unwrap_or("-");
        let reason = row.reason.as_deref().unwrap_or("-");
        let detail = match (&row.max_severity, &row.action_category, &row.display_path) {
            (Some(sev), _, _) if reason == REASON_FINDING_THRESHOLD => sev.clone(),
            (_, Some(category), _) if reason == REASON_ACTION_GUARD => category.clone(),
            (_, _, Some(path)) if !hide_paths => path.clone(),
            _ => "-".into(),
        };
        let count = row
            .finding_count
            .map(|n| format!(" findings={n}"))
            .unwrap_or_default();
        println!("  {ts}  {tool:<12} {hook:<12} {reason:<20} {detail}{count}");
    }
}

fn print_count_section(title: &str, rows: &[CountRow]) {
    if rows.is_empty() {
        return;
    }
    println!();
    println!("{title}");
    for row in rows {
        println!("  {:<28} {}", row.label, row.count);
    }
}

fn format_ts_short(ts: &str) -> String {
    DateTime::parse_from_rfc3339(ts)
        .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|_| ts.chars().take(16).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::AuditReasonArg;

    fn entry(json: serde_json::Value) -> serde_json::Value {
        json
    }

    fn base_inv() -> AuditInvocation {
        AuditInvocation {
            path: PathBuf::from("."),
            json: false,
            since: None,
            tool: None,
            reason: None,
            limit: 10,
            hide_paths: false,
        }
    }

    #[test]
    fn summarize_counts_entry_kinds() {
        let entries = vec![
            entry(serde_json::json!({"event":"blocked","max_severity":"high"})),
            entry(serde_json::json!({"tool":"cursor","hook":"pre","finding_count":1})),
            entry(serde_json::json!({"action":"secrets.push","provider":"gcp"})),
        ];
        let summary = summarize(&entries);
        assert_eq!(summary.total_entries, 3);
        assert_eq!(summary.blocked_events, 1);
        assert_eq!(summary.hook_audit_events, 1);
        assert_eq!(summary.secrets_push_events, 1);
        assert_eq!(summary.max_severity.as_deref(), Some("high"));
    }

    #[test]
    fn count_rule_ids_aggregates_arrays() {
        let entries = vec![
            entry(serde_json::json!({"rule_ids":["secret.a","pii.email"]})),
            entry(serde_json::json!({"rule_ids":["secret.a"]})),
        ];
        let rows = count_rule_ids(&entries);
        assert_eq!(rows[0].label, "secret.a");
        assert_eq!(rows[0].count, 2);
    }

    #[test]
    fn reason_filter_matches_blocked_only() {
        let blocked = entry(serde_json::json!({"event":"blocked","reason":"finding_threshold"}));
        let audit = entry(serde_json::json!({"tool":"cursor","hook":"pre"}));
        let inv = AuditInvocation {
            reason: Some(AuditReasonArg::Blocked),
            ..base_inv()
        };
        assert!(entry_matches_filters(&blocked, &inv, None));
        assert!(!entry_matches_filters(&audit, &inv, None));
    }

    #[test]
    fn parse_since_supports_day_suffix() {
        let cutoff = parse_since("1d").unwrap();
        let delta = Utc::now().signed_duration_since(cutoff);
        assert!(delta.num_hours() >= 23);
    }

    #[test]
    fn parse_since_accepts_uppercase_units() {
        assert!(parse_since("24H").is_ok());
    }

    #[test]
    fn build_report_respects_tool_filter() {
        let dir = tempfile::tempdir().unwrap();
        audit_log::append_line(
            dir.path(),
            serde_json::json!({"tool":"cursor","hook":"pre","finding_count":1}),
        )
        .unwrap();
        audit_log::append_line(
            dir.path(),
            serde_json::json!({"tool":"codex","hook":"pre","finding_count":1}),
        )
        .unwrap();

        let inv = AuditInvocation {
            path: dir.path().to_path_buf(),
            tool: Some(AiTool::Cursor),
            ..base_inv()
        };
        let read = audit_log::read_entries(dir.path()).unwrap();
        let report = build_report(dir.path(), read.entries, 0, &inv).unwrap();
        assert_eq!(report.summary.total_entries, 1);
        assert_eq!(report.by_tool[0].label, "cursor");
    }

    #[test]
    fn recent_rows_hide_paths_when_requested() {
        let entries = vec![entry(serde_json::json!({
            "event":"blocked",
            "ts":"2026-05-23T02:31:00Z",
            "tool":"cursor",
            "hook":"pre",
            "reason":"finding_threshold",
            "display_path":"secret.txt",
        }))];
        let rows = recent_rows(&entries, 5, true);
        assert!(rows[0].display_path.is_none());
    }
}
