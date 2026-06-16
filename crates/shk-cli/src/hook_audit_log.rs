//! Metadata-only audit log payloads for hook-mode scans and blocks.

use crate::args::AiTool;
use crate::audit_log;
use crate::hook_output::{self, HookEvent};
use anyhow::Result;
use shk_core::finding::Finding;
use shk_core::policy::Severity;
use shk_core::scanner::ScanResult;
use shk_integrations::ActionGuardMatch;
use std::collections::BTreeSet;
use std::path::Path;

pub const EVENT_BLOCKED: &str = "blocked";
pub const REASON_FINDING_THRESHOLD: &str = "finding_threshold";
pub const REASON_ACTION_GUARD: &str = "action_guard";

pub fn hook_phase_name(event: HookEvent) -> &'static str {
    match event {
        HookEvent::PostToolUse => "post",
        HookEvent::UserPromptSubmit => "user-prompt",
        HookEvent::PreToolUse | HookEvent::PermissionRequest => "pre",
    }
}

pub fn blocking_findings(res: &ScanResult) -> Vec<&Finding> {
    let threshold = res.exit_threshold;
    res.findings
        .iter()
        .filter(|f| {
            Severity::parse(&f.severity)
                .map(|s| s.meets_threshold(threshold))
                .unwrap_or(false)
        })
        .collect()
}

pub fn unique_sorted(items: impl IntoIterator<Item = impl AsRef<str>>) -> Vec<String> {
    items
        .into_iter()
        .map(|s| s.as_ref().to_string())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub fn audit_hook_payload(
    tool: AiTool,
    event: HookEvent,
    display_path: &str,
    res: &ScanResult,
) -> serde_json::Value {
    let max_sev = res.max_severity().map(|s| s.as_str());
    serde_json::json!({
        "tool": tool.kebab_str(),
        "hook": hook_phase_name(event),
        "display_path": display_path,
        "finding_count": res.findings.len(),
        "suppressed": res.suppressed,
        "deduplicated": res.deduplicated,
        "max_severity": max_sev,
    })
}

pub fn blocked_scan_payload(
    tool: AiTool,
    event: HookEvent,
    display_path: &str,
    res: &ScanResult,
) -> serde_json::Value {
    let blocking = blocking_findings(res);
    let rule_ids = unique_sorted(blocking.iter().map(|f| f.rule_id.as_str()));
    let kinds = unique_sorted(blocking.iter().map(|f| f.kind.as_str()));
    let max_sev = blocking
        .iter()
        .filter_map(|f| Severity::parse(&f.severity))
        .max()
        .map(|s| s.as_str());

    serde_json::json!({
        "event": EVENT_BLOCKED,
        "tool": tool.kebab_str(),
        "hook": hook_phase_name(event),
        "reason": REASON_FINDING_THRESHOLD,
        "display_path": display_path,
        "finding_count": blocking.len(),
        "suppressed_total": res.suppressed,
        "deduplicated_total": res.deduplicated,
        "max_severity": max_sev,
        "rule_ids": rule_ids,
        "kinds": kinds,
    })
}

pub fn blocked_action_guard_payload(
    tool: AiTool,
    event: HookEvent,
    guard_match: &ActionGuardMatch,
) -> serde_json::Value {
    serde_json::json!({
        "event": EVENT_BLOCKED,
        "tool": tool.kebab_str(),
        "hook": hook_phase_name(event),
        "reason": REASON_ACTION_GUARD,
        "action_category": guard_match.category,
    })
}

pub fn append_audit_hook(
    repo_root: &Path,
    tool: AiTool,
    event: HookEvent,
    display_path: &str,
    res: &ScanResult,
) -> Result<()> {
    let payload = audit_hook_payload(tool, event, display_path, res);
    audit_log::append_line(repo_root, payload)?;
    let max_sev = res.max_severity().map(|s| s.as_str());
    eprintln!(
        "{}",
        hook_output::audit_note(res.findings.len(), res.suppressed, max_sev),
    );
    Ok(())
}

pub fn append_blocked_scan(
    repo_root: &Path,
    tool: AiTool,
    event: HookEvent,
    display_path: &str,
    res: &ScanResult,
) -> Result<()> {
    let payload = blocked_scan_payload(tool, event, display_path, res);
    let rule_count = payload["rule_ids"].as_array().map_or(0, |a| a.len());
    let finding_count = payload["finding_count"].as_u64().unwrap_or(0) as usize;
    audit_log::append_line(repo_root, payload)?;
    eprintln!("shk blocked: findings={finding_count} rules={rule_count} (see .shk/audit.log)",);
    Ok(())
}

pub fn append_blocked_action_guard(
    repo_root: &Path,
    tool: AiTool,
    event: HookEvent,
    guard_match: &ActionGuardMatch,
) -> Result<()> {
    let payload = blocked_action_guard_payload(tool, event, guard_match);
    audit_log::append_line(repo_root, payload)?;
    eprintln!(
        "shk blocked: action_guard category={} (see .shk/audit.log)",
        guard_match.category,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use shk_core::policy::Policy;

    fn sample_finding(rule_id: &str, severity: &str, kind: &str) -> Finding {
        Finding {
            rule_id: rule_id.into(),
            severity: severity.into(),
            kind: kind.into(),
            file: "demo.txt".into(),
            line: 1,
            column: 1,
            message: "test finding".into(),
            redacted_value: "[REDACTED]".into(),
            value_hash: None,
            confidence: 0.9,
            context_before: vec![],
            context_after: vec![],
        }
    }

    fn scan_result(findings: Vec<Finding>, threshold: Severity) -> ScanResult {
        ScanResult {
            findings,
            scanned_paths: vec!["demo.txt".into()],
            policy: Policy::default(),
            policy_path: None,
            exit_threshold: threshold,
            suppressed: 2,
            deduplicated: 1,
        }
    }

    #[test]
    fn blocking_findings_respects_exit_threshold() {
        let res = scan_result(
            vec![
                sample_finding("secret.high", "high", "secret"),
                sample_finding("pii.low", "low", "pii"),
            ],
            Severity::High,
        );
        let blocking = blocking_findings(&res);
        assert_eq!(blocking.len(), 1);
        assert_eq!(blocking[0].rule_id, "secret.high");
    }

    #[test]
    fn unique_sorted_dedupes_and_sorts() {
        assert_eq!(
            unique_sorted(["b", "a", "b", "c"]),
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
    }

    #[test]
    fn blocked_scan_payload_is_metadata_only() {
        let res = scan_result(
            vec![Finding {
                rule_id: "secret.openai_api_key".into(),
                severity: "high".into(),
                kind: "secret".into(),
                file: "x.txt".into(),
                line: 1,
                column: 10,
                message: "Possible API key detected".into(),
                redacted_value: "[REDACTED]".into(),
                value_hash: None,
                confidence: 0.95,
                context_before: vec!["neighbor-before".into()],
                context_after: vec!["neighbor-after".into()],
            }],
            Severity::High,
        );

        let payload = blocked_scan_payload(AiTool::Cursor, HookEvent::PreToolUse, "x.txt", &res);
        let encoded = payload.to_string();

        assert_eq!(payload["event"], EVENT_BLOCKED);
        assert_eq!(payload["reason"], REASON_FINDING_THRESHOLD);
        assert_eq!(payload["tool"], "cursor");
        assert_eq!(payload["hook"], "pre");
        assert_eq!(payload["display_path"], "x.txt");
        assert_eq!(payload["finding_count"], 1);
        assert_eq!(payload["suppressed_total"], 2);
        assert_eq!(payload["deduplicated_total"], 1);
        assert!(payload.get("suppressed").is_none());
        assert!(payload.get("deduplicated").is_none());
        assert_eq!(
            payload["rule_ids"],
            serde_json::json!(["secret.openai_api_key"])
        );
        assert_eq!(payload["kinds"], serde_json::json!(["secret"]));

        assert!(!encoded.contains("neighbor-before"));
        assert!(!encoded.contains("neighbor-after"));
        assert!(!encoded.contains("[REDACTED]"));
        assert!(!encoded.contains("message"));
        assert!(!encoded.contains("redacted_value"));
        assert!(!encoded.contains("context_before"));
    }

    #[test]
    fn blocked_action_guard_payload_uses_category_not_reason() {
        let guard = ActionGuardMatch {
            category: "direct_db_mutation",
            reason: "shk action guard: blocked command details omitted".into(),
        };
        let payload =
            blocked_action_guard_payload(AiTool::Codex, HookEvent::PermissionRequest, &guard);
        let encoded = payload.to_string();

        assert_eq!(payload["event"], EVENT_BLOCKED);
        assert_eq!(payload["reason"], REASON_ACTION_GUARD);
        assert_eq!(payload["action_category"], "direct_db_mutation");
        assert_eq!(payload["hook"], "pre");
        assert!(!encoded.contains("blocked command"));
        assert!(!encoded.contains("guard_match"));
    }

    #[test]
    fn audit_hook_payload_shape() {
        let res = scan_result(
            vec![sample_finding("pii.email", "medium", "pii")],
            Severity::High,
        );
        let payload =
            audit_hook_payload(AiTool::ClaudeCode, HookEvent::PostToolUse, "out.txt", &res);

        assert_eq!(payload["tool"], "claude-code");
        assert_eq!(payload["hook"], "post");
        assert_eq!(payload["display_path"], "out.txt");
        assert_eq!(payload["finding_count"], 1);
        assert!(payload.get("event").is_none());
    }

    #[test]
    fn hook_phase_name_maps_events() {
        assert_eq!(hook_phase_name(HookEvent::UserPromptSubmit), "user-prompt");
        assert_eq!(hook_phase_name(HookEvent::PermissionRequest), "pre");
    }
}
