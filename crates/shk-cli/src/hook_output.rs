//! Hook-mode stdout payloads (Cursor / Codex / Claude-compatible).

use crate::args::AiTool;
use serde_json::json;

const REASON_DENY_DEFAULT: &str =
    "shk: secrets detected above threshold — run `shk scan` for details";

fn hook_event_json_name(is_post: bool) -> &'static str {
    if is_post {
        "PostToolUse"
    } else {
        "PreToolUse"
    }
}

/// Pre-hook deny payload (blocking `shk scan --hook-mode`; exit code 2 at CLI).
pub fn deny_stdout(tool: AiTool) -> String {
    let event = hook_event_json_name(false);

    match tool {
        AiTool::Cursor => json!({
            "permission":"deny",
            "user_message": REASON_DENY_DEFAULT,
            "agent_message": "Blocked by shk: potential secrets/PII over threshold."
        })
        .to_string(),
        AiTool::Codex | AiTool::ClaudeCode => json!({
            "hookSpecificOutput":{
                "hookEventName": event,
                "permissionDecision":"deny",
                "permissionDecisionReason": REASON_DENY_DEFAULT
            }
        })
        .to_string(),
    }
}

pub fn allow_stdout(tool: AiTool, post: bool, info: Option<&str>) -> String {
    let event = hook_event_json_name(post);

    match tool {
        AiTool::Cursor => {
            let msg = info.unwrap_or("shk: OK");
            json!({
                "permission":"allow",
                "user_message": msg,
                "agent_message": msg,
            })
            .to_string()
        }
        AiTool::Codex | AiTool::ClaudeCode => {
            let reason = info.unwrap_or("shk: OK");
            json!({
                "hookSpecificOutput":{
                    "hookEventName": event,
                    "permissionDecision": "allow",
                    "permissionDecisionReason": reason
                }
            })
            .to_string()
        }
    }
}

pub fn audit_note(findings_len: usize, suppressed: u64, max_sev: Option<&str>) -> String {
    format!(
        "shk audit: findings={findings_len} suppressed={suppressed}{}",
        max_sev
            .map(|s| format!(" max_severity={s}"))
            .unwrap_or_default()
    )
}
