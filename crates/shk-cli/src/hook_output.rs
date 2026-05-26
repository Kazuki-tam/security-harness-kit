//! Hook-mode stdout payloads (Cursor / Codex / Claude-compatible).

use crate::args::AiTool;
use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HookEvent {
    PreToolUse,
    PermissionRequest,
    PostToolUse,
    UserPromptSubmit,
}

impl HookEvent {
    fn from_post_flag(post: bool) -> Self {
        if post {
            Self::PostToolUse
        } else {
            Self::PreToolUse
        }
    }

    fn json_name(self) -> &'static str {
        match self {
            Self::PreToolUse => "PreToolUse",
            Self::PermissionRequest => "PermissionRequest",
            Self::PostToolUse => "PostToolUse",
            Self::UserPromptSubmit => "UserPromptSubmit",
        }
    }
}

fn permission_output(event: HookEvent, decision: &str, reason: &str) -> Value {
    json!({
        "hookSpecificOutput":{
            "hookEventName": event.json_name(),
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    })
}

fn mask_replacement_message(finding_count: usize, content: &str) -> String {
    format!(
        "shk security: {finding_count} sensitive value(s) detected and sanitized. \
        Use the following redacted version in place of the original tool output:\n\n{content}"
    )
}

pub fn deny_stdout_for_event(tool: AiTool, event: HookEvent, reason: &str) -> String {
    match tool {
        AiTool::Cursor => json!({
            "permission":"deny",
            "user_message": reason,
            "agent_message": reason
        })
        .to_string(),
        AiTool::Codex if event == HookEvent::PermissionRequest => json!({
            "hookSpecificOutput":{
                "hookEventName": event.json_name(),
                "decision": {
                    "behavior": "deny",
                    "message": reason
                }
            }
        })
        .to_string(),
        AiTool::Codex | AiTool::ClaudeCode => permission_output(event, "deny", reason).to_string(),
    }
}

pub fn allow_stdout_for_event(tool: AiTool, event: HookEvent, info: Option<&str>) -> String {
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
        AiTool::Codex if event == HookEvent::PermissionRequest => json!({}).to_string(),
        AiTool::Codex | AiTool::ClaudeCode => {
            let reason = info.unwrap_or("shk: OK");
            permission_output(event, "allow", reason).to_string()
        }
    }
}

pub fn mask_stdout(
    tool: AiTool,
    post: bool,
    finding_count: usize,
    masked_content: Option<&str>,
) -> String {
    let event = HookEvent::from_post_flag(post);
    let msg = if finding_count == 0 {
        "shk mask: no sensitive content detected".to_string()
    } else {
        format!("shk mask: redacted {finding_count} finding(s)")
    };

    match tool {
        AiTool::Cursor => {
            let mut out = json!({
                "permission": "allow",
                "user_message": msg,
                "agent_message": msg,
            });
            if let Some(content) = masked_content {
                out["masked_content"] = json!(content);
            }
            out.to_string()
        }
        AiTool::Codex | AiTool::ClaudeCode => {
            let mut out = permission_output(event, "allow", &msg);
            if let Some(content) = masked_content {
                out["hookSpecificOutput"]["output"] =
                    json!(mask_replacement_message(finding_count, content));
            }
            out.to_string()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::AiTool;

    fn parse_json(output: &str) -> Value {
        serde_json::from_str(output).expect("valid hook output JSON")
    }

    #[test]
    fn cursor_deny_contains_user_and_agent_messages() {
        let output = deny_stdout_for_event(AiTool::Cursor, HookEvent::PreToolUse, "blocked");
        let value = parse_json(&output);

        assert_eq!(value["permission"], "deny");
        assert_eq!(value["user_message"], "blocked");
        assert_eq!(value["agent_message"], "blocked");
    }

    #[test]
    fn codex_permission_request_uses_decision_shape() {
        let output =
            deny_stdout_for_event(AiTool::Codex, HookEvent::PermissionRequest, "needs review");
        let value = parse_json(&output);

        assert_eq!(
            value["hookSpecificOutput"]["hookEventName"],
            "PermissionRequest"
        );
        assert_eq!(value["hookSpecificOutput"]["decision"]["behavior"], "deny");
        assert_eq!(
            value["hookSpecificOutput"]["decision"]["message"],
            "needs review"
        );
    }

    #[test]
    fn codex_permission_request_allow_is_empty_object() {
        let output = allow_stdout_for_event(AiTool::Codex, HookEvent::PermissionRequest, None);

        assert_eq!(parse_json(&output), json!({}));
    }

    #[test]
    fn claude_allow_uses_hook_specific_permission_output() {
        let output = allow_stdout_for_event(
            AiTool::ClaudeCode,
            HookEvent::UserPromptSubmit,
            Some("looks good"),
        );
        let value = parse_json(&output);

        assert_eq!(
            value["hookSpecificOutput"]["hookEventName"],
            "UserPromptSubmit"
        );
        assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "allow");
        assert_eq!(
            value["hookSpecificOutput"]["permissionDecisionReason"],
            "looks good"
        );
    }

    #[test]
    fn cursor_mask_output_includes_masked_content_when_present() {
        let output = mask_stdout(AiTool::Cursor, false, 2, Some("[REDACTED]"));
        let value = parse_json(&output);

        assert_eq!(value["permission"], "allow");
        assert_eq!(value["masked_content"], "[REDACTED]");
        assert_eq!(value["user_message"], "shk mask: redacted 2 finding(s)");
    }

    #[test]
    fn claude_post_mask_output_uses_post_tool_event_and_replacement_message() {
        let output = mask_stdout(AiTool::ClaudeCode, true, 1, Some("safe output"));
        let value = parse_json(&output);

        assert_eq!(value["hookSpecificOutput"]["hookEventName"], "PostToolUse");
        assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "allow");
        assert!(
            value["hookSpecificOutput"]["output"]
                .as_str()
                .expect("string output")
                .contains("safe output")
        );
    }

    #[test]
    fn mask_without_findings_reports_clean_output() {
        let output = mask_stdout(AiTool::Codex, false, 0, None);
        let value = parse_json(&output);

        assert_eq!(
            value["hookSpecificOutput"]["permissionDecisionReason"],
            "shk mask: no sensitive content detected"
        );
        assert!(value["hookSpecificOutput"].get("output").is_none());
    }

    #[test]
    fn audit_note_includes_max_severity_only_when_present() {
        assert_eq!(
            audit_note(3, 2, Some("high")),
            "shk audit: findings=3 suppressed=2 max_severity=high"
        );
        assert_eq!(audit_note(0, 0, None), "shk audit: findings=0 suppressed=0");
    }
}
