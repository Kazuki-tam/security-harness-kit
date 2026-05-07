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
