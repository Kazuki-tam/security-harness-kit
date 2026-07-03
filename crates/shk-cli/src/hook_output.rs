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

fn codex_pre_tool_output(decision: &str, reason: &str) -> String {
    permission_output(HookEvent::PreToolUse, decision, reason).to_string()
}

fn codex_message_allow(info: Option<&str>) -> String {
    match info {
        Some(msg) => json!({ "systemMessage": msg }).to_string(),
        None => "{}".to_string(),
    }
}

/// Claude-compatible PostToolUse "block" payload (`decision`/`reason` +
/// `hookSpecificOutput.additionalContext`). Used by both Codex and Claude
/// Code; `permissionDecision` is PreToolUse-only and must not appear here.
fn post_tool_block(reason: &str, additional_context: Option<&str>) -> String {
    let mut out = json!({
        "decision": "block",
        "reason": reason,
        "hookSpecificOutput": {
            "hookEventName": HookEvent::PostToolUse.json_name(),
        }
    });
    if let Some(context) = additional_context {
        out["hookSpecificOutput"]["additionalContext"] = json!(context);
    }
    out.to_string()
}

fn codex_deny_stdout(event: HookEvent, reason: &str) -> String {
    match event {
        HookEvent::PermissionRequest => json!({
            "hookSpecificOutput": {
                "hookEventName": event.json_name(),
                "decision": {
                    "behavior": "deny",
                    "message": reason
                }
            }
        })
        .to_string(),
        HookEvent::PreToolUse => codex_pre_tool_output("deny", reason),
        HookEvent::PostToolUse => post_tool_block(reason, None),
        HookEvent::UserPromptSubmit => json!({ "decision": "block", "reason": reason }).to_string(),
    }
}

/// Claude Code deny payloads per event.
///
/// `UserPromptSubmit` cannot use `permissionDecision` (PreToolUse-only); the
/// block travels via `decision: "block"` on exit 0, where `reason` is shown
/// to the user and `suppressOriginalPrompt` keeps the sensitive prompt text
/// out of the block message. Exit 2 would discard this stdout JSON entirely.
fn claude_deny_stdout(event: HookEvent, reason: &str) -> String {
    match event {
        HookEvent::UserPromptSubmit => json!({
            "decision": "block",
            "reason": reason,
            "hookSpecificOutput": {
                "hookEventName": event.json_name(),
                "suppressOriginalPrompt": true,
            }
        })
        .to_string(),
        _ => permission_output(event, "deny", reason).to_string(),
    }
}

fn mask_replacement_message(finding_count: usize, content: &str) -> String {
    format!(
        "shk security: {finding_count} sensitive value(s) detected and sanitized. \
        Use the following redacted version in place of the original tool output:\n\n{content}"
    )
}

/// Antigravity PreToolUse contract: `{"decision":"allow"|"deny","reason":...}`.
/// PostToolUse hooks must return an empty JSON object.
fn antigravity_decision(decision: &str, reason: Option<&str>) -> String {
    let mut out = json!({ "decision": decision });
    if let Some(reason) = reason {
        out["reason"] = json!(reason);
    }
    out.to_string()
}

/// GitHub Copilot hook stdout shapes (hooks reference, version 1).
///
/// - `preToolUse`: flat `{"permissionDecision":"allow"|"deny","permissionDecisionReason":...}`.
///   A deny travels via stdout JSON with exit 0 (exit 2 is a non-blocking
///   warning for `preToolUse`; the scan command exits 0 for Copilot pre denies).
/// - `permissionRequest`: `{"behavior":"allow"|"deny","message":...}`.
/// - `postToolUse`: `{"modifiedResult":{...}, "additionalContext":...}`; never blocks.
/// - `userPromptSubmitted`: output is NOT processed by Copilot, so emit `{}`
///   and rely on stderr + exit 2 for an advisory warning.
fn copilot_deny(event: HookEvent, reason: &str) -> String {
    match event {
        HookEvent::PreToolUse => json!({
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        })
        .to_string(),
        HookEvent::PermissionRequest => json!({
            "behavior": "deny",
            "message": reason,
        })
        .to_string(),
        HookEvent::PostToolUse => json!({ "additionalContext": reason }).to_string(),
        // userPromptSubmitted output is not processed; advisory only.
        HookEvent::UserPromptSubmit => "{}".to_string(),
    }
}

fn copilot_allow(event: HookEvent, info: Option<&str>) -> String {
    match (event, info) {
        (HookEvent::PreToolUse, Some(msg)) => json!({
            "permissionDecision": "allow",
            "permissionDecisionReason": msg,
        })
        .to_string(),
        (HookEvent::PostToolUse, Some(msg)) => json!({ "additionalContext": msg }).to_string(),
        // Empty output falls through to Copilot's default (allow) behavior.
        _ => "{}".to_string(),
    }
}

pub fn deny_stdout_for_event(tool: AiTool, event: HookEvent, reason: &str) -> String {
    match tool {
        AiTool::Antigravity => antigravity_decision("deny", Some(reason)),
        AiTool::Copilot => copilot_deny(event, reason),
        AiTool::Cursor => json!({
            "permission":"deny",
            "user_message": reason,
            "agent_message": reason
        })
        .to_string(),
        AiTool::Codex => codex_deny_stdout(event, reason),
        AiTool::ClaudeCode => claude_deny_stdout(event, reason),
        // Cascade (Windsurf) does not parse hook stdout for
        // decisions; a block travels via exit code 2 + the stderr message.
        AiTool::Windsurf => "{}".to_string(),
    }
}

pub fn allow_stdout_for_event(tool: AiTool, event: HookEvent, info: Option<&str>) -> String {
    match tool {
        AiTool::Antigravity if event == HookEvent::PostToolUse => "{}".to_string(),
        AiTool::Antigravity => antigravity_decision("allow", info),
        AiTool::Copilot => copilot_allow(event, info),
        AiTool::Cursor => {
            let msg = info.unwrap_or("shk: OK");
            json!({
                "permission":"allow",
                "user_message": msg,
                "agent_message": msg,
            })
            .to_string()
        }
        AiTool::Codex => codex_message_allow(info),
        // UserPromptSubmit has no permissionDecision schema; on exit 0 an
        // empty object is the schema-valid no-op (plain text or
        // additionalContext would be injected into Claude's context).
        AiTool::ClaudeCode if event == HookEvent::UserPromptSubmit => "{}".to_string(),
        AiTool::ClaudeCode => {
            let reason = info.unwrap_or("shk: OK");
            permission_output(event, "allow", reason).to_string()
        }
        // Cascade ignores hook stdout; exit 0 already lets the action proceed.
        AiTool::Windsurf => "{}".to_string(),
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
        // Antigravity has no schema field for replacing tool payloads; post
        // hooks must return `{}` and pre hooks report via decision/reason only.
        AiTool::Antigravity if post => "{}".to_string(),
        AiTool::Antigravity => antigravity_decision("allow", Some(&msg)),
        // Cascade has no schema for replacing tool payloads via hook stdout, so
        // masking is advisory only (the stderr hint reports the finding count).
        AiTool::Windsurf => "{}".to_string(),
        // Copilot postToolUse replaces the result via `modifiedResult`; preToolUse
        // cannot rewrite tool args here, so it allows with an advisory note.
        AiTool::Copilot if post => {
            if let Some(content) = masked_content {
                json!({
                    "modifiedResult": {
                        "resultType": "success",
                        "textResultForLlm": content,
                    },
                    "additionalContext": format!(
                        "shk mask: sanitized {finding_count} sensitive value(s) from tool output"
                    ),
                })
                .to_string()
            } else {
                "{}".to_string()
            }
        }
        AiTool::Copilot => copilot_allow(HookEvent::PreToolUse, Some(&msg)),
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
        AiTool::Codex if post => {
            if let Some(content) = masked_content {
                post_tool_block(
                    &mask_replacement_message(finding_count, content),
                    Some("shk mask: sanitized sensitive values from tool output"),
                )
            } else {
                codex_message_allow(Some(&msg))
            }
        }
        AiTool::Codex if finding_count == 0 && masked_content.is_none() => {
            codex_message_allow(None)
        }
        AiTool::Codex => codex_message_allow(Some(&msg)),
        // PostToolUse has no `permissionDecision`; the only schema-valid way
        // to replace tool output with the masked version is the
        // `decision: "block"` shape with the redacted content in `reason`.
        AiTool::ClaudeCode if post => {
            if let Some(content) = masked_content {
                post_tool_block(
                    &mask_replacement_message(finding_count, content),
                    Some("shk mask: sanitized sensitive values from tool output"),
                )
            } else {
                json!({ "systemMessage": msg }).to_string()
            }
        }
        AiTool::ClaudeCode => {
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
    fn codex_post_tool_allow_uses_system_message() {
        let output = allow_stdout_for_event(
            AiTool::Codex,
            HookEvent::PostToolUse,
            Some("review findings"),
        );
        let value = parse_json(&output);

        assert_eq!(value["systemMessage"], "review findings");
        assert!(value.get("hookSpecificOutput").is_none());
    }

    #[test]
    fn codex_post_tool_allow_without_message_is_empty_object() {
        let output = allow_stdout_for_event(AiTool::Codex, HookEvent::PostToolUse, None);

        assert_eq!(parse_json(&output), json!({}));
    }

    #[test]
    fn codex_pre_tool_allow_is_empty_object_without_message() {
        let output = allow_stdout_for_event(AiTool::Codex, HookEvent::PreToolUse, None);

        assert_eq!(parse_json(&output), json!({}));
    }

    #[test]
    fn codex_pre_tool_allow_uses_system_message_when_present() {
        let output = allow_stdout_for_event(AiTool::Codex, HookEvent::PreToolUse, Some("ok"));
        let value = parse_json(&output);

        assert_eq!(value["systemMessage"], "ok");
        assert!(value.get("hookSpecificOutput").is_none());
    }

    #[test]
    fn codex_user_prompt_deny_uses_block_decision() {
        let output =
            deny_stdout_for_event(AiTool::Codex, HookEvent::UserPromptSubmit, "blocked prompt");
        let value = parse_json(&output);

        assert_eq!(value["decision"], "block");
        assert_eq!(value["reason"], "blocked prompt");
    }

    #[test]
    fn claude_allow_uses_hook_specific_permission_output() {
        let output = allow_stdout_for_event(
            AiTool::ClaudeCode,
            HookEvent::PreToolUse,
            Some("looks good"),
        );
        let value = parse_json(&output);

        assert_eq!(value["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "allow");
        assert_eq!(
            value["hookSpecificOutput"]["permissionDecisionReason"],
            "looks good"
        );
    }

    #[test]
    fn claude_user_prompt_allow_is_empty_object() {
        // Anything else (plain text or additionalContext) would be injected
        // into Claude's context on exit 0.
        for info in [None, Some("shk audit: non-blocking")] {
            let output =
                allow_stdout_for_event(AiTool::ClaudeCode, HookEvent::UserPromptSubmit, info);
            assert_eq!(parse_json(&output), json!({}));
        }
    }

    #[test]
    fn claude_user_prompt_deny_uses_block_decision_and_suppresses_prompt() {
        let output = deny_stdout_for_event(
            AiTool::ClaudeCode,
            HookEvent::UserPromptSubmit,
            "blocked prompt",
        );
        let value = parse_json(&output);

        assert_eq!(value["decision"], "block");
        assert_eq!(value["reason"], "blocked prompt");
        assert_eq!(
            value["hookSpecificOutput"]["hookEventName"],
            "UserPromptSubmit"
        );
        assert_eq!(value["hookSpecificOutput"]["suppressOriginalPrompt"], true);
        assert!(
            value["hookSpecificOutput"]
                .get("permissionDecision")
                .is_none(),
            "permissionDecision is PreToolUse-only: {value}"
        );
    }

    #[test]
    fn claude_pre_tool_deny_keeps_permission_decision_shape() {
        let output = deny_stdout_for_event(AiTool::ClaudeCode, HookEvent::PreToolUse, "blocked");
        let value = parse_json(&output);

        assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "deny");
        assert_eq!(
            value["hookSpecificOutput"]["permissionDecisionReason"],
            "blocked"
        );
        assert!(value.get("decision").is_none());
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
    fn claude_post_mask_output_uses_block_shape_with_replacement_message() {
        let output = mask_stdout(AiTool::ClaudeCode, true, 1, Some("safe output"));
        let value = parse_json(&output);

        // PostToolUse must not use the PreToolUse-only permissionDecision
        // field; the masked replacement travels via decision:block + reason.
        assert_eq!(value["decision"], "block");
        assert_eq!(value["hookSpecificOutput"]["hookEventName"], "PostToolUse");
        assert!(
            value["hookSpecificOutput"]
                .get("permissionDecision")
                .is_none()
        );
        assert!(
            value["reason"]
                .as_str()
                .expect("string reason")
                .contains("safe output")
        );
        assert_eq!(
            value["hookSpecificOutput"]["additionalContext"],
            "shk mask: sanitized sensitive values from tool output"
        );
    }

    #[test]
    fn claude_post_mask_without_findings_uses_system_message() {
        let output = mask_stdout(AiTool::ClaudeCode, true, 0, None);
        let value = parse_json(&output);

        assert_eq!(
            value["systemMessage"],
            "shk mask: no sensitive content detected"
        );
        assert!(value.get("hookSpecificOutput").is_none());
    }

    #[test]
    fn mask_without_findings_reports_clean_output() {
        let output = mask_stdout(AiTool::Codex, false, 0, None);
        let value = parse_json(&output);

        assert_eq!(value, json!({}));
    }

    #[test]
    fn codex_post_mask_uses_block_shape_with_additional_context() {
        let output = mask_stdout(AiTool::Codex, true, 1, Some("safe output"));
        let value = parse_json(&output);

        assert_eq!(value["decision"], "block");
        assert_eq!(value["hookSpecificOutput"]["hookEventName"], "PostToolUse");
        assert!(
            value["reason"]
                .as_str()
                .unwrap_or_default()
                .contains("safe output")
        );
        assert_eq!(
            value["hookSpecificOutput"]["additionalContext"],
            "shk mask: sanitized sensitive values from tool output"
        );
    }

    #[test]
    fn antigravity_deny_uses_decision_reason_shape() {
        let output = deny_stdout_for_event(AiTool::Antigravity, HookEvent::PreToolUse, "blocked");
        let value = parse_json(&output);

        assert_eq!(value["decision"], "deny");
        assert_eq!(value["reason"], "blocked");
        assert!(value.get("hookSpecificOutput").is_none());
    }

    #[test]
    fn antigravity_pre_allow_uses_decision_shape() {
        let output = allow_stdout_for_event(AiTool::Antigravity, HookEvent::PreToolUse, None);
        let value = parse_json(&output);

        assert_eq!(value["decision"], "allow");
        assert!(value.get("reason").is_none());
    }

    #[test]
    fn antigravity_post_allow_is_empty_object() {
        let output =
            allow_stdout_for_event(AiTool::Antigravity, HookEvent::PostToolUse, Some("hint"));

        assert_eq!(parse_json(&output), json!({}));
    }

    #[test]
    fn antigravity_post_mask_is_empty_object() {
        let output = mask_stdout(AiTool::Antigravity, true, 2, Some("[REDACTED]"));

        assert_eq!(parse_json(&output), json!({}));
    }

    #[test]
    fn antigravity_pre_mask_reports_via_decision_allow() {
        let output = mask_stdout(AiTool::Antigravity, false, 2, Some("[REDACTED]"));
        let value = parse_json(&output);

        assert_eq!(value["decision"], "allow");
        assert_eq!(value["reason"], "shk mask: redacted 2 finding(s)");
    }

    #[test]
    fn copilot_pre_deny_uses_flat_permission_decision() {
        let output = deny_stdout_for_event(AiTool::Copilot, HookEvent::PreToolUse, "blocked");
        let value = parse_json(&output);

        assert_eq!(value["permissionDecision"], "deny");
        assert_eq!(value["permissionDecisionReason"], "blocked");
        assert!(value.get("hookSpecificOutput").is_none());
    }

    #[test]
    fn copilot_permission_request_deny_uses_behavior_shape() {
        let output = deny_stdout_for_event(
            AiTool::Copilot,
            HookEvent::PermissionRequest,
            "needs review",
        );
        let value = parse_json(&output);

        assert_eq!(value["behavior"], "deny");
        assert_eq!(value["message"], "needs review");
    }

    #[test]
    fn copilot_pre_allow_without_info_is_empty_object() {
        let output = allow_stdout_for_event(AiTool::Copilot, HookEvent::PreToolUse, None);
        assert_eq!(parse_json(&output), json!({}));
    }

    #[test]
    fn copilot_pre_allow_with_info_sets_permission_decision_allow() {
        let output = allow_stdout_for_event(AiTool::Copilot, HookEvent::PreToolUse, Some("ok"));
        let value = parse_json(&output);

        assert_eq!(value["permissionDecision"], "allow");
        assert_eq!(value["permissionDecisionReason"], "ok");
    }

    #[test]
    fn copilot_post_mask_uses_modified_result() {
        let output = mask_stdout(AiTool::Copilot, true, 2, Some("safe output"));
        let value = parse_json(&output);

        assert_eq!(value["modifiedResult"]["resultType"], "success");
        assert_eq!(value["modifiedResult"]["textResultForLlm"], "safe output");
        assert!(
            value["additionalContext"]
                .as_str()
                .unwrap_or_default()
                .contains("sanitized 2")
        );
    }

    #[test]
    fn copilot_post_mask_without_findings_is_empty_object() {
        let output = mask_stdout(AiTool::Copilot, true, 0, None);
        assert_eq!(parse_json(&output), json!({}));
    }

    #[test]
    fn windsurf_outputs_are_empty_objects_blocking_is_via_exit_and_stderr() {
        // Cascade ignores hook stdout; decisions travel via exit code + stderr.
        let deny = deny_stdout_for_event(AiTool::Windsurf, HookEvent::PreToolUse, "blocked");
        assert_eq!(parse_json(&deny), json!({}));

        let allow = allow_stdout_for_event(AiTool::Windsurf, HookEvent::PreToolUse, Some("ok"));
        assert_eq!(parse_json(&allow), json!({}));

        let mask_pre = mask_stdout(AiTool::Windsurf, false, 2, Some("[REDACTED]"));
        assert_eq!(parse_json(&mask_pre), json!({}));
        let mask_post = mask_stdout(AiTool::Windsurf, true, 2, Some("[REDACTED]"));
        assert_eq!(parse_json(&mask_post), json!({}));
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
