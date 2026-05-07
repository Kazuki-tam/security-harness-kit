//! Optional integrations for external tools (dotenvx, AI hooks, etc.).

pub const MANAGED_MARKER_JSON: &str = "\"_shk_managed\": true";
pub const MANAGED_MARKER_SH: &str = "# shk-managed-start";

pub mod action_guard;
pub mod ai_hooks;

pub use action_guard::{
    ActionGuardConfig, ActionGuardMatch, claude_recommended_deny_entries, detect_dangerous_action,
    detect_dangerous_action_with_config,
};
pub use ai_hooks::{AiHookTool, stdin_to_hook_body};
