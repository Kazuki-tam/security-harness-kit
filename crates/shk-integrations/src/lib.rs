//! Optional integrations for external tools (dotenvx, AI hooks, etc.).

pub const MANAGED_MARKER_JSON: &str = "\"_shk_managed\": true";
pub const MANAGED_MARKER_SH: &str = "# shk-managed-start";

pub mod action_guard;
pub mod ai_hooks;
pub mod codex;

pub use action_guard::{
    ActionGuardConfig, ActionGuardMatch, antigravity_recommended_deny_entries,
    claude_deny_entry_covers, claude_recommended_deny_entries, detect_dangerous_action,
    detect_dangerous_action_with_config, normalize_claude_deny_entry,
};
pub use ai_hooks::{AiHookTool, USER_PROMPT_HOOK_FAIL_ON, extract_user_prompt, stdin_to_hook_body};
pub use codex::{
    CONFIG_REL_PATH, HOOKS_FEATURE_KEY, LEGACY_HOOKS_FEATURE_KEY, RECOMMENDED_APPROVAL_POLICY,
    RECOMMENDED_SANDBOX_MODE, RISKY_APPROVAL_POLICY, RISKY_DEFAULT_PERMISSIONS, RISKY_SANDBOX_MODE,
};
