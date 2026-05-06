//! Optional integrations for external tools (dotenvx, AI hooks, etc.).

pub const MANAGED_MARKER_JSON: &str = "\"_shk_managed\": true";
pub const MANAGED_MARKER_SH: &str = "# shk-managed-start";

pub mod ai_hooks;

pub use ai_hooks::{stdin_to_hook_body, AiHookTool};
