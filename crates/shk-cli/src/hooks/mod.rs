mod ai;
mod git;

pub(crate) use ai::{
    CLAUDE_PRE_TOOL_USE_MATCHER, OPENCODE_SKIPPED, has_managed_hooks, is_managed_claude_block,
    is_managed_opencode_plugin, resolve_ai_config_path,
};
pub use ai::{
    ConfigureAiOptions, InstallAiOptions, configure_ai_with_summaries, install_ai,
    install_ai_with_summaries, opencode_plugin_drift,
};
pub use git::install_pre_commit;
