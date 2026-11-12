mod ai;
mod git;

pub(crate) use ai::{
    CLAUDE_HOOK_ON_FAILURE, CLAUDE_PRE_TOOL_USE_MATCHER, claude_command_is_audit,
    has_managed_hooks, is_managed_claude_block, is_managed_opencode_plugin, resolve_ai_config_path,
};
pub use ai::{
    ConfigureAiOptions, InstallAiOptions, claude_managed_scan_flags, configure_ai_with_summaries,
    install_ai, install_ai_with_summaries, opencode_plugin_drift,
};
pub use git::{
    HooksDirManagedElsewhere, has_shk_pre_commit, install_pre_commit, pre_commit_hook_path,
};
