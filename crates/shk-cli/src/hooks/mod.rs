mod ai;
mod git;

pub use ai::{
    ConfigureAiOptions, InstallAiOptions, configure_ai_with_summaries, install_ai,
    install_ai_with_summaries, opencode_plugin_drift,
};
pub(crate) use ai::{is_managed_opencode_plugin, resolve_ai_config_path};
pub use git::install_pre_commit;
