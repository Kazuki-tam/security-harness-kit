mod ai;
mod git;

pub(crate) use ai::resolve_ai_config_path;
pub use ai::{
    ConfigureAiOptions, InstallAiOptions, configure_ai_with_summaries, install_ai,
    install_ai_with_summaries,
};
pub use git::install_pre_commit;
