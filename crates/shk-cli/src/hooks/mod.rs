mod ai;
mod git;

pub use ai::{
    ConfigureAiOptions, InstallAiOptions, configure_ai_with_summaries, install_ai,
    install_ai_with_summaries,
};
pub use git::install_pre_commit;
