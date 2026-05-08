use crate::args::Cli;
use anyhow::Result;
use clap::CommandFactory;
use clap_complete::{Shell, generate};

pub fn run(shell: Shell) -> Result<()> {
    let mut cmd = Cli::command();
    generate(shell, &mut cmd, "shk", &mut std::io::stdout());
    Ok(())
}
