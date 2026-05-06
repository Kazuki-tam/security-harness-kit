//! `shk` / `security-harness-kit` CLI library (callable from tests and tooling).

mod args;
mod audit_log;
mod color;
mod commands;
mod doctor;
mod hook_output;
mod hooks;
mod output;
mod policy_cmd;

use anyhow::{Context, Result};
use args::{Cli, Commands, DoctorCmd, HooksCmd, PolicyCmd};
use clap::Parser;
use shk_core::policy::ColorMode;
pub fn run() -> Result<()> {
    let cli = Cli::parse();
    let color = color::resolve_color(if cli.no_color {
        ColorMode::Never
    } else {
        ColorMode::Auto
    });
    let cwd = std::env::current_dir().context("current directory")?;

    match cli.command {
        Commands::Scan {
            path,
            staged,
            json,
            fail_on,
            include_binary,
            follow_symlinks,
            hook_mode,
            post,
            audit,
        } => commands::scan::run(commands::scan::ScanInvocation {
            path,
            staged,
            json,
            fail_on,
            include_binary,
            follow_symlinks,
            hook_mode,
            post,
            audit,
            color_enabled: color,
        })?,
        Commands::Mask {
            file,
            json,
            output,
            redaction,
        } => commands::mask::run(&cwd, file, json, output, redaction)?,
        Commands::Doctor { cmd, json } => match cmd {
            None => doctor::run_all(&cwd, json)?,
            Some(DoctorCmd::Ignore { path, fix }) => {
                let p = doctor::doctor_ignore_path(path);
                doctor::run_ignore(&p, fix)?
            }
            Some(DoctorCmd::Env { dotenvx, path }) => {
                let p = path.unwrap_or_else(|| cwd.clone());
                doctor::run_env(&p, dotenvx)?
            }
        },
        Commands::Hooks { cmd } => match cmd {
            HooksCmd::Install { .. } => {
                let root =
                    shk_core::git::discover_repo_root(&cwd).context("not a git repository")?;
                hooks::install_pre_commit(&root)?;
                println!("Installed pre-commit hook under {}", root.display());
            }
            HooksCmd::InstallAi {
                audit,
                dry_run,
                global,
                all,
                tool,
                fail_closed,
            } => hooks::install_ai(&cwd, tool, all, audit, dry_run, global, fail_closed)?,
        },
        Commands::Policy { cmd } => match cmd {
            PolicyCmd::Init { strict, force } => policy_cmd::init(&cwd, strict, force)?,
        },
    }
    Ok(())
}
