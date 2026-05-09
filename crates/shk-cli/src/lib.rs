//! `shk` / `security-harness-kit` CLI library (callable from tests and tooling).

mod args;
mod audit_log;
mod color;
mod commands;
mod doctor;
mod exit;
mod hook_output;
mod hooks;
mod output;
mod policy_cmd;
mod safety;
mod version_check;

use anyhow::{Context, Result};
use args::{
    CiCmd, CiInitProvider, Cli, Commands, DoctorCmd, DotenvxCmd, EnvCmd, HooksCmd, PolicyCmd,
    SecretsCmd, SkillToolArg, SkillsCmd,
};
use clap::Parser;
use shk_core::policy::ColorMode;
use std::io::Write;

pub fn run_main() {
    if let Err(err) = run() {
        let code = exit::code_for(&err);
        if !exit::is_silent(&err) {
            eprintln!("Error: {err:#}");
        }
        let _ = std::io::stdout().flush();
        let _ = std::io::stderr().flush();
        std::process::exit(code);
    }
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    let color = color::resolve_color(if cli.no_color {
        ColorMode::Never
    } else {
        ColorMode::Auto
    });
    let cwd = std::env::current_dir().context("current directory")?;

    match cli.command {
        Commands::Init { strict, force } => policy_cmd::init(&cwd, strict, force)?,
        Commands::Scan {
            path,
            staged,
            json,
            verbose,
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
            verbose,
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
            hook_mode,
            post,
        } => commands::mask::run(&cwd, file, json, output, redaction, hook_mode, post)?,
        Commands::Completions { shell } => commands::completions::run(shell)?,
        Commands::Status => commands::status::run(&cwd)?,
        Commands::Doctor { cmd, json } => match cmd {
            None => doctor::run_all(&cwd, json)?,
            Some(DoctorCmd::Version) => version_check::run(json)?,
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
            HooksCmd::Install { pre_commit: _ } => {
                let root =
                    shk_core::git::discover_repo_root(&cwd).context("not a git repository")?;
                safety::require_project_policy(&root, "hooks install")?;
                hooks::install_pre_commit(&root)?;
                println!("Installed pre-commit hook under {}", root.display());
            }
            HooksCmd::InstallAi {
                audit,
                dry_run,
                global,
                tool,
                fail_closed,
                apply_deny,
                apply_sandbox,
            } => {
                if !dry_run {
                    safety::require_project_policy(&cwd, "hooks install-ai")?;
                }
                hooks::install_ai(
                    &cwd,
                    tool,
                    hooks::InstallAiOptions {
                        audit,
                        dry_run,
                        global,
                        fail_closed,
                        apply_deny,
                        apply_sandbox,
                    },
                )?
            }
        },
        Commands::Policy { cmd } => match cmd {
            PolicyCmd::Init { strict, force } => policy_cmd::init(&cwd, strict, force)?,
        },
        Commands::Ci { cmd } => match cmd {
            CiCmd::Init { provider } => match provider {
                CiInitProvider::Github(args) => commands::ci::init_github(&cwd, args)?,
            },
        },
        Commands::Skills { cmd } => match cmd {
            SkillsCmd::List => commands::skills::list()?,
            SkillsCmd::Status => commands::skills::status()?,
            SkillsCmd::Install {
                tool,
                global,
                dry_run,
                force,
            } => commands::skills::install(commands::skills::SkillsInstallArgs {
                tool: tool.map(|t| match t {
                    SkillToolArg::ClaudeCode => commands::skills::SkillTool::ClaudeCode,
                    SkillToolArg::Codex => commands::skills::SkillTool::Codex,
                    SkillToolArg::Cursor => commands::skills::SkillTool::Cursor,
                    SkillToolArg::All => commands::skills::SkillTool::All,
                }),
                global,
                dry_run,
                force,
            })?,
        },
        Commands::Env { cmd } => match cmd {
            EnvCmd::Dotenvx { cmd } => match cmd {
                DotenvxCmd::ImportKeys { file } => commands::env::dotenvx_import_keys(&cwd, &file)?,
                DotenvxCmd::List => commands::env::dotenvx_list(&cwd)?,
                DotenvxCmd::Delete(args) => commands::env::dotenvx_delete(&cwd, args)?,
                DotenvxCmd::Run(args) => commands::env::dotenvx_run(&cwd, args)?,
            },
        },
        Commands::Secrets { cmd } => match cmd {
            SecretsCmd::Push(args) => commands::secrets::push(&cwd, args)?,
        },
    }
    Ok(())
}
