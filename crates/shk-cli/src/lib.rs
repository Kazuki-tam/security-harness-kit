//! `shk` CLI library (callable from tests and tooling).

mod args;
mod audit_log;
mod color;
mod commands;
pub mod desktop_api;
mod doctor;
mod env_store;
mod exit;
mod fs_atomic;
mod hook_audit_log;
mod hook_output;
mod hooks;
mod mcp_audit;
mod npm_hardening;
mod output;
mod policy_cmd;
mod safety;
mod sarif;
mod version_check;
mod workflow_hardening;

use anyhow::{Context, Result};
use args::{
    AllowlistCmd, CiCmd, CiInitProvider, Cli, ClipboardCmd, Commands, DoctorCmd, DotenvxCmd,
    EnvCmd, EnvKeyCmd, HooksCmd, McpCmd, PolicyCmd, SecretsCmd, SkillToolArg, SkillsCmd,
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
    // Policy resolution is cwd-based throughout the CLI; switching the process
    // working directory makes `--project-root` apply uniformly to every command.
    if let Some(root) = &cli.project_root {
        let root = std::fs::canonicalize(root)
            .with_context(|| format!("--project-root not found: {}", root.display()))?;
        if !root.is_dir() {
            anyhow::bail!("--project-root must be a directory: {}", root.display());
        }
        std::env::set_current_dir(&root)
            .with_context(|| format!("switch to --project-root {}", root.display()))?;
    }
    let cwd = std::env::current_dir().context("current directory")?;

    match cli.command {
        Commands::Init {
            strict,
            force,
            yes,
            audit,
            log_blocked,
            tool,
            no_git_hook,
            no_ai_hooks,
            no_skills,
            no_npm_hardening,
            global,
            apply_sandbox,
        } => commands::init::run(
            &cwd,
            commands::init::InitArgs {
                strict,
                force,
                yes,
                audit,
                log_blocked,
                tools: tool,
                no_git_hook,
                no_ai_hooks,
                no_skills,
                no_npm_hardening,
                global,
                apply_sandbox,
            },
        )?,
        Commands::Scan {
            path,
            staged,
            changed_since,
            git_history,
            preview,
            git_history_ref,
            since,
            max_commits,
            json,
            sarif,
            with_value_hash,
            verbose,
            fail_on,
            include_binary,
            follow_symlinks,
            hook_mode,
            post,
            audit,
            log_blocked,
        } => commands::scan::run(commands::scan::ScanInvocation {
            path,
            staged,
            changed_since,
            git_history,
            preview,
            git_history_ref,
            since,
            max_commits,
            json,
            sarif,
            with_value_hash,
            verbose,
            fail_on,
            include_binary,
            follow_symlinks,
            hook_mode,
            post,
            audit,
            log_blocked,
            color_enabled: color,
        })?,
        Commands::Mask {
            file,
            json,
            output,
            redaction,
            min_severity,
            hook_mode,
            post,
        } => commands::mask::run(commands::mask::MaskInvocation {
            project_root: cwd,
            file,
            json,
            output,
            redaction,
            min_severity,
            hook_mode,
            post,
        })?,
        Commands::Clipboard { cmd } => match cmd {
            ClipboardCmd::Scan {
                json,
                verbose,
                fail_on,
            } => commands::clipboard::scan(commands::clipboard::ClipboardScanInvocation {
                json,
                verbose,
                fail_on,
                color_enabled: color,
            })?,
            ClipboardCmd::Hold => commands::clipboard::hold()?,
            ClipboardCmd::Mask {
                json,
                write,
                redaction,
                min_severity,
            } => commands::clipboard::mask(commands::clipboard::ClipboardMaskInvocation {
                json,
                write,
                redaction,
                min_severity,
            })?,
        },
        Commands::Completions { shell } => commands::completions::run(shell)?,
        Commands::Status => commands::status::run(&cwd)?,
        Commands::Audit {
            path,
            json,
            since,
            tool,
            reason,
            limit,
            no_paths,
        } => commands::audit::run(commands::audit::AuditInvocation {
            path,
            json,
            since,
            tool,
            reason,
            limit,
            hide_paths: no_paths,
        })?,
        Commands::Mcp { cmd } => match cmd {
            McpCmd::Audit {
                path,
                global,
                json,
                sarif,
                fail_on,
                verbose,
            } => commands::mcp::run(commands::mcp::McpAuditInvocation {
                path,
                global,
                json,
                sarif,
                fail_on,
                verbose,
                color_enabled: color,
            })?,
        },
        Commands::Doctor { cmd, json, strict } => match cmd {
            None => doctor::run_all(&cwd, json, strict)?,
            Some(_) if strict => {
                return Err(exit::CliExit::message(
                    2,
                    "--strict is only supported by the full `shk doctor` suite",
                )
                .into());
            }
            Some(DoctorCmd::Version) => version_check::run(json)?,
            Some(DoctorCmd::Ignore { path, fix }) => {
                let p = doctor::doctor_ignore_path(path);
                doctor::run_ignore(&p, fix)?
            }
            Some(DoctorCmd::Env { dotenvx, path }) => {
                let p = path.unwrap_or_else(|| cwd.clone());
                doctor::run_env(&p, dotenvx)?
            }
            Some(DoctorCmd::Workflows { path, fix }) => {
                let p = path.unwrap_or_else(|| cwd.clone());
                doctor::run_workflows(&p, fix, json)?
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
                log_blocked,
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
                        log_blocked,
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
        Commands::Allowlist { cmd } => match cmd {
            AllowlistCmd::Suggest {
                from,
                value_hash,
                reason,
                expires,
            } => commands::allowlist::suggest(commands::allowlist::SuggestArgs {
                from,
                value_hash,
                reason,
                expires,
            })?,
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
                    SkillToolArg::Antigravity => commands::skills::SkillTool::Antigravity,
                    SkillToolArg::ClaudeCode => commands::skills::SkillTool::ClaudeCode,
                    SkillToolArg::Codex => commands::skills::SkillTool::Codex,
                    SkillToolArg::Copilot => commands::skills::SkillTool::Copilot,
                    SkillToolArg::Cursor => commands::skills::SkillTool::Cursor,
                    SkillToolArg::Windsurf => commands::skills::SkillTool::Windsurf,
                    SkillToolArg::All => commands::skills::SkillTool::All,
                }),
                global,
                dry_run,
                force,
            })?,
        },
        Commands::Env { cmd } => match cmd {
            EnvCmd::Encrypt(args) => commands::env::encrypt(&cwd, args)?,
            EnvCmd::Decrypt(args) => commands::env::decrypt(&cwd, args)?,
            EnvCmd::Run(args) => commands::env::run(&cwd, args)?,
            EnvCmd::Key { cmd } => match cmd {
                EnvKeyCmd::Import(args) => commands::env::key_import(&cwd, args)?,
                EnvKeyCmd::List => commands::env::key_list(&cwd)?,
                EnvKeyCmd::Delete(args) => commands::env::key_delete(&cwd, args)?,
                EnvKeyCmd::Export(args) => commands::env::key_export(&cwd, args)?,
                EnvKeyCmd::Migrate(args) => commands::env::key_migrate(&cwd, args)?,
            },
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
