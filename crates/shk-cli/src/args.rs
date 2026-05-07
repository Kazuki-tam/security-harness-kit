use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "shk",
    version,
    about = "Local-first security harness for AI-assisted development",
    propagate_version = true
)]
pub struct Cli {
    /// Disable colored human output.
    #[arg(long, global = true)]
    pub no_color: bool,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Create starter `shk.toml`
    Init {
        #[arg(long)]
        strict: bool,
        #[arg(long)]
        force: bool,
    },
    /// Scan repository or path for secrets and PII
    Scan {
        #[arg(value_name = "PATH", default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        staged: bool,
        #[arg(long)]
        json: bool,
        /// Show informational skip findings in human output.
        #[arg(long)]
        verbose: bool,
        #[arg(long, value_name = "SEVERITY")]
        fail_on: Option<String>,
        /// Include binary files instead of emitting scan.binary_skipped info findings.
        #[arg(long)]
        include_binary: bool,
        /// Follow symlinks during repository traversal.
        #[arg(long)]
        follow_symlinks: bool,
        /// Interpret stdin as AI tool hook JSON (see `_llm-docs/cli-implementation-spec.md` §7.9).
        #[arg(long, value_enum)]
        hook_mode: Option<AiTool>,
        /// Post-tool hook inbound scan — never blocks (spec §7.9).
        #[arg(long)]
        post: bool,
        /// Audit-only hooks: append JSON lines to `.shk/audit.log`, always exit 0.
        #[arg(long)]
        audit: bool,
    },
    /// Mask stdin or file (streaming-friendly line redaction)
    Mask {
        #[arg(value_name = "FILE")]
        file: Option<PathBuf>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long, value_enum)]
        redaction: Option<RedactionMode>,
        /// Interpret stdin as AI tool hook JSON and return masked hook output.
        #[arg(long, value_enum)]
        hook_mode: Option<AiTool>,
        /// Post-tool hook inbound masking mode.
        #[arg(long)]
        post: bool,
    },
    /// Project diagnostics
    Doctor {
        #[command(subcommand)]
        cmd: Option<DoctorCmd>,
        #[arg(long)]
        json: bool,
    },
    /// Git hook installation
    Hooks {
        #[command(subcommand)]
        cmd: HooksCmd,
    },
    /// Policy file helpers
    Policy {
        #[command(subcommand)]
        cmd: PolicyCmd,
    },
    /// Manage AI tool skills bundled with shk
    Skills {
        #[command(subcommand)]
        cmd: SkillsCmd,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum AiTool {
    ClaudeCode,
    Codex,
    Cursor,
}

impl AiTool {
    pub fn kebab_str(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
            Self::Cursor => "cursor",
        }
    }

    pub fn integration_tool(self) -> shk_integrations::AiHookTool {
        match self {
            Self::ClaudeCode => shk_integrations::AiHookTool::ClaudeCode,
            Self::Codex => shk_integrations::AiHookTool::Codex,
            Self::Cursor => shk_integrations::AiHookTool::Cursor,
        }
    }
}
#[derive(Subcommand)]
pub enum DoctorCmd {
    /// Check the latest released version
    Version,
    /// Check ignore coverage for Git and AI tools
    Ignore {
        #[arg(value_name = "PATH")]
        path: Option<PathBuf>,
        #[arg(long)]
        fix: bool,
    },
    /// Check .env-style files at project root
    Env {
        #[arg(long)]
        dotenvx: bool,
        #[arg(value_name = "PATH")]
        path: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub enum HooksCmd {
    /// Install Git pre-commit hook (runs `shk scan --staged`)
    Install {
        #[arg(long, help = "Explicit alias for the default pre-commit hook.")]
        pre_commit: bool,
    },
    /// Configure AI-editor hooks (Cursor / Claude Code / Codex)
    InstallAi {
        #[arg(
            long,
            help = "Append `--audit` to hook commands (non-blocking adoption)."
        )]
        audit: bool,
        #[arg(long)]
        dry_run: bool,
        #[arg(
            long,
            help = "Write user-level configs (~/.cursor, ~/.codex, ~/.claude)."
        )]
        global: bool,
        #[arg(long, value_enum)]
        tool: Option<AiTool>,
        /// Cursor hooks only: sets `failClosed` in injected entries.
        #[arg(long)]
        fail_closed: bool,
        /// Claude Code only: merge recommended permissions.deny action guard entries.
        #[arg(long)]
        apply_deny: bool,
    },
}

#[derive(Subcommand)]
pub enum PolicyCmd {
    /// Create starter `shk.toml`
    Init {
        #[arg(long)]
        strict: bool,
        #[arg(long)]
        force: bool,
    },
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum RedactionMode {
    Full,
    Partial,
}

#[derive(Subcommand)]
pub enum SkillsCmd {
    /// List built-in skills available for installation
    List,
    /// Show installation status for all supported tools
    Status,
    /// Install shk skill for Claude Code, Codex, and/or Cursor
    Install {
        /// Target tool: claude-code, codex, cursor, or all (default: all)
        #[arg(long, value_enum)]
        tool: Option<SkillToolArg>,
        /// Write to user-level directory (~/.claude/skills/ or ~/.agents/skills/)
        #[arg(long)]
        global: bool,
        /// Print planned changes without writing
        #[arg(long)]
        dry_run: bool,
        /// Overwrite an existing skill file
        #[arg(long)]
        force: bool,
    },
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum SkillToolArg {
    ClaudeCode,
    Codex,
    Cursor,
    All,
}
