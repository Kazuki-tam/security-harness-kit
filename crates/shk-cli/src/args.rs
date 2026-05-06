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
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan repository or path for secrets and PII
    Scan {
        #[arg(value_name = "PATH", default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        staged: bool,
        #[arg(long)]
        json: bool,
        #[arg(long, value_name = "SEVERITY")]
        fail_on: Option<String>,
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
        #[arg(long)]
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
        #[arg(long)]
        all: bool,
        #[arg(long, value_enum)]
        tool: Option<AiTool>,
        /// Cursor hooks only: sets `failClosed` in injected entries.
        #[arg(long)]
        fail_closed: bool,
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
