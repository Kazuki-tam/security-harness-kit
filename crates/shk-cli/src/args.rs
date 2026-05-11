use clap::{ArgGroup, Args, Parser, Subcommand};
use clap_complete::Shell;
use shk_core::policy::Severity;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "shk",
    version,
    about = "Local-first security harness for AI-assisted development",
    propagate_version = true
)]
pub struct Cli {
    /// Disable colored human-readable output.
    #[arg(long, global = true)]
    pub no_color: bool,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Interactive first-run setup for policy, hooks, and agent skills
    Init {
        /// Use the strict starter policy profile.
        #[arg(long)]
        strict: bool,
        /// Overwrite existing managed files where supported.
        #[arg(long)]
        force: bool,
        /// Accept recommended defaults without prompting.
        #[arg(short = 'y', long)]
        yes: bool,
        /// Install AI hooks in audit-only mode.
        #[arg(long)]
        audit: bool,
        /// AI tools to configure: claude-code, codex, cursor. Repeat or use commas.
        #[arg(long, value_enum, value_delimiter = ',')]
        tool: Vec<AiTool>,
        /// Skip Git pre-commit hook setup.
        #[arg(long)]
        no_git_hook: bool,
        /// Skip AI editor hook setup.
        #[arg(long)]
        no_ai_hooks: bool,
        /// Skip bundled agent skill setup.
        #[arg(long)]
        no_skills: bool,
        /// Write AI hooks and skills to user-level config directories.
        #[arg(long)]
        global: bool,
        /// Apply supported AI-tool sandbox hardening while installing hooks.
        #[arg(long)]
        apply_sandbox: bool,
    },
    /// Scan repository or path for secrets and PII
    Scan {
        #[arg(value_name = "PATH", default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        staged: bool,
        #[arg(long)]
        json: bool,
        /// Show informational skip findings in human-readable output.
        #[arg(long)]
        verbose: bool,
        #[arg(long, value_enum, value_name = "SEVERITY")]
        fail_on: Option<SeverityArg>,
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
    /// Generate shell completion scripts
    Completions {
        #[arg(value_enum)]
        shell: Shell,
    },
    /// Show project health and CLI status
    Status,
    /// Project diagnostics
    Doctor {
        #[command(subcommand)]
        cmd: Option<DoctorCmd>,
        #[arg(long)]
        json: bool,
    },
    /// Hook installation (Git pre-commit and AI editor hooks)
    Hooks {
        #[command(subcommand)]
        cmd: HooksCmd,
    },
    /// Policy file helpers
    Policy {
        #[command(subcommand)]
        cmd: PolicyCmd,
    },
    /// Generate CI configuration
    Ci {
        #[command(subcommand)]
        cmd: CiCmd,
    },
    /// Manage AI tool skills bundled with shk
    Skills {
        #[command(subcommand)]
        cmd: SkillsCmd,
    },
    /// Secure local environment helpers
    Env {
        #[command(subcommand)]
        cmd: EnvCmd,
    },
    /// Push dotenv payloads into external secret managers
    Secrets {
        #[command(subcommand)]
        cmd: SecretsCmd,
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
        /// Apply supported sandbox hardening for Claude Code and Codex.
        ///
        /// Cursor does not expose a local sandbox setting in hooks.json; for Cursor this also
        /// enables fail-closed managed hooks.
        #[arg(long)]
        apply_sandbox: bool,
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

#[derive(Subcommand)]
pub enum CiCmd {
    /// Create CI workflow files
    Init {
        #[command(subcommand)]
        provider: CiInitProvider,
    },
}

#[derive(Subcommand)]
pub enum CiInitProvider {
    /// Create a GitHub Actions workflow
    Github(GithubCiArgs),
}

#[derive(Args)]
pub struct GithubCiArgs {
    /// Scan mode: blocking fails CI at or above --fail-on; audit always exits 0.
    #[arg(long, value_enum, default_value_t = CiModeArg::Blocking)]
    pub mode: CiModeArg,
    /// Severity threshold for blocking mode (info | low | medium | high | critical).
    /// Optional so the CLI can detect explicit overrides — useful for warning when
    /// `--mode audit` is combined with an explicit `--fail-on`. Defaults to `high`
    /// when unset; the help text below documents the effective default.
    #[arg(
        long,
        value_enum,
        value_name = "SEVERITY",
        help = "Severity threshold for blocking mode [default: high]"
    )]
    pub fail_on: Option<SeverityArg>,
    /// Path passed to `shk scan`.
    #[arg(long, default_value = ".")]
    pub path: String,
    /// GitHub owner/repository that hosts shk releases.
    #[arg(long, default_value = "Kazuki-tam/security-harness-kit")]
    pub repo: String,
    /// shk release version to install, or `latest` (e.g. `v0.2.3`).
    #[arg(long = "shk-version", default_value = "latest")]
    pub shk_version: String,
    /// cargo-dist shell installer asset name.
    #[arg(long, default_value = "shk-cli-installer.sh")]
    pub installer_name: String,
    /// Workflow destination path.
    #[arg(long, default_value = ".github/workflows/shk.yml")]
    pub output: PathBuf,
    /// Print the workflow without writing it.
    #[arg(long)]
    pub dry_run: bool,
    /// Overwrite an existing workflow file.
    #[arg(long)]
    pub force: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum CiModeArg {
    Blocking,
    Audit,
}

/// clap-validated severity shared by every subcommand that synthesises a scan threshold.
/// Unknown values are rejected at the CLI parsing layer with the standard clap error.
#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum SeverityArg {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl SeverityArg {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl From<SeverityArg> for Severity {
    fn from(value: SeverityArg) -> Self {
        match value {
            SeverityArg::Info => Severity::Info,
            SeverityArg::Low => Severity::Low,
            SeverityArg::Medium => Severity::Medium,
            SeverityArg::High => Severity::High,
            SeverityArg::Critical => Severity::Critical,
        }
    }
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum RedactionMode {
    Full,
    Match,
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

#[derive(Subcommand)]
pub enum EnvCmd {
    /// Store and inject dotenvx private keys with the OS credential store
    Dotenvx {
        #[command(subcommand)]
        cmd: DotenvxCmd,
    },
}

#[derive(Subcommand)]
pub enum DotenvxCmd {
    /// Import DOTENV_PRIVATE_KEY* entries from a .env.keys file
    ImportKeys {
        #[arg(value_name = "FILE", default_value = ".env.keys")]
        file: PathBuf,
    },
    /// List stored dotenvx private key names for this project
    List,
    /// Delete stored dotenvx private keys for this project
    Delete(DotenvxDeleteArgs),
    /// Run a command through dotenvx with private keys injected from the OS store
    Run(DotenvxRunArgs),
}

#[derive(Args)]
#[command(group(
    ArgGroup::new("target")
        .required(true)
        .multiple(false)
        .args(["all", "key", "env"])
))]
pub struct DotenvxDeleteArgs {
    /// Delete every stored dotenvx private key for this project.
    #[arg(long)]
    pub all: bool,
    /// Delete this exact DOTENV_PRIVATE_KEY* variable.
    #[arg(long)]
    pub key: Option<String>,
    /// Delete DOTENV_PRIVATE_KEY_<ENV>. Use `default` for DOTENV_PRIVATE_KEY.
    #[arg(long)]
    pub env: Option<String>,
}

#[derive(Args)]
pub struct DotenvxRunArgs {
    /// dotenvx executable to invoke.
    #[arg(long, default_value = "dotenvx")]
    pub dotenvx_bin: String,
    /// Pass one or more dotenvx env files, e.g. `-f .env.production`.
    #[arg(short = 'f', long = "file", value_name = "FILE")]
    pub files: Vec<PathBuf>,
    /// Only inject this exact DOTENV_PRIVATE_KEY* variable. Repeat as needed.
    #[arg(long = "key")]
    pub keys: Vec<String>,
    /// Only inject DOTENV_PRIVATE_KEY_<ENV>. Use `default` for DOTENV_PRIVATE_KEY.
    #[arg(long = "env")]
    pub envs: Vec<String>,
    /// Command to run after `dotenvx run --`.
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

#[derive(Subcommand)]
pub enum SecretsCmd {
    /// Push a dotenv file to AWS Secrets Manager or GCP Secret Manager
    Push(SecretsPushArgs),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum SecretProviderArg {
    Aws,
    Gcp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum SecretsPushModeArg {
    Blob,
    PerKey,
}

#[derive(Args)]
pub struct SecretsPushArgs {
    /// Read provider settings from [secrets.profiles.<name>] in shk.toml.
    #[arg(long)]
    pub profile: Option<String>,
    /// Secret manager provider.
    #[arg(long, value_enum)]
    pub provider: Option<SecretProviderArg>,
    /// Blob mode target secret name.
    #[arg(long, conflicts_with = "target_prefix")]
    pub target: Option<String>,
    /// Per-key mode target prefix.
    #[arg(long, conflicts_with = "target")]
    pub target_prefix: Option<String>,
    /// Source dotenv file.
    #[arg(long = "from", value_name = "FILE")]
    pub source: Option<PathBuf>,
    /// Push mode: blob stores the whole file; per-key stores each dotenv key separately.
    #[arg(long, value_enum)]
    pub mode: Option<SecretsPushModeArg>,
    /// Backward-compatible shorthand for --mode per-key.
    #[arg(long, hide = true, conflicts_with = "mode")]
    pub per_key: bool,
    /// Print planned writes without invoking provider CLIs.
    #[arg(long)]
    pub dry_run: bool,
    /// Append metadata-only audit entries.
    #[arg(long)]
    pub audit: bool,
    /// Prompt before writing.
    #[arg(long)]
    pub confirm: bool,
    /// Skip confirmation prompts.
    #[arg(long)]
    pub yes: bool,
    /// Create provider secrets when they are missing.
    #[arg(long)]
    pub create_if_missing: bool,
    /// Treat lint warnings as failures.
    #[arg(long)]
    pub strict: bool,
    /// Skip the pre-push PII scan.
    #[arg(long)]
    pub no_scan: bool,
    /// AWS region. Otherwise delegated to AWS CLI environment/config.
    #[arg(long)]
    pub region: Option<String>,
    /// GCP project. Otherwise delegated to gcloud environment/config.
    #[arg(long)]
    pub project: Option<String>,
    /// GCP location, defaulting to global.
    #[arg(long)]
    pub location: Option<String>,
    /// Expected environment name used by dotenv lint checks.
    #[arg(long)]
    pub expected_env: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Parser, error::ErrorKind};

    #[test]
    fn secrets_push_accepts_per_key_shorthand() {
        let cli = Cli::try_parse_from(["shk", "secrets", "push", "--per-key"])
            .expect("--per-key should remain available as a compatibility shorthand");

        let Commands::Secrets {
            cmd: SecretsCmd::Push(args),
        } = cli.command
        else {
            panic!("expected secrets push command");
        };

        assert!(args.per_key);
        assert_eq!(args.mode, None);
    }

    #[test]
    fn secrets_push_rejects_per_key_shorthand_with_mode() {
        let err =
            match Cli::try_parse_from(["shk", "secrets", "push", "--mode", "per-key", "--per-key"])
            {
                Ok(_) => panic!("--mode and --per-key should not both be accepted"),
                Err(err) => err,
            };

        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn secrets_push_rejects_target_and_target_prefix_together() {
        let err = match Cli::try_parse_from([
            "shk",
            "secrets",
            "push",
            "--target",
            "app/prod",
            "--target-prefix",
            "app/prod/",
        ]) {
            Ok(_) => panic!("--target and --target-prefix should not both be accepted"),
            Err(err) => err,
        };

        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum SkillToolArg {
    ClaudeCode,
    Codex,
    Cursor,
    All,
}
