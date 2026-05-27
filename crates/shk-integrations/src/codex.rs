//! Codex configuration constants (aligned with OpenAI Codex docs).

pub const CONFIG_REL_PATH: &str = ".codex/config.toml";

pub const HOOKS_FEATURE_KEY: &str = "hooks";
pub const LEGACY_HOOKS_FEATURE_KEY: &str = "codex_hooks";

pub const RISKY_SANDBOX_MODE: &str = "danger-full-access";
pub const RECOMMENDED_SANDBOX_MODE: &str = "workspace-write";

pub const RISKY_APPROVAL_POLICY: &str = "never";
pub const RECOMMENDED_APPROVAL_POLICY: &str = "on-request";

pub const RISKY_DEFAULT_PERMISSIONS: &str = ":danger-full-access";
