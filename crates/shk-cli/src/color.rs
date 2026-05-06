use shk_core::policy::ColorMode;
use std::io::{self, IsTerminal};

pub fn resolve_color(cli: ColorMode) -> bool {
    let no_color = std::env::var("NO_COLOR")
        .map(|v| !v.is_empty())
        .unwrap_or(false);
    let clicolor_0 = std::env::var("CLICOLOR").map(|v| v == "0").unwrap_or(false);
    let clicolor_force = std::env::var("CLICOLOR_FORCE")
        .map(|v| v == "1")
        .unwrap_or(false);
    if no_color || clicolor_0 {
        return false;
    }
    match cli {
        ColorMode::Never => false,
        ColorMode::Always => true,
        ColorMode::Auto => clicolor_force || io::stdout().is_terminal(),
    }
}
