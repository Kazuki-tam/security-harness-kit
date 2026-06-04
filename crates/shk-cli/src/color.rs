use shk_core::policy::ColorMode;
use std::io::{self, IsTerminal};

pub fn resolve_color(cli: ColorMode) -> bool {
    let no_color = std::env::var("NO_COLOR").ok();
    let clicolor = std::env::var("CLICOLOR").ok();
    let clicolor_force = std::env::var("CLICOLOR_FORCE").ok();
    resolve_color_with_env(
        cli,
        no_color.as_deref(),
        clicolor.as_deref(),
        clicolor_force.as_deref(),
        io::stdout().is_terminal(),
    )
}

fn resolve_color_with_env(
    cli: ColorMode,
    no_color: Option<&str>,
    clicolor: Option<&str>,
    clicolor_force: Option<&str>,
    stdout_is_terminal: bool,
) -> bool {
    let no_color = no_color.map(|v| !v.is_empty()).unwrap_or(false);
    let clicolor_0 = clicolor.map(|v| v == "0").unwrap_or(false);
    let clicolor_force = clicolor_force.map(|v| v == "1").unwrap_or(false);
    if no_color || clicolor_0 {
        return false;
    }
    match cli {
        ColorMode::Never => false,
        ColorMode::Always => true,
        ColorMode::Auto => clicolor_force || stdout_is_terminal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_mode_disables_color_even_with_force() {
        assert!(!resolve_color_with_env(
            ColorMode::Never,
            None,
            None,
            Some("1"),
            true,
        ));
    }

    #[test]
    fn always_mode_enables_color_when_no_color_unset() {
        assert!(resolve_color_with_env(
            ColorMode::Always,
            None,
            None,
            None,
            false,
        ));
    }

    #[test]
    fn no_color_env_disables_output() {
        assert!(!resolve_color_with_env(
            ColorMode::Always,
            Some("1"),
            None,
            None,
            true,
        ));
    }

    #[test]
    fn clicolor_zero_disables_output() {
        assert!(!resolve_color_with_env(
            ColorMode::Always,
            None,
            Some("0"),
            None,
            true,
        ));
    }

    #[test]
    fn auto_mode_uses_force_or_terminal_status() {
        assert!(resolve_color_with_env(
            ColorMode::Auto,
            None,
            None,
            Some("1"),
            false,
        ));
        assert!(resolve_color_with_env(
            ColorMode::Auto,
            None,
            None,
            None,
            true,
        ));
        assert!(!resolve_color_with_env(
            ColorMode::Auto,
            None,
            None,
            None,
            false,
        ));
    }
}
