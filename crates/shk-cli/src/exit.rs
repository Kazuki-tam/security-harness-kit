use anyhow::Error;
use std::fmt;

#[derive(Debug)]
pub(crate) struct CliExit {
    code: i32,
    message: Option<String>,
}

impl CliExit {
    pub(crate) fn silent(code: i32) -> Self {
        Self {
            code,
            message: None,
        }
    }

    pub(crate) fn message(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: Some(message.into()),
        }
    }
}

impl fmt::Display for CliExit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(message) = &self.message {
            f.write_str(message)
        } else {
            f.write_str("command exited")
        }
    }
}

impl std::error::Error for CliExit {}

pub(crate) fn code_for(err: &Error) -> i32 {
    err.chain()
        .find_map(|cause| cause.downcast_ref::<CliExit>().map(|exit| exit.code))
        .unwrap_or(1)
}

pub(crate) fn is_silent(err: &Error) -> bool {
    err.chain()
        .find_map(|cause| {
            cause
                .downcast_ref::<CliExit>()
                .map(|exit| exit.message.is_none())
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

    #[test]
    fn display_uses_message_when_present() {
        let exit = CliExit::message(2, "blocked by policy");

        assert_eq!(exit.to_string(), "blocked by policy");
    }

    #[test]
    fn display_uses_generic_text_for_silent_exit() {
        let exit = CliExit::silent(0);

        assert_eq!(exit.to_string(), "command exited");
    }

    #[test]
    fn code_for_extracts_nested_cli_exit_code() {
        let err = anyhow!(CliExit::message(2, "blocked")).context("wrapper");

        assert_eq!(code_for(&err), 2);
    }

    #[test]
    fn code_for_defaults_to_one_without_cli_exit() {
        let err = anyhow!("plain failure");

        assert_eq!(code_for(&err), 1);
    }

    #[test]
    fn is_silent_detects_silent_cli_exit() {
        let err = anyhow!(CliExit::silent(0)).context("wrapper");

        assert!(is_silent(&err));
    }

    #[test]
    fn is_silent_is_false_for_message_exit_and_plain_errors() {
        let message = anyhow!(CliExit::message(1, "failed"));
        let plain = anyhow!("plain failure");

        assert!(!is_silent(&message));
        assert!(!is_silent(&plain));
    }
}
