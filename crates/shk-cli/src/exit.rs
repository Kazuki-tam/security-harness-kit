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
