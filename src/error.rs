// SPDX-License-Identifier: GPL-3.0-or-later

use std::{fmt::Write as _, process::ExitCode};

pub type Result<T> = std::result::Result<T, AppError>;

#[must_use]
pub fn format_error_chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut rendered = error.to_string();
    let mut source = error.source();
    while let Some(error) = source {
        let _ = write!(rendered, ": {error}");
        source = error.source();
    }
    rendered
}

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    Config(String),
    #[error("{0}")]
    Runtime(String),
    #[error("profile '{0}' is unknown or inactive")]
    UnknownProfile(String),
    #[error("{0}")]
    Platform(String),
    #[error("{0}")]
    Ipc(String),
    #[error("{0}")]
    StatusUnavailable(String),
    #[error("administrator authorization is required for VPN control")]
    AuthorizationRequired,
}

impl AppError {
    #[must_use]
    pub const fn exit_status(&self) -> ExitStatus {
        match self {
            Self::Config(_) => ExitStatus::Invalid,
            Self::UnknownProfile(_) => ExitStatus::UnknownProfile,
            Self::Platform(_) => ExitStatus::Platform,
            Self::AuthorizationRequired => ExitStatus::AuthorizationRequired,
            Self::Runtime(_) | Self::Ipc(_) | Self::StatusUnavailable(_) => ExitStatus::Runtime,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ExitStatus {
    Success = 0,
    Runtime = 1,
    Invalid = 2,
    UnknownProfile = 3,
    Platform = 4,
    AuthorizationRequired = 5,
}

impl From<ExitStatus> for ExitCode {
    fn from(value: ExitStatus) -> Self {
        Self::from(value as u8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, thiserror::Error)]
    #[error("outer failure")]
    struct OuterError(#[source] std::io::Error);

    #[test]
    fn error_chain_includes_nested_causes() {
        let error = OuterError(std::io::Error::from_raw_os_error(libc::EHOSTUNREACH));
        let rendered = format_error_chain(&error);
        assert!(rendered.starts_with("outer failure: "));
        assert!(rendered.contains("No route to host"));
    }
}
