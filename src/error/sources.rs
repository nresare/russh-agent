// Copyright (c) 2020 russh-agent developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! `russh-agent` Error Sources
use crate::error::{ErrCode, Error};
use std::fmt;

macro_rules! dep_error {
    ($error:ty, $kind:expr, $code:expr, $reason:expr) => {
        impl From<$error> for Error {
            #[must_use]
            fn from(inner: $error) -> Self {
                Self::new($code, $reason, Some($kind(inner)))
            }
        }
    };
}

dep_error!(
    std::env::VarError,
    ErrSource::Var,
    ErrCode::Env,
    "There was an error processing your enviroment"
);
dep_error!(
    std::io::Error,
    ErrSource::Io,
    ErrCode::Io,
    "There was an error processing your request"
);
dep_error!(
    tokio::sync::mpsc::error::SendError<bytes::Bytes>,
    ErrSource::SendBytes,
    ErrCode::Io,
    "There was an error sending out bytes"
);
#[cfg(test)]
dep_error!(
    tokio::sync::mpsc::error::SendError<crate::client::Message>,
    ErrSource::SendMessage,
    ErrCode::Io,
    "There was an error sending out bytes"
);
dep_error!(
    std::num::TryFromIntError,
    ErrSource::TryFromInt,
    ErrCode::Parse,
    "There was an error converting from an int"
);
#[cfg(test)]
dep_error!(
    std::fmt::Error,
    ErrSource::Fmt,
    ErrCode::Io,
    "There was an error in the formatting test"
);
#[cfg(test)]
dep_error!(
    tokio::task::JoinError,
    ErrSource::Join,
    ErrCode::Protocol,
    "There was an error at the tokio join point"
);

/// DataQ Error Source
#[derive(Debug)]
#[allow(clippy::large_enum_variant, variant_size_differences)]
pub enum ErrSource {
    #[cfg(test)]
    /// An error
    Fmt(std::fmt::Error),
    /// An I/O error
    Io(std::io::Error),
    #[cfg(test)]
    /// An error at join on a spawned task
    Join(tokio::task::JoinError),
    /// An error occurred trying to send bytes
    SendBytes(tokio::sync::mpsc::error::SendError<bytes::Bytes>),
    #[cfg(test)]
    /// An error occurred trying to send bytes
    SendMessage(tokio::sync::mpsc::error::SendError<crate::client::Message>),
    /// An error converting from an int
    TryFromInt(std::num::TryFromIntError),
    /// An error reading an environment variable
    Var(std::env::VarError),
}

impl std::error::Error for ErrSource {}

impl fmt::Display for ErrSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(test)]
            Self::Fmt(source) => write!(f, "{}", source),
            Self::Io(source) => write!(f, "{}", source),
            #[cfg(test)]
            Self::Join(source) => write!(f, "{}", source),
            Self::SendBytes(source) => write!(f, "{}", source),
            #[cfg(test)]
            Self::SendMessage(source) => write!(f, "{}", source),
            Self::TryFromInt(source) => write!(f, "{}", source),
            Self::Var(source) => write!(f, "{}", source),
        }
    }
}
