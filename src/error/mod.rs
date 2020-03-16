// Copyright (c) 2020 russh_agent developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! `russh_agent` errors
mod codes;
mod sources;

crate use codes::ErrCode;
pub use sources::ErrSource;

use std::fmt;

/// A result that must include a [Error]
pub type Result<T> = std::result::Result<T, Error>;

/// `russh-agent` error
#[derive(Debug)]
pub struct Error {
    /// the code
    code: ErrCode,
    /// the reason
    reason: String,
    /// the source
    source: Option<ErrSource>,
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        self.code == other.code
            && self.reason == other.reason
            && (self.source.is_none() && other.source.is_none()
                || self.source.is_some() && other.source.is_some())
    }
}

impl Error {
    crate fn new<U>(code: ErrCode, reason: U, source: Option<ErrSource>) -> Self
    where
        U: Into<String>,
    {
        let reason = reason.into();

        Self {
            code,
            reason,
            source,
        }
    }

    crate fn unknown_packet_kind(val: u8) -> Self {
        Self::new(
            ErrCode::Protocol,
            format!("The value {} cannot be converted to a PacketKind", val),
            None,
        )
    }

    // #[cfg(test)]
    // crate fn invalid_ssh_string() -> Self {
    //     Self::new(ErrCode::Protocol, "Tried to read an invalid string", None)
    // }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(ref x) = self.source {
            Some(x)
        } else {
            None
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let err: &(dyn std::error::Error) = self;
        let mut iter = err.chain();
        let _skip_me = iter.next();
        write!(f, "{}: {}", self.code, self.reason)?;

        for e in iter {
            writeln!(f)?;
            write!(f, "{}", e)?;
        }

        Ok(())
    }
}

impl From<&str> for Error {
    fn from(text: &str) -> Self {
        let split = text.split(':');
        let vec = split.collect::<Vec<&str>>();
        let code = vec.get(0).unwrap_or_else(|| &"");
        let reason = vec.get(1).unwrap_or_else(|| &"");
        Self::new((*code).into(), *reason, None)
    }
}

impl From<String> for Error {
    fn from(text: String) -> Self {
        let split = text.split(':');
        let vec = split.collect::<Vec<&str>>();
        let code = vec.get(0).unwrap_or_else(|| &"");
        let reason = vec.get(1).unwrap_or_else(|| &"");
        Self::new((*code).into(), *reason, None)
    }
}

#[cfg(test)]
mod test {
    use super::{Error, Result};
    use crate::error::{ErrCode, ErrSource};
    use std::{fmt, io::ErrorKind};

    #[test]
    fn from_str() {
        let actual = Error::from("env:a_reason");
        let expected = Error::new(ErrCode::Env, "a_reason", None);
        assert_eq!(actual, expected);

        let actual_s = Error::from("env:a_reason".to_string());
        assert_eq!(actual_s, expected);
    }

    #[test]
    fn generated() {
        let actual = Error::unknown_packet_kind(8);
        let expected = Error::new(
            ErrCode::Protocol,
            "The value 8 cannot be converted to a PacketKind",
            None,
        );
        assert_eq!(actual, expected);
    }

    #[test]
    fn display() -> Result<()> {
        let mut buf = String::new();
        let actual = Error::new(
            ErrCode::Protocol,
            "Something",
            Some(ErrSource::Io(std::io::Error::new(
                ErrorKind::Other,
                "oh no!",
            ))),
        );
        fmt::write(&mut buf, format_args!("{}", actual))?;
        assert_eq!(buf, "protocol: Something\noh no!".to_string());
        buf.clear();
        Ok(())
    }
}
