// Copyright (c) 2020 russh-agent developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! `russh-agent` inbound messages
//!
//! # Example
//! ```
//! # use russh_agent::client::Message;
//! let _msg = Message::List;
//! ```

use bytes::Bytes;
use std::fmt;

const REQUEST_IDENTITIES: &'static str = "Request Identities";
const SIGNATURE_REQUEST: &'static str = "Signature Request";

/// Agent Messages
#[derive(Clone, Debug)]
pub enum Message {
    /// List of keys from the agent
    List,
    /// Sign the given bytes
    Sign(Bytes, Bytes),
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::List => REQUEST_IDENTITIES,
                Self::Sign(_, _) => SIGNATURE_REQUEST,
            }
        )
    }
}

#[cfg(test)]
mod test {
    use super::{Message, REQUEST_IDENTITIES, SIGNATURE_REQUEST};
    use crate::error::Result;
    use bytes::Bytes;
    use std::fmt;

    #[test]
    fn display() -> Result<()> {
        let mut buf = String::new();
        fmt::write(&mut buf, format_args!("{}", Message::List))?;
        assert_eq!(buf, REQUEST_IDENTITIES);
        buf.clear();
        fmt::write(
            &mut buf,
            format_args!("{}", Message::Sign(Bytes::default(), Bytes::default())),
        )?;
        assert_eq!(buf, SIGNATURE_REQUEST);
        Ok(())
    }
}
