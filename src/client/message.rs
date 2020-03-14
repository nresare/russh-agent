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

const ADD_IDENTITY: &'static str = "Add Identity";
const REMOVE_IDENTITY: &'static str = "Remove Identity";
const REMOVE_ALL_IDENTITIES: &'static str = "Remove All Identities";
const REQUEST_IDENTITIES: &'static str = "Request Identities";
const SIGNATURE_REQUEST: &'static str = "Signature Request";
const LOCK: &'static str = "Lock";
const UNLOCK: &'static str = "Unlock";
const SHUTDOWN: &'static str = "Shutdown";

/// Agent Messages
#[derive(Clone, Debug)]
pub enum Message {
    /// Add an identity to the agent, (i.e. Add(type, key, comment))
    Add(Bytes, Bytes, Bytes),
    /// Remove an identity from the agent
    Remove(Bytes),
    /// Remove all identities
    RemoveAll,
    /// List the identities stored on the agent
    List,
    /// Sign the given data with the key (i.e. Sign(key, data, flags))
    ///
    /// # Notes
    /// The flags are only valid for "ssh-rsa" sign requests.
    /// See https://tools.ietf.org/html/draft-miller-ssh-agent-00#section-4.5.1
    Sign(Bytes, Bytes, u32),
    /// Lock the agent with the given passphrase (i.e. Lock(passphrase))
    /// See https://tools.ietf.org/html/draft-miller-ssh-agent-00#section-4.6
    Lock(Bytes),
    /// Lock the agent with the given passphrase (i.e. Unlock(passphrase))
    /// See https://tools.ietf.org/html/draft-miller-ssh-agent-00#section-4.6
    Unlock(Bytes),
    /// Shutdown the client
    Shutdown,
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Add(_, _, _) => ADD_IDENTITY,
                Self::Remove(_) => REMOVE_IDENTITY,
                Self::RemoveAll => REMOVE_ALL_IDENTITIES,
                Self::List => REQUEST_IDENTITIES,
                Self::Sign(_, _, _) => SIGNATURE_REQUEST,
                Self::Lock(_) => LOCK,
                Self::Unlock(_) => UNLOCK,
                Self::Shutdown => SHUTDOWN,
            }
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::error::Result;
    use bytes::Bytes;
    use lazy_static::lazy_static;
    use std::fmt;

    lazy_static! {
        static ref TEST_CASE_1: (&'static str, Message) = (REQUEST_IDENTITIES, Message::List);
        static ref TEST_CASE_2: (&'static str, Message) = (
            SIGNATURE_REQUEST,
            Message::Sign(Bytes::default(), Bytes::default(), 0)
        );
        static ref TEST_CASE_3: (&'static str, Message) = (SHUTDOWN, Message::Shutdown);
        static ref TEST_CASE_4: (&'static str, Message) = (LOCK, Message::Lock(Bytes::default()));
        static ref TEST_CASE_5: (&'static str, Message) =
            (UNLOCK, Message::Unlock(Bytes::default()));
        static ref TEST_CASE_6: (&'static str, Message) =
            (REMOVE_IDENTITY, Message::Remove(Bytes::default()));
        static ref TEST_CASE_7: (&'static str, Message) =
            (REMOVE_ALL_IDENTITIES, Message::RemoveAll);
        static ref TEST_CASES: Vec<(&'static str, Message)> = {
            let mut test_cases = Vec::new();
            test_cases.push(TEST_CASE_1.clone());
            test_cases.push(TEST_CASE_2.clone());
            test_cases.push(TEST_CASE_3.clone());
            test_cases.push(TEST_CASE_4.clone());
            test_cases.push(TEST_CASE_5.clone());
            test_cases.push(TEST_CASE_6.clone());
            test_cases.push(TEST_CASE_7.clone());
            test_cases
        };
    }

    #[test]
    fn display() -> Result<()> {
        let mut buf = String::new();

        for (s, message) in &*TEST_CASES {
            fmt::write(&mut buf, format_args!("{}", message))?;
            assert_eq!(buf, *s);
            buf.clear();
        }
        Ok(())
    }
}
