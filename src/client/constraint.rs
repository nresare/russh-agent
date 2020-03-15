// Copyright (c) 2020 russh-agent developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! `russh-agent` constraints
//!
//! # Example
//! ```
//! # use russh_agent::client::Constraint;
//! let _constraint = Constraint::lifetime(3600);
//! ```

use bytes::{BufMut, Bytes, BytesMut};
use getset::Getters;
use std::fmt;

const SSH_AGENT_CONSTRAIN_LIFETIME: u8 = 1;
const SSH_AGENT_CONSTRAIN_LIFETIME_S: &str = "SSH_AGENT_CONSTRAIN_LIFETIME";
const SSH_AGENT_CONSTRAIN_CONFIRM: u8 = 2;
const SSH_AGENT_CONSTRAIN_CONFIRM_S: &str = "SSH_AGENT_CONSTRAIN_CONFIRM";
const SSH_AGENT_CONSTRAIN_EXTENSION: u8 = 3;
const SSH_AGENT_CONSTRAIN_EXTENSION_S: &str = "SSH_AGENT_CONSTRAIN_EXTENSION";

#[derive(Clone, Debug, Getters)]
/// An ssh key constraint
#[get = "pub"]
pub struct Constraint {
    /// The constraint kind
    kind: u8,
    /// The constraint payload
    payload: Bytes,
}

impl fmt::Display for Constraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self.kind {
                SSH_AGENT_CONSTRAIN_LIFETIME => SSH_AGENT_CONSTRAIN_LIFETIME_S,
                SSH_AGENT_CONSTRAIN_CONFIRM => SSH_AGENT_CONSTRAIN_CONFIRM_S,
                SSH_AGENT_CONSTRAIN_EXTENSION => SSH_AGENT_CONSTRAIN_EXTENSION_S,
                _ => "unknown",
            }
        )
    }
}

impl Constraint {
    /// Create a lifetime constraint
    #[must_use]
    pub fn lifetime(seconds: u32) -> Self {
        let mut payload_b = BytesMut::new();
        payload_b.put_u8(SSH_AGENT_CONSTRAIN_LIFETIME);
        payload_b.put_u32(seconds);
        let payload = payload_b.freeze();
        Self {
            kind: SSH_AGENT_CONSTRAIN_LIFETIME,
            payload,
        }
    }

    /// Create a confirm constraint
    #[must_use]
    pub fn confirm() -> Self {
        let mut payload_b = BytesMut::new();
        payload_b.put_u8(SSH_AGENT_CONSTRAIN_CONFIRM);
        let payload = payload_b.freeze();
        Self {
            kind: SSH_AGENT_CONSTRAIN_CONFIRM,
            payload,
        }
    }
}
