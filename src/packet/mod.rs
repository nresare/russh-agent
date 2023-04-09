// Copyright (c) 2020 russh-agent developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! `russh-agent` packet handling

pub(crate) mod identity;
pub(crate) mod lock;
pub(crate) mod sign;
pub(crate) mod unlock;

use crate::error::{Error, Result};
use agent_msg::{
    SSH_AGENTC_ADD_IDENTITY, SSH_AGENTC_ADD_IDENTITYS_S, SSH_AGENTC_ADD_ID_CONSTRAINED,
    SSH_AGENTC_ADD_ID_CONSTRAINED_S, SSH_AGENTC_ADD_SMARTCARD_KEY,
    SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED, SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED_S,
    SSH_AGENTC_ADD_SMARTCARD_KEY_S, SSH_AGENTC_EXTENSION, SSH_AGENTC_EXTENSION_S,
    SSH_AGENTC_IDENTITIES_ANSWER, SSH_AGENTC_IDENTITIES_ANSWER_S, SSH_AGENTC_LOCK,
    SSH_AGENTC_LOCK_S, SSH_AGENTC_REMOVE_ALL_IDENTITIES, SSH_AGENTC_REMOVE_ALL_IDENTITIES_S,
    SSH_AGENTC_REMOVE_IDENTITY, SSH_AGENTC_REMOVE_IDENTITY_S, SSH_AGENTC_REMOVE_SMARTCARD_KEY,
    SSH_AGENTC_REMOVE_SMARTCARD_KEY_S, SSH_AGENTC_REQUEST_IDENTITIES,
    SSH_AGENTC_REQUEST_IDENTITIES_S, SSH_AGENTC_SIGN_REQUEST, SSH_AGENTC_SIGN_REQUEST_S,
    SSH_AGENTC_SIGN_RESPONSE, SSH_AGENTC_SIGN_RESPONSE_S, SSH_AGENTC_UNLOCK, SSH_AGENTC_UNLOCK_S,
    SSH_AGENT_EXTENSION_FAILURE, SSH_AGENT_EXTENSION_FAILURE_S, SSH_AGENT_FAILURE,
    SSH_AGENT_FAILURE_S, SSH_AGENT_SUCCESS, SSH_AGENT_SUCCESS_S, UNKNOWN, UNKNOWN_S,
};
use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, Bytes, BytesMut};
use getset::{Getters, Setters};
use std::{convert::TryFrom, fmt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// Agent Message Constants
//
// See https://tools.ietf.org/html/draft-miller-ssh-agent-00#section-7.1
mod agent_msg {
    pub(crate) const UNKNOWN: u8 = 0;
    pub(crate) const UNKNOWN_S: &str = "UNKNOWN";

    pub(crate) const SSH_AGENT_FAILURE: u8 = 5;
    pub(crate) const SSH_AGENT_FAILURE_S: &str = "SSH_AGENT_FAILURE";
    pub(crate) const SSH_AGENT_SUCCESS: u8 = 6;
    pub(crate) const SSH_AGENT_SUCCESS_S: &str = "SSH_AGENT_SUCCESS";

    pub(crate) const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
    pub(crate) const SSH_AGENTC_REQUEST_IDENTITIES_S: &str = "SSH_AGENTC_REQUEST_IDENTITIES";
    pub(crate) const SSH_AGENTC_IDENTITIES_ANSWER: u8 = 12;
    pub(crate) const SSH_AGENTC_IDENTITIES_ANSWER_S: &str = "SSH_AGENTC_IDENTITIES_ANSWER";
    pub(crate) const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
    pub(crate) const SSH_AGENTC_SIGN_REQUEST_S: &str = "SSH_AGENTC_SIGN_REQUEST";
    pub(crate) const SSH_AGENTC_SIGN_RESPONSE: u8 = 14;
    pub(crate) const SSH_AGENTC_SIGN_RESPONSE_S: &str = "SSH_AGENTC_SIGN_RESPONSE";

    pub(crate) const SSH_AGENTC_ADD_IDENTITY: u8 = 17;
    pub(crate) const SSH_AGENTC_ADD_IDENTITYS_S: &str = "SSH_AGENTC_ADD_IDENTITY";
    pub(crate) const SSH_AGENTC_REMOVE_IDENTITY: u8 = 18;
    pub(crate) const SSH_AGENTC_REMOVE_IDENTITY_S: &str = "SSH_AGENTC_REMOVE_IDENTITY";
    pub(crate) const SSH_AGENTC_REMOVE_ALL_IDENTITIES: u8 = 19;
    pub(crate) const SSH_AGENTC_REMOVE_ALL_IDENTITIES_S: &str = "SSH_AGENTC_REMOVE_ALL_IDENTITIES";
    pub(crate) const SSH_AGENTC_ADD_SMARTCARD_KEY: u8 = 20;
    pub(crate) const SSH_AGENTC_ADD_SMARTCARD_KEY_S: &str = "SSH_AGENTC_ADD_SMARTCARD_KEY";
    pub(crate) const SSH_AGENTC_REMOVE_SMARTCARD_KEY: u8 = 21;
    pub(crate) const SSH_AGENTC_REMOVE_SMARTCARD_KEY_S: &str = "SSH_AGENTC_REMOVE_SMARTCARD_KEY";
    pub(crate) const SSH_AGENTC_LOCK: u8 = 22;
    pub(crate) const SSH_AGENTC_LOCK_S: &str = "SSH_AGENTC_LOCK";
    pub(crate) const SSH_AGENTC_UNLOCK: u8 = 23;
    pub(crate) const SSH_AGENTC_UNLOCK_S: &str = "SSH_AGENTC_UNLOCK";

    pub(crate) const SSH_AGENTC_ADD_ID_CONSTRAINED: u8 = 25;
    pub(crate) const SSH_AGENTC_ADD_ID_CONSTRAINED_S: &str = "SSH_AGENTC_ADD_ID_CONSTRAINED";
    pub(crate) const SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED: u8 = 26;
    pub(crate) const SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED_S: &str =
        "SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED";
    pub(crate) const SSH_AGENTC_EXTENSION: u8 = 27;
    pub(crate) const SSH_AGENTC_EXTENSION_S: &str = "SSH_AGENTC_EXTENSION";
    pub(crate) const SSH_AGENT_EXTENSION_FAILURE: u8 = 28;
    pub(crate) const SSH_AGENT_EXTENSION_FAILURE_S: &str = "SSH_AGENT_EXTENSION_FAILURE";
}

pub(crate) trait IntoPacket {
    fn into_packet(&self) -> Result<Packet>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum PacketKind {
    Unknown = UNKNOWN,
    Failure = SSH_AGENT_FAILURE,
    Success = SSH_AGENT_SUCCESS,
    RequestIdentities = SSH_AGENTC_REQUEST_IDENTITIES,
    IdentitiesAnswer = SSH_AGENTC_IDENTITIES_ANSWER,
    SignRequest = SSH_AGENTC_SIGN_REQUEST,
    SignResponse = SSH_AGENTC_SIGN_RESPONSE,
    AddIdentity = SSH_AGENTC_ADD_IDENTITY,
    RemoveIdentity = SSH_AGENTC_REMOVE_IDENTITY,
    RemoveAllIdentities = SSH_AGENTC_REMOVE_ALL_IDENTITIES,
    AddSmartcardKey = SSH_AGENTC_ADD_SMARTCARD_KEY,
    RemoveSmartcardKey = SSH_AGENTC_REMOVE_SMARTCARD_KEY,
    Lock = SSH_AGENTC_LOCK,
    Unlock = SSH_AGENTC_UNLOCK,
    AddIdConstrained = SSH_AGENTC_ADD_ID_CONSTRAINED,
    AddSmartcardKeyConstrained = SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED,
    Extension = SSH_AGENTC_EXTENSION,
    ExtensionFailure = SSH_AGENT_EXTENSION_FAILURE,
}

impl Default for PacketKind {
    fn default() -> Self {
        PacketKind::Unknown
    }
}

impl fmt::Display for PacketKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Unknown => UNKNOWN_S,
                Self::Failure => SSH_AGENT_FAILURE_S,
                Self::Success => SSH_AGENT_SUCCESS_S,
                Self::RequestIdentities => SSH_AGENTC_REQUEST_IDENTITIES_S,
                Self::IdentitiesAnswer => SSH_AGENTC_IDENTITIES_ANSWER_S,
                Self::SignRequest => SSH_AGENTC_SIGN_REQUEST_S,
                Self::SignResponse => SSH_AGENTC_SIGN_RESPONSE_S,
                Self::AddIdentity => SSH_AGENTC_ADD_IDENTITYS_S,
                Self::RemoveIdentity => SSH_AGENTC_REMOVE_IDENTITY_S,
                Self::RemoveAllIdentities => SSH_AGENTC_REMOVE_ALL_IDENTITIES_S,
                Self::AddSmartcardKey => SSH_AGENTC_ADD_SMARTCARD_KEY_S,
                Self::RemoveSmartcardKey => SSH_AGENTC_REMOVE_SMARTCARD_KEY_S,
                Self::Lock => SSH_AGENTC_LOCK_S,
                Self::Unlock => SSH_AGENTC_UNLOCK_S,
                Self::AddIdConstrained => SSH_AGENTC_ADD_ID_CONSTRAINED_S,
                Self::AddSmartcardKeyConstrained => SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED_S,
                Self::Extension => SSH_AGENTC_EXTENSION_S,
                Self::ExtensionFailure => SSH_AGENT_EXTENSION_FAILURE_S,
            }
        )
    }
}

impl TryFrom<u8> for PacketKind {
    type Error = Error;

    fn try_from(val: u8) -> Result<Self> {
        match val {
            SSH_AGENT_FAILURE => Ok(Self::Failure),
            SSH_AGENT_SUCCESS => Ok(Self::Success),
            SSH_AGENTC_REQUEST_IDENTITIES => Ok(Self::RequestIdentities),
            SSH_AGENTC_IDENTITIES_ANSWER => Ok(Self::IdentitiesAnswer),
            SSH_AGENTC_SIGN_REQUEST => Ok(Self::SignRequest),
            SSH_AGENTC_SIGN_RESPONSE => Ok(Self::SignResponse),
            SSH_AGENTC_ADD_IDENTITY => Ok(Self::AddIdentity),
            SSH_AGENTC_REMOVE_IDENTITY => Ok(Self::RemoveIdentity),
            SSH_AGENTC_REMOVE_ALL_IDENTITIES => Ok(Self::RemoveAllIdentities),
            SSH_AGENTC_ADD_SMARTCARD_KEY => Ok(Self::AddSmartcardKey),
            SSH_AGENTC_REMOVE_SMARTCARD_KEY => Ok(Self::RemoveSmartcardKey),
            SSH_AGENTC_LOCK => Ok(Self::Lock),
            SSH_AGENTC_UNLOCK => Ok(Self::Unlock),
            SSH_AGENTC_ADD_ID_CONSTRAINED => Ok(Self::AddIdConstrained),
            SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED => Ok(Self::AddSmartcardKeyConstrained),
            SSH_AGENTC_EXTENSION => Ok(Self::Extension),
            SSH_AGENT_EXTENSION_FAILURE => Ok(Self::ExtensionFailure),
            _ => Err(Error::unknown_packet_kind(val)),
        }
    }
}

impl Into<u8> for PacketKind {
    fn into(self) -> u8 {
        self as u8
    }
}

impl PacketKind {
    pub(crate) fn is_response(&self) -> bool {
        match self {
            Self::Failure
            | Self::Success
            | Self::IdentitiesAnswer
            | Self::SignResponse
            | Self::ExtensionFailure => true,
            _ => false,
        }
    }
}

const MESSAGE_LEN: usize = 4;

#[derive(Clone, Debug, Default, Eq, Getters, PartialEq, Setters)]
#[get = "pub(crate)"]
#[set = "pub(crate)"]
pub(crate) struct Packet {
    kind: PacketKind,
    payload: Bytes,
}

impl fmt::Display for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Packet {{ ")?;
        write!(f, "kind: {}, ", self.kind)?;
        write!(f, "payload: [{} bytes]", self.payload.len())?;
        write!(f, " }}")
    }
}

impl Packet {
    pub(crate) async fn write_packet<S>(self, stream: &mut S) -> Result<()>
    where
        S: AsyncWrite + Unpin + Send,
    {
        let mut final_packet = BytesMut::new();

        let message_length = self.payload.len();
        final_packet.put_u32(u32::try_from(message_length)?);
        final_packet.put_slice(self.payload());
        let fp = final_packet.freeze();

        stream.write_all(&fp).await?;

        Ok(())
    }

    pub(crate) async fn read_packet<S>(stream: &mut S) -> Result<Self>
    where
        S: AsyncRead + Unpin + Send,
    {
        // Setup the packet
        let mut packet = Packet::default();

        // Read the message length bytes
        let mut mlen_bytes = vec![0_u8; MESSAGE_LEN];
        let bytes_read = stream.read_exact(&mut mlen_bytes).await?;
        assert_eq!(bytes_read, MESSAGE_LEN);
        let mlen = BigEndian::read_u32(&mlen_bytes);

        // Read the payload bytes
        if mlen > 0 {
            let mut payload_bytes = vec![0_u8; mlen as usize];
            let bytes_read = stream.read_exact(&mut payload_bytes).await?;
            assert_eq!(bytes_read, mlen as usize);

            packet.kind = PacketKind::try_from(payload_bytes[0])?;
            packet.payload = Bytes::copy_from_slice(&payload_bytes[..]);
        }

        Ok(packet)
    }
}

#[cfg(test)]
mod test {
    use super::{Packet, PacketKind};
    use crate::error::Result;
    use bytes::Bytes;
    use std::{fmt, io::Cursor};

    #[tokio::test]
    async fn write_pkt() -> Result<()> {
        let mut actual = Vec::new();

        let mut pkt = Packet::default();
        let _ = pkt.set_kind(PacketKind::SignRequest);
        let _ = pkt.set_payload(Bytes::from_static(&[13, 0, 0, 0, 3, b'a', b'b', b'c']));

        pkt.write_packet(&mut actual).await?;

        let expected = &[0, 0, 0, 8, 13, 0, 0, 0, 3, b'a', b'b', b'c'];

        assert_eq!(actual, expected);
        Ok(())
    }

    #[tokio::test]
    async fn read_pkt() -> Result<()> {
        let mut stream = Cursor::new(vec![0, 0, 0, 8, 13, 0, 0, 0, 3, b'a', b'b', b'c']);

        let mut expected = Packet::default();
        let _ = expected.set_kind(PacketKind::SignRequest);
        let _ = expected.set_payload(Bytes::from_static(&[13, 0, 0, 0, 3, b'a', b'b', b'c']));

        let actual = Packet::read_packet(&mut stream).await?;
        assert_eq!(actual, expected);
        Ok(())
    }

    const PACKET_EXPECTED: &str = r#"Packet { kind: SSH_AGENTC_SIGN_REQUEST, payload: [8 bytes] }"#;

    #[test]
    fn display() -> Result<()> {
        let mut buf = String::new();
        let mut expected = Packet::default();
        let _ = expected.set_kind(PacketKind::SignRequest);
        let _ = expected.set_payload(Bytes::from_static(&[13, 0, 0, 0, 3, b'a', b'b', b'c']));
        fmt::write(&mut buf, format_args!("{}", expected))?;
        assert_eq!(buf, PACKET_EXPECTED);
        Ok(())
    }
}
