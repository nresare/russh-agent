// Copyright (c) 2020 russh-agent developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! `russh-agent` packet handling

crate mod identity;
crate mod sign;

use crate::error::{Error, Result};
use agent_msg::*;
use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, Bytes, BytesMut};
use getset::{Getters, Setters};
use std::{convert::TryFrom, fmt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

mod agent_msg {
    crate const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
    crate const SSH_AGENTC_REQUEST_IDENTITIES_S: &'static str = "SSH_AGENTC_REQUEST_IDENTITIES";
    crate const SSH_AGENTC_IDENTITIES_ANSWER: u8 = 12;
    crate const SSH_AGENTC_IDENTITIES_ANSWER_S: &'static str = "SSH_AGENTC_IDENTITIES_ANSWER";
    crate const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
    crate const SSH_AGENTC_SIGN_REQUEST_S: &'static str = "SSH_AGENTC_SIGN_REQUEST";
    crate const SSH_AGENTC_SIGN_RESPONSE: u8 = 14;
    crate const SSH_AGENTC_SIGN_RESPONSE_S: &'static str = "SSH_AGENTC_SIGN_RESPONSE";
    crate const UNKNOWN: u8 = 0;
    crate const UNKNOWN_S: &'static str = "UNKNOWN";
}

crate trait IntoPacket {
    fn into_packet(&self) -> Result<Packet>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
crate enum PacketKind {
    Unknown = UNKNOWN,
    RequestIdentities = SSH_AGENTC_REQUEST_IDENTITIES,
    IdentitiesAnswer = SSH_AGENTC_IDENTITIES_ANSWER,
    SignRequest = SSH_AGENTC_SIGN_REQUEST,
    SignResponse = SSH_AGENTC_SIGN_RESPONSE,
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
                Self::RequestIdentities => SSH_AGENTC_REQUEST_IDENTITIES_S,
                Self::IdentitiesAnswer => SSH_AGENTC_IDENTITIES_ANSWER_S,
                Self::SignRequest => SSH_AGENTC_SIGN_REQUEST_S,
                Self::SignResponse => SSH_AGENTC_SIGN_RESPONSE_S,
                Self::Unknown => UNKNOWN_S,
            }
        )
    }
}

impl TryFrom<u8> for PacketKind {
    type Error = Error;

    fn try_from(val: u8) -> Result<Self> {
        match val {
            SSH_AGENTC_REQUEST_IDENTITIES => Ok(Self::RequestIdentities),
            SSH_AGENTC_IDENTITIES_ANSWER => Ok(Self::IdentitiesAnswer),
            SSH_AGENTC_SIGN_REQUEST => Ok(Self::SignRequest),
            SSH_AGENTC_SIGN_RESPONSE => Ok(Self::SignResponse),
            _ => Err(Error::unknown_packet_kind(val)),
        }
    }
}

impl Into<u8> for PacketKind {
    fn into(self) -> u8 {
        self as u8
    }
}

const MESSAGE_LEN: usize = 4;

#[derive(Clone, Debug, Default, Eq, Getters, PartialEq, Setters)]
#[get = "crate"]
#[set = "crate"]
crate struct Packet {
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
    crate async fn write_packet<S>(self, stream: &mut S) -> Result<()>
    where
        S: AsyncWrite + Unpin + Send,
    {
        let mut final_packet = BytesMut::new();

        let message_length = self.payload.len();
        final_packet.put_u32(u32::try_from(message_length)?);
        final_packet.put_slice(self.payload());
        let fp = final_packet.freeze();

        let _ = stream.write_all(&fp).await?;

        Ok(())
    }

    #[allow(dead_code)]
    crate async fn read_packet<S>(stream: &mut S) -> Result<Self>
    where
        S: AsyncRead + Unpin + Send,
    {
        // Read the message length bytes
        let mut mlen_bytes = vec![0u8; MESSAGE_LEN];
        let bytes_read = stream.read_exact(&mut mlen_bytes).await?;
        assert_eq!(bytes_read, MESSAGE_LEN);
        let mlen = BigEndian::read_u32(&mlen_bytes);

        // Read the payload bytes
        let mut payload_bytes = vec![0u8; mlen as usize];
        let bytes_read = stream.read_exact(&mut payload_bytes).await?;
        assert_eq!(bytes_read, mlen as usize);

        // Setup the packet
        let mut packet = Packet::default();
        packet.kind = PacketKind::try_from(payload_bytes[0])?;
        packet.payload = Bytes::copy_from_slice(&payload_bytes[..]);

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

        let _ = pkt.write_packet(&mut actual).await?;

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

    const PACKET_EXPECTED: &'static str =
        r#"Packet { kind: SSH_AGENTC_SIGN_REQUEST, payload: [8 bytes] }"#;

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
