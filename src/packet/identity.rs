// Copyright (c) 2020 russh-agent developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! `russh-agent` identity management

use crate::{
    error::Result,
    packet::{IntoPacket, Packet, PacketKind},
    utils::put_string,
};
use bytes::{BufMut, Bytes, BytesMut};

#[derive(Clone, Debug)]
pub(crate) struct AddIdentity {
    kind: Bytes,
    key_blob: Bytes,
    comment: Bytes,
}

impl IntoPacket for AddIdentity {
    fn into_packet(&self) -> Result<Packet> {
        let mut pkt = Packet::default();

        let kind = PacketKind::AddIdentity;
        let _ = pkt.set_kind(kind.clone());

        let mut payload = BytesMut::new();
        payload.put_u8(kind.into());
        put_string(&mut payload, &self.kind)?;
        payload.put_slice(&self.key_blob);
        put_string(&mut payload, &self.comment)?;

        let _ = pkt.set_payload(payload.freeze());

        Ok(pkt)
    }
}

impl AddIdentity {
    pub(crate) fn new(kind: Bytes, key_blob: Bytes, comment: Bytes) -> Self {
        Self {
            kind,
            key_blob,
            comment,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct AddIdentityConstrained {
    kind: Bytes,
    key_blob: Bytes,
    comment: Bytes,
    constraints: Bytes,
}

impl IntoPacket for AddIdentityConstrained {
    fn into_packet(&self) -> Result<Packet> {
        let mut pkt = Packet::default();

        let kind = PacketKind::AddIdentity;
        let _ = pkt.set_kind(kind.clone());

        let mut payload = BytesMut::new();
        payload.put_u8(kind.into());
        put_string(&mut payload, &self.kind)?;
        payload.put_slice(&self.key_blob);
        put_string(&mut payload, &self.comment)?;
        payload.put_slice(&self.constraints);

        let _ = pkt.set_payload(payload.freeze());

        Ok(pkt)
    }
}

impl AddIdentityConstrained {
    pub(crate) fn new(kind: Bytes, key_blob: Bytes, comment: Bytes, constraints: Bytes) -> Self {
        Self {
            kind,
            key_blob,
            comment,
            constraints,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct RemoveIdentity {
    key_blob: Bytes,
}

impl IntoPacket for RemoveIdentity {
    fn into_packet(&self) -> Result<Packet> {
        let mut pkt = Packet::default();

        let kind = PacketKind::RemoveIdentity;
        let _ = pkt.set_kind(kind.clone());

        let mut payload = BytesMut::new();
        payload.put_u8(kind.into());
        put_string(&mut payload, &self.key_blob)?;

        let _ = pkt.set_payload(payload.freeze());

        Ok(pkt)
    }
}

impl RemoveIdentity {
    pub(crate) fn new(key_blob: Bytes) -> Self {
        Self { key_blob }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RemoveAll {}

impl IntoPacket for RemoveAll {
    fn into_packet(&self) -> Result<Packet> {
        let mut pkt = Packet::default();

        let kind = PacketKind::RemoveAllIdentities;
        let _ = pkt.set_kind(kind.clone());

        let mut payload = BytesMut::new();
        payload.put_u8(kind.into());

        let _ = pkt.set_payload(payload.freeze());

        Ok(pkt)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RequestIdentities {}

impl IntoPacket for RequestIdentities {
    fn into_packet(&self) -> Result<Packet> {
        let mut pkt = Packet::default();

        let kind = PacketKind::RequestIdentities;
        let _ = pkt.set_kind(kind.clone());

        let mut payload = BytesMut::new();
        payload.put_u8(kind.into());

        let _ = pkt.set_payload(payload.freeze());

        Ok(pkt)
    }
}

#[cfg(test)]
mod test {
    use super::{AddIdentity, RequestIdentities};
    use crate::{
        error::Result,
        packet::{IntoPacket, Packet, PacketKind},
    };
    use bytes::Bytes;

    #[test]
    fn request_identities() -> Result<()> {
        let req_ident = RequestIdentities::default();
        let pkt = req_ident.into_packet()?;
        let mut expected = Packet::default();
        let _ = expected.set_kind(PacketKind::RequestIdentities);
        let _ = expected.set_payload(Bytes::from_static(&[11]));
        assert_eq!(pkt, expected);
        Ok(())
    }

    #[test]
    fn add_identity() -> Result<()> {
        let req_ident = AddIdentity::new(
            Bytes::from_static(b"ssh-dsa"),
            Bytes::from_static(&[0, 0, 0, 3, 0xff, 0xde, 0xd1]),
            Bytes::from_static(b"comment"),
        );
        let pkt = req_ident.into_packet()?;
        let mut expected = Packet::default();
        let _ = expected.set_kind(PacketKind::AddIdentity);
        let _ = expected.set_payload(Bytes::from_static(&[
            17, 0, 0, 0, 7, b's', b's', b'h', b'-', b'd', b's', b'a', 0, 0, 0, 3, 0xff, 0xde, 0xd1,
            0, 0, 0, 7, b'c', b'o', b'm', b'm', b'e', b'n', b't',
        ]));
        assert_eq!(pkt, expected);
        Ok(())
    }
}
