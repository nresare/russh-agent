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
};
use bytes::{BufMut, BytesMut};

#[derive(Clone, Copy, Debug, Default)]
crate struct RequestIdentities {}

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
    use super::RequestIdentities;
    use crate::{
        error::Result,
        packet::{IntoPacket, Packet, PacketKind},
    };
    use bytes::Bytes;

    #[test]
    fn req_ident_into_packet() -> Result<()> {
        let req_ident = RequestIdentities::default();
        let pkt = req_ident.into_packet()?;
        let mut expected = Packet::default();
        let _ = expected.set_kind(PacketKind::RequestIdentities);
        let _ = expected.set_payload(Bytes::from_static(&[11]));
        assert_eq!(pkt, expected);
        Ok(())
    }
}
