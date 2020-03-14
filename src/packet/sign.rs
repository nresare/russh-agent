// Copyright (c) 2020 russh-agent developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! ssh-agent signature request packet

use crate::{
    error::Result,
    packet::{IntoPacket, Packet, PacketKind},
    utils::put_string,
};
use bytes::{BufMut, Bytes, BytesMut};

#[derive(Clone, Debug, Default)]
crate struct SignRequest {
    key: Bytes,
    data: Bytes,
    flags: u32,
}

impl IntoPacket for SignRequest {
    fn into_packet(&self) -> Result<Packet> {
        let mut pkt = Packet::default();

        let kind = PacketKind::SignRequest;
        let _ = pkt.set_kind(kind.clone());

        let mut payload = BytesMut::new();
        payload.put_u8(kind.into());
        put_string(&mut payload, &self.key)?;
        put_string(&mut payload, &self.data)?;
        payload.put_u32(self.flags);

        let _ = pkt.set_payload(payload.freeze());

        Ok(pkt)
    }
}

impl SignRequest {
    crate fn new(key: Bytes, data: Bytes, flags: u32) -> Self {
        Self { key, data, flags }
    }
}

#[cfg(test)]
mod test {
    use super::SignRequest;
    use crate::{
        error::Result,
        packet::{IntoPacket, Packet, PacketKind},
    };
    use bytes::Bytes;

    #[test]
    fn sign_req_into_packet() -> Result<()> {
        let sign_req = SignRequest::new(Bytes::from_static(b"abc"), Bytes::from_static(b"123"), 0);
        let pkt = sign_req.into_packet()?;
        let mut expected = Packet::default();
        let _ = expected.set_kind(PacketKind::SignRequest);
        let _ = expected.set_payload(Bytes::from_static(&[
            13, 0, 0, 0, 3, b'a', b'b', b'c', 0, 0, 0, 3, b'1', b'2', b'3', 0, 0, 0, 0,
        ]));
        assert_eq!(pkt, expected);
        Ok(())
    }
}
