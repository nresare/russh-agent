// Copyright (c) 2020 russh-agent developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! An asynchronous ssh-agent client implementation
//!
//! # Example
//! ```
//! # use russh_agent::client::Client;
//! let (_sender, _receiver, _client) = Client::new();
//! ```

mod message;
pub use message::Message;

use crate::{
    error::Result,
    packet::{identity::RequestIdentities, sign::SignRequest, IntoPacket, Packet, PacketKind},
};
use bytes::Bytes;
use slog::{error, trace, Logger};
use slog_try::{try_error, try_trace};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc::{channel, Receiver, Sender},
};

/// An asynchronous ssh-agent client implementation
///
/// # Example
/// ```
/// # use russh_agent::client::Client;
/// let (_sender, _receiver, _client) = Client::new();
/// ```
#[derive(Debug)]
pub struct Client {
    logger: Option<Logger>,
    receiver: Receiver<Message>,
    sender: Sender<Bytes>,
}

impl Client {
    /// Create a new ssh-agent client.
    ///
    /// This returns a sender that should be used to request ssh-agent work
    /// via [Message](crate::client::Message), and a receiver to listen for the results
    /// of those requests in [Bytes](bytes::Bytes).
    pub fn new() -> (Sender<Message>, Receiver<Bytes>, Self) {
        let (msg_sender, msg_receiver) = channel(10);
        let (agent_sender, agent_receiver) = channel(10);

        let client = Self {
            logger: None,
            receiver: msg_receiver,
            sender: agent_sender,
        };

        (msg_sender, agent_receiver, client)
    }

    /// Run the agent handler
    pub async fn run<R>(mut self, mut stream: R) -> Result<()>
    where
        R: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut disconnected = false;

        while !disconnected {
            tokio::select! {
                msg_opt = self.receiver.recv() => {
                    if let Some(msg) = msg_opt {
                        try_trace!(self.logger, "Agent <= {}", msg);
                        match msg {
                            Message::List => {
                                let pkt = RequestIdentities::default().into_packet()?;
                                try_trace!(self.logger, "Agent => {}", pkt.kind());
                                try_trace!(self.logger, "PKT: {}", pkt);
                                let _ = pkt.write_packet(&mut stream).await?;
                            }
                            Message::Sign(key, data) => {
                                let pkt = SignRequest::new(key, data, 0).into_packet()?;
                                try_trace!(self.logger, "Agent => {}", pkt.kind());
                                try_trace!(self.logger, "PKT: {}", pkt);
                                let _ = pkt.write_packet(&mut stream).await?;
                            }
                        }
                    } else {
                        try_error!(self.logger, "NONE received, sender dropped?");
                        disconnected =true;
                    }
                }
                packet_res = Packet::read_packet(&mut stream) => {
                    match packet_res {
                        Ok(packet) => match packet.kind() {
                            PacketKind::IdentitiesAnswer => {
                                try_trace!(self.logger, "Agent <= {}", packet.kind());
                                let _ = self.sender.send(packet.payload().clone()).await?;
                            }
                            PacketKind::SignResponse => {
                                try_trace!(self.logger, "Agent <= {}", packet.kind());
                                let _ = self.sender.send(packet.payload().clone()).await?;
                            }
                            _ => {}
                        }
                        Err(e) => try_error!(self.logger, "{}", e),
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::Client;
    use crate::error::Result;
    use std::io::Cursor;
    use tokio::spawn;

    #[tokio::test]
    async fn client() -> Result<()> {
        let (_sender, _receiver, client) = Client::new();
        let buffer = Cursor::new(vec![]);
        let _handle = spawn(client.run(buffer));
        Ok(())
    }
}
