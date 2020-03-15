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
//! # use russh_agent::{Result, client::{Client, Message}};
//! # use bytes::Bytes;
//! # use std::{env, time::Duration};
//! # use tokio::{join, net::UnixStream, spawn, time::delay_for};
//! #
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!   // Get the agent socket here
//!   let (actual_agent, sock) = setup_socket().await?;
//!   let (sender, mut receiver, mut client) = Client::new();
//!
//!   if actual_agent {
//!     // This is the client task
//!     let ssh_agent_client = spawn(client.run(sock));
//!
//!     // This is a simulated sender of messages to the client
//!     let mut sender = sender.clone();
//!     let work = spawn(async move {
//!        let _ = sender.send(Message::List).await;
//!        delay_for(Duration::from_millis(100)).await;
//!        let _ = sender.send(Message::Shutdown).await;
//!     });
//!
//!     // This is the receiver of agent responses
//!     let receive = spawn(async move {
//!        loop {
//!            if let Some(msg) = receiver.recv().await {
//!                // Process your msg here!
//!            } else {
//!                break;
//!            }
//!        }
//!     });
//!
//!     let _ = join!(ssh_agent_client, receive, work);
//!   }
//!   Ok(())
//! }
//!
//! async fn setup_socket() -> Result<(bool, UnixStream)> {
//!   Ok(match env::var("SSH_AUTH_SOCK") {
//!     Ok(v) => (true, UnixStream::connect(v).await?),
//!     Err(_) => {
//!         let (up, _down) = UnixStream::pair()?;
//!         (false, up)
//!     }
//!   })
//! }
//! ```

mod message;
pub use message::Message;

use crate::{
    error::Result,
    packet::{
        identity::{AddIdentity, RemoveAll, RemoveIdentity, RequestIdentities},
        lock::Lock,
        sign::SignRequest,
        unlock::Unlock,
        IntoPacket, Packet,
    },
};
use bytes::Bytes;
use getset::Setters;
use slog::{error, trace, Logger};
use slog_try::{try_error, try_trace};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc::{channel, Receiver, Sender},
};

/// An asynchronous ssh-agent client implementation
#[derive(Debug, Setters)]
pub struct Client {
    /// An optional slog logger
    #[set = "pub"]
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
                            Message::Add(kind, key_blob, comment) => {
                                let pkt = AddIdentity::new(kind, key_blob, comment).into_packet()?;
                                try_trace!(self.logger, "Agent => {}", pkt.kind());
                                try_trace!(self.logger, "PKT: {}", pkt);
                                let _ = pkt.write_packet(&mut stream).await?;
                            }
                            Message::Remove(key_blob) => {
                                let pkt = RemoveIdentity::new(key_blob).into_packet()?;
                                try_trace!(self.logger, "Agent => {}", pkt.kind());
                                try_trace!(self.logger, "PKT: {}", pkt);
                                let _ = pkt.write_packet(&mut stream).await?;
                            }
                            Message::RemoveAll => {
                                let pkt = RemoveAll::default().into_packet()?;
                                try_trace!(self.logger, "Agent => {}", pkt.kind());
                                try_trace!(self.logger, "PKT: {}", pkt);
                                let _ = pkt.write_packet(&mut stream).await?;
                            }
                            Message::List => {
                                let pkt = RequestIdentities::default().into_packet()?;
                                try_trace!(self.logger, "Agent => {}", pkt.kind());
                                try_trace!(self.logger, "PKT: {}", pkt);
                                let _ = pkt.write_packet(&mut stream).await?;
                            }
                            Message::Sign(key, data, flags) => {
                                let pkt = SignRequest::new(key, data, flags).into_packet()?;
                                try_trace!(self.logger, "Agent => {}", pkt.kind());
                                try_trace!(self.logger, "PKT: {}", pkt);
                                let _ = pkt.write_packet(&mut stream).await?;
                            }
                            Message::Lock(passphrase) => {
                                let pkt = Lock::new(passphrase).into_packet()?;
                                try_trace!(self.logger, "Agent => {}", pkt.kind());
                                try_trace!(self.logger, "PKT: {}", pkt);
                                let _ = pkt.write_packet(&mut stream).await?;
                            }
                            Message::Unlock(passphrase) => {
                                let pkt = Unlock::new(passphrase).into_packet()?;
                                try_trace!(self.logger, "Agent => {}", pkt.kind());
                                try_trace!(self.logger, "PKT: {}", pkt);
                                let _ = pkt.write_packet(&mut stream).await?;
                            }
                            Message::Shutdown => {
                                try_trace!(self.logger, "Shutting down");
                                disconnected = true;
                            }
                        }
                    } else {
                        try_error!(self.logger, "NONE received, sender likely dropped");
                        disconnected = true;
                    }
                }
                packet_res = Packet::read_packet(&mut stream) => {
                    match packet_res {
                        Ok(packet) => {
                            try_trace!(self.logger, "Agent <= {}", packet.kind());
                            if packet.kind().is_response() {
                                let _ = self.sender.send(packet.payload().clone()).await?;
                            } else {
                                try_error!(self.logger, "invalid response packet read! {}", packet);
                            }
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
    use crate::{client::Message, error::Result, utils::hexy, utils::put_string};
    use bytes::Bytes;
    use bytes::BytesMut;
    use ed25519_dalek::Keypair;
    use rand::rngs::OsRng;
    use slog::{o, trace, Drain, Logger};
    use slog_async::Async;
    use slog_term::{FullFormat, TermDecorator};
    use std::{env, time::Duration};
    use tokio::{
        join,
        net::UnixStream,
        spawn,
        sync::mpsc::{Receiver, Sender},
        time::delay_for,
    };

    async fn setup_socket() -> Result<UnixStream> {
        let path = env::var("SSH_AUTH_SOCK")?;
        Ok(UnixStream::connect(path).await?)
    }

    #[tokio::test]
    async fn client() -> Result<()> {
        if let Ok(sock) = setup_socket().await {
            // Setup the ssh-agent client
            let (sender, receiver, mut client) = Client::new();

            // Setup some logging
            let decorator = TermDecorator::new().build();
            let term_drain = FullFormat::new(decorator).build().fuse();
            let async_drain = Async::new(term_drain).build().fuse();
            let log = Logger::root(async_drain, o!());
            let _ = client.set_logger(Some(log.clone()));

            // This is the client task
            let client = spawn(client.run(sock));

            // This is a simulated sender of messages
            let send = spawn(send(sender.clone()));

            // This is the receiver of agent responses
            let receive = spawn(receive(receiver, log.clone()));

            // Start 'em all up
            let _ = join!(client, receive, send);
        }
        Ok(())
    }

    async fn send(mut sender: Sender<Message>) -> Result<()> {
        // Add an identity
        if let Ok(pk) = add_identity(&mut sender).await {
            // Sign something
            assert!(sign_data(&mut sender, &pk).await.is_ok());
            // Lock the agent
            assert!(lock_agent(&mut sender).await.is_ok());
            // Sign something (this should generate a failure at the reciever)
            assert!(sign_data(&mut sender, &pk).await.is_ok());
            // Unlock the agent
            assert!(unlock_agent(&mut sender).await.is_ok());
            // Sign something
            assert!(sign_data(&mut sender, &pk).await.is_ok());
            // Remove the identity
            assert!(remove_identity(&mut sender, &pk).await.is_ok());
        }

        // List the remaining identites
        assert!(list_identities(&mut sender).await.is_ok());
        // Remove all identities
        assert!(remove_all_identities(&mut sender).await.is_ok());
        // List the remaining identites (there should be none)
        assert!(list_identities(&mut sender).await.is_ok());

        let _ = sender.send(Message::Shutdown).await;
        Ok(())
    }

    async fn receive(mut receiver: Receiver<Bytes>, logger: Logger) -> Result<()> {
        let mut count = 0;
        loop {
            if let Some(msg) = receiver.recv().await {
                trace!(logger, "Receiver <= Msg");
                let _ = hexy("MSG", &logger, &msg);
                count += 1;
            } else {
                break;
            }
        }
        assert_eq!(count, 10);
        Ok(())
    }

    async fn add_identity(sender: &mut Sender<Message>) -> Result<Vec<u8>> {
        let mut csprng = OsRng {};
        let keypair = Keypair::generate(&mut csprng);
        let key_bytes = keypair.to_bytes();
        let mut add_ident_payload = BytesMut::new();
        let public_key = &key_bytes[32..];
        put_string(&mut add_ident_payload, public_key)?;
        put_string(&mut add_ident_payload, &key_bytes)?;

        let add = Message::Add(
            Bytes::from_static(b"ssh-ed25519"),
            add_ident_payload.freeze(),
            Bytes::from_static(b"test key"),
        );
        sender.send(add).await?;
        delay_for(Duration::from_millis(100)).await;
        Ok(public_key.into())
    }

    async fn remove_identity(sender: &mut Sender<Message>, pk: &[u8]) -> Result<()> {
        let mut key_blob = BytesMut::new();
        put_string(&mut key_blob, b"ssh-ed25519")?;
        put_string(&mut key_blob, pk)?;
        let remove = Message::Remove(key_blob.freeze());
        sender.send(remove).await?;
        delay_for(Duration::from_millis(100)).await;
        Ok(())
    }

    async fn sign_data(sender: &mut Sender<Message>, pk: &[u8]) -> Result<()> {
        let mut key_blob = BytesMut::new();
        put_string(&mut key_blob, b"ssh-ed25519")?;
        put_string(&mut key_blob, pk)?;
        let sign = Message::Sign(key_blob.freeze(), Bytes::from_static(b"testing"), 0);
        sender.send(sign).await?;
        delay_for(Duration::from_millis(100)).await;
        Ok(())
    }

    async fn lock_agent(sender: &mut Sender<Message>) -> Result<()> {
        let lock = Message::Lock(Bytes::from_static(b"test"));
        sender.send(lock).await?;
        delay_for(Duration::from_millis(100)).await;
        Ok(())
    }

    async fn unlock_agent(sender: &mut Sender<Message>) -> Result<()> {
        let unlock = Message::Unlock(Bytes::from_static(b"test"));
        sender.send(unlock).await?;
        delay_for(Duration::from_millis(100)).await;
        Ok(())
    }

    async fn list_identities(sender: &mut Sender<Message>) -> Result<()> {
        sender.send(Message::List).await?;
        delay_for(Duration::from_millis(100)).await;
        Ok(())
    }

    async fn remove_all_identities(sender: &mut Sender<Message>) -> Result<()> {
        let remove_all = Message::RemoveAll;
        sender.send(remove_all).await?;
        delay_for(Duration::from_millis(100)).await;
        Ok(())
    }
}
