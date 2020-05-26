use crate::chan_msg::{ChanMsg, ChanMsgKind};
use crate::handshake::Handshake;
use crate::torrent_msg::TorrentMsg;
use crate::type_alias::*;
use anyhow::Result;
use std::net::IpAddr;
use std::sync::atomic::{self, AtomicUsize};
use tokio::{self, net::tcp, net::TcpStream, sync::mpsc};

lazy_static! {
    static ref NEXT_PEER_ID: AtomicUsize = AtomicUsize::new(0);
}

/// Manages receiving messages from a peer. Dumps parsed messages to the given
// `mpsc::UnboundedSender` channel.
#[derive(Debug)]
pub struct PeerConn {
    /// The peer's unique id.
    id: usize,
    /// A TCP read stream to a peer.
    recv_tcp: tcp::OwnedReadHalf,
    /// A channel to send parsed messages to.
    send_chan: mpsc::UnboundedSender<ChanMsg>,
}

impl std::fmt::Display for PeerConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PeerConn(id={}, recv_tcp={:?})", self.id, self.recv_tcp)
    }
}

impl PeerConn {
    fn new(recv_tcp: tcp::OwnedReadHalf, send_chan: mpsc::UnboundedSender<ChanMsg>) -> PeerConn {
        PeerConn {
            id: NEXT_PEER_ID.fetch_add(1, atomic::Ordering::Relaxed),
            recv_tcp,
            send_chan,
        }
    }

    fn send(&self, kind: ChanMsgKind) -> Result<()> {
        self.send_chan.send(ChanMsg::new(self.id, kind))?;
        Ok(())
    }

    async fn run(
        &mut self,
        send_tcp: tcp::OwnedWriteHalf,
        ip: IpAddr,
        info_hash: InfoHash,
    ) -> Result<()> {
        // Notify the channel of the new peer.
        self.send(ChanMsgKind::NewPeer(send_tcp, ip))?;

        // Receive and validate the handshake.
        let handshake = Handshake::read(&mut self.recv_tcp).await?;
        if handshake.protocol != Handshake::PROTOCOL {
            return Err(anyhow!("bad protocol: {:?}", handshake.protocol));
        }
        if handshake.info_hash != info_hash {
            return Err(anyhow!("bad info hash: {:?}", handshake.info_hash));
        }

        // Forward all torrent protocol messages via `send_chan`.
        loop {
            let msg = TorrentMsg::read(&mut self.recv_tcp).await?;
            self.send(ChanMsgKind::Msg(msg))?;
        }
    }

    pub async fn start(
        socket: TcpStream,
        send_chan: mpsc::UnboundedSender<ChanMsg>,
        info_hash: InfoHash,
    ) {
        let ip = socket.peer_addr().unwrap().ip();
        let (recv_tcp, send_tcp) = socket.into_split();
        let mut peer_conn = PeerConn::new(recv_tcp, send_chan);
        // TODO: info! instead.
        trace!("Starting peer {} {}", peer_conn.id, ip);
        match peer_conn.run(send_tcp, ip, info_hash).await {
            Ok(_) => {}
            Err(e) => {
                // TODO: info! instead.
                trace!("Peer {} error: {}", peer_conn.id, e);
                let _ = peer_conn.send(ChanMsgKind::Shutdown);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_peer_conn() {
        let mut listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let info_hash = [41; INFO_HASH_LEN];
        // 1. Simulate a peer sending messages via TCP.
        let peer_fut = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let handshake = Handshake::new(info_hash, [0; PEER_ID_LEN]);
            handshake.write(&mut socket).await.unwrap();

            TorrentMsg::Have(42).write(&mut socket).await.unwrap();

            socket.shutdown(std::net::Shutdown::Both).unwrap();
        });

        let (send_chan, mut recv_chan) = mpsc::unbounded_channel();
        // 2. `PeerConn` receives TCP messages and forwards the messages via the `send_chan`.
        let peer_conn_fut = tokio::spawn(async move {
            PeerConn::start(
                TcpStream::connect(addr).await.unwrap(),
                send_chan,
                info_hash,
            )
            .await
        });

        // 3. Check that the messages are received by the `recv_chan`.
        // The `NewPeer` message contains a `tcp::OwnedReadHalf` which if dropped, kills the connection.
        // Hence, this message is kept in scope.
        let new_peer_msg = recv_chan.recv().await;
        assert_matches!(
            new_peer_msg,
            Some(ChanMsg {
                peer_index: 0,
                kind: ChanMsgKind::NewPeer(_, _),
            })
        );
        assert_matches!(
            recv_chan.recv().await,
            Some(ChanMsg {
                peer_index: 0,
                kind: ChanMsgKind::Msg(TorrentMsg::Have(42)),
            })
        );
        assert_matches!(
            recv_chan.recv().await,
            Some(ChanMsg {
                peer_index: 0,
                kind: ChanMsgKind::Shutdown,
            })
        );
        assert_matches!(recv_chan.recv().await, None);

        peer_fut.await.unwrap();
        peer_conn_fut.await.unwrap();
    }
}
