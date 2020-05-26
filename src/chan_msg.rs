use crate::torrent_msg::TorrentMsg;
use std::net::IpAddr;
use tokio::net::tcp;

#[derive(Debug)]
pub enum ChanMsgKind {
    /// A connection has been created with a peer.
    NewPeer(tcp::OwnedWriteHalf, IpAddr),
    /// Shutdown the connection with the peer.
    Shutdown,
    /// A torrent message from the peer.
    Msg(TorrentMsg),
}

impl std::fmt::Display for ChanMsgKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChanMsgKind::NewPeer(_send_tcp, ip) => write!(f, "NewPeer({})", ip),
            ChanMsgKind::Shutdown => write!(f, "Shutdown"),
            ChanMsgKind::Msg(msg) => write!(f, "Msg({})", msg),
        }
    }
}

/// A message from peers to the worker task.
#[derive(Debug)]
pub struct ChanMsg {
    /// The peer from which the message comes from.
    pub peer_index: usize,
    /// The message itself.
    pub kind: ChanMsgKind,
}

impl ChanMsg {
    pub fn new(peer_index: usize, kind: ChanMsgKind) -> ChanMsg {
        ChanMsg { peer_index, kind }
    }
}
