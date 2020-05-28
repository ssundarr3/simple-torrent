use crate::bencode::{BencodeDict, BencodeValue, GetBencodeErr, GetFromBencodeDict};
use crate::type_alias::*;
use bytes::Bytes;

const TRANS_KEY: &'static [u8] = b"t";
const MSG_KIND_KEY: &'static [u8] = b"y";
const QUERY_KEY: &'static [u8] = b"q";
const RESPONSE_KEY: &'static [u8] = b"r";
const ERROR_KEY: &'static [u8] = b"q";
const ARGS_KEY: &'static [u8] = b"a";
const SENDER_KEY: &'static [u8] = b"id";

type NodeId = [u8; 20];
type Token = u32;

// #[derive(Debug)]

// pub enum DhtQueryMsg {
//     /// Ping the
//     Ping,

//     ///
//     FindNode(NodeId),

//     ///
//     GetPeers(InfoHash),

//     ///
//     Announce(InfoHash, u16, Token),
// }
// #[derive(Debug)]
// pub enum DhtResponseMsg {
//     /// Response for `DhtQueryMsg::Ping` and 'DhtQueryMsg::Announce` queries.
//     Ack,

//     /// Response for the `DhtQueryMsg::FindNode` query.
//     Nodes(Vec<NodeId>),

//     /// Reseponse for the `DhtQueryMsg::GetPeers` query.
//     Peers(InfoHash),
// }
// Query(DhtQueryMsg),
// Response(DhtResponseMsg),
// Error(DhtErrorMsg),

// #[derive(Debug)]
// pub struct DhtErrorMsg {
//     code: i64,
//     msg: Bytes,
// }

#[derive(Debug)]
pub enum DhtMsgKind {
    /// Ping
    Ping,
    ///
    FindNode(NodeId),
    ///
    GetPeers(InfoHash),
    ///
    Announce(InfoHash, u16, Token),

    /// Response for `DhtMsgKind::Ping` and 'DhtMsgKind::Announce` queries.
    Ack,

    /// Response for the `DhtMsgKind::FindNode` query.
    Nodes(Vec<NodeId>),

    /// Reseponse for the `DhtMsgKind::GetPeers` query.
    Peers(InfoHash),

    /// Error message.
}

impl DhtMsgKind {
    pub fn msg_kind_key(&self) -> &'static [u8] {
        match self {
            DhtMsgKind::Ping
            | DhtMsgKind::FindNode(_)
            | DhtMsgKind::GetPeers(_)
            | DhtMsgKind::Announce(_, _, _) => QUERY_KEY,
            DhtMsgKind::Ack | DhtMsgKind::Nodes(_) | DhtMsgKind::Peers(_) => RESPONSE_KEY,
        }
    }
}

#[derive(Debug)]
pub struct DhtMsg {
    trans_id: Bytes,
    sender: NodeId,
    kind: DhtMsgKind,
}

impl DhtMsg {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = BencodeDict::new();

        b.insert(TRANS_KEY.into(), BencodeValue::Bytes(self.trans_id.clone()));
        let msg_kind_key: Bytes = self.kind.msg_kind_key().into();
        b.insert(MSG_KIND_KEY.into(), BencodeValue::Bytes(msg_kind_key));

        match &self.kind {
            DhtMsgKind::Ping => {
                //
            }
            DhtMsgKind::FindNode(target) => {}
            DhtMsgKind::GetPeers(info_hash) => {}
            DhtMsgKind::Announce(info_hash, port, token) => {}
            DhtMsgKind::Ack => {}
            DhtMsgKind::Nodes(peers) => {}
            DhtMsgKind::Peers(info_hash) => {}
        }

        vec![]
    }
}
