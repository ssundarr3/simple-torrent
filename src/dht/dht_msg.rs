use crate::bencode::{BencodeDict, BencodeValue, GetFromBencodeDict};
use crate::dht::node::{Node, NodeId};
use crate::type_alias::*;
use crate::util::IpPort;
use anyhow::Result;
use bytes::{BufMut, Bytes, BytesMut};
use std::convert::TryInto;

const TRANSACTION_KEY: &'static [u8] = b"t";
const MSG_KIND_KEY: &'static [u8] = b"y";
const QUERY_KEY: &'static [u8] = b"q";
const RESPONSE_KEY: &'static [u8] = b"r";
const ERROR_KEY: &'static [u8] = b"e";
const ARGS_KEY: &'static [u8] = b"a";
const SENDER_KEY: &'static [u8] = b"id";
const TARGET_KEY: &'static [u8] = b"target";
const INFO_HASH_KEY: &'static [u8] = b"info_hash";
const PING_KEY: &'static [u8] = b"ping";
const FIND_NODES_KEY: &'static [u8] = b"find_node";
const GET_PEERS_KEY: &'static [u8] = b"get_peers";
const ANNOUNCE_KEY: &'static [u8] = b"announce_peer";
const NODES_KEY: &'static [u8] = b"nodes";
// rename ADDRESSES_KEY Peer address
const ADDRS_KEY: &'static [u8] = b"values";
const TOKEN_KEY: &'static [u8] = b"token";
const PORT_KEY: &'static [u8] = b"port";
const IMPLIED_PORT_KEY: &'static [u8] = b"implied_port";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token(Bytes);

impl Token {
    pub fn gen_random() -> Token {
        let mut bytes = BytesMut::with_capacity(8); // Arbitrary size of 8.
        for _ in 0..8 {
            bytes.put_u8(rand::random::<u8>());
        }
        Token(bytes.freeze())
    }

    pub fn get(&self) -> &Bytes {
        &self.0
    }

    pub fn from_bencode(b: &BencodeValue) -> Result<Token> {
        Ok(Token(b.get_bytes()?.clone()))
    }

    pub fn to_bencode(&self) -> BencodeValue {
        BencodeValue::Bytes(self.get().clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhtErrorCode {
    GenericError = 201,
    ServerError = 202,
    ProtocolError = 203,
    MethodUnknown = 204,
}

impl DhtErrorCode {
    pub fn from_i64(x: i64) -> Result<DhtErrorCode> {
        match x {
            201 => Ok(DhtErrorCode::GenericError),
            202 => Ok(DhtErrorCode::ServerError),
            203 => Ok(DhtErrorCode::ProtocolError),
            204 => Ok(DhtErrorCode::MethodUnknown),
            _ => Err(anyhow!("unknown dht error code: {:}", x)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhtMsgKind {
    /// The Ping query.
    Ping,

    /// `FindNode(node_id)` is a query to find the IpPort for the given `node_id`.
    FindNode(NodeId),

    ///
    GetPeers(InfoHash),

    ///
    Announce(InfoHash, Option<u16>, Token),

    /// Response for `DhtMsgKind::Ping` and 'DhtMsgKind::Announce` queries.
    Ack,

    /// Returns a list of nodes close to the specified `node_id` in the `DhtMsgKind::FindNode(node_id)` query.
    Nodes(Vec<Node>),

    /// `Peers(token, nodes, addrs)` is the reseponse for the `DhtMsgKind::GetPeers(info_hash)` query.
    /// `nodes` is a list of nodes close to the specified `info_hash`.
    /// `addrs` is a list of peer addresses that are downloading the torrent that has `info_hash`.
    Peers(Token, Vec<Node>, Vec<IpPort>),

    /// `Error(err_code, err_msg)` message.
    Error(DhtErrorCode, Bytes),
}

impl DhtMsgKind {
    pub fn msg_kind(&self) -> &'static [u8] {
        match self {
            DhtMsgKind::Ping
            | DhtMsgKind::FindNode(_)
            | DhtMsgKind::GetPeers(_)
            | DhtMsgKind::Announce(_, _, _) => QUERY_KEY,
            DhtMsgKind::Ack | DhtMsgKind::Nodes(_) | DhtMsgKind::Peers(_, _, _) => RESPONSE_KEY,
            DhtMsgKind::Error(_, _) => ERROR_KEY,
        }
    }

    pub fn query_kind(&self) -> Option<&'static [u8]> {
        match self {
            DhtMsgKind::Ping => Some(PING_KEY),
            DhtMsgKind::FindNode(_) => Some(FIND_NODES_KEY),
            DhtMsgKind::GetPeers(_) => Some(GET_PEERS_KEY),
            DhtMsgKind::Announce(_, _, _) => Some(ANNOUNCE_KEY),
            DhtMsgKind::Ack
            | DhtMsgKind::Nodes(_)
            | DhtMsgKind::Peers(_, _, _)
            | DhtMsgKind::Error(_, _) => None,
        }
    }

    pub fn data_key(&self) -> &'static [u8] {
        match self {
            DhtMsgKind::Ping
            | DhtMsgKind::FindNode(_)
            | DhtMsgKind::GetPeers(_)
            | DhtMsgKind::Announce(_, _, _) => ARGS_KEY,
            DhtMsgKind::Ack | DhtMsgKind::Nodes(_) | DhtMsgKind::Peers(_, _, _) => RESPONSE_KEY,
            DhtMsgKind::Error(_, _) => ERROR_KEY,
        }
    }

    pub fn to_bencode(self) -> BencodeValue {
        let mut dict = BencodeDict::new();
        match self {
            DhtMsgKind::Ping => {}
            DhtMsgKind::FindNode(target) => {
                dict.insert(TARGET_KEY.into(), target.to_bencode());
            }
            DhtMsgKind::GetPeers(info_hash) => {
                dict.insert(INFO_HASH_KEY.into(), info_hash.to_bencode());
            }
            DhtMsgKind::Announce(info_hash, port_opt, token) => {
                dict.insert(INFO_HASH_KEY.into(), info_hash.to_bencode());
                dict.insert(TOKEN_KEY.into(), token.to_bencode());
                let port = BencodeValue::Int(port_opt.unwrap_or(0) as i64);
                dict.insert(PORT_KEY.into(), port);
                if port_opt.is_none() {
                    dict.insert(IMPLIED_PORT_KEY.into(), BencodeValue::Int(1));
                }
            }
            DhtMsgKind::Ack => {}
            DhtMsgKind::Nodes(nodes) => {
                let mut nodes_bytes = BytesMut::with_capacity(nodes.len() * Node::LEN);
                for node_info in nodes {
                    nodes_bytes.extend(node_info.encode());
                }
                dict.insert(NODES_KEY.into(), BencodeValue::Bytes(nodes_bytes.freeze()));
            }
            DhtMsgKind::Peers(token, nodes, addrs) => {
                dict.insert(TOKEN_KEY.into(), token.to_bencode());

                let mut nodes_bytes = BytesMut::with_capacity(nodes.len() * Node::LEN);
                for node_info in nodes {
                    nodes_bytes.extend(node_info.encode());
                }
                dict.insert(NODES_KEY.into(), BencodeValue::Bytes(nodes_bytes.freeze()));

                let bencoded_addrs = addrs
                    .iter()
                    .map(|addr| BencodeValue::Bytes(addr.encode()))
                    .collect();
                dict.insert(ADDRS_KEY.into(), BencodeValue::List(bencoded_addrs));
            }
            DhtMsgKind::Error(err_code, err_msg) => {
                return BencodeValue::List(vec![
                    BencodeValue::Int(err_code as i64),
                    BencodeValue::Bytes(err_msg),
                ]);
            }
        }

        BencodeValue::Dict(dict)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhtMsg {
    trans_id: Bytes,
    sender: NodeId,
    kind: DhtMsgKind,
}

impl DhtMsg {
    pub fn new(trans_id: Bytes, mut sender: NodeId, kind: DhtMsgKind) -> DhtMsg {
        DhtMsg {
            trans_id,
            sender,
            kind,
        }
    }

    pub fn to_bencode(self) -> BencodeValue {
        let mut b = BencodeDict::new();

        b.insert(TRANSACTION_KEY.into(), BencodeValue::Bytes(self.trans_id));

        let msg_kind: Bytes = self.kind.msg_kind().into();
        b.insert(MSG_KIND_KEY.into(), BencodeValue::Bytes(msg_kind.clone()));

        if let Some(query_kind) = self.kind.query_kind() {
            b.insert(msg_kind.into(), BencodeValue::Bytes(query_kind.into()));
        }

        let data_key = self.kind.data_key();
        let mut data = self.kind.to_bencode();
        if data.get_dict().is_ok() {
            let mut data_dict = data.into_dict().unwrap();
            data_dict.insert(SENDER_KEY.into(), self.sender.to_bencode());
            data = BencodeValue::Dict(data_dict);
        }
        b.insert(data_key.into(), data);

        BencodeValue::Dict(b)
    }

    pub fn from_bencode(b: &BencodeValue) -> Result<DhtMsg> {
        let dict = b.get_dict()?;
        let trans_id = dict.val(TRANSACTION_KEY)?.get_bytes()?.clone();
        let mut sender: NodeId = NodeId::new([0u8; NodeId::LEN]);

        let kind_str: &[u8] = &dict.val(MSG_KIND_KEY)?.get_bytes()?;
        let kind = match kind_str {
            QUERY_KEY => {
                let query_kind: &[u8] = &dict.val(QUERY_KEY)?.get_bytes()?;
                let data = dict.val(ARGS_KEY)?.get_dict()?;
                let sender_bytes: &[u8] = data.val(SENDER_KEY)?.get_bytes()?;
                sender = NodeId::new(sender_bytes.try_into()?);

                match query_kind {
                    PING_KEY => DhtMsgKind::Ping,
                    FIND_NODES_KEY => {
                        let target: &[u8] = data.val(TARGET_KEY)?.get_bytes()?;
                        DhtMsgKind::FindNode(NodeId::new(target.try_into()?))
                    }
                    GET_PEERS_KEY => {
                        let info_hash: &[u8] = data.val(INFO_HASH_KEY)?.get_bytes()?;
                        DhtMsgKind::GetPeers(InfoHash::new(info_hash.try_into()?))
                    }
                    ANNOUNCE_KEY => {
                        let info_hash: &[u8] = data.val(INFO_HASH_KEY)?.get_bytes()?;
                        let token = Token(data.val(TOKEN_KEY)?.get_bytes()?.clone());
                        let port = if data
                            .val(IMPLIED_PORT_KEY)
                            .unwrap_or(&BencodeValue::Int(0))
                            .get_int()?
                            == 0
                        {
                            Some(data.val(PORT_KEY)?.get_int()? as u16)
                        } else {
                            None
                        };
                        DhtMsgKind::Announce(InfoHash::new(info_hash.try_into()?), port, token)
                    }
                    _ => {
                        return Err(anyhow!("could not parse dht query msg: `{:?}` ", b));
                    }
                }
            }
            RESPONSE_KEY => {
                let data = dict.val(RESPONSE_KEY)?.get_dict()?;
                let sender_bytes: &[u8] = data.val(SENDER_KEY)?.get_bytes()?;
                sender = NodeId::new(sender_bytes.try_into()?);

                if let Ok(token_bencoded) = data.val(TOKEN_KEY) {
                    let token = Token::from_bencode(token_bencoded)?;
                    let empty = BencodeValue::Bytes("".into());

                    let mut nodes = vec![];
                    let nodes_bencoded = data.val(NODES_KEY).unwrap_or(&empty);
                    for chunk in nodes_bencoded.get_bytes()?.chunks(Node::LEN) {
                        nodes.push(Node::decode(chunk)?);
                    }

                    let mut addrs = vec![];
                    let addrs_bencoded = data.val(ADDRS_KEY).unwrap_or(&empty);
                    for ben_addr in addrs_bencoded.get_list()? {
                        addrs.push(IpPort::decode(ben_addr.get_bytes()?)?);
                    }

                    DhtMsgKind::Peers(token, nodes, addrs)
                } else if let Ok(nodes_bencoded) = data.val(NODES_KEY) {
                    let mut nodes = vec![];
                    for chunk in nodes_bencoded.get_bytes()?.chunks(Node::LEN) {
                        nodes.push(Node::decode(chunk)?);
                    }
                    DhtMsgKind::Nodes(nodes)
                } else if let Err(_) = data.val(ADDRS_KEY) {
                    DhtMsgKind::Ack
                } else {
                    return Err(anyhow!("could not parse dht response msg: `{:?}` ", b));
                }
            }
            ERROR_KEY => {
                let data = dict.val(ERROR_KEY)?.get_list()?;
                if data.len() != 2 {
                    return Err(anyhow!("expected 2 items in key `e`"));
                }
                let err_code = data[0].get_int()?;
                let err_msg = data[1].get_bytes()?.clone();
                DhtMsgKind::Error(DhtErrorCode::from_i64(err_code)?, err_msg)
            }
            unknown_msg_kind => {
                return Err(anyhow!("unknown msg kind: `{:?}`", unknown_msg_kind));
            }
        };

        Ok(DhtMsg {
            trans_id,
            sender,
            kind,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn test_(msg_kind: DhtMsgKind) {
        let msg = DhtMsg::new(
            "transaction id".into(),
            NodeId::new([95; NodeId::LEN]),
            msg_kind,
        );
        assert_eq!(
            DhtMsg::from_bencode(&msg.clone().to_bencode()).unwrap(),
            msg
        );
    }

    #[test]
    fn test_dht_msg_ping_and_ack() {
        test_(DhtMsgKind::Ping);
        test_(DhtMsgKind::Ack);
    }

    #[test]
    fn test_dht_msg_find_node_and_nodes() {
        test_(DhtMsgKind::FindNode(NodeId::new([12; NodeId::LEN])));
        test_(DhtMsgKind::Nodes(vec![]));
        test_(DhtMsgKind::Nodes(vec![
            Node::new(
                NodeId::new([65; NodeId::LEN]),
                IpPort::new(Ipv4Addr::new(1, 2, 3, 4), 8080),
            ),
            Node::new(
                NodeId::new([66; NodeId::LEN]),
                IpPort::new(Ipv4Addr::new(5, 6, 7, 8), 8081),
            ),
        ]));
    }

    #[test]
    fn test_dht_msg_get_peers_and_peers() {
        test_(DhtMsgKind::GetPeers(InfoHash::new([67; InfoHash::LEN])));

        let nodes = vec![
            Node::new(
                NodeId::new([65; NodeId::LEN]),
                IpPort::new(Ipv4Addr::new(1, 2, 3, 4), 8080),
            ),
            Node::new(
                NodeId::new([66; NodeId::LEN]),
                IpPort::new(Ipv4Addr::new(5, 6, 7, 8), 8081),
            ),
        ];
        let addrs = vec![
            IpPort::new(Ipv4Addr::new(11, 12, 13, 14), 8082),
            IpPort::new(Ipv4Addr::new(15, 16, 17, 18), 8083),
        ];
        let token = Token("token".into());
        test_(DhtMsgKind::Peers(token.clone(), vec![], vec![]));
        test_(DhtMsgKind::Peers(token.clone(), nodes.clone(), vec![]));
        test_(DhtMsgKind::Peers(token.clone(), vec![], addrs.clone()));
        test_(DhtMsgKind::Peers(token, nodes, addrs));
    }

    #[test]
    fn test_dht_msg_announce() {
        test_(DhtMsgKind::Announce(
            InfoHash::new([67; InfoHash::LEN]),
            Some(8080),
            Token("token".into()),
        ));
        test_(DhtMsgKind::Announce(
            InfoHash::new([67; InfoHash::LEN]),
            None,
            Token("token".into()),
        ))
    }

    #[test]
    fn test_dht_msg_error() {
        let msg = DhtMsg::new(
            "transaction id".into(),
            NodeId::new([0; NodeId::LEN]),
            DhtMsgKind::Error(DhtErrorCode::GenericError, "hello".into()),
        );
        assert_eq!(
            DhtMsg::from_bencode(&msg.clone().to_bencode()).unwrap(),
            msg
        );
    }
}
