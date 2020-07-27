mod dht_msg;
mod node;

use crate::dht::dht_msg::{DhtMsg, DhtMsgKind, Token};
use crate::dht::node::{Node, NodeId};
use crate::type_alias::InfoHash;
use crate::util::IpPort;
use anyhow::Result;
use bitvec::{order::Msb0, vec::BitVec};
use bytes::Bytes;
use std::collections::HashMap;
use std::time::Instant;
use tokio::net::UdpSocket;

struct Bucket {
    nodes: Vec<Node>,
    last_update_time: Instant,
}

struct RoutingTable {
    buckets: Vec<Bucket>,
    me: Node,
    pending: HashMap<Bytes, DhtMsg>,
    trans_id: u16,
    socket: UdpSocket,
}

impl RoutingTable {
    pub async fn new(ip_port: IpPort) -> Result<RoutingTable> {
        Ok(RoutingTable {
            buckets: vec![],
            me: Node::new(NodeId::gen_random(), ip_port),
            pending: HashMap::new(),
            trans_id: std::u16::MAX,
            socket: UdpSocket::bind("127.0.0.1:0").await?,
        })
    }

    pub fn next_trans_id(&mut self) -> Bytes {
        self.trans_id = self.trans_id.wrapping_add(1);
        Bytes::copy_from_slice(&self.trans_id.to_be_bytes())
    }

    /// Inserts or updates `node`.
    pub fn upsert(node: Node) {
        //
    }

    pub fn send(&mut self, msg_kind: DhtMsgKind) -> Result<()> {
        let msg = DhtMsg::new(self.next_trans_id(), self.me.id, msg_kind);
        trace!("Dht sending: {:?}", msg);
        todo!(" Take IpPort as param and Send the msg to them")
    }

    pub fn recv(&mut self) -> Result<DhtMsg> {
        lazy_static! {
            static ref BUF: [u8; 9216] = [0u8; 9216];
        }
        // let bytes_recvd = udp recv(BUF)?;
        // let msg = DhtMsg::from_bencode( BencodeValue::decode(*BUF[..bytes_recvd])?)?)?;
        todo!(" Return IpPort? and msg received ...")
    }
}

struct Dht {
    routing_table: RoutingTable,
}

impl Dht {
    pub async fn new(ip_port: IpPort) -> Result<Dht> {
        Ok(Dht {
            routing_table: RoutingTable::new(ip_port).await?,
        })
    }

    pub fn start(&self, info_hash: InfoHash) {
        // self.routing_table.get_peers
        // ping bad nodes ... self.routing_table
        loop {
            todo!()
        }
    }
}
