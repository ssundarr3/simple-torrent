#![allow(dead_code, unused_imports, unused_variables, unused_mut)]

pub mod dht_msg;
pub mod node;

use crate::dht::dht_msg::{DhtMsg, DhtMsgKind, Token};
use crate::dht::node::{Node, NodeId};
use crate::type_alias::InfoHash;
use crate::util::IpPort;
use anyhow::Result;
use bitvec::{order::Msb0, vec::BitVec};
use bytes::Bytes;
use std::collections::HashMap;
use std::net::UdpSocket;
use std::time::Instant;

/*
// Making a query for peers example:
    // use std::net::UdpSocket;

    // let socket = UdpSocket::bind("0.0.0.0:0").expect("couldn't bind to address");
    // socket
    //     .connect("67.215.246.10:6881")
    //     .expect("couldn't connect ");
    // println!("connected: {:?}", socket);

    // let bytes_to_send = b"d1:ad2:id20:abczefghij0123456789e1:q4:ping1:t2:aa1:y1:qe";
    // socket.send(bytes_to_send).expect("couldn't send data");
    // println!("sent: {:?}", bytes_to_send);

    // let mut buf = [0; 512];
    // match socket.recv(&mut buf) {
    //     Ok(received) => {
    //         println!("received {} bytes {:?}", received, &buf[..received]);
    //         let bytes = bytes::Bytes::copy_from_slice(&buf[..received]);
    //         println!("{:?}", bytes);
    //     }
    //     Err(e) => println!("recv function failed: {:?}", e),
    // }

    let bytes = [
        100u8, 50, 58, 105, 112, 54, 58, 99, 75, 49, 3, 197, 167, 49, 58, 114, 100, 50, 58, 105,
        100, 50, 48, 58, 50, 245, 78, 105, 115, 81, 255, 74, 236, 41, 205, 186, 171, 242, 251, 227,
        70, 124, 194, 103, 101, 49, 58, 116, 50, 58, 97, 97, 49, 58, 121, 49, 58, 114, 101,
    ];
    let bytes = bytes::Bytes::copy_from_slice(&bytes);
    println!("{:?}", bytes);
    let bencode =
        simple_torrent::bencode::BencodeValue::decode(&bytes).expect("could not decode bencode");
    println!("{:?}", bencode);

    let dht_msg = simple_torrent::dht::dht_msg::DhtMsg::from_bencode(&bencode)
        .expect("could not get understand bencode");
    println!("{:?}", dht_msg);

*/

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
    pub fn new(ip_port: IpPort) -> Result<RoutingTable> {
        Ok(RoutingTable {
            buckets: vec![],
            me: Node::new(NodeId::gen_random(), ip_port),
            pending: HashMap::new(),
            trans_id: std::u16::MAX,
            socket: UdpSocket::bind("0.0.0.0:0")?,
        })
    }

    pub fn next_trans_id(&mut self) -> Bytes {
        self.trans_id = self.trans_id.wrapping_add(1);
        Bytes::copy_from_slice(&self.trans_id.to_be_bytes())
    }

    /// Queries a set of default trackers for peers to seed the routing table.
    pub fn find_initial_peers(&mut self) {
        todo!()
    }

    /// Inserts or updates `node`.
    pub fn upsert(&mut self, node: Node) {
        todo!()
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
    pub fn new(ip_port: IpPort) -> Result<Dht> {
        Ok(Dht {
            routing_table: RoutingTable::new(ip_port)?,
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
