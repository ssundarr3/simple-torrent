use crate::bencode::BencodeValue;
use crate::util::IpPort;
use anyhow::Result;
use bytes::{Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeId([u8; NodeId::LEN]);

impl NodeId {
    pub const LEN: usize = 20;

    pub fn new(data: [u8; NodeId::LEN]) -> NodeId {
        NodeId(data)
    }

    pub fn get(&self) -> &[u8; NodeId::LEN] {
        &self.0
    }

    pub fn xor(&self, other: &NodeId) -> NodeId {
        let mut data = [0; NodeId::LEN];
        for i in 0..data.len() {
            data[i] = self.get()[i] ^ other.get()[i];
        }
        NodeId::new(data)
    }

    pub fn leading_zeros(&self) -> usize {
        for (i, byte) in self.get().iter().enumerate() {
            if *byte != 0 {
                return i * 8 + (*byte).leading_zeros() as usize;
            }
        }
        self.get().len() * 8
    }

    pub fn to_bencode(&self) -> BencodeValue {
        BencodeValue::Bytes(Bytes::copy_from_slice(self.get()))
    }

    pub fn gen_random() -> NodeId {
        let mut data = [0; NodeId::LEN];
        for i in 0..NodeId::LEN {
            data[i] = rand::random::<u8>();
        }
        NodeId(data)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Node {
    pub id: NodeId,
    pub ip_port: IpPort,
}

impl Node {
    pub const LEN: usize = NodeId::LEN + IpPort::LEN;

    pub fn new(id: NodeId, ip_port: IpPort) -> Node {
        Node { id, ip_port }
    }

    pub fn decode(bytes: &[u8]) -> Result<Node> {
        if bytes.len() != Node::LEN {
            return Err(anyhow!("expected {} bytes, got {:?}", Node::LEN, bytes));
        }

        let node_id_data: [u8; NodeId::LEN] = bytes[..NodeId::LEN].try_into()?;
        Ok(Node {
            id: NodeId::new(node_id_data),
            ip_port: IpPort::decode(&bytes[NodeId::LEN..])?,
        })
    }

    pub fn encode(&self) -> Bytes {
        let mut bytes = BytesMut::with_capacity(Node::LEN);
        bytes.extend(self.id.get());
        bytes.extend(self.ip_port.encode());
        bytes.freeze()
    }
}