use crate::bencode::BencodeValue;
use bytes::Bytes;
use rand::distributions::Uniform;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerId([u8; PeerId::LEN]);

impl PeerId {
    pub const LEN: usize = 20;

    pub fn new(data: [u8; PeerId::LEN]) -> PeerId {
        PeerId(data)
    }

    pub fn get(&self) -> &[u8; PeerId::LEN] {
        &self.0
    }

    pub fn gen_random() -> PeerId {
        // An arbitrary prefix that doesn't clash with known clients: http://www.bittorrent.org/beps/bep_0020.html
        const PREFIX: &[u8] = "PI".as_bytes();
        let distribution = Uniform::new(0, 10);
        let mut rng = thread_rng();

        let mut peer_id = [0; PeerId::LEN];
        peer_id[..PREFIX.len()].copy_from_slice(PREFIX);
        for i in PREFIX.len()..PeerId::LEN {
            peer_id[i] = b'0' + rng.sample(distribution);
        }
        PeerId::new(peer_id)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct PieceHash([u8; PieceHash::LEN]);

impl PieceHash {
    pub const LEN: usize = 20;

    pub fn new(data: [u8; PieceHash::LEN]) -> PieceHash {
        PieceHash(data)
    }

    pub fn get(&self) -> &[u8; PieceHash::LEN] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct InfoHash([u8; InfoHash::LEN]);

impl InfoHash {
    pub const LEN: usize = 20;

    pub fn new(data: [u8; InfoHash::LEN]) -> InfoHash {
        InfoHash(data)
    }

    pub fn get(&self) -> &[u8; InfoHash::LEN] {
        &self.0
    }

    pub fn to_bencode(&self) -> BencodeValue {
        BencodeValue::Bytes(Bytes::copy_from_slice(self.get()))
    }

    pub fn filename(&self) -> String {
        let byte_strings: Vec<String> = self.get().iter().map(|byte| byte.to_string()).collect();
        byte_strings.join("_")
    }

    pub fn filepath(&self, directory: &PathBuf) -> PathBuf {
        let byte_strings: Vec<String> = self.get().iter().map(|byte| byte.to_string()).collect();
        [directory, &byte_strings.join("_").into()].iter().collect()
    }
}
