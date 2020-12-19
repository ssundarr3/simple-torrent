use crate::common::fake_data::*;
use bitvec::{order::Msb0, vec::BitVec};
use bytes::Bytes;
use simple_torrent::handshake::Handshake;
use simple_torrent::meta_info::MetaInfo;
use simple_torrent::torrent_msg::{DataIndex, TorrentMsg};
use simple_torrent::tracker::gen_peer_id;
use simple_torrent::type_alias::*;
use simple_torrent::util::div_ceil;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

#[derive(Debug)]
pub struct FakePeer {
    listener: TcpListener,
    peer_id: PeerId,
    have: BitVec<Msb0, u8>,
    data: FakeData,
    meta_info: MetaInfo,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PiecesHave {
    None,
    All,
    Only(Vec<usize>),
    Missing(Vec<usize>),
}

impl PiecesHave {
    fn to_bitfield(&self, num_pieces: usize) -> BitVec<Msb0, u8> {
        let mut bitfield = BitVec::repeat(false, div_ceil(num_pieces, 8) * 8);

        match self {
            PiecesHave::None => {}
            PiecesHave::All => {
                bitfield |= BitVec::<Msb0, u8>::repeat(true, num_pieces);
            }
            PiecesHave::Missing(not_haves) => {
                bitfield |= BitVec::<Msb0, u8>::repeat(true, num_pieces);
                for not_have_index in not_haves {
                    bitfield.set(*not_have_index, false);
                }
            }
            PiecesHave::Only(haves) => {
                for have_index in haves {
                    bitfield.set(*have_index, true);
                }
            }
        }

        bitfield
    }
}

impl FakePeer {
    pub fn new(meta_info: Arc<MetaInfo>, data: Arc<FakeData>, have: PiecesHave) -> FakePeer {
        FakePeer {
            listener: TcpListener::bind("127.0.0.1:0").unwrap(),
            peer_id: gen_peer_id(),
            have: have.to_bitfield(meta_info.num_pieces),
            data: (*data).clone(),
            meta_info: (*meta_info).clone(),
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.listener.local_addr().unwrap()
    }

    pub fn start(&mut self) {
        let mut socket = self.listener.accept().unwrap().0;
        let handshake = Handshake::new(self.meta_info.info_hash, self.peer_id);
        handshake.write(&mut socket).unwrap();
        Handshake::read(&mut socket).unwrap();

        TorrentMsg::Bitfield(self.have.clone())
            .write(&mut socket)
            
            .unwrap();

        let mut other_have: BitVec<Msb0, u8> = BitVec::repeat(false, self.have.len());
        let mut complete: BitVec<Msb0, u8> = BitVec::repeat(true, self.meta_info.num_pieces);
        for _ in 0..(other_have.len() - complete.len()) {
            complete.push(false);
        }

        if self.have != complete {
            TorrentMsg::Interested.write(&mut socket).unwrap();
        }

        while let Ok(msg) = TorrentMsg::read(&mut socket) {
            match msg {
                TorrentMsg::Interested => TorrentMsg::Unchoke.write(&mut socket).unwrap(),
                TorrentMsg::Have(i) => other_have.set(i, true),
                TorrentMsg::Bitfield(have) => other_have |= have,
                TorrentMsg::Request(index, block_len) => {
                    let start = index.piece * self.meta_info.piece_len + index.offset;
                    let end = start + block_len;
                    TorrentMsg::Block(index, Bytes::copy_from_slice(&self.data.bytes[start..end]))
                        .write(&mut socket)
                        
                        .unwrap();
                }
                TorrentMsg::Block(index, block) => {
                    assert_eq!(block.len(), self.meta_info.piece_len(index.piece));
                    self.have.set(index.piece, true);
                }
                TorrentMsg::Unchoke
                | TorrentMsg::KeepAlive
                | TorrentMsg::Choke
                | TorrentMsg::NotInterested
                | TorrentMsg::Cancel(_, _)
                | TorrentMsg::Port(_) => {}
            }

            let needs = !self.have.clone() & other_have.clone();
            for (piece_index, need) in needs.iter().enumerate() {
                if *need {
                    TorrentMsg::Request(
                        DataIndex::new(piece_index, 0),
                        self.meta_info.piece_len(piece_index),
                    )
                    .write(&mut socket)
                    
                    .unwrap();
                }
            }

            // This fake peer and the real peer have all data, so stop.
            if self.have == complete && other_have == complete {
                break;
            }
        }
    }
}
