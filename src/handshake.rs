use crate::type_alias::*;
use anyhow::Result;
use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const EXTENSION_PROTOCOL: u64 = 1 << 20;

/// A message to initiate a connection with a peer.
#[derive(Debug, PartialEq, Eq)]
pub struct Handshake {
    pub protocol: Bytes,
    pub flags: u64,
    pub info_hash: InfoHash,
    pub peer_id: PeerId,
}

impl Handshake {
    pub const PROTOCOL: &'static str = "BitTorrent protocol";
    const NUM_RESERVED_BYTES: usize = 8;

    //
    pub fn new(info_hash: InfoHash, peer_id: PeerId, flags: u64) -> Handshake {
        Handshake {
            protocol: Bytes::from(Handshake::PROTOCOL),
            flags,
            info_hash: info_hash,
            peer_id: peer_id,
        }
    }

    fn encoded_size_(protocol_len: usize) -> usize {
        1 + protocol_len + Handshake::NUM_RESERVED_BYTES + InfoHash::LEN + PeerId::LEN
    }

    fn encode_(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(Handshake::encoded_size_(self.protocol.len()));
        buf.put_u8(self.protocol.len() as u8);
        buf.extend(&self.protocol);
        buf.extend(&self.flags.to_be_bytes());
        buf.extend(self.info_hash.get());
        buf.extend(self.peer_id.get());
        buf.freeze()
    }

    pub async fn read<Reader>(stream: &mut Reader) -> Result<Handshake>
    where
        Reader: AsyncReadExt + std::marker::Unpin,
    {
        let mut protocol_len_bytes = [0; 1];
        stream.read_exact(&mut protocol_len_bytes).await?;
        let protocol_len = protocol_len_bytes[0] as usize;

        let mut protocol = vec![0u8; protocol_len];
        stream.read_exact(&mut protocol).await?;

        let mut reserved = [0; Handshake::NUM_RESERVED_BYTES];
        stream.read_exact(&mut reserved).await?;

        let mut info_hash = [0; InfoHash::LEN];
        stream.read_exact(&mut info_hash).await?;

        let mut peer_id = [0; PeerId::LEN];
        stream.read_exact(&mut peer_id).await?;

        Ok(Handshake {
            protocol: Bytes::copy_from_slice(&protocol),
            flags: u64::from_be_bytes(reserved),
            info_hash: InfoHash::new(info_hash),
            peer_id: PeerId::new(peer_id),
        })
    }

    pub async fn write<Writer>(&self, stream: &mut Writer) -> Result<()>
    where
        Writer: AsyncWriteExt + std::marker::Unpin,
    {
        let encoded = self.encode_();
        stream.write_all(&encoded).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    async fn test_(msg: Handshake, bytes: &[u8]) {
        {
            let mut encoded_msg = Vec::with_capacity(bytes.len());
            let mut cursor = Cursor::new(&mut encoded_msg);
            msg.write(&mut cursor).await.unwrap();
            assert_eq!(bytes, encoded_msg.as_slice());
        }

        {
            let mut input = bytes.to_vec();
            let mut cursor = Cursor::new(&mut input);
            let decoded_msg = Handshake::read(&mut cursor).await.unwrap();
            assert_eq!(&msg, &decoded_msg);
        }
    }

    #[tokio::test]
    async fn test_handshake() {
        test_(
            Handshake {
                protocol: Bytes::from("AAAABBBB"),
                flags: EXTENSION_PROTOCOL,
                info_hash: InfoHash::new([12; InfoHash::LEN]),
                peer_id: PeerId::new([11; PeerId::LEN]),
            },
            &[
                8, // protocol length
                65, 65, 65, 65, 66, 66, 66, 66, // protocol
                0, 0, 0, 0, 0, 0x10, 0, 0, // reserved bytes
                12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
                12, // info hash
                11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
                11, // peer id
            ],
        )
        .await;
    }
}
