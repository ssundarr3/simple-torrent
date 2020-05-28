use crate::bencode::{BencodeDict, BencodeValue};
use anyhow::Result;
use bitvec::{order::Msb0, vec::BitVec};
use bytes::{Bytes, BytesMut};
use std::convert::TryInto;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const CHOKE_ID: u8 = 0;
const UNCHOKE_ID: u8 = 1;
const INTERESTED_ID: u8 = 2;
const NOT_INTERESTED_ID: u8 = 3;
const HAVE_ID: u8 = 4;
const BITFIELD_ID: u8 = 5;
const REQUEST_ID: u8 = 6;
const BLOCK_ID: u8 = 7;
const CANCEL_ID: u8 = 8;
const PORT_ID: u8 = 9;
const EXTEND_ID: u8 = 20;

/// An index to a byte in the data.
#[derive(Debug, Hash, Clone, PartialEq, Eq)]
pub struct DataIndex {
    /// The piece index.
    pub piece: usize,

    /// The byte offset within the given `piece`.
    pub offset: usize,
}

impl DataIndex {
    pub fn new(piece: usize, offset: usize) -> DataIndex {
        DataIndex { piece, offset }
    }

    fn decode(bytes: &[u8]) -> Result<DataIndex> {
        Ok(DataIndex::new(
            u32::from_be_bytes(bytes[..4].try_into()?) as usize,
            u32::from_be_bytes(bytes[4..8].try_into()?) as usize,
        ))
    }

    fn encode(&self, buf: &mut BytesMut) {
        buf.extend(&(self.piece as u32).to_be_bytes());
        buf.extend(&(self.offset as u32).to_be_bytes());
    }
}

/// A message in the Bittorrent protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TorrentMsg {
    /// A keep alive message to keep the connection alive.
    KeepAlive,

    /// The receiver of this message is choked and will not get any more `Piece` messages.
    Choke,

    /// The receiver of this message is unchoked and can now start `Request`ing pieces.
    Unchoke,

    /// The sender of this message is interested in the pieces that the receiver has.
    Interested,

    /// The sender of this message is not interested in the pieces that the receiver has.
    NotInterested,

    /// `Have(piece_index)` indicates the sender has the piece at `piece_index`.
    Have(usize),

    /// In `Bitfield(haves)`, `haves` is a bitvector where `haves[i]` is set if the sender has piece `i`.
    /// The sender may choose to not reveal all the pieces they have.
    Bitfield(BitVec<Msb0, u8>),

    /// In `Request(DataIndex { piece, offset }, length)`, the sender requests `length` bytes
    /// starting at `offset` within `piece`.
    Request(DataIndex, usize),

    /// `Block(DataIndex { piece, offset }, bytes)` contains the data `bytes` starting at
    /// `offset` within `piece`.
    Block(DataIndex, Bytes),

    /// `Cancel(index, length)` cancels the request for `length` bytes starting at `index`.
    Cancel(DataIndex, usize),

    /// Used to pass the port number for DHT.
    Port(u16),

    /// `Extend(extend_id, dict, extra_bytes)` message.
    Extend(u8, BencodeDict, Bytes),
}

impl TorrentMsg {
    pub fn encode(self) -> Bytes {
        let mut buf = BytesMut::with_capacity(5);
        match self {
            TorrentMsg::KeepAlive => {}
            TorrentMsg::Choke => buf.extend(&[CHOKE_ID]),
            TorrentMsg::Unchoke => buf.extend(&[UNCHOKE_ID]),
            TorrentMsg::Interested => buf.extend(&[INTERESTED_ID]),
            TorrentMsg::NotInterested => buf.extend(&[NOT_INTERESTED_ID]),
            TorrentMsg::Have(piece_index) => {
                buf.extend(&[HAVE_ID]);
                buf.extend(&(piece_index as u32).to_be_bytes())
            }
            TorrentMsg::Bitfield(bitfield) => {
                buf.extend(&[BITFIELD_ID]);
                buf.extend(&bitfield.into_vec());
            }
            TorrentMsg::Request(index, length) => {
                buf.extend(&[REQUEST_ID]);
                index.encode(&mut buf);
                buf.extend(&(length as u32).to_be_bytes());
            }
            TorrentMsg::Block(index, block) => {
                buf.extend(&[BLOCK_ID]);
                index.encode(&mut buf);
                // TODO: See if this copy can be avoided.
                buf.extend(block);
            }
            TorrentMsg::Cancel(index, length) => {
                buf.extend(&[CANCEL_ID]);
                index.encode(&mut buf);
                buf.extend(&(length as u32).to_be_bytes());
            }
            TorrentMsg::Port(port) => {
                buf.extend(&[PORT_ID]);
                buf.extend(&port.to_be_bytes());
            }
            TorrentMsg::Extend(extend_id, extend_msg, extra_bytes) => {
                buf.extend(&[EXTEND_ID]);
                buf.extend(&extend_id.to_be_bytes());
                buf.extend(BencodeValue::Dict(extend_msg).encode());
                buf.extend(extra_bytes);
            }
        };
        buf.freeze()
    }

    pub fn decode(bytes: Vec<u8>) -> Result<TorrentMsg> {
        let body = bytes.get(1..).unwrap_or(&[]);
        // TODO: [..] may panic.
        match bytes.get(0) {
            None => Ok(TorrentMsg::KeepAlive),
            Some(&CHOKE_ID) => Ok(TorrentMsg::Choke),
            Some(&UNCHOKE_ID) => Ok(TorrentMsg::Unchoke),
            Some(&INTERESTED_ID) => Ok(TorrentMsg::Interested),
            Some(&NOT_INTERESTED_ID) => Ok(TorrentMsg::NotInterested),
            Some(&HAVE_ID) => Ok(TorrentMsg::Have(
                u32::from_be_bytes(body.try_into()?) as usize
            )),
            Some(&BITFIELD_ID) => Ok(TorrentMsg::Bitfield(BitVec::from(body))),
            Some(&REQUEST_ID) => Ok(TorrentMsg::Request(
                DataIndex::decode(&body[..8])?,
                u32::from_be_bytes(body[8..].try_into()?) as usize,
            )),
            Some(&BLOCK_ID) => Ok(TorrentMsg::Block(
                DataIndex::decode(&body[..8])?,
                // TODO: See if this copy can be avoided.
                Bytes::copy_from_slice(&body[8..]),
            )),
            Some(&CANCEL_ID) => Ok(TorrentMsg::Cancel(
                DataIndex::decode(&body[..8])?,
                u32::from_be_bytes(body[8..].try_into()?) as usize,
            )),
            Some(&PORT_ID) => Ok(TorrentMsg::Port(u16::from_be_bytes(body.try_into()?))),
            Some(&EXTEND_ID) => {
                let (decoded, rest) = BencodeValue::decode_and_rest(&body[1..])?;
                Ok(TorrentMsg::Extend(
                    body[0],
                    decoded.into_dict()?,
                    Bytes::copy_from_slice(rest),
                ))
            }
            Some(id) => Err(anyhow!(
                "unknown TorrentMsg id `{}` in `{:?}`",
                *id,
                Bytes::copy_from_slice(&bytes),
            )),
        }
    }

    pub async fn read<Reader>(stream: &mut Reader) -> Result<TorrentMsg>
    where
        Reader: AsyncReadExt + std::marker::Unpin,
    {
        let mut message_len_bytes: [u8; 4] = [0; 4];
        stream.read_exact(&mut message_len_bytes).await?;
        let message_len = u32::from_be_bytes(message_len_bytes);

        let mut buf = Vec::with_capacity(message_len as usize);
        stream
            .take(message_len as u64)
            .read_to_end(&mut buf)
            .await?;

        let msg = TorrentMsg::decode(buf)?;

        Ok(msg)
    }

    pub async fn write<Writer>(self, stream: &mut Writer) -> Result<()>
    where
        Writer: AsyncWriteExt + std::marker::Unpin,
    {
        let encoded = self.encode();
        // Write the size and then the data itself.
        stream
            .write_all(&(encoded.len() as u32).to_be_bytes())
            .await?;
        stream.write_all(&encoded).await?;
        Ok(())
    }
}

impl std::fmt::Display for TorrentMsg {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if let TorrentMsg::Block(index, block) = self {
            write!(
                f,
                "Piece({:?}, len={:?}, sample={:?})",
                index,
                block.len(),
                Bytes::copy_from_slice(&block[..(std::cmp::min(5, block.len()))])
            )
        } else if let TorrentMsg::Extend(extend_id, dict, bytes) = self {
            write!(
                f,
                "Extend({:?}, dict={:?}, extra={:?})",
                extend_id,
                dict,
                Bytes::copy_from_slice(&bytes[..(std::cmp::min(5, bytes.len()))])
            )
        } else {
            write!(f, "{:?}", self)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn len_prefixed_(bytes: &[u8]) -> Vec<u8> {
        let mut len_prefixed = (bytes.len() as u32).to_be_bytes().to_vec();
        len_prefixed.extend(bytes);
        len_prefixed
    }

    async fn test_(msg: TorrentMsg, bytes: &[u8]) {
        assert_eq!(bytes, msg.clone().encode());
        assert_eq!(&TorrentMsg::decode(bytes.to_vec()).unwrap(), &msg);

        {
            let mut len_prefixed = len_prefixed_(bytes);
            let mut cursor = Cursor::new(&mut len_prefixed);
            let actual = TorrentMsg::read(&mut cursor).await.unwrap();
            assert_eq!(&msg, &actual);
        }

        {
            let len_prefixed = len_prefixed_(bytes);
            let mut actual_bytes = Vec::with_capacity(len_prefixed.len());
            let mut cursor = Cursor::new(&mut actual_bytes);
            msg.write(&mut cursor).await.unwrap();
            assert_eq!(len_prefixed, actual_bytes);
        }
    }

    #[tokio::test]
    async fn test_constant_messages() {
        test_(TorrentMsg::KeepAlive, &[]).await;
        test_(TorrentMsg::Choke, &[CHOKE_ID]).await;
        test_(TorrentMsg::Unchoke, &[UNCHOKE_ID]).await;
        test_(TorrentMsg::Interested, &[INTERESTED_ID]).await;
        test_(TorrentMsg::NotInterested, &[NOT_INTERESTED_ID]).await;
    }

    #[tokio::test]
    async fn test_constant_size_messages() {
        test_(TorrentMsg::Have(42), &[HAVE_ID, 0, 0, 0, 42]).await;
        test_(
            TorrentMsg::Cancel(DataIndex::new(257, 2), 42),
            &[CANCEL_ID, 0, 0, 1, 1, 0, 0, 0, 2, 0, 0, 0, 42],
        )
        .await;
        test_(
            TorrentMsg::Request(DataIndex::new(1, 2), 42),
            &[REQUEST_ID, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 42],
        )
        .await;
        test_(TorrentMsg::Port(42), &[PORT_ID, 0, 42]).await;
    }

    #[tokio::test]
    async fn test_bitfield_message() {
        test_(
            TorrentMsg::Bitfield(BitVec::<Msb0, u8>::from_vec(b"ABC".to_vec())),
            &[BITFIELD_ID, 65, 66, 67],
        )
        .await;
    }

    #[tokio::test]
    async fn test_block_message() {
        test_(
            TorrentMsg::Block(DataIndex::new(1, 2), Bytes::from("ABC")),
            &[BLOCK_ID, 0, 0, 0, 1, 0, 0, 0, 2, 65, 66, 67],
        )
        .await;
    }

    #[tokio::test]
    async fn test_extend_message() {
        let mut d = BencodeDict::new();
        d.insert("m".into(), BencodeValue::Int(42));

        test_(
            TorrentMsg::Extend(1, d.clone(), "".into()),
            &[
                EXTEND_ID, 1, // id
                100, 49, 58, 109, 105, 52, 50, 101, 101, // "d1:mi42ee" in bytes
            ],
        )
        .await
    }
}
