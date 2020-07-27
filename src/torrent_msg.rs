use crate::bencode::{BencodeDict, BencodeValue, GetFromBencodeDict};
use anyhow::Result;
use bitvec::{order::Msb0, vec::BitVec};
use bytes::{Bytes, BytesMut};
use std::convert::TryInto;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// The ids for various torrent messages.
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
    /// A message to keep connection from timing out.
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

    /// In `Bitfield(haves)`, `haves` is a bitvector where `haves[i]` indicates that the sender has piece `i`.
    /// The sender may choose to not reveal all the pieces that they have.
    Bitfield(BitVec<Msb0, u8>),

    /// In `Request(DataIndex { piece, offset }, length)`, the sender requests `length` bytes
    /// starting at `offset` within `piece`.
    Request(DataIndex, usize),

    /// `Block(DataIndex { piece, offset }, bytes)` contains `bytes` data starting at
    /// `offset` within `piece`.
    Block(DataIndex, Bytes),

    /// `Cancel(index, length)` cancels the request for `length` bytes starting at `index`.
    Cancel(DataIndex, usize),

    /// The `Port` number where the sender is listening for DHT messages.
    Port(u16),

    // TODO:
    // /// `ExtendHandshake(ExtendMsgIds)`
    // ExtendHandshake(ExtendMsgIds),
    /// A protocol extension message.
    Extend(ExtendMsg),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendMsg {
    /// The extension message id.
    id: u8,
    /// Bencoded dictionary data for this extension message.
    data: BencodeDict,
    /// Trailing bytes used by `MetadataBlock`.
    extra: Bytes,
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
            TorrentMsg::Extend(extend) => {
                buf.extend(&[EXTEND_ID]);
                buf.extend(&extend.id.to_be_bytes());
                buf.extend(BencodeValue::Dict(extend.data).encode());
                buf.extend(extend.extra);
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
                let extend_id = body[0];
                let (decoded, rest) = BencodeValue::decode_and_rest(&body[1..])?;
                Ok(TorrentMsg::Extend(ExtendMsg {
                    id: body[0],
                    data: decoded.into_dict()?,
                    extra: Bytes::copy_from_slice(rest),
                }))
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
        } else if let TorrentMsg::Extend(extend) = self {
            write!(
                f,
                "Extend({:?}, data={:?}, extra={:?})",
                extend.id,
                extend.data,
                Bytes::copy_from_slice(&extend.extra[..(std::cmp::min(5, extend.extra.len()))])
            )
        } else {
            write!(f, "{:?}", self)
        }
    }
}

const EXTEND_HANDSHAKE_ID: u8 = 0;
/// A mapping from message type to the message id.
/// Peers choose this mapping and sends it in `ExtendMsg::Handshake`.
/// Message id of 0 indicates the message type is not supported.
/// All other message ids must be unique and positive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendMsgIds {
    ut_metadata: u8,
    ut_pex: u8,
}

// Ids for various messages.
// These are arbitrary positive byte values that are not repeated.
const SUPPORTED_EXTENSIONS_KEY: &'static [u8] = b"m";
const UT_METADATA_KEY: &'static [u8] = b"ut_metadata";
const UT_PEX_KEY: &'static [u8] = b"ut_pex";
const METADATA_MSG_TYPE_KEY: &'static [u8] = b"msg_type";
const METADATA_PIECE_KEY: &'static [u8] = b"piece";
const METADATA_SIZE_KEY: &'static [u8] = b"total_size";
const METADATA_REQUEST_ID: i64 = 0;
const METADATA_BLOCK_ID: i64 = 1;
const METADATA_REJECT_ID: i64 = 2;

impl ExtendMsgIds {
    pub fn new(ut_metadata: bool, ut_pex: bool) -> ExtendMsgIds {
        // Arbitrary positive and unique ids chosen if extension is supported.
        ExtendMsgIds {
            ut_metadata: if ut_metadata { 1 } else { 0 },
            ut_pex: if ut_pex { 2 } else { 0 },
        }
    }

    pub fn ut_metadata(&self) -> Result<u8> {
        if self.ut_metadata == 0 {
            Err(anyhow!("ut_metadata not supported"))
        } else {
            Ok(self.ut_metadata)
        }
    }

    pub fn to_bencode(&self) -> BencodeValue {
        let mut d = BencodeDict::new();
        d.insert(
            UT_METADATA_KEY.into(),
            BencodeValue::Int(self.ut_metadata as i64),
        );
        d.insert(UT_PEX_KEY.into(), BencodeValue::Int(self.ut_pex as i64));
        BencodeValue::Dict(d)
    }

    pub fn from_bencode(b: &BencodeValue) -> Result<ExtendMsgIds> {
        let d = b.get_dict()?;
        const ZERO: BencodeValue = BencodeValue::Int(0);
        let ut_metadata = d.get(UT_METADATA_KEY).unwrap_or(&ZERO).get_int()? as u8;
        let ut_pex = d.get(UT_PEX_KEY).unwrap_or(&ZERO).get_int()? as u8;
        Ok(ExtendMsgIds {
            ut_metadata,
            ut_pex,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtendMsgKind {
    /// A handshake message with the message types supported.
    Handshake(ExtendMsgIds),
    /// `MetadataRequest(piece)` is a request for a `piece` of the meta data.
    /// Each piece (except possibly for the last piece) is 16KB.
    MetadataRequest(usize),
    /// `MetadataBlock(piece, total_size, metadata_block)` is the response for a `MetadataRequest`.
    MetadataBlock(usize, usize, Bytes),
    /// `MetadataReject(piece)` means the sender will not send `piece` of the meta data.
    MetadataReject(usize),
    /// An unknown extension message.
    Unknown,
}

impl ExtendMsgKind {
    pub fn from_extend_msg(msg: ExtendMsg, ids: &ExtendMsgIds) -> Result<ExtendMsgKind> {
        let parsed = if msg.id == EXTEND_HANDSHAKE_ID {
            ExtendMsgKind::Handshake(ExtendMsgIds::from_bencode(
                msg.data.val(SUPPORTED_EXTENSIONS_KEY)?,
            )?)
        } else if msg.id == ids.ut_metadata {
            match msg.data.val(METADATA_MSG_TYPE_KEY)?.get_int()? {
                METADATA_REQUEST_ID => ExtendMsgKind::MetadataRequest(
                    msg.data.val(METADATA_PIECE_KEY)?.get_int()? as usize,
                ),
                METADATA_BLOCK_ID => ExtendMsgKind::MetadataBlock(
                    msg.data.val(METADATA_PIECE_KEY)?.get_int()? as usize,
                    msg.data.val(METADATA_SIZE_KEY)?.get_int()? as usize,
                    msg.extra,
                ),
                METADATA_REJECT_ID => ExtendMsgKind::MetadataReject(
                    msg.data.val(METADATA_PIECE_KEY)?.get_int()? as usize,
                ),
                _ => ExtendMsgKind::Unknown,
            }
        } else {
            ExtendMsgKind::Unknown
        };

        Ok(parsed)
    }

    pub fn try_into_extend_msg(self, ids: &ExtendMsgIds) -> Result<ExtendMsg> {
        let mut data = BencodeDict::new();
        let mut extra = Bytes::new();
        let id;
        match self {
            ExtendMsgKind::Handshake(ids) => {
                id = EXTEND_HANDSHAKE_ID;
                data.insert(SUPPORTED_EXTENSIONS_KEY.into(), ids.to_bencode());
            }
            ExtendMsgKind::MetadataRequest(piece) => {
                id = ids.ut_metadata()?;
                data.insert(
                    METADATA_MSG_TYPE_KEY.into(),
                    BencodeValue::Int(METADATA_REQUEST_ID),
                );
                data.insert(METADATA_PIECE_KEY.into(), BencodeValue::Int(piece as i64));
            }
            ExtendMsgKind::MetadataBlock(piece, total_size, block) => {
                id = ids.ut_metadata()?;
                data.insert(
                    METADATA_MSG_TYPE_KEY.into(),
                    BencodeValue::Int(METADATA_BLOCK_ID),
                );
                data.insert(METADATA_PIECE_KEY.into(), BencodeValue::Int(piece as i64));
                data.insert(
                    METADATA_SIZE_KEY.into(),
                    BencodeValue::Int(total_size as i64),
                );
                extra = block;
            }
            ExtendMsgKind::MetadataReject(piece) => {
                id = ids.ut_metadata()?;
                data.insert(
                    METADATA_MSG_TYPE_KEY.into(),
                    BencodeValue::Int(METADATA_REJECT_ID),
                );
                data.insert(METADATA_PIECE_KEY.into(), BencodeValue::Int(piece as i64));
            }
            ExtendMsgKind::Unknown => {
                return Err(anyhow!("unknown extend message"));
            }
        };

        Ok(ExtendMsg { id, data, extra })
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
            TorrentMsg::Block(DataIndex::new(1, 2), Bytes::new()),
            &[BLOCK_ID, 0, 0, 0, 1, 0, 0, 0, 2],
        )
        .await;
        test_(
            TorrentMsg::Block(DataIndex::new(1, 2), Bytes::from("ABC")),
            &[BLOCK_ID, 0, 0, 0, 1, 0, 0, 0, 2, 65, 66, 67],
        )
        .await;
    }

    #[test]
    fn test_extend_ids() {
        let ids = ExtendMsgIds::new(true, false);
        assert_eq!(ExtendMsgIds::from_bencode(&ids.to_bencode()).unwrap(), ids);
        assert!(ids.ut_metadata().is_ok());
    }

    fn test_extend_msg_(msg: ExtendMsgKind, ids: &ExtendMsgIds, bad_ids: &ExtendMsgIds) {
        let extend_msg = msg.clone().try_into_extend_msg(&ids).unwrap();
        assert_eq!(
            ExtendMsgKind::from_extend_msg(extend_msg.clone(), &ids).unwrap(),
            msg
        );

        if let ExtendMsgKind::Handshake(_) = &msg {
            // Handshakes do not require knowing message id and can be encoded/decoded.
            assert_eq!(
                ExtendMsgKind::from_extend_msg(extend_msg.clone(), &ids).unwrap(),
                msg
            );
        } else {
            // Other messages cannot be encoded/decoded if id is not known.
            assert!(msg.clone().try_into_extend_msg(&bad_ids).is_err());
            assert_eq!(
                ExtendMsgKind::from_extend_msg(extend_msg, &bad_ids).unwrap(),
                ExtendMsgKind::Unknown
            );
        }
    }

    #[test]
    fn test_extend_msg_kind() {
        let ids = ExtendMsgIds::new(true, false);
        let bad_ids = ExtendMsgIds::new(false, false);

        let handshake_msg = ExtendMsgKind::Handshake(ids.clone());
        test_extend_msg_(handshake_msg, &ids, &bad_ids);

        let request_msg = ExtendMsgKind::MetadataRequest(42);
        test_extend_msg_(request_msg, &ids, &bad_ids);

        let block_msg = ExtendMsgKind::MetadataBlock(12, 1999, "metadata...".into());
        test_extend_msg_(block_msg, &ids, &bad_ids);

        let reject_msg = ExtendMsgKind::MetadataReject(43);
        test_extend_msg_(reject_msg, &ids, &bad_ids);

        let unknown_msg = ExtendMsgKind::Unknown;
        assert!(unknown_msg.try_into_extend_msg(&ids).is_err());
        assert_eq!(
            ExtendMsgKind::from_extend_msg(
                ExtendMsg {
                    id: 88,
                    data: BencodeDict::new(),
                    extra: Bytes::new(),
                },
                &ids
            )
            .unwrap(),
            ExtendMsgKind::Unknown
        );
    }

    #[tokio::test]
    async fn test_extend_message() {
        let mut d = BencodeDict::new();
        d.insert("m".into(), BencodeValue::Int(42));

        test_(
            TorrentMsg::Extend(ExtendMsg {
                id: 1,
                data: d,
                extra: "ABC".into(),
            }),
            &[
                EXTEND_ID, 1, // id
                100, 49, 58, 109, 105, 52, 50, 101, 101, // "d1:mi42ee" in bytes
                65, 66, 67, // extra bytes "ABC"
            ],
        )
        .await
    }
}
