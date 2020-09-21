use crate::bencode::{BencodeDict, BencodeValue, GetBencodeErr, GetFromBencodeDict};
use crate::type_alias::*;
use crate::util::div_ceil;
use bytes::{Bytes, BytesMut};
use reqwest::Url;
use sha1::{Digest, Sha1};
use std::convert::TryInto;
use std::path::PathBuf;
use thiserror::Error;

const INFO_KEY: &'static [u8] = b"info";
const PIECE_LEN_KEY: &'static [u8] = b"piece length";
const PIECE_HASHES_KEY: &'static [u8] = b"pieces";
const NAME_KEY: &'static [u8] = b"name";
const ANNOUNCE_KEY: &'static [u8] = b"announce";
const LENGTH_KEY: &'static [u8] = b"length";
const FILES_KEY: &'static [u8] = b"files";
const PATH_KEY: &'static [u8] = b"path";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaInfo {
    /// The size of any piece, except for the last piece.
    pub piece_len: usize,

    /// The number of pieces.
    pub num_pieces: usize,

    /// A list of hashes, one for each piece. Used to verify that piece data is correct.
    pub piece_hashes: Vec<PieceHash>,

    /// The name of the output directory or file.
    pub name: String,
    /// The relative path of each file to download and the size of each file in bytes.
    pub files: Vec<(PathBuf, usize)>,
    /// `piece_starts[i]` has the file index and offset of where piece `i` starts.
    piece_starts: Vec<FileIndex>,

    /// The size (in bytes) of all the files to download.
    pub data_len: usize,

    /// The URL of the tracker for this torrent, used to find the peers for the torrent.
    pub announce: Url,

    /// SHA-1 hash of the bencoded `info` dictionary. Used in handshake messages to verify the torrent.
    pub info_hash: InfoHash,
}

#[derive(Error, Debug)]
pub enum FromBencodeErr {
    #[error("exactly one of the keys `length` (file download) and `files` (directory download) must exist")]
    ExpectedFileXorDir,

    #[error("path to a file to download must not be empty")]
    FilePathEmpty,

    #[error(
        "found {0} bytes when parsing piece hashes which is not divisible by {}",
        PieceHash::LEN
    )]
    InvalidPieceHashBytes(usize),

    #[error("number of piece hashes (`{0}`) must be equal to ceil(data len / piece len) (`{1}`) ")]
    NumPiecesInvalid(usize, usize),

    #[error("{0}")]
    GetBencodeErr(#[from] GetBencodeErr),

    #[error("{0}")]
    Utf8StringErr(#[from] std::string::FromUtf8Error),

    #[error("{0}")]
    InvalidAnnounceUrl(#[from] url::ParseError),

    #[error("bencode err: {0}")]
    Generic(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileIndex {
    /// The index of the file.
    file: usize,
    /// The offset in the given `file`.
    offset: usize,
}

impl FileIndex {
    pub fn new(file: usize, offset: usize) -> FileIndex {
        FileIndex { file, offset }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PieceFiles<'a> {
    pub path_and_lens: &'a [(PathBuf, usize)],
    pub start_offset: usize,
    pub end_offset: usize,
}

impl MetaInfo {
    pub fn piece_len(&self, piece_index: usize) -> usize {
        assert!(piece_index < self.num_pieces);
        if piece_index + 1 < self.num_pieces {
            self.piece_len
        } else {
            let rem = self.data_len % self.piece_len;
            if rem == 0 {
                self.piece_len
            } else {
                rem
            }
        }
    }

    pub fn from_bencode(b: &BencodeValue, mut output: PathBuf) -> Result<MetaInfo, FromBencodeErr> {
        // The top-level dict.
        let dict = b.get_dict()?;
        let info_dict_bval = dict.val(INFO_KEY)?;
        // The `info` sub-dict.
        let info_dict = info_dict_bval.get_dict()?;

        // Exactly one of `length` and `files` should be set.
        let length_res = info_dict.val(LENGTH_KEY);
        let files_res = info_dict.val(FILES_KEY);
        // `output` is now either the path to the output file (for single file torrent),
        // or the path to the output directory (for multi-file torrent).
        let name = info_dict.val(NAME_KEY)?.get_string()?;
        output.push(name.clone());
        let files: Vec<(PathBuf, usize)> = match (length_res, files_res) {
            (Ok(_), Ok(_)) | (Err(_), Err(_)) => {
                return Err(FromBencodeErr::ExpectedFileXorDir);
            }
            (Ok(length), Err(_)) => vec![(output, (length.get_int()? as usize))],
            (Err(_), Ok(files)) => {
                let mut file_and_lengths: Vec<(PathBuf, usize)> = vec![];
                for file in files.get_list()? {
                    let file_dict = file.get_dict()?;

                    let mut output_path: std::path::PathBuf = output.clone();
                    let rel_path = file_dict.val(PATH_KEY)?.get_strings()?;
                    if rel_path.is_empty() {
                        return Err(FromBencodeErr::FilePathEmpty);
                    }
                    output_path.extend(rel_path);

                    let length = file_dict.val(LENGTH_KEY)?.get_int()?;

                    file_and_lengths.push((output_path, length as usize));
                }
                file_and_lengths
            }
        };

        let data_len = files.iter().map(|(_, file_len)| file_len).sum();
        if data_len == 0 {
            return Err(FromBencodeErr::Generic("no data to download!"));
        }

        let hashes_bytes = info_dict.val(PIECE_HASHES_KEY)?.get_bytes()?;
        if hashes_bytes.len() % PieceHash::LEN != 0 {
            return Err(FromBencodeErr::InvalidPieceHashBytes(hashes_bytes.len()));
        }
        let piece_hashes: Vec<PieceHash> = hashes_bytes
            .chunks_exact(PieceHash::LEN)
            .map(|chunk| PieceHash::new(chunk.try_into().unwrap()))
            .collect();

        let piece_len = info_dict.val(PIECE_LEN_KEY)?.get_int()? as usize;
        let num_pieces = div_ceil(data_len, piece_len);
        if piece_hashes.len() != num_pieces {
            return Err(FromBencodeErr::NumPiecesInvalid(
                piece_hashes.len(),
                num_pieces,
            ));
        }

        Ok(MetaInfo {
            announce: Url::parse(&dict.val(ANNOUNCE_KEY)?.get_string()?)?,
            info_hash: InfoHash::new(Sha1::digest(&info_dict_bval.encode()).into()),
            piece_len: piece_len,
            name,
            num_pieces,
            piece_starts: MetaInfo::piece_starts(&files, num_pieces, piece_len),
            piece_hashes,
            files,
            data_len,
        })
    }

    /// Returns the filepath(s) in which this piece should exist.
    /// Also returns the start offset for the first file and the end offset for the last file.
    /// `piece_index` must be valid.
    pub fn piece_files<'a>(&'a self, piece_index: usize) -> PieceFiles<'a> {
        let start = self.piece_starts[piece_index].clone();
        let end = self.piece_starts[piece_index + 1].clone();
        PieceFiles {
            path_and_lens: &self.files[start.file..end.file + 1],
            start_offset: start.offset,
            end_offset: end.offset,
        }
    }

    fn piece_starts(
        files: &[(PathBuf, usize)],
        num_pieces: usize,
        piece_len: usize,
    ) -> Vec<FileIndex> {
        let mut piece_file_starts = Vec::with_capacity(num_pieces);
        let mut cur_file_index = 0;
        let mut cur_file_offset = 0;
        piece_file_starts.push(FileIndex::new(cur_file_index, cur_file_offset));
        while piece_file_starts.len() < num_pieces {
            let mut len_moved = 0;
            loop {
                let file_len = files[cur_file_index].1;
                let to_move = piece_len - len_moved;
                if to_move > file_len - cur_file_offset {
                    len_moved += file_len - cur_file_offset;
                    cur_file_index += 1;
                    cur_file_offset = 0;
                } else {
                    cur_file_offset += to_move;
                    break;
                }
            }
            piece_file_starts.push(FileIndex::new(cur_file_index, cur_file_offset));
        }
        piece_file_starts.push(FileIndex::new(files.len() - 1, files.last().unwrap().1));
        piece_file_starts
    }

    pub fn new(
        name: String,
        piece_len: usize,
        files: Vec<(PathBuf, usize)>,
        piece_hashes: Vec<PieceHash>,
        announce: Url,
    ) -> MetaInfo {
        let mut meta_info = MetaInfo {
            piece_len: piece_len,
            num_pieces: piece_hashes.len(),
            piece_starts: MetaInfo::piece_starts(&files, piece_hashes.len(), piece_len),
            piece_hashes,
            name,
            data_len: files.iter().map(|(_, file_len)| file_len).sum(),
            files: files,
            announce: announce,
            info_hash: InfoHash::new([0; InfoHash::LEN]),
        };

        // Set the info hash.
        let b = meta_info.to_bencode();
        let info_dict = b.get_dict().unwrap().val(INFO_KEY).unwrap();
        meta_info.info_hash = InfoHash::new(Sha1::digest(&info_dict.encode()).into());

        meta_info
    }

    pub fn to_bencode(&self) -> BencodeValue {
        let mut i = BencodeDict::new();
        i.insert(
            NAME_KEY.into(),
            BencodeValue::Bytes(Bytes::from(
                self.files[0]
                    .0
                    .iter()
                    .next()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string(),
            )),
        );
        i.insert(
            PIECE_LEN_KEY.into(),
            BencodeValue::Int(self.piece_len as i64),
        );
        let mut piece_hashes_concat = BytesMut::new();
        for piece_hash in &self.piece_hashes {
            piece_hashes_concat.extend(piece_hash.get());
        }
        i.insert(
            PIECE_HASHES_KEY.into(),
            BencodeValue::Bytes(piece_hashes_concat.freeze()),
        );
        if self.files.len() == 1 {
            i.insert(LENGTH_KEY.into(), BencodeValue::Int(self.files[0].1 as i64));
        } else {
            let mut files = vec![];
            for (filepath, file_len) in &self.files {
                let mut file = BencodeDict::new();
                file.insert(LENGTH_KEY.into(), BencodeValue::Int(*file_len as i64));
                let filepath_list = BencodeValue::List(
                    filepath
                        .iter()
                        .skip(1)
                        .map(|s| BencodeValue::Bytes(s.to_str().unwrap().to_string().into()))
                        .collect(),
                );
                file.insert(PATH_KEY.into(), filepath_list);
                files.push(BencodeValue::Dict(file));
            }
            i.insert(FILES_KEY.into(), BencodeValue::List(files));
        }

        let mut d = BencodeDict::new();
        d.insert(
            Bytes::from(ANNOUNCE_KEY),
            BencodeValue::Bytes(Bytes::from(self.announce.as_str().to_string())),
        );
        d.insert(INFO_KEY.into(), BencodeValue::Dict(i));

        BencodeValue::Dict(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_meta_info() {
        let piece_len = 2usize.pow(16);
        let files = vec![
            ("output_dir/file_1.txt".into(), 100_000),
            ("output_dir/file_2.txt".into(), 10_000),
            ("output_dir/file_3.txt".into(), 20_000),
            ("output_dir/file_4.txt".into(), 200_000),
        ];
        let data_len = files.iter().map(|(_, file_len)| file_len).sum();
        let piece_hashes: Vec<PieceHash> = (0..div_ceil(data_len, piece_len))
            .map(|i| PieceHash::new([i as u8; PieceHash::LEN]))
            .collect();
        let announce = reqwest::Url::parse("http://example.com/").unwrap();
        let name = "output_dir".to_string();
        let meta_info = MetaInfo::new(name, piece_len, files, piece_hashes, announce);

        // Test encoding and decoding.
        assert_eq!(
            meta_info,
            MetaInfo::from_bencode(&meta_info.to_bencode(), PathBuf::new()).unwrap()
        );

        // Test `piece_files()`.
        assert_eq!(
            meta_info.piece_files(0),
            PieceFiles {
                path_and_lens: &meta_info.files[0..1],
                start_offset: 0,
                end_offset: piece_len,
            }
        );
        // The piece at index 1 starts in `file_1` and ends in `file_4`.
        let first_3_files_len: usize = meta_info.files.iter().take(3).map(|(_, l)| l).sum();
        let file_4_offset = piece_len - (first_3_files_len % piece_len);
        assert_eq!(
            meta_info.piece_files(1),
            PieceFiles {
                path_and_lens: &meta_info.files[0..4],
                start_offset: piece_len,
                end_offset: file_4_offset,
            }
        );
        assert_eq!(
            meta_info.piece_files(2),
            PieceFiles {
                path_and_lens: &meta_info.files[3..4],
                start_offset: file_4_offset,
                end_offset: file_4_offset + piece_len,
            }
        );
        assert_eq!(
            meta_info.piece_files(5),
            PieceFiles {
                path_and_lens: &meta_info.files[3..4],
                start_offset: file_4_offset + 3 * piece_len,
                end_offset: meta_info.files[3].1,
            }
        );
    }
}
