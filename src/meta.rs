use crate::bencode::{BencodeDict, BencodeValue, GetFromBencodeDict};
use crate::type_alias::*;
use crate::util::div_ceil;
use anyhow::Result;
use bytes::{Bytes, BytesMut};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::convert::TryInto;
use std::path::PathBuf;

const INFO_KEY: &'static [u8] = b"info";
const PIECE_LEN_KEY: &'static [u8] = b"piece length";
const PIECE_HASHES_KEY: &'static [u8] = b"pieces";
const NAME_KEY: &'static [u8] = b"name";
const ANNOUNCE_KEY: &'static [u8] = b"announce";
const LENGTH_KEY: &'static [u8] = b"length";
const FILES_KEY: &'static [u8] = b"files";
const PATH_KEY: &'static [u8] = b"path";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Info {
    /// The size of a piece. The last piece may be smaller.
    pub piece_len: usize,

    /// The number of pieces.
    pub num_pieces: usize,

    /// A list of hashes, one for each piece. Used to verify that piece data is correct.
    pub piece_hashes: Vec<PieceHash>,

    /// The name of the output directory or file.
    pub name: String,

    /// The relative path of each file and the size of each file in bytes.
    files: Vec<(PathBuf, usize)>,

    /// `piece_starts[i]` has the file index and offset of where piece `i` starts.
    piece_starts: Vec<FileIndex>,

    /// The size (in bytes) of all the files to download.
    pub data_len: usize,
}

impl Info {
    pub fn new(
        name: String,
        piece_len: usize,
        files: Vec<(PathBuf, usize)>,
        piece_hashes: Vec<PieceHash>,
    ) -> Info {
        Info {
            piece_len: piece_len,
            num_pieces: piece_hashes.len(),
            piece_starts: MetaInfo::piece_starts(&files, piece_hashes.len(), piece_len),
            piece_hashes,
            name,
            data_len: files.iter().map(|(_, file_len)| file_len).sum(),
            files: files,
        }
    }

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

    pub fn from_bytes(
        info_bytes: &[u8],
        downloads_dir: &PathBuf,
        info_hash: &InfoHash,
    ) -> Result<Info> {
        if info_hash != &InfoHash::new(Sha1::digest(info_bytes).into()) {
            return Err(anyhow!("Info hash did not match"));
        }
        let b = BencodeValue::decode(info_bytes)?;
        let dict = b.get_dict()?;
        let info = Info::from_bencode(dict, downloads_dir.clone())?;
        Ok(info)
    }

    fn from_bencode(info_dict: &BencodeDict, mut output: PathBuf) -> Result<Info> {
        // Exactly one of `length` and `files` should be set.
        let length_res = info_dict.val(LENGTH_KEY);
        let files_res = info_dict.val(FILES_KEY);
        let name = info_dict.val(NAME_KEY)?.get_string()?;
        output.push(name.clone());
        // `output` is now either the path to the output file (for single file torrent),
        // or the path to the output directory (for multi-file torrent).

        let files: Vec<(PathBuf, usize)> = match (length_res, files_res) {
            (Ok(_), Ok(_)) | (Err(_), Err(_)) => {
                return Err(anyhow!("download must either be a file or directory"));
            }
            (Ok(length), Err(_)) => vec![(output, (length.get_int()? as usize))],
            (Err(_), Ok(files)) => {
                let mut file_and_lengths: Vec<(PathBuf, usize)> = vec![];
                for file in files.get_list()? {
                    let file_dict = file.get_dict()?;

                    let mut output_path: PathBuf = output.clone();
                    let rel_path = file_dict.val(PATH_KEY)?.get_strings()?;
                    if rel_path.is_empty() {
                        return Err(anyhow!("path to file to download is empty"));
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
            return Err(anyhow!("no data to download!"));
        }

        let hashes_bytes = info_dict.val(PIECE_HASHES_KEY)?.get_bytes()?;
        if hashes_bytes.len() % PieceHash::LEN != 0 {
            return Err(anyhow!("invalid piece hashes `{:?}`", hashes_bytes));
        }
        let piece_hashes: Vec<PieceHash> = hashes_bytes
            .chunks_exact(PieceHash::LEN)
            .map(|chunk| PieceHash::new(chunk.try_into().unwrap()))
            .collect();

        let piece_len = info_dict.val(PIECE_LEN_KEY)?.get_int()? as usize;
        let num_pieces = div_ceil(data_len, piece_len);
        if piece_hashes.len() != num_pieces {
            return Err(anyhow!("inconsistent number of pieces"));
        }

        Ok(Info {
            piece_len,
            name,
            num_pieces,
            piece_starts: MetaInfo::piece_starts(&files, num_pieces, piece_len),
            piece_hashes,
            files,
            data_len,
        })
    }

    fn to_bencode(&self) -> BencodeValue {
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

        return BencodeValue::Dict(i);
    }

    /// Returns the filepath(s) in which this piece should exist, and the
    /// start offset for the first file and the end offset for the last file.
    pub fn piece_files<'a>(&'a self, piece_index: usize) -> PieceFiles<'a> {
        let start = self.piece_starts[piece_index].clone();
        let end = self.piece_starts[piece_index + 1].clone();
        PieceFiles {
            path_and_lens: &self.files[start.file..end.file + 1],
            start_offset: start.offset,
            end_offset: end.offset,
        }
    }

    pub fn info_hash(&self) -> InfoHash {
        InfoHash::new(Sha1::digest(&self.to_bencode().encode()).into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InfoKind {
    Partial {
        /// Bencoded `Info` that may not be complete.
        info_bytes: Vec<u8>,
        /// The directory where the download should go.
        downloads_dir: PathBuf,
        /// The (temporary) display name given to the torrent.
        name: String,
        /// The info hash.
        info_hash: InfoHash,
    },
    Full(Info),
}

impl InfoKind {
    pub fn info_hash(&self) -> InfoHash {
        match self {
            InfoKind::Partial { info_hash, .. } => info_hash.clone(),
            InfoKind::Full(info) => info.info_hash(),
        }
    }

    pub fn name(&self) -> &str {
        match self {
            InfoKind::Partial { name, .. } => name,
            InfoKind::Full(info) => &info.name,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetaInfo {
    #[serde(skip)]
    pub cache_dir_opt: Option<PathBuf>,
    pub tracker_url_opt: Option<String>,
    pub info_kind: InfoKind,
    pub my_peer_id: PeerId,
    pub info_hash: InfoHash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    pub fn maybe_save_to_cache(&self) {
        if let Some(cache_dir) = &self.cache_dir_opt {
            std::fs::create_dir_all(cache_dir).unwrap();
            std::fs::write(
                self.info_hash.filepath(cache_dir),
                serde_json::to_string_pretty(&self).unwrap(),
            )
            .unwrap();
        }
    }

    // // TODO: Remove this...
    // pub fn info(&self) -> &Info {
    //     match &self.info_kind {
    //         InfoKind::Full(info) => info,
    //         InfoKind::Partial { .. } => panic!("did not find info data"),
    //     }
    // }

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
        cache_dir_opt: Option<PathBuf>,
        info_kind: InfoKind,
        tracker_url_opt: Option<Url>,
    ) -> MetaInfo {
        let info_hash = info_kind.info_hash();
        if let Some(cache_dir) = &cache_dir_opt {
            let cache_path = info_hash.filepath(cache_dir);
            if let Ok(s) = std::fs::read_to_string(cache_path) {
                info!("Getting MetaInfo from cache!");
                let mut meta = serde_json::from_str::<MetaInfo>(&s).unwrap();
                meta.cache_dir_opt = cache_dir_opt;
                return meta;
            }
        }

        MetaInfo {
            tracker_url_opt: tracker_url_opt.map(|url| url.to_string()),
            my_peer_id: PeerId::gen_random(),
            info_hash,
            cache_dir_opt,
            info_kind: info_kind,
        }
    }

    pub fn from_bencode(
        b: &BencodeValue,
        output: PathBuf,
        cache_dir_opt: Option<PathBuf>,
    ) -> Result<MetaInfo> {
        // The top-level dict.
        let dict = b.get_dict()?;
        let info_dict_bval = dict.val(INFO_KEY)?;
        // The `info` sub-dict.
        let info_dict = info_dict_bval.get_dict()?;

        Ok(MetaInfo {
            tracker_url_opt: Some(Url::parse(&dict.val(ANNOUNCE_KEY)?.get_string()?)?.to_string()),
            my_peer_id: PeerId::gen_random(),
            info_hash: InfoHash::new(Sha1::digest(&info_dict_bval.encode()).into()),
            cache_dir_opt,
            info_kind: InfoKind::Full(Info::from_bencode(info_dict, output)?),
        })
    }

    pub fn to_bencode(&self) -> BencodeValue {
        let mut d = BencodeDict::new();
        d.insert(
            Bytes::from(ANNOUNCE_KEY),
            BencodeValue::Bytes(Bytes::from(
                /* TODO: Maybe shouldn't unwrap here? */
                self.tracker_url_opt.clone().unwrap().as_str().to_string(),
            )),
        );

        let info = match &self.info_kind {
            InfoKind::Full(info) => info,
            InfoKind::Partial { .. } => panic!("TODO: to_bencode should return Result?"),
        };
        d.insert(INFO_KEY.into(), info.to_bencode());

        BencodeValue::Dict(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // #[test]
    // fn test_meta() {
    //     let piece_len = 2usize.pow(16);
    //     let files = vec![
    //         ("output_dir/file_1.txt".into(), 100_000),
    //         ("output_dir/file_2.txt".into(), 10_000),
    //         ("output_dir/file_3.txt".into(), 20_000),
    //         ("output_dir/file_4.txt".into(), 200_000),
    //     ];
    //     let data_len = files.iter().map(|(_, file_len)| file_len).sum();
    //     let piece_hashes: Vec<PieceHash> = (0..div_ceil(data_len, piece_len))
    //         .map(|i| PieceHash::new([i as u8; PieceHash::LEN]))
    //         .collect();
    //     let announce = reqwest::Url::parse("http://example.com/").unwrap();
    //     let name = "output_dir".to_string();
    //     let info_kind = InfoKind::Full(Info::new(name, piece_len, files, piece_hashes));
    //     // TODO: Set cache_dir_opt to test caching...
    //     let meta = MetaInfo::new(None, info_kind, Some(announce));

    //     // Test encoding and decoding.
    //     assert_eq!(
    //         meta,
    //         MetaInfo::from_bencode(&meta.to_bencode(), PathBuf::new(), None).unwrap()
    //     );

    //     // Test `piece_files()`.
    //     assert_eq!(
    //         meta.piece_files(0),
    //         PieceFiles {
    //             path_and_lens: &meta.info().files[0..1],
    //             start_offset: 0,
    //             end_offset: piece_len,
    //         }
    //     );
    //     // The piece at index 1 starts in `file_1` and ends in `file_4`.
    //     let first_3_files_len: usize = meta.info().files.iter().take(3).map(|(_, l)| l).sum();
    //     let file_4_offset = piece_len - (first_3_files_len % piece_len);
    //     assert_eq!(
    //         meta.piece_files(1),
    //         PieceFiles {
    //             path_and_lens: &meta.info().files[0..4],
    //             start_offset: piece_len,
    //             end_offset: file_4_offset,
    //         }
    //     );
    //     assert_eq!(
    //         meta.piece_files(2),
    //         PieceFiles {
    //             path_and_lens: &meta.info().files[3..4],
    //             start_offset: file_4_offset,
    //             end_offset: file_4_offset + piece_len,
    //         }
    //     );
    //     assert_eq!(
    //         meta.piece_files(5),
    //         PieceFiles {
    //             path_and_lens: &meta.info().files[3..4],
    //             start_offset: file_4_offset + 3 * piece_len,
    //             end_offset: meta.info().files[3].1,
    //         }
    //     );
    // }
}
