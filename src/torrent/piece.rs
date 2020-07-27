use crate::meta::PieceFiles;
use crate::torrent_msg::DataIndex;
use crate::type_alias::*;
use crate::util::div_ceil;
use bytes::Bytes;
use sha1::{Digest, Sha1};
use std::io::{Read, Seek, SeekFrom, Write};

const BLOCK_LEN: usize = 16 * 1024; // Each block is 16KB.

#[derive(Debug)]
pub struct Piece {
    /// The expected SHA-1 hash of this piece's data.
    pub piece_hash: PieceHash,
    /// The final length of this piece.
    pub piece_len: usize,
    /// Blocks of data that make up a piece.
    /// Option is used to accomodate blocks that arrive out of order.
    blocks: Vec<Option<Bytes>>,
    /// The number of blocks left to complete this piece.
    blocks_left: usize,
    /// The next block index to request.
    pub next_block: usize,
    /// Whether or not this piece is de-prioritized when downloading.
    /// This is done so that blocks of this piece that are en-route, aren't re-requested.
    pub deprioritized: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PieceStatus {
    InProgress,
    FailedHashCheck,
    Complete,
}

impl Piece {
    pub fn new(piece_hash: PieceHash, piece_len: usize) -> Piece {
        Piece {
            piece_hash,
            piece_len,
            blocks: vec![],
            blocks_left: div_ceil(piece_len, BLOCK_LEN),
            next_block: 0,
            deprioritized: false,
        }
    }

    fn block_len(&self, block_index: usize) -> usize {
        if block_index + 1 < div_ceil(self.piece_len, BLOCK_LEN) {
            BLOCK_LEN
        } else {
            self.piece_len - (block_index * BLOCK_LEN)
        }
    }

    /// Returns true if the given `data` block was successfully inserted at `offset`.
    pub fn insert(&mut self, offset: usize, data: Bytes) -> bool {
        let block_index = offset / BLOCK_LEN;
        if offset % BLOCK_LEN != 0 || data.len() != self.block_len(block_index) {
            warn!("invalid block (offset={}, len={})", offset, data.len());
            return false;
        }

        for _ in self.blocks.len()..=block_index {
            self.blocks.push(None);
        }

        let block_opt = &mut self.blocks[block_index];
        if block_opt.is_none() {
            *block_opt = Some(data);
            self.blocks_left -= 1;
            return true;
        } else {
            return false;
        }
    }

    pub fn flush_to_disk<'a>(&mut self, piece_files: PieceFiles<'a>) {
        let mut data: Vec<u8> = vec![];
        for block in self.blocks.drain(..) {
            data.extend(block.unwrap());
        }

        let mut data_index = 0;
        for (i, (filepath, file_len)) in piece_files.path_and_lens.iter().enumerate() {
            let mut dir_path = filepath.clone();
            dir_path.pop();
            std::fs::create_dir_all(dir_path).unwrap();
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .open(filepath)
                .unwrap();

            let s = if i == 0 { piece_files.start_offset } else { 0 };
            let e = if i == piece_files.path_and_lens.len() - 1 {
                piece_files.end_offset
            } else {
                *file_len
            };
            let num_bytes_to_write = e - s;

            if file.metadata().unwrap().len() < e as u64 {
                file.set_len(e as u64).unwrap();
            }
            file.seek(SeekFrom::Start(s as u64)).unwrap();
            file.write(&data[data_index..data_index + num_bytes_to_write])
                .unwrap();

            data_index += num_bytes_to_write;
        }
    }

    pub fn data_from_disk<'a>(piece_len: usize, piece_files: PieceFiles<'a>) -> Option<Vec<u8>> {
        let mut buf: Vec<u8> = Vec::with_capacity(piece_len);

        for (i, (filepath, file_len)) in piece_files.path_and_lens.iter().enumerate() {
            let mut file = std::fs::File::open(filepath).ok()?;
            let s = if i == 0 { piece_files.start_offset } else { 0 };
            let e = if i == piece_files.path_and_lens.len() - 1 {
                piece_files.end_offset
            } else {
                *file_len
            };

            if file.metadata().unwrap().len() < e as u64 {
                return None;
            }
            file.seek(SeekFrom::Start(s as u64)).unwrap();
            file.take((e - s) as u64).read_to_end(&mut buf).ok()?;
        }
        Some(buf)
    }

    pub fn piece_status(&self) -> PieceStatus {
        if self.blocks_left != 0 {
            return PieceStatus::InProgress;
        }

        let mut hasher = Sha1::new();
        for block_opt in &self.blocks {
            hasher.input(block_opt.as_ref().unwrap());
        }
        let piece_hash = PieceHash::new(hasher.result().into());
        if piece_hash != self.piece_hash {
            PieceStatus::FailedHashCheck
        } else {
            PieceStatus::Complete
        }
    }

    pub fn next_block(&mut self, piece_index: usize) -> Option<(DataIndex, usize)> {
        // Skip blocks that have been filled-in.
        while let Some(Some(_)) = self.blocks.get(self.next_block) {
            self.next_block += 1;
        }
        if self.next_block >= div_ceil(self.piece_len, BLOCK_LEN) {
            return None;
        }

        let block_offset = self.next_block * BLOCK_LEN;
        self.next_block += 1;
        Some((
            DataIndex::new(piece_index, block_offset),
            std::cmp::min(BLOCK_LEN, self.piece_len - block_offset),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fake_piece_data(piece_len: usize, chunk_size: usize) -> (Piece, Vec<u8>) {
        let mut data = Vec::with_capacity(piece_len);
        for i in (0..piece_len).step_by(chunk_size) {
            let val = (i % std::u8::MAX as usize) as u8;
            data.resize(std::cmp::min(data.len() + chunk_size, piece_len), val);
        }
        assert!(data.len() == piece_len);
        let piece_hash = PieceHash::new(Sha1::digest(&data[..]).into());
        (Piece::new(piece_hash, piece_len), data)
    }

    #[test]
    fn test_piece_failed_hash_check() {
        let chunk_size = 10;
        let piece_len = 2 * BLOCK_LEN + chunk_size;
        let (mut piece, data) = fake_piece_data(piece_len, chunk_size);

        let mut first_block = data[..BLOCK_LEN].to_vec();
        // Change the data, so that piece integrity check fails.
        first_block[0] = first_block[0].wrapping_add(1);
        assert!(piece.insert(0, first_block.into()));
        for (index, chunk) in data.chunks(BLOCK_LEN).enumerate().skip(1) {
            assert_eq!(piece.piece_status(), PieceStatus::InProgress);
            assert!(piece.insert(index * BLOCK_LEN, Bytes::copy_from_slice(chunk)));
        }

        assert_eq!(piece.piece_status(), PieceStatus::FailedHashCheck);
    }

    #[test]
    fn test_piece_from_and_to_disk() {
        let chunk_size = 10;
        let piece_len = 2 * BLOCK_LEN + chunk_size;
        let (mut piece, data) = fake_piece_data(piece_len, chunk_size);

        // Insert blocks into piece.
        for (index, chunk) in data.chunks(BLOCK_LEN).enumerate() {
            assert_eq!(piece.piece_status(), PieceStatus::InProgress);
            assert!(piece.insert(index * BLOCK_LEN, Bytes::copy_from_slice(chunk)));
        }
        assert_eq!(piece.piece_status(), PieceStatus::Complete);

        // Flush piece to disk.
        let temp_dir = tempfile::TempDir::new().unwrap();
        let dir_path = temp_dir.path().to_str().unwrap();
        let start_offset = 10;
        let files: Vec<(PathBuf, usize)> = vec![
            (
                [dir_path, "file1.txt"].iter().collect(),
                start_offset + BLOCK_LEN,
            ),
            ([dir_path, "out", "file2.txt"].iter().collect(), BLOCK_LEN),
            (
                [dir_path, "out", "subfolder", "file3.txt"].iter().collect(),
                chunk_size + 42,
            ),
        ];
        let piece_files = PieceFiles {
            path_and_lens: &files[..],
            start_offset,
            end_offset: chunk_size,
        };
        piece.flush_to_disk(piece_files.clone());

        // Read piece from disk and check if data matches.
        assert_eq!(data, Piece::data_from_disk(piece_len, piece_files).unwrap());
    }
}
