mod piece;

use crate::bencode::{BencodeDict, BencodeValue, GetFromBencodeDict};
use crate::chan_msg::{ChanMsg, ChanMsgKind};
use crate::handshake::{Handshake, EXTENSION_PROTOCOL};
use crate::meta::{Info, InfoKind, MetaInfo};
use crate::torrent::piece::{Piece, PieceStatus};
use crate::torrent_msg::{DataIndex, ExtendMsgIds, ExtendMsgKind, TorrentMsg};
use crate::type_alias::*;
use crate::util::div_ceil;
use anyhow::Result;
use bitvec::{order::Msb0, vec::BitVec};
use bytes::Bytes;
use sha1::{Digest, Sha1};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};
use tokio::{net::tcp, sync::mpsc, time::timeout};

const ZERO_DURATION: Duration = Duration::from_secs(0);
const TIMEOUT_DURATION: Duration = Duration::from_secs(10);
const DISCONNECT_TIME: Duration = Duration::from_secs(120);
const KEEPALIVE_TIME: Duration = Duration::from_secs(100);
const MAX_DOWNLOADERS: usize = 4;
const METADATA_BLOCK_LEN: usize = 16 * 1024; // 16KB.

#[derive(Debug)]
struct Peer {
    peer_index: usize,
    send_tcp: tcp::OwnedWriteHalf,
    peer_ip: IpAddr,
    /// A bitfield of the pieces that this peer has.
    have: BitVec<Msb0, u8>,
    am_choking: bool,
    am_interested: bool,
    peer_choking: bool,
    peer_interested: bool,
    /// The last time a message was received from this peer.
    last_msg_time: Instant,
    /// The number of queued requests made to this peer.
    cur_queue_len: usize,
    /// The maximum number of requests to queue.
    max_queue_len: usize,
    /// The number of bytes uploaded to this peer.
    upload_rate: u64,
    /// The number of bytes downloaded from this peer since the last `TIMEOUT_DURATION`.
    download_rate: u64,
    /// The number of bytes downloaded from this peer in the last three `TIMEOUT_DURATION`.
    past_download_rates: VecDeque<u64>,
    /// The ids of the extensions the peer supports.
    extend_ids: ExtendMsgIds,
}

impl Peer {
    pub fn new(peer_index: usize, send_tcp: tcp::OwnedWriteHalf, peer_ip: IpAddr) -> Peer {
        const DEFAULT_MAX_QUEUE_LEN: usize = 5;
        Peer {
            peer_index,
            send_tcp,
            peer_ip,
            have: BitVec::new(),
            last_msg_time: Instant::now(),
            am_choking: true,
            am_interested: false,
            peer_choking: true,
            peer_interested: false,
            cur_queue_len: 0,
            max_queue_len: DEFAULT_MAX_QUEUE_LEN,
            upload_rate: 0,
            download_rate: 0,
            past_download_rates: vec![0, 0, 0].into_iter().collect(),
            extend_ids: ExtendMsgIds::new(false, false),
        }
    }

    pub fn set_num_pieces(&mut self, num_pieces: usize) {
        if self.have.is_empty() {
            self.have = BitVec::repeat(false, div_ceil(num_pieces, 8) * 8);
        }
    }

    pub async fn set_am_interested(&mut self, value: bool) -> Result<()> {
        if self.am_interested != value {
            let msg = if value {
                TorrentMsg::Interested
            } else {
                TorrentMsg::NotInterested
            };
            self.send(msg).await?;
            self.am_interested = value;
        }
        Ok(())
    }

    pub async fn send(&mut self, msg: TorrentMsg) -> Result<()> {
        trace!("Sending to peer {}: {}", self.peer_index, msg);
        msg.write(&mut self.send_tcp).await?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct TorrentStats {
    downloaded: AtomicU64,
    uploaded: AtomicU64,
    left: AtomicU64,
    num_peers: AtomicU32,
    max_peers: u32,
    // TODO: Set this in the code...
    do_not_contact: Mutex<HashSet<IpAddr>>,
}

impl TorrentStats {
    pub fn new(max_peers: u32) -> TorrentStats {
        TorrentStats {
            downloaded: AtomicU64::new(0),
            uploaded: AtomicU64::new(0),
            left: AtomicU64::new(0),
            num_peers: AtomicU32::new(0),
            do_not_contact: Mutex::new(HashSet::new()),
            max_peers,
        }
    }

    pub fn set_downloaded(&self, val: u64) {
        self.downloaded.fetch_add(val, Ordering::Relaxed);
    }

    pub fn set_uploaded(&self, val: u64) {
        self.uploaded.fetch_add(val, Ordering::Relaxed);
    }

    pub fn downloaded(&self) -> u64 {
        self.downloaded.load(Ordering::Relaxed)
    }

    pub fn uploaded(&self) -> u64 {
        self.uploaded.load(Ordering::Relaxed)
    }

    pub fn left(&self) -> u64 {
        self.left.load(Ordering::Relaxed)
    }

    pub fn num_peers(&self) -> u32 {
        self.num_peers.load(Ordering::Relaxed)
    }

    pub fn num_peers_needed(&self) -> u32 {
        if self.left() == 0 {
            return 0;
        }
        self.max_peers.saturating_sub(self.num_peers())
    }
}

pub struct Torrent {
    // TODO: Set downloaded and uploaded...
    stats: Arc<TorrentStats>,
    meta: MetaInfo,
    have: BitVec<Msb0, u8>,
    cur_pieces: HashMap<usize, Piece>,
    peers: HashMap<usize, Peer>,
    extend_ids: ExtendMsgIds,
}

impl Torrent {
    fn set_from_info(&mut self) {
        if let InfoKind::Full(info) = &self.meta.info_kind {
            self.have = BitVec::repeat(false, div_ceil(info.num_pieces, 8) * 8);
            self.stats
                .left
                .store(info.data_len as u64, Ordering::Relaxed);
            for piece_index in 0..info.num_pieces {
                let piece_len = info.piece_len(piece_index);
                if let Some(data) = Piece::data_from_disk(piece_len, info.piece_files(piece_index))
                {
                    let piece_hash = PieceHash::new(Sha1::digest(&data).into());
                    if info.piece_hashes[piece_index] == piece_hash {
                        self.have.set(piece_index, true);
                        self.stats
                            .left
                            .fetch_sub(data.len() as u64, Ordering::Relaxed);
                    }
                }
            }

            for peer in self.peers.values_mut() {
                peer.set_num_pieces(info.num_pieces);
            }

            info!(
                "{}/{} pieces were read from disk!",
                self.have.iter().map(|x| *x as u32).sum::<u32>(),
                info.num_pieces
            );
        }
    }

    pub fn new(stats: Arc<TorrentStats>, meta: MetaInfo) -> Torrent {
        let mut torrent = Torrent {
            stats,
            have: BitVec::new(),
            meta,
            cur_pieces: HashMap::new(),
            peers: HashMap::new(),
            extend_ids: ExtendMsgIds::new(true, false),
        };
        torrent.set_from_info();
        torrent
    }

    fn shutdown(&mut self, peer_index: usize) {
        if let Some(peer) = self.peers.remove(&peer_index) {
            // TODO: Tracker update...
            // self.tracker.cached.downloaded += peer.download_rate;
            self.stats.num_peers.fetch_sub(1, Ordering::Relaxed);
            trace!("Shutting down peer {} {}", peer_index, peer.peer_ip);
        }
    }

    /// Returns at most `n` blocks to request, given a peer that has `have` blocks.
    /// Prioritizes blocks in the order:
    ///   1) blocks from pieces that are currently being downloaded, but not already requested.
    ///   2) blocks from pieces not yet started, in order of rarest piece first.
    ///   3) blocks from pieces that are currently being downloaded, and have already been requested.
    fn pick_blocks(&mut self, peer_have: BitVec<Msb0, u8>, n: usize) -> Vec<(DataIndex, usize)> {
        if n == 0 {
            return vec![];
        }
        let mut blocks = Vec::with_capacity(n);
        let info = match &self.meta.info_kind {
            InfoKind::Full(info) => info,
            InfoKind::Partial { .. } => panic!("TODO: Pass info to pick_blocks"),
        };

        // 1) Get next blocks from pieces that are currently being downloaded.
        for (piece_index, piece) in self.cur_pieces.iter_mut() {
            if !peer_have[*piece_index] || piece.deprioritized {
                continue;
            }

            while let Some(block) = piece.next_block(*piece_index) {
                blocks.push(block);
                if blocks.len() == n {
                    return blocks;
                }
            }
            piece.next_block = 0;
            piece.deprioritized = true;
        }

        // 2) Get blocks from new pieces. Prioritize rarest pieces.
        let mut piece_freqs = HashMap::new();
        for peer in self.peers.values() {
            for (piece_index, has) in peer.have.iter().enumerate() {
                if *has && !self.have[piece_index] && !self.cur_pieces.contains_key(&piece_index) {
                    *piece_freqs.entry(piece_index).or_insert(0) += 1;
                }
            }
        }
        let mut piece_freqs_vec: Vec<(u32, usize)> = piece_freqs
            .iter()
            .map(|(piece_index, freq)| (*freq, *piece_index))
            .collect();
        piece_freqs_vec.sort_unstable();
        for (_, piece_index) in piece_freqs_vec {
            let piece_hash = info.piece_hashes[piece_index];
            let piece_len = info.piece_len(piece_index);
            assert!(self
                .cur_pieces
                .insert(piece_index, Piece::new(piece_hash, piece_len))
                .is_none());
            let piece = self.cur_pieces.get_mut(&piece_index).unwrap();
            while let Some(block) = piece.next_block(piece_index) {
                blocks.push(block);
                if blocks.len() == n {
                    return blocks;
                }
            }
            piece.next_block = 0;
            piece.deprioritized = true;
        }

        // 3) Re-request blocks that haven't been received.
        for (piece_index, piece) in self.cur_pieces.iter_mut() {
            if !peer_have[*piece_index] || !piece.deprioritized {
                continue;
            }

            while let Some(block) = piece.next_block(*piece_index) {
                // TODO: O(N) lookup, but this code-path only runs when there are few blocks left...
                if !blocks.contains(&block) {
                    blocks.push(block);
                }
                if blocks.len() == n {
                    return blocks;
                }
            }
            piece.next_block = 0;
        }

        blocks
    }

    fn num_downloaders(&mut self) -> usize {
        self.peers
            .values()
            .map(|peer| !peer.am_choking as usize)
            .sum::<usize>()
    }

    async fn handle_torrent_msg(&mut self, peer_index: usize, msg: TorrentMsg) -> Result<()> {
        let peer = if let Some(peer) = self.peers.get_mut(&peer_index) {
            peer
        } else {
            return Err(anyhow!("peer {} not found. Ignoring `{}`", peer_index, msg));
        };
        peer.last_msg_time = Instant::now();

        let info = match &mut self.meta.info_kind {
            InfoKind::Partial {
                info_bytes,
                downloads_dir,
                info_hash,
                ..
            } => {
                if let TorrentMsg::Extend(extend_msg) = msg {
                    let kind = ExtendMsgKind::from_extend_msg(extend_msg, &peer.extend_ids)?;
                    match kind {
                        ExtendMsgKind::Handshake(ids) => {
                            peer.extend_ids = ids;
                            // Request the first piece of the metadata.
                            let meta_req_kind = ExtendMsgKind::MetadataRequest(0);
                            if let Ok(meta_req) =
                                meta_req_kind.try_into_extend_msg(&peer.extend_ids)
                            {
                                let _ = peer.send(TorrentMsg::Extend(meta_req)).await?;
                            }
                        }
                        ExtendMsgKind::MetadataBlock(piece, total_size, block) => {
                            let start = piece * METADATA_BLOCK_LEN;
                            // The peer could be lying about `total_size` anyways, so there's no use
                            // in checking if `block.len()` is <= `METADATA_BLOCK_LEN`.
                            if info_bytes.len() == start {
                                info_bytes.extend(block)
                            }

                            if info_bytes.len() < total_size {
                                // If not done, request the next piece.
                                let piece_to_req = info_bytes.len() / METADATA_BLOCK_LEN;
                                let meta_req_kind = ExtendMsgKind::MetadataRequest(piece_to_req);
                                if let Ok(meta_req) =
                                    meta_req_kind.try_into_extend_msg(&peer.extend_ids)
                                {
                                    let _ = peer.send(TorrentMsg::Extend(meta_req)).await?;
                                }
                            } else {
                                // Otherwise, construct the meta data.
                                if let Ok(info) =
                                    Info::from_bytes(info_bytes, downloads_dir, info_hash)
                                {
                                    trace!("Successfully acquired meta data: {:?}", info);
                                    self.meta.info_kind = InfoKind::Full(info);
                                    self.meta.maybe_save_to_cache();
                                    self.set_from_info();
                                } else {
                                    // If metadata is not valid, clear existing data and start over.
                                    info_bytes.clear();
                                    let meta_req_kind = ExtendMsgKind::MetadataRequest(0);
                                    if let Ok(meta_req) =
                                        meta_req_kind.try_into_extend_msg(&peer.extend_ids)
                                    {
                                        let _ = peer.send(TorrentMsg::Extend(meta_req)).await?;
                                    }
                                }
                            }
                        }
                        ExtendMsgKind::MetadataRequest(piece) => {
                            // TODO: Respond with Reject message...
                        }
                        ExtendMsgKind::Unknown | ExtendMsgKind::MetadataReject(_) => {}
                    }
                } else {
                    trace!("meta info not present, ignoring msg: {}", msg);
                }
                return Ok(());
            }
            InfoKind::Full(info) => info,
        };

        match msg {
            TorrentMsg::KeepAlive | TorrentMsg::Cancel(_, _) | TorrentMsg::Port(_) => {}
            TorrentMsg::Extend(_) => {
                // TODO: Send reject message if MetadataRequest maybe...
            }
            TorrentMsg::Request(index, block_len) => {
                if !peer.am_choking && index.piece < info.num_pieces && self.have[index.piece] {
                    // TODO: Use a piece cache instead of reading from disk each time.
                    let piece_data = Piece::data_from_disk(
                        info.piece_len(index.piece),
                        info.piece_files(index.piece),
                    )
                    .unwrap();
                    if let Some(block_data) = piece_data.get(index.offset..index.offset + block_len)
                    {
                        peer.send(TorrentMsg::Block(index, Bytes::copy_from_slice(block_data)))
                            .await?;
                        peer.upload_rate += block_len as u64;
                    } else {
                        warn!("Invalid block request: {:?} len={}", index, block_len);
                    }
                }
            }
            TorrentMsg::Interested => peer.peer_interested = true,
            TorrentMsg::NotInterested => peer.peer_interested = false,
            TorrentMsg::Choke => {
                peer.peer_choking = true;
                peer.cur_queue_len = 0;
            }
            TorrentMsg::Unchoke => peer.peer_choking = false,
            TorrentMsg::Have(piece_index) => {
                if piece_index >= info.num_pieces {
                    return Err(anyhow!("have {} is out of range", msg));
                }
                peer.have.set(piece_index, true);
                if !self.have[piece_index] {
                    peer.set_am_interested(true).await?;
                }
            }
            TorrentMsg::Bitfield(have) => {
                if have.len() != peer.have.len() {
                    return Err(anyhow!("bitvec len {} != {}", have.len(), peer.have.len()));
                }
                peer.have |= have;
                if !self.have.clone() && peer.have.clone() {
                    peer.set_am_interested(true).await?;
                }
            }
            TorrentMsg::Block(index, block) => {
                peer.cur_queue_len = peer.cur_queue_len.saturating_sub(1);
                peer.download_rate += block.len() as u64;
                if index.piece < info.num_pieces && !self.have[index.piece] {
                    let piece = self.cur_pieces.get_mut(&index.piece).unwrap();
                    piece.insert(index.offset, block);

                    match piece.piece_status() {
                        PieceStatus::InProgress => {}
                        PieceStatus::FailedHashCheck => {
                            warn!("piece {} failed hash check", index.piece);
                            *piece = Piece::new(piece.piece_hash, piece.piece_len);
                        }
                        PieceStatus::Complete => {
                            info!("Piece {} is complete", index.piece);
                            piece.flush_to_disk(info.piece_files(index.piece));
                            // self.left -= piece.piece_len;
                            // TODO: Set stats.left inistead
                            self.have.set(index.piece, true);
                            self.cur_pieces.remove(&index.piece);

                            let download_complete = self.stats.left() == 0;
                            for peer in self.peers.values_mut() {
                                let _ = peer.send(TorrentMsg::Have(index.piece)).await;
                                if download_complete {
                                    let _ = peer.set_am_interested(false).await;
                                }
                            }
                            if download_complete {
                                info!("Download complete!");
                                // TODO: Tracker...
                                // self.tracker
                                //     .make_request(self.left, tracker::Event::Completed)
                                //     .await;
                            }
                        }
                    }
                } else {
                    trace!("block at `{:?}` not required", index);
                }
            }
        }

        // Maybe submit block requests to this peer.
        let peer = &self.peers[&peer_index];
        if !peer.peer_choking && peer.am_interested && peer.cur_queue_len <= peer.max_queue_len / 2
        {
            let peer_have = peer.have.clone();
            let to_request = peer.max_queue_len - peer.cur_queue_len;
            let requests = self.pick_blocks(peer_have, to_request);

            let peer = self.peers.get_mut(&peer_index).unwrap();
            if requests.is_empty() {
                peer.set_am_interested(false).await?;
            }
            for (index, block_len) in requests {
                peer.send(TorrentMsg::Request(index, block_len)).await?;
                peer.cur_queue_len += 1;
            }
        }

        // Maybe unchoke the peer.
        let peer = &self.peers[&peer_index];
        if peer.am_choking && peer.peer_interested && self.num_downloaders() < MAX_DOWNLOADERS {
            let peer = self.peers.get_mut(&peer_index).unwrap();
            peer.send(TorrentMsg::Unchoke).await?;
            peer.am_choking = false;
        }

        Ok(())
    }

    async fn handle_chan_msg(&mut self, chan_msg: ChanMsg) {
        trace!("Received from {}: {}", chan_msg.peer_index, chan_msg.kind);
        match chan_msg.kind {
            ChanMsgKind::NewPeer(mut send_tcp, peer_ip) => {
                let handshake = Handshake::new(
                    self.meta.info_hash,
                    self.meta.my_peer_id,
                    EXTENSION_PROTOCOL,
                );
                let _ = handshake.write(&mut send_tcp).await;
                let mut peer = Peer::new(chan_msg.peer_index, send_tcp, peer_ip);
                if let InfoKind::Full(info) = &self.meta.info_kind {
                    peer.set_num_pieces(info.num_pieces);
                }
                self.peers.insert(chan_msg.peer_index, peer);
                self.stats.num_peers.fetch_add(1, Ordering::Relaxed);
            }
            ChanMsgKind::Handshake(handshake) => {
                if handshake.protocol != Handshake::PROTOCOL {
                    warn!("bad protocol: {:?}", handshake.protocol);
                    self.shutdown(chan_msg.peer_index);
                    return;
                }
                if handshake.info_hash != self.meta.info_hash {
                    warn!("bad info hash: {:?}", handshake.info_hash);
                    self.shutdown(chan_msg.peer_index);
                    return;
                }

                // If the peer supports the extension protocol, let the peer know of the extensions we support.
                if handshake.flags & EXTENSION_PROTOCOL != 0 {
                    if let Some(peer) = self.peers.get_mut(&chan_msg.peer_index) {
                        let extend_msg = ExtendMsgKind::Handshake(self.extend_ids.clone())
                            .try_into_extend_msg(&self.extend_ids)
                            .unwrap();
                        // Maybe metadata_size needs to be included here?
                        let _ = peer.send(TorrentMsg::Extend(extend_msg)).await;
                    }
                }
            }
            ChanMsgKind::Msg(msg) => {
                if let Err(e) = self.handle_torrent_msg(chan_msg.peer_index, msg).await {
                    warn!("torrent msg err for peer {}: {}", chan_msg.peer_index, e);
                    self.shutdown(chan_msg.peer_index);
                }
            }
            ChanMsgKind::Shutdown => self.shutdown(chan_msg.peer_index),
        }
    }

    async fn handle_timeout(&mut self, _rotate_unchoke: bool) {
        // TODO: This isn't super clean...
        let info = match &mut self.meta.info_kind {
            InfoKind::Partial { .. } => {
                return;
            }
            InfoKind::Full(info) => info,
        };

        // TODO: Get info into a separate variable.
        // Update the state for the tracker and for each peer.
        let mut down_speed = 0.0;
        let mut up_speed = 0.0;
        let mut to_shutdown = vec![];
        for peer in self.peers.values_mut() {
            // TODO: TorrentStats update...
            self.stats
                .downloaded
                .fetch_add(peer.download_rate, Ordering::Relaxed);
            self.stats
                .downloaded
                .fetch_add(peer.upload_rate, Ordering::Relaxed);
            // self.tracker.cached.downloaded += peer.download_rate;
            // self.tracker.cached.uploaded += peer.upload_rate;

            peer.past_download_rates.push_back(peer.download_rate);
            peer.past_download_rates.pop_front();

            // Update the number of requests to queue for this peer.
            let kb_per_sec =
                (peer.download_rate as f64 / 1024.0) / (TIMEOUT_DURATION.as_secs() as f64);
            down_speed += kb_per_sec;
            up_speed += (peer.upload_rate as f64 / 1024.0) / (TIMEOUT_DURATION.as_secs() as f64);

            peer.download_rate = 0;
            peer.upload_rate = 0;
            // Magic numbers copied from rtorrent.
            let new_queue_len = if kb_per_sec < 20.0 {
                kb_per_sec + 2.0
            } else {
                18.0 + (kb_per_sec / 5.0)
            } as usize;
            trace!(
                "Updating peer {}'s queue len from {} to {}",
                peer.peer_index,
                peer.max_queue_len,
                new_queue_len
            );
            peer.max_queue_len = new_queue_len;

            // Disconnect (or keep alive) unused connections.
            if peer.am_interested && peer.last_msg_time.elapsed() > KEEPALIVE_TIME {
                let _ = peer.send(TorrentMsg::KeepAlive).await;
            }
            if !peer.am_interested && peer.last_msg_time.elapsed() > DISCONNECT_TIME {
                to_shutdown.push(peer.peer_index);
            }
        }
        let percent_complete =
            100.0 * ((info.data_len - self.stats.left() as usize) as f64 / info.data_len as f64);
        info!(
            "Download speed = {:.2} KB/s. Upload down_speed: {:.2} KB/s. {:.2} % complete",
            down_speed, up_speed, percent_complete
        );
        for peer_index in to_shutdown {
            self.shutdown(peer_index);
        }

        // TODO: Unchoke peers.
        // TODO: Rotate the optimistically unchoked peer.
        // if _rotate_unchoke {}

        // Maybe make tracker request and add new peers from tracker request.
        // TODO: Tracker update...
        // if self.tracker.should_request() {
        //     self.tracker
        //         .make_request(self.left, tracker::Event::None)
        //         .await;
        // }
        // // Cache tracker information regardless, as bytes downloaded, uploaded were updated.
        // self.tracker.maybe_save_to_cache();

        // if self.left != 0 {
        //     // Connect to at-most `self.max_peers` peers.
        //     let to_connect_addrs: Vec<SocketAddr> = self
        //         .tracker
        //         .cached
        //         .peer_addrs
        //         .iter()
        //         .filter(|addr| !self.do_not_contact.contains(&addr.ip()))
        //         .map(|addr| (*addr).clone())
        //         .take(self.max_peers - self.peers.len())
        //         .collect();
        //     for peer_addr in to_connect_addrs {
        //         self.do_not_contact.insert(peer_addr.ip());
        //         let send_chan = self.send_chan.clone();
        //         let info_hash = self.meta.info_hash;
        //         tokio::spawn(async move {
        //             if let Ok(socket) = TcpStream::connect(peer_addr).await {
        //                 PeerConn::start(socket, send_chan, info_hash).await
        //             }
        //         });
        // }
        // }
    }

    pub async fn start(
        &mut self,
        mut recv_chan: mpsc::UnboundedReceiver<ChanMsg>,
        seed_on_done: bool,
    ) {
        info!("Starting torrent!");
        // self.tracker
        //     .make_request(self.left, tracker::Event::None)
        //     .await;

        let mut timeout_counter: u64 = 0;
        let mut last_timeout = SystemTime::UNIX_EPOCH;
        const UNCHOKE_PERIOD: u64 = 3;
        while seed_on_done || self.stats.left() > 0 {
            // TODO: `try_recv` might be simpler...
            let chan_msg_fut = recv_chan.recv();
            let duration_left = TIMEOUT_DURATION
                .checked_sub(last_timeout.elapsed().unwrap())
                .unwrap_or(ZERO_DURATION);
            match timeout(duration_left, chan_msg_fut).await {
                Err(_) => {
                    let rotate_unchoke = timeout_counter % UNCHOKE_PERIOD == 0;
                    self.handle_timeout(rotate_unchoke).await;
                    last_timeout = SystemTime::now();
                    timeout_counter += 1;
                }
                Ok(Some(chan_msg)) => self.handle_chan_msg(chan_msg).await,
                Ok(None) => break,
            }
        }

        info!("Stopping torrent...");
        // self.tracker
        //     .make_request(self.left, tracker::Event::Stopped)
        //     .await;
    }
}
