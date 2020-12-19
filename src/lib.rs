#[macro_use]
extern crate log;
#[macro_use]
extern crate anyhow;
#[macro_use]
extern crate lazy_static;

pub mod bencode;
pub mod chan_msg;
pub mod dht;
pub mod handshake;
pub mod listener;
pub mod magnet_link;
pub mod meta_info;
pub mod peer_conn;
pub mod torrent;
pub mod torrent_msg;
pub mod tracker;
pub mod type_alias;
pub mod util;

use crate::listener::Listener;
use crate::magnet_link::MagnetLinkInfo;
use crate::meta_info::MetaInfo;
use crate::tracker::Tracker;
use anyhow::Result;
use std::collections::HashMap;
use std::net::TcpStream;
use structopt::StructOpt;

#[derive(Debug, Clone, StructOpt)]
#[structopt(name = "torrent", about = "A simple Bittorrent client.")]
pub struct CmdOptions {
    /// Path to torrent file.
    #[structopt(parse(try_from_str = parse_cmd_input))]
    pub cmd_input: CmdInput,

    /// Output directory.
    #[structopt(short, long, parse(from_os_str), default_value = "downloads")]
    pub out_dir: std::path::PathBuf,

    /// Path to cache directory.
    #[structopt(long, default_value = "cache")]
    pub cache_dir: std::path::PathBuf,

    /// Whether or not the cache can be used.
    #[structopt(long)]
    pub no_cache: bool,

    /// Shut down the program once the download completes.
    #[structopt(long)]
    pub seed_on_done: bool,

    /// The maximum number of peers to connect to.
    #[structopt(long, default_value = "50")]
    pub max_peers: usize,
}

/// The input to the program is either a magnet link or a path to a torrent file.
#[derive(Debug, Clone)]
pub enum CmdInput {
    MagnetLink(MagnetLinkInfo),
    TorrentFile(std::path::PathBuf),
}

fn parse_cmd_input(input_str: &str) -> Result<CmdInput> {
    if let Some(uri) = MagnetLinkInfo::is_magnet_uri(input_str) {
        Ok(CmdInput::MagnetLink(MagnetLinkInfo::from_uri(uri)?))
    } else {
        Ok(CmdInput::TorrentFile(input_str.into()))
    }
}

pub fn run(opts: CmdOptions) -> Result<()> {
    let cache_dir = if opts.no_cache {
        None
    } else {
        Some(opts.cache_dir)
    };

    let meta_info = match opts.cmd_input {
        CmdInput::MagnetLink { .. } => {
            todo!("Magnet link not yet supported");
        }
        CmdInput::TorrentFile(filepath) => {
            let bytes = std::fs::read(filepath)?;
            let bencode = bencode::BencodeValue::decode(&bytes)?;
            MetaInfo::from_bencode(&bencode, opts.out_dir)?
        }
    };

    // Listen for new connections.
    // let (send_chan, recv_chan) = mpsc::unbounded_channel();
    let mut listener = Listener::new(meta_info.info_hash)?;
    let listen_addr = listener.addr()?;

    let mut peers: HashMap<usize, TcpStream> = HashMap::new();

    // info!("Starting torrent!");
    // self.tracker.make_request(self.left, tracker::Event::None);

    // Data being cached:
    // Peer Id
    // Peers (and whether we successfully connected or not...)
    // Tracker:
    // downloaded and uploaded information.
    // last query time
    //
    // Dht Routing Table

    // let mut timeout_counter: u64 = 0;
    // let mut last_timeout = SystemTime::UNIX_EPOCH;
    // const UNCHOKE_PERIOD: u64 = 3;
    // todo!("lol do this");
    // // while seed_on_done || self.left > 0 {
    // //     // TODO: `try_recv` might be simpler...
    // //     let chan_msg_fut = recv_chan.recv();
    // //     let duration_left = TIMEOUT_DURATION
    // //         .checked_sub(last_timeout.elapsed().unwrap())
    // //         .unwrap_or(ZERO_DURATION);
    // //     // match timeout(duration_left, chan_msg_fut) {
    // //     //     Err(_) => {
    // //     //         let rotate_unchoke = timeout_counter % UNCHOKE_PERIOD == 0;
    // //     //         self.handle_timeout(rotate_unchoke);
    // //     //         last_timeout = SystemTime::now();
    // //     //         timeout_counter += 1;
    // //     //     }
    // //     //     Ok(Some(chan_msg)) => self.handle_chan_msg(chan_msg),
    // //     //     Ok(None) => break,
    // //     // }
    // // }

    // info!("Stopping torrent...");
    // self.tracker
    //     .make_request(self.left, tracker::Event::Stopped);
    // tokio::spawn(async move { listener.start() });

    let tracker = Tracker::new(
        &meta_info.name,
        &meta_info.info_hash,
        &meta_info.announce,
        listen_addr,
        cache_dir,
    );
    let mut torrent = torrent::Torrent::new(opts.max_peers, tracker, meta_info);

    while opts.seed_on_done || !torrent.is_done() {
        // Get new peers from listener.
        let peer_streams = listener.accept_conns();

        // Check dht for messages.

        // Get and process messages from peers.
        // for message in peer_list.get_messages() {
        //     //
        // }

        // Request pieces from peers.

        // Query tracker if timeout.

        // Switch the optimistically unchoked peers if third timeout.
    }

    /*
    // Handle SIGINT and cache before quitting.
    // Maybe create a cached list of good peers and bad peers.
     */

    torrent.start(opts.seed_on_done);

    Ok(())
}
