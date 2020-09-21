#[macro_use]
extern crate log;
#[macro_use]
extern crate anyhow;
#[macro_use]
extern crate lazy_static;

pub mod bencode;
pub mod chan_msg;
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
use structopt::StructOpt;
use tokio::sync::mpsc;

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

pub async fn run(opts: CmdOptions) -> Result<()> {
    let cache_dir = if opts.no_cache {
        None
    } else {
        Some(opts.cache_dir)
    };

    /*
    TODO:
        // Create the listener.
        // Create the dht.

        // A list of peer connections.
        // let mut peer_conns = vec![];

        // Create the tracker (needs announce url).

        // loop {
        //     // Get new peer connections.

        //     // See if it's time for a timeout.

        //     // Check dht messages.

        //     // Check torrent messages.

        //     // Reply to torrent messages.
        // }

        // Handle SIGINT and cache before quitting.
        // Maybe create a cached list of good peers and bad peers.
    */

    let meta_info = match opts.cmd_input {
        CmdInput::MagnetLink { .. } => {
            // TODO:
            // Query dht for peers with this info hash.
            // Hopefully we get to connect with some peers either from dht or from cached tracker responses.
            // Send torrent handshake messages to these peers to connect.
            // Ask nicely for meta info file.
            // Construct meta info file and return back. Maintain connections with peers.
            todo!("Magnet link not yet supported");
        }
        CmdInput::TorrentFile(filepath) => {
            let bytes = std::fs::read(filepath)?;
            let bencode = bencode::BencodeValue::decode(&bytes)?;
            MetaInfo::from_bencode(&bencode, opts.out_dir)?
        }
    };

    // Listen for new connections.
    let (send_chan, recv_chan) = mpsc::unbounded_channel();
    let mut listener = Listener::new(meta_info.info_hash, send_chan.clone()).await?;
    let listen_addr = listener.addr()?;
    tokio::spawn(async move { listener.start().await });

    let tracker = Tracker::new(
        &meta_info.name,
        &meta_info.info_hash,
        &meta_info.announce,
        listen_addr,
        cache_dir,
    );
    let mut torrent = torrent::Torrent::new(opts.max_peers, send_chan, tracker, meta_info);

    torrent.start(recv_chan, opts.seed_on_done).await;

    Ok(())
}
