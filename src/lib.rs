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
pub mod meta_info;
pub mod peer_conn;
pub mod torrent;
pub mod torrent_msg;
pub mod tracker;
pub mod type_alias;
pub mod util;

use crate::listener::Listener;
use crate::meta_info::MetaInfo;
use crate::tracker::Tracker;
use anyhow::Result;
use structopt::StructOpt;
use tokio::sync::mpsc;

#[derive(Debug, Clone, StructOpt)]
#[structopt(name = "torrent", about = "A simple Bittorrent client.")]
pub struct CmdOptions {
    /// Path to torrent file.
    #[structopt(parse(from_os_str))]
    pub torrent_path: std::path::PathBuf,

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

    /// Run in dry mode. Will do everything except start the download.
    #[structopt(long)]
    pub dry_run: bool,
}

pub async fn run(opts: CmdOptions) -> Result<()> {
    let cache_dir = if opts.no_cache {
        None
    } else {
        Some(opts.cache_dir)
    };

    // Parse the torrent file.
    let bytes = std::fs::read(opts.torrent_path)?;
    let bencode = bencode::BencodeValue::decode(&bytes)?;
    let meta_info = MetaInfo::from_bencode(&bencode, opts.out_dir)?;

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

    if !opts.dry_run {
        torrent.start(recv_chan, opts.seed_on_done).await;
    }

    Ok(())
}
