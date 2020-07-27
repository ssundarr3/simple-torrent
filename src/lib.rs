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
pub mod meta;
pub mod peer_conn;
pub mod torrent;
pub mod torrent_msg;
pub mod tracker;
pub mod type_alias;
pub mod util;

use crate::listener::Listener;
use crate::meta::{InfoKind, MetaInfo};
use crate::tracker::Tracker;
use crate::type_alias::*;
use anyhow::Result;
use reqwest::Url;
use std::collections::HashMap;
use structopt::StructOpt;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub enum CmdInput {
    /// The magnet link used to start the torrent.
    MagnetLink {
        info_hash: InfoHash,
        name: String,
        tracker_url_opt: Option<Url>,
    },
    /// Path to the `.torrent` file.
    TorrentPath(std::path::PathBuf),
}

fn parse_cmd_input(input_str: &str) -> Result<CmdInput> {
    let uri_res = reqwest::Url::parse(input_str);
    if let Ok((true, uri)) = uri_res.map(|uri| (uri.scheme() == "magnet", uri)) {
        // TODO: Query pairs may have duplicates. E.g. with many trackers.
        let params: HashMap<_, _> = uri
            .query_pairs()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let urn = params.get("xt").ok_or(anyhow!("xt param not found"))?;
        let name = params.get("dn").cloned().unwrap_or("unknown".into());
        let tracker_url_opt = if let Some(url) = params.get("tr") {
            Some(Url::parse(url)?)
        } else {
            None
        };

        const XT_URN_PREFIX: &str = "urn:btih:";
        if urn.get(..XT_URN_PREFIX.len()) == Some(XT_URN_PREFIX) {
            let mut data = [0u8; InfoHash::LEN];
            hex::decode_to_slice(&urn[XT_URN_PREFIX.len()..], &mut data)?;
            Ok(CmdInput::MagnetLink {
                info_hash: InfoHash::new(data),
                name: name.to_string(),
                tracker_url_opt,
            })
        } else {
            Err(anyhow!("urn `{}` prefix != `{}`", urn, XT_URN_PREFIX))
        }
    } else {
        Ok(CmdInput::TorrentPath(input_str.into()))
    }
}

#[derive(Debug, Clone, StructOpt)]
#[structopt(name = "torrent", about = "A simple Bittorrent client.")]
pub struct CmdOptions {
    /// Path to torrent file or magnet link.
    #[structopt(parse(try_from_str = parse_cmd_input))]
    pub input: CmdInput,

    /// Output directory.
    #[structopt(short, long, parse(from_os_str), default_value = "downloads")]
    pub out_dir: std::path::PathBuf,

    /// Path to cache directory.
    #[structopt(long, default_value = "cache")]
    pub cache_dir: std::path::PathBuf,

    /// Whether or not the cache can be used.
    #[structopt(long)]
    pub no_cache: bool,

    /// Continue seeding after download completes.
    #[structopt(long)]
    pub seed_on_done: bool,

    /// The maximum number of peers to connect to.
    #[structopt(long, default_value = "30")]
    pub max_peers: u32,
}

pub async fn run(opts: CmdOptions) -> Result<()> {
    let (tracker_cache_dir, meta_cache_dir, _dht_cache_dir) = if opts.no_cache {
        (None, None, None)
    } else {
        let mut tracker_dir = opts.cache_dir.clone();
        tracker_dir.push("trackers");

        let mut meta_dir = opts.cache_dir.clone();
        meta_dir.push("meta");

        let mut dht_dir = opts.cache_dir.clone();
        dht_dir.push("dht");

        (Some(tracker_dir), Some(meta_dir), Some(dht_dir))
    };

    // Parse the torrent file.
    let meta = match opts.input {
        CmdInput::MagnetLink {
            info_hash,
            name,
            tracker_url_opt,
        } => {
            let info_kind = InfoKind::Partial {
                info_bytes: vec![],
                downloads_dir: opts.out_dir,
                name,
                info_hash,
            };
            MetaInfo::new(meta_cache_dir, info_kind, tracker_url_opt)
        }
        CmdInput::TorrentPath(filepath) => {
            let bytes = std::fs::read(filepath)?;
            let bencode = bencode::BencodeValue::decode(&bytes)?;
            MetaInfo::from_bencode(&bencode, opts.out_dir, meta_cache_dir)?
        }
    };

    // Listen for new connections.
    let (send_chan, recv_chan) = mpsc::unbounded_channel();
    let mut listener = Listener::new(meta.info_hash, send_chan.clone()).await?;
    let listen_addr = listener.addr()?;
    tokio::spawn(async move { listener.start().await });

    let stats = std::sync::Arc::new(torrent::TorrentStats::new(opts.max_peers));
    let mut tracker = Tracker::new(&meta, listen_addr, stats.clone(), tracker_cache_dir);
    tokio::spawn(async move { tracker.start(send_chan).await });

    let mut torrent = torrent::Torrent::new(stats, meta);
    torrent.start(recv_chan, opts.seed_on_done).await;

    Ok(())
}
