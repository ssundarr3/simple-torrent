use crate::bencode::*;
use crate::chan_msg::ChanMsg;
use crate::meta::MetaInfo;
use crate::torrent::TorrentStats;
use crate::type_alias::PeerId;
use crate::type_alias::*;
use crate::util::{maybe_save_to_cache, read_from_cache, IpPort};
use anyhow::Result;
use bytes::Bytes;
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;
use url::form_urlencoded::byte_serialize;

const PEERS_KEY: &'static [u8] = b"peers";
const INTERVAL_KEY: &'static [u8] = b"interval";

// For tracker response parsing.
const BYTES_FOR_IP: usize = 4;
const BYTES_FOR_PORT: usize = 2;
const BYTES_PER_PEER: usize = BYTES_FOR_IP + BYTES_FOR_PORT;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Cached {
    /// A String to more easily identify the torrent.
    name: String,

    /// The url to query to get the tracker response. String is used so that
    // TODO: Maybe use url?
    announce: Option<String>,

    /// The number of bytes downloaded. This may be more than the size of the torrent
    /// (e.g. when piece is downloaded twice due to failed piece integrity check).
    downloaded: u64,
    /// The number of bytes uploaded.
    uploaded: u64,

    /// Whether or not the `Event::Started` and `Event::Completed` messages have been sent.
    started: bool,
    completed: bool,

    /// The last time a query to the tracker was made.
    last_query_time: SystemTime,

    /// The time to wait in seconds between tracker queries.
    interval: Duration,
    /// A list of peers' address.
    peer_addrs: HashSet<IpPort>,
}

#[derive(Debug, Clone)]
pub struct Tracker {
    /// The path to the cached trackers directory. None indicates not to use a cache.
    cache_dir_opt: Option<PathBuf>,
    /// The address where we listen for incoming connections.
    listen_addr: SocketAddr,
    /// All tracker information that should be cached.
    pub stats: Arc<TorrentStats>,
    pub cached: Cached,
    pub my_peer_id: PeerId,
    pub info_hash: InfoHash,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Sent when a download first begins.
    Started,
    /// Sent when a download first ends.
    Completed,
    /// Sent when the downloading ceases.
    Stopped,
    /// Sent when none of the others apply.
    None,
}

impl Event {
    pub fn into_string(&self) -> String {
        match self {
            Event::Started => "started".to_string(),
            Event::Completed => "completed".to_string(),
            Event::Stopped => "stopped".to_string(),
            Event::None => "empty".to_string(),
        }
    }
}

impl Tracker {
    const DEFAULT_REQUEST_INTERVAL: Duration = Duration::from_secs(600);

    pub fn new(
        meta: &MetaInfo,
        listen_addr: SocketAddr,
        stats: Arc<TorrentStats>,
        cache_dir_opt: Option<PathBuf>,
    ) -> Tracker {
        // TODO: Get announce and stuff here instead of doing `info()`.
        // If `cache_dir_opt` exists and a cached file already exists, get the tracker from there.
        // read_from_cache()
        if let Some(cache_dir) = &cache_dir_opt {
            let cache_path = meta.info_hash.filepath(cache_dir);
            if let Ok(s) = std::fs::read_to_string(cache_path) {
                info!("Getting tracker from cache!");
                let cached: Cached = serde_json::from_str(&s).unwrap();
                stats.set_downloaded(cached.downloaded);
                stats.set_uploaded(cached.uploaded);
                return Tracker {
                    cache_dir_opt: cache_dir_opt,
                    listen_addr: listen_addr,
                    my_peer_id: meta.my_peer_id,
                    info_hash: meta.info_hash,
                    stats,
                    cached,
                };
            }
        }

        // Otherwise, create a new tracker object and cache it.
        let tracker = Tracker {
            cache_dir_opt: cache_dir_opt,
            listen_addr: listen_addr,
            my_peer_id: meta.my_peer_id,
            info_hash: meta.info_hash,
            stats,
            cached: Cached {
                downloaded: 0,
                uploaded: 0,
                started: false,
                completed: false,
                name: meta.info_kind.name().to_string(),
                announce: meta.tracker_url_opt.clone().map(|z| z.as_str().to_string()),
                last_query_time: SystemTime::UNIX_EPOCH,
                interval: Tracker::DEFAULT_REQUEST_INTERVAL,
                peer_addrs: HashSet::new(),
            },
        };
        maybe_save_to_cache(&tracker.cached, tracker.cache_dir_and_name());
        tracker
    }

    pub fn cache_dir_and_name(&self) -> Option<(PathBuf, String)> {
        let cache_dir = self.cache_dir_opt.clone()?;
        Some((cache_dir, self.info_hash.filename()))
    }

    pub fn should_request(&self) -> bool {
        self.cached.last_query_time.elapsed().unwrap() >= self.cached.interval
    }

    async fn make_request_(&mut self, left: u64, event: Event) -> Result<()> {
        // TODO: Avoid manually percent encoding bytes into the query string.
        // TODO: Maybe use `hex::encode`.
        let url = Url::from_str(&format!(
            "{}?info_hash={}",
            /* TODO: Maybe don't unwrap... */
            self.cached.announce.clone().unwrap(),
            byte_serialize(self.info_hash.get()).collect::<String>(),
        ))?;
        let request = Client::new()
            .get(url)
            .query(&[(
                "peer_id",
                std::str::from_utf8(self.my_peer_id.get()).unwrap(),
            )])
            .query(&[("left", left)])
            .query(&[("ip", self.listen_addr.ip())])
            .query(&[("port", self.listen_addr.port())])
            .query(&[("uploaded", self.cached.uploaded)])
            .query(&[("downloaded", self.cached.downloaded)])
            .query(&[("compact", 1)])
            .query(&[("event", event.into_string())]);

        let response = request.send().await?.bytes().await?;
        self.cached.last_query_time = SystemTime::now();
        let (interval, peer_addrs) = Tracker::decode_response(&response)?;
        self.cached.interval = interval;
        self.cached.peer_addrs.extend(&peer_addrs);

        Ok(())
    }

    pub async fn make_request(&mut self, left: u64, event: Event) {
        match self.make_request_(left, event.clone()).await {
            Ok(_) => {
                info!(
                    "Tracker (Event::{:?}) request ok! Found {} peers",
                    event,
                    self.cached.peer_addrs.len()
                );
                maybe_save_to_cache(&self.cached, self.cache_dir_and_name());
            }
            Err(e) => warn!("Tracker (Event::{:?}) err: {}", event, e),
        }
    }

    pub async fn start(&mut self, _send_chan: mpsc::UnboundedSender<ChanMsg>) {
        loop {
            let time_left = self
                .cached
                .interval
                .checked_sub(self.cached.last_query_time.elapsed().unwrap())
                .unwrap_or(Duration::new(0, 0));
            // TODO: Timeout every 10 seconds to check if new peers required...
            tokio::time::delay_for(time_left).await;

            let event = if !self.cached.started {
                self.cached.started = true;
                Event::Started
            } else if self.stats.left() == 0 && !self.cached.completed {
                self.cached.completed = true;
                Event::Completed
            } else {
                Event::None
            };
            self.cached.downloaded = self.stats.downloaded();
            self.cached.uploaded = self.stats.uploaded();
            self.make_request(self.stats.left(), event).await;

            // filter the ones that aren't in the do not contact list...
            // self.cached.peer_addrs.filter()
            // take(self.stats.num_peers_needed())
            for _ in 0..self.stats.num_peers_needed() {
                //
                // start new peer
            }
            maybe_save_to_cache(&self.cached, self.cache_dir_and_name());
            //
            // Make requst with correct Event
            // Add new peer while need_peer

            // self.make_request(left, event)
            // TODO: Do everything done in torrent here...
            // Also remove pub from make_request...
            // Query tracker and add
            // Create NewPeer using _send_chan
        }
    }

    pub fn encode_response(interval: &Duration, addrs: &HashSet<IpPort>) -> Bytes {
        let mut bencode = BencodeDict::new();
        bencode.insert(
            INTERVAL_KEY.into(),
            BencodeValue::Int(interval.as_secs() as i64),
        );

        let mut addr_bytes = Vec::with_capacity(BYTES_PER_PEER * addrs.len());
        for addr in addrs {
            addr_bytes.extend(addr.encode());
        }
        bencode.insert(PEERS_KEY.into(), BencodeValue::Bytes(addr_bytes.into()));

        BencodeValue::Dict(bencode).encode()
    }

    pub fn decode_response(bytes: &[u8]) -> Result<(Duration, HashSet<IpPort>)> {
        info!("tracker response: {:?}", bytes);
        let response_bencode = BencodeValue::decode(bytes)?;
        let dict = response_bencode.get_dict()?;

        let addrs_bytes = dict.val(PEERS_KEY)?.get_bytes()?;
        let mut addrs = HashSet::with_capacity(addrs_bytes.len() / IpPort::LEN);
        for chunk in addrs_bytes.chunks(IpPort::LEN) {
            addrs.insert(IpPort::decode(chunk)?);
        }

        let interval = Duration::from_secs(dict.val(INTERVAL_KEY)?.get_int()? as u64);
        Ok((interval, addrs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn assert_encode_decode(interval_: u64, addrs_: Vec<IpPort>) {
        let interval = Duration::from_secs(interval_);
        let addrs: HashSet<_> = addrs_.into_iter().collect();
        let bytes = Tracker::encode_response(&interval, &addrs);
        assert_eq!((interval, addrs), Tracker::decode_response(&bytes).unwrap());
    }

    #[test]
    fn test_parse_peer_addrs() {
        assert_encode_decode(42, vec![]);
        assert_encode_decode(
            10,
            vec![
                IpPort::new(Ipv4Addr::new(127, 77, 99, 99), 8080),
                IpPort::new(Ipv4Addr::new(100, 77, 58, 99), 2960),
            ],
        );
    }

    // #[tokio::test]
    // async fn test_tracker_request() {
    //     // Setup mock http server.
    //     let interval = Duration::from_secs(42);
    //     let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 77, 58, 99)), 8080);
    //     let response = Tracker::encode_response(&interval, &vec![addr].into_iter().collect());
    //     let _m = mockito::mock("GET", mockito::Matcher::Any)
    //         .with_body(response)
    //         .create();

    //     // Create tracker.
    //     let temp_dir = tempfile::TempDir::new().unwrap();
    //     let cache_dir: PathBuf = temp_dir.path().into();
    //     let name = "file or dir name".to_string();
    //     let info_hash = InfoHash::new([77; InfoHash::LEN]);
    //     let announce = Url::parse(&mockito::server_url()).unwrap();
    //     let listen_addr: SocketAddr =
    //         SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 6881);
    //     let meta = MetaInfo {
    //         info_hash,
    //         tracker_url_opt: Some(announce),
    //         info_opt: None,
    //         my_peer_id: PeerId::new([12; PeerId::LEN]),
    //         cache_dir_opt: None,
    //     };
    //     let mut tracker = Tracker::new(&meta, listen_addr, Some(cache_dir.clone()));

    //     // Make tracker request and check that the tracker has the information from the tracker request.
    //     assert!(tracker.cached.peer_addrs.is_empty());
    //     assert!(tracker.should_request());
    //     assert_eq!(tracker.cached.interval, Tracker::DEFAULT_REQUEST_INTERVAL);
    //     tracker.make_request(43, Event::None).await;
    //     assert_eq!(
    //         tracker.cached.peer_addrs,
    //         HashSet::from_iter(vec![addr].into_iter())
    //     );
    //     assert!(!tracker.should_request());
    //     assert_eq!(tracker.cached.interval, interval);

    //     // Creating a tracker from the cached file should re-create the tracker exactly.
    //     assert_eq!(tracker, Tracker::new(&meta, listen_addr, Some(cache_dir)));
    // }
}
