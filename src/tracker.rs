use crate::bencode::*;
use crate::type_alias::PeerId;
use crate::type_alias::*;
use anyhow::Result;
use bytes::Bytes;
use rand::distributions::Uniform;
use rand::{thread_rng, Rng};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::convert::TryInto;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{Duration, SystemTime};
use url::form_urlencoded::byte_serialize;

const PEERS_KEY: &'static [u8] = b"peers";
const INTERVAL_KEY: &'static [u8] = b"interval";

// For tracker response parsing.
const BYTES_FOR_IP: usize = 4;
const BYTES_FOR_PORT: usize = 2;
const BYTES_PER_PEER: usize = BYTES_FOR_IP + BYTES_FOR_PORT;

fn empty_socket_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tracker {
    /// The path to the cached trackers directory. None indicates not to use a cache.
    #[serde(skip)]
    cache_dir_opt: Option<PathBuf>,
    /// The address where we listen for incoming connections.
    #[serde(skip, default = "empty_socket_addr")]
    listen_addr: SocketAddr,

    /// A String to more easily identify the torrent.
    name: String,

    /// The url to query to get the tracker response.
    announce: String,
    info_hash: InfoHash,
    pub my_peer_id: PeerId,

    /// The number of bytes downloaded. This may be more than the size of the torrent
    /// (e.g. when piece is downloaded twice due to failed piece integrity check).
    pub downloaded: u64,
    /// The number of bytes uploaded.
    pub uploaded: u64,

    /// The last time a query to the tracker was made.
    last_query_time: SystemTime,

    /// The time to wait in seconds between tracker queries.
    interval: Duration,
    /// A list of peers' address.
    pub peer_addrs: HashSet<SocketAddr>,
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

// TODO: Place in PeerId.
pub fn gen_peer_id() -> PeerId {
    const PREFIX: &[u8] = "-AZ2060-".as_bytes();
    let distribution = Uniform::new(0, 10);
    let mut rng = thread_rng();

    let mut peer_id = [0; PeerId::LEN];
    peer_id[..PREFIX.len()].copy_from_slice(PREFIX);
    for i in PREFIX.len()..PeerId::LEN {
        peer_id[i] = b'0' + rng.sample(distribution);
    }
    PeerId::new(peer_id)
}

impl Tracker {
    const DEFAULT_REQUEST_INTERVAL: Duration = Duration::from_secs(600);

    pub fn new(
        name: &str,
        info_hash: &InfoHash,
        announce: &Url,
        listen_addr: SocketAddr,
        cache_dir_opt: Option<PathBuf>,
    ) -> Tracker {
        // If `cache_dir_opt` exists and a cached file already exists, get the tracker from there.
        if let Some(cache_dir) = &cache_dir_opt {
            let cache_path = Tracker::cache_path(info_hash, &cache_dir);
            if let Ok(s) = std::fs::read_to_string(cache_path) {
                info!("Got tracker from cache!");
                let mut tracker: Tracker = serde_json::from_str(&s).unwrap();
                tracker.cache_dir_opt = cache_dir_opt;
                tracker.listen_addr = listen_addr;
                tracker.name = name.to_string();
                return tracker;
            }
        }

        // Otherwise, create a new tracker object and cache it.
        let tracker = Tracker {
            cache_dir_opt,
            listen_addr,
            downloaded: 0,
            uploaded: 0,
            name: name.to_string(),
            announce: announce.as_str().to_string(),
            info_hash: info_hash.clone(),
            my_peer_id: gen_peer_id(),
            last_query_time: SystemTime::UNIX_EPOCH,
            interval: Tracker::DEFAULT_REQUEST_INTERVAL,
            peer_addrs: HashSet::new(),
        };

        tracker.maybe_save_to_cache();
        tracker
    }

    fn cache_path(info_hash: &InfoHash, cache_dir: &PathBuf) -> PathBuf {
        let byte_strings: Vec<String> = info_hash.iter().map(|byte| byte.to_string()).collect();
        let cache_path: PathBuf = [cache_dir, &byte_strings.join("_").into()].iter().collect();
        cache_path
    }

    pub fn maybe_save_to_cache(&self) {
        if let Some(cache_dir) = &self.cache_dir_opt {
            std::fs::create_dir_all(cache_dir).unwrap();
            let cache_path = Tracker::cache_path(&self.info_hash, cache_dir);
            std::fs::write(cache_path, serde_json::to_string_pretty(&self).unwrap()).unwrap();
        }
    }

    pub fn should_request(&self) -> bool {
        self.last_query_time.elapsed().unwrap() >= self.interval
    }

    async fn make_request_(&mut self, left: usize, event: Event) -> Result<()> {
        // TODO: Avoid manually percent encoding bytes into the query string.
        let url = Url::from_str(&format!(
            "{}?info_hash={}",
            self.announce,
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
            .query(&[("uploaded", self.uploaded)])
            .query(&[("downloaded", self.downloaded)])
            .query(&[("compact", 1)])
            .query(&[("event", event.into_string())]);

        let response = request.send().await?.bytes().await?;
        self.last_query_time = SystemTime::now();
        let (interval, peer_addrs) = Tracker::decode_response(&response)?;
        self.interval = interval;
        self.peer_addrs.extend(&peer_addrs);

        Ok(())
    }

    pub async fn make_request(&mut self, left: usize, event: Event) {
        match self.make_request_(left, event.clone()).await {
            Ok(_) => {
                info!(
                    "Tracker (Event::{:?}) request ok! Found {} peers",
                    event,
                    self.peer_addrs.len()
                );
                self.maybe_save_to_cache();
            }
            Err(e) => warn!("Tracker (Event::{:?}) err: {}", event, e),
        }
    }

    pub fn encode_response(interval: &Duration, addrs: &HashSet<SocketAddr>) -> Bytes {
        let mut bencode = BencodeDict::new();
        bencode.insert(
            INTERVAL_KEY.into(),
            BencodeValue::Int(interval.as_secs() as i64),
        );

        let mut addr_bytes = Vec::with_capacity(BYTES_PER_PEER * addrs.len());
        for addr in addrs {
            if let IpAddr::V4(ipv4_addr) = addr.ip() {
                addr_bytes.extend(ipv4_addr.octets().to_vec());
                addr_bytes.extend(&u16::to_be_bytes(addr.port()));
            } else {
                panic!("can only encode IpAddr::V4");
            }
        }
        bencode.insert(PEERS_KEY.into(), BencodeValue::Bytes(addr_bytes.into()));

        BencodeValue::Dict(bencode).encode()
    }

    pub fn decode_response(bytes: &[u8]) -> Result<(Duration, HashSet<SocketAddr>)> {
        info!("tracker response: {:?}", bytes);
        let response_bencode = BencodeValue::decode(bytes)?;
        let dict = response_bencode.get_dict()?;

        let addrs_bytes = dict.val(PEERS_KEY)?.get_bytes()?;
        if addrs_bytes.len() % BYTES_PER_PEER != 0 {
            return Err(anyhow!("Invalid peer address size `{}`", addrs_bytes.len()));
        }
        let mut addrs = HashSet::with_capacity(addrs_bytes.len() / BYTES_PER_PEER);
        for chunk in addrs_bytes.chunks_exact(BYTES_PER_PEER) {
            let ip_bytes: [u8; 4] = chunk[..BYTES_FOR_IP].try_into()?;
            addrs.insert(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(ip_bytes)),
                u16::from_be_bytes(chunk[BYTES_FOR_IP..].try_into()?),
            ));
        }

        let interval = Duration::from_secs(dict.val(INTERVAL_KEY)?.get_int()? as u64);
        Ok((interval, addrs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::iter::FromIterator;

    fn assert_encode_decode(interval_: u64, addrs_: Vec<(Ipv4Addr, u16)>) {
        let interval = Duration::from_secs(interval_);
        let addrs: HashSet<SocketAddr> = addrs_
            .iter()
            .map(|(ip, port)| SocketAddr::new(IpAddr::V4(*ip), *port))
            .collect();
        let bytes = Tracker::encode_response(&interval, &addrs);
        assert_eq!((interval, addrs), Tracker::decode_response(&bytes).unwrap());
    }

    #[test]
    fn test_parse_peer_addrs() {
        assert_encode_decode(42, vec![]);
        assert_encode_decode(
            10,
            vec![
                (Ipv4Addr::new(127, 77, 99, 99), 8080),
                (Ipv4Addr::new(100, 77, 58, 99), 2960),
            ],
        );
    }

    #[tokio::test]
    async fn test_tracker_request() {
        // Setup mock http server.
        let interval = Duration::from_secs(42);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 77, 58, 99)), 8080);
        let response = Tracker::encode_response(&interval, &vec![addr].into_iter().collect());
        let _m = mockito::mock("GET", mockito::Matcher::Any)
            .with_body(response)
            .create();

        // Create tracker.
        let temp_dir = tempfile::TempDir::new().unwrap();
        let cache_dir: PathBuf = temp_dir.path().into();
        let name = "file or dir name".to_string();
        let info_hash = InfoHash::new([77; InfoHash::LEN]);
        let announce = Url::parse(&mockito::server_url()).unwrap();
        let listen_addr: SocketAddr =
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 6881);
        let mut tracker = Tracker::new(
            &name,
            &info_hash,
            &announce,
            listen_addr,
            Some(cache_dir.clone()),
        );

        // Make tracker request and check that the tracker has the information from the tracker request.
        assert!(tracker.peer_addrs.is_empty());
        assert!(tracker.should_request());
        assert_eq!(tracker.interval, Tracker::DEFAULT_REQUEST_INTERVAL);
        tracker.make_request(43, Event::None).await;
        assert_eq!(
            tracker.peer_addrs,
            HashSet::from_iter(vec![addr].into_iter())
        );
        assert!(!tracker.should_request());
        assert_eq!(tracker.interval, interval);

        // Creating a tracker from the cached file should re-create the tracker exactly.
        assert_eq!(
            tracker,
            Tracker::new(&name, &info_hash, &announce, listen_addr, Some(cache_dir))
        );
    }
}
