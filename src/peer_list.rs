use std::collections::HashMap;

enum PeerStatus {
    /// Have not attempted to contact this peer.
    Unknown,
    /// Could not connect with this peer last time.
    Bad,
    /// Successfully connected with the peer last time.
    Good,
}

struct PeerList {
    peers_addrs: HashMap<IpPort, PeerStatus>,
}
