use simple_torrent::CmdOptions;
use structopt::StructOpt;

#[tokio::main]
async fn main() {
    pretty_env_logger::init();

    let opts = CmdOptions::from_args();
    if let Err(e) = simple_torrent::run(opts).await {
        log::error!("Err: {}", e);
    }
}

/*


Tomorrow:
  - Cache of done pieces -- easy
  - Kademlia!!!!
  - Unchoke with optimistic unchoke...

Supports:
  - Rarest first piece picking policy
  - Pipelined requests with adaptive queue sizes
  - Uploading, including optimistic unchoking

Maybe:
  - Last piece. Cancel

Will support:
  - Magnet links (using Kademlia DHT)

References:
  - https://fileformats.fandom.com/wiki/Torrent_file
  - https://wiki.theory.org/index.php/BitTorrentSpecification
  - https://en.wikipedia.org/wiki/Torrent_file
  - https://www.bittorrent.org/bittorrentecon.pdf
  - https://luminarys.com/posts/writing-a-bittorrent-client.html
  - https://blog.libtorrent.org/

Not going to do:
  - Test with a swarm
  - Queuing requests _from_ peers.
  - Tracker on a separate thread?
  - Handle multiple pieces at once before making new requests...


Does not support:
  - UDP Tracker protocol
  - Anti snubbing
  - End-game mode
  - Super seeding
*/
