use crate::chan_msg::ChanMsg;
use crate::peer_conn::PeerConn;
use crate::type_alias::*;
use std::net::SocketAddr;
use tokio::stream::StreamExt;
use tokio::{net::TcpListener, sync::mpsc};

pub struct Listener {
    listener: TcpListener,
    info_hash: InfoHash,
    send_chan: mpsc::UnboundedSender<ChanMsg>,
}

impl Listener {
    pub async fn new(
        info_hash: InfoHash,
        send_chan: mpsc::UnboundedSender<ChanMsg>,
    ) -> tokio::io::Result<Listener> {
        Ok(Listener {
            listener: TcpListener::bind("127.0.0.1:0").await?,
            info_hash: info_hash,
            send_chan,
        })
    }

    pub fn addr(&self) -> tokio::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn start(&mut self) {
        let mut incoming = self.listener.incoming();
        while let Some(socket_res) = incoming.next().await {
            match socket_res {
                Ok(socket) => {
                    info!("Incoming peer {}", socket.peer_addr().unwrap());
                    let send_chan = self.send_chan.clone();
                    let info_hash = self.info_hash;
                    tokio::spawn(
                        async move { PeerConn::start(socket, send_chan, info_hash).await },
                    );
                }
                Err(e) => warn!("{}", e),
            }
        }
    }
}
