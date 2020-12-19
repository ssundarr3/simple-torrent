// use crate::chan_msg::ChanMsg;
// use crate::peer_conn::PeerConn;
use crate::type_alias::*;
use std::net::SocketAddr;
use std::net::{TcpListener, TcpStream};
// use tokio::sync::mpsc;

pub struct Listener {
    listener: TcpListener,
    info_hash: InfoHash,
}

impl Listener {
    pub fn new(info_hash: InfoHash) -> std::io::Result<Listener> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        Ok(Listener {
            listener,
            info_hash: info_hash,
        })
    }

    pub fn addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn accept_conns(&mut self) -> Vec<TcpStream> {
        let mut streams = vec![];
        while let Ok((stream, _addr)) = self.listener.accept() {
            streams.push(stream);
        }
        return streams;
    }

    pub fn start(&mut self) {
        todo!("Listen for connections");
        // let mut incoming = self.listener.incoming();
        // while let Some(socket_res) = incoming.next() {
        //     match socket_res {
        //         Ok(socket) => {
        //             info!("Incoming peer {}", socket.peer_addr().unwrap());
        //             // let send_chan = self.send_chan.clone();
        //             let info_hash = self.info_hash;
        //             // tokio::spawn(async move { PeerConn::start(socket, send_chan, info_hash) });
        //         }
        //         Err(e) => warn!("{}", e),
        //     }
        // }
    }
}
