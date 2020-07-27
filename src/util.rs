use anyhow::Result;
use bytes::{Bytes, BytesMut};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::convert::TryInto;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

/// Returns `ceil(a / b)`.
///
/// ## Examples
/// ```
/// assert_eq!(simple_torrent::util::div_ceil(10, 1), 10);
/// assert_eq!(simple_torrent::util::div_ceil(10, 3), 4);
/// assert_eq!(simple_torrent::util::div_ceil(10, 9), 2);
/// assert_eq!(simple_torrent::util::div_ceil(10, 10), 1);
/// assert_eq!(simple_torrent::util::div_ceil(10, 11), 1);
/// ```
///
/// ## Panics
/// ```should_panic
/// simple_torrent::util::div_ceil(10, 0); // Panics
/// ```
#[inline]
pub fn div_ceil(a: usize, b: usize) -> usize {
    (a + b - 1) / b
}

// TODO: Take dir and info_hash instead.

pub fn maybe_save_to_cache<T>(t: &T, dir_and_name: Option<(PathBuf, String)>)
where
    T: Sized + Serialize,
{
    if let Some((mut path, name)) = dir_and_name {
        std::fs::create_dir_all(path.clone()).unwrap();
        path.push(name);
        std::fs::write(path, serde_json::to_string_pretty(&t).unwrap()).unwrap();
    }
}

pub fn read_from_cache<T>(dir_and_name: Option<(PathBuf, String)>) -> Option<T>
where
    T: Sized + DeserializeOwned,
{
    let (mut path, name) = dir_and_name?;
    path.push(name);

    let json = std::fs::read_to_string(path).ok()?;
    let cached: T = serde_json::from_str(&json).unwrap();
    Some(cached)
}

// An IpV4 address and port.
#[derive(Debug, Hash, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct IpPort {
    ip: Ipv4Addr,
    port: u16,
}

impl IpPort {
    const IP_LEN: usize = 4;
    const PORT_LEN: usize = 2;
    pub const LEN: usize = IpPort::IP_LEN + IpPort::PORT_LEN;

    pub fn new(ip: Ipv4Addr, port: u16) -> IpPort {
        IpPort { ip, port }
    }

    pub fn addr(&self) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(self.ip), self.port)
    }

    pub fn decode(bytes: &[u8]) -> Result<IpPort> {
        if bytes.len() != IpPort::LEN {
            return Err(anyhow!("expected {} bytes, got {:?}", IpPort::LEN, bytes));
        }

        let ip_bytes: [u8; 4] = bytes[..IpPort::IP_LEN].try_into()?;
        Ok(IpPort::new(
            Ipv4Addr::from(ip_bytes),
            u16::from_be_bytes(bytes[IpPort::IP_LEN..].try_into()?),
        ))
    }

    pub fn encode(&self) -> Bytes {
        let mut bytes = BytesMut::new();
        bytes.extend(self.ip.octets().to_vec());
        bytes.extend(&self.port.to_be_bytes());
        bytes.freeze()
    }
}
