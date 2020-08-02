use crate::type_alias::{InfoHash, INFO_HASH_LEN};
use anyhow::Result;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct MagnetLinkInfo {
    info_hash: InfoHash,
    name: String,
    tracker_url_opt: Option<reqwest::Url>,
}

impl MagnetLinkInfo {
    pub fn is_magnet_uri(input_str: &str) -> Option<reqwest::Url> {
        reqwest::Url::parse(input_str)
            .ok()
            .filter(|uri| uri.scheme() == "magnet")
    }

    pub fn from_uri(uri: reqwest::Url) -> Result<MagnetLinkInfo> {
        // TODO: Query pairs may have duplicates. E.g. with many trackers.
        let params: HashMap<_, _> = uri
            .query_pairs()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let urn = params.get("xt").ok_or(anyhow!("xt param not found"))?;
        let name = params.get("dn").cloned().unwrap_or("unknown".to_string());
        let tracker_url_opt = if let Some(url) = params.get("tr") {
            Some(reqwest::Url::parse(url)?)
        } else {
            None
        };

        const XT_URN_PREFIX: &str = "urn:btih:";
        if urn.get(..XT_URN_PREFIX.len()) == Some(XT_URN_PREFIX) {
            let mut data = [0u8; INFO_HASH_LEN];
            hex::decode_to_slice(&urn[XT_URN_PREFIX.len()..], &mut data)?;
            Ok(MagnetLinkInfo {
                info_hash: data,
                name: name.to_string(),
                tracker_url_opt,
            })
        } else {
            Err(anyhow!("urn `{}` prefix != `{}`", urn, XT_URN_PREFIX))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_not_magnet_link() {
        const NOT_MAGNET_URI: &str = "https://en.wikipedia.org/wiki/Magnet_URI_scheme";
        assert!(MagnetLinkInfo::is_magnet_uri(NOT_MAGNET_URI).is_none());
    }

    #[test]
    fn test_magnet_link() {
        const TEST_URI: &str = "magnet:?xt=urn:btih:c12fe1c06bba254a9dc9f519b335aa7c1367a88a";
        let uri = MagnetLinkInfo::is_magnet_uri(TEST_URI).unwrap();
        let _magnet_info = MagnetLinkInfo::from_uri(uri).unwrap();
    }
}
