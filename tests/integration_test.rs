// mod common;

// use common::{fake_data::*, fake_peer::*};
// use mockito;
// use reqwest::Url;
// use sha1::{Digest, Sha1};
// use simple_torrent::meta::MetaInfo;
// use simple_torrent::tracker::Tracker;
// use simple_torrent::type_alias::*;
// use std::io::prelude::*;
// use std::path::PathBuf;
// use std::sync::Arc;
// use std::time::Duration;

// fn fake_meta(data: &FakeData, tracker_url: Url) -> MetaInfo {
//     let piece_len = 2usize.pow(16); // 64KB.
//     let piece_hashes: Vec<PieceHash> = data
//         .bytes
//         .chunks(piece_len)
//         .map(|piece| PieceHash::new(Sha1::digest(piece).into()))
//         .collect();
//     let meta = MetaInfo::new(
//         data.name.clone(),
//         piece_len,
//         data.files.clone(),
//         piece_hashes,
//         tracker_url,
//     );

//     // Make sure the encoded and decoded versions match.
//     assert_eq!(
//         MetaInfo::from_bencode(&meta.to_bencode(), PathBuf::new()).unwrap(),
//         meta
//     );

//     meta
// }

// async fn test(data: Arc<FakeData>, peer_pieces_haves: Vec<PiecesHave>) {
//     // Create torrent file to download the data.
//     let meta = Arc::new(fake_meta(
//         &data,
//         Url::parse(&mockito::server_url()).unwrap(),
//     ));
//     let mut torrent_file = tempfile::NamedTempFile::new().unwrap();
//     torrent_file
//         .write_all(&meta.to_bencode().encode())
//         .unwrap();

//     // Create fake peers.
//     let mut fake_peer_addrs = vec![];
//     let mut fake_peer_futs = vec![];
//     let seed_on_done = peer_pieces_haves
//         .iter()
//         .any(|pieces_have| pieces_have != &PiecesHave::All);
//     for pieces_have in peer_pieces_haves {
//         let mut fake_peer = FakePeer::new(meta.clone(), data.clone(), pieces_have).await;
//         fake_peer_addrs.push(fake_peer.addr());
//         fake_peer_futs.push(tokio::spawn(async move {
//             fake_peer.start().await;
//         }));
//     }

//     // Create the tracker that points to these fake peers.
//     let response = Tracker::encode_response(
//         &Duration::from_secs(1000),
//         &fake_peer_addrs.into_iter().collect(),
//     );
//     let _mock_tracker = mockito::mock("GET", mockito::Matcher::Any)
//         .with_body(response)
//         .create();

//     let output_dir = tempfile::tempdir().unwrap();
//     let opts = simple_torrent::CmdOptions {
//         input: simple_torrent::CmdInput::TorrentPath(torrent_file.path().into()),
//         out_dir: output_dir.path().into(),
//         cache_dir: "".into(),
//         no_cache: true,
//         seed_on_done,
//         max_peers: 30,
//         dry_run: false,
//     };

//     // Run the torrent.
//     if opts.seed_on_done {
//         tokio::spawn(async move {
//             simple_torrent::run(opts.clone()).await.unwrap();
//         });
//     } else {
//         simple_torrent::run(opts.clone()).await.unwrap();
//     }
//     for fake_peer_fut in fake_peer_futs {
//         fake_peer_fut.await.unwrap();
//     }

//     // Make sure data has been saved correctly.
//     for (index, (rel_filepath, _)) in data.files.iter().enumerate() {
//         let filepath: PathBuf = [output_dir.path(), rel_filepath].iter().collect();
//         assert_eq!(
//             data.file_data(index),
//             std::fs::read(filepath).unwrap().as_slice()
//         );
//     }
// }

// #[cfg(test)]
// #[tokio::test]
// async fn test_torrent_one_fake_peer_singlefile() {
//     test(
//         Arc::new(FakeData::generate(2usize.pow(16), vec![100])),
//         vec![PiecesHave::All],
//     )
//     .await;
// }

// #[cfg(test)]
// #[tokio::test]
// async fn test_torrent_one_fake_peer_multifile() {
//     test(
//         Arc::new(FakeData::generate(520_000, vec![45, 55])),
//         vec![PiecesHave::All],
//     )
//     .await;
// }

// #[cfg(test)]
// #[tokio::test]
// async fn test_torrent_many_fake_peers() {
//     test(
//         Arc::new(FakeData::generate(520_000, vec![10, 10, 80])),
//         vec![PiecesHave::Only(vec![0]), PiecesHave::Missing(vec![0])],
//     )
//     .await;
// }

// #[cfg(test)]
// #[tokio::test]
// async fn test_torrent_many_fake_peers_leecher() {
//     test(
//         Arc::new(FakeData::generate(520_000, vec![100])),
//         vec![
//             PiecesHave::None,
//             PiecesHave::Only(vec![0]),
//             PiecesHave::Missing(vec![0]),
//         ],
//     )
//     .await;
// }
