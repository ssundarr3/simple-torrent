# simple-torrent
A simple command-line BitTorrent client written in Rust

Currently supports downloading, uploading and resuming a torrent.

## Usage

1. Install rust and cargo (https://www.rust-lang.org/tools/install).

2. Build using: `cargo run --release`.

3. Run the built executable: `./target/release/simple-torrent <path_to_torrent_file>`. Or, build and run in one command using: `cargo run --release <path_to_torrent_file>`.

Supported arguments can be found using `cargo run -- --help`, which outputs:

```
USAGE:
    simple-torrent [FLAGS] [OPTIONS] <torrent-path>

FLAGS:
        --dry-run         Run in dry mode. Will do everything except start the download
    -h, --help            Prints help information
        --no-cache        Whether or not the cache can be used
        --seed-on-done    Shut down the program once the download completes
    -V, --version         Prints version information

OPTIONS:
        --cache-dir <cache-dir>    Path to cache directory [default: cache]
        --max-peers <max-peers>    The maximum number of peers to connect to [default: 50]
    -o, --out-dir <out-dir>        Output directory [default: downloads]

ARGS:
    <torrent-path>    Path to torrent file
```

## Tests

Run tests using `cargo test --release`.
