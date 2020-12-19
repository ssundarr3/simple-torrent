use simple_torrent::CmdOptions;
use structopt::StructOpt;

#[tokio::main]
async fn main() {
    pretty_env_logger::init();

    // let opts = CmdOptions::from_args();
    // if let Err(e) = simple_torrent::run(opts) {
    //     log::error!("Err: {}", e);
    // }
}
