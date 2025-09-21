use std::{env, time::Duration};

use rustpatcher::data::Patcher;
use tokio::time::sleep;

//#[rustpatcher::main]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("Patcher Starting...");
    env_logger::init();

    // if sysargs manually set version
    let version = if env::args().len() == 2 {
        env::args().nth(1).unwrap()
    } else if env::args().len() == 4 {
        env::args().nth(3).unwrap()
    } else {
        env!("CARGO_PKG_VERSION").to_string().clone()
    };

    // Needed since this is an example of the same crate and not loading as a package
    // Normal:
    //
    //  #[rustpatcher::main]
    //  fn main() -> Result<()> {
    //     // ..
    //  }
    //
    rustpatcher::version_embed::__set_version(Box::leak(version.into_boxed_str()));

    println!("Version: {}", rustpatcher::version_embed::get_app_version());

    let patcher = Patcher::new()
        .trusted_key_from_z32_str("u9a1irehmsxj15wei1raf7mkmjjshqtczp94tq1e3rb3pexa5q1o")
        .shared_secret_key_from_z32_str("f5daiq34tu1x4nf5roagw9jhfz6zncxkhzdizijxm61hzkhyeycy")
        .build()
        .await?;

    loop {
        sleep(Duration::from_secs(10)).await;
        if patcher.clone().update_available().await? {
            println!("Update available");
            println!("Updating: {:?}", patcher.clone().try_update().await);
        }
    }
}
