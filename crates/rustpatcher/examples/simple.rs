use std::{env, time::Duration};

use rustpatcher::data::Patcher;
use tokio::time::sleep;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().expect("dotenv failed to load");
    let v_string = env!("CARGO_PKG_VERSION").to_string().clone();
    rustpatcher::version_embed::__set_version(Box::leak(v_string.into_boxed_str()));
    let patcher = Patcher::new()
        .trusted_key_from_z32_str("mqgmpxe8nkbge73kzbw9jw96j676xa84ot781cwy8aij9i67ppzo")
        .shared_secret_key_from_z32_str("wqnwmgkb8i6fqtj55qzs499kq495oezw3j1xxz58igijztpkyjcy")
        .build()
        .await?;

    println!("1Paul war hier!");
    println!("2Paul war hier!");
    println!("3Paul war hier!");
    println!("4Paul war hier!");
    println!("5Paul war hier!");
    println!("6Paul war hier!");
    println!("7Paul war hier!");
    println!("8Paul war hier!");
    println!("9Paul war hier!");
    println!("10Paul war hier!");
    println!("Version: {}\n\n--\n", env!("CARGO_PKG_VERSION").to_string());

    loop {
        sleep(Duration::from_secs(10)).await;
        if patcher.clone().update_available().await? {
            println!("Updating: {:?}",patcher.clone().try_update().await?);
        }
    }
    

    // - rustpatcher create trustkey
    //    just create key pair so trusted_key can be used in patcher builder (required)
    // - rustpatcher create patch
    //    Just takes the current binary and creates version with signature etc
    //    this will just be stored under the current nodes .patcher file as
    //    latest_version, this will auto distribute as soon as at least one
    //    node copied the data
}
