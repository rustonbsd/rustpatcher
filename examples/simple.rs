use std::{env, time::Duration};

use rustpatcher::data::{Patcher, Version};
use tokio::time::sleep;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().expect("dotenv failed to load");
    let patcher = Patcher::new()
        .trusted_key_from_z32_str(&env::var("TRUSTED_KEY")?)
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
    Ok(())

    // - rustpatcher create trustkey
    //    just create key pair so trusted_key can be used in patcher builder (required)
    // - rustpatcher create patch
    //    Just takes the current binary and creates version with signature etc
    //    this will just be stored under the current nodes .patcher file as
    //    latest_version, this will auto distribute as soon as at least one
    //    node copied the data
}
