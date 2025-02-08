use std::time::Duration;

use rustpatcher::data::{Patcher, Version};
use tokio::time::sleep;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let patcher = Patcher::new()
        .trusted_key_from_z32_str("ewkijs9aynd1gxp8bd7y73qkc7maqc8qh1j8kej9dumuwr9cq7by")
        .build()
        .await?;

    println!("Paul war hier!");
    println!("Version: {}", env!("CARGO_PKG_VERSION").to_string());

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
