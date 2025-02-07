use std::time::Duration;

use rustpatcher::data::Patcher;
use tokio::time::sleep;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let patcher = Patcher::new()
        .trusted_key_from_z32_str("bdj4qg7imiqr6mo4geq638ri7fjdbs51s1c5jqyc45d4ri3ux64o")
        .load_secret_key_from_file(true)
        .load_latest_version_from_file(true)
        .build()
        .await?;

    loop {
        sleep(Duration::from_secs(99999)).await;
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
