use rustpatcher::{data::Patcher, PubTPatcher};


#[tokio::main]
async fn main() -> anyhow::Result<()> {

    let patcher = Patcher::new().trusted_key_from_z32_str("78xrxgeq5er55t1tka681g8ban73rzmwpcx6p6qei9iryf31fqso").load_secret_key_from_file(true).load_latest_version_from_file(false).build().await?;
    patcher.spawn().await?;
    Ok(())

    // - rustpatcher create trustkey  
    //    just create key pair so trusted_key can be used in patcher builder (required)
    // - rustpatcher create patch
    //    Just takes the current binary and creates version with signature etc
    //    this will just be stored under the current nodes .patcher file as
    //    latest_version, this will auto distribute as soon as at least one 
    //    node copied the data
}