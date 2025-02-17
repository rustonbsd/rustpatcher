use std::{env, time::Duration};

use rustpatcher::data::Patcher;
use tokio::time::sleep;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().expect("dotenv failed to load");
    let v_string = env!("CARGO_PKG_VERSION").to_string().clone();
    rustpatcher::version_embed::__set_version(Box::leak(v_string.into_boxed_str()));
    let patcher = Patcher::new()
    .trusted_key_from_z32_str("mw6iuq1iu7qd5gcz59qpjnu6tw9yn7pn4gxxkdbqwwwxfzyziuro")
    .shared_secret_key_from_z32_str("8656fg8j6s43a4jndkzdysjuof588zezsn6s8sd6wwcpwf6b3r9y")
    .update_interval(Duration::from_secs(10))
    .build()
    .await?;

    println!("1Paul war hier!");
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
