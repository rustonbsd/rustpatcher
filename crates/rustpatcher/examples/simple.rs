use std::{env, time::Duration};

use rustpatcher::data::Patcher;
use tokio::time::sleep;

//#[rustpatcher::main]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let v_string = env!("CARGO_PKG_VERSION").to_string().clone();

    // Needed since this is an example of the same crate and not loading as a package
    // Normal: 
    //
    //  #[rustpatcher::main]
    //  fn main() -> Result<()> {
    //     // ..
    //  }
    //
    rustpatcher::version_embed::__set_version(Box::leak(v_string.into_boxed_str()));

    let patcher = Patcher::new()
        .trusted_key_from_z32_str("36nqmiugqobr5uw4j7mm8xfbfpc8pggpxnmw6k9sj7x7mtgbdr9o")
        .shared_secret_key_from_z32_str("3j86j9r7zn1r71xj4ky4nakwhpu1syywrwn9m6ahe5iqp897up1o")
        .update_interval(Duration::from_secs(10))
        .build()
        .await?;

    loop {
        sleep(Duration::from_secs(10)).await;
        if patcher.clone().update_available().await? {
            println!("Updating: {:?}", patcher.clone().try_update().await?);
        }
    }
}
