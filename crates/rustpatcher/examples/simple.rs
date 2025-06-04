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
        .trusted_key_from_z32_str(env::var("TRUSTED_KEY")?.as_str())
        .shared_secret_key_from_z32_str(env::var("SHARED_SECRET_KEY")?.as_str())
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
