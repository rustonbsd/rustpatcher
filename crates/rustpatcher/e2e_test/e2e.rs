#[cfg(target_os = "macos")]
const PUBLIC_KEY: &str = "9mrnh6bhosexei8ciwe1gm7kqitg7y3rbzjbezqbncpg1sk6sq6o";
#[cfg(target_os = "linux")]
const PUBLIC_KEY: &str = "6qdxs69eg39f1iu79sza56tqbzzgur4gteowp9fa8dwfpakc3ngy";
#[cfg(target_os = "windows")]
const PUBLIC_KEY: &str = "bhafqhm8k9e7fzab7i7h6gie6oedncwyffautkngqsa9d1ohzuho";

#[tokio::main]
#[rustpatcher::public_key(PUBLIC_KEY)]
async fn main() -> anyhow::Result<()> {
    
    rustpatcher::spawn(rustpatcher::UpdaterMode::Now).await?;
    println!("{:?}", rustpatcher::Version::current()?);

    tokio::signal::ctrl_c()
        .await
        .map_err(|e| anyhow::anyhow!(e))
}
