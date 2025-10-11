const PUBLIC_KEY: &str = "axegnqus3miex47g1kxf1j7j8spczbc57go7jgpeixq8nxjfz7gy";

#[tokio::main]
#[rustpatcher::public_key(PUBLIC_KEY)]
async fn main() -> anyhow::Result<()> {
    // Only in --release builds, not intended for debug builds
    rustpatcher::spawn(rustpatcher::UpdaterMode::Now).await?;

    println!("my version is {:?}", rustpatcher::Version::current()?);

    #[cfg(not(debug_assertions))]
    println!("{:?}", rustpatcher::Patch::from_self()?.info());
    #[cfg(debug_assertions)]
    println!("Debug build, skipping Patch::from_self()");

    tokio::signal::ctrl_c()
        .await
        .map_err(|e| anyhow::anyhow!(e))
}
