
#[tokio::main]
#[rustpatcher::public_key("axegnqus3miex47g1kxf1j7j8spczbc57go7jgpeixq8nxjfz7gy")]
async fn main() -> anyhow::Result<()> {

    // Only in --release builds, not intended for debug builds
    rustpatcher::spawn(rustpatcher::UpdaterMode::At(13, 40)).await?;

    println!("my version is {:?}", rustpatcher::Version::current()?);
    
    #[cfg(not(debug_assertions))]
    println!("{:?}", rustpatcher::Patch::from_self()?.info());
    #[cfg(debug_assertions)]
    println!("Debug build, skipping Patch::from_self()");

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("Exiting on Ctrl-C");
                break;
            }
        }
    }
    Ok(())
}