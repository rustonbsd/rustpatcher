use rustpatcher2::UpdaterMode;
use tracing::warn;

#[tokio::main]
#[rustpatcher2::public_key("axegnqus3miex47g1kxf1j7j8spczbc57go7jgpeixq8nxjfz7gy")]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_thread_ids(true)
        .init();

    let self_patch = rustpatcher2::Patch::from_self()?;
    println!("my version {:?} running", self_patch.info().version);
    warn!(": {:?}", self_patch.info());

    rustpatcher2::spawn(UpdaterMode::At(13, 40)).await?;

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