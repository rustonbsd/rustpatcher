#[cfg(target_os = "windows")]
const PUBLIC_KEY: &str = "...windows-key...";
#[cfg(target_os = "linux")]
const PUBLIC_KEY: &str = "...linux-key...";
#[cfg(target_os = "macos")]
const PUBLIC_KEY: &str = "...macos-key...";

#[rustpatcher::public_key(PUBLIC_KEY)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_thread_ids(true)
        .init();

    #[cfg(not(debug_assertions))]
    {
        rustpatcher::spawn(rustpatcher::UpdaterMode::At(13, 40)).await?;

        let self_patch = rustpatcher::Patch::from_self()?;
        println!("my version {:?} running", self_patch.info().version);
    }

    tokio::signal::ctrl_c()
        .await
        .map_err(|e| anyhow::anyhow!(e))
}
