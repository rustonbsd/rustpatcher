use rustpatcher::UpdaterMode;
use tracing::warn;

#[cfg(target_os = "windows")]
const PUBLIC_KEY: &'static str = "...windows-key...";
#[cfg(target_os = "linux")]
const PUBLIC_KEY: &'static str = "...linux-key...";
#[cfg(target_os = "macos")]
const PUBLIC_KEY: &'static str = "...macos-key...";

#[rustpatcher::public_key(PUBLIC_KEY)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_thread_ids(true)
        .init();

    let self_patch = rustpatcher::Patch::from_self()?;
    println!("my version {:?} running", self_patch.info().version);
    warn!(": {:?}", self_patch.info());

    rustpatcher::spawn(UpdaterMode::At(13, 40)).await?;

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
