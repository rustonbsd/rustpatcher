
#[tokio::main]
#[rustpatcher2::public_key("axegnqus3miex47g1kxf1j7j8spczbc57go7jgpeixq8nxjfz7gy")]
async fn main() -> anyhow::Result<()> {

    let _my_patch = rustpatcher2::Patch::from_self()?;
    Ok(())
}