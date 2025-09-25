use rustpatcher2;

#[tokio::main]
#[rustpatcher2::public_key("axegnqus3miex47g1kxf1j7j8spczbc57go7jgpeixq8nxjfz7gy")]
async fn main() -> anyhow::Result<()> {
    let patch_info = rustpatcher2::Patch::from_self()?;
    println!("pub-key: {:?}", z32::encode(rustpatcher2::get_owner_pub_key().as_bytes()));
    println!("app-version: {:?}", rustpatcher2::get_app_version());
    println!("Embedded patch info: {:?}", patch_info.info());
    
    Ok(())
}