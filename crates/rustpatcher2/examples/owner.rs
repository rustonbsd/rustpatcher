use std::{fs, path::PathBuf};

use ed25519_dalek::{SigningKey, VerifyingKey};
use rustpatcher2;

#[tokio::main]
#[rustpatcher2::main]
async fn main() -> anyhow::Result<()> {
    println!("1");
    let owner_signing_key = load_signing_key(KeySource::File(PathBuf::from(
        "./owner_key",
    )))?;
    println!("2");
    let patch_info = rustpatcher2::Patch::from_self(owner_signing_key.verifying_key())?;
    
    println!("3");
    println!("Embedded patch info: {:?}", patch_info.info());
    
    Ok(())
}

enum KeySource {
    File(PathBuf),
    Inline(String),
}

fn load_signing_key(source: KeySource) -> anyhow::Result<SigningKey> {
    match source {
        KeySource::File(path) => {
            let data = if let Ok(data) = fs::read(&path) {
                data
            } else {
                let signing_key = SigningKey::generate(&mut rand::thread_rng());
                let signing_key_z32 = z32::encode(signing_key.as_bytes());
                let signing_key_bytes = signing_key_z32.as_bytes();
                fs::write(&path, signing_key_bytes)?;
                signing_key_bytes.to_vec()
            };
            println!("signing_key data: {:?}", data);

            let sing_key_bytes = z32::decode(&data)
                .map_err(|_| anyhow::anyhow!("failed to decode signing key from z-base-32"))?;
            let sign_key_bytes = sing_key_bytes.as_slice();
            Ok(SigningKey::from_bytes(sign_key_bytes.try_into().map_err(
                |_| {
                    anyhow::anyhow!(
                        "signing key must be 32 bytes (got {})",
                        sign_key_bytes.len()
                    )
                },
            )?))
        }
        KeySource::Inline(key_str) => {
            let sing_key_bytes = z32::decode(key_str.as_bytes())
                .map_err(|_| anyhow::anyhow!("failed to decode signing key from z-base-32"))?;
            let sign_key_bytes = sing_key_bytes.as_slice();
            Ok(SigningKey::from_bytes(sign_key_bytes.try_into().map_err(
                |_| {
                    anyhow::anyhow!(
                        "signing key must be 32 bytes (got {})",
                        sign_key_bytes.len()
                    )
                },
            )?))
        }
    }
}
