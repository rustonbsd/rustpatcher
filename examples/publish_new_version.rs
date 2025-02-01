use ed25519_dalek::{ed25519::signature::SignerMut, SecretKey, SigningKey};
use rand::rngs::OsRng;
use rustpatcher::{
    data::{Version, VersionInfo, VersionTracker},
    utils::{Storage, LATEST_VERSION_NAME, PUBLISHER_SIGNING_KEY_NAME, PUBLISHER_TRUSTED_KEY_NAME, SECRET_KEY_NAME},
};
use sha2::{Digest, Sha256};
use tokio::{fs::File, io::AsyncReadExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let version = Version(0,0,2);
    let file_path = "test.file";
    let mut file = File::open(file_path).await?;
    let mut buf = vec![];
    file.read_to_end(&mut buf).await?;

    let mut publisher_signing_key = {
        if let Ok(secret_key) = SecretKey::from_file(PUBLISHER_SIGNING_KEY_NAME).await {
            SigningKey::from_bytes(&secret_key)
        } else {
            let mut csprng = OsRng;
            let signing_key = SigningKey::generate(&mut csprng);

            // persist generated keys
            signing_key.clone().to_file(PUBLISHER_SIGNING_KEY_NAME).await?;
            signing_key.clone().verifying_key().to_file(PUBLISHER_TRUSTED_KEY_NAME).await?;
            signing_key
        }
    };

    let node_secret_key = {
        if let Ok(secret_key) = SecretKey::from_file(SECRET_KEY_NAME).await {
            secret_key
        } else {
            let signing_key = *publisher_signing_key.as_bytes();
            signing_key.clone().to_file(SECRET_KEY_NAME).await?;
            signing_key
        }
    };

    if !publisher_signing_key.as_bytes().eq(&node_secret_key) {
        anyhow::bail!("secret key and publisher signing key don't match. not allowed for trusted node")
    }

    let signature = publisher_signing_key.sign(&buf.as_slice());
    let hash = compute_hash(&buf);
    let trusted_key = publisher_signing_key.verifying_key().as_bytes().clone();

    let version_info = VersionInfo {
        version,
        hash,
        signature,
        trusted_key,
    };
    let version_tracker = VersionTracker::load(&trusted_key, &version_info, &buf.clone().into(), vec![node_secret_key])?;
    version_tracker.to_file(LATEST_VERSION_NAME).await?;

    Ok(())
}

fn compute_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&hasher.finalize());
    buf
}
