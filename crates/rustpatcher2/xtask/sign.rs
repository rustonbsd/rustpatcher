use std::{fs::{self, OpenOptions}, io::{Seek, SeekFrom, Write}, path::PathBuf};

use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;

#[derive(Parser, Debug)]
#[command(name = "rustpatcher", version, about)]
struct RootCli {
    #[command(subcommand)]
    cmd: Commands,
}
enum KeySource {
    File(PathBuf),
    Inline(String),
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Sign and embed a patch into a binary
    Sign(SignArgs),
}

#[derive(Parser, Debug)]
struct SignArgs {
    #[arg(value_name = "BIN")]
    binary: std::path::PathBuf,
    #[arg(long = "key-file", value_name = "PATH")]
    key_file: Option<std::path::PathBuf>,
    #[arg(long = "key", value_name = "Z32")]
    key: Option<String>,
}

fn main() -> anyhow::Result<()> {
    let root = RootCli::parse();
    match root.cmd {
        Commands::Sign(args) => sign_cmd(args),
    }
}

fn sign_cmd(args: SignArgs) -> anyhow::Result<()> {
    let key_src = if let Some(k) = args.key {
        KeySource::Inline(k)
    } else {
        KeySource::File(
            args.key_file
                .unwrap_or_else(|| PathBuf::from("./owner_signing_key")),
        )
    };

    let signing_key = load_signing_key(key_src)?;

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(false)
        .open(&args.binary)?;

    let mut data = fs::read(&args.binary)
        .map_err(|e| anyhow::anyhow!("failed to read binary {}: {}", args.binary.display(), e))?;

    let (data_no_embed, data_embed, embed_region) =
        rustpatcher2::embed::cut_embed_section(data.clone())?;
    let version = rustpatcher2::embed::get_embedded_version(&data_embed)?;

    let patch_info = rustpatcher2::Patch::sign(signing_key, data_no_embed, version)?;
    rustpatcher2::embed::set_embedded_patch_info(&mut data, patch_info, embed_region)?;

    file.seek(SeekFrom::Start(0))?;
    file.write_all(&data)?;
    file.set_len(data.len() as u64)?;

    Ok(())
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
