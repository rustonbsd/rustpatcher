use std::{io::SeekFrom, str::FromStr, time::Duration};

use anyhow::bail;
use pkarr::dns::{self, Packet};
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    fs::{create_dir, File, OpenOptions},
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
};

use crate::data::Version;

pub const PUBLISHER_TRUSTED_KEY_NAME: &str = "trusted_key";
pub const PUBLISHER_SIGNING_KEY_NAME: &str = "publisher_signing_key";

pub const PATCHER_DIR: &str = ".patcher";
pub const SECRET_KEY_NAME: &str = "secret_key";
pub const SHARED_SECRET_KEY_NAME: &str = "shared_secret_key";
pub const LATEST_VERSION_NAME: &str = "latest_version";
pub const LAST_REPLY_ID_NAME: &str = "last_reply_id";
pub const LAST_TRUSTED_PACKAGE: &str = "last_trusted_package";

pub const PKARR_PUBLISHING_INTERVAL: Duration = Duration::from_secs(60*60);

pub fn decode_rdata<T: DeserializeOwned + Clone>(
    packet: &Packet<'_>,
    query: &str,
) -> anyhow::Result<T> {
    let record = packet
        .answers
        .iter()
        .find(|&record| record.name.to_string().starts_with(&query))
        .ok_or_else(|| anyhow::anyhow!("record not found"))?;

    match &record.rdata {
        dns::rdata::RData::TXT(txt) => {
            let attrbs_raw = txt.attributes();
            let attrbs = attrbs_raw
                .keys()
                .map(|a| a.clone())
                .collect::<Vec<String>>()
                .clone();

            let val = attrbs
                .first()
                .ok_or_else(|| anyhow::anyhow!("no attributes"))?;

            Ok(serde_json::from_str::<T>(&val.clone())?.clone())
        }
        _ => {
            bail!("rdata record not txt: {:?}", record.rdata.type_code())
        }
    }
}

pub trait Storage<T: Serialize + DeserializeOwned + Clone> {
    fn from_file(file_name: &str) -> impl std::future::Future<Output = anyhow::Result<T>> + Send;
    fn to_file(self, file_name: &str) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
}

impl<S: Serialize + DeserializeOwned + Clone + Send> Storage<S> for S {
    async fn from_file(file_name: &str) -> anyhow::Result<S> {
        create_check_patcher_dir().await;

        let mut file = File::open(format!("{PATCHER_DIR}/{file_name}")).await?;
        let mut buf = vec![];
        file.read_to_end(&mut buf).await?;

        let t: S = serde_json::from_slice(&buf.as_slice())?;

        Ok(t)
    }

    async fn to_file(self: S, file_name: &str) -> anyhow::Result<()> {
        create_check_patcher_dir().await;

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .open(format!("{PATCHER_DIR}/{file_name}"))
            .await?;

        file.seek(SeekFrom::Start(0)).await?;
        file.set_len(0).await?;

        let buf = serde_json::to_vec(&self)?;
        file.write_all(buf.as_slice()).await?;
        file.flush().await?;

        Ok(())
    }
}

pub async fn create_check_patcher_dir() {
    let mut create = false;
    if let Ok(dir) = File::open(PATCHER_DIR).await {
        if let Ok(meta) = dir.metadata().await {
            if !meta.is_dir() {
                create = true;
            }
        } else {
            create = true;
        }
    } else {
        create = true;
    }

    if create {
        let _ = create_dir(PATCHER_DIR).await;
    }
}


pub fn compute_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&hasher.finalize());
    buf
}

pub fn get_app_version()->anyhow::Result<Version> {
    Version::from_str(super::version_embed::get_app_version())
}