use anyhow::bail;
use iroh::Endpoint;
use pkarr::dns::{self, Packet};
use serde::{de::DeserializeOwned, Serialize};
use tokio::{fs::{create_dir, File}, io::{AsyncReadExt, AsyncWriteExt}};

pub const PATCHER_DIR: &str = ".patcher";

pub async fn wait_for_relay(endpoint: &Endpoint) -> anyhow::Result<()> {
    while endpoint.home_relay().get().is_err() {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    Ok(())
}

pub fn decode_rdata<T: DeserializeOwned + Clone>(
    packet: &Packet<'_>,
    query: &str,
) -> anyhow::Result<T> {
    let record = packet
        .answers
        .iter()
        .find(|&record| record.name.to_string().starts_with(query))
        .ok_or_else(|| anyhow::anyhow!("record not found"))?;

    match &record.rdata {
        dns::rdata::RData::TXT(txt) => {
            let attrbs_raw = txt.attributes();
            let attrbs = attrbs_raw
                .values()
                .filter_map(|a| a.clone())
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

pub trait Storage {
    async fn from_file<T: DeserializeOwned + Clone>(
        file_name: &str,
    ) -> anyhow::Result<T>;
    async fn to_file<T: Serialize + Clone> (&self,file_name: &str) -> anyhow::Result<()>;
}
impl<S: Serialize + DeserializeOwned + Clone> Storage for S {

    async fn from_file<T: DeserializeOwned + Clone>(
        file_name: &str,
    ) -> anyhow::Result<T> {
        create_check_patcher_dir().await;
        
        let mut file = File::open(format!("{PATCHER_DIR}/{file_name}")).await?;
        let mut buf = vec![];
        file.read_to_end(&mut buf).await?;
    
        let t: T = serde_json::from_slice(&buf.as_slice())?;
    
        Ok(t)
    }
    
    async fn to_file<T: Serialize + Clone> (self: &S,file_name: &str) -> anyhow::Result<()> {
        create_check_patcher_dir().await;
    
        let mut file = File::open(format!("{PATCHER_DIR}/{file_name}")).await?;
        let buf = serde_json::to_vec(self)?;
        file.write_all(buf.as_slice()).await?;
    
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
        }else {create = true;}
    } else {create = true;}

    if create {
        let _ = create_dir(PATCHER_DIR).await;
    }
}