use actor_helper::{Action, Actor, Handle, act_ok};
use distributed_topic_tracker::unix_minute;
use iroh::{
    Endpoint, NodeId,
    endpoint::VarInt,
    protocol::{AcceptError, ProtocolHandler},
};
use sha2::Digest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::error;

use crate::{Patch, PatchInfo};

#[derive(Debug, Clone)]
pub struct Distributor {
    api: Handle<DistributorActor>,
}

#[derive(Debug)]
struct DistributorActor {
    rx: tokio::sync::mpsc::Receiver<Action<DistributorActor>>,

    self_patch_bytes: Vec<u8>,
    endpoint: Endpoint,
}

impl Distributor {
    pub fn new(endpoint: Endpoint) -> anyhow::Result<Self> {
        let self_patch_bytes = postcard::to_allocvec(&Patch::from_self()?)?;
        let (api, rx) = Handle::channel(32);
        tokio::spawn(async move {
            let mut actor = DistributorActor {
                rx,
                endpoint,
                self_patch_bytes,
            };
            if let Err(e) = actor.run().await {
                error!("Distributor actor error: {:?}", e);
            }
        });
        Ok(Self { api })
    }

    #[allow(non_snake_case)]
    pub fn ALPN() -> Vec<u8> {
        format!(
            "/rustpatcher/{}/v0",
            z32::encode(crate::embed::get_owner_pub_key().as_bytes())
        )
        .into_bytes()
    }

    pub async fn get_patch(&self, node_id: NodeId, patch_info: PatchInfo) -> anyhow::Result<Patch> {
        let endpoint = self
            .api
            .call(act_ok!(actor => async move {
                actor.endpoint.clone()
            }))
            .await?;

        let conn = endpoint.connect(node_id, &Distributor::ALPN()).await?;
        let (mut tx, mut rx) = conn.open_bi().await?;

        // auth: hash(owner_pub_key + unix_minute)
        let mut auth_hasher = sha2::Sha512::new();
        auth_hasher.update(crate::embed::get_owner_pub_key().as_bytes());
        auth_hasher.update(unix_minute(0).to_le_bytes());
        let auth_hash = auth_hasher.finalize();
        tx.write_all(&auth_hash).await?;

        if let Ok(0) = rx.read_u8().await {
            anyhow::bail!("auth failed");
        }

        // read data
        let buf_len = rx.read_u64().await?;
        let mut buf = vec![0u8; buf_len as usize];
        rx.read_exact(&mut buf).await?;

        // verify and parse
        let patch = postcard::from_bytes::<Patch>(buf.as_slice())?;
        patch.verify()?;
        if !patch.info().eq(&patch_info) {
            anyhow::bail!("patch info mismatch");
        }

        Ok(patch)
    }
}

impl Actor for DistributorActor {
    async fn run(&mut self) -> anyhow::Result<()> {
        loop {
            tokio::select! {
                Some(action) = self.rx.recv() => {
                    action(self).await
                }
            }
        }
    }
}

type IrohError = Box<dyn std::error::Error + Send + Sync>;

fn to_iroh_error<E>(e: E) -> AcceptError
where
    E: Into<IrohError>,
{
    AcceptError::User { source: e.into() }
}

impl ProtocolHandler for Distributor {
    async fn accept(
        &self,
        connection: iroh::endpoint::Connection,
    ) -> Result<(), iroh::protocol::AcceptError> {
        let (mut tx, mut rx) = connection.accept_bi().await.map_err(to_iroh_error)?;

        // auth: hash(owner_pub_key + unix_minute)
        let mut auth_buf = [0u8; 64];
        rx.read_exact(&mut auth_buf).await.map_err(to_iroh_error)?;

        let owner_pub_key = crate::embed::get_owner_pub_key();

        fn auth_hash(t: i64, owner_pub_key: &ed25519_dalek::VerifyingKey) -> Vec<u8> {
            let mut auth_hasher = sha2::Sha512::new();
            auth_hasher.update(owner_pub_key.as_bytes());
            auth_hasher.update(unix_minute(t).to_le_bytes());
            let auth_hash = auth_hasher.finalize();
            auth_hash.to_vec()
        }

        let mut accept_auth = false;
        for t in -1..2 {
            if auth_buf == auth_hash(t, owner_pub_key)[..] {
                accept_auth = true;
                break;
            }
        }

        if !accept_auth {
            tx.write_u8(0).await.map_err(to_iroh_error)?;
            connection.close(VarInt::default(), b"auth failed");
            return Err(to_iroh_error(std::io::Error::other("auth failed")));
        } else {
            tx.write_u8(1).await.map_err(to_iroh_error)?;
        }

        // send data
        let self_patch_bytes = self
            .api
            .call(act_ok!(actor => async move {
                actor.self_patch_bytes.clone()
            }))
            .await
            .map_err(to_iroh_error)?;

        tx.write_u64(self_patch_bytes.len() as u64)
            .await
            .map_err(to_iroh_error)
            .map_err(to_iroh_error)?;
        tx.write_all(&self_patch_bytes)
            .await
            .map_err(to_iroh_error)
            .map_err(to_iroh_error)?;

        let _ = tx.stopped().await;

        Ok(())
    }
}
