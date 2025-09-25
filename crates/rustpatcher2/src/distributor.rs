use actor_helper::{act, act_ok, Action, Actor, Handle};
use distributed_topic_tracker::unix_minute;
use iroh::{endpoint::VarInt, protocol::ProtocolHandler, Endpoint, NodeId};
use sha2::Digest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
            let mut actor = DistributorActor { rx, endpoint, self_patch_bytes };
            if let Err(e) = actor.run().await {
                eprintln!("Distributor actor error: {:?}", e);
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
        let endpoint = self.api.call(act_ok!(actor => async move {
            actor.endpoint.clone()
        })).await?;
        println!("1");
        let conn = endpoint.connect(node_id,&Distributor::ALPN()).await?;
        let (mut tx, mut rx) = conn.open_bi().await?;
        println!("2");
    
        // auth: hash(owner_pub_key + unix_minute)
        let mut auth_hasher = sha2::Sha512::new();
        auth_hasher.update(crate::embed::get_owner_pub_key().as_bytes());
        auth_hasher.update(unix_minute(0).to_le_bytes());
        let auth_hash = auth_hasher.finalize();
        tx.write_all(&auth_hash).await?;
        println!("3");

        if let Ok(0) = rx.read_u8().await {
            anyhow::bail!("auth failed");
        }

        println!("4");
        // read data
        let buf_len = rx.read_u64().await?;
        let mut buf = vec![0u8; buf_len as usize];
        println!("4.5");
        rx.read_exact(&mut buf).await?;
        println!("5");

        // verify and parse
        let patch = postcard::from_bytes::<Patch>(buf.as_slice())?;
        println!("6");
        patch.verify()?;
        println!("7");
        if !patch.info().eq(&patch_info) {
            println!("9");
            anyhow::bail!("patch info mismatch");
        }
        println!("8");
        rx.stop(VarInt::default())?;

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

impl ProtocolHandler for Distributor {
    async fn accept(
        &self,
        connection: iroh::endpoint::Connection,
    ) -> Result<(), iroh::protocol::AcceptError> {
        self.api
            .call(act!(actor => async move {
                let (mut tx, mut rx) = connection.accept_bi().await?;
                println!("1");

                // auth: hash(owner_pub_key + unix_minute)
                let mut auth_buf = [0u8; 64];
                rx.read_exact(&mut auth_buf).await?;
                println!("2");

                let owner_pub_key = crate::embed::get_owner_pub_key();

                fn auth_hash(t: i64, owner_pub_key: &ed25519_dalek::VerifyingKey) -> Vec<u8> {
                    let mut auth_hasher = sha2::Sha512::new();
                    auth_hasher.update(owner_pub_key.as_bytes());
                    auth_hasher.update(unix_minute(t).to_le_bytes());
                    let auth_hash = auth_hasher.finalize();
                    auth_hash.to_vec()
                }

                let mut accept_auth = false;
                for t in -2..2 {
                    if auth_buf == auth_hash(t, &owner_pub_key)[..] {
                        accept_auth = true;
                        break;
                    }
                }

                println!("3");
                if !accept_auth {
                    tx.write_u8(0).await?;
                    println!("Auth failed");
                    connection.close(VarInt::default(), b"auth failed");
                    anyhow::bail!("auth failed");
                } else {
                    tx.write_u8(1).await?;
                }
                
                println!("4");
                // send data
                tx.write_u64(actor.self_patch_bytes.len() as u64).await?;
                tx.write_all(&actor.self_patch_bytes).await?;
                println!("5");

                tx.stopped().await?;
                println!("6");
                
                Ok(())
            }))
            .await
            .map_err(|e| iroh::protocol::AcceptError::User {
                source: Box::<dyn std::error::Error + Send + Sync>::from(e),
            })?;
        Ok(())
    }
}
