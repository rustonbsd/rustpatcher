pub mod data;
pub mod utils;

use std::{future::Future, pin::Pin, str::FromStr, sync::Arc, time::Instant};

use anyhow::{bail, Result};
use bytes::Bytes;
use data::{Inner, Patcher, Protocol, Version, VersionInfo, VersionTracker};
use ed25519_dalek::{Signature, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
use iroh::{
    endpoint::{Connecting, Endpoint, RecvStream, SendStream},
    protocol::ProtocolHandler,
    NodeAddr, NodeId, SecretKey,
};
use pkarr::{dns, Keypair, PkarrClient, PublicKey, SignedPacket};
use rand::{rngs::OsRng, Rng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
};
use utils::{Storage, LAST_REPLY_ID_NAME, LATEST_VERSION_NAME, SECRET_KEY_NAME};

use crate::utils::wait_for_relay;

pub struct Builder {
    secret_key: [u8; SECRET_KEY_LENGTH],
    trusted_key: Option<[u8; PUBLIC_KEY_LENGTH]>,
    load_latest_version_from_file: bool,
    load_secret_key_from_file: bool,
}

impl Builder {
    pub fn new() -> Self {
        Self {
            secret_key: SecretKey::generate(rand::rngs::OsRng).to_bytes(),
            trusted_key: None,
            load_latest_version_from_file: false,
            load_secret_key_from_file: false,
        }
    }

    pub fn load_latest_version_from_file(mut self, val: bool) -> Self {
        self.load_latest_version_from_file = val;
        self
    }

    pub fn load_secret_key_from_file(mut self, val: bool) -> Self {
        self.load_secret_key_from_file = val;
        self
    }

    pub fn trusted_key(mut self, trusted_key: &[u8; PUBLIC_KEY_LENGTH]) -> Self {
        self.trusted_key = Some(*trusted_key);
        self
    }

    pub fn trusted_key_from_z32_str(mut self, trusted_key: &str) -> Self {
        let tk = z32::decode(trusted_key.as_bytes());
        if tk.is_err() {
            return self;
        }

        let mut trusted_key_buf = [0u8; PUBLIC_KEY_LENGTH];
        trusted_key_buf.copy_from_slice(tk.unwrap().as_slice());
        self.trusted_key = Some(trusted_key_buf);
        self
    }

    pub async fn build(self: &mut Self) -> anyhow::Result<Patcher> {
        if self.trusted_key.is_none() {
            bail!("trusted key required")
        }

        if self.load_secret_key_from_file {
            self.secret_key = SecretKey::from_file(SECRET_KEY_NAME).await?.to_bytes();
        }

        // Iroh setup
        let secret_key = SecretKey::from_bytes(&self.secret_key);
        let endpoint = Endpoint::builder()
            .secret_key(secret_key)
            .discovery_n0()
            .discovery_dht()
            .bind()
            .await?;

        let patcher = if self.load_latest_version_from_file {
            let latest_version = VersionTracker::from_file(LATEST_VERSION_NAME).await;
            if latest_version.is_ok() {
                Patcher::with_latest_version(&endpoint, latest_version.unwrap())
            } else {
                Patcher::with_endpoint(&endpoint)
            }
        } else {
            Patcher::with_endpoint(&endpoint)
        };

        let _router = iroh::protocol::Router::builder(endpoint.clone())
            .accept(Patcher::ALPN, patcher.clone())
            .spawn()
            .await?;

        Ok(patcher.spawn().await?)
    }
}

impl Patcher {
    pub const ALPN: &'static [u8] = b"iroh/patcher/1";
    pub const MAX_MSG_SIZE_BYTES: u64 = 1024 * 1024 * 1024;

    pub fn new() -> Builder {
        Builder::new()
    }

    fn with_endpoint(endpoint: &Endpoint) -> Self {
        Self::with_latest_version(endpoint, VersionTracker::new())
    }

    fn with_latest_version(endpoint: &Endpoint, latest_version: VersionTracker) -> Self {
        let me = Self {
            trusted_key: endpoint.node_id().as_bytes().clone(),
            inner: Inner {
                endpoint: endpoint.clone(),
                latest_version: Arc::new(Mutex::new(latest_version)),
            },
            secret_key: endpoint.secret_key().to_bytes(),
            public_key: endpoint.node_id().as_bytes().clone(),
        };
        me
    }

    async fn spawn(self) -> Result<Self> {
        // Iroh
        tokio::spawn({
            let me2 = self.clone();
            async move {
                while let Some(connecting) = me2.inner.endpoint.accept().await {
                    match connecting.accept() {
                        Ok(conn) => {
                            tokio::spawn({
                                let me3 = me2.clone();
                                async move {
                                    let _ = me3.accept_handler(conn).await;
                                }
                            });
                        }
                        Err(err) => {
                            println!("Failed to connect {err}");
                        }
                    }
                }
            }
        });

        // Pkarr
        tokio::spawn({
            let mut me = self.clone();
            async move {
                // - Publish if latest version if known
                // - Check trusted_key record for updates
                loop {
                    let version_tracker = { me.inner.latest_version.lock().await.clone() };
                    if let Some(version_info) = version_tracker.version_info() {

                        // Publish
                        if version_tracker.data().is_some() {
                            let _ = me.publish_pkarr().await;
                        }

                        // Check trusted_key record
                        if let Ok((trusted_version_info, trusted_node_ids)) =
                            me.resolve_pkarr(&me.trusted_key).await
                        {
                            {   // Add all current node ids
                                let mut lt = me.inner.latest_version.lock().await;
                                for node_id in trusted_node_ids.clone() {
                                    lt.add_node_id(&node_id);
                                }
                            }

                            if trusted_version_info.version > version_info.version {
                                // Update process
                                for node_id in trusted_node_ids.clone() {
                                    match me.try_update(iroh::PublicKey::from_bytes(&node_id).unwrap()).await {
                                        Ok(_) => {
                                            println!("New version downloaded: {:?}",me.inner.latest_version.lock().await);
                                            break
                                        },
                                        Err(_) => {
                                            let mut lt = me.inner.latest_version.lock().await;
                                            lt.rm_node_id(&node_id);
                                        },
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
        Ok(self)
    }
}

trait PrivatePatcherIroh {
    async fn send_msg(msg: Protocol, send: &mut SendStream) -> Result<()>;
    async fn recv_msg(recv: &mut RecvStream) -> Result<Protocol>;
    async fn accept_handler(&self, conn: Connecting) -> Result<()>;
    async fn try_update(self: &mut Self, node_id: NodeId) -> Result<()>;
}

impl PrivatePatcherIroh for Patcher {
    async fn send_msg(msg: Protocol, send: &mut SendStream) -> Result<()> {
        let encoded = postcard::to_stdvec(&msg)?;
        assert!(encoded.len() <= Self::MAX_MSG_SIZE_BYTES as usize);

        send.write_u64_le(encoded.len() as u64).await?;
        send.write(&encoded).await?;
        Ok(())
    }

    async fn recv_msg(recv: &mut RecvStream) -> Result<Protocol> {
        let len = recv.read_u64_le().await?;

        assert!(len <= Self::MAX_MSG_SIZE_BYTES);

        let mut buffer = vec![0u8; len as usize];
        recv.read_exact(&mut buffer).await?;
        let msg: Protocol = postcard::from_bytes(&buffer)?;
        Ok(msg)
    }

    async fn try_update(self: &mut Self, node_id: NodeId) -> Result<()> {
        wait_for_relay(&self.inner.endpoint).await?;

        let conn = self
            .inner
            .endpoint
            .connect(NodeAddr::new(node_id), Self::ALPN)
            .await?;
        let remote_node_id = iroh::endpoint::get_remote_node_id(&conn)?;

        let (mut send, mut recv) = conn.open_bi().await?;

        let msg = Protocol::Request;
        Self::send_msg(msg, &mut send).await?;

        match Self::recv_msg(&mut recv).await? {
            Protocol::Data(version_info, data) => {
                let mut latest_vt = self.inner.latest_version.lock().await;
                let latest_version_info = latest_vt.version_info();
                if latest_version_info.is_none()
                    || latest_version_info.unwrap().version < version_info.version
                {
                    latest_vt.update_version(
                        &version_info,
                        &data,
                        Some(vec![*remote_node_id.as_bytes()]),
                    )?;
                }
                drop(latest_vt);
            }
            Protocol::DataUnavailable => {}
            _ => bail!("illegal message received"),
        };

        Self::send_msg(Protocol::Done, &mut send).await?;
        Self::recv_msg(&mut recv).await?;
        Ok(())
    }

    async fn accept_handler(&self, conn: Connecting) -> Result<()> {
        let connection = conn.await?;
        let remote_node_id = iroh::endpoint::get_remote_node_id(&connection)?;
        let (mut send, mut recv) = connection.accept_bi().await?;
        let msg = Self::recv_msg(&mut recv).await?;

        match msg {
            Protocol::Request => {
                let latest_vt = { self.inner.latest_version.lock().await.clone() };

                if latest_vt.version_info().is_none() {
                    Self::send_msg(Protocol::DataUnavailable, &mut send).await?;
                    Self::send_msg(Protocol::Done, &mut send).await?;
                    return Ok(());
                }
                let resp =
                    Protocol::Data(latest_vt.version_info().unwrap(), latest_vt.data().unwrap());

                Self::send_msg(resp, &mut send).await?;
                Self::send_msg(Protocol::Done, &mut send).await?;
                Self::recv_msg(&mut recv).await?;

                self.inner
                    .latest_version
                    .lock()
                    .await
                    .add_node_id(remote_node_id.as_bytes());
            }
            _ => {
                bail!("Illegal request");
            }
        };

        send.finish()?;
        Ok(())
    }
}

trait PatcherPkarr {
    fn resolve_pkarr(
        &self,
        public_key: &[u8; PUBLIC_KEY_LENGTH],
    ) -> impl std::future::Future<Output = anyhow::Result<(VersionInfo, Vec<[u8; PUBLIC_KEY_LENGTH]>)>>
           + Send;
    fn publish_pkarr(&self) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
}

impl PatcherPkarr for Patcher {
    async fn resolve_pkarr(
        &self,
        public_key: &[u8; PUBLIC_KEY_LENGTH],
    ) -> anyhow::Result<(VersionInfo, Vec<[u8; PUBLIC_KEY_LENGTH]>)> {
        let client = PkarrClient::builder().build().unwrap();
        let pkarr_pk = PublicKey::try_from(public_key)?;

        match client.resolve(&pkarr_pk) {
            Ok(Some(pkg)) => {
                let packet = pkg.packet();

                let version = utils::decode_rdata::<Version>(packet, "_version")?;
                let hash = utils::decode_rdata::<[u8; PUBLIC_KEY_LENGTH]>(packet, "_hash")?;
                let signature = utils::decode_rdata::<Signature>(packet, "_signature")?;
                let trusted_key =
                    utils::decode_rdata::<[u8; PUBLIC_KEY_LENGTH]>(packet, "_trusted_key")?;
                let node_ids =
                    utils::decode_rdata::<Vec<[u8; PUBLIC_KEY_LENGTH]>>(packet, "_node_ids")?;

                Ok((
                    VersionInfo {
                        version,
                        hash,
                        signature,
                        trusted_key,
                    },
                    node_ids,
                ))
            }
            _ => bail!("failed to resolve package"),
        }
    }

    async fn publish_pkarr(&self) -> anyhow::Result<()> {
        let client = PkarrClient::builder().build().unwrap();
        let keypair = Keypair::from_secret_key(&self.secret_key);

        let lt = { self.inner.latest_version.lock().await.clone() };

        if lt.version_info().is_none() {
            bail!("no version available locally")
        }

        // Set reply id to unix time
        let vi = lt.version_info().unwrap();
        let mut last_reply_id: LastReplyId = LastReplyId::from_file(LAST_REPLY_ID_NAME).await.unwrap_or(LastReplyId(0));
        let mut packet = dns::Packet::new_reply(last_reply_id.0);
        
        // Not sure if rap around will cause an error so to be safe
        last_reply_id.0 = if last_reply_id.0 >= u16::MAX -1 {
            0
        } else {
            last_reply_id.0 + 1
        };
        let _ = last_reply_id.to_file("last_reply_id").await;


        // Version
        let version = serde_json::to_string(&vi.version)?;
        packet.answers.push(dns::ResourceRecord::new(
            dns::Name::new("_version").unwrap(),
            dns::CLASS::IN,
            30,
            dns::rdata::RData::TXT(version.as_str().try_into()?),
        ));
        // Signature
        let signature = serde_json::to_string(&vi.signature)?;
        packet.answers.push(dns::ResourceRecord::new(
            dns::Name::new("_signature").unwrap(),
            dns::CLASS::IN,
            30,
            dns::rdata::RData::TXT(signature.as_str().try_into()?),
        ));
        // Hash
        let hash = serde_json::to_string(&vi.hash)?;
        packet.answers.push(dns::ResourceRecord::new(
            dns::Name::new("_hash").unwrap(),
            dns::CLASS::IN,
            30,
            dns::rdata::RData::TXT(hash.as_str().try_into()?),
        ));
        // TrustedKey
        let trusted_key = serde_json::to_string(&self.trusted_key)?;
        packet.answers.push(dns::ResourceRecord::new(
            dns::Name::new("_trusted_key").unwrap(),
            dns::CLASS::IN,
            30,
            dns::rdata::RData::TXT(trusted_key.as_str().try_into()?),
        ));
        // NodeIds
        let node_ids = serde_json::to_string(&lt.node_ids())?;
        packet.answers.push(dns::ResourceRecord::new(
            dns::Name::new("_node_ids").unwrap(),
            dns::CLASS::IN,
            30,
            dns::rdata::RData::TXT(node_ids.as_str().try_into()?),
        ));

        let signed_packet = SignedPacket::from_packet(&keypair, &packet)?;
        let instant = Instant::now();

        match client.publish(&signed_packet) {
            Ok(()) => {
                println!(
                    "\nSuccessfully published {} in {:?}",
                    keypair.public_key(),
                    instant.elapsed(),
                );
            }
            Err(err) => {
                println!("\nFailed to publish {} \n {}", keypair.public_key(), err);
            }
        };

        Ok(())
    }
}

#[derive(Debug,Clone,Serialize,Deserialize)]
struct LastReplyId(u16);

impl ProtocolHandler for Patcher {
    fn accept(
        &self,
        conn: Connecting,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'static>> {
        let patcher = self.clone();

        Box::pin(async move {
            patcher.accept(conn).await?;
            Ok(())
        })
    }
}
