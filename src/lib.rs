pub mod data;
pub mod utils;

use std::{
    any::Any, cmp::min, future::Future, pin::Pin, str::FromStr, sync::{mpsc::Sender, Arc}, time::Instant
};

use anyhow::{bail, Result};
use data::{Inner, Patcher, Protocol, Version, VersionInfo, VersionTracker};
use ed25519_dalek::{Signature, SigningKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
use iroh::{
    endpoint::{Connecting, Endpoint, RecvStream, SendStream},
    protocol::ProtocolHandler,
    NodeAddr, NodeId, SecretKey,
};
use iroh_topic_tracker::topic_tracker::{self, TopicTracker};
use pkarr::{dns, Keypair, PkarrClient, PublicKey, SignedPacket};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{
        mpsc::{self, Receiver},
        Mutex,
    },
    time::sleep,
};
use utils::{
    Storage, LAST_REPLY_ID_NAME, LATEST_VERSION_NAME, PKARR_PUBLISHING_INTERVAL, SECRET_KEY_NAME,
};

use crate::utils::wait_for_relay;

pub struct Builder {
    secret_key: [u8; SECRET_KEY_LENGTH],
    trusted_key: Option<[u8; PUBLIC_KEY_LENGTH]>,
    load_latest_version_from_file: bool,
    load_secret_key_from_file: bool,
    master_node: bool,
}

impl Builder {
    pub fn new() -> Self {
        Self {
            secret_key: SecretKey::generate(rand::rngs::OsRng).to_bytes(),
            trusted_key: None,
            load_latest_version_from_file: true,
            load_secret_key_from_file: true,
            master_node: false,
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
            if let Ok(secret_key) = SecretKey::from_file(SECRET_KEY_NAME).await {
                self.secret_key = secret_key.to_bytes();
                if self.trusted_key.is_some() && SigningKey::from_bytes(&self.secret_key).verifying_key().as_bytes().eq(&self.trusted_key.unwrap()) {
                    // Master node here
                    self.master_node = true;
                    println!("Master node");
                }
            }
        }

        // Iroh setup
        let secret_key = SecretKey::from_bytes(&self.secret_key);
        let endpoint = Endpoint::builder()
            .secret_key(secret_key)
            .discovery_n0()
            .bind()
            .await?;

        let topic_tracker = TopicTracker::new(&endpoint);
        let patcher = if self.load_latest_version_from_file {
            let latest_version = VersionTracker::from_file(LATEST_VERSION_NAME).await;
            
            if latest_version.is_ok() {
                let latest_version = latest_version.unwrap();
                let mut trusted_packet = None;
                if self.master_node {
                    trusted_packet = Some(latest_version.as_signed_packet(&self.secret_key).await?);
                }
                Patcher::with_latest_version(
                    &self.trusted_key.unwrap(),
                    &endpoint,
                    &topic_tracker,
                    trusted_packet,
                    latest_version,
                )
            } else {
                Patcher::with_endpoint(&self.trusted_key.unwrap(), &endpoint,&topic_tracker)
            }
        } else {
            Patcher::with_endpoint(&self.trusted_key.unwrap(), &endpoint,&topic_tracker)
        };
        let _router = iroh::protocol::Router::builder(endpoint.clone())
            .accept(Patcher::ALPN, patcher.clone())
            .accept(TopicTracker::ALPN, topic_tracker.clone())
            .spawn()
            .await?;

        Ok(patcher._spawn().await?)
    }
}

impl Patcher {
    pub const ALPN: &'static [u8] = b"iroh/patcher/1";
    const MAX_MSG_SIZE_BYTES: u64 = 1024 * 1024 * 1024;
    pub fn new() -> Builder {
        Builder::new()
    }

    pub async fn persist(self) -> anyhow::Result<()> {
        let inner = self.inner.clone();
        let lv = inner.latest_version.lock().await.clone();
        lv.to_file(LATEST_VERSION_NAME).await?;

        Ok(())
    }
}
trait TPatcher: Sized {
    fn with_endpoint(
        trusted_key: &[u8; PUBLIC_KEY_LENGTH],
        endpoint: &Endpoint,
        topic_tracker: &TopicTracker,
    ) -> Self;
    fn with_latest_version(
        trusted_key: &[u8; PUBLIC_KEY_LENGTH],
        endpoint: &Endpoint,
        topic_tracker: &TopicTracker,
        SignedPacket: Option<SignedPacket>,
        latest_version: VersionTracker,
    ) -> Self;
    async fn _spawn(self) -> Result<Self>;
    async fn _spawn_pkarr_publish(self) -> Result<()>;
    async fn _spawn_pkarr_trusted_publish(self) -> Result<Receiver<VersionInfo>>;
    async fn _spawn_updater(self, trusted_update_notifier: Receiver<VersionInfo>) -> Result<()>;
    async fn _spawn_topic_tracker_update(self) -> Result<()>;
    async fn topic_tracker_update(self) -> Result<()>;
    async fn update(self: &mut Self, new_version_info: VersionInfo) -> Result<()>;
}

impl TPatcher for Patcher {
    fn with_endpoint(
        trusted_key: &[u8; PUBLIC_KEY_LENGTH],
        endpoint: &Endpoint,
        topic_tracker: &TopicTracker,
    ) -> Self {
        Self::with_latest_version(
            trusted_key,
            endpoint,
            topic_tracker,
            None,
            VersionTracker::new(trusted_key),
        )
    }

    fn with_latest_version(
        trusted_key: &[u8; PUBLIC_KEY_LENGTH],
        endpoint: &Endpoint,
        topic_tracker: &TopicTracker,
        signed_packet: Option<SignedPacket>,
        latest_version: VersionTracker,
    ) -> Self {

        let me = Self {
            trusted_key: trusted_key.clone(),
            inner: Inner {
                endpoint: endpoint.clone(),
                topic_tracker: topic_tracker.clone(),
                latest_version: Arc::new(Mutex::new(latest_version)),
                latest_trusted_package: Arc::new(Mutex::new(signed_packet)),
            },
            secret_key: endpoint.secret_key().to_bytes(),
            public_key: endpoint.node_id().as_bytes().clone(),
        };
        me
    }


    // Publish the latest version_tracker own file under own key
    async fn _spawn_pkarr_publish(self) -> Result<()> {
        tokio::spawn({
            let me = self.clone();
            async move {
                loop {
                    let version_tracker = { me.inner.latest_version.lock().await.clone() };
                    if version_tracker.version_info().is_some() && version_tracker.data().is_some()
                    {
                        let res = me.publish_pkarr().await;
                    }
                    sleep(PKARR_PUBLISHING_INTERVAL).await;
                }
            }
        });
        Ok(())
    }

    async fn _spawn_pkarr_trusted_publish(self) -> Result<Receiver<VersionInfo>> {
        let (tx, rx) = mpsc::channel(1);

        tokio::spawn({
            let me = self.clone();
            async move {
                loop {
                    if let Ok((trusted_version_info, trusted_signed_packet)) =
                        me.resolve_pkarr(&me.trusted_key).await
                    {
                        // Check if latest_trusted_packet is the same
                        {
                            let l_trusted_packet =
                                self.inner.latest_trusted_package.lock().await.clone();
                            if l_trusted_packet.clone().is_some()
                                && l_trusted_packet
                                    .unwrap()
                                    .as_bytes()
                                    .eq(trusted_signed_packet.as_bytes())
                            {
                                // Same packet as last time (no update)
                                println!("no update");
                                sleep(PKARR_PUBLISHING_INTERVAL).await;
                                continue;
                            }
                        }

                        // new trusted packet
                        println!("tp bytes: {} {}",z32::encode(trusted_signed_packet
                            .public_key()
                            .as_bytes()),z32::encode(&me.trusted_key));
                        if trusted_signed_packet
                            .public_key()
                            .as_bytes()
                            .eq(&me.trusted_key)
                        {
                            println!("trusted_signed_packet: {}",trusted_signed_packet.public_key().to_z32());

                            // check if newer version update notifier
                            let lt = me.inner.latest_version.lock().await.clone();

                            // Check for newer version signed packet even exists at all
                            {
                                let me_signed_package = me.inner.latest_trusted_package.lock().await.clone();
                                println!("ME: {}",me_signed_package.is_some());
                                if me_signed_package.is_none() || lt.version_info().is_none() || (lt.version_info().is_some() && trusted_version_info.version > lt.version_info().unwrap().version) {
                                    let mut signed_packet  = self.inner.latest_trusted_package.lock().await;
                                    *signed_packet = Some(trusted_signed_packet);
                                    println!("Signed packet replaced:!");
                                }
                            }

                            // 
                            if lt.version_info().is_none() || trusted_version_info.version > lt.version_info().unwrap().version {
                                let vtc = self.inner.latest_version.lock().await.clone();
                                if vtc.version_info().is_none() || vtc.version_info().unwrap().version < trusted_version_info.version {
                                    println!("Send update notification: {:?}",trusted_version_info.version);
                                    let _ = tx.send(trusted_version_info).await;
                                }
                            }
                        }
                    } else {
                        println!("Failed to resolve trusted key!");
                    }

                    println!("Publishing pkrarrar");
                    let a = self.publish_trusted_pkarr().await;
                    println!("published trusted: {a:?}");

                    sleep(PKARR_PUBLISHING_INTERVAL).await;
                }
            }
        });
        Ok(rx)
    }

    async fn _spawn_updater(
        self,
        mut trusted_update_notifier: Receiver<VersionInfo>,
    ) -> Result<()> {
        let my_version = Version::from_str(env!("CARGO_PKG_VERSION"))?;
        tokio::spawn({
            let me = self.clone();
            async move {
                while let Some(potential_update) = trusted_update_notifier.recv().await {
                    println!("Potential new version _spawn_updater: {}",potential_update.version.to_string());
                    if my_version < potential_update.version {
                        match me.clone().update(potential_update).await {
                            Ok(_) => {
                                let _ = me.clone().topic_tracker_update().await;
                                println!("Update successfull")
                            },
                            Err(err) => println!("Update attempt failed: {err}"),
                        }
                    }
                }
            }
        });
        Ok(())
    }

    async fn update(self: &mut Self, new_version_info: VersionInfo) -> Result<()> {
        // Update
        // 1. Find node ids
        // 2. Try update from node ids
        println!("update: version {}",new_version_info.version.to_string());
        
        // 1. Find node ids via topic tracker
        let topic_tracker = self.inner.topic_tracker.clone();
        let node_ids = topic_tracker.get_topic_nodes(&new_version_info.to_topic_hash()?).await?;
        println!("update: found node_ids: {:?}",node_ids);
        for node_id in node_ids.clone() {
            // 2. try and update
            match self
                .try_update(iroh::PublicKey::from_bytes(&node_id.as_bytes()).unwrap())
                .await
            {
                Ok(_) => {
                    println!(
                        "New version downloaded: {:?}",
                        self.inner.latest_version.lock().await
                    );
                    let _ = self.clone().persist().await;
                    return Ok(())
                }
                Err(err) => {
                    println!("failed: {err}");
                    let mut lt = self.inner.latest_version.lock().await;
                    lt.rm_node_id(&node_id.as_bytes());
                }
            }
        }
        bail!("no node ids found")
    }

    async fn _spawn(self) -> Result<Self> {
        
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
        

        self.clone()._spawn_pkarr_publish().await?;
        let notifier = self.clone()._spawn_pkarr_trusted_publish().await?;
        self.clone()._spawn_updater(notifier).await?;
        self.clone()._spawn_topic_tracker_update().await?;

        Ok(self)
    }
    
    async fn _spawn_topic_tracker_update(self) -> Result<()> {
        tokio::spawn({
            let me = self.clone();
            async move {
                loop {
                    let res = me.clone().topic_tracker_update().await;
                    println!("topic tracker update: {:?}",res);
                    sleep(PKARR_PUBLISHING_INTERVAL).await
                }
            }
        });
        Ok(())
    }
    
    async fn topic_tracker_update(self) -> Result<()> {
        if let Some(vi) = self.inner.latest_version.lock().await.version_info() {
            if let Ok(topic_hash) = vi.to_topic_hash() {
                let _ = self.inner.topic_tracker.clone().get_topic_nodes(&topic_hash).await;
            }
        }
        Ok(())
    }
}

trait TPatcherIroh: Sized {
    async fn send_msg(msg: Protocol, send: &mut SendStream) -> Result<()>;
    async fn recv_msg(recv: &mut RecvStream) -> Result<Protocol>;
    async fn accept_handler(&self, conn: Connecting) -> Result<()>;
    async fn try_update(self: &mut Self, node_id: NodeId) -> Result<()>;
}

impl TPatcherIroh for Patcher {
    async fn send_msg(msg: Protocol, send: &mut SendStream) -> Result<()> {
        println!("Send msg: {:?}",msg.type_id());
        let encoded = postcard::to_stdvec(&msg)?;
        assert!(encoded.len() <= Self::MAX_MSG_SIZE_BYTES as usize);

        send.write_u64_le(encoded.len() as u64).await?;
        let chunk_size = 1024;
        println!("Send chunk count: {chunk_size}");
        let chunks = encoded.chunks(chunk_size).into_iter().collect::<Vec<&[u8]>>();
        for mut chunk in chunks {
            //println!("Iroh-Sending {}",chunk.len());
            println!("Send attepmt: {:?}",send.write_all(&mut chunk).await);
            println!("chunk: {chunk:?}");
        }
        
        Ok(())
    }

    async fn recv_msg(recv: &mut RecvStream) -> Result<Protocol> {
        let len = recv.read_u64_le().await? as usize;
        println!("Starting to receive... {len}");

        assert!(len <= Self::MAX_MSG_SIZE_BYTES as usize);

        let mut buffer = [0u8; 1024];
        let mut data = Vec::with_capacity(len);

        while let Some(size) = recv.read(&mut buffer).await? {
            data.extend_from_slice(&buffer[..min(size,len-data.len())]);

            if data.len() == len {
                break;
            }
        }

        println!("Data");
        let msg: Protocol = postcard::from_bytes(&data)?;
        println!("Recv msg: {msg:?}");
        Ok(msg)
    }

    async fn try_update(self: &mut Self, node_id: NodeId) -> Result<()> {
        println!("try update");
        let (node_version_info, _) = self.resolve_pkarr(node_id.as_bytes()).await?;
        {
            println!("pkrr res: ");
            let me_version_info = self.inner.latest_version.lock().await.version_info();
            // if we dont have an inner version update
            if me_version_info.is_some()
                && node_version_info.version <= me_version_info.unwrap().version
            {
                bail!("node version not newer {}",node_version_info.version.to_string())
            }
        }

        wait_for_relay(&self.inner.endpoint).await?;
        println!("got record: {:?}",z32::encode(node_id.as_bytes()));

        let conn = self
            .inner
            .endpoint
            .connect(NodeAddr::new(node_id), Self::ALPN)
            .await?;

        println!("update: connected to {}",z32::encode(node_id.as_bytes()));
        let (mut send, mut recv) = conn.open_bi().await?;

        let msg = Protocol::Request;
        println!("pre send");
        //Self::send_msg(msg, &mut send).await?;
        println!("update: Req send: {:?}",Self::send_msg(msg, &mut send).await);

        match Self::recv_msg(&mut recv).await? {
            Protocol::Data(version_info, data) => {
                println!("update: data received: {}",data.len());
                let mut latest_vt = self.inner.latest_version.lock().await;
                let latest_version_info = latest_vt.version_info();
                if latest_version_info.is_none()
                    || latest_version_info.unwrap().version < version_info.version
                {
                    // Signature checked in update_version
                    // as low as possible
                    latest_vt.update_version(
                        &version_info,
                        &data,
                        Some(vec![*node_id.as_bytes()]),
                    )?;
                }
                drop(latest_vt);
            }
            Protocol::DataUnavailable => {}
            other => {
                println!("accepted - illegal msg: {:?}", other);
                 bail!("illegal message received")},
        };

        Self::send_msg(Protocol::Done, &mut send).await?;
        //Self::recv_msg(&mut recv).await?;
        Ok(())
    }

    async fn accept_handler(&self, conn: Connecting) -> Result<()> {
        let connection = conn.await?;
        let remote_node_id = iroh::endpoint::get_remote_node_id(&connection)?;
        println!("accept - new connection accepted: {}",z32::encode(remote_node_id.as_bytes()));

        let (mut send, mut recv) = connection.accept_bi().await?;
        let msg = Self::recv_msg(&mut recv).await;
        println!("accepted - Raw:msg: {msg:?}");
        let msg = msg?;
        println!("accepted - First recv");

        match msg {
            Protocol::Request => {
                println!("accept - Request");
                let latest_vt = { self.inner.latest_version.lock().await.clone() };

                if latest_vt.version_info().is_none() {
                    println!("accept - Data unavailable");
                    Self::send_msg(Protocol::DataUnavailable, &mut send).await?;
                    //Self::send_msg(Protocol::Done, &mut send).await?;
                    return Ok(());
                }
                let resp =
                    Protocol::Data(latest_vt.version_info().unwrap(), latest_vt.data().unwrap());

                Self::send_msg(resp, &mut send).await?;
                //Self::send_msg(Protocol::Done, &mut send).await?;
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

trait TPatcherPkarr: Sized {
    fn resolve_pkarr(
        &self,
        public_key: &[u8; PUBLIC_KEY_LENGTH],
    ) -> impl std::future::Future<Output = anyhow::Result<(VersionInfo, SignedPacket)>> + Send;
    fn publish_pkarr(&self) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    fn publish_trusted_pkarr(&self)
        -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
}

impl TPatcherPkarr for Patcher {
    async fn resolve_pkarr(
        &self,
        public_key: &[u8; PUBLIC_KEY_LENGTH],
    ) -> anyhow::Result<(VersionInfo, SignedPacket)> {
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
               
                Ok((
                    VersionInfo {
                        version,
                        hash,
                        signature,
                        trusted_key,
                    },
                    pkg,
                ))
            }
            _ => bail!("failed to resolve package"),
        }
    }

    async fn publish_trusted_pkarr(&self) -> anyhow::Result<()> {
        let signed_packet = { self.inner.latest_trusted_package.lock().await.clone() };
        println!("Signed packet: {}",signed_packet.is_some());
        if let Some(signed_packet) = signed_packet {
            let client = PkarrClient::builder().build().unwrap();
            println!("publish attempt");
            return match client.publish(&signed_packet) {
                Ok(_) => Ok(()),
                Err(err) => bail!("bail {}",err),
            };
        }
        bail!("nomb")
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
        let mut last_reply_id: LastReplyId = LastReplyId::from_file(LAST_REPLY_ID_NAME)
            .await
            .unwrap_or(LastReplyId(0));
        let mut packet = dns::Packet::new_reply(last_reply_id.0);

        // Not sure if rap around will cause an error so to be safe
        last_reply_id.0 = if last_reply_id.0 >= u16::MAX - 1 {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
