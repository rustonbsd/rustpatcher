pub mod data;
pub mod utils;
pub mod version_embed;

pub use rustpatcher_macros::main;

use std::{
    cmp::min, env, ffi::CString, future::Future, io::Write, num::NonZero, pin::Pin, ptr, sync::Arc,
    time::Duration,
};

use anyhow::{bail, Result};
use bytes::Bytes;
use data::{Auth, AuthRequest, Inner, Patcher, Protocol, Version, VersionInfo, VersionTracker};
use ed25519_dalek::{
    ed25519::signature::SignerMut, Signature, SigningKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH,
};
use iroh::{
    endpoint::{Connecting, Endpoint, RecvStream, SendStream},
    protocol::ProtocolHandler,
    NodeAddr, NodeId, SecretKey,
};
use iroh_topic_tracker::topic_tracker::TopicTracker;
use nix::libc::{self};
use pkarr::{dns, Keypair, PkarrClient, PublicKey, SignedPacket};
use rand::{rngs::OsRng, Rng};
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{
        mpsc::{self, Receiver},
        Mutex,
    },
    time::sleep,
};
use utils::{
    compute_hash, get_app_version, Storage, LAST_REPLY_ID_NAME, LAST_TRUSTED_PACKAGE,
    LATEST_VERSION_NAME, PKARR_PUBLISHING_INTERVAL, PUBLISHER_SIGNING_KEY_NAME,
    PUBLISHER_TRUSTED_KEY_NAME, SECRET_KEY_NAME, SHARED_SECRET_KEY_NAME,
};

use crate::utils::wait_for_relay;

#[derive(Debug, Clone)]
pub struct Builder {
    secret_key: [u8; SECRET_KEY_LENGTH],
    trusted_key: Option<[u8; PUBLIC_KEY_LENGTH]>,
    shared_secret_key: Option<[u8; SECRET_KEY_LENGTH]>,
    load_latest_version_from_file: bool,
    load_secret_key_from_file: bool,
    master_node: bool,
    trusted_packet: Option<SignedPacket>,
    update_interval: Duration,
}

impl Builder {
    pub fn new() -> Self {
        Self {
            secret_key: SecretKey::generate(rand::rngs::OsRng).to_bytes(),
            shared_secret_key: None,
            trusted_key: None,
            load_latest_version_from_file: true,
            load_secret_key_from_file: true,
            master_node: false,
            trusted_packet: None,
            update_interval: PKARR_PUBLISHING_INTERVAL,
        }
    }

    pub fn load_latest_version_from_file(mut self, val: bool) -> Self {
        self.load_latest_version_from_file = val;
        self
    }

    pub fn update_interval(mut self, update_interval: Duration) -> Self {
        self.update_interval = update_interval;
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

    pub fn shared_secret_key(mut self, shared_secret_key: &[u8; SECRET_KEY_LENGTH]) -> Self {
        self.shared_secret_key = Some(*shared_secret_key);
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

    pub fn shared_secret_key_from_z32_str(mut self, shared_secret_key: &str) -> Self {
        let sk = z32::decode(shared_secret_key.as_bytes());
        if sk.is_err() {
            return self;
        }

        let mut shared_secret_key_buf = [0u8; PUBLIC_KEY_LENGTH];
        shared_secret_key_buf.copy_from_slice(sk.unwrap().as_slice());
        self.shared_secret_key = Some(shared_secret_key_buf);
        self
    }

    async fn check_cli(self) -> anyhow::Result<()> {
        let args: Vec<String> = env::args().collect();

        if args.len() == 3 && "rustpatcher".eq(&args[1]) {
            match args[2].as_str() {
                "init" => {
                    self.init().await?;
                    std::process::exit(0);
                }
                "publish" => {
                    self.publish().await?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn init(self) -> anyhow::Result<()> {
        let publisher_signing_key = {
            if let Ok(secret_key) = SecretKey::from_file(PUBLISHER_SIGNING_KEY_NAME).await {
                SigningKey::from_bytes(&secret_key.to_bytes())
            } else {
                let mut csprng = OsRng;
                let signing_key = SigningKey::generate(&mut csprng);

                // persist generated keys
                signing_key
                    .clone()
                    .to_file(PUBLISHER_SIGNING_KEY_NAME)
                    .await?;
                signing_key
                    .clone()
                    .verifying_key()
                    .to_file(PUBLISHER_TRUSTED_KEY_NAME)
                    .await?;
                signing_key
            }
        };

        let shared_key = {
            if let Ok(secret_key) = SecretKey::from_file(SHARED_SECRET_KEY_NAME).await {
                SigningKey::from_bytes(&secret_key.to_bytes())
            } else {
                let mut csprng = OsRng;
                let signing_key = SigningKey::generate(&mut csprng);

                // persist generated keys
                signing_key.clone().to_file(SHARED_SECRET_KEY_NAME).await?;
                signing_key
            }
        };

        println!("");
        println!("");
        println!("New Signing key generated in ./patcher/publisher_signing_key!");
        println!("");
        println!(
            "   Trusted-Key = {}",
            z32::encode(publisher_signing_key.verifying_key().as_bytes())
        );
        println!("   Shared-Secret = {}", z32::encode(shared_key.as_bytes()));
        println!("");
        println!("Insert the new trusted key into the patcher builder:");
        println!("");
        println!(
            r#"let patcher = Patcher::new()
    .trusted_key_from_z32_str("{}")
    .shared_secret_key_from_z32_str("{}")
    .build()
    .await?;"#,
            z32::encode(publisher_signing_key.verifying_key().as_bytes()),
            z32::encode(shared_key.as_bytes())
        );
        println!("");
        println!("");

        Ok(())
    }

    async fn publish(self) -> anyhow::Result<()> {
        let version = get_app_version()?;
        let file_path = std::env::current_exe()?;
        let mut file = File::open(file_path).await?;
        let mut buf = vec![];
        file.read_to_end(&mut buf).await?;

        println!("Version: {version:?}");

        let mut publisher_signing_key = {
            if let Ok(secret_key) = SecretKey::from_file(PUBLISHER_SIGNING_KEY_NAME).await {
                SigningKey::from_bytes(&secret_key.to_bytes())
            } else {
                let mut csprng = OsRng;
                let signing_key = SigningKey::generate(&mut csprng);

                // persist generated keys
                signing_key
                    .clone()
                    .to_file(PUBLISHER_SIGNING_KEY_NAME)
                    .await?;
                signing_key
                    .clone()
                    .verifying_key()
                    .to_file(PUBLISHER_TRUSTED_KEY_NAME)
                    .await?;
                signing_key
            }
        };

        let node_secret_key = {
            if let Ok(secret_key) = ed25519_dalek::SecretKey::from_file(SECRET_KEY_NAME).await {
                secret_key
            } else {
                let signing_key = *publisher_signing_key.as_bytes();
                signing_key.clone().to_file(SECRET_KEY_NAME).await?;
                signing_key
            }
        };

        if !publisher_signing_key.as_bytes().eq(&node_secret_key) {
            anyhow::bail!(
                "secret key and publisher signing key don't match. not allowed for trusted node"
            )
        }

        let signature = publisher_signing_key.sign(&buf.as_slice());
        let hash = compute_hash(&buf);
        let trusted_key = publisher_signing_key.verifying_key().as_bytes().clone();

        let version_info = VersionInfo {
            version,
            hash,
            signature,
        };
        let version_tracker = VersionTracker::load(
            &trusted_key,
            &version_info,
            &buf.clone().into(),
            vec![node_secret_key],
        )?;
        version_tracker.to_file(LATEST_VERSION_NAME).await?;

        println!(
            "Signature validation check: {:?}",
            VersionTracker::verify_data(&trusted_key, &version_info, &buf.clone().into())
        );

        println!("Sig: {}", z32::encode(&signature.to_bytes()));
        println!("hash: {}", z32::encode(&hash));
        println!("trusted: {}", z32::encode(&trusted_key));

        println!("Publish successfull!");

        Ok(())
    }

    pub async fn build(self: &mut Self) -> anyhow::Result<Patcher> {
        self.clone().check_cli().await?;

        if self.trusted_key.is_none() {
            bail!("trusted key required")
        }
        if self.shared_secret_key.is_none() {
            bail!("shared secret key required")
        }

        if self.load_secret_key_from_file {
            if let Ok(secret_key) = SecretKey::from_file(SECRET_KEY_NAME).await {
                self.secret_key = secret_key.to_bytes();
                if self.trusted_key.is_some()
                    && SigningKey::from_bytes(&self.secret_key)
                        .verifying_key()
                        .as_bytes()
                        .eq(&self.trusted_key.unwrap())
                {
                    // Master node here
                    self.master_node = true;
                    println!("Master node");
                }
            }
        }

        if let Ok(bytes) = Vec::from_file(LAST_TRUSTED_PACKAGE).await {
            self.trusted_packet = Some(SignedPacket::from_bytes(&Bytes::copy_from_slice(
                bytes.as_slice(),
            ))?);
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
                if self.master_node {
                    self.trusted_packet =
                        Some(latest_version.as_signed_packet(&self.secret_key).await?);
                    println!("master mode");
                }
                Patcher::with_latest_version(
                    &self.trusted_key.unwrap(),
                    &self.shared_secret_key.unwrap(),
                    &endpoint,
                    &topic_tracker,
                    self.trusted_packet.clone(),
                    latest_version,
                    self.update_interval,
                )
            } else {
                let me = Patcher::with_latest_version(
                    &self.trusted_key.unwrap(),
                    &self.shared_secret_key.unwrap(),
                    &endpoint,
                    &topic_tracker,
                    self.trusted_packet.clone(),
                    VersionTracker::new(&self.trusted_key.unwrap()),
                    self.update_interval,
                );
                me
            }
        } else {
            Patcher::with_latest_version(
                &self.trusted_key.unwrap(),
                &self.shared_secret_key.unwrap(),
                &endpoint,
                &topic_tracker,
                self.trusted_packet.clone(),
                VersionTracker::new(&self.trusted_key.unwrap()),
                self.update_interval,
            )
        };

        let _router = iroh::protocol::Router::builder(endpoint.clone())
            .accept(&patcher.ALPN(), patcher.clone())
            .spawn()
            .await?;

        Ok(patcher._spawn().await?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SigPackage(pub Vec<u8>);

impl Patcher {
    const MAX_MSG_SIZE_BYTES: u64 = 1024 * 1024 * 1024;
    pub fn new() -> Builder {
        Builder::new()
    }

    #[allow(non_snake_case)]
    pub fn ALPN(&self) -> Vec<u8> {
        let shared_key = SigningKey::from_bytes(&self.shared_secret_key);
        let verifying_key = shared_key.verifying_key();
        format!("{}/0", z32::encode(verifying_key.as_bytes())).into_bytes()
    }

    pub async fn persist(&self) -> anyhow::Result<()> {
        let inner = self.inner.clone();
        let lv = inner.latest_version.lock().await.clone();
        println!("persist: {:?}", lv.to_file(LATEST_VERSION_NAME).await);

        let secret_key = self.secret_key.clone();
        secret_key.to_file(SECRET_KEY_NAME).await?;

        if let Some(lp) = inner.latest_trusted_package.lock().await.clone() {
            lp.as_bytes()
                .clone()
                .to_vec()
                .to_file(LAST_TRUSTED_PACKAGE)
                .await?;
        }

        Ok(())
    }

    pub async fn update_available(self) -> Result<bool> {
        let lv = self.inner.latest_version.lock().await.clone();
        let version = get_app_version()?;
        let patcher_version = lv.version_info();

        Ok(patcher_version.is_some() && version < patcher_version.unwrap().version)
    }

    pub async fn try_update(self) -> Result<()> {
        if self.clone().update_available().await? == false {
            bail!("no update available")
        }
        let lv = self.clone().inner.latest_version.lock().await.clone();
        if lv.data().is_none() {
            bail!("no new version found in version tracker")
        }
        let data = lv.data().unwrap();
        let mut temp_file = tempfile::NamedTempFile::new()?;
        temp_file.write_all(&data)?;
        let path = temp_file.path();

        // Get exe path before self_replace.
        // after: it will add "[..] (deleted)"
        // to the end of the filename on ubuntu (maybe all linux).
        let exe_raw = std::env::current_exe()?;
        let exe = CString::new(exe_raw.to_str().unwrap())?;

        self_replace::self_replace(path)?;

        // The array must be null-terminated.
        let args: [*const libc::c_char; 1] = [ptr::null()];

        unsafe {
            libc::execv(exe.as_ptr(), args.as_ptr());
        }
        Ok(())
    }
}
trait TPatcher: Sized {
    fn with_latest_version(
        trusted_key: &[u8; PUBLIC_KEY_LENGTH],
        shared_secret_key: &[u8; SECRET_KEY_LENGTH],
        endpoint: &Endpoint,
        topic_tracker: &TopicTracker,
        signed_packet: Option<SignedPacket>,
        latest_version: VersionTracker,
        pkarr_publishing_interval: Duration,
    ) -> Self;
    async fn _spawn(self) -> Result<Self>;
    async fn _spawn_pkarr_publish(self) -> Result<()>;
    async fn _spawn_pkarr_trusted_publish(self) -> Result<Receiver<VersionInfo>>;
    async fn _spawn_updater(
        self,
        trusted_update_notifier: Receiver<VersionInfo>,
        tracker_update_notifier: Receiver<VersionInfo>,
    ) -> Result<()>;
    async fn _spawn_topic_tracker_update(self) -> Result<Receiver<VersionInfo>>;
    async fn topic_tracker_update(self) -> Result<Vec<iroh::PublicKey>>;
    async fn update(self: &mut Self, new_version_info: VersionInfo) -> Result<()>;
}

impl TPatcher for Patcher {
    fn with_latest_version(
        trusted_key: &[u8; PUBLIC_KEY_LENGTH],
        shared_secret_key: &[u8; SECRET_KEY_LENGTH],
        endpoint: &Endpoint,
        topic_tracker: &TopicTracker,
        signed_packet: Option<SignedPacket>,
        latest_version: VersionTracker,
        pkarr_publishing_interval: Duration,
    ) -> Self {
        let me = Self {
            trusted_key: trusted_key.clone(),
            shared_secret_key: shared_secret_key.clone(),
            inner: Inner {
                endpoint: endpoint.clone(),
                topic_tracker: topic_tracker.clone(),
                latest_version: Arc::new(Mutex::new(latest_version)),
                latest_trusted_package: Arc::new(Mutex::new(signed_packet)),
                pkarr_publishing_interval: pkarr_publishing_interval,
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
                        let _ = me.publish_pkarr().await;
                        //println!("pub: {:?}",res);
                    }
                    sleep(self.inner.pkarr_publishing_interval).await;
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
                        if trusted_signed_packet
                            .public_key()
                            .as_bytes()
                            .eq(&me.trusted_key)
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
                                    println!("no update"); //, {:?}",me.inner.latest_version.lock().await.version_info());
                                    let _ = self.publish_trusted_pkarr().await;
                                    sleep(self.inner.pkarr_publishing_interval).await;
                                    continue;
                                }
                            }

                            // Different package candidate

                            //println!("trusted_signed_packet: {}",trusted_signed_packet.public_key().to_z32());

                            // check if newer version update notifier
                            let lt = me.inner.latest_version.lock().await.clone();

                            // Check for newer version signed packet even exists at all
                            {
                                let me_signed_package =
                                    me.inner.latest_trusted_package.lock().await.clone();
                                //println!("me signed package: {:?}", me_signed_package);
                                if me_signed_package.is_none()
                                    || (lt.version_info().is_some()
                                        && trusted_version_info.version
                                            > lt.version_info().unwrap().version)
                                {
                                    let mut signed_packet =
                                        self.inner.latest_trusted_package.lock().await;
                                    *signed_packet = Some(trusted_signed_packet);
                                    drop(signed_packet);
                                    let _ = self.persist().await;
                                    println!("Signed packet replaced");
                                }
                            }

                            // Update notifier
                            if lt.version_info().is_none()
                                || trusted_version_info.version > lt.version_info().unwrap().version
                            {
                                let vtc = self.inner.latest_version.lock().await.clone();
                                if vtc.version_info().is_none()
                                    || vtc.version_info().unwrap().version
                                        < trusted_version_info.version
                                {
                                    //println!("Send update notification: {:?}",trusted_version_info.version);
                                    let _ = tx.send(trusted_version_info).await;
                                }
                            }
                        }
                    } else {
                        //println!("Failed to resolve trusted key!");
                    }

                    //println!("Publishing pkrarrar");
                    let _ = self.publish_trusted_pkarr().await;
                    //println!("published trusted: {a:?}");

                    sleep(self.inner.pkarr_publishing_interval).await;
                }
            }
        });
        Ok(rx)
    }

    async fn _spawn_updater(
        self,
        mut trusted_update_notifier: Receiver<VersionInfo>,
        mut tracker_update_notifier: Receiver<VersionInfo>,
    ) -> Result<()> {
        let my_version = get_app_version()?;
        tokio::spawn({
            let me = self.clone();
            async move {
                loop {
                    tokio::select! {
                        Some(trusted_potential_update) = trusted_update_notifier.recv() => {
                            println!(
                                "RCs: {}",
                                trusted_potential_update.version.to_string()
                            );
                            if my_version < trusted_potential_update.version || me.clone().inner.latest_version.lock().await.clone().data().is_none() {
                                println!("Starting to update!");
                                match me.clone().update(trusted_potential_update).await {
                                    Ok(_) => {
                                    }
                                    Err(_) => println!("Update attempt failed: "),
                                }
                            }
                        }
                        Some(tracker_potential_update) = tracker_update_notifier.recv() => {
                            println!(
                                "RCs: {}",
                                tracker_potential_update.version.to_string()
                            );
                            if my_version < tracker_potential_update.version || me.clone().inner.latest_version.lock().await.clone().data().is_none() {
                                println!("Starting to update!");
                                match me.clone().update(tracker_potential_update).await {
                                    Ok(_) => {
                                        println!("Update successfull")
                                    }
                                    Err(_) => println!("Update attempt failed: "),
                                }
                            }
                        }
                        //todo
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
        println!("update: version {}", new_version_info.version.to_string());

        // 1. Find node ids via topic tracker
        let topic_tracker = self.inner.topic_tracker.clone();
        let node_ids = topic_tracker
            .get_topic_nodes(&new_version_info.to_topic_hash(self.shared_secret_key)?)
            .await?;
        println!("update: found node_ids: {:?}", node_ids);
        for node_id in node_ids.clone() {
            // 2. try and update
            match self
                .try_update(iroh::PublicKey::from_bytes(&node_id.as_bytes()).unwrap())
                .await
            {
                Ok(_) => {
                    println!("New version downloaded");
                    return Ok(());
                }
                Err(err) => {
                    println!("New version download failed: {err:?}");
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
                                    let res = me3.accept_handler(conn).await;
                                    println!("accept - {res:?}");
                                }
                            });
                        }
                        Err(_) => {
                            println!("Failed to connect");
                        }
                    }
                }
            }
        });

        let tracker_notifier = self.clone()._spawn_topic_tracker_update().await?;
        self.clone()._spawn_pkarr_publish().await?;
        let notifier = self.clone()._spawn_pkarr_trusted_publish().await?;
        self.clone()
            ._spawn_updater(notifier, tracker_notifier)
            .await?;

        Ok(self)
    }

    async fn _spawn_topic_tracker_update(self) -> Result<Receiver<VersionInfo>> {
        let (tx, rx) = mpsc::channel(1024);

        tokio::spawn({
            let me = self.clone();
            async move {
                loop {
                    let node_ids = me.clone().topic_tracker_update().await;
                    if let Ok(node_ids) = node_ids {
                        for node_id in node_ids {
                            if let Ok((vi, _)) = me.resolve_pkarr(&node_id.as_bytes()).await {
                                let _ = tx.send(vi).await;
                            }
                        }
                    }
                    sleep(self.inner.pkarr_publishing_interval).await
                }
            }
        });
        Ok(rx)
    }

    async fn topic_tracker_update(self) -> Result<Vec<iroh::PublicKey>> {
        let lv = self.inner.latest_version.lock().await.clone();
        if let Some(vi) = lv.version_info() {
            if let Ok(topic_hash) = vi.to_topic_hash(self.shared_secret_key) {
                return self.inner.topic_tracker.get_topic_nodes(&topic_hash).await;
            }
        }
        Ok(vec![])
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
        let encoded = postcard::to_stdvec(&msg)?;
        assert!(encoded.len() <= Self::MAX_MSG_SIZE_BYTES as usize);

        send.write_u64_le(encoded.len() as u64).await?;
        let chunk_size = 1024;
        let chunks = encoded
            .chunks(chunk_size)
            .into_iter()
            .collect::<Vec<&[u8]>>();
        for mut chunk in chunks {
            send.write_all(&mut chunk).await?;
        }

        Ok(())
    }

    async fn recv_msg(recv: &mut RecvStream) -> Result<Protocol> {
        println!("starting to recv msg");
        let len = recv.read_u64_le().await? as usize;
        println!("Recv: len: {len}");

        assert!(len <= Self::MAX_MSG_SIZE_BYTES as usize);

        let mut buffer = [0u8; 1024];
        let mut data = Vec::with_capacity(len);

        while let Some(size) = recv.read(&mut buffer).await? {
            data.extend_from_slice(&buffer[..min(size, len - data.len())]);

            if data.len() == len {
                break;
            }
        }

        let msg: Protocol = postcard::from_bytes(&data)?;
        Ok(msg)
    }

    async fn try_update(self: &mut Self, node_id: NodeId) -> Result<()> {
        //println!("try update");
        let (node_version_info, _) = self.resolve_pkarr(node_id.as_bytes()).await?;
        {
            //println!("pkrr res: ");
            let me_version_info = self.inner.latest_version.lock().await.version_info();
            // if we dont have an inner version update
            println!(
                "try_update: me version info: is_some == {}",
                me_version_info.is_some()
            );
            if me_version_info.is_some()
                && node_version_info.version <= me_version_info.unwrap().version
            {
                bail!(
                    "node version not newer {}",
                    node_version_info.version.to_string()
                )
            }
        }

        wait_for_relay(&self.inner.endpoint).await?;
        println!("update: got record: {:?}", z32::encode(node_id.as_bytes()));

        let conn = self
            .inner
            .endpoint
            .connect(NodeAddr::new(node_id), &self.ALPN())
            .await?;

        let (mut send, mut recv) = conn.open_bi().await?;
        println!("update: connected to {}", z32::encode(node_id.as_bytes()));

        Self::send_msg(Protocol::Ready, &mut send).await?;

        // 1 . Receive auth token to sign with shared key
        match Self::recv_msg(&mut recv).await? {
            Protocol::AuthRequest(auth_request) => {
                let mut key = SigningKey::from_bytes(&self.shared_secret_key);
                let request = Protocol::Request(Auth {
                    signature: key.sign(&auth_request.sign_request),
                });
                Self::send_msg(request, &mut send).await?
            }
            _ => bail!("expected auth request got something different"),
        }

        // Await data request after successfull auth
        match Self::recv_msg(&mut recv).await? {
            Protocol::Data(version_info, data) => {
                println!("update: data received: {}", data.len());
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
                self.persist().await?;

                self.publish_pkarr().await?;
                println!("After data received and lv overwrite pkarr published");
            }
            Protocol::DataUnavailable => {}
            _ => {
                println!("update - illegal msg or auth failure");
                bail!("illegal message received")
            }
        };

        Self::send_msg(Protocol::Done, &mut send).await?;

        //Self::recv_msg(&mut recv).await?;
        Ok(())
    }

    async fn accept_handler(&self, conn: Connecting) -> Result<()> {
        let connection = conn.await?;
        let remote_node_id = iroh::endpoint::get_remote_node_id(&connection)?;

        println!("accept - splitting streams");
        let (mut send, mut recv) = connection.accept_bi().await?;
        println!(
            "accept - new connection accepted: {}",
            z32::encode(remote_node_id.as_bytes())
        );

        match Self::recv_msg(&mut recv).await? {
            Protocol::Ready => {
                println!("accept - starting auth")
            }
            _ => bail!("illegal command"),
        };

        // 1 . Send auth request
        let token = rand::thread_rng().gen::<[u8; 32]>();
        let auth_req = Protocol::AuthRequest(AuthRequest {
            sign_request: token.to_vec().into(),
        });
        Self::send_msg(auth_req, &mut send).await?;

        // 2 . recv auth token signed with shared key
        let request = Self::recv_msg(&mut recv).await?;
        match request {
            Protocol::Request(auth) => {
                let key = SigningKey::from_bytes(&self.shared_secret_key);
                if key.verify(&token, &auth.signature).is_err() {
                    println!("auth failure");
                    bail!("authentication failed")
                }
            }
            _ => bail!("Illegal request"),
        };

        // 3 . after auth confirmation send data
        println!("accepted - auth successfull");
        println!("accept - sending data...");
        let latest_vt = { self.inner.latest_version.lock().await.clone() };

        if latest_vt.version_info().is_none() {
            println!("accept - Data unavailable");
            Self::send_msg(Protocol::DataUnavailable, &mut send).await?;
            //Self::send_msg(Protocol::Done, &mut send).await?;
            return Ok(());
        }
        let resp = Protocol::Data(latest_vt.version_info().unwrap(), latest_vt.data().unwrap());

        Self::send_msg(resp, &mut send).await?;
        //Self::send_msg(Protocol::Done, &mut send).await?;
        Self::recv_msg(&mut recv).await?;

        self.inner
            .latest_version
            .lock()
            .await
            .add_node_id(remote_node_id.as_bytes());

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
    fn pkarr_dht_relay_switch_get(
        &self,
        public_key: &[u8; PUBLIC_KEY_LENGTH],
    ) -> impl std::future::Future<Output = Result<Option<SignedPacket>>> + Send;
    fn pkarr_dht_relay_switch_put(
        &self,
        public_key: &[u8; PUBLIC_KEY_LENGTH],
        signed_packet: SignedPacket,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}

impl TPatcherPkarr for Patcher {
    async fn resolve_pkarr(
        &self,
        public_key: &[u8; PUBLIC_KEY_LENGTH],
    ) -> anyhow::Result<(VersionInfo, SignedPacket)> {
        match self.pkarr_dht_relay_switch_get(public_key).await {
            Ok(Some(pkg)) => {
                let packet = pkg.packet();

                let version = utils::decode_rdata::<Version>(packet, "_version")?;
                let hash = utils::decode_rdata::<[u8; PUBLIC_KEY_LENGTH]>(packet, "_hash")?;
                let signature = utils::decode_rdata::<Signature>(packet, "_signature")?;

                Ok((
                    VersionInfo {
                        version,
                        hash,
                        signature,
                    },
                    pkg,
                ))
            }
            _ => bail!("failed to resolve package: {}", z32::encode(public_key)),
        }
    }

    async fn publish_trusted_pkarr(&self) -> anyhow::Result<()> {
        let signed_packet = { self.inner.latest_trusted_package.lock().await.clone() };
        //println!("Signed packet: {}",signed_packet.is_some());
        if let Some(signed_packet) = signed_packet {
            //println!("publish attempt: {:?}", signed_packet.packet());
            return match self
                .pkarr_dht_relay_switch_put(&self.trusted_key, signed_packet)
                .await
            {
                Ok(_) => Ok(()),
                Err(err) => bail!("bail {}", err),
            };
        }
        bail!("nomb")
    }

    async fn publish_pkarr(&self) -> anyhow::Result<()> {
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

        let keypair = Keypair::from_secret_key(&self.secret_key);
        let signed_packet = SignedPacket::from_packet(&keypair, &packet)?;

        match self
            .pkarr_dht_relay_switch_put(&self.public_key, signed_packet)
            .await
        {
            Ok(_) => {}
            Err(err) => {
                println!("pkarr pub: {err}");
            }
        };

        Ok(())
    }

    async fn pkarr_dht_relay_switch_get(
        &self,
        public_key: &[u8; PUBLIC_KEY_LENGTH],
    ) -> Result<Option<SignedPacket>> {
        let mut signed_package = None;

        // Pkarr Relay server
        let req_client = reqwest::ClientBuilder::new().build()?;
        if let Ok(resp) = req_client
            .request(
                Method::GET,
                format!("https://relay.pkarr.org/{}", z32::encode(public_key)),
            )
            .send()
            .await
        {
            if resp.status() == StatusCode::OK {
                if let Ok(content) = resp.bytes().await {
                    let pub_key = PublicKey::try_from(public_key)?;
                    if let Ok(_signed_package) =
                        SignedPacket::from_relay_payload(&pub_key, &content)
                    {
                        println!("PKARR GET RELAY");
                        return Ok(Some(_signed_package));
                    }
                }
            }
        }

        // Pkarr dht
        if let Ok(client) = PkarrClient::builder()
            .cache_size(NonZero::new(1).unwrap())
                .build() {
                
            let pkarr_pk = PublicKey::try_from(public_key)?;
            if let Ok(_signed_package) = client.resolve(&pkarr_pk) {
                signed_package = _signed_package;

                println!("PKARR GET DHT");
            }

            Ok(signed_package)
        } else {
            bail!("failed to get package by public_key: {}",z32::encode(public_key))
        }
    }

    async fn pkarr_dht_relay_switch_put(
        &self,
        public_key: &[u8; PUBLIC_KEY_LENGTH],
        signed_packet: SignedPacket,
    ) -> Result<()> {
        // Pkarr Relay server
        let req_client = reqwest::ClientBuilder::new().build()?;
        let packet_bytes: Vec<u8> = signed_packet.as_bytes()[32..].to_vec();

        if let Ok(resp) = req_client
            .request(
                Method::PUT,
                format!("https://relay.pkarr.org/{}", z32::encode(public_key)),
            )
            .body(packet_bytes)
            .send()
            .await
        {
            if resp.status() == StatusCode::OK || resp.status() == StatusCode::CONFLICT {
                println!("PKARR PUT RELAY");
                return Ok(());
            }
            let s = resp.status();
            let text = resp.text().await;
            println!("resp {:?} {:?}", &text, s);
        }

        // Pkarr dht
        if let Ok(client) = PkarrClient::builder().build() {
            match client.publish(&signed_packet) {
                Ok(_) => {
                    println!("PKARR PUT DHT");
                    Ok(())
                }
                Err(_) => bail!(
                    "dht and relay failed to publish pkarr record for nodeid: {}",
                    z32::encode(public_key)
                ),
            }
        } else {
            bail!(
                "dht and relay failed to publish pkarr record for nodeid: {}",
                z32::encode(public_key)
            )
        }
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
