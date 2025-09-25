use std::{str::FromStr, sync::Mutex};

use actor_helper::{Action, Actor, Handle};
use distributed_topic_tracker::{RecordPublisher,RecordTopic};
use iroh::{protocol::Router, Endpoint};
use once_cell::sync::OnceCell;
use sha2::Digest;
use tracing::warn;

use crate::{Distributor, Publisher, Updater, UpdaterMode};

static PATCHER: OnceCell<Mutex<Option<Patcher>>> = OnceCell::new();

pub async fn run(update_mode: UpdaterMode) -> anyhow::Result<()> {
    if PATCHER.get().is_none() {
        let patcher = Patcher::builder().updater_mode(update_mode).build().await?;
        let _ = PATCHER.set(Mutex::new(Some(patcher)));
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct Builder {
    updater_mode: UpdaterMode,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            updater_mode: UpdaterMode::Now,
        }
    }
}

impl Builder {

    pub fn updater_mode(mut self, mode: UpdaterMode) -> Self {
        self.updater_mode = mode;
        self
    }

    pub async fn build(self) -> anyhow::Result<Patcher> {
        let secret_key = iroh::SecretKey::generate(rand::rngs::OsRng);
        let topic_id = RecordTopic::from_str(format!(
            "rustpatcher:{}",
            z32::encode(crate::embed::get_owner_pub_key().as_bytes())
        ).as_str())?;
        let mut hash = sha2::Sha512::new();
        hash.update(topic_id.hash());
        hash.update("v1");
        let initial_secret = hash.finalize().to_vec();

        let record_publisher = RecordPublisher::new(
            topic_id,
            secret_key.public().public(),
            secret_key.secret().clone(),
            None,
            initial_secret,
        );

        let (update_starter, update_receiver) = tokio::sync::mpsc::channel(1);
        let publisher = Publisher::new(record_publisher, update_starter)?;

        let endpoint = Endpoint::builder()
            .secret_key(secret_key.clone())
            //.add_discovery(DnsDiscovery::n0_dns())
            .discovery_n0()
            .bind()
            .await?;

        let distributor = Distributor::new(endpoint.clone())?;

        let _router = iroh::protocol::Router::builder(endpoint.clone())
            .accept(Distributor::ALPN(), distributor.clone())
            .spawn();

        Ok(Patcher::new(
            publisher,
            self.updater_mode,
            update_receiver,
            distributor,
            endpoint,
            _router,
        ))
    }
}

#[derive(Debug, Clone)]
pub struct Patcher {
    _api: Handle<PatcherActor>,
}

#[derive(Debug)]
struct PatcherActor {
    rx: tokio::sync::mpsc::Receiver<Action<PatcherActor>>,

    publisher: Publisher,
    updater: Option<Updater>,
    updater_mode: UpdaterMode,
    distributor: Distributor,

    _endpoint: Endpoint,
    _router: Router,

    update_receiver: tokio::sync::mpsc::Receiver<()>,
}

impl Patcher {
    pub fn builder() -> Builder {
        Builder::default()
    }

    fn new(
        publisher: Publisher,
        updater_mode: UpdaterMode,
        update_receiver: tokio::sync::mpsc::Receiver<()>,
        distributor: Distributor,
        endpoint: Endpoint,
        router: Router,
    ) -> Self {
        let (api, rx) = Handle::channel(32);
        tokio::spawn(async move {
            let mut actor = PatcherActor {
                rx,
                publisher,
                updater: None,
                _endpoint: endpoint,
                _router: router,
                updater_mode,
                update_receiver,
                distributor,
            };
            if let Err(e) = actor.run().await {
                eprintln!("Patcher actor error: {:?}", e);
            }
        });

        Self { _api: api }
    }
}

impl Actor for PatcherActor {
    async fn run(&mut self) -> anyhow::Result<()> {
        loop {
            tokio::select! {
                Some(action) = self.rx.recv() => {
                    action(self).await
                }
                Some(_) = self.update_receiver.recv(), if self.updater.is_none() => {
                    warn!("update notification received from Publisher, starting Updater");
                    if let Ok(record_publisher) = self.publisher.get_record_publisher().await {
                        self.updater = Some(Updater::new(self.updater_mode.clone(),self.distributor.clone(),record_publisher));
                    } else {
                        anyhow::bail!("Failed to get RecordPublisher for Updater");
                    }
                }
            }
        }
    }
}
