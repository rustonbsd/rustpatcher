use actor_helper::{Action, Actor, Handle, act_ok};
use distributed_topic_tracker::{RecordPublisher, unix_minute};
use iroh::NodeId;
use tracing::warn;

use crate::{Patch, PatchInfo, Version};

#[derive(Debug, Clone)]
pub struct Publisher {
    api: Handle<PublisherActor>,
}

#[derive(Debug, Clone)]
pub enum PublisherState {
    Publishing,
    NewerAvailable,
}

#[derive(Debug)]
struct PublisherActor {
    rx: tokio::sync::mpsc::Receiver<Action<PublisherActor>>,
    state: PublisherState,

    interval: tokio::time::Interval,
    self_patch: Patch,
    record_publisher: RecordPublisher,

    update_starter: tokio::sync::mpsc::Sender<()>,
}

impl Publisher {
    pub fn new(
        record_publisher: RecordPublisher,
        update_starter: tokio::sync::mpsc::Sender<()>,
    ) -> anyhow::Result<Self> {
        let self_patch = Patch::from_self()?;
        let (api, rx) = Handle::channel(32);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(55));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            let mut actor = PublisherActor {
                rx,
                state: PublisherState::Publishing,
                interval,
                self_patch,
                record_publisher,
                update_starter,
            };
            if let Err(e) = actor.run().await {
                eprintln!("VersionPublisher actor error: {:?}", e);
            }
        });
        Ok(Self { api })
    }

    pub async fn get_record_publisher(&self) -> anyhow::Result<RecordPublisher> {
        self.api
            .call(act_ok!(actor => async move {
                actor.record_publisher.clone()
            }))
            .await
    }
}

impl Actor for PublisherActor {
    async fn run(&mut self) -> anyhow::Result<()> {
        loop {
            tokio::select! {
                Some(action) = self.rx.recv() => {
                    action(self).await
                }
                _ = self.interval.tick(), if matches!(self.state, PublisherState::Publishing) => {
                    let now = unix_minute(0);
                    let records = self.record_publisher.get_records(now).await;
                    warn!("Checked for records, found {} records", records.len());
                    let c_version = Version::current()?;
                    let newer_patch_infos = records
                        .iter()
                        .filter_map(|r| if let Ok(patch_info) = r.content::<PatchInfo>(){
                            if let Ok(node_id) = NodeId::from_bytes(&r.node_id()) {
                                warn!("Found patch info: {:?}{:?}", node_id,patch_info);
                                Some((node_id,patch_info.clone()))
                            } else {
                                None
                            }
                        } else {
                            None
                        })
                        .filter(|(_,p)| p.version > c_version)
                        .collect::<Vec<(NodeId, PatchInfo)>>();

                    warn!("Checked for updates, found {} newer versions", newer_patch_infos.len());
                    if newer_patch_infos.is_empty() {
                        let res = self.publish_self(now).await;
                        println!("Published self: {:?}", res);
                        continue;
                    }
                    self.state = PublisherState::NewerAvailable;
                    let _ = self.update_starter.send(()).await;
                }
            }
        }
    }
}

impl PublisherActor {
    async fn publish_self(&mut self, unix_minute: u64) -> anyhow::Result<()> {
        let record = self
            .record_publisher
            .new_record(unix_minute, self.self_patch.info().clone())?;
        self.record_publisher.publish_record(record).await
    }
}
