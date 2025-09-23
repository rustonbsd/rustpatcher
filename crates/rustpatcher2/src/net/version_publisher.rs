use actor_helper::{Action, Actor, Handle, act_ok};

use crate::Patch;

#[derive(Debug, Clone)]
pub struct Publisher {
    api: Handle<PublisherActor>,
}

#[derive(Debug)]
struct PublisherActor {
    rx: tokio::sync::mpsc::Receiver<Action<PublisherActor>>,

    interval: tokio::time::Interval,
    latest_patch: Option<Patch>,
}

impl Publisher {
    pub fn new() -> Self {
        let (api, rx) = Handle::channel(32);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            let mut actor = PublisherActor {
                rx,
                interval,
                latest_patch: None,
            };
            if let Err(e) = actor.run().await {
                eprintln!("VersionPublisher actor error: {:?}", e);
            }
        });
        Self { api }
    }

    pub async fn set_latest_patch(&self, patch: Patch) -> anyhow::Result<()> {
        self.api
            .call(act_ok!(actor => async move { actor.latest_patch = Some(patch)}))
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
                _ = self.interval.tick() => {
                    todo!("publish our patch if we have a owner-patch-signature and the version is newer or equal than the already listed patches");
                }
            }
        }
    }
}

impl PublisherActor {
    async fn publish_version(&mut self) -> anyhow::Result<()> {
        // load patch from disk if we have one
        // check if we have a owner-signing-key
        // if we have both sign the patch and publish it to the network
        Ok(())
    }
}
