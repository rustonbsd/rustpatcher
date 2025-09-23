use actor_helper::{Action, Actor, Handle};
use ed25519_dalek::VerifyingKey;

use crate::Patch;



#[derive(Debug,Clone)]
pub struct Patcher {
    api: Handle<PatcherActor>,
}

#[derive(Debug)]
struct PatcherActor {
    rx: tokio::sync::mpsc::Receiver<Action<PatcherActor>>,

    owner_pub_key: VerifyingKey,
    patch: Option<Patch>,

    // maybe intervals or notifiers and then intervals here so we can trigger a (new version update)
    // after setting the newest version for example. 
    // 
    // use self as data source always
    // only signature the owner does everything else every peer does. 
    // load data from own exec bytes
    // load version from own version identifier (from own bytes)
    // no loading versions or anything from storage.
    // owner signing key created once and then pub key stored in patcher
    // signing key stored on disk
    // load signing key only for owner new update
    
}

impl Patcher {
    pub fn new(owner_pub_key: VerifyingKey) -> Self {
        let (api, rx) = Handle::channel(32);
        tokio::spawn(async move {
            let mut actor = PatcherActor { rx, owner_pub_key, patch: None };
            if let Err(e) = actor.run().await {
                eprintln!("Patcher actor error: {:?}", e);
            }
        });
        
        Self { api }
    }
}

impl Actor for PatcherActor {
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