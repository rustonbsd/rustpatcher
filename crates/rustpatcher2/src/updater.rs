use std::{ffi::CString, io::Write, process, ptr};

use actor_helper::{Action, Actor, Handle};
use chrono::Timelike;
use distributed_topic_tracker::{RecordPublisher, unix_minute};
use iroh::NodeId;
use nix::libc;

use crate::{Patch, PatchInfo, Version, distributor::Distributor};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UpdaterMode {
    Now,
    OnRestart,
    At(u8, u8), // hour, minute
}

#[derive(Debug, Clone)]
pub struct Updater {
    _api: Handle<UpdaterActor>,
}

#[derive(Debug)]
struct UpdaterActor {
    rx: tokio::sync::mpsc::Receiver<Action<UpdaterActor>>,
    distributor: Distributor,

    mode: UpdaterMode,
    newer_patch: Option<Patch>,
    record_publisher: RecordPublisher,
    try_update_interval: tokio::time::Interval,
}

impl Updater {
    pub fn new(
        mode: UpdaterMode,
        distributor: Distributor,
        record_publisher: RecordPublisher,
    ) -> Self {
        let (api, rx) = Handle::channel(32);
        tokio::spawn(async move {
            let mut try_update_interval = tokio::time::interval(tokio::time::Duration::from_secs(56));
            try_update_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            let mut actor = UpdaterActor {
                rx,
                mode,
                distributor,
                newer_patch: None,
                record_publisher,
                try_update_interval,
            };
            if let Err(e) = actor.run().await {
                eprintln!("Updater actor error: {:?}", e);
            }
        });
        Self { _api: api }
    }
}

impl Actor for UpdaterActor {
    async fn run(&mut self) -> anyhow::Result<()> {
        loop {
            tokio::select! {
                Some(action) = self.rx.recv() => {
                    action(self).await
                }
                _ = self.try_update_interval.tick() => {
                    if self.newer_patch.is_none() {
                        let patches = self.check_for_updates().await?;
                        for (node_id, patch_info) in patches {
                            if self.try_download_patch(node_id, patch_info).await.is_ok() {
                                break;
                            }
                        }
                    } else {
                        match self.mode {
                            UpdaterMode::Now => {
                                self.restart_after_update().await?;
                            },
                            UpdaterMode::OnRestart => {
                                // do nothing, wait for next restart
                            },
                            UpdaterMode::At(hour, minute) => {
                                let now = chrono::Local::now();
                                // prob midnight rollover bug here, fine for now [!] todo
                                if (now.hour() * 60 + now.minute()) as u8 >= (hour * 60 + minute) {
                                    self.restart_after_update().await?;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

impl UpdaterActor {
    async fn check_for_updates(&mut self) -> anyhow::Result<Vec<(NodeId, PatchInfo)>> {
        let now = unix_minute(0);
        let records = self.record_publisher.get_records(now).await;
        let c_version = Version::current()?;
        let mut newer_patch_infos = records
            .iter()
            .filter_map(|r| {
                if let Ok(patch_info) = r.content::<PatchInfo>() {
                    if let Ok(node_id) = NodeId::from_bytes(&r.node_id()) {
                        Some((node_id, patch_info.clone()))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .filter(|(_, p)| p.version > c_version)
            .collect::<Vec<(NodeId, PatchInfo)>>();

        if newer_patch_infos.is_empty() {
            return Ok(vec![]);
        }
        newer_patch_infos.sort_by_key(|(_, p)| p.version.clone());
        newer_patch_infos.reverse();

        let newest = newer_patch_infos[0].clone();
        Ok(newer_patch_infos
            .iter()
            .filter(|(_, p)| p.version == newest.1.version)
            .cloned()
            .collect::<Vec<_>>())
    }

    async fn try_download_patch(
        &mut self,
        node_id: NodeId,
        patch_info: PatchInfo,
    ) -> anyhow::Result<()> {
        println!("Downloading patch {:?} from {:?}", patch_info, node_id);
        let res = self.distributor.get_patch(node_id, patch_info).await;
        println!("Downloaded patch: {:?}", res.is_ok());
        let patch = res?;
        self.newer_patch = Some(patch.clone());

        let mut temp_file = tempfile::NamedTempFile::new()?;
        temp_file.write_all(&patch.data())?;
        let path = temp_file.path();

        self_replace::self_replace(path)?;
        println!("Updated successfully to version {:?}", patch.info().version);
        Ok(())
    }

    async fn restart_after_update(&mut self) -> anyhow::Result<()> {
        let exe_raw = std::env::current_exe()?;
        let exe = CString::new(exe_raw.to_str().unwrap())?;

        // The array must be null-terminated.
        let args: [*const libc::c_char; 1] = [ptr::null()];

        unsafe {
            println!("execv: {:?}", nix::libc::execv(exe.as_ptr(), args.as_ptr()));
        }
        process::exit(0);
    }
}
