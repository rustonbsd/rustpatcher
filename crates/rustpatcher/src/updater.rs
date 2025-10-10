use std::{
    env,
    ffi::{CString, OsString},
    io::Write,
    process, ptr,
};

use actor_helper::{Action, Actor, Handle};
use chrono::Timelike;
use distributed_topic_tracker::{RecordPublisher, unix_minute};
use iroh::NodeId;
use nix::libc;
use tracing::{error, info};

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

    self_path_before_replace: Option<OsString>,
}

impl Updater {
    pub fn new(
        mode: UpdaterMode,
        distributor: Distributor,
        record_publisher: RecordPublisher,
    ) -> Self {
        let (api, rx) = Handle::channel(32);
        tokio::spawn(async move {
            let mut try_update_interval =
                tokio::time::interval(tokio::time::Duration::from_secs(56));
            try_update_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            let mut actor = UpdaterActor {
                rx,
                mode,
                distributor,
                newer_patch: None,
                record_publisher,
                try_update_interval,
                self_path_before_replace: None,
            };
            if let Err(e) = actor.run().await {
                error!("Updater actor error: {:?}", e);
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
                                let t_offset = (now.hour() as i32 * 60 + now.minute() as i32) - (hour as i32 * 60 + minute as i32);
                                if matches!(t_offset, 0..2) {
                                    let _ = self.restart_after_update().await;
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
        let mut records = self.record_publisher.get_records(now).await;
        records.extend(self.record_publisher.get_records(now - 1).await);
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
        info!("Downloading patch {:?} from {:?}", patch_info, node_id);
        let res = self.distributor.get_patch(node_id, patch_info).await;
        info!("Downloaded patch: {:?}", res.is_ok());
        let patch = res?;
        self.newer_patch = Some(patch.clone());

        self.self_path_before_replace = Some(env::current_exe()?.into());

        let mut temp_file = tempfile::NamedTempFile::new()?;
        temp_file.write_all(patch.data())?;
        let path = temp_file.path();

        self_replace::self_replace(path)?;
        info!("Updated successfully to version {:?}", patch.info().version);

        if self.mode == UpdaterMode::Now {
            self.restart_after_update().await?;
        }
        Ok(())
    }

    async fn restart_after_update(&mut self) -> anyhow::Result<()> {
        let exe_raw = self
            .self_path_before_replace
            .clone()
            .ok_or(anyhow::anyhow!("no self path stored"))?;
        let exe = CString::new(exe_raw.to_str().unwrap())?;

        // The array must be null-terminated.
        let args: [*const libc::c_char; 1] = [ptr::null()];

        unsafe {
            info!("execv: {:?}", nix::libc::execv(exe.as_ptr(), args.as_ptr()));
        }
        process::exit(0);
    }
}
