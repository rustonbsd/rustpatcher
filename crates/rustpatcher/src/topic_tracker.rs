use actor_helper::{Action, Actor, Handle, act_ok};
use distributed_topic_tracker::{RecordPublisher, unix_minute};
use ed25519_dalek::VerifyingKey;

#[derive(Debug,Clone)]
pub struct TopicTracker {
    api: Handle<TopicTrackerActor>,
}

#[derive(Debug)]
struct TopicTrackerActor {
    rx: tokio::sync::mpsc::Receiver<Action<TopicTrackerActor>>,

    record_publisher: RecordPublisher,
}

impl TopicTracker {
    pub fn new(record_publisher: RecordPublisher) -> Self {
        let (api, rx) = Handle::channel(32);
        tokio::spawn(async move {
            let mut actor = TopicTrackerActor {
                rx,
                record_publisher,
            };
            let _ = actor.run().await;
        });

        Self { api }
    }

    pub async fn get_node_ids(&self) -> anyhow::Result<Vec<VerifyingKey>> {
        self.api.call(act_ok!(actor => async move {
            actor.record_publisher.get_records(unix_minute(0)).await.iter().filter_map(|record| {
                VerifyingKey::from_bytes(&record.node_id()).ok()
            }).collect::<Vec<_>>()
        })).await
    }
}

impl Actor for TopicTrackerActor {
    async fn run(&mut self) -> anyhow::Result<()> {
        let mut write_ticker = tokio::time::interval(std::time::Duration::from_secs(60));
        write_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                Some(action) = self.rx.recv() => {
                    action(self).await
                }
                _ = write_ticker.tick() => {
                    let record = self.record_publisher.new_record(unix_minute(0),vec![], vec![]);
                    let res = self.record_publisher.publish_record(record).await;
                    println!("published record: {:?}", res.is_ok());
                }
            }
        }
    }
}
