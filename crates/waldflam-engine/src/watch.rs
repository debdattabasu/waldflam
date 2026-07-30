//! Commit-event fan-out for Listen streams.
//!
//! Every applied commit publishes the final state of each changed document;
//! Listen streams subscribe and translate events into per-target changes.
//!
//! TODO(multi-instance): this is an in-process bus — all writes flow through
//! this server. For horizontal scaling, back it with Mongo change streams.

use std::sync::Arc;

use tokio::sync::broadcast;

use crate::path::{DatabaseName, ResourcePath};
use crate::store::StoredDocument;

#[derive(Debug)]
pub struct CommitEvent {
    pub database: DatabaseName,
    /// Final state per changed document; `None` = deleted.
    pub changes: Vec<(ResourcePath, Option<StoredDocument>)>,
    pub commit_us: i64,
}

#[derive(Debug)]
pub struct WatchHub {
    tx: broadcast::Sender<Arc<CommitEvent>>,
}

impl Default for WatchHub {
    fn default() -> Self {
        Self { tx: broadcast::channel(1024).0 }
    }
}

impl WatchHub {
    pub fn publish(&self, event: CommitEvent) {
        // No subscribers is fine.
        let _ = self.tx.send(Arc::new(event));
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<CommitEvent>> {
        self.tx.subscribe()
    }
}
