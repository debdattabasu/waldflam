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

/// One document's transition in a commit.
#[derive(Debug, Clone)]
pub struct DocumentDelta {
    pub path: ResourcePath,
    /// State before the commit; `None` = the document did not exist.
    pub before: Option<StoredDocument>,
    /// State after the commit; `None` = deleted.
    pub after: Option<StoredDocument>,
}

#[derive(Debug)]
pub struct CommitEvent {
    pub database: DatabaseName,
    pub changes: Vec<DocumentDelta>,
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
