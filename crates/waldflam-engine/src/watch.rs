//! Commit-event fan-out for Listen streams and triggers.
//!
//! Every applied commit publishes the final state of each changed document;
//! Listen streams subscribe and translate events into per-target changes.
//!
//! The bus itself is in-process, but it carries commits from the whole
//! cluster: each commit also records the paths it touched to a shared
//! collection, and `fanout` tails that collection and republishes other
//! instances' commits here. See `Origin` for what that costs.

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

/// Which instance applied the commit this event describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Applied here. Deltas are exact: `before` and `after` are the states
    /// the commit actually moved between.
    Local,
    /// Applied by another instance and learned from the shared event
    /// collection, which records only the paths a commit touched. `after` is
    /// read back from storage (so it reflects current state, not necessarily
    /// the state at that commit) and `before` is always `None`.
    ///
    /// That is enough for Listen, which needs `after` for document targets
    /// and only the paths for query targets. It is *not* enough for
    /// triggers, which classify create/update/delete from `before`. Triggers
    /// therefore only act on `Local` events — which is also what keeps each
    /// CloudEvent delivered once cluster-wide instead of once per instance.
    Remote,
}

#[derive(Debug)]
pub struct CommitEvent {
    pub database: DatabaseName,
    pub changes: Vec<DocumentDelta>,
    pub commit_us: i64,
    pub origin: Origin,
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
