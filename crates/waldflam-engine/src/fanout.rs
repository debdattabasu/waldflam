//! Cluster-wide commit fan-out.
//!
//! Each commit records the paths it touched to a shared collection (inside
//! its own transaction — see `commit`). This tails that collection with a
//! MongoDB change stream and republishes *other* instances' commits onto the
//! local `WatchHub`, so a Listen stream served by one instance sees writes
//! applied by any of them.
//!
//! Notices carry paths only, so the tail reads current state back from
//! storage to build each delta. That makes remote events `Origin::Remote`:
//! good enough for Listen, not for triggers. See `watch::Origin`.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;

use crate::path::{DatabaseName, ResourcePath};
use crate::store::{CommitNotice, Store};
use crate::watch::{CommitEvent, DocumentDelta, Origin, WatchHub};

/// How long to wait before rebuilding a change stream that errored, so a
/// MongoDB outage doesn't turn into a reconnect storm.
const RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// Starts tailing commit notices in the background. Runs until the process
/// exits, rebuilding its change stream (resuming where it left off) on error.
pub fn spawn(store: Store, hub: Arc<WatchHub>) {
    tokio::spawn(async move {
        let mut resume_token = None;
        loop {
            let mut stream = match store.watch_commit_notices(resume_token.clone()).await {
                Ok(stream) => stream,
                Err(error) => {
                    tracing::warn!(%error, "commit fan-out: cannot open change stream");
                    tokio::time::sleep(RECONNECT_DELAY).await;
                    continue;
                }
            };
            tracing::debug!(instance = store.instance_id(), "commit fan-out: tailing");
            while let Some(next) = stream.next().await {
                match next {
                    Ok(event) => {
                        resume_token = stream.resume_token();
                        let Some(notice) = event.full_document else {
                            continue;
                        };
                        // Our own commits already went out in-process.
                        if notice.instance == store.instance_id() {
                            continue;
                        }
                        if let Some(event) = rebuild(&store, notice).await {
                            hub.publish(event);
                        }
                    }
                    Err(error) => {
                        tracing::warn!(%error, "commit fan-out: change stream failed, resuming");
                        break;
                    }
                }
            }
            tokio::time::sleep(RECONNECT_DELAY).await;
        }
    });
}

/// Turns a path-only notice into an event Listen can act on by reading each
/// path's current state. A path that reads back as missing was deleted.
async fn rebuild(store: &Store, notice: CommitNotice) -> Option<CommitEvent> {
    let database = DatabaseName::new(notice.project_id, notice.database_id);
    let mut changes = Vec::with_capacity(notice.paths.len());
    for raw in &notice.paths {
        let Ok(path) = ResourcePath::parse(raw) else {
            tracing::warn!(path = raw, "commit fan-out: unparsable path in notice");
            continue;
        };
        let after = match store.get_document(&database, &path).await {
            Ok(after) => after,
            Err(error) => {
                tracing::warn!(%error, path = raw, "commit fan-out: cannot read changed document");
                continue;
            }
        };
        changes.push(DocumentDelta { path, before: None, after });
    }
    if changes.is_empty() {
        return None;
    }
    Some(CommitEvent { database, changes, commit_us: notice.commit_us, origin: Origin::Remote })
}
