//! Server-side transactions: optimistic read-set validation.
//!
//! Clients read with a transaction selector (we record each read document's
//! version), buffer writes locally, then Commit with the transaction id. At
//! commit we re-check every recorded version and answer `ABORTED` on any
//! mismatch — the one code that makes every client retry its transaction
//! function. A commit lock serializes validate+apply so concurrent commits
//! can't interleave between validation and persistence.
//!
//! TODO(snapshot-reads): reads see latest state, not a fixed snapshot;
//! wire Mongo snapshot sessions for true snapshot isolation.
//! TODO(phantoms): query read-sets record returned docs only, so a doc
//! *appearing* in a queried range after the read is not detected.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::EngineError;
use crate::path::DatabaseName;

const TXN_LIFETIME: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub struct TxnState {
    pub database: DatabaseName,
    pub read_only: bool,
    /// Document path → observed `update_time_us` (0 = observed missing).
    pub read_versions: HashMap<String, i64>,
    expires_at: Instant,
}

#[derive(Default)]
pub struct TransactionManager {
    counter: AtomicU64,
    active: Mutex<HashMap<Vec<u8>, TxnState>>,
    /// Serializes commit validate+apply sections.
    pub commit_lock: tokio::sync::Mutex<()>,
}

impl TransactionManager {
    pub fn begin(&self, database: &DatabaseName, read_only: bool) -> Vec<u8> {
        let id = self.counter.fetch_add(1, Ordering::Relaxed) + 1;
        let mut token = id.to_be_bytes().to_vec();
        token.extend_from_slice(&Instant::now().elapsed().as_nanos().to_be_bytes()[8..]);
        let mut active = self.active.lock().expect("txn lock");
        active.retain(|_, t| t.expires_at > Instant::now());
        active.insert(
            token.clone(),
            TxnState {
                database: database.clone(),
                read_only,
                read_versions: HashMap::new(),
                expires_at: Instant::now() + TXN_LIFETIME,
            },
        );
        token
    }

    /// Records a read observation (document version, or 0 for missing).
    /// First observation wins — later re-reads don't overwrite what the
    /// transaction originally saw.
    pub fn record_read(&self, token: &[u8], path: String, version_us: i64) {
        let mut active = self.active.lock().expect("txn lock");
        if let Some(state) = active.get_mut(token) {
            state.read_versions.entry(path).or_insert(version_us);
        }
    }

    /// Removes and returns the transaction for commit; expired or unknown
    /// ids answer `ABORTED` so clients retry cleanly.
    pub fn take(&self, token: &[u8], database: &DatabaseName) -> Result<TxnState, EngineError> {
        let mut active = self.active.lock().expect("txn lock");
        let state = active.remove(token).ok_or(EngineError::Aborted)?;
        if state.expires_at <= Instant::now() {
            return Err(EngineError::Aborted);
        }
        if state.database != *database {
            return Err(EngineError::InvalidArgument(
                "transaction belongs to a different database".into(),
            ));
        }
        Ok(state)
    }

    pub fn rollback(&self, token: &[u8]) {
        self.active.lock().expect("txn lock").remove(token);
    }
}

/// Re-checks every recorded read against current storage; any version drift
/// is `ABORTED`. Call with the commit lock held.
pub async fn validate_read_set(
    store: &crate::store::Store,
    state: &TxnState,
) -> Result<(), EngineError> {
    for (path, observed_us) in &state.read_versions {
        let parsed = crate::path::ResourcePath::parse(path)?;
        let current_us = store
            .get_document(&state.database, &parsed)
            .await?
            .map(|d| d.update_time_us)
            .unwrap_or(0);
        if current_us != *observed_us {
            return Err(EngineError::Aborted);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle() {
        let mgr = TransactionManager::default();
        let db = DatabaseName::new("p", "(default)");
        let token = mgr.begin(&db, false);
        mgr.record_read(&token, "c/d".into(), 42);
        mgr.record_read(&token, "c/d".into(), 99); // first observation wins
        mgr.record_read(&token, "c/missing".into(), 0);

        let state = mgr.take(&token, &db).unwrap();
        assert_eq!(state.read_versions["c/d"], 42);
        assert_eq!(state.read_versions["c/missing"], 0);
        // Second take: gone → ABORTED.
        assert!(matches!(mgr.take(&token, &db), Err(EngineError::Aborted)));

        let token = mgr.begin(&db, false);
        mgr.rollback(&token);
        assert!(matches!(mgr.take(&token, &db), Err(EngineError::Aborted)));

        // Wrong database.
        let token = mgr.begin(&db, false);
        let other = DatabaseName::new("other", "(default)");
        assert!(matches!(mgr.take(&token, &other), Err(EngineError::InvalidArgument(_))));
    }
}
