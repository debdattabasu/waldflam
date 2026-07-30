//! Cluster fan-out against a real MongoDB replica set (docker compose up -d).
//!
//! Two `Store`s on one database stand in for two waldflam instances: they get
//! distinct instance ids, so one's commits are another's remote events.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use waldflam_engine::commit::apply_commit;
use waldflam_engine::fanout;
use waldflam_engine::path::DatabaseName;
use waldflam_engine::store::Store;
use waldflam_engine::watch::{CommitEvent, Origin, WatchHub};
use waldflam_proto::v1::value::ValueType;
use waldflam_proto::v1::write::Operation;
use waldflam_proto::v1::{Document, Value, Write};

async fn store() -> Store {
    let uri = std::env::var("WALDFLAM_TEST_MONGO")
        .unwrap_or_else(|_| "mongodb://127.0.0.1:27017/?directConnection=true".into());
    Store::connect(&uri).await.expect("MongoDB not reachable — run `docker compose up -d`")
}

/// Unique per run *and* per test: these tests run concurrently and assert on
/// what they don't receive, so two of them sharing a database name would make
/// one observe the other's commits. The clock alone isn't enough — threads
/// starting in the same microsecond can read the same value.
fn test_db(label: &str) -> DatabaseName {
    let nanos =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    DatabaseName::new(format!("fanout-{label}-{nanos}"), "(default)")
}

fn set_write(name: &str, key: &str, value: i64) -> Write {
    Write {
        operation: Some(Operation::Update(Document {
            name: name.into(),
            fields: HashMap::from([(
                key.to_owned(),
                Value { value_type: Some(ValueType::IntegerValue(value)) },
            )]),
            ..Default::default()
        })),
        ..Default::default()
    }
}

/// Waits for an event on `database`, ignoring commits other tests make
/// against the same shared notice collection.
async fn next_event_for(
    events: &mut tokio::sync::broadcast::Receiver<Arc<CommitEvent>>,
    database: &DatabaseName,
    within: Duration,
) -> Option<Arc<CommitEvent>> {
    tokio::time::timeout(within, async {
        loop {
            match events.recv().await {
                Ok(event) if event.database == *database => return Some(event),
                Ok(_) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => return None,
            }
        }
    })
    .await
    .ok()
    .flatten()
}

/// Gives the change stream time to open before the commit it must observe —
/// a stream started afterwards would never see it.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(1_500)).await;
}

/// The point of the whole exercise: a commit applied by one instance shows up
/// on another instance's hub, which is what lets a Listen stream served
/// anywhere see a write made anywhere.
#[tokio::test]
async fn a_commit_on_one_instance_reaches_another() {
    let writer = store().await;
    let watcher = store().await;
    assert_ne!(writer.instance_id(), watcher.instance_id(), "instances must be distinguishable");

    let db = test_db("reaches-peer");
    let hub = Arc::new(WatchHub::default());
    let mut events = hub.subscribe();
    fanout::spawn(watcher.clone(), hub.clone());
    settle().await;

    let name = format!("{}/rooms/lobby", db.documents_root());
    apply_commit(&writer, &db, &[set_write(&name, "occupants", 3)], 7_000).await.unwrap();

    let event = next_event_for(&mut events, &db, Duration::from_secs(15))
        .await
        .expect("the other instance's commit should arrive");

    assert_eq!(event.origin, Origin::Remote, "a peer's commit is a remote event");
    assert_eq!(event.commit_us, 7_000);
    let delta = event.changes.first().expect("one changed document");
    assert_eq!(delta.path.to_string(), "rooms/lobby");
    let after = delta.after.as_ref().expect("state read back from storage");
    assert_eq!(
        after.fields.get("occupants").and_then(|v| v.value_type.clone()),
        Some(ValueType::IntegerValue(3))
    );
    assert!(delta.before.is_none(), "notices carry no before-image (see watch::Origin)");
}

/// An instance must not re-deliver its own commits: those already went out
/// in-process, and a duplicate would fire every trigger twice.
#[tokio::test]
async fn an_instance_skips_its_own_commits() {
    let store = store().await;
    let db = test_db("skips-own");
    let hub = Arc::new(WatchHub::default());
    let mut events = hub.subscribe();
    fanout::spawn(store.clone(), hub.clone());
    settle().await;

    let name = format!("{}/rooms/echo", db.documents_root());
    apply_commit(&store, &db, &[set_write(&name, "n", 1)], 8_000).await.unwrap();

    let echoed = next_event_for(&mut events, &db, Duration::from_secs(5)).await;
    assert!(echoed.is_none(), "fan-out re-published a commit this instance made itself");
}

/// A rolled-back commit must not notify anyone: the notice is written inside
/// the commit's transaction, so it dies with it.
#[tokio::test]
async fn a_failed_commit_notifies_nobody() {
    let writer = store().await;
    let watcher = store().await;
    let db = test_db("failed-commit");
    let hub = Arc::new(WatchHub::default());
    let mut events = hub.subscribe();
    fanout::spawn(watcher.clone(), hub.clone());
    settle().await;

    // Oversized: past MongoDB's per-document ceiling, so the commit aborts.
    let root = db.documents_root();
    let huge = Write {
        operation: Some(Operation::Update(Document {
            name: format!("{root}/rooms/huge"),
            fields: HashMap::from([(
                "blob".to_owned(),
                Value { value_type: Some(ValueType::StringValue("x".repeat(9 * 1024 * 1024))) },
            )]),
            ..Default::default()
        })),
        ..Default::default()
    };
    assert!(apply_commit(&writer, &db, &[huge], 9_000).await.is_err());

    let leaked = next_event_for(&mut events, &db, Duration::from_secs(5)).await;
    assert!(leaked.is_none(), "a rolled-back commit still published a notice");
}
