//! Commit atomicity against a real MongoDB replica set (docker compose up -d).
//!
//! These two properties are what the transaction in `commit::apply_commit`
//! buys, and both fail without it: a batch never half-lands, and concurrent
//! read-modify-write commits on one document don't lose updates.

use std::collections::HashMap;

use waldflam_engine::commit::apply_commit;
use waldflam_engine::path::{DatabaseName, ResourcePath};
use waldflam_engine::store::Store;
use waldflam_proto::v1::document_transform::FieldTransform;
use waldflam_proto::v1::document_transform::field_transform::TransformType;
use waldflam_proto::v1::value::ValueType;
use waldflam_proto::v1::write::Operation;
use waldflam_proto::v1::{Document, DocumentTransform, Value, Write};

async fn store() -> Store {
    let uri = std::env::var("WALDFLAM_TEST_MONGO")
        .unwrap_or_else(|_| "mongodb://127.0.0.1:27017/?directConnection=true".into());
    Store::connect(&uri).await.expect("MongoDB not reachable — run `docker compose up -d`")
}

/// Unique per run so tests don't collide with leftovers.
fn test_db() -> DatabaseName {
    let nanos =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    DatabaseName::new(format!("commit-{nanos}"), "(default)")
}

fn int(i: i64) -> Value {
    Value { value_type: Some(ValueType::IntegerValue(i)) }
}

fn set_write(name: &str, fields: HashMap<String, Value>) -> Write {
    Write {
        operation: Some(Operation::Update(Document {
            name: name.into(),
            fields,
            ..Default::default()
        })),
        ..Default::default()
    }
}

fn increment_write(name: &str, field: &str, by: i64) -> Write {
    Write {
        operation: Some(Operation::Transform(DocumentTransform {
            document: name.into(),
            field_transforms: vec![FieldTransform {
                field_path: field.into(),
                transform_type: Some(TransformType::Increment(int(by))),
            }],
        })),
        ..Default::default()
    }
}

/// A write that fails while persisting must take the rest of its batch with
/// it. The oversized document blows MongoDB's 16 MiB per-document ceiling,
/// so it fails *after* the first write has already been sent — exactly the
/// half-applied batch the transaction exists to prevent.
#[tokio::test]
async fn a_rejected_write_rolls_back_the_whole_batch() {
    let store = store().await;
    let db = test_db();
    let root = db.documents_root();

    let oversized = Value { value_type: Some(ValueType::StringValue("x".repeat(9 * 1024 * 1024))) };
    let writes = vec![
        set_write(&format!("{root}/batch/small"), HashMap::from([("n".to_owned(), int(1))])),
        set_write(&format!("{root}/batch/huge"), HashMap::from([("blob".to_owned(), oversized)])),
    ];

    let result = apply_commit(&store, &db, &writes, 1_000).await;
    assert!(result.is_err(), "a document past MongoDB's size ceiling should fail the commit");

    let small = ResourcePath::parse("batch/small").unwrap();
    assert!(
        store.get_document(&db, &small).await.unwrap().is_none(),
        "the first write must not survive a batch that failed partway"
    );
}

/// `increment` is a read-modify-write against the loaded document, so
/// concurrent commits racing on one counter will lose updates unless each
/// commit reads and writes inside the same transaction (and restarts when
/// MongoDB reports the write conflict).
#[tokio::test]
async fn concurrent_increments_do_not_lose_updates() {
    const WRITERS: i64 = 8;

    let store = store().await;
    let db = test_db();
    let root = db.documents_root();
    let name = format!("{root}/counters/hits");
    let path = ResourcePath::parse("counters/hits").unwrap();

    let seed = set_write(&name, HashMap::from([("n".to_owned(), int(0))]));
    apply_commit(&store, &db, &[seed], 1_000).await.unwrap();

    let mut tasks = Vec::new();
    for i in 0..WRITERS {
        let (store, db, name) = (store.clone(), db.clone(), name.clone());
        tasks.push(tokio::spawn(async move {
            apply_commit(&store, &db, &[increment_write(&name, "n", 1)], 2_000 + i).await
        }));
    }
    for task in tasks {
        task.await.expect("writer panicked").expect("increment should commit");
    }

    let stored = store.get_document(&db, &path).await.unwrap().expect("counter exists");
    assert_eq!(
        stored.fields.get("n").and_then(|v| v.value_type.clone()),
        Some(ValueType::IntegerValue(WRITERS)),
        "every concurrent increment should be reflected"
    );
}
