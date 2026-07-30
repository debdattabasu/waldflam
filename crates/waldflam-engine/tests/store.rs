//! Integration tests against a real MongoDB (docker compose up -d).
//!
//! Set WALDFLAM_TEST_MONGO to override the URI; tests fail fast with a clear
//! message if Mongo is unreachable.

use std::collections::HashMap;

use waldflam_engine::path::{DatabaseName, ResourcePath};
use waldflam_engine::store::Store;
use waldflam_proto::v1::value::ValueType;
use waldflam_proto::v1::{ArrayValue, MapValue, Value};

fn mongo_uri() -> String {
    std::env::var("WALDFLAM_TEST_MONGO")
        .unwrap_or_else(|_| "mongodb://127.0.0.1:27017/?directConnection=true".into())
}

fn val(vt: ValueType) -> Value {
    Value { value_type: Some(vt) }
}

fn test_db() -> DatabaseName {
    // Unique per run so tests don't collide with leftovers.
    let nanos =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    DatabaseName::new(format!("test-{nanos}"), "(default)")
}

#[tokio::test]
async fn document_round_trip() {
    let store = Store::connect(&mongo_uri())
        .await
        .expect("MongoDB not reachable — run `docker compose up -d`");
    let db = test_db();
    let path = ResourcePath::parse("users/alice/posts/p1").unwrap();

    // Missing document reads as None.
    assert!(store.get_document(&db, &path).await.unwrap().is_none());

    // Create with a nested/array-bearing field map.
    let mut fields = HashMap::new();
    fields.insert("title".into(), val(ValueType::StringValue("hello".into())));
    fields.insert("views".into(), val(ValueType::IntegerValue(42)));
    fields.insert(
        "tags".into(),
        val(ValueType::ArrayValue(ArrayValue {
            values: vec![
                val(ValueType::StringValue("a".into())),
                val(ValueType::StringValue("b".into())),
            ],
        })),
    );
    fields.insert(
        "meta".into(),
        val(ValueType::MapValue(MapValue {
            fields: [("draft".to_owned(), val(ValueType::BooleanValue(true)))]
                .into_iter()
                .collect(),
        })),
    );

    let created = store.set_document(&db, &path, fields.clone(), 1_000).await.unwrap();
    assert_eq!(created.create_time_us, 1_000);
    assert_eq!(created.update_time_us, 1_000);
    assert_eq!(created.fields, fields);

    // Read back losslessly.
    let read = store.get_document(&db, &path).await.unwrap().unwrap();
    assert_eq!(read.fields, fields);
    assert_eq!(read.path.to_string(), "users/alice/posts/p1");

    // Replace: update_time moves, create_time is preserved.
    let mut replaced_fields = HashMap::new();
    replaced_fields.insert("title".into(), val(ValueType::StringValue("bye".into())));
    let replaced = store.set_document(&db, &path, replaced_fields.clone(), 2_000).await.unwrap();
    assert_eq!(replaced.create_time_us, 1_000);
    assert_eq!(replaced.update_time_us, 2_000);
    assert_eq!(replaced.fields, replaced_fields);

    // Delete: reports existence, then reads as None, second delete false.
    assert!(store.delete_document(&db, &path).await.unwrap());
    assert!(store.get_document(&db, &path).await.unwrap().is_none());
    assert!(!store.delete_document(&db, &path).await.unwrap());
}
