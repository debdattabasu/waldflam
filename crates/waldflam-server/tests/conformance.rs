//! End-to-end conformance: Commit / GetDocument / BatchGetDocuments /
//! RunQuery over real gRPC against real MongoDB (docker compose up -d).

use std::collections::HashMap;

use waldflam_proto::v1::document_transform::FieldTransform;
use waldflam_proto::v1::document_transform::field_transform::{ServerValue, TransformType};
use waldflam_proto::v1::firestore_client::FirestoreClient;
use waldflam_proto::v1::precondition::ConditionType;
use waldflam_proto::v1::structured_query::field_filter::Operator as FieldOp;
use waldflam_proto::v1::structured_query::filter::FilterType;
use waldflam_proto::v1::structured_query::{
    CollectionSelector, Direction, FieldFilter, FieldReference, Filter, Order,
};
use waldflam_proto::v1::value::ValueType;
use waldflam_proto::v1::write::Operation;
use waldflam_proto::v1::*;

fn val(vt: ValueType) -> Value {
    Value { value_type: Some(vt) }
}
fn int(i: i64) -> Value {
    val(ValueType::IntegerValue(i))
}
fn string(s: &str) -> Value {
    val(ValueType::StringValue(s.into()))
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

async fn boot() -> (FirestoreClient<tonic::transport::Channel>, String) {
    let mongo = std::env::var("WALDFLAM_TEST_MONGO")
        .unwrap_or_else(|_| "mongodb://127.0.0.1:27017/?directConnection=true".into());
    let store = waldflam_engine::store::Store::connect(&mongo)
        .await
        .expect("MongoDB not reachable — run `docker compose up -d`");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    tokio::spawn(waldflam_server::serve(
        addr,
        store.clone(),
        Default::default(),
        std::sync::Arc::new(waldflam_server::credentials::Credentials::new(
            store,
            format!("http://{addr}"),
        )),
        None,
    ));
    let client = loop {
        match FirestoreClient::connect(format!("http://{addr}")).await {
            Ok(c) => break c,
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
        }
    };
    let nanos =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    (client, format!("projects/conf-{nanos}/databases/(default)"))
}

#[tokio::test]
async fn commit_get_query_round_trip() {
    let (mut client, db) = boot().await;
    let doc = |p: &str| format!("{db}/documents/{p}");

    // Create three cities plus one with transforms.
    let cities = [("tokyo", 37_400_000), ("delhi", 31_200_000), ("lyon", 1_700_000)];
    let writes: Vec<Write> = cities
        .iter()
        .map(|(name, pop)| {
            set_write(
                &doc(&format!("cities/{name}")),
                [("name".to_owned(), string(name)), ("population".to_owned(), int(*pop))]
                    .into_iter()
                    .collect(),
            )
        })
        .collect();
    let resp = client
        .commit(CommitRequest { database: db.clone(), writes, ..Default::default() })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.write_results.len(), 3);
    assert!(resp.commit_time.is_some());
    assert!(resp.write_results[0].update_time.is_some());

    // Transforms: serverTimestamp + increment on a fresh doc.
    let mut write =
        set_write(&doc("cities/lyon"), [("name".to_owned(), string("lyon"))].into_iter().collect());
    write.update_mask = Some(DocumentMask { field_paths: vec!["name".into()] });
    write.update_transforms = vec![
        FieldTransform {
            field_path: "updated".into(),
            transform_type: Some(TransformType::SetToServerValue(ServerValue::RequestTime as i32)),
        },
        FieldTransform {
            field_path: "population".into(),
            transform_type: Some(TransformType::Increment(int(300_000))),
        },
    ];
    let resp = client
        .commit(CommitRequest { database: db.clone(), writes: vec![write], ..Default::default() })
        .await
        .unwrap()
        .into_inner();
    let results = &resp.write_results[0].transform_results;
    assert_eq!(results.len(), 2);
    assert!(matches!(results[0].value_type, Some(ValueType::TimestampValue(_))));
    assert_eq!(results[1], int(2_000_000)); // 1.7M + 300k

    // GetDocument sees the merged + transformed state.
    let got = client
        .get_document(GetDocumentRequest { name: doc("cities/lyon"), ..Default::default() })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(got.fields["population"], int(2_000_000));
    assert_eq!(got.fields["name"], string("lyon"));
    assert!(got.fields.contains_key("updated"));
    assert!(got.create_time.is_some() && got.update_time.is_some());

    // Preconditions: exists=false on an existing doc → ALREADY_EXISTS;
    // exists=true on a missing doc → NOT_FOUND.
    let mut write = set_write(&doc("cities/lyon"), HashMap::new());
    write.current_document =
        Some(Precondition { condition_type: Some(ConditionType::Exists(false)) });
    let status = client
        .commit(CommitRequest { database: db.clone(), writes: vec![write], ..Default::default() })
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::AlreadyExists);

    let mut write = set_write(&doc("cities/atlantis"), HashMap::new());
    write.current_document =
        Some(Precondition { condition_type: Some(ConditionType::Exists(true)) });
    let status = client
        .commit(CommitRequest { database: db.clone(), writes: vec![write], ..Default::default() })
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::NotFound);

    // RunQuery: population > 2M, implicit order on the inequality field +
    // __name__, explicit DESC.
    let query = StructuredQuery {
        from: vec![CollectionSelector { collection_id: "cities".into(), all_descendants: false }],
        r#where: Some(Filter {
            filter_type: Some(FilterType::FieldFilter(FieldFilter {
                field: Some(FieldReference { field_path: "population".into() }),
                op: FieldOp::GreaterThan as i32,
                value: Some(int(2_000_000)),
            })),
        }),
        order_by: vec![Order {
            field: Some(FieldReference { field_path: "population".into() }),
            direction: Direction::Descending as i32,
        }],
        ..Default::default()
    };
    let mut stream = client
        .run_query(RunQueryRequest {
            parent: format!("{db}/documents"),
            query_type: Some(run_query_request::QueryType::StructuredQuery(query)),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let mut names = Vec::new();
    while let Some(msg) = stream.message().await.unwrap() {
        if let Some(d) = msg.document {
            names.push(d.fields["name"].clone());
        } else {
            assert!(msg.read_time.is_some());
        }
    }
    assert_eq!(names, vec![string("tokyo"), string("delhi")]);

    // Empty result: one read_time-only response.
    let query = StructuredQuery {
        from: vec![CollectionSelector { collection_id: "ghosts".into(), all_descendants: false }],
        ..Default::default()
    };
    let mut stream = client
        .run_query(RunQueryRequest {
            parent: format!("{db}/documents"),
            query_type: Some(run_query_request::QueryType::StructuredQuery(query)),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let first = stream.message().await.unwrap().unwrap();
    assert!(first.document.is_none() && first.read_time.is_some());
    assert!(stream.message().await.unwrap().is_none());

    // BatchGet: found + missing, duplicates answered once.
    let mut stream = client
        .batch_get_documents(BatchGetDocumentsRequest {
            database: db.clone(),
            documents: vec![doc("cities/tokyo"), doc("cities/nowhere"), doc("cities/tokyo")],
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let mut found = 0;
    let mut missing = 0;
    while let Some(msg) = stream.message().await.unwrap() {
        match msg.result.unwrap() {
            batch_get_documents_response::Result::Found(d) => {
                assert!(d.name.ends_with("cities/tokyo"));
                found += 1;
            }
            batch_get_documents_response::Result::Missing(n) => {
                assert!(n.ends_with("cities/nowhere"));
                missing += 1;
            }
        }
    }
    assert_eq!((found, missing), (1, 1));

    // Delete via commit, then the doc is gone.
    let delete =
        Write { operation: Some(Operation::Delete(doc("cities/tokyo"))), ..Default::default() };
    client
        .commit(CommitRequest { database: db.clone(), writes: vec![delete], ..Default::default() })
        .await
        .unwrap();
    let status = client
        .get_document(GetDocumentRequest { name: doc("cities/tokyo"), ..Default::default() })
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::NotFound);
}
