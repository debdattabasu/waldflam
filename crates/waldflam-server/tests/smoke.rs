//! End-to-end smoke: boots the server against real MongoDB (docker compose
//! up -d) and speaks gRPC to it with the generated client.

use waldflam_proto::v1::GetDocumentRequest;
use waldflam_proto::v1::firestore_client::FirestoreClient;

#[tokio::test]
async fn serves_firestore_service_over_h2c() {
    let mongo = std::env::var("WALDFLAM_TEST_MONGO")
        .unwrap_or_else(|_| "mongodb://127.0.0.1:27017/?directConnection=true".into());
    let store = waldflam_engine::store::Store::connect(&mongo)
        .await
        .expect("MongoDB not reachable — run `docker compose up -d`");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    tokio::spawn(waldflam_server::serve(addr, store));

    let mut client = loop {
        match FirestoreClient::connect(format!("http://{addr}")).await {
            Ok(c) => break c,
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
        }
    };

    // Missing document → NOT_FOUND.
    let status = client
        .get_document(GetDocumentRequest {
            name: "projects/smoke/databases/(default)/documents/c/missing".into(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::NotFound);

    // firestore-rs ping probe (collection-arity path) → NOT_FOUND too.
    let status = client
        .get_document(GetDocumentRequest {
            name: "projects/smoke/databases/(default)/documents/-ping-".into(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::NotFound);

    // Unparseable name → INVALID_ARGUMENT.
    let status = client
        .get_document(GetDocumentRequest {
            name: "not-a-name".into(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);

    // Unimplemented RPCs still answer cleanly.
    let status = client
        .partition_query(waldflam_proto::v1::PartitionQueryRequest::default())
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unimplemented);
}
