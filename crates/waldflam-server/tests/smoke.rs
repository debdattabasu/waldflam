//! Boots the server on an ephemeral port and checks the gRPC surface answers.

use waldflam_proto::v1::GetDocumentRequest;
use waldflam_proto::v1::firestore_client::FirestoreClient;

#[tokio::test]
async fn serves_firestore_service_over_h2c() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    tokio::spawn(waldflam_server::serve(addr));

    let mut client = loop {
        match FirestoreClient::connect(format!("http://{addr}")).await {
            Ok(c) => break c,
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
        }
    };

    let status = client
        .get_document(GetDocumentRequest {
            name: "projects/p/databases/(default)/documents/c/d".into(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unimplemented);
}
