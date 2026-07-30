pub mod auth;
pub mod service;

use std::net::SocketAddr;

use tonic::transport::Server;
use waldflam_proto::v1::firestore_server::FirestoreServer;

use crate::service::FirestoreService;

/// Serve the Firestore gRPC surface on `addr` over h2c (plaintext HTTP/2
/// prior knowledge — what every SDK speaks in emulator mode).
pub async fn serve(addr: SocketAddr) -> anyhow::Result<()> {
    tracing::info!(%addr, "waldflam listening (gRPC h2c)");
    Server::builder()
        .add_service(FirestoreServer::new(FirestoreService::default()))
        .serve(addr)
        .await?;
    Ok(())
}
