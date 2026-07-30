pub mod auth;
pub mod listen;
pub mod rest;
pub mod service;

use std::net::SocketAddr;
use std::sync::Arc;

use waldflam_engine::store::Store;
use waldflam_proto::v1::firestore_server::FirestoreServer;

use crate::service::FirestoreService;

/// Serve every protocol surface on one port, like the official emulator:
/// native gRPC over h2c (all SDKs in emulator mode), REST v1 in proto3-JSON
/// (JS lite + browser unary), and a health check at `/`.
pub async fn serve(addr: SocketAddr, store: Store) -> anyhow::Result<()> {
    let svc = Arc::new(FirestoreService::new(store));
    let rest_state = rest::RestState { svc: svc.clone(), pool: rest::descriptor_pool() };

    let grpc = tonic::service::Routes::new(FirestoreServer::from_arc(svc));
    let rest_router = axum::Router::new()
        .route("/", axum::routing::get(rest::health))
        .route("/v1/{*path}", axum::routing::post(rest::v1_post))
        .with_state(rest_state);
    let router = grpc
        .into_axum_router()
        .merge(rest_router)
        .layer(axum::middleware::from_fn(rest::cors));

    tracing::info!(%addr, "waldflam listening (gRPC h2c + REST v1)");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;
    Ok(())
}
