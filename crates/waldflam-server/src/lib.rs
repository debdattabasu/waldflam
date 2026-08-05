pub mod auth;
pub mod credentials;
pub mod functions;
pub mod listen;
pub mod rest;
pub mod rules;
pub mod sealing;
pub mod service;
pub mod signer;
pub mod tls;
pub mod webchannel;
pub mod write_stream;

use std::net::SocketAddr;
use std::sync::Arc;

use waldflam_engine::store::Store;
use waldflam_proto::v1::firestore_server::FirestoreServer;

use crate::service::FirestoreService;

/// Serve every protocol surface on one port, like the official emulator:
/// native gRPC over h2c (all SDKs in emulator mode), REST v1 in proto3-JSON
/// (JS lite + browser unary), and a health check at `/`.
pub async fn serve(
    addr: SocketAddr,
    store: Store,
    auth: auth::AuthPolicy,
    credentials: Arc<credentials::Credentials>,
    tls: Option<Arc<tokio_rustls::rustls::ServerConfig>>,
) -> anyhow::Result<()> {
    let svc = Arc::new(FirestoreService::with_auth(store.clone(), auth));
    let pool = rest::descriptor_pool();
    let triggers: Arc<functions::TriggerRegistry> = Default::default();
    functions::spawn_dispatcher(svc.hub_handle(), triggers.clone(), pool.clone());
    // Republishes other instances' commits onto this instance's hub, so
    // Listen streams here see writes applied anywhere in the cluster.
    waldflam_engine::fanout::spawn(store, svc.hub_handle());
    // Applies revocations published by other instances, so a credential
    // revoked anywhere stops working here immediately rather than whenever
    // this instance's cache next turns over.
    credentials::spawn_invalidation_watcher(credentials.clone());
    let rest_state = rest::RestState {
        svc: svc.clone(),
        pool,
        sessions: Default::default(),
        triggers,
        credentials,
    };

    let grpc = tonic::service::Routes::new(FirestoreServer::from_arc(svc));
    let rest_router = axum::Router::new()
        .route("/", axum::routing::get(rest::health))
        .route("/v1/{*path}", axum::routing::post(rest::v1_post))
        .route("/oauth2/v4/token", axum::routing::post(rest::oauth_token))
        .route("/.well-known/jwks.json", axum::routing::get(rest::jwks))
        .route("/.well-known/openid-configuration", axum::routing::get(rest::openid_configuration))
        .route("/emulator/v1/projects/{project}", axum::routing::put(rest::set_security_rules))
        .route(
            "/emulator/v1/projects/{project}/databases/{database}/documents",
            axum::routing::delete(rest::clear_data),
        )
        .route("/emulator/v1/projects/{project}/triggers", axum::routing::put(rest::set_triggers))
        .route(
            "/emulator/v1/projects/{project}/accounts/{uid}",
            axum::routing::post(rest::revoke_refresh_tokens),
        )
        .with_state(rest_state.clone());
    let router = grpc
        .into_axum_router()
        .merge(rest_router)
        .layer(axum::middleware::from_fn_with_state(rest_state, webchannel::intercept))
        .layer(axum::middleware::from_fn(rest::cors));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    match tls {
        None => {
            tracing::info!(%addr, "waldflam listening (gRPC h2c + REST v1)");
            axum::serve(listener, router).await?;
        }
        Some(config) => {
            tracing::info!(%addr, "waldflam listening over TLS (gRPC h2 + REST v1)");
            serve_tls(listener, router, config).await?;
        }
    }
    Ok(())
}

/// Serves the same router over TLS.
///
/// Hand-rolled rather than handed to `axum::serve` because the protocol has
/// to be decided per connection: gRPC needs HTTP/2 and the browser surfaces
/// need HTTP/1.1, and which one a client wants is known only after the ALPN
/// handshake. `auto::Builder` reads the negotiated protocol and serves
/// whichever was agreed.
async fn serve_tls(
    listener: tokio::net::TcpListener,
    router: axum::Router,
    config: Arc<tokio_rustls::rustls::ServerConfig>,
) -> anyhow::Result<()> {
    let acceptor = tokio_rustls::TlsAcceptor::from(config);
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            // One failed accept must not take the server down; the usual
            // cause is transient (descriptor exhaustion, a client vanishing
            // between SYN and accept).
            Err(e) => {
                tracing::warn!(error = %e, "TLS: accept failed");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let service = hyper_util::service::TowerToHyperService::new(router.clone());
        tokio::spawn(async move {
            let stream = match acceptor.accept(stream).await {
                Ok(stream) => stream,
                // Scanners, health checks and clients that don't trust our
                // certificate all land here. Debug, not warn: it is normal
                // background noise on a public address.
                Err(e) => {
                    tracing::debug!(%peer, error = %e, "TLS: handshake failed");
                    return;
                }
            };
            let served =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection_with_upgrades(hyper_util::rt::TokioIo::new(stream), service)
                    .await;
            if let Err(e) = served {
                tracing::debug!(%peer, error = %e, "TLS: connection ended");
            }
        });
    }
}
