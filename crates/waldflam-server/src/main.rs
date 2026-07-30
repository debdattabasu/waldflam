use std::net::SocketAddr;
use std::sync::Arc;

use waldflam_server::auth::{AuthPolicy, Verifier, VerifyConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let addr: SocketAddr =
        std::env::var("WALDFLAM_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".into()).parse()?;
    let mongo_uri = std::env::var("WALDFLAM_MONGO")
        .unwrap_or_else(|_| "mongodb://127.0.0.1:27017/?directConnection=true".into());
    let auth = auth_policy()?;
    let store = waldflam_engine::store::Store::connect(&mongo_uri).await?;
    waldflam_server::serve(addr, store, auth).await
}

/// Builds the auth policy from the environment.
///
/// Emulator semantics are the default because that is what the SDKs' emulator
/// mode expects and what every local workflow relies on. Verification is
/// opt-in, and deliberately refuses to start half-configured: a server that
/// silently fell back to trusting unsigned tokens would be worse than one
/// that won't boot.
fn auth_policy() -> anyhow::Result<AuthPolicy> {
    let mode = std::env::var("WALDFLAM_AUTH").unwrap_or_else(|_| "emulator".into());
    match mode.as_str() {
        "emulator" => {
            tracing::warn!(
                "auth: emulator mode — tokens are decoded but NOT verified and \
                 `Bearer owner` is admin. Set WALDFLAM_AUTH=verify for a \
                 deployment reachable by anyone."
            );
            Ok(AuthPolicy::Emulator)
        }
        "verify" => {
            let required = |name: &str| {
                std::env::var(name)
                    .map_err(|_| anyhow::anyhow!("WALDFLAM_AUTH=verify requires {name} to be set"))
            };
            let config = VerifyConfig {
                issuer: required("WALDFLAM_AUTH_ISSUER")?,
                audience: required("WALDFLAM_AUTH_AUDIENCE")?,
                jwks_url: required("WALDFLAM_AUTH_JWKS_URL")?,
                admin_token: std::env::var("WALDFLAM_ADMIN_TOKEN").ok().filter(|t| !t.is_empty()),
            };
            if config.admin_token.is_none() {
                tracing::info!(
                    "auth: no WALDFLAM_ADMIN_TOKEN set — no request can bypass \
                     security rules, and the /emulator/v1 admin endpoints are closed"
                );
            }
            tracing::info!(issuer = %config.issuer, "auth: verifying token signatures");
            Ok(AuthPolicy::Verify(Arc::new(Verifier::new(config))))
        }
        other => {
            Err(anyhow::anyhow!("WALDFLAM_AUTH must be `emulator` or `verify`, got {other:?}"))
        }
    }
}
