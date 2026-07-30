use std::net::SocketAddr;

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
    let store = waldflam_engine::store::Store::connect(&mongo_uri).await?;
    waldflam_server::serve(addr, store).await
}
