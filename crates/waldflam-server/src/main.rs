use std::net::SocketAddr;
use std::sync::Arc;

use waldflam_server::auth::{AuthPolicy, ExternalIssuer, Verifier, VerifyConfig};
use waldflam_server::credentials::Credentials;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("credentials") => credentials_cli(&args[1..]).await,
        Some("help" | "--help" | "-h") => {
            print!("{USAGE}");
            Ok(())
        }
        Some(other) => Err(anyhow::anyhow!("unknown command {other:?}\n\n{USAGE}")),
        None => serve().await,
    }
}

const USAGE: &str = "\
waldflam — a Firebase-compatible backend

  waldflam                              serve every protocol surface
  waldflam credentials create <name>    create a service account, print its key file
  waldflam credentials list             list service accounts
  waldflam credentials revoke <who>     revoke by key id or email
  waldflam credentials revoke-user <uid>
                                        end every session a user has
  waldflam credentials rotate-signing-key
                                        sign with a new key; the old one keeps
                                        verifying until its tokens expire
  waldflam credentials generate-kek     print a new key-encryption key
  waldflam credentials seal-signing-key encrypt the stored signing key under it

Options for `credentials create`:
  --project <id>   project the credential is admin of (default: WALDFLAM_PROJECT
                   or `demo`)
  --out <path>     write the key file here instead of stdout

Environment:
  WALDFLAM_LISTEN        address to serve on (default 0.0.0.0:8080)
  WALDFLAM_MONGO         MongoDB URI
  WALDFLAM_MONGO_DATABASE
                         database within it (default `waldflam`)
  WALDFLAM_PUBLIC_URL    externally reachable base URL; identifies this
                         deployment as a token issuer and is baked into the
                         key files it emits (default http://127.0.0.1:8080)
  WALDFLAM_AUTH          `emulator` (default) or `verify`
  WALDFLAM_AUTH_ISSUER   trust an external identity provider as well; needs
  WALDFLAM_AUTH_AUDIENCE all three, or none
  WALDFLAM_AUTH_JWKS_URL
  WALDFLAM_ADMIN_TOKEN   shared secret granting admin (weaker than a service
                         account: names nobody, never expires)
  WALDFLAM_AUTH_CHECK_REVOKED
                         set to 1 to check every ID token against its user's
                         revocation state, instead of trusting it until it
                         expires (costs a lookup per request)
  WALDFLAM_AUTH_REQUIRE_JTI
                         set to 1 to refuse one-shot assertions with no `jti`,
                         which are the ones replay protection cannot cover.
                         Only for deployments that control their clients — not
                         every Google auth library sends one
  WALDFLAM_KEK           base64 key-encryption key: encrypts the signing key at
  WALDFLAM_KEK_FILE      rest, so a database dump (or a backup, or a snapshot)
                         yields nothing usable. The file form keeps it out of
                         the process environment. Set one, not both
  WALDFLAM_SIGNER_URL    sign through something that holds the key (KMS, Vault,
  WALDFLAM_SIGNER_TOKEN  an HSM) instead of holding it. waldflam then stores no
                         signing key at all, and rotation belongs to the signer
  WALDFLAM_TLS_CERT      PEM certificate chain; with WALDFLAM_TLS_KEY, waldflam
  WALDFLAM_TLS_KEY       terminates TLS itself (ALPN h2 + http/1.1)
  WALDFLAM_TLS           set to `terminated` to acknowledge that something in
                         front already terminates TLS, silencing the warning
";

async fn serve() -> anyhow::Result<()> {
    let addr: SocketAddr =
        std::env::var("WALDFLAM_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".into()).parse()?;
    let store = connect().await?;
    let credentials = Arc::new(
        Credentials::new(store.clone(), public_url())
            .with_revocation_checks(enabled("WALDFLAM_AUTH_CHECK_REVOKED"))
            .with_required_jti(enabled("WALDFLAM_AUTH_REQUIRE_JTI"))
            .with_kek(waldflam_server::sealing::from_env()?)
            .with_remote_signer(
                waldflam_server::signer::from_env().await?.map(std::sync::Arc::new),
            ),
    );
    let auth = auth_policy(credentials.clone())?;
    if auth.guards_admin_api() {
        // Force the signing key to exist now: a deployment that cannot mint
        // or verify its own tokens should fail at boot, not on its first
        // authenticated request.
        credentials.warm().await?;
        tracing::info!(issuer = credentials.issuer(), "auth: waldflam is issuing tokens");
    }
    let tls = tls_config()?;
    waldflam_server::tls::warn_if_unprotected(
        auth.guards_admin_api(),
        tls.is_some(),
        std::env::var("WALDFLAM_TLS").is_ok_and(|mode| mode == "terminated"),
    );
    waldflam_server::serve(addr, store, auth, credentials, tls).await
}

/// Reads the TLS certificate and key, if this deployment terminates TLS.
///
/// Both or neither: one without the other is a deployment that meant to be
/// encrypted and silently would not be.
fn tls_config() -> anyhow::Result<Option<Arc<tokio_rustls::rustls::ServerConfig>>> {
    let get = |name: &str| std::env::var(name).ok().filter(|value| !value.is_empty());
    match (get("WALDFLAM_TLS_CERT"), get("WALDFLAM_TLS_KEY")) {
        (None, None) => Ok(None),
        (Some(cert), Some(key)) => {
            waldflam_server::tls::load(std::path::Path::new(&cert), std::path::Path::new(&key))
                .map(Some)
        }
        _ => Err(anyhow::anyhow!(
            "TLS needs WALDFLAM_TLS_CERT and WALDFLAM_TLS_KEY together — set both or neither"
        )),
    }
}

/// Reads a boolean switch from the environment.
fn enabled(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| matches!(value.as_str(), "1" | "true" | "yes"))
}

fn mongo_uri() -> String {
    std::env::var("WALDFLAM_MONGO")
        .unwrap_or_else(|_| "mongodb://127.0.0.1:27017/?directConnection=true".into())
}

/// MongoDB database to use, so independent deployments can share a cluster
/// without sharing documents, credentials or signing keys.
fn mongo_database() -> String {
    std::env::var("WALDFLAM_MONGO_DATABASE")
        .unwrap_or_else(|_| waldflam_engine::store::DEFAULT_DATABASE.to_owned())
}

async fn connect() -> anyhow::Result<waldflam_engine::store::Store> {
    Ok(waldflam_engine::store::Store::connect_to(&mongo_uri(), &mongo_database()).await?)
}

/// How this deployment names itself as a token issuer.
///
/// It ends up inside every token waldflam mints and is compared on the way
/// back in, so changing it invalidates outstanding tokens. The default is
/// deliberately a loopback address: a deployment other machines reach has to
/// say so, and would otherwise hand out key files pointing at localhost.
fn public_url() -> String {
    std::env::var("WALDFLAM_PUBLIC_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".into())
}

/// Builds the auth policy from the environment.
///
/// Emulator semantics are the default because that is what the SDKs' emulator
/// mode expects and what every local workflow relies on. Verification is
/// opt-in, and deliberately refuses to start half-configured: a server that
/// silently fell back to trusting unsigned tokens would be worse than one
/// that won't boot.
fn auth_policy(credentials: Arc<Credentials>) -> anyhow::Result<AuthPolicy> {
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
            let config = VerifyConfig {
                external: external_issuer()?,
                admin_token: std::env::var("WALDFLAM_ADMIN_TOKEN").ok().filter(|t| !t.is_empty()),
            };
            if let Some(external) = &config.external {
                tracing::info!(issuer = %external.issuer, "auth: also trusting an external issuer");
            }
            if config.admin_token.is_some() {
                tracing::warn!(
                    "auth: WALDFLAM_ADMIN_TOKEN grants admin to anyone holding it, \
                     with no identity and no expiry — prefer a service account \
                     (`waldflam credentials create`)"
                );
            }
            Ok(AuthPolicy::Verify(Arc::new(Verifier::new(config, credentials))))
        }
        other => {
            Err(anyhow::anyhow!("WALDFLAM_AUTH must be `emulator` or `verify`, got {other:?}"))
        }
    }
}

/// An external identity provider is all-or-nothing: two of the three settings
/// describe a verifier that cannot verify, and starting anyway would mean
/// rejecting every token from an issuer the operator believed was configured.
fn external_issuer() -> anyhow::Result<Option<ExternalIssuer>> {
    let get = |name: &str| std::env::var(name).ok().filter(|value| !value.is_empty());
    let (issuer, audience, jwks_url) =
        (get("WALDFLAM_AUTH_ISSUER"), get("WALDFLAM_AUTH_AUDIENCE"), get("WALDFLAM_AUTH_JWKS_URL"));
    match (issuer, audience, jwks_url) {
        (None, None, None) => Ok(None),
        (Some(issuer), Some(audience), Some(jwks_url)) => {
            Ok(Some(ExternalIssuer { issuer, audience, jwks_url }))
        }
        _ => Err(anyhow::anyhow!(
            "an external issuer needs WALDFLAM_AUTH_ISSUER, WALDFLAM_AUTH_AUDIENCE, \
             and WALDFLAM_AUTH_JWKS_URL together — set all three or none"
        )),
    }
}

/// `waldflam credentials …`
///
/// Talks to MongoDB rather than to a running server, which is what solves the
/// bootstrap problem: creating the first credential cannot itself require a
/// credential. Whoever can reach the database can mint one, and they could
/// have written the record by hand anyway.
async fn credentials_cli(args: &[String]) -> anyhow::Result<()> {
    let store = connect().await?;
    let credentials =
        Credentials::new(store, public_url()).with_kek(waldflam_server::sealing::from_env()?);

    match args.first().map(String::as_str) {
        Some("create") => {
            let name = args
                .get(1)
                .filter(|arg| !arg.starts_with("--"))
                .ok_or_else(|| anyhow::anyhow!("usage: waldflam credentials create <name>"))?;
            let project = flag(args, "--project")
                .or_else(|| std::env::var("WALDFLAM_PROJECT").ok())
                .unwrap_or_else(|| "demo".into());
            let (account, key_file) = credentials
                .create_service_account(name, &project)
                .await
                .map_err(|status| anyhow::anyhow!("{}", status.message()))?;
            let rendered = serde_json::to_string_pretty(&key_file)?;
            match flag(args, "--out") {
                Some(path) => {
                    std::fs::write(&path, format!("{rendered}\n"))?;
                    eprintln!("wrote {path}");
                }
                None => println!("{rendered}"),
            }
            eprintln!(
                "created {} (key id {})\n\
                 This is the only copy of the private key — waldflam stored only the public half.",
                account.client_email, account.key_id
            );
        }
        Some("list") => {
            let accounts = credentials
                .list_service_accounts()
                .await
                .map_err(|status| anyhow::anyhow!("{}", status.message()))?;
            if accounts.is_empty() {
                eprintln!("no service accounts");
            }
            for account in accounts {
                println!(
                    "{}\t{}\t{}{}",
                    account.key_id,
                    account.client_email,
                    account.project_id,
                    if account.revoked { "\tREVOKED" } else { "" }
                );
            }
        }
        Some("generate-kek") => {
            // To stdout alone, so it can be piped into a secret store
            // without the surrounding prose coming along.
            println!("{}", waldflam_server::sealing::Kek::generate());
            eprintln!(
                "Store this outside the database and pass it as WALDFLAM_KEK, or better \
                 WALDFLAM_KEK_FILE.\nLose it and a sealed signing key cannot be recovered."
            );
        }
        Some("seal-signing-key") => match credentials.seal_signing_key().await {
            Ok(true) => eprintln!("signing key sealed; the plaintext copy is gone"),
            Ok(false) => eprintln!("nothing to do — the signing key is already sealed"),
            Err(status) => return Err(anyhow::anyhow!("{}", status.message())),
        },
        Some("rotate-signing-key") => {
            let key_id = credentials
                .rotate_signing_key()
                .await
                .map_err(|status| anyhow::anyhow!("{}", status.message()))?;
            eprintln!(
                "now signing with {key_id}\n\
                 The previous key keeps verifying until the tokens it signed expire, \
                 so nothing in flight breaks."
            );
        }
        Some("revoke-user") => {
            let uid = args.get(1).ok_or_else(|| {
                anyhow::anyhow!("usage: waldflam credentials revoke-user <uid> [--project <id>]")
            })?;
            let project = flag(args, "--project")
                .or_else(|| std::env::var("WALDFLAM_PROJECT").ok())
                .unwrap_or_else(|| "demo".into());
            credentials
                .revoke_identity_tokens(&project, uid)
                .await
                .map_err(|status| anyhow::anyhow!("{}", status.message()))?;
            eprintln!("revoked every session for {uid} in {project}");
        }
        Some("revoke") => {
            let selector = args.get(1).ok_or_else(|| {
                anyhow::anyhow!("usage: waldflam credentials revoke <key-id|email>")
            })?;
            match credentials
                .revoke_service_account(selector)
                .await
                .map_err(|status| anyhow::anyhow!("{}", status.message()))?
            {
                Some(account) => eprintln!("revoked {}", account.client_email),
                None => return Err(anyhow::anyhow!("no service account matching {selector:?}")),
            }
        }
        _ => return Err(anyhow::anyhow!("{USAGE}")),
    }
    Ok(())
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|arg| arg == name).and_then(|at| args.get(at + 1)).cloned()
}
