//! Signing through something that holds the key, instead of holding it.
//!
//! Runs a real signing service over HTTP and drives waldflam against it, so
//! what's checked is the seam actually working end to end — waldflam storing
//! no key, publishing the signer's public half, and minting tokens that
//! verify — rather than a trait definition that compiles.
//!
//! The service here holds the key in memory, which a real one would not; that
//! difference is on the far side of the contract and invisible to waldflam,
//! which is the point of the contract.

use std::sync::Arc;

use axum::extract::State;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use waldflam_server::credentials::Credentials;
use waldflam_server::signer::{RemoteSigner, Signer as _};

const PEM: &str = include_str!("data/test-key.pem");
const KEY_ID: &str = "remote-key-1";

#[derive(Clone)]
struct TestSigner {
    signer: Arc<waldflam_server::signer::LocalSigner>,
    modulus: String,
    exponent: String,
    /// Refuses everything, to check that a failing signer surfaces as an
    /// error rather than as a token nobody can verify.
    broken: bool,
}

async fn public_key(State(state): State<TestSigner>) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "kid": KEY_ID, "n": state.modulus, "e": state.exponent,
    }))
}

async fn sign(
    State(state): State<TestSigner>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    if state.broken {
        return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "key unavailable").into_response();
    }
    let message = URL_SAFE_NO_PAD
        .decode(body["message"].as_str().expect("message"))
        .expect("valid base64url");
    let signature = state.signer.sign(&message).await.expect("sign");
    axum::Json(serde_json::json!({ "signature": URL_SAFE_NO_PAD.encode(signature) }))
        .into_response()
}

/// Starts a signing service and returns its URL.
async fn start_signer(broken: bool) -> String {
    use rsa::pkcs8::DecodePrivateKey as _;
    use rsa::traits::PublicKeyParts as _;
    let public = rsa::RsaPrivateKey::from_pkcs8_pem(PEM).expect("test key").to_public_key();
    let state = TestSigner {
        signer: Arc::new(
            waldflam_server::signer::LocalSigner::from_pem(KEY_ID, PEM).expect("test key"),
        ),
        modulus: URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
        exponent: URL_SAFE_NO_PAD.encode(public.e().to_bytes_be()),
        broken,
    };
    let app =
        axum::Router::new().route("/", axum::routing::get(public_key).post(sign)).with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move { axum::serve(listener, app).await });
    format!("http://{addr}/")
}

async fn credentials(url: &str, label: &str) -> Arc<Credentials> {
    let mongo = std::env::var("WALDFLAM_TEST_MONGO")
        .unwrap_or_else(|_| "mongodb://127.0.0.1:27017/?directConnection=true".into());
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    // Its own database: a deployment signing remotely stores no key, and
    // sharing one with tests that do would confuse both.
    let store = waldflam_engine::store::Store::connect_to(&mongo, &format!("wf-{label}-{nanos}"))
        .await
        .expect("MongoDB not reachable — run `docker compose up -d`");
    let remote = RemoteSigner::connect(url, None).await.expect("the signer is reachable");
    Arc::new(
        Credentials::new(store, "http://waldflam.test".into())
            .with_remote_signer(Some(Arc::new(remote))),
    )
}

#[tokio::test]
async fn waldflam_can_sign_without_holding_the_key() {
    let url = start_signer(false).await;
    let credentials = credentials(&url, "remote").await;

    // The published key set is the signer's, and only the signer's — if
    // waldflam had quietly generated one of its own, this would be its kid.
    let jwks = credentials.jwks().await.expect("jwks");
    let keys = jwks["keys"].as_array().expect("keys");
    assert_eq!(keys.len(), 1, "a remote deployment publishes exactly the signer's key");
    assert_eq!(keys[0]["kid"], KEY_ID);

    // A full identity round trip, signed over the wire by the service.
    let (_, key_file) = credentials.create_service_account("remote", "demo").await.expect("create");
    let email = key_file["client_email"].as_str().expect("email");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64;
    let custom_token = {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(key_file["private_key_id"].as_str().expect("kid").to_owned());
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(
            key_file["private_key"].as_str().expect("pem").as_bytes(),
        )
        .expect("key file loads");
        jsonwebtoken::encode(
            &header,
            &serde_json::json!({
                "iss": email, "sub": email,
                "aud": "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit",
                "iat": now, "exp": now + 600, "uid": "judy",
            }),
            &key,
        )
        .expect("sign")
    };

    let signed_in =
        credentials.sign_in_with_custom_token(&custom_token).await.expect("sign in remotely");
    assert_eq!(
        jsonwebtoken::decode_header(&signed_in.id_token).expect("header").kid.as_deref(),
        Some(KEY_ID),
        "tokens must carry the signer's key id"
    );

    // And waldflam accepts what the remote signer produced.
    let policy = waldflam_server::auth::AuthPolicy::Verify(Arc::new(
        waldflam_server::auth::Verifier::new(Default::default(), credentials.clone()),
    ));
    let auth = policy
        .authorize(Some(&format!("Bearer {}", signed_in.id_token)))
        .await
        .expect("a remotely signed token verifies");
    let waldflam_server::auth::Authorization::User(claims) = auth else {
        panic!("expected a user identity, got {auth:?}");
    };
    assert_eq!(claims.uid.as_deref(), Some("judy"));
}

/// A signer that is down must produce an error, not a token.
#[tokio::test]
async fn a_failing_signer_is_an_error_not_a_bad_token() {
    let url = start_signer(true).await;
    let credentials = credentials(&url, "broken").await;
    let error = credentials
        .sign_in_with_custom_token("not.even.reached")
        .await
        .expect_err("nothing can be minted without the signer");
    // Reaching the signer is a precondition for issuing anything at all.
    assert!(!error.message().is_empty());
}

/// A signer that cannot be reached at startup fails then, rather than on the
/// first token somebody needs.
#[tokio::test]
async fn an_unreachable_signer_fails_at_connect() {
    let error = RemoteSigner::connect("http://127.0.0.1:1/unreachable", None)
        .await
        .expect_err("nothing is listening there");
    assert!(error.message().contains("cannot reach the signer"), "{}", error.message());
}
