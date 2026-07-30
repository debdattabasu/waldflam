//! Service-account credentials end to end, against real MongoDB.
//!
//! These exercise the whole credential path the way a client does: sign with
//! the private key from an emitted key file, hand the result to the auth
//! policy, and check what it grants. Signing with the real key is the point —
//! a test that called the verifier's internals could pass while the wire
//! shape a Google auth library produces was rejected.

use std::sync::Arc;

use waldflam_server::auth::{AuthPolicy, Authorization, Verifier, VerifyConfig};
use waldflam_server::credentials::Credentials;

const ISSUER: &str = "http://waldflam.test";
const CUSTOM_TOKEN_AUDIENCE: &str =
    "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit";

async fn credentials() -> Arc<Credentials> {
    Arc::new(credentials_with_ttl(std::time::Duration::from_secs(30)).await)
}

async fn credentials_with_ttl(ttl: std::time::Duration) -> Credentials {
    let mongo = std::env::var("WALDFLAM_TEST_MONGO")
        .unwrap_or_else(|_| "mongodb://127.0.0.1:27017/?directConnection=true".into());
    let store = waldflam_engine::store::Store::connect(&mongo)
        .await
        .expect("MongoDB not reachable — run `docker compose up -d`");
    Credentials::new(store, ISSUER.into()).with_account_cache_ttl(ttl)
}

fn policy(credentials: Arc<Credentials>) -> AuthPolicy {
    AuthPolicy::Verify(Arc::new(Verifier::new(VerifyConfig::default(), credentials)))
}

/// Each test gets its own account names, since the credential collections are
/// shared by every database and outlive the run.
fn unique(prefix: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    format!("{prefix}-{nanos}")
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("clock").as_secs()
        as i64
}

/// Signs with the private key from a key file, exactly as a client library
/// holding that file would.
fn sign(key_file: &serde_json::Value, claims: serde_json::Value) -> String {
    let pem = key_file["private_key"].as_str().expect("key file has a private key");
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(key_file["private_key_id"].as_str().expect("key id").to_owned());
    let key = jsonwebtoken::EncodingKey::from_rsa_pem(pem.as_bytes()).expect("key file loads");
    jsonwebtoken::encode(&header, &claims, &key).expect("sign")
}

/// The assertion a Google auth library builds from a service-account key
/// file: issuer and subject are the account, signed with its private key.
fn assertion(key_file: &serde_json::Value, audience: &str) -> String {
    let email = key_file["client_email"].as_str().expect("client email");
    sign(
        key_file,
        serde_json::json!({
            "iss": email,
            "sub": email,
            "aud": audience,
            "iat": now(),
            "exp": now() + 3600,
        }),
    )
}

async fn judge(policy: &AuthPolicy, token: &str) -> Result<Authorization, tonic::Status> {
    policy.authorize(Some(&format!("Bearer {token}"))).await
}

#[tokio::test]
async fn a_service_account_assertion_is_admin() {
    let credentials = credentials().await;
    let (account, key_file) =
        credentials.create_service_account(&unique("assert"), "demo").await.expect("create");

    // The key file has to look like Google's, or the client libraries that
    // load it will not.
    assert_eq!(key_file["type"], "service_account");
    assert_eq!(key_file["project_id"], "demo");
    assert_eq!(key_file["client_email"], account.client_email.as_str());
    assert_eq!(key_file["token_uri"], format!("{ISSUER}/oauth2/v4/token"));
    assert!(
        key_file["private_key"].as_str().expect("pem").starts_with("-----BEGIN PRIVATE KEY-----"),
        "the private key must be a PKCS#8 PEM, which is what JWT tooling reads"
    );

    let policy = policy(credentials.clone());
    let auth = judge(&policy, &assertion(&key_file, &format!("{ISSUER}/oauth2/v4/token")))
        .await
        .expect("a signed assertion authenticates");
    let Authorization::Admin(admin) = auth else {
        panic!("a service account must be admin, got {auth:?}");
    };
    assert_eq!(admin.subject.as_deref(), Some(account.client_email.as_str()));
    assert_eq!(admin.project_id.as_deref(), Some("demo"));
}

#[tokio::test]
async fn an_assertion_signed_by_the_wrong_key_is_refused() {
    let credentials = credentials().await;
    let (_, mine) =
        credentials.create_service_account(&unique("real"), "demo").await.expect("create");
    let (_, theirs) =
        credentials.create_service_account(&unique("other"), "demo").await.expect("create");

    // Claim to be one account while holding the other's private key: the
    // whole point of a signed credential is that this fails.
    let email = mine["client_email"].as_str().expect("email");
    let forged = sign(
        &serde_json::json!({
            "private_key": theirs["private_key"],
            "private_key_id": mine["private_key_id"],
            "client_email": mine["client_email"],
        }),
        serde_json::json!({ "iss": email, "sub": email, "aud": ISSUER, "exp": now() + 600 }),
    );
    assert!(judge(&policy(credentials), &forged).await.is_err());
}

/// The OAuth2 JWT-bearer grant: what a client performs when it honours the
/// key file's `token_uri` instead of sending the assertion directly.
#[tokio::test]
async fn an_assertion_exchanges_for_an_access_token() {
    let credentials = credentials().await;
    let (account, key_file) =
        credentials.create_service_account(&unique("exchange"), "demo").await.expect("create");

    let (access_token, expires_in) = credentials
        .exchange_assertion(&assertion(&key_file, &format!("{ISSUER}/oauth2/v4/token")))
        .await
        .expect("exchange");
    assert!(expires_in > 0);

    let auth =
        judge(&policy(credentials), &access_token).await.expect("access token authenticates");
    let Authorization::Admin(admin) = auth else {
        panic!("an access token must be admin, got {auth:?}");
    };
    assert_eq!(admin.subject.as_deref(), Some(account.client_email.as_str()));
}

/// Revocation has to reach tokens that were already minted, not just refuse
/// new ones — otherwise a leaked credential stays usable until it expires.
#[tokio::test]
async fn revocation_stops_assertions_and_outstanding_access_tokens() {
    let credentials = credentials().await;
    let (account, key_file) =
        credentials.create_service_account(&unique("revoke"), "demo").await.expect("create");
    let signed = assertion(&key_file, ISSUER);
    let (access_token, _) = credentials.exchange_assertion(&signed).await.expect("exchange");

    let policy = policy(credentials.clone());
    assert!(judge(&policy, &signed).await.is_ok(), "valid before revocation");
    assert!(judge(&policy, &access_token).await.is_ok(), "valid before revocation");

    credentials.revoke_service_account(&account.client_email).await.expect("revoke");

    assert!(judge(&policy, &signed).await.is_err(), "a revoked account cannot assert");
    assert!(
        judge(&policy, &access_token).await.is_err(),
        "an access token already handed out must stop working too"
    );
}

/// An assertion valid for a year is a bearer secret wearing a signature.
#[tokio::test]
async fn a_long_lived_assertion_is_refused() {
    let credentials = credentials().await;
    let (_, key_file) =
        credentials.create_service_account(&unique("longlived"), "demo").await.expect("create");
    let email = key_file["client_email"].as_str().expect("email");
    let forever = sign(
        &key_file,
        serde_json::json!({
            "iss": email,
            "sub": email,
            "aud": ISSUER,
            "iat": now(),
            "exp": now() + 365 * 24 * 3600,
        }),
    );
    assert!(judge(&policy(credentials), &forever).await.is_err());
}

/// The self-hosting path: a service account vouches for a uid, waldflam
/// issues the ID token, and waldflam's own verifier accepts it — no external
/// identity provider anywhere in the loop.
#[tokio::test]
async fn a_custom_token_becomes_a_user_identity() {
    let credentials = credentials().await;
    let (_, key_file) =
        credentials.create_service_account(&unique("signin"), "demo").await.expect("create");
    let email = key_file["client_email"].as_str().expect("email");

    let custom_token = sign(
        &key_file,
        serde_json::json!({
            "iss": email,
            "sub": email,
            "aud": CUSTOM_TOKEN_AUDIENCE,
            "iat": now(),
            "exp": now() + 3600,
            "uid": "alice",
            "claims": { "role": "editor" },
        }),
    );
    let signed_in =
        credentials.sign_in_with_custom_token(&custom_token).await.expect("sign in succeeds");
    assert_eq!(signed_in.uid, "alice");
    assert_eq!(signed_in.project_id, "demo");

    let auth =
        judge(&policy(credentials.clone()), &signed_in.id_token).await.expect("id token verifies");
    let Authorization::User(claims) = auth else {
        panic!("an ID token is a user, not an admin: {auth:?}");
    };
    assert_eq!(claims.uid.as_deref(), Some("alice"));
    assert_eq!(claims.project_id.as_deref(), Some("demo"));
    assert_eq!(claims.payload["role"], serde_json::json!("editor"), "custom claims reach rules");
    assert_eq!(claims.payload["user_id"], serde_json::json!("alice"));

    // The key that signed it must be published, or nothing else could check
    // this token.
    let jwks = credentials.jwks().await.expect("jwks");
    let kid = jsonwebtoken::decode_header(&signed_in.id_token).expect("header").kid.expect("kid");
    assert!(
        jwks["keys"].as_array().expect("keys").iter().any(|key| key["kid"] == kid.as_str()),
        "the signing key must appear in the published key set"
    );
}

/// Token kinds must not be interchangeable: a user holding an ID token must
/// not be able to present it where a service account's access token goes.
#[tokio::test]
async fn a_refresh_token_is_not_a_credential() {
    let credentials = credentials().await;
    let (_, key_file) =
        credentials.create_service_account(&unique("refresh"), "demo").await.expect("create");
    let email = key_file["client_email"].as_str().expect("email");
    let custom_token = sign(
        &key_file,
        serde_json::json!({
            "iss": email, "sub": email, "aud": CUSTOM_TOKEN_AUDIENCE,
            "iat": now(), "exp": now() + 3600, "uid": "bob",
        }),
    );
    let signed_in = credentials.sign_in_with_custom_token(&custom_token).await.expect("sign in");

    assert!(
        judge(&policy(credentials.clone()), &signed_in.refresh_token).await.is_err(),
        "a refresh token is for the refresh endpoint, not for authenticating requests"
    );

    let refreshed = credentials.refresh(&signed_in.refresh_token).await.expect("refresh");
    assert_eq!(refreshed.uid, "bob");
    let auth = judge(&policy(credentials), &refreshed.id_token).await.expect("refreshed id token");
    assert!(matches!(auth, Authorization::User(_)));
}

/// Custom claims cannot overwrite the claims that give an ID token meaning.
#[tokio::test]
async fn reserved_claims_cannot_be_overridden() {
    let credentials = credentials().await;
    let (_, key_file) =
        credentials.create_service_account(&unique("reserved"), "demo").await.expect("create");
    let email = key_file["client_email"].as_str().expect("email");
    let custom_token = sign(
        &key_file,
        serde_json::json!({
            "iss": email, "sub": email, "aud": CUSTOM_TOKEN_AUDIENCE,
            "iat": now(), "exp": now() + 3600, "uid": "mallory",
            // Claiming to be someone else, and to be a service account.
            "claims": { "sub": "admin", "wf_typ": "access" },
        }),
    );
    assert!(credentials.sign_in_with_custom_token(&custom_token).await.is_err());
}

/// A credential for one project must not reach another project's data.
#[tokio::test]
async fn a_service_account_is_confined_to_its_project() {
    let credentials = credentials().await;
    let (_, key_file) =
        credentials.create_service_account(&unique("scoped"), "alpha").await.expect("create");
    let auth = judge(&policy(credentials), &assertion(&key_file, ISSUER)).await.expect("valid");

    assert!(matches!(auth.for_project("alpha"), Authorization::Admin(_)));
    assert_eq!(
        auth.for_project("beta"),
        Authorization::Unauthenticated,
        "alpha's service account is nobody in beta"
    );
}

/// With no external issuer configured, a token from somewhere else is simply
/// not trusted — verified mode does not fall open.
#[tokio::test]
async fn tokens_from_elsewhere_are_refused() {
    let credentials = credentials().await;
    let policy = policy(credentials);
    for token in ["owner", "not.a.jwt", "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhbGljZSJ9."] {
        assert!(judge(&policy, token).await.is_err(), "{token} must not authenticate");
    }
}

/// Revoking on one instance must reach the others once their cache turns
/// over — and must *keep* reaching them. A cached lookup that skips the
/// revocation check would let a revoked credential work again on every
/// request after the first one that refreshed the cache.
#[tokio::test]
async fn revocation_reaches_other_instances_and_stays_that_way() {
    let ttl = std::time::Duration::from_millis(150);
    let one = Arc::new(credentials_with_ttl(ttl).await);
    let two = credentials_with_ttl(ttl).await;

    let (account, key_file) =
        one.create_service_account(&unique("cluster"), "demo").await.expect("create");
    let signed = assertion(&key_file, ISSUER);
    let policy = policy(one.clone());
    assert!(judge(&policy, &signed).await.is_ok(), "valid before revocation");

    // A different instance revokes it: this one's cache knows nothing of it.
    two.revoke_service_account(&account.client_email).await.expect("revoke");
    tokio::time::sleep(ttl * 2).await;

    for attempt in 1..=3 {
        assert!(
            judge(&policy, &signed).await.is_err(),
            "attempt {attempt}: a revoked credential must stay revoked"
        );
    }
}
