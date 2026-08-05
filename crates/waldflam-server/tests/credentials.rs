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

/// Revoking on one instance must reach the others *now*, not when their
/// caches happen to turn over.
///
/// The cache lifetime here is five minutes, so a pass cannot come from
/// expiry — only from the invalidation broadcast.
#[tokio::test]
async fn a_revocation_reaches_another_instance_immediately() {
    let ttl = std::time::Duration::from_secs(300);
    let one = Arc::new(credentials_with_ttl(ttl).await);
    let two = Arc::new(credentials_with_ttl(ttl).await);
    waldflam_server::credentials::spawn_invalidation_watcher(two.clone());
    // A change stream opened without a resume token only sees what happens
    // after it opens, so let the watcher get established before publishing.
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    let (account, key_file) =
        one.create_service_account(&unique("broadcast"), "demo").await.expect("create");
    let signed = assertion(&key_file, ISSUER);
    let policy = policy(two.clone());
    assert!(judge(&policy, &signed).await.is_ok(), "valid before revocation, and now cached");

    one.revoke_service_account(&account.client_email).await.expect("revoke");

    for _ in 0..100 {
        if judge(&policy, &signed).await.is_err() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("revocation did not reach the other instance within 5s, and its cache lasts 300s");
}

/// Signs a user in and returns the session, for the revocation tests below.
async fn sign_in(
    credentials: &Credentials,
    name: &str,
    uid: &str,
) -> waldflam_server::credentials::SignIn {
    let (_, key_file) =
        credentials.create_service_account(&unique(name), "demo").await.expect("create");
    let email = key_file["client_email"].as_str().expect("email");
    let custom_token = sign(
        &key_file,
        serde_json::json!({
            "iss": email, "sub": email, "aud": CUSTOM_TOKEN_AUDIENCE,
            "iat": now(), "exp": now() + 3600, "uid": uid,
        }),
    );
    credentials.sign_in_with_custom_token(&custom_token).await.expect("sign in")
}

/// A refresh token is opaque and stored, so it can actually be taken back —
/// which a signed one could not be before its thirty days were up.
#[tokio::test]
async fn revoking_a_user_ends_their_sessions() {
    let credentials = credentials().await;
    let session = sign_in(&credentials, "session", "alice").await;

    assert!(
        !session.refresh_token.contains('.'),
        "a refresh token must be opaque, not a JWT anyone can read"
    );
    assert!(credentials.refresh(&session.refresh_token).await.is_ok(), "works before revocation");

    credentials.revoke_identity_tokens("demo", "alice").await.expect("revoke");

    assert!(
        credentials.refresh(&session.refresh_token).await.is_err(),
        "a revoked session must not be able to refresh"
    );
}

/// Revoking one user must not sign out another.
#[tokio::test]
async fn revoking_one_user_leaves_others_alone() {
    let credentials = credentials().await;
    let alice = sign_in(&credentials, "alice-sess", "alice").await;
    let bob = sign_in(&credentials, "bob-sess", "bob").await;

    credentials.revoke_identity_tokens("demo", "alice").await.expect("revoke");

    assert!(credentials.refresh(&alice.refresh_token).await.is_err());
    assert!(credentials.refresh(&bob.refresh_token).await.is_ok(), "bob was not signed out");
}

/// A refresh token that names nothing must be refused, and must not say
/// whether it ever named anything.
#[tokio::test]
async fn an_unknown_refresh_token_is_refused() {
    let credentials = credentials().await;
    let error = credentials.refresh("not-a-real-token").await.expect_err("refused");
    assert_eq!(error.message(), "refresh token rejected");

    // A revoked one reports the same thing, so a caller cannot tell a token
    // that was never issued from one that was.
    let session = sign_in(&credentials, "opaque", "carol").await;
    credentials.revoke_identity_tokens("demo", "carol").await.expect("revoke");
    let revoked = credentials.refresh(&session.refresh_token).await.expect_err("refused");
    assert_eq!(revoked.message(), error.message());
}

/// Firebase's tradeoff, and now ours: an ID token already handed out stays
/// valid until it expires unless the server is asked to check.
#[tokio::test]
async fn id_tokens_survive_revocation_unless_checks_are_on() {
    let relaxed = credentials().await;
    let session = sign_in(&relaxed, "relaxed", "dave").await;
    relaxed.revoke_identity_tokens("demo", "dave").await.expect("revoke");
    assert!(
        judge(&policy(relaxed.clone()), &session.id_token).await.is_ok(),
        "by default an issued ID token lives out its hour, as in Firebase"
    );

    // Same token, a server that checks.
    let strict = Arc::new(
        credentials_with_ttl(std::time::Duration::from_millis(1))
            .await
            .with_revocation_checks(true),
    );
    assert!(
        judge(&policy(strict), &session.id_token).await.is_err(),
        "with revocation checks on, a signed-out user's ID token must be refused"
    );
}

/// The signing key is deployment-wide state, so two tests rotating at once
/// would see each other's keys. Serialised rather than isolated because the
/// key is genuinely global — pretending otherwise would test a fiction.
static ROTATION: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Rotation must not be an outage: tokens signed by the old key have to keep
/// verifying until they expire, and the new key has to take over for signing.
#[tokio::test]
async fn rotating_the_signing_key_keeps_old_tokens_working() {
    let _serialised = ROTATION.lock().await;
    let credentials = credentials().await;
    let before = sign_in(&credentials, "rotate", "erin").await;
    let policy = policy(credentials.clone());
    assert!(judge(&policy, &before.id_token).await.is_ok(), "valid before rotation");

    let old_kid = jsonwebtoken::decode_header(&before.id_token).expect("header").kid.expect("kid");
    let new_kid = credentials.rotate_signing_key().await.expect("rotate");
    assert_ne!(new_kid, old_kid, "rotation must produce a different key");

    // The whole point: a token already in circulation still verifies.
    assert!(
        judge(&policy, &before.id_token).await.is_ok(),
        "a token signed by the retired key must keep working until it expires"
    );

    // And new tokens carry the new key.
    let after = sign_in(&credentials, "rotate2", "erin").await;
    let signed_with =
        jsonwebtoken::decode_header(&after.id_token).expect("header").kid.expect("kid");
    assert_eq!(signed_with, new_kid, "new tokens must be signed by the new key");
    assert!(judge(&policy, &after.id_token).await.is_ok());

    // Both keys are published, or verifiers could not check both.
    let jwks = credentials.jwks().await.expect("jwks");
    let published: Vec<&str> =
        jwks["keys"].as_array().expect("keys").iter().filter_map(|k| k["kid"].as_str()).collect();
    assert!(published.contains(&old_kid.as_str()), "the retired key must still be published");
    assert!(published.contains(&new_kid.as_str()), "the new key must be published");
}

/// A key rotated in on one instance has to be picked up by another without
/// waiting out its refresh interval, or every token minted after a rotation
/// would be rejected there for a minute.
#[tokio::test]
async fn another_instance_picks_up_a_rotated_key() {
    let _serialised = ROTATION.lock().await;
    let one = credentials().await;
    let two = credentials().await;

    // Give `two` a loaded key set that predates the rotation.
    let before = sign_in(&one, "pickup", "frank").await;
    assert!(judge(&policy(two.clone()), &before.id_token).await.is_ok());

    one.rotate_signing_key().await.expect("rotate");
    let after = sign_in(&one, "pickup2", "frank").await;

    assert!(
        judge(&policy(two.clone()), &after.id_token).await.is_ok(),
        "a token naming an unfamiliar key must trigger a re-read, not a rejection"
    );
}

/// An assertion traded for an access token is spent: presenting the same one
/// again must not buy a second token.
#[tokio::test]
async fn a_one_shot_assertion_cannot_be_replayed() {
    let credentials = credentials().await;
    let (_, key_file) =
        credentials.create_service_account(&unique("replay"), "demo").await.expect("create");
    let email = key_file["client_email"].as_str().expect("email");
    let once = sign(
        &key_file,
        serde_json::json!({
            "iss": email, "sub": email, "aud": ISSUER,
            "iat": now(), "exp": now() + 600, "jti": unique("nonce"),
        }),
    );

    assert!(credentials.exchange_assertion(&once).await.is_ok(), "first exchange works");
    let replayed = credentials.exchange_assertion(&once).await.expect_err("replay refused");
    assert!(replayed.message().contains("already been used"), "{}", replayed.message());
}

/// The flow that would break if replay protection were applied everywhere:
/// a self-signed assertion is sent as a bearer token on *every* request for
/// its whole lifetime, so it must stay usable more than once.
#[tokio::test]
async fn an_assertion_used_as_a_bearer_token_still_works_repeatedly() {
    let credentials = credentials().await;
    let (_, key_file) =
        credentials.create_service_account(&unique("bearer"), "demo").await.expect("create");
    let email = key_file["client_email"].as_str().expect("email");
    let repeated = sign(
        &key_file,
        serde_json::json!({
            "iss": email, "sub": email, "aud": ISSUER,
            "iat": now(), "exp": now() + 600, "jti": unique("nonce"),
        }),
    );

    let policy = policy(credentials);
    for attempt in 1..=3 {
        assert!(
            judge(&policy, &repeated).await.is_ok(),
            "attempt {attempt}: a bearer assertion is reused by design and must keep working"
        );
    }
}

/// Two service accounts choosing the same `jti` must not collide — the claim
/// is only unique per issuer.
#[tokio::test]
async fn the_same_jti_from_two_issuers_does_not_collide() {
    let credentials = credentials().await;
    let nonce = unique("shared");
    let mut assertions = Vec::new();
    for label in ["issuer-a", "issuer-b"] {
        let (_, key_file) =
            credentials.create_service_account(&unique(label), "demo").await.expect("create");
        let email = key_file["client_email"].as_str().expect("email").to_owned();
        assertions.push(sign(
            &key_file,
            serde_json::json!({
                "iss": email, "sub": email, "aud": ISSUER,
                "iat": now(), "exp": now() + 600, "jti": nonce,
            }),
        ));
    }
    for assertion in &assertions {
        assert!(
            credentials.exchange_assertion(assertion).await.is_ok(),
            "the same jti from a different issuer is a different assertion"
        );
    }
}

/// A custom token buys a session, so replaying one would mint a second.
#[tokio::test]
async fn a_custom_token_cannot_be_replayed() {
    let credentials = credentials().await;
    let (_, key_file) =
        credentials.create_service_account(&unique("ctreplay"), "demo").await.expect("create");
    let email = key_file["client_email"].as_str().expect("email");
    let custom_token = sign(
        &key_file,
        serde_json::json!({
            "iss": email, "sub": email, "aud": CUSTOM_TOKEN_AUDIENCE,
            "iat": now(), "exp": now() + 600, "uid": "grace", "jti": unique("nonce"),
        }),
    );

    assert!(credentials.sign_in_with_custom_token(&custom_token).await.is_ok());
    assert!(
        credentials.sign_in_with_custom_token(&custom_token).await.is_err(),
        "a captured custom token must not mint a second session"
    );
}

/// Without a `jti` there is nothing to track, so RFC 7523 leaves replay
/// protection off — unless the deployment insists.
#[tokio::test]
async fn assertions_without_a_jti_are_allowed_unless_required() {
    let credentials = credentials().await;
    let (_, key_file) =
        credentials.create_service_account(&unique("nojti"), "demo").await.expect("create");
    let without = assertion(&key_file, ISSUER);
    assert!(credentials.exchange_assertion(&without).await.is_ok(), "permitted by default");

    let strict = Arc::new(
        credentials_with_ttl(std::time::Duration::from_secs(30)).await.with_required_jti(true),
    );
    let error = strict.exchange_assertion(&without).await.expect_err("refused when required");
    assert!(error.message().contains("jti"), "{}", error.message());
}
