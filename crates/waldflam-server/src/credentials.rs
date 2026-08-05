//! Service-account credentials, and the tokens waldflam issues itself.
//!
//! Two kinds of identity, one signing story:
//!
//! - **Service accounts** are machine credentials. waldflam generates an RSA
//!   keypair, hands the operator a Google-shaped key file once, and keeps
//!   only the public half. Holding the private key proves the identity, so
//!   there is no shared secret to leak, credentials expire on their own, and
//!   revoking one reaches every instance — within [`ACCOUNT_CACHE_TTL`], and
//!   including access tokens already handed out.
//! - **ID tokens** are user identities that waldflam mints for a `uid` after
//!   a service account vouches for it (a custom token). They are signed with
//!   the deployment's own key and published at a JWKS endpoint, which is what
//!   lets verified mode run with no external identity provider at all.
//!
//! Everything is RS256, because that is what the Firebase and Google client
//! libraries sign and verify — the point is that their credential handling
//! works unchanged.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures::StreamExt as _;
use rsa::traits::PublicKeyParts as _;
use tonic::Status;
use waldflam_engine::credentials::{
    ACTIVE_SIGNING_KEY, RefreshTokenRecord, ServiceAccount, SigningKey, identity_key,
};
use waldflam_engine::store::Store;

/// Lifetime of a minted access token. Short on purpose: an access token is
/// the thing that travels on every request, so it is the thing most likely to
/// be captured, and the holder can always mint another.
const ACCESS_TOKEN_TTL: i64 = 3600;

/// Lifetime of a minted ID token. Matches Firebase, so clients that refresh
/// on a schedule behave the same way here.
const ID_TOKEN_TTL: i64 = 3600;

/// Lifetime of a refresh token.
const REFRESH_TOKEN_TTL: i64 = 30 * 24 * 3600;

/// Bytes of randomness in a refresh token. Opaque rather than signed, so
/// unguessability is the entire security property.
const REFRESH_TOKEN_BYTES: usize = 32;

/// Longest assertion we will honour. A client that signs a year-long
/// assertion has effectively minted a bearer secret; capping the window keeps
/// a captured assertion from outliving its usefulness.
const MAX_ASSERTION_LIFETIME: i64 = 3600;

/// Tolerance for clock skew between waldflam and whoever signed the token.
const CLOCK_LEEWAY_SECONDS: u64 = 60;

/// How long a service-account lookup is reused before going back to MongoDB.
///
/// This is the delay between revoking a credential and the last instance
/// honouring it. Short enough that revocation is meaningful, long enough that
/// a busy server isn't reading the same row thousands of times a second.
const ACCOUNT_CACHE_TTL: Duration = Duration::from_secs(30);

/// Size of generated RSA keys.
const KEY_BITS: usize = 2048;

/// How long this instance reuses its copy of the signing keys before
/// re-reading them. Bounds how long a rotation elsewhere goes unnoticed;
/// a token naming an unknown key forces a reload anyway, so this only
/// governs when we stop *signing* with a key that has been retired.
const SIGNING_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// Shortest gap between key re-reads prompted by a token naming a key we
/// don't know. Without it, junk tokens would be a way to make this server
/// hammer MongoDB.
const SIGNING_RELOAD_THROTTLE: Duration = Duration::from_secs(5);

/// How long a retired key keeps verifying. Every token it could have signed
/// is an access or ID token, both of which live an hour; the extra covers
/// clock skew and instances that hadn't noticed the rotation yet.
///
/// Refresh tokens are deliberately *not* in this calculation — they are
/// opaque and stored, not signed, so a thirty-day session no longer forces a
/// thirty-day key retention.
const RETIRED_KEY_GRACE: i64 = ACCESS_TOKEN_TTL + SIGNING_REFRESH_INTERVAL.as_secs() as i64 + 300;

/// The `aud` the Firebase Admin SDKs put on a custom token.
const CUSTOM_TOKEN_AUDIENCE: &str =
    "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit";

/// Claim naming the kind of token waldflam minted. Inside our own signature,
/// so it cannot be forged — which is what keeps a user's ID token from being
/// presented as a service account's access token.
const KIND_CLAIM: &str = "wf_typ";

/// Claims a caller may not set on a custom token, because waldflam sets them
/// and the ID token's meaning depends on them.
const RESERVED_CLAIMS: &[&str] = &[
    "iss",
    "aud",
    "sub",
    "iat",
    "exp",
    "nbf",
    "jti",
    "auth_time",
    "user_id",
    "firebase",
    KIND_CLAIM,
];

/// Service accounts and the deployment's signing key.
///
/// The signing key is loaded lazily: a server that never touches credentials
/// (emulator mode, which is every local workflow) should not pay for RSA key
/// generation at startup. Verified mode forces it during boot instead, so a
/// broken key surfaces immediately rather than on the first request.
pub struct Credentials {
    store: Store,
    /// This deployment's identity as a token issuer, and the base URL the
    /// key file points back at. Externally reachable, or the credentials it
    /// emits will point clients somewhere they cannot go.
    issuer: String,
    /// Reloadable, not load-once: a key rotated on another instance has to
    /// be picked up here, both to verify its tokens and to stop signing with
    /// the retired one.
    signing: tokio::sync::RwLock<Option<CachedSigning>>,
    /// When a token naming an unknown key last prompted a re-read.
    last_key_miss: std::sync::Mutex<Option<Instant>>,
    accounts: RwLock<HashMap<String, CachedAccount>>,
    /// `{project}:{uid}` → when that user's tokens stopped counting.
    identities: RwLock<HashMap<String, CachedValidAfter>>,
    account_cache_ttl: Duration,
    check_revoked: bool,
    require_jti: bool,
}

struct CachedAccount {
    at: Instant,
    account: Option<ServiceAccount>,
}

struct CachedValidAfter {
    at: Instant,
    valid_after_us: i64,
}

struct CachedSigning {
    at: Instant,
    signing: std::sync::Arc<Signing>,
}

/// Loaded signing material for the deployment key.
struct Signing {
    key_id: String,
    encoding: jsonwebtoken::EncodingKey,
    /// Every key whose signatures are still accepted, by `kid` — retired keys
    /// included, so rotation doesn't invalidate tokens already in flight.
    verifying: HashMap<String, jsonwebtoken::DecodingKey>,
    jwks: serde_json::Value,
}

/// What a bearer token turned out to be.
#[derive(Debug, Clone, PartialEq)]
pub enum Resolved {
    /// A service account, proven either by a direct assertion or by an
    /// access token waldflam minted for it.
    ServiceAccount { client_email: String, project_id: String },
    /// A user identity from an ID token waldflam issued.
    User { uid: String, project_id: String, claims: serde_json::Map<String, serde_json::Value> },
}

impl Credentials {
    pub fn new(store: Store, issuer: String) -> Self {
        Self {
            store,
            issuer: issuer.trim_end_matches('/').to_owned(),
            signing: tokio::sync::RwLock::new(None),
            last_key_miss: std::sync::Mutex::new(None),
            accounts: RwLock::new(HashMap::new()),
            identities: RwLock::new(HashMap::new()),
            account_cache_ttl: ACCOUNT_CACHE_TTL,
            check_revoked: false,
            require_jti: false,
        }
    }

    /// Refuses one-shot assertions that carry no `jti`, instead of letting
    /// them through unprotected.
    ///
    /// Off by default because the Google auth libraries don't all set one and
    /// requiring it would lock them out. Turn it on where the clients are
    /// yours: without it, replay protection is only as good as what each
    /// client happens to send.
    pub fn with_required_jti(mut self, require: bool) -> Self {
        self.require_jti = require;
        self
    }

    /// Checks every ID token against its user's revocation state, instead of
    /// trusting it until it expires.
    ///
    /// Off by default, matching Firebase: `verifyIdToken` ignores revocation
    /// unless asked, because the check costs a lookup on every request and an
    /// ID token only lives an hour. Turn it on when an hour is too long to
    /// wait for a sign-out to bite.
    pub fn with_revocation_checks(mut self, check: bool) -> Self {
        self.check_revoked = check;
        self
    }

    /// Overrides how long credential lookups are cached.
    ///
    /// With the invalidation broadcast running this is only the backstop —
    /// how long a revocation could go unnoticed by an instance whose change
    /// stream is broken. Lower it if that worst case matters more than the
    /// extra reads.
    pub fn with_account_cache_ttl(mut self, ttl: Duration) -> Self {
        self.account_cache_ttl = ttl;
        self
    }

    /// Drops whatever is cached for these selectors, so the next request
    /// re-reads them.
    ///
    /// Both caches are cleared regardless of what the selector names: a key
    /// id, an email and a `{project}:{uid}` can't collide, so matching on the
    /// event's kind would only add a way to get it wrong.
    fn forget(&self, selectors: &[String]) {
        let mut accounts = self.accounts.write().expect("account cache");
        let mut identities = self.identities.write().expect("identity cache");
        for selector in selectors {
            accounts.remove(selector);
            identities.remove(selector);
        }
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Forces the signing key to exist, so a deployment fails at boot rather
    /// than on its first authenticated request.
    pub async fn warm(&self) -> Result<(), Status> {
        self.signing().await.map(|_| ())
    }

    /// The current signing material, reloading when the copy in hand is old
    /// enough that a rotation elsewhere could have happened.
    async fn signing(&self) -> Result<std::sync::Arc<Signing>, Status> {
        if let Some(cached) = self.signing.read().await.as_ref()
            && cached.at.elapsed() < SIGNING_REFRESH_INTERVAL
        {
            return Ok(cached.signing.clone());
        }
        self.reload_signing().await
    }

    async fn reload_signing(&self) -> Result<std::sync::Arc<Signing>, Status> {
        let mut slot = self.signing.write().await;
        // Someone else may have reloaded while this task waited for the lock.
        if let Some(cached) = slot.as_ref()
            && cached.at.elapsed() < SIGNING_REFRESH_INTERVAL
        {
            return Ok(cached.signing.clone());
        }
        let signing = std::sync::Arc::new(Signing::load(&self.store).await?);
        *slot = Some(CachedSigning { at: Instant::now(), signing: signing.clone() });
        Ok(signing)
    }

    /// Signing material that can verify `kid`, re-reading if this instance
    /// has not yet seen the key a token names — which is exactly what a
    /// rotation on another instance looks like from here.
    ///
    /// Throttled, because an unknown `kid` is also what a stream of junk
    /// tokens looks like, and that must not become a stream of database
    /// reads.
    async fn signing_for(&self, kid: &str) -> Result<std::sync::Arc<Signing>, Status> {
        let signing = self.signing().await?;
        if signing.verifying.contains_key(kid) {
            return Ok(signing);
        }
        let mut slot = self.signing.write().await;
        if let Some(cached) = slot.as_ref()
            && cached.signing.verifying.contains_key(kid)
        {
            // Another task reloaded while this one waited for the lock.
            return Ok(cached.signing.clone());
        }
        // Throttle on when a *miss* last made us re-read, not on when the
        // keys were loaded: the first unknown key after a rotation has to get
        // through, and it is the repeats that need damping.
        {
            let mut last = self.last_key_miss.lock().expect("key miss clock");
            if last.is_some_and(|at| at.elapsed() < SIGNING_RELOAD_THROTTLE)
                && let Some(cached) = slot.as_ref()
            {
                return Ok(cached.signing.clone());
            }
            *last = Some(Instant::now());
        }
        let reloaded = std::sync::Arc::new(Signing::load(&self.store).await?);
        *slot = Some(CachedSigning { at: Instant::now(), signing: reloaded.clone() });
        Ok(reloaded)
    }

    /// Retires the current signing key and starts signing with a new one.
    ///
    /// The old key keeps verifying until every token it could have signed has
    /// expired; anything shorter would invalidate tokens already in
    /// circulation, which is an outage rather than a rotation.
    pub async fn rotate_signing_key(&self) -> Result<String, Status> {
        let generated = generate_key()?;
        let now = now_seconds();
        let candidate = SigningKey {
            role: ACTIVE_SIGNING_KEY.into(),
            key_id: random_id(),
            private_key_pem: generated.private_key_pem,
            modulus: generated.modulus,
            exponent: generated.exponent,
            created_us: now * 1_000_000,
            retire_after_us: 0,
        };
        let retire_after_us = (now + RETIRED_KEY_GRACE) * 1_000_000;
        let rotated = self
            .store
            .rotate_signing_key(&candidate, retire_after_us)
            .await
            .map_err(engine_status)?;
        // Old enough keys are worth nothing but risk.
        self.store.purge_retired_signing_keys(now * 1_000_000).await.map_err(engine_status)?;
        // Drop this instance's copy so the next request picks the new key up
        // rather than waiting out the refresh interval.
        *self.signing.write().await = None;
        Ok(rotated.key_id)
    }

    /// The public keys verifying waldflam-issued tokens, in JWK Set form.
    pub async fn jwks(&self) -> Result<serde_json::Value, Status> {
        Ok(self.signing().await?.jwks.clone())
    }

    /// OpenID discovery, so a verifier — including waldflam's own, and
    /// anything else that speaks OIDC — can configure itself from the issuer
    /// URL alone.
    pub async fn discovery(&self) -> serde_json::Value {
        serde_json::json!({
            "issuer": self.issuer,
            "jwks_uri": format!("{}/.well-known/jwks.json", self.issuer),
            "token_endpoint": self.token_uri(),
            "id_token_signing_alg_values_supported": ["RS256"],
            "response_types_supported": ["id_token"],
            "subject_types_supported": ["public"],
            "grant_types_supported": [
                "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "refresh_token",
            ],
        })
    }

    fn token_uri(&self) -> String {
        format!("{}/oauth2/v4/token", self.issuer)
    }

    // ---- creating and managing service accounts -------------------------

    /// Creates a service account and returns its key file.
    ///
    /// The private key exists only in the returned value: it is generated
    /// here, never written to MongoDB, and cannot be recovered afterwards.
    /// Losing it means creating a new account, which is the correct failure
    /// mode for a credential.
    pub async fn create_service_account(
        &self,
        name: &str,
        project_id: &str,
    ) -> Result<(ServiceAccount, serde_json::Value), Status> {
        validate_account_name(name)?;
        let generated = generate_key()?;
        let account = ServiceAccount {
            key_id: random_id(),
            client_email: format!("{name}@{project_id}.iam.waldflam.local"),
            project_id: project_id.to_owned(),
            modulus: generated.modulus.clone(),
            exponent: generated.exponent.clone(),
            created_us: now_seconds() * 1_000_000,
            revoked: false,
        };
        self.store.register_service_account(&account).await.map_err(engine_status)?;

        // Shaped like a Google service-account key file so the official
        // client libraries load it without knowing it isn't one.
        let key_file = serde_json::json!({
            "type": "service_account",
            "project_id": account.project_id,
            "private_key_id": account.key_id,
            "private_key": generated.private_key_pem,
            "client_email": account.client_email,
            "client_id": account.key_id,
            "auth_uri": format!("{}/o/oauth2/auth", self.issuer),
            "token_uri": self.token_uri(),
            "auth_provider_x509_cert_url": format!("{}/.well-known/jwks.json", self.issuer),
            "universe_domain": "waldflam.local",
        });
        Ok((account, key_file))
    }

    pub async fn list_service_accounts(&self) -> Result<Vec<ServiceAccount>, Status> {
        self.store.list_service_accounts().await.map_err(engine_status)
    }

    /// Revokes by key id or email. Outstanding access tokens stop working
    /// too, within [`ACCOUNT_CACHE_TTL`], because every one of them is
    /// re-checked against the account it names.
    pub async fn revoke_service_account(
        &self,
        selector: &str,
    ) -> Result<Option<ServiceAccount>, Status> {
        let revoked = self.store.revoke_service_account(selector).await.map_err(engine_status)?;
        if let Some(account) = &revoked {
            // Locally now; the other instances learn from the notice the
            // store just published.
            self.forget(&[account.key_id.clone(), account.client_email.clone()]);
        }
        Ok(revoked)
    }

    /// Looks up a service account, distinguishing two failures that must be
    /// handled differently: `Ok(None)` means we have never heard of it, so a
    /// caller may try another issuer, while a revoked account is an error
    /// that must not fall through to anything else.
    ///
    /// The revocation check deliberately happens *after* the cache, not
    /// before it goes in: an account read back while already revoked would
    /// otherwise be cached as usable, and every request after the one that
    /// refreshed the cache would be let through.
    async fn find_account(
        &self,
        selector: &str,
        by_email: bool,
    ) -> Result<Option<ServiceAccount>, Status> {
        let cached = self
            .accounts
            .read()
            .expect("account cache")
            .get(selector)
            .filter(|hit| hit.at.elapsed() < self.account_cache_ttl)
            .map(|hit| hit.account.clone());

        let account = match cached {
            Some(account) => account,
            None => {
                let looked_up = if by_email {
                    self.store.service_account_by_email(selector).await
                } else {
                    self.store.service_account(selector).await
                }
                .map_err(engine_status)?;
                self.accounts.write().expect("account cache").insert(
                    selector.to_owned(),
                    CachedAccount { at: Instant::now(), account: looked_up.clone() },
                );
                looked_up
            }
        };

        match account {
            Some(account) if account.revoked => Err(Status::unauthenticated("credential revoked")),
            other => Ok(other),
        }
    }

    async fn account(&self, selector: &str, by_email: bool) -> Result<ServiceAccount, Status> {
        self.find_account(selector, by_email)
            .await?
            .ok_or_else(|| Status::unauthenticated("unknown credential"))
    }

    // ---- resolving incoming tokens --------------------------------------

    /// Judges a bearer token that may be a waldflam-issued token or a
    /// service-account assertion.
    ///
    /// `Ok(None)` means "not ours" — the token is signed by somebody else,
    /// and the caller should hand it to the configured external issuer.
    /// `Err` means it *is* ours and it is bad, which must not fall through to
    /// another verifier.
    pub async fn resolve(&self, token: &str) -> Result<Option<Resolved>, Status> {
        let Ok(header) = jsonwebtoken::decode_header(token) else {
            return Ok(None);
        };
        let Ok(payload) = unverified_payload(token) else {
            return Ok(None);
        };

        // Ours to verify? `signing_for` re-reads when the key is unfamiliar,
        // so a token signed by a key rotated in on another instance verifies
        // here immediately instead of after this instance's next refresh.
        if let Some(kid) = header.kid.as_deref() {
            let signing = self.signing_for(kid).await?;
            if signing.verifying.contains_key(kid) {
                return self.resolve_issued(token, &signing, kid).await.map(Some);
            }
        }

        // A service account's own assertion. Route by `kid` when present
        // (every Google auth library sets it from `private_key_id`), else by
        // the issuer, which is the account's email.
        let issuer = payload.get("iss").and_then(|v| v.as_str()).unwrap_or_default();
        // `?` rather than `.ok()`: an account we know to be revoked is a
        // rejection, not a token to hand to the next verifier.
        let account = match header.kid.as_deref() {
            Some(kid) => self.find_account(kid, false).await?,
            None if issuer.contains('@') => self.find_account(issuer, true).await?,
            None => None,
        };
        let Some(account) = account else {
            return Ok(None);
        };
        self.verify_assertion(token, &account, None)?;
        Ok(Some(Resolved::ServiceAccount {
            client_email: account.client_email,
            project_id: account.project_id,
        }))
    }

    /// Verifies a token waldflam signed, and says what it grants.
    async fn resolve_issued(
        &self,
        token: &str,
        signing: &Signing,
        kid: &str,
    ) -> Result<Resolved, Status> {
        let key = signing.verifying.get(kid).expect("checked by caller");
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_required_spec_claims(&["exp", "iss", "sub"]);
        // `aud` carries different things per token kind (the issuer for an
        // access token, the project for an ID token), so it is checked below
        // rather than by a single blanket rule here.
        validation.validate_aud = false;
        validation.leeway = CLOCK_LEEWAY_SECONDS;

        let decoded = jsonwebtoken::decode::<serde_json::Map<String, serde_json::Value>>(
            token,
            key,
            &validation,
        )
        .map_err(|e| Status::unauthenticated(format!("token rejected: {e}")))?;
        let claims = decoded.claims;

        let subject = claims
            .get("sub")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Status::unauthenticated("token has no subject"))?
            .to_owned();
        let audience = claims.get("aud").and_then(|v| v.as_str()).unwrap_or_default().to_owned();

        match claims.get(KIND_CLAIM).and_then(|v| v.as_str()) {
            Some("access") => {
                // Re-read the account so revocation reaches tokens that were
                // already minted; without this, revoking would only stop new
                // ones and the old ones would work until they expired.
                let account = self.account(&subject, true).await?;
                Ok(Resolved::ServiceAccount {
                    client_email: account.client_email,
                    project_id: account.project_id,
                })
            }
            Some("id") => {
                if self.check_revoked {
                    // `auth_time` is when the identity was established, which
                    // is what a revocation is compared against — `iat` would
                    // let a refresh mint a token that outlived the sign-out.
                    let auth_time = claim_i64(&claims, "auth_time").unwrap_or_default();
                    let valid_after = self.valid_after_us(&audience, &subject).await?;
                    if auth_time * 1_000_000 < valid_after {
                        return Err(Status::unauthenticated("token revoked"));
                    }
                }
                Ok(Resolved::User { uid: subject, project_id: audience, claims })
            }
            // A refresh token is for the refresh endpoint only. Accepting it
            // as a credential would hand out a month-long session token.
            other => {
                Err(Status::unauthenticated(format!("token of kind {other:?} is not a credential")))
            }
        }
    }

    /// Verifies a JWT signed by a service account's private key.
    ///
    /// `expect_audience` is enforced where the shape is fixed (custom
    /// tokens). It is *not* enforced for the OAuth2 assertion: the Google
    /// auth libraries each pick their own audience — the token endpoint, the
    /// service URL, the scope — and the assertion is useless anywhere else
    /// regardless, since no other service holds this account's public key.
    fn verify_assertion(
        &self,
        token: &str,
        account: &ServiceAccount,
        expect_audience: Option<&str>,
    ) -> Result<serde_json::Map<String, serde_json::Value>, Status> {
        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| Status::unauthenticated(format!("invalid token header: {e}")))?;
        if header.alg != jsonwebtoken::Algorithm::RS256 {
            return Err(Status::unauthenticated("assertions must be signed with RS256"));
        }
        let key =
            jsonwebtoken::DecodingKey::from_rsa_components(&account.modulus, &account.exponent)
                .map_err(|e| Status::internal(format!("stored public key unusable: {e}")))?;

        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_issuer(&[&account.client_email]);
        validation.set_required_spec_claims(&["exp", "iss"]);
        match expect_audience {
            Some(audience) => validation.set_audience(&[audience]),
            None => validation.validate_aud = false,
        }
        validation.leeway = CLOCK_LEEWAY_SECONDS;

        let decoded = jsonwebtoken::decode::<serde_json::Map<String, serde_json::Value>>(
            token,
            &key,
            &validation,
        )
        .map_err(|e| Status::unauthenticated(format!("assertion rejected: {e}")))?;
        let claims = decoded.claims;

        if let (Some(iat), Some(exp)) = (claim_i64(&claims, "iat"), claim_i64(&claims, "exp"))
            && exp - iat > MAX_ASSERTION_LIFETIME
        {
            return Err(Status::unauthenticated(format!(
                "assertion lifetime exceeds {MAX_ASSERTION_LIFETIME}s"
            )));
        }
        Ok(claims)
    }

    /// Spends a one-shot assertion, so presenting it twice fails the second
    /// time.
    ///
    /// **Only for assertions redeemed once.** The self-signed-JWT flow sends
    /// the *same* assertion as a bearer token on every request for its whole
    /// lifetime, by design; spending it there would reject the legitimate
    /// client on its second call. So this guards the two exchange
    /// endpoints — where an assertion buys a new credential — and nothing
    /// else.
    ///
    /// An assertion without a `jti` cannot be tracked, because there is
    /// nothing to track it by. RFC 7523 makes replay protection a MAY for
    /// exactly this reason, and a client that sends a `jti` gets it while one
    /// that doesn't, doesn't — unless the deployment requires it.
    async fn spend_assertion(
        &self,
        claims: &serde_json::Map<String, serde_json::Value>,
        issuer: &str,
    ) -> Result<(), Status> {
        let Some(jti) = claims.get("jti").and_then(|v| v.as_str()).filter(|jti| !jti.is_empty())
        else {
            if self.require_jti {
                return Err(Status::invalid_argument(
                    "assertion must carry a `jti` claim (WALDFLAM_AUTH_REQUIRE_JTI is set)",
                ));
            }
            return Ok(());
        };

        // Namespaced by issuer: `jti` is only unique per issuer, so two
        // service accounts could legitimately pick the same one.
        let id = hash_token(&format!("{issuer}:{jti}"));
        // Remember it exactly as long as the assertion could be replayed —
        // past its own expiry the signature check refuses it anyway.
        let expires_at = waldflam_engine::credentials::expiry_at(
            claim_i64(claims, "exp").unwrap_or_else(|| now_seconds() + MAX_ASSERTION_LIFETIME),
        );
        let first_use = self.store.claim_assertion(&id, expires_at).await.map_err(engine_status)?;
        if !first_use {
            return Err(Status::unauthenticated("assertion has already been used"));
        }
        Ok(())
    }

    // ---- minting ---------------------------------------------------------

    /// Exchanges a service-account assertion for an access token: the OAuth2
    /// JWT-bearer grant, which is what a Google auth library performs when it
    /// honours the key file's `token_uri`.
    pub async fn exchange_assertion(&self, assertion: &str) -> Result<(String, i64), Status> {
        let header = jsonwebtoken::decode_header(assertion)
            .map_err(|e| Status::unauthenticated(format!("invalid assertion: {e}")))?;
        let payload = unverified_payload(assertion)
            .map_err(|e| Status::unauthenticated(format!("invalid assertion: {e}")))?;
        let issuer = payload.get("iss").and_then(|v| v.as_str()).unwrap_or_default();
        let account = match header.kid.as_deref() {
            Some(kid) => self.account(kid, false).await?,
            None => self.account(issuer, true).await?,
        };
        let claims = self.verify_assertion(assertion, &account, None)?;
        // One-shot: this assertion is being traded for an access token, so a
        // second attempt with the same one is a replay.
        self.spend_assertion(&claims, &account.client_email).await?;
        self.mint_access_token(&account).await
    }

    async fn mint_access_token(&self, account: &ServiceAccount) -> Result<(String, i64), Status> {
        let now = now_seconds();
        self.sign(serde_json::json!({
            "iss": self.issuer,
            "sub": account.client_email,
            "aud": self.issuer,
            "project_id": account.project_id,
            KIND_CLAIM: "access",
            "iat": now,
            "exp": now + ACCESS_TOKEN_TTL,
        }))
        .await
        .map(|token| (token, ACCESS_TOKEN_TTL))
    }

    /// Verifies a custom token minted by a service account and issues the ID
    /// token a client actually authenticates with — waldflam standing in for
    /// the identity provider, so verified mode needs nothing external.
    pub async fn sign_in_with_custom_token(&self, custom_token: &str) -> Result<SignIn, Status> {
        let header = jsonwebtoken::decode_header(custom_token)
            .map_err(|e| Status::unauthenticated(format!("invalid custom token: {e}")))?;
        let payload = unverified_payload(custom_token)
            .map_err(|e| Status::unauthenticated(format!("invalid custom token: {e}")))?;
        let issuer = payload.get("iss").and_then(|v| v.as_str()).unwrap_or_default();
        let account = match header.kid.as_deref() {
            Some(kid) => self.account(kid, false).await?,
            None => self.account(issuer, true).await?,
        };
        let claims = self.verify_assertion(custom_token, &account, Some(CUSTOM_TOKEN_AUDIENCE))?;
        // Also one-shot: a custom token buys an ID token and a session, so
        // replaying one would mint a second session from a captured copy.
        self.spend_assertion(&claims, &account.client_email).await?;

        let uid = claims
            .get("uid")
            .and_then(|v| v.as_str())
            .filter(|uid| !uid.is_empty())
            .ok_or_else(|| Status::invalid_argument("custom token has no uid"))?;
        let extra = match claims.get("claims") {
            Some(serde_json::Value::Object(map)) => map.clone(),
            None => serde_json::Map::new(),
            Some(_) => {
                return Err(Status::invalid_argument("custom token `claims` must be an object"));
            }
        };
        self.issue_identity(&account.project_id, uid, &extra).await
    }

    /// Mints the ID + refresh token pair for a uid.
    async fn issue_identity(
        &self,
        project_id: &str,
        uid: &str,
        extra: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<SignIn, Status> {
        if let Some(reserved) = extra.keys().find(|k| RESERVED_CLAIMS.contains(&k.as_str())) {
            return Err(Status::invalid_argument(format!("custom claim {reserved:?} is reserved")));
        }
        let now = now_seconds();
        let mut claims = serde_json::Map::new();
        for (key, value) in extra {
            claims.insert(key.clone(), value.clone());
        }
        // Firebase's own claim shape, so rules and client SDKs written
        // against Firebase read what they expect.
        claims.insert("iss".into(), self.issuer.clone().into());
        claims.insert("aud".into(), project_id.into());
        claims.insert("sub".into(), uid.into());
        claims.insert("user_id".into(), uid.into());
        claims.insert("auth_time".into(), now.into());
        claims.insert("iat".into(), now.into());
        claims.insert("exp".into(), (now + ID_TOKEN_TTL).into());
        claims.insert(KIND_CLAIM.into(), "id".into());
        claims.insert(
            "firebase".into(),
            serde_json::json!({ "identities": {}, "sign_in_provider": "custom" }),
        );

        let id_token = self.sign(serde_json::Value::Object(claims)).await?;

        // Opaque and stored, not signed. A signed refresh token cannot be
        // taken back before it expires, and thirty days is a long time to be
        // unable to end a session; the cost is a lookup per refresh, which
        // happens hourly per user rather than per request.
        let refresh_token = random_token();
        self.store
            .store_refresh_token(&RefreshTokenRecord {
                token_hash: hash_token(&refresh_token),
                uid: uid.to_owned(),
                project_id: project_id.to_owned(),
                issued_us: now * 1_000_000,
                expires_at: waldflam_engine::credentials::expiry_at(now + REFRESH_TOKEN_TTL),
                revoked: false,
            })
            .await
            .map_err(engine_status)?;

        Ok(SignIn {
            id_token,
            refresh_token,
            expires_in: ID_TOKEN_TTL,
            uid: uid.to_owned(),
            project_id: project_id.to_owned(),
        })
    }

    /// Trades a refresh token for a fresh ID token.
    ///
    /// The presented token is hashed and looked up; a revoked or unknown one
    /// is refused. Returning the *same* refresh token matches Firebase and
    /// keeps clients from having to track rotation.
    pub async fn refresh(&self, refresh_token: &str) -> Result<SignIn, Status> {
        let record = self
            .store
            .refresh_token(&hash_token(refresh_token))
            .await
            .map_err(engine_status)?
            // Deliberately the same message for "never existed" and
            // "revoked": a caller holding a bad token learns only that it is
            // bad, not whether it ever named a real session.
            .ok_or_else(|| Status::unauthenticated("refresh token rejected"))?;
        if record.revoked {
            return Err(Status::unauthenticated("refresh token rejected"));
        }
        // MongoDB's TTL monitor runs on its own schedule, so an expired
        // record can outlive its expiry by minutes. Check the time here
        // rather than trusting the sweeper to be punctual.
        if record.issued_us / 1_000_000 + REFRESH_TOKEN_TTL < now_seconds() {
            return Err(Status::unauthenticated("refresh token rejected"));
        }

        let mut signed_in =
            self.issue_identity(&record.project_id, &record.uid, &serde_json::Map::new()).await?;
        // Hand back the token the caller already has rather than the freshly
        // minted one, so refreshing doesn't quietly orphan sessions.
        self.store
            .revoke_refresh_token(&hash_token(&signed_in.refresh_token))
            .await
            .map_err(engine_status)?;
        signed_in.refresh_token = refresh_token.to_owned();
        Ok(signed_in)
    }

    /// Ends every session a user has.
    ///
    /// Firebase's `revokeRefreshTokens(uid)`: refresh tokens stop working at
    /// once, and ID tokens already issued are rejected too — but only where
    /// [`Credentials::with_revocation_checks`] is on, because otherwise
    /// nothing looks.
    pub async fn revoke_identity_tokens(&self, project_id: &str, uid: &str) -> Result<(), Status> {
        // Rounded *up* to the next second, deliberately.
        //
        // `auth_time` is a whole number of seconds, so a token minted in the
        // same second as the revocation compares equal. Firebase resolves
        // that tie in the token's favour and documents waiting a second
        // before trusting a revocation; erring the other way costs a user at
        // most one second of not being able to sign back in, and closes a
        // window in which a token issued *before* the revocation survives it.
        let valid_after_us = (now_seconds() + 1) * 1_000_000;
        self.store
            .revoke_identity_tokens(project_id, uid, valid_after_us)
            .await
            .map_err(engine_status)?;
        self.forget(&[identity_key(project_id, uid)]);
        Ok(())
    }

    /// When this user's tokens stopped counting; `0` if never revoked.
    async fn valid_after_us(&self, project_id: &str, uid: &str) -> Result<i64, Status> {
        let key = identity_key(project_id, uid);
        if let Some(hit) = self.identities.read().expect("identity cache").get(&key)
            && hit.at.elapsed() < self.account_cache_ttl
        {
            return Ok(hit.valid_after_us);
        }
        let valid_after_us = self
            .store
            .identity(project_id, uid)
            .await
            .map_err(engine_status)?
            .map(|identity| identity.valid_after_us)
            .unwrap_or_default();
        self.identities
            .write()
            .expect("identity cache")
            .insert(key, CachedValidAfter { at: Instant::now(), valid_after_us });
        Ok(valid_after_us)
    }

    async fn sign(&self, claims: serde_json::Value) -> Result<String, Status> {
        let signing = self.signing().await?;
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(signing.key_id.clone());
        jsonwebtoken::encode(&header, &claims, &signing.encoding)
            .map_err(|e| Status::internal(format!("cannot sign token: {e}")))
    }
}

/// How long to wait before rebuilding a change stream that errored, so a
/// MongoDB outage doesn't become a reconnect storm.
const RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// Starts applying other instances' credential invalidations to this one's
/// caches.
///
/// Runs until the process exits, resuming its change stream where it left
/// off. If it can't — MongoDB down, stream broken — nothing is unsafe; the
/// cache lifetime takes over as the slower path it always was.
pub fn spawn_invalidation_watcher(credentials: std::sync::Arc<Credentials>) {
    tokio::spawn(async move {
        let mut resume_token = None;
        loop {
            let mut stream =
                match credentials.store.watch_credential_events(resume_token.clone()).await {
                    Ok(stream) => stream,
                    Err(error) => {
                        tracing::warn!(%error, "credentials: cannot open invalidation stream");
                        tokio::time::sleep(RECONNECT_DELAY).await;
                        continue;
                    }
                };
            tracing::debug!("credentials: tailing invalidations");
            while let Some(next) = stream.next().await {
                match next {
                    Ok(event) => {
                        resume_token = stream.resume_token();
                        let Some(notice) = event.full_document else {
                            continue;
                        };
                        // Ours was applied before it was published.
                        if notice.instance == credentials.store.instance_id() {
                            continue;
                        }
                        tracing::info!(
                            kind = %notice.kind,
                            count = notice.selectors.len(),
                            "credentials: applying a revocation from another instance"
                        );
                        credentials.forget(&notice.selectors);
                    }
                    Err(error) => {
                        tracing::warn!(%error, "credentials: invalidation stream failed, resuming");
                        break;
                    }
                }
            }
            tokio::time::sleep(RECONNECT_DELAY).await;
        }
    });
}

/// The result of signing in: what the identitytoolkit response carries.
///
/// `Debug` is written out rather than derived so the tokens never reach a log
/// line: both fields are live credentials, and a struct that prints itself is
/// one `dbg!` away from leaking a session.
pub struct SignIn {
    pub id_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub uid: String,
    pub project_id: String,
}

impl std::fmt::Debug for SignIn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignIn")
            .field("uid", &self.uid)
            .field("project_id", &self.project_id)
            .field("expires_in", &self.expires_in)
            .field("id_token", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .finish()
    }
}

impl Signing {
    /// Loads the deployment key, generating one the first time any instance
    /// needs it. The insert is atomic, so instances racing at first boot end
    /// up sharing a key rather than each minting tokens the others reject.
    async fn load(store: &Store) -> Result<Self, Status> {
        let existing = store.all_signing_keys().await.map_err(engine_status)?;
        let active = match existing.iter().find(|key| key.role == ACTIVE_SIGNING_KEY) {
            Some(key) => key.clone(),
            None => {
                tracing::info!("credentials: generating this deployment's signing key");
                let generated = generate_key()?;
                let candidate = SigningKey {
                    role: ACTIVE_SIGNING_KEY.into(),
                    key_id: random_id(),
                    private_key_pem: generated.private_key_pem,
                    modulus: generated.modulus,
                    exponent: generated.exponent,
                    created_us: now_seconds() * 1_000_000,
                    retire_after_us: 0,
                };
                store.signing_key_or_insert(&candidate).await.map_err(engine_status)?
            }
        };

        let mut all = existing;
        if !all.iter().any(|key| key.key_id == active.key_id) {
            all.push(active.clone());
        }
        let mut verifying = HashMap::new();
        let mut jwks = Vec::new();
        for key in &all {
            verifying.insert(
                key.key_id.clone(),
                jsonwebtoken::DecodingKey::from_rsa_components(&key.modulus, &key.exponent)
                    .map_err(|e| Status::internal(format!("stored signing key unusable: {e}")))?,
            );
            jwks.push(serde_json::json!({
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "kid": key.key_id,
                "n": key.modulus,
                "e": key.exponent,
            }));
        }

        Ok(Self {
            key_id: active.key_id.clone(),
            encoding: jsonwebtoken::EncodingKey::from_rsa_pem(active.private_key_pem.as_bytes())
                .map_err(|e| Status::internal(format!("stored signing key unusable: {e}")))?,
            verifying,
            jwks: serde_json::json!({ "keys": jwks }),
        })
    }
}

struct GeneratedKey {
    private_key_pem: String,
    modulus: String,
    exponent: String,
}

/// Generates an RSA keypair and renders it the way JWT tooling wants it:
/// PKCS#8 PEM for signing, base64url big-endian components for the JWK.
fn generate_key() -> Result<GeneratedKey, Status> {
    use rsa::pkcs8::{EncodePrivateKey as _, LineEnding};

    let mut rng = rand::thread_rng();
    let private = rsa::RsaPrivateKey::new(&mut rng, KEY_BITS)
        .map_err(|e| Status::internal(format!("cannot generate key: {e}")))?;
    let pem = private
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| Status::internal(format!("cannot encode key: {e}")))?
        .to_string();
    let public = private.to_public_key();
    Ok(GeneratedKey {
        private_key_pem: pem,
        modulus: URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
        exponent: URL_SAFE_NO_PAD.encode(public.e().to_bytes_be()),
    })
}

/// An opaque refresh token: unguessable randomness, nothing else.
fn random_token() -> String {
    use rand::RngCore as _;
    let mut bytes = [0u8; REFRESH_TOKEN_BYTES];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// What gets stored in place of a refresh token.
///
/// A plain SHA-256 with no salt or stretching, which would be wrong for a
/// password and is right here: the input is 32 bytes of uniform randomness,
/// so there is no dictionary to attack and nothing for a salt to defend.
fn hash_token(token: &str) -> String {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(token.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn random_id() -> String {
    use rand::Rng as _;
    let bytes: [u8; 20] = rand::thread_rng().r#gen();
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Service-account names become part of an email address and show up in
/// revocation commands and logs, so keep them boring.
fn validate_account_name(name: &str) -> Result<(), Status> {
    let shaped = (3..=30).contains(&name.len())
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if shaped {
        Ok(())
    } else {
        Err(Status::invalid_argument(
            "name must be 3-30 characters of [a-z0-9-], starting with a letter",
        ))
    }
}

/// Reads a JWT's claims *without* checking the signature, to decide which key
/// should check it. Nothing read here is trusted; it only routes.
fn unverified_payload(
    token: &str,
) -> Result<serde_json::Map<String, serde_json::Value>, &'static str> {
    let mut parts = token.split('.');
    let (Some(_header), Some(payload), Some(_signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("expected three dot-separated segments");
    };
    let bytes = URL_SAFE_NO_PAD.decode(payload).map_err(|_| "invalid base64url")?;
    match serde_json::from_slice(&bytes) {
        Ok(serde_json::Value::Object(map)) => Ok(map),
        _ => Err("payload is not a JSON object"),
    }
}

fn claim_i64(claims: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<i64> {
    claims.get(key).and_then(|v| v.as_i64())
}

fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs() as i64)
        .unwrap_or_default()
}

fn engine_status(error: waldflam_engine::EngineError) -> Status {
    match error {
        waldflam_engine::EngineError::AlreadyExists(what) => {
            Status::already_exists(format!("service account {what} already exists"))
        }
        other => Status::internal(other.to_string()),
    }
}
