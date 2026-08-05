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
use waldflam_engine::credentials::{ACTIVE_SIGNING_KEY, ServiceAccount, SigningKey};
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
    signing: tokio::sync::OnceCell<Signing>,
    accounts: RwLock<HashMap<String, CachedAccount>>,
    account_cache_ttl: Duration,
}

struct CachedAccount {
    at: Instant,
    account: Option<ServiceAccount>,
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
            signing: tokio::sync::OnceCell::new(),
            accounts: RwLock::new(HashMap::new()),
            account_cache_ttl: ACCOUNT_CACHE_TTL,
        }
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
    fn forget(&self, selectors: &[String]) {
        let mut cache = self.accounts.write().expect("account cache");
        for selector in selectors {
            cache.remove(selector);
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

    async fn signing(&self) -> Result<&Signing, Status> {
        self.signing.get_or_try_init(|| Signing::load(&self.store)).await
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

        // Ours to verify?
        if let Some(kid) = header.kid.as_deref()
            && self.signing().await?.verifying.contains_key(kid)
        {
            return self.resolve_issued(token, kid).await.map(Some);
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
    async fn resolve_issued(&self, token: &str, kid: &str) -> Result<Resolved, Status> {
        let signing = self.signing().await?;
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
            Some("id") => Ok(Resolved::User { uid: subject, project_id: audience, claims }),
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
        self.verify_assertion(assertion, &account, None)?;
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
        let refresh_token = self
            .sign(serde_json::json!({
                "iss": self.issuer,
                "sub": uid,
                "aud": project_id,
                KIND_CLAIM: "refresh",
                "iat": now,
                "exp": now + REFRESH_TOKEN_TTL,
            }))
            .await?;
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
    /// Refresh tokens are signed rather than stored, which keeps the hot path
    /// free of a database read but means an individual one cannot be revoked
    /// before it expires — only the signing key can be rotated. Recorded in
    /// backlog.md rather than papered over.
    pub async fn refresh(&self, refresh_token: &str) -> Result<SignIn, Status> {
        let signing = self.signing().await?;
        let header = jsonwebtoken::decode_header(refresh_token)
            .map_err(|e| Status::unauthenticated(format!("invalid refresh token: {e}")))?;
        let key = header
            .kid
            .as_deref()
            .and_then(|kid| signing.verifying.get(kid))
            .ok_or_else(|| Status::unauthenticated("refresh token was not issued here"))?;

        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_required_spec_claims(&["exp", "iss", "sub"]);
        validation.validate_aud = false;
        validation.leeway = CLOCK_LEEWAY_SECONDS;
        let decoded = jsonwebtoken::decode::<serde_json::Map<String, serde_json::Value>>(
            refresh_token,
            key,
            &validation,
        )
        .map_err(|e| Status::unauthenticated(format!("refresh token rejected: {e}")))?;
        let claims = decoded.claims;
        if claims.get(KIND_CLAIM).and_then(|v| v.as_str()) != Some("refresh") {
            return Err(Status::unauthenticated("not a refresh token"));
        }
        let uid = claims.get("sub").and_then(|v| v.as_str()).unwrap_or_default().to_owned();
        let project_id = claims.get("aud").and_then(|v| v.as_str()).unwrap_or_default().to_owned();
        self.issue_identity(&project_id, &uid, &serde_json::Map::new()).await
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
pub struct SignIn {
    pub id_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub uid: String,
    pub project_id: String,
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
