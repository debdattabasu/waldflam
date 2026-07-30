//! Authorization, in one of two modes.
//!
//! **Emulator** (the default) matches the official emulator so the SDKs work
//! in their emulator mode:
//!
//! - no `authorization` header → unauthenticated (`request.auth == null`)
//! - `Bearer owner` (case-insensitive) → admin, bypasses security rules
//! - any other bearer token → an *unsigned* JWT (`alg: "none"`, empty
//!   signature); claims are decoded but never verified. `request.auth.uid`
//!   is the `sub` claim, `request.auth.token` the whole payload.
//! - anything malformed → INVALID_ARGUMENT
//!
//! **Verify** is for deployments reachable by anyone. Tokens must carry a
//! real RS256 signature from a key published at the configured JWKS
//! endpoint, and must match the configured issuer and audience. The `owner`
//! backdoor does not exist here — admin comes only from a configured shared
//! secret, and if none is set, nothing is admin.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use tonic::Status;

#[derive(Debug, Clone, PartialEq)]
pub enum Authorization {
    /// No credentials: rules see `request.auth == null`.
    Unauthenticated,
    /// `Bearer owner`: full bypass, like a server/Admin SDK.
    Admin,
    /// Decoded (unverified) JWT claims payload.
    User(JwtClaims),
}

#[derive(Debug, Clone, PartialEq)]
pub struct JwtClaims {
    /// The `sub` claim — becomes `request.auth.uid`.
    pub uid: Option<String>,
    /// The entire decoded payload — becomes `request.auth.token`.
    pub payload: serde_json::Map<String, serde_json::Value>,
}

/// How incoming credentials are judged. Cheap to clone; share one per server.
#[derive(Clone, Default)]
pub enum AuthPolicy {
    /// Emulator semantics: unsigned tokens trusted, `owner` is admin.
    #[default]
    Emulator,
    /// Signatures verified against a JWKS; no `owner` backdoor.
    Verify(Arc<Verifier>),
}

impl AuthPolicy {
    /// Judges credentials from gRPC request metadata.
    pub async fn from_metadata(
        &self,
        metadata: &tonic::metadata::MetadataMap,
    ) -> Result<Authorization, Status> {
        let header = metadata.get("authorization").and_then(|v| v.to_str().ok());
        self.authorize(header).await
    }

    /// Judges an `authorization` header value (or its absence).
    pub async fn authorize(&self, header: Option<&str>) -> Result<Authorization, Status> {
        match self {
            Self::Emulator => Authorization::from_header(header),
            Self::Verify(verifier) => verifier.authorize(header).await,
        }
    }

    /// Whether this policy protects the admin endpoints (rules, clear-data,
    /// triggers). Emulator mode leaves them open, like the emulator does.
    pub fn guards_admin_api(&self) -> bool {
        matches!(self, Self::Verify(_))
    }
}

impl Authorization {
    /// Extracts credentials from gRPC request metadata under emulator rules.
    pub fn from_metadata(metadata: &tonic::metadata::MetadataMap) -> Result<Self, Status> {
        let header = metadata.get("authorization").and_then(|v| v.to_str().ok());
        Self::from_header(header)
    }

    /// Parses an `authorization` header value (or its absence).
    pub fn from_header(header: Option<&str>) -> Result<Self, Status> {
        let Some(header) = header else {
            return Ok(Self::Unauthenticated);
        };
        let token = header
            .get(..7)
            .filter(|p| p.eq_ignore_ascii_case("bearer "))
            .map(|_| &header[7..])
            .ok_or_else(|| Status::invalid_argument("expected Bearer authorization"))?;
        if token.eq_ignore_ascii_case("owner") {
            return Ok(Self::Admin);
        }
        parse_unsigned_jwt(token)
            .map(Self::User)
            .map_err(|reason| Status::invalid_argument(format!("invalid jwt: {reason}")))
    }
}

/// Settings for verified mode.
#[derive(Clone, Debug)]
pub struct VerifyConfig {
    /// Required `iss` claim. For Firebase Auth:
    /// `https://securetoken.google.com/<project-id>`.
    pub issuer: String,
    /// Required `aud` claim — the project id, for Firebase Auth.
    pub audience: String,
    /// Where signing keys are published in JWK Set form. For Firebase Auth:
    /// `https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com`.
    pub jwks_url: String,
    /// Shared secret granting admin, for server-side callers. `None` means
    /// no request can reach admin — rules apply to everyone.
    pub admin_token: Option<String>,
}

/// Verifies RS256 tokens against keys published at a JWKS endpoint.
pub struct Verifier {
    config: VerifyConfig,
    http: reqwest::Client,
    keys: RwLock<KeyCache>,
}

#[derive(Default)]
struct KeyCache {
    by_kid: HashMap<String, jsonwebtoken::DecodingKey>,
    /// When the set was last pulled, to throttle refetching on an unknown
    /// `kid` — otherwise a stream of junk tokens becomes a stream of
    /// outbound requests.
    refreshed: Option<Instant>,
}

/// How long a fetched key set is trusted before an unknown `kid` may trigger
/// another fetch. Issuers rotate keys on the order of days.
const KEY_REFRESH_INTERVAL: Duration = Duration::from_secs(300);

/// Tolerance for clock skew between this server and the token's issuer.
const CLOCK_LEEWAY_SECONDS: u64 = 60;

#[derive(serde::Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

#[derive(serde::Deserialize)]
struct Jwk {
    kid: Option<String>,
    kty: String,
    n: Option<String>,
    e: Option<String>,
}

impl Verifier {
    /// Fetches keys lazily on the first token that needs them.
    pub fn new(config: VerifyConfig) -> Self {
        Self { config, http: reqwest::Client::new(), keys: RwLock::new(KeyCache::default()) }
    }

    /// Uses a fixed key set instead of fetching — for pinned deployments
    /// that would rather ship keys than reach out, and for tests.
    pub fn with_jwks(config: VerifyConfig, jwks: &str) -> Result<Self, String> {
        let verifier = Self::new(config);
        let parsed = parse_jwks(jwks)?;
        {
            let mut cache = verifier.keys.write().expect("key cache");
            cache.by_kid = parsed;
            cache.refreshed = Some(Instant::now());
        }
        Ok(verifier)
    }

    async fn authorize(&self, header: Option<&str>) -> Result<Authorization, Status> {
        let Some(header) = header else {
            return Ok(Authorization::Unauthenticated);
        };
        let token = header
            .get(..7)
            .filter(|scheme| scheme.eq_ignore_ascii_case("bearer "))
            .map(|_| &header[7..])
            .ok_or_else(|| Status::unauthenticated("expected Bearer authorization"))?;

        // Admin is a configured secret, never the emulator's `owner`.
        if let Some(expected) = self.config.admin_token.as_deref()
            && secret_eq(token, expected)
        {
            return Ok(Authorization::Admin);
        }

        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| Status::unauthenticated(format!("invalid token header: {e}")))?;
        if header.alg != jsonwebtoken::Algorithm::RS256 {
            return Err(Status::unauthenticated("token must be signed with RS256"));
        }
        let kid =
            header.kid.ok_or_else(|| Status::unauthenticated("token header has no key id"))?;

        let key = self.key_for(&kid).await?;
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        validation.leeway = CLOCK_LEEWAY_SECONDS;

        let decoded = jsonwebtoken::decode::<serde_json::Map<String, serde_json::Value>>(
            token,
            &key,
            &validation,
        )
        .map_err(|e| Status::unauthenticated(format!("token rejected: {e}")))?;

        let payload = decoded.claims;
        // A token that identifies nobody cannot authorize anything: rules
        // read `request.auth.uid`, and `null` there means unauthenticated.
        let uid = payload
            .get("sub")
            .and_then(|value| value.as_str())
            .filter(|sub| !sub.is_empty())
            .ok_or_else(|| Status::unauthenticated("token has no subject"))?
            .to_owned();
        Ok(Authorization::User(JwtClaims { uid: Some(uid), payload }))
    }

    /// Looks up a signing key, refetching the set once if the `kid` is
    /// unknown and the cache is old enough to be worth refreshing.
    async fn key_for(&self, kid: &str) -> Result<jsonwebtoken::DecodingKey, Status> {
        if let Some(key) = self.lookup(kid) {
            return Ok(key);
        }
        let stale = {
            let cache = self.keys.read().expect("key cache");
            cache.refreshed.is_none_or(|at| at.elapsed() >= KEY_REFRESH_INTERVAL)
        };
        if !stale {
            return Err(Status::unauthenticated("unknown token key id"));
        }
        self.refresh().await?;
        self.lookup(kid).ok_or_else(|| Status::unauthenticated("unknown token key id"))
    }

    fn lookup(&self, kid: &str) -> Option<jsonwebtoken::DecodingKey> {
        self.keys.read().expect("key cache").by_kid.get(kid).cloned()
    }

    async fn refresh(&self) -> Result<(), Status> {
        let body = self
            .http
            .get(&self.config.jwks_url)
            .send()
            .await
            .and_then(|response| response.error_for_status())
            .map_err(|e| Status::unavailable(format!("cannot fetch signing keys: {e}")))?
            .text()
            .await
            .map_err(|e| Status::unavailable(format!("cannot read signing keys: {e}")))?;
        let parsed =
            parse_jwks(&body).map_err(|e| Status::unavailable(format!("bad key set: {e}")))?;
        let mut cache = self.keys.write().expect("key cache");
        cache.by_kid = parsed;
        cache.refreshed = Some(Instant::now());
        Ok(())
    }
}

fn parse_jwks(body: &str) -> Result<HashMap<String, jsonwebtoken::DecodingKey>, String> {
    let set: JwkSet = serde_json::from_str(body).map_err(|e| e.to_string())?;
    let mut out = HashMap::new();
    for jwk in set.keys {
        // Only RSA keys are usable for RS256; skip anything else rather than
        // failing the whole set, since issuers publish mixed sets.
        let (Some(kid), Some(n), Some(e)) = (jwk.kid, jwk.n, jwk.e) else {
            continue;
        };
        if jwk.kty != "RSA" {
            continue;
        }
        let key = jsonwebtoken::DecodingKey::from_rsa_components(&n, &e)
            .map_err(|e| format!("key {kid}: {e}"))?;
        out.insert(kid, key);
    }
    if out.is_empty() {
        return Err("no usable RSA keys".into());
    }
    Ok(out)
}

/// Compares in time independent of how far the values match, so a caller
/// cannot discover the secret one byte at a time. Length still leaks, which
/// is standard and harmless for a random secret.
fn secret_eq(candidate: &str, expected: &str) -> bool {
    let (candidate, expected) = (candidate.as_bytes(), expected.as_bytes());
    if candidate.len() != expected.len() {
        return false;
    }
    candidate.iter().zip(expected).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

fn parse_unsigned_jwt(token: &str) -> Result<JwtClaims, &'static str> {
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("expected three dot-separated segments");
    };
    if !signature.is_empty() {
        return Err("expected empty signature");
    }

    let header: serde_json::Map<String, serde_json::Value> = decode_json_segment(header)?;
    match header.get("alg").and_then(|v| v.as_str()) {
        Some("none") => {}
        _ => return Err("expected alg 'none'"),
    }

    let payload: serde_json::Map<String, serde_json::Value> = decode_json_segment(payload)?;
    let uid = payload.get("sub").and_then(|v| v.as_str()).map(str::to_owned);
    Ok(JwtClaims { uid, payload })
}

fn decode_json_segment(
    segment: &str,
) -> Result<serde_json::Map<String, serde_json::Value>, &'static str> {
    let bytes =
        URL_SAFE_NO_PAD.decode(segment.trim_end_matches('=')).map_err(|_| "invalid base64url")?;
    match serde_json::from_slice(&bytes) {
        Ok(serde_json::Value::Object(map)) => Ok(map),
        _ => Err("segment is not a JSON object"),
    }
}

#[cfg(test)]
mod verify_tests {
    use super::*;

    /// Throwaway RSA keypair, generated for this test file and used nowhere
    /// else. Signing material in a repository is only safe because this key
    /// guards nothing.
    const TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCwilG3rzoH61C8\n\
XvgogZy8YTNhJyiozPkEfvHIrzfKZ2Nf9abtp9BYn770Bh9ZwpKQ7H2cXMouCkWp\n\
QbVLNCx14TsXjnoMl5NvuAzABQx33jGnC/r+YDqb8w9nHjA8bEwAlBFeIZ708Q4S\n\
v7PvdD7me69nvHYFkmHpuGNtAIQgnGodkWFbejMlrl+6oQg3dmgU9RveeLmlgcLL\n\
KqCo6Gw7N1lqA2tTll+8lEsbBGtn/3DfnrVgLNbDpG2bE8UHMxDtgIlhUXX5k8ob\n\
UA2Olkw1oNY0pJBwXwQ4oxJyIhDZPOqLM924PwTqXxWrYgk0dsaEDb7PDnJqRvPM\n\
yQNRelp9AgMBAAECggEASnFxRw8tXdSFPYGgjFgncypbw56DHzcb1KEBLNpyILgb\n\
KAZK51FJ4m0uVPFV/AA31MPcrfhUyzhKqrZKEBXGn8ijpenPHos2QThvq/MVEGDS\n\
ODotk2GZpVRHzPhmZ7xVCjNl5Xcw8+HISPCsnA89TOygCRLoA653+lnmFztN+/+z\n\
vaWQ/n5+m9lTDC0cFh8YLnpPFuKo9RyiZ4X9wzKgZbMZFTQduyrGykwMU4pq5X18\n\
5h7m3RM0LYVtR6v3L7h4yVhwOWfQv4KIJ6s7LH2rzEh5SaGEgye58agSnv2cgJLn\n\
6J/xgWyjdJd2Y+rT1PqdXAb35cimHxg3WZJtqN1VAwKBgQD3tDhk79Riy0afOndy\n\
+xpslA8IhZOuLQtnZJC8oDu64lAkHAOekPqagWkyaka5Lasn3ShOeETOp+g1w25U\n\
cXY46v5i6eRDurco2cpMYabusUFfssRLroW1X7rauXfoexVshZtGzA6iCbrc2jv/\n\
Ar44tzG1O7rUHJym5WJhKxdt6wKBgQC2c/OPKYZ74/albs5P+biU6QBehw+5FDUz\n\
0j0dW+X+3YvnsoY46uZXcde7yVVMODkOatS7V6j0W0lAVzX+GKNSqzZUC0tA6nSR\n\
Q+/JFG9EhlRg6JwHL6VzRuHxmLHCJzfexg4HwwtIWXhTx4RorIW1Vdb3Y5ZHbbMi\n\
NL0lsCz3NwKBgHPovjblTwIH0v0xc7G3NK84PSykrO1lIJ/6HAxYAns56XxsK3lo\n\
qAvioKI5vuxqJVwbDgBiIPh+85cs4xTanxKVTAJnJixXU9vmxdYmH+Izyb6JPXeY\n\
q/KqYBp3jVeZOPY2MunXFMXYPbuY11hGJVMOzlDbKVqWJOuoDPghHO6PAoGBALYv\n\
iFg/DdPuKR6+S3Mel8rR8xVw5ilYXVu2pmIHntzlGsusv0xces98lQAlpW/rgEW+\n\
NVgwyzvdX4LI0tg8f/GPlztK38UdmHJplSmDpyuUuvLdsteWIy696+XUJEQL50Uj\n\
HWVwxHZlKLr3smbXRthws6vqHGiMyN/yK6FTj0L3AoGAbo9q0aaMbrLia8FSSci8\n\
d3v6MymDIsVhDsba/hNI5HnvpYxES/L4EYiIsQtG11TgC43JnvdhqIs5ER0mB+OO\n\
TqObOOM3U3SyUAtGXbsm+P97cD9VFC3RxfkWxEP88ESQYo99J+RYyqaWFyfaSXBc\n\
ovX42z10ITdIZCEk527/S+k=\n\
-----END PRIVATE KEY-----\n";

    const TEST_JWKS: &str = r#"{"keys":[{"kty":"RSA","kid":"test-key","alg":"RS256","use":"sig","n":"sIpRt686B-tQvF74KIGcvGEzYScoqMz5BH7xyK83ymdjX_Wm7afQWJ--9AYfWcKSkOx9nFzKLgpFqUG1SzQsdeE7F456DJeTb7gMwAUMd94xpwv6_mA6m_MPZx4wPGxMAJQRXiGe9PEOEr-z73Q-5nuvZ7x2BZJh6bhjbQCEIJxqHZFhW3ozJa5fuqEIN3ZoFPUb3ni5pYHCyyqgqOhsOzdZagNrU5ZfvJRLGwRrZ_9w3561YCzWw6RtmxPFBzMQ7YCJYVF1-ZPKG1ANjpZMNaDWNKSQcF8EOKMSciIQ2TzqizPduD8E6l8Vq2IJNHbGhA2-zw5yakbzzMkDUXpafQ","e":"AQAB"}]}"#;

    const ISSUER: &str = "https://securetoken.example/demo";
    const AUDIENCE: &str = "demo";

    fn policy(admin_token: Option<&str>) -> AuthPolicy {
        let config = VerifyConfig {
            issuer: ISSUER.into(),
            audience: AUDIENCE.into(),
            // Never reached: the key set is supplied up front.
            jwks_url: "http://127.0.0.1:1/unused".into(),
            admin_token: admin_token.map(str::to_owned),
        };
        AuthPolicy::Verify(Arc::new(
            Verifier::with_jwks(config, TEST_JWKS).expect("test key set parses"),
        ))
    }

    fn now() -> i64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("clock").as_secs()
            as i64
    }

    fn sign(kid: &str, claims: serde_json::Value) -> String {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(kid.into());
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(TEST_KEY_PEM.as_bytes())
            .expect("test key loads");
        jsonwebtoken::encode(&header, &claims, &key).expect("sign")
    }

    fn token(overrides: serde_json::Value) -> String {
        let mut claims = serde_json::json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "alice",
            "iat": now() - 10,
            "exp": now() + 3600,
        });
        let base = claims.as_object_mut().expect("object");
        for (key, value) in overrides.as_object().expect("overrides object") {
            base.insert(key.clone(), value.clone());
        }
        sign("test-key", claims)
    }

    async fn judge(policy: &AuthPolicy, token: &str) -> Result<Authorization, Status> {
        policy.authorize(Some(&format!("Bearer {token}"))).await
    }

    #[tokio::test]
    async fn accepts_a_properly_signed_token() {
        let auth = judge(&policy(None), &token(serde_json::json!({"email": "a@example.com"})))
            .await
            .expect("valid token");
        let Authorization::User(claims) = auth else {
            panic!("expected user auth");
        };
        assert_eq!(claims.uid.as_deref(), Some("alice"));
        assert_eq!(claims.payload["email"], serde_json::json!("a@example.com"));
    }

    #[tokio::test]
    async fn rejects_tokens_that_fail_validation() {
        let policy = policy(None);
        let cases = [
            ("expired", token(serde_json::json!({"exp": now() - 3600}))),
            ("wrong issuer", token(serde_json::json!({"iss": "https://elsewhere.example"}))),
            ("wrong audience", token(serde_json::json!({"aud": "someone-else"}))),
            ("no subject", token(serde_json::json!({"sub": ""}))),
            ("unknown key id", sign("not-our-key", serde_json::json!({"sub": "alice"}))),
        ];
        for (label, token) in cases {
            assert!(judge(&policy, &token).await.is_err(), "`{label}` should be rejected");
        }
    }

    #[tokio::test]
    async fn rejects_a_tampered_signature() {
        let valid = token(serde_json::json!({}));
        let (body, signature) = valid.rsplit_once('.').expect("three segments");
        // Flip one character of the signature.
        let flipped: String = signature
            .chars()
            .enumerate()
            .map(|(i, c)| if i == 0 && c != 'A' { 'A' } else { c })
            .collect();
        assert!(judge(&policy(None), &format!("{body}.{flipped}")).await.is_err());
    }

    /// The emulator's backdoors must not exist once signatures are required.
    #[tokio::test]
    async fn emulator_shortcuts_do_not_work_in_verify_mode() {
        let policy = policy(None);
        assert!(
            policy.authorize(Some("Bearer owner")).await.is_err(),
            "`owner` must not grant admin when tokens are verified"
        );

        let enc = |v: serde_json::Value| URL_SAFE_NO_PAD.encode(v.to_string());
        let unsigned = format!(
            "{}.{}.",
            enc(serde_json::json!({"alg": "none"})),
            enc(serde_json::json!({"sub": "alice", "iss": ISSUER, "aud": AUDIENCE}))
        );
        assert!(
            judge(&policy, &unsigned).await.is_err(),
            "an unsigned token must not be accepted when tokens are verified"
        );
    }

    #[tokio::test]
    async fn admin_comes_only_from_the_configured_secret() {
        let policy = policy(Some("s3cret"));
        assert_eq!(
            policy.authorize(Some("Bearer s3cret")).await.unwrap(),
            Authorization::Admin,
            "the configured secret grants admin"
        );
        assert!(
            policy.authorize(Some("Bearer s3cre")).await.is_err(),
            "a near-miss secret is not admin"
        );
        assert!(policy.authorize(Some("Bearer owner")).await.is_err());
    }

    #[tokio::test]
    async fn absent_credentials_are_unauthenticated_not_an_error() {
        assert_eq!(
            policy(None).authorize(None).await.unwrap(),
            Authorization::Unauthenticated,
            "rules still need to see anonymous requests"
        );
    }

    #[tokio::test]
    async fn emulator_mode_is_unchanged() {
        let emulator = AuthPolicy::Emulator;
        assert_eq!(emulator.authorize(Some("Bearer owner")).await.unwrap(), Authorization::Admin);
        assert!(!emulator.guards_admin_api(), "the emulator leaves its admin API open");
        assert!(policy(None).guards_admin_api(), "verified mode guards it");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unsigned_jwt(payload: serde_json::Value) -> String {
        let enc = |v: &serde_json::Value| URL_SAFE_NO_PAD.encode(v.to_string());
        format!("{}.{}.", enc(&serde_json::json!({"alg": "none", "typ": "JWT"})), enc(&payload))
    }

    #[test]
    fn absent_header_is_unauthenticated() {
        assert_eq!(Authorization::from_header(None).unwrap(), Authorization::Unauthenticated);
    }

    #[test]
    fn owner_is_admin_case_insensitively() {
        for h in ["Bearer owner", "bearer owner", "Bearer OWNER", "BEARER Owner"] {
            assert_eq!(Authorization::from_header(Some(h)).unwrap(), Authorization::Admin, "{h}");
        }
    }

    #[test]
    fn unsigned_jwt_claims_are_decoded_not_verified() {
        let jwt = unsigned_jwt(serde_json::json!({
            "sub": "alice",
            "email": "alice@example.com",
            "firebase": {"sign_in_provider": "password"},
        }));
        let auth = Authorization::from_header(Some(&format!("Bearer {jwt}"))).unwrap();
        let Authorization::User(claims) = auth else {
            panic!("expected user auth");
        };
        assert_eq!(claims.uid.as_deref(), Some("alice"));
        assert_eq!(claims.payload["email"], serde_json::json!("alice@example.com"));
    }

    #[test]
    fn missing_sub_is_allowed() {
        let jwt = unsigned_jwt(serde_json::json!({"custom": true}));
        let Authorization::User(claims) =
            Authorization::from_header(Some(&format!("Bearer {jwt}"))).unwrap()
        else {
            panic!("expected user auth");
        };
        assert_eq!(claims.uid, None);
    }

    #[test]
    fn rejects_malformed_tokens() {
        for h in [
            "Basic abc",      // wrong scheme
            "Bearer not.a",   // two segments
            "Bearer a.b.c.d", // four segments
            "Bearer !!.!!.",  // bad base64
        ] {
            assert!(Authorization::from_header(Some(h)).is_err(), "{h}");
        }
        // signed JWT (non-empty signature) must be rejected in this mode
        let signed = format!("{}sig", unsigned_jwt(serde_json::json!({"sub": "x"})));
        assert!(Authorization::from_header(Some(&format!("Bearer {signed}"))).is_err());
        // alg RS256 must be rejected
        let enc = |v: serde_json::Value| URL_SAFE_NO_PAD.encode(v.to_string());
        let rs256 = format!(
            "{}.{}.",
            enc(serde_json::json!({"alg": "RS256"})),
            enc(serde_json::json!({"sub": "x"}))
        );
        assert!(Authorization::from_header(Some(&format!("Bearer {rs256}"))).is_err());
    }
}
