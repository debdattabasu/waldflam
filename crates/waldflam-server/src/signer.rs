//! Where signing actually happens.
//!
//! Sealing the key at rest (see `sealing`) keeps it out of database dumps but
//! still loads it into this process to sign with. The other rung is to not
//! have it here at all: hand the bytes to something that holds the key —
//! Cloud KMS, Vault's transit engine, an HSM, a signing sidecar — and get a
//! signature back.
//!
//! That does not stop an attacker on the waldflam host either; they can call
//! the same signer with the same credentials. What it changes is the shape of
//! the loss. A stolen key is transferable, silent, and good forever. A stolen
//! *ability to call a signer* is none of those: it works only from where the
//! credentials work, every use is logged by the signer, and it stops the
//! moment that binding is revoked.
//!
//! waldflam ships the seam and one generic implementation rather than a
//! client for any particular vendor: [`RemoteSigner`] speaks a two-call HTTP
//! contract small enough to put in front of anything.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use tonic::Status;

/// Something that can produce RS256 signatures for this deployment.
#[async_trait::async_trait]
pub trait Signer: Send + Sync {
    /// JWK `kid` of the key this signs with; goes in every token header.
    fn key_id(&self) -> &str;

    /// RSASSA-PKCS1-v1_5 over SHA-256 of `message`.
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Status>;
}

/// Assembles and signs a JWT.
///
/// Built by hand rather than with `jsonwebtoken::encode` because a remote
/// signer never yields an `EncodingKey` — it only ever answers "here is the
/// signature for those bytes". Keeping assembly here means both signers
/// produce byte-identical tokens.
pub async fn sign_jwt(signer: &dyn Signer, claims: &serde_json::Value) -> Result<String, Status> {
    let header = serde_json::json!({ "alg": "RS256", "typ": "JWT", "kid": signer.key_id() });
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(claims).map_err(|e| Status::internal(e.to_string()))?,)
    );
    let signature = signer.sign(signing_input.as_bytes()).await?;
    Ok(format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature)))
}

/// The ASN.1 DigestInfo header RSASSA-PKCS1-v1_5 puts in front of a SHA-256
/// digest (RFC 8017 §9.2, and the `id-sha256` OID 2.16.840.1.101.3.4.2.1).
///
/// Spelled out rather than reached through `SigningKey<Sha256>`, whose
/// generic bound drags in an `AssociatedOid` impl that collides across the
/// two `const-oid` versions already in this dependency graph. The constant is
/// fixed and public, and `a_local_signature_verifies_as_rs256` checks the
/// result against an independent RS256 verifier — so a wrong byte here fails
/// a test rather than shipping.
const SHA256_DIGEST_INFO: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// Signs in-process with a key held in memory.
pub struct LocalSigner {
    key_id: String,
    key: rsa::RsaPrivateKey,
}

impl LocalSigner {
    pub fn from_pem(key_id: &str, pem: &str) -> Result<Self, Status> {
        use rsa::pkcs8::DecodePrivateKey as _;
        let key = rsa::RsaPrivateKey::from_pkcs8_pem(pem).map_err(|e| {
            Status::internal(format!("signing key is not a usable PKCS#8 PEM: {e}"))
        })?;
        Ok(Self { key_id: key_id.to_owned(), key })
    }
}

#[async_trait::async_trait]
impl Signer for LocalSigner {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Status> {
        use sha2::Digest as _;
        let mut prefixed = SHA256_DIGEST_INFO.to_vec();
        prefixed.extend_from_slice(&sha2::Sha256::digest(message));
        self.key
            .sign(rsa::Pkcs1v15Sign::new_unprefixed(), &prefixed)
            .map_err(|e| Status::internal(format!("cannot sign: {e}")))
    }
}

/// Signs by asking something else, which holds the key.
///
/// The contract is deliberately two calls, so a shim in front of KMS, Vault
/// or a PKCS#11 device is a short script rather than a project:
///
/// - `GET <url>` → `{"kid": "...", "n": "<base64url>", "e": "<base64url>"}`
///   — the public key, so waldflam can publish a JWKS and verify what it
///   signed.
/// - `POST <url>` with `{"message": "<base64url>"}` →
///   `{"signature": "<base64url>"}` — RS256 over those exact bytes.
///
/// Rotation belongs to whatever is behind the endpoint: waldflam re-reads the
/// public key on load and follows whichever `kid` it reports.
pub struct RemoteSigner {
    url: String,
    key_id: String,
    modulus: String,
    exponent: String,
    authorization: Option<String>,
    http: reqwest::Client,
}

impl std::fmt::Debug for RemoteSigner {
    /// Written out so the credential that authenticates to the signer is
    /// never printed — it is what stands between an attacker and the key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteSigner")
            .field("url", &self.url)
            .field("key_id", &self.key_id)
            .field("authorization", &self.authorization.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

#[derive(serde::Deserialize)]
struct RemotePublicKey {
    kid: String,
    n: String,
    e: String,
}

#[derive(serde::Deserialize)]
struct RemoteSignature {
    signature: String,
}

impl RemoteSigner {
    /// Connects and reads the public key.
    ///
    /// Done at construction so a signer that is unreachable or misconfigured
    /// fails while the server is starting, rather than on the first token
    /// somebody needs.
    pub async fn connect(url: &str, authorization: Option<String>) -> Result<Self, Status> {
        let http = reqwest::Client::new();
        let mut request = http.get(url);
        if let Some(header) = &authorization {
            request = request.header(reqwest::header::AUTHORIZATION, header);
        }
        let key: RemotePublicKey = request
            .send()
            .await
            .and_then(|response| response.error_for_status())
            .map_err(|e| Status::unavailable(format!("cannot reach the signer at {url}: {e}")))?
            .json()
            .await
            .map_err(|e| {
                Status::unavailable(format!("the signer's public key is unusable: {e}"))
            })?;
        Ok(Self {
            url: url.to_owned(),
            key_id: key.kid,
            modulus: key.n,
            exponent: key.e,
            authorization,
            http,
        })
    }

    /// The public half, for the JWKS and for verifying our own tokens.
    pub fn public_key(&self) -> (&str, &str) {
        (&self.modulus, &self.exponent)
    }
}

#[async_trait::async_trait]
impl Signer for RemoteSigner {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Status> {
        let mut request = self.http.post(&self.url).json(&serde_json::json!({
            "message": URL_SAFE_NO_PAD.encode(message),
        }));
        if let Some(header) = &self.authorization {
            request = request.header(reqwest::header::AUTHORIZATION, header);
        }
        let signed: RemoteSignature = request
            .send()
            .await
            .and_then(|response| response.error_for_status())
            .map_err(|e| Status::unavailable(format!("the signer refused: {e}")))?
            .json()
            .await
            .map_err(|e| Status::unavailable(format!("the signer's reply is unusable: {e}")))?;
        URL_SAFE_NO_PAD
            .decode(signed.signature)
            .map_err(|e| Status::unavailable(format!("the signer returned invalid base64: {e}")))
    }
}

/// Builds a remote signer from the environment, if one is configured.
pub async fn from_env() -> Result<Option<RemoteSigner>, Status> {
    let Some(url) = std::env::var("WALDFLAM_SIGNER_URL").ok().filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let authorization = std::env::var("WALDFLAM_SIGNER_TOKEN")
        .ok()
        .filter(|v| !v.is_empty())
        .map(|token| format!("Bearer {token}"));
    RemoteSigner::connect(&url, authorization).await.map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Throwaway key, generated for this test file.
    const PEM: &str = include_str!("../tests/data/test-key.pem");

    #[tokio::test]
    async fn a_local_signature_verifies_as_rs256() {
        let signer = LocalSigner::from_pem("k1", PEM).expect("test key loads");
        let token = sign_jwt(&signer, &serde_json::json!({ "sub": "alice" })).await.expect("sign");

        // Verified with the same library that checks incoming tokens, so
        // this proves the hand-assembled JWT is the shape everything else
        // expects — not merely that it round-trips through our own code.
        let public = {
            use rsa::pkcs8::DecodePrivateKey as _;
            use rsa::traits::PublicKeyParts as _;
            let key = rsa::RsaPrivateKey::from_pkcs8_pem(PEM).expect("pem").to_public_key();
            jsonwebtoken::DecodingKey::from_rsa_raw_components(
                &key.n().to_bytes_be(),
                &key.e().to_bytes_be(),
            )
        };
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.validate_exp = false;
        validation.required_spec_claims.clear();
        let decoded = jsonwebtoken::decode::<serde_json::Value>(&token, &public, &validation)
            .expect("a hand-assembled RS256 token must verify");
        assert_eq!(decoded.claims["sub"], "alice");
        assert_eq!(decoded.header.kid.as_deref(), Some("k1"));
    }

    #[test]
    fn a_bad_pem_is_refused_rather_than_panicking() {
        assert!(LocalSigner::from_pem("k1", "-----BEGIN PRIVATE KEY-----\nnope\n").is_err());
    }
}
