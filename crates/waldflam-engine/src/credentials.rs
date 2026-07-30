//! Credential records: registered service accounts, and this deployment's
//! own signing key.
//!
//! Both live in MongoDB rather than in a config file because every instance
//! has to agree on them: a token minted on one instance must verify on
//! another, and revoking a service account has to take effect everywhere at
//! once. Configuration files drift between instances; a collection cannot.
//!
//! This module is storage only — key generation, signing, and verification
//! live in the server crate, which owns the crypto.

use mongodb::Collection;
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};

use crate::EngineError;
use crate::store::Store;

/// Registered service accounts, keyed by key id.
const SERVICE_ACCOUNTS: &str = "_service_accounts";

/// This deployment's signing keys. Singleton for now; `_id` is a role rather
/// than a key id so "create one if none exists" can be a single atomic
/// upsert that concurrent instances converge on.
const SIGNING_KEYS: &str = "_signing_keys";

/// `_id` of the key currently used to sign.
pub const ACTIVE_SIGNING_KEY: &str = "active";

/// A registered service account.
///
/// waldflam keeps only the *public* half. The private key is handed to the
/// operator once, when the account is created, and never stored — so a
/// database dump cannot be replayed into working credentials, and a lost key
/// is replaced rather than recovered.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAccount {
    /// `private_key_id` in the emitted key file, and the `kid` header of
    /// every assertion it signs.
    #[serde(rename = "_id")]
    pub key_id: String,
    /// The credential's identity: `iss`/`sub` on assertions it signs, and
    /// what shows up in logs and in `revoke`.
    pub client_email: String,
    /// Project this credential is admin of. A service account is scoped to
    /// one project, so a multi-project deployment can't have one tenant's
    /// credentials reach another's data.
    pub project_id: String,
    /// RSA public modulus, base64url — the JWK `n`.
    pub modulus: String,
    /// RSA public exponent, base64url — the JWK `e`.
    pub exponent: String,
    pub created_us: i64,
    /// Revoked accounts are kept as tombstones rather than deleted, so a key
    /// id is never reissued and an audit trail survives.
    pub revoked: bool,
}

/// The deployment's own signing key: what waldflam-issued access tokens and
/// ID tokens are signed with.
///
/// Unlike a service account, waldflam holds the private half — it has to, in
/// order to mint anything. Anyone who can read this collection can mint any
/// identity, which makes the MongoDB deployment part of the trust boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningKey {
    /// Role, not identity — see [`ACTIVE_SIGNING_KEY`].
    #[serde(rename = "_id")]
    pub role: String,
    /// Published as the JWK `kid`, and set on the header of tokens we sign.
    pub key_id: String,
    /// PKCS#8 PEM.
    pub private_key_pem: String,
    pub modulus: String,
    pub exponent: String,
    pub created_us: i64,
}

impl Store {
    fn service_accounts(&self) -> Collection<ServiceAccount> {
        self.db().collection(SERVICE_ACCOUNTS)
    }

    fn signing_keys(&self) -> Collection<SigningKey> {
        self.db().collection(SIGNING_KEYS)
    }

    /// Registers a new service account. Fails if the email is already taken —
    /// two credentials answering to one identity would make revocation
    /// ambiguous.
    pub async fn register_service_account(
        &self,
        account: &ServiceAccount,
    ) -> Result<(), EngineError> {
        let unique = mongodb::IndexModel::builder()
            .keys(doc! { "client_email": 1 })
            .options(mongodb::options::IndexOptions::builder().unique(true).build())
            .build();
        self.service_accounts().create_index(unique).await?;
        self.service_accounts().insert_one(account).await.map_err(|e| {
            if is_duplicate_key(&e) {
                EngineError::AlreadyExists(account.client_email.clone())
            } else {
                EngineError::Mongo(e)
            }
        })?;
        Ok(())
    }

    /// Looks up a service account by key id — the `kid` an assertion carries.
    pub async fn service_account(
        &self,
        key_id: &str,
    ) -> Result<Option<ServiceAccount>, EngineError> {
        Ok(self.service_accounts().find_one(doc! { "_id": key_id }).await?)
    }

    /// Looks up by identity, for assertions whose header omits `kid`.
    pub async fn service_account_by_email(
        &self,
        client_email: &str,
    ) -> Result<Option<ServiceAccount>, EngineError> {
        Ok(self.service_accounts().find_one(doc! { "client_email": client_email }).await?)
    }

    pub async fn list_service_accounts(&self) -> Result<Vec<ServiceAccount>, EngineError> {
        use futures::TryStreamExt as _;
        let cursor = self.service_accounts().find(doc! {}).sort(doc! { "created_us": 1 }).await?;
        Ok(cursor.try_collect().await?)
    }

    /// Revokes by key id or by email, whichever the operator had to hand.
    /// Returns the account as it now stands, or `None` if nothing matched.
    pub async fn revoke_service_account(
        &self,
        selector: &str,
    ) -> Result<Option<ServiceAccount>, EngineError> {
        let filter = doc! { "$or": [{ "_id": selector }, { "client_email": selector }] };
        Ok(self
            .service_accounts()
            .find_one_and_update(filter, doc! { "$set": { "revoked": true } })
            .return_document(mongodb::options::ReturnDocument::After)
            .await?)
    }

    /// Returns the active signing key, inserting `candidate` if there isn't
    /// one yet.
    ///
    /// Atomic on purpose: several instances starting at once must end up
    /// sharing one key, or tokens minted by one would fail to verify on the
    /// others. The upsert is the arbiter — whoever loses the race gets the
    /// winner's key back.
    pub async fn signing_key_or_insert(
        &self,
        candidate: &SigningKey,
    ) -> Result<SigningKey, EngineError> {
        let mut fields = mongodb::bson::to_document(candidate)
            .map_err(|e| EngineError::InvalidArgument(e.to_string()))?;
        fields.remove("_id");
        let key = self
            .signing_keys()
            .find_one_and_update(
                doc! { "_id": ACTIVE_SIGNING_KEY },
                doc! { "$setOnInsert": fields },
            )
            .upsert(true)
            .return_document(mongodb::options::ReturnDocument::After)
            .await?;
        key.ok_or_else(|| EngineError::InvalidArgument("signing key upsert returned none".into()))
    }

    /// Every key whose signatures should still verify — what the JWKS
    /// endpoint publishes. Retired keys stay here so tokens they signed
    /// remain valid until they expire.
    pub async fn all_signing_keys(&self) -> Result<Vec<SigningKey>, EngineError> {
        use futures::TryStreamExt as _;
        let cursor = self.signing_keys().find(doc! {}).await?;
        Ok(cursor.try_collect().await?)
    }
}

fn is_duplicate_key(error: &mongodb::error::Error) -> bool {
    matches!(*error.kind, mongodb::error::ErrorKind::Write(
        mongodb::error::WriteFailure::WriteError(ref e)
    ) if e.code == 11000)
}
