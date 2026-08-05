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

/// Collection every instance tails to learn that a credential stopped being
/// valid. See [`CredentialEvent`].
const CREDENTIAL_EVENTS: &str = "_credential_events";

/// How long an invalidation notice lives before MongoDB reaps it. It only has
/// to outlast the moment live instances read it — an instance that was down
/// re-reads the underlying record on its next cache miss regardless.
const CREDENTIAL_EVENT_TTL_SECONDS: u64 = 3600;

/// A credential stopped being valid somewhere in the cluster.
///
/// Instances cache credential lookups, so without this the only thing ending
/// a revoked credential's life elsewhere is that cache expiring — a window of
/// tens of seconds. Broadcasting makes the common case immediate and leaves
/// the cache lifetime as the backstop for an instance whose change stream has
/// broken.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialEvent {
    /// Who published it, so an instance can skip its own notice.
    pub instance: String,
    /// What `selectors` name — see [`KIND_SERVICE_ACCOUNT`].
    pub kind: String,
    /// Cache keys to drop. A service account is reachable by key id *and* by
    /// email, so revoking one names both.
    pub selectors: Vec<String>,
    /// TTL anchor; MongoDB reaps the notice once this passes.
    pub expires_at: mongodb::bson::DateTime,
}

/// A service account was revoked.
pub const KIND_SERVICE_ACCOUNT: &str = "service_account";

/// A user's sessions were revoked; the selector is `{project}:{uid}`.
pub const KIND_IDENTITY: &str = "identity";

/// Issued refresh tokens, keyed by hash of the token.
const REFRESH_TOKENS: &str = "_refresh_tokens";

/// Per-user revocation state.
const IDENTITIES: &str = "_identities";

/// One-shot assertions already spent, so they cannot be spent again.
const USED_ASSERTIONS: &str = "_used_assertions";

/// A one-shot assertion that has been redeemed.
///
/// Kept in MongoDB rather than in memory because replay protection that only
/// covers one instance is not replay protection: an attacker would simply
/// present the captured assertion to a different one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsedAssertion {
    /// Hash of issuer + `jti`. `jti` is only unique per issuer, so the
    /// issuer has to be part of the key.
    #[serde(rename = "_id")]
    pub id: String,
    /// TTL anchor, set to when the assertion expires: past that the
    /// signature is refused on its own and the record has nothing left to
    /// protect.
    pub expires_at: mongodb::bson::DateTime,
}

/// One issued refresh token.
///
/// Stored rather than self-describing, which is the whole point: a signed
/// refresh token cannot be taken back before it expires, and thirty days is a
/// long time to be unable to end a session. The cost is one database read per
/// *refresh* — hourly per user, not per request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenRecord {
    /// SHA-256 of the token, hex. The token itself is never stored, so a
    /// database dump cannot be replayed into live sessions — the same reason
    /// service-account private keys aren't kept either.
    #[serde(rename = "_id")]
    pub token_hash: String,
    pub uid: String,
    pub project_id: String,
    pub issued_us: i64,
    /// TTL anchor; MongoDB reaps the record when the token expires, so
    /// expiry needs no sweeper of its own.
    pub expires_at: mongodb::bson::DateTime,
    pub revoked: bool,
}

/// Per-user revocation state. Only written when someone revokes, so signing
/// in costs no extra write.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    /// `{project}:{uid}`.
    #[serde(rename = "_id")]
    pub id: String,
    pub project_id: String,
    pub uid: String,
    /// Tokens issued before this instant are dead. Firebase calls this
    /// `tokensValidAfterTime`; it is what lets an *already issued* ID token
    /// be rejected, since the token itself can't be recalled.
    pub valid_after_us: i64,
}

/// Cache and lookup key for an identity.
pub fn identity_key(project_id: &str, uid: &str) -> String {
    format!("{project_id}:{uid}")
}

/// Builds a TTL anchor from a Unix timestamp, so callers don't need to name
/// MongoDB's date type — storage details stay in this crate.
pub fn expiry_at(unix_seconds: i64) -> mongodb::bson::DateTime {
    mongodb::bson::DateTime::from_millis(unix_seconds * 1000)
}

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
    /// [`ACTIVE_SIGNING_KEY`] for the key currently signing, and the key id
    /// for retired ones. A fixed `_id` for the active key is what makes
    /// "create one if none exists" and "swap it" single atomic operations.
    #[serde(rename = "_id")]
    pub role: String,
    /// Published as the JWK `kid`, and set on the header of tokens we sign.
    pub key_id: String,
    /// PKCS#8 PEM, when the deployment stores keys in the clear. Empty once
    /// `sealed_key` is set.
    #[serde(default)]
    pub private_key_pem: String,
    /// The same PEM under a key-encryption key, when one is configured.
    ///
    /// Exactly one of these two is populated. Both being empty is a record
    /// that cannot sign, which the loader treats as an error rather than
    /// quietly generating a replacement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed_key: Option<SealedKey>,
    pub modulus: String,
    pub exponent: String,
    pub created_us: i64,
    /// When a retired key stops verifying and may be deleted; `0` on the
    /// active key. Retired keys keep verifying until every token they signed
    /// has expired, or rotating would invalidate tokens already in flight.
    #[serde(default)]
    pub retire_after_us: i64,
}

/// A private key encrypted with a key-encryption key held outside the
/// database.
///
/// The point is narrow and worth stating exactly: this puts the signing key
/// beyond anyone who can *read the database without being on the waldflam
/// host* — backups, snapshots, a managed provider's staff, a leaked
/// connection string, an exposed port. It does nothing against an attacker
/// with the host itself, who has the key-encryption key too.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedKey {
    /// Identifies the key-encryption key, so "sealed with a different KEK"
    /// can be reported as such instead of as a generic decryption failure.
    pub kek_id: String,
    /// AES-256-GCM nonce, base64. Fresh per sealing — reusing one under the
    /// same key is what breaks GCM.
    pub nonce: String,
    /// Ciphertext with its authentication tag, base64.
    pub ciphertext: String,
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
    ///
    /// Publishes an invalidation notice so the other instances stop honouring
    /// it now rather than whenever their caches happen to turn over.
    pub async fn revoke_service_account(
        &self,
        selector: &str,
    ) -> Result<Option<ServiceAccount>, EngineError> {
        let filter = doc! { "$or": [{ "_id": selector }, { "client_email": selector }] };
        let revoked = self
            .service_accounts()
            .find_one_and_update(filter, doc! { "$set": { "revoked": true } })
            .return_document(mongodb::options::ReturnDocument::After)
            .await?;
        if let Some(account) = &revoked {
            self.publish_credential_event(
                KIND_SERVICE_ACCOUNT,
                vec![account.key_id.clone(), account.client_email.clone()],
            )
            .await?;
        }
        Ok(revoked)
    }

    fn refresh_tokens(&self) -> Collection<RefreshTokenRecord> {
        self.db().collection(REFRESH_TOKENS)
    }

    fn identities(&self) -> Collection<Identity> {
        self.db().collection(IDENTITIES)
    }

    /// Records an issued refresh token. The TTL index means expiry is
    /// MongoDB's job rather than a sweeper of ours.
    pub async fn store_refresh_token(
        &self,
        record: &RefreshTokenRecord,
    ) -> Result<(), EngineError> {
        let ttl = mongodb::IndexModel::builder()
            .keys(doc! { "expires_at": 1 })
            .options(
                mongodb::options::IndexOptions::builder()
                    .expire_after(std::time::Duration::from_secs(0))
                    .build(),
            )
            .build();
        self.refresh_tokens().create_index(ttl).await?;
        // Revoking a user's sessions has to find them all.
        let by_user =
            mongodb::IndexModel::builder().keys(doc! { "project_id": 1, "uid": 1 }).build();
        self.refresh_tokens().create_index(by_user).await?;
        self.refresh_tokens().insert_one(record).await?;
        Ok(())
    }

    pub async fn refresh_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<RefreshTokenRecord>, EngineError> {
        Ok(self.refresh_tokens().find_one(doc! { "_id": token_hash }).await?)
    }

    /// Revokes one session, leaving the user's others alone.
    pub async fn revoke_refresh_token(&self, token_hash: &str) -> Result<bool, EngineError> {
        let updated = self
            .refresh_tokens()
            .update_one(doc! { "_id": token_hash }, doc! { "$set": { "revoked": true } })
            .await?;
        Ok(updated.matched_count > 0)
    }

    /// Ends every session a user has: existing refresh tokens stop working,
    /// and `valid_after_us` moves forward so ID tokens already handed out can
    /// be rejected too.
    ///
    /// Publishes an invalidation notice, so instances holding a cached
    /// `valid_after` drop it rather than waiting out their cache.
    pub async fn revoke_identity_tokens(
        &self,
        project_id: &str,
        uid: &str,
        now_us: i64,
    ) -> Result<(), EngineError> {
        self.refresh_tokens()
            .update_many(
                doc! { "project_id": project_id, "uid": uid },
                doc! { "$set": { "revoked": true } },
            )
            .await?;
        let id = identity_key(project_id, uid);
        self.identities()
            .update_one(
                doc! { "_id": &id },
                doc! { "$set": {
                    "project_id": project_id,
                    "uid": uid,
                    "valid_after_us": now_us,
                } },
            )
            .upsert(true)
            .await?;
        self.publish_credential_event(KIND_IDENTITY, vec![id]).await?;
        Ok(())
    }

    /// A user's revocation state, or `None` if nobody has ever revoked for
    /// them — which is the common case, and why sign-in writes no record.
    pub async fn identity(
        &self,
        project_id: &str,
        uid: &str,
    ) -> Result<Option<Identity>, EngineError> {
        Ok(self.identities().find_one(doc! { "_id": identity_key(project_id, uid) }).await?)
    }

    /// Spends a one-shot assertion, returning `false` if it was already
    /// spent.
    ///
    /// The uniqueness of `_id` is what makes this safe under concurrency:
    /// two instances racing the same replayed assertion both attempt the
    /// insert and exactly one wins, with no read-then-write window for the
    /// other to slip through.
    pub async fn claim_assertion(
        &self,
        id: &str,
        expires_at: mongodb::bson::DateTime,
    ) -> Result<bool, EngineError> {
        let used: Collection<UsedAssertion> = self.db().collection(USED_ASSERTIONS);
        let ttl = mongodb::IndexModel::builder()
            .keys(doc! { "expires_at": 1 })
            .options(
                mongodb::options::IndexOptions::builder()
                    .expire_after(std::time::Duration::from_secs(0))
                    .build(),
            )
            .build();
        used.create_index(ttl).await?;
        match used.insert_one(UsedAssertion { id: id.to_owned(), expires_at }).await {
            Ok(_) => Ok(true),
            Err(error) if is_duplicate_key(&error) => Ok(false),
            Err(error) => Err(EngineError::Mongo(error)),
        }
    }

    fn credential_events(&self) -> Collection<CredentialEvent> {
        self.db().collection(CREDENTIAL_EVENTS)
    }

    /// Tells every instance to forget what it cached about these selectors.
    pub async fn publish_credential_event(
        &self,
        kind: &str,
        selectors: Vec<String>,
    ) -> Result<(), EngineError> {
        let index = mongodb::IndexModel::builder()
            .keys(doc! { "expires_at": 1 })
            .options(
                mongodb::options::IndexOptions::builder()
                    .expire_after(std::time::Duration::from_secs(0))
                    .build(),
            )
            .build();
        self.credential_events().create_index(index).await?;
        let event = CredentialEvent {
            instance: self.instance_id().to_string(),
            kind: kind.to_owned(),
            selectors,
            expires_at: mongodb::bson::DateTime::from_system_time(
                std::time::SystemTime::now()
                    + std::time::Duration::from_secs(CREDENTIAL_EVENT_TTL_SECONDS),
            ),
        };
        self.credential_events().insert_one(event).await?;
        Ok(())
    }

    /// Tails credential invalidations from every instance.
    pub async fn watch_credential_events(
        &self,
        resume_after: Option<mongodb::change_stream::event::ResumeToken>,
    ) -> Result<
        mongodb::change_stream::ChangeStream<
            mongodb::change_stream::event::ChangeStreamEvent<CredentialEvent>,
        >,
        EngineError,
    > {
        // A change stream on a collection that has never been written to is
        // fine in MongoDB, so there is nothing to create up front.
        let events = self.credential_events();
        let watch = events.watch();
        let watch = match resume_after {
            Some(token) => watch.resume_after(token),
            None => watch,
        };
        Ok(watch.await?)
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

    /// Promotes `candidate` to the signing key and retires the current one.
    ///
    /// Retiring rather than deleting is the point: tokens signed by the old
    /// key are still in circulation, and a rotation that invalidated them
    /// would be an outage. It keeps verifying until `retire_after_us`, which
    /// the caller sets past the longest-lived token it could have signed.
    ///
    /// One transaction, so no window exists in which the deployment has two
    /// active keys or none.
    pub async fn rotate_signing_key(
        &self,
        candidate: &SigningKey,
        retire_after_us: i64,
    ) -> Result<SigningKey, EngineError> {
        let mut session = self.start_session().await?;
        session.start_transaction().await?;
        let keys = self.signing_keys();

        if let Some(current) =
            keys.find_one(doc! { "_id": ACTIVE_SIGNING_KEY }).session(&mut session).await?
        {
            let retired = SigningKey { role: current.key_id.clone(), retire_after_us, ..current };
            // `_id` is immutable, so retiring is an insert plus a delete
            // rather than an update.
            keys.insert_one(&retired).session(&mut session).await?;
            keys.delete_one(doc! { "_id": ACTIVE_SIGNING_KEY }).session(&mut session).await?;
        }
        keys.insert_one(candidate).session(&mut session).await?;
        session.commit_transaction().await?;
        Ok(candidate.clone())
    }

    /// Replaces a stored key's plaintext PEM with its sealed form.
    ///
    /// Unsets `private_key_pem` in the same update, so there is no moment
    /// where the row holds both — leaving the plaintext behind would make
    /// the encryption decorative.
    pub async fn seal_signing_key(
        &self,
        role: &str,
        sealed: &SealedKey,
    ) -> Result<(), EngineError> {
        let sealed = mongodb::bson::to_bson(sealed)
            .map_err(|e| EngineError::InvalidArgument(e.to_string()))?;
        self.signing_keys()
            .update_one(
                doc! { "_id": role },
                doc! { "$set": { "sealed_key": sealed, "private_key_pem": "" } },
            )
            .await?;
        Ok(())
    }

    /// Deletes retired keys whose tokens have all expired. Nothing verifies
    /// against them any more, so keeping them only widens what a database
    /// dump is worth.
    pub async fn purge_retired_signing_keys(&self, now_us: i64) -> Result<u64, EngineError> {
        let deleted = self
            .signing_keys()
            .delete_many(doc! { "retire_after_us": { "$gt": 0, "$lt": now_us } })
            .await?;
        Ok(deleted.deleted_count)
    }
}

fn is_duplicate_key(error: &mongodb::error::Error) -> bool {
    matches!(*error.kind, mongodb::error::ErrorKind::Write(
        mongodb::error::WriteFailure::WriteError(ref e)
    ) if e.code == 11000)
}
