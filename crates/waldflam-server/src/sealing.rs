//! Encrypting the signing key at rest, under a key held outside the database.
//!
//! **What this defends against, precisely.** The set of people who can read
//! waldflam's database is larger than the set who can log into its host:
//! backups (which are dumps by definition, retained for years, restored into
//! staging, copied to laptops), volume snapshots, a managed provider's
//! operators, a leaked connection string in CI or a Kubernetes Secret, an
//! exposed port. Sealing the key means none of those yield anything usable.
//!
//! **What it does not defend against.** An attacker on the waldflam host. The
//! key-encryption key is there too, by construction — in the environment or
//! in a file the process can read. Anyone claiming otherwise about this class
//! of design is mistaken. Root on the host also reads tokens in flight and
//! request bodies, so it defeats essentially every design here; it is not the
//! target.
//!
//! It is therefore worth most to deployments where the database is further
//! away than the host — managed MongoDB, cloud backups, a provider you don't
//! operate — and least on a single machine you own outright, where the two
//! sets are the same people.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use waldflam_engine::credentials::SealedKey;

/// Bytes in a key-encryption key: AES-256.
const KEK_BYTES: usize = 32;

/// A loaded key-encryption key.
pub struct Kek {
    key: [u8; KEK_BYTES],
    id: String,
}

impl std::fmt::Debug for Kek {
    /// Prints the identifier and never the key. A struct that can print its
    /// own key material is one stray log line from undoing the encryption.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Kek").field("id", &self.id).field("key", &"<redacted>").finish()
    }
}

impl Kek {
    /// Reads a KEK from base64.
    ///
    /// Strict about length rather than hashing whatever it is handed: accept
    /// a passphrase and someone will use one, and a KEK derived from
    /// `hunter2` protects nothing while looking like it does.
    pub fn from_base64(encoded: &str) -> anyhow::Result<Self> {
        let bytes = BASE64
            .decode(encoded.trim())
            .map_err(|e| anyhow::anyhow!("key-encryption key is not valid base64: {e}"))?;
        let key: [u8; KEK_BYTES] = bytes.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!(
                "key-encryption key must be exactly {KEK_BYTES} bytes ({} given). \
                 Generate one with `waldflam credentials generate-kek`.",
                bytes.len()
            )
        })?;
        Ok(Self { id: fingerprint(&key), key })
    }

    /// Generates a fresh KEK, base64 encoded.
    pub fn generate() -> String {
        use rand::RngCore as _;
        let mut key = [0u8; KEK_BYTES];
        rand::thread_rng().fill_bytes(&mut key);
        BASE64.encode(key)
    }

    /// Which KEK this is — a fingerprint, not the key.
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn seal(&self, plaintext: &str) -> anyhow::Result<SealedKey> {
        use aes_gcm::AeadCore as _;
        use aes_gcm::aead::{Aead as _, KeyInit as _};
        let cipher = aes_gcm::Aes256Gcm::new((&self.key).into());
        // A fresh nonce every time: reusing one under the same key is the
        // way GCM fails catastrophically rather than gracefully.
        let nonce = aes_gcm::Aes256Gcm::generate_nonce(&mut aes_gcm::aead::OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|_| anyhow::anyhow!("cannot seal the signing key"))?;
        Ok(SealedKey {
            kek_id: self.id.clone(),
            nonce: BASE64.encode(nonce),
            ciphertext: BASE64.encode(ciphertext),
        })
    }

    pub fn unseal(&self, sealed: &SealedKey) -> anyhow::Result<String> {
        use aes_gcm::aead::{Aead as _, KeyInit as _};
        // Checked before decrypting so the wrong KEK reports itself as the
        // wrong KEK, rather than as an indistinguishable authentication
        // failure that sends an operator hunting for corruption.
        if sealed.kek_id != self.id {
            anyhow::bail!(
                "the signing key was sealed with a different key-encryption key \
                 (stored {}, configured {}) — waldflam will not start with the wrong one",
                sealed.kek_id,
                self.id
            );
        }
        let nonce = BASE64
            .decode(&sealed.nonce)
            .map_err(|e| anyhow::anyhow!("sealed key has an invalid nonce: {e}"))?;
        let ciphertext = BASE64
            .decode(&sealed.ciphertext)
            .map_err(|e| anyhow::anyhow!("sealed key is not valid base64: {e}"))?;
        let cipher = aes_gcm::Aes256Gcm::new((&self.key).into());
        let plaintext = cipher
            .decrypt(nonce.as_slice().into(), ciphertext.as_slice())
            .map_err(|_| anyhow::anyhow!("the sealed signing key failed authentication"))?;
        String::from_utf8(plaintext)
            .map_err(|_| anyhow::anyhow!("the sealed signing key is not valid UTF-8"))
    }
}

/// Names a KEK without revealing it: the first bytes of its SHA-256.
fn fingerprint(key: &[u8]) -> String {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(key);
    digest.iter().take(8).map(|byte| format!("{byte:02x}")).collect()
}

/// Loads the configured KEK, if this deployment seals its signing key.
///
/// The file form exists because an environment variable is visible to
/// anything that can read `/proc/<pid>/environ`, shows up in `docker
/// inspect`, and gets captured by crash reporters — a file with restrictive
/// permissions leaks in fewer directions.
pub fn from_env() -> anyhow::Result<Option<Kek>> {
    let inline = std::env::var("WALDFLAM_KEK").ok().filter(|value| !value.is_empty());
    let path = std::env::var("WALDFLAM_KEK_FILE").ok().filter(|value| !value.is_empty());
    match (inline, path) {
        (None, None) => Ok(None),
        (Some(_), Some(_)) => Err(anyhow::anyhow!(
            "set WALDFLAM_KEK or WALDFLAM_KEK_FILE, not both — two sources for one key \
             is a way to encrypt with one and try to decrypt with the other"
        )),
        (Some(inline), None) => Kek::from_base64(&inline).map(Some),
        (None, Some(path)) => {
            let contents = std::fs::read_to_string(&path)
                .map_err(|e| anyhow::anyhow!("cannot read {path}: {e}"))?;
            Kek::from_base64(&contents).map(Some)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kek() -> Kek {
        Kek::from_base64(&Kek::generate()).expect("generated keys load")
    }

    #[test]
    fn a_sealed_key_round_trips() {
        let kek = kek();
        let secret = "-----BEGIN PRIVATE KEY-----\nnot really\n-----END PRIVATE KEY-----\n";
        let sealed = kek.seal(secret).expect("seal");
        assert!(!sealed.ciphertext.contains("PRIVATE KEY"), "the plaintext must not survive");
        assert_eq!(kek.unseal(&sealed).expect("unseal"), secret);
    }

    #[test]
    fn every_sealing_uses_a_fresh_nonce() {
        let kek = kek();
        let (a, b) = (kek.seal("same").expect("seal"), kek.seal("same").expect("seal"));
        assert_ne!(a.nonce, b.nonce, "a repeated nonce under one key breaks GCM");
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn the_wrong_kek_says_so() {
        let sealed = kek().seal("secret").expect("seal");
        let error = kek().unseal(&sealed).expect_err("a different KEK must not open it");
        assert!(
            error.to_string().contains("different key-encryption key"),
            "the error should name the cause, got: {error}"
        );
    }

    #[test]
    fn tampering_is_detected() {
        let kek = kek();
        let mut sealed = kek.seal("secret").expect("seal");
        let mut raw = BASE64.decode(&sealed.ciphertext).expect("decode");
        raw[0] ^= 0xff;
        sealed.ciphertext = BASE64.encode(&raw);
        // GCM authenticates, so a flipped bit is a refusal rather than
        // garbage handed back as if it were a key.
        assert!(kek.unseal(&sealed).is_err());
    }

    #[test]
    fn a_short_or_malformed_key_is_refused() {
        assert!(Kek::from_base64("").is_err(), "empty");
        assert!(Kek::from_base64("not base64!!").is_err(), "malformed");
        // A passphrase is the shape of mistake this length check exists for.
        assert!(Kek::from_base64(&BASE64.encode(b"hunter2")).is_err(), "too short");
    }

    #[test]
    fn a_fingerprint_does_not_reveal_the_key() {
        let generated = Kek::generate();
        let kek = Kek::from_base64(&generated).expect("load");
        assert_eq!(kek.id().len(), 16, "8 bytes as hex");
        assert!(!generated.contains(kek.id()));
        assert!(!format!("{kek:?}").contains(&generated), "Debug must not print the key");
    }
}
