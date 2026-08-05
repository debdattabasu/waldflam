//! TLS termination.
//!
//! Credentials travel on every request, so on any network that isn't loopback
//! they need a private channel — rotating signing keys carefully while bearer
//! tokens cross the wire in cleartext is the wrong order of operations.
//!
//! waldflam can terminate TLS itself, or sit behind something that already
//! does (a load balancer, an ingress, a service mesh). Both are legitimate;
//! what isn't is doing neither and not noticing, which is what
//! [`warn_if_unprotected`] is for.
//!
//! One caveat worth knowing before reaching for this: the Firebase SDKs'
//! emulator mode is plaintext by definition — `connectFirestoreEmulator` and
//! `FIRESTORE_EMULATOR_HOST` both force `http://`. TLS here serves clients
//! configured for production endpoints, REST callers you control, and
//! deployments where a proxy in front is not wanted.

use std::path::Path;
use std::sync::Arc;

use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Builds a TLS configuration from PEM files on disk.
///
/// Certificates are read once, at startup: renewing them means restarting.
/// That is the usual arrangement for a process behind a cert-management tool,
/// and hot reload is a separate feature rather than a hidden one.
pub fn load(cert_path: &Path, key_path: &Path) -> anyhow::Result<Arc<ServerConfig>> {
    // rustls 0.23 needs a crypto provider chosen explicitly when more than
    // one could be linked. Installing fails harmlessly if something else got
    // there first, which is why the result is discarded.
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

    let certs = read_certificates(cert_path)?;
    let key = read_private_key(key_path)?;
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow::anyhow!("certificate and key do not form a valid pair: {e}"))?;

    // Without `h2` in ALPN a gRPC client negotiating TLS falls back to
    // HTTP/1.1 and gRPC simply does not work. This line is the whole reason
    // the native surface survives being wrapped in TLS.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

fn read_certificates(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let mut reader = std::io::BufReader::new(
        std::fs::File::open(path)
            .map_err(|e| anyhow::anyhow!("cannot read certificate {}: {e}", path.display()))?,
    );
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let certs = certs.map_err(|e| anyhow::anyhow!("invalid certificate PEM: {e}"))?;
    if certs.is_empty() {
        anyhow::bail!("{} contains no certificates", path.display());
    }
    Ok(certs)
}

/// Accepts whatever a certificate tool produced — PKCS#8, PKCS#1 (`BEGIN RSA
/// PRIVATE KEY`), or SEC1 (`BEGIN EC PRIVATE KEY`).
fn read_private_key(path: &Path) -> anyhow::Result<PrivateKeyDer<'static>> {
    let mut reader = std::io::BufReader::new(
        std::fs::File::open(path)
            .map_err(|e| anyhow::anyhow!("cannot read private key {}: {e}", path.display()))?,
    );
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| anyhow::anyhow!("invalid private key PEM: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("{} contains no private key", path.display()))
}

/// Says something when a deployment that verifies credentials is carrying
/// them in the clear.
///
/// A warning rather than a refusal: serving plaintext is *correct* behind a
/// terminator, and refusing would break those deployments. But it has to be
/// deliberate, so it takes an explicit acknowledgement — silence is the one
/// outcome not on offer.
pub fn warn_if_unprotected(verifying: bool, has_tls: bool, terminated_upstream: bool) {
    if !verifying || has_tls || terminated_upstream {
        return;
    }
    tracing::warn!(
        "TLS: serving plaintext while verifying credentials — every bearer \
         token on this server is readable by anything on the network path. \
         Set WALDFLAM_TLS_CERT/WALDFLAM_TLS_KEY, or WALDFLAM_TLS=terminated \
         if something in front of waldflam already terminates TLS."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generated for this test file and used nowhere else: a self-signed
    /// leaf whose key guards nothing.
    const TEST_CERT: &str = include_str!("../tests/data/test-cert.pem");
    const TEST_KEY: &str = include_str!("../tests/data/test-key.pem");

    fn write(name: &str, contents: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("waldflam-tls-{name}"));
        std::fs::write(&path, contents).expect("write test pem");
        path
    }

    #[test]
    fn loads_a_certificate_and_advertises_h2() {
        let config = load(&write("cert.pem", TEST_CERT), &write("key.pem", TEST_KEY))
            .expect("test certificate loads");
        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            "h2 must be advertised first or gRPC over TLS silently degrades to HTTP/1.1"
        );
    }

    #[test]
    fn rejects_a_key_that_does_not_match_the_certificate() {
        // A syntactically fine key that belongs to a different certificate.
        let other = "-----BEGIN PRIVATE KEY-----\n\
                     MC4CAQAwBQYDK2VwBCIEIHwvMOB0i0mrKY7uHfKBd6qJZ4YSNSPqPq2nSyKvVBnk\n\
                     -----END PRIVATE KEY-----\n";
        assert!(load(&write("cert2.pem", TEST_CERT), &write("key2.pem", other)).is_err());
    }

    #[test]
    fn reports_missing_and_empty_files_clearly() {
        let missing = std::path::Path::new("/nonexistent/waldflam/cert.pem");
        let error = load(missing, missing).expect_err("missing file");
        assert!(error.to_string().contains("cannot read certificate"), "{error}");

        let empty = write("empty.pem", "");
        let error = load(&empty, &empty).expect_err("empty file");
        assert!(error.to_string().contains("no certificates"), "{error}");
    }
}
