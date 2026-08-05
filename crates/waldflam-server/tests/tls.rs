//! TLS end to end, against real MongoDB.
//!
//! The interesting failure is not "TLS doesn't work" — it's that wrapping the
//! server in TLS silently breaks *gRPC* while leaving REST fine, because a
//! client that can't negotiate `h2` over ALPN quietly falls back to HTTP/1.1
//! and gRPC needs HTTP/2. So this drives a real gRPC client over TLS rather
//! than settling for an HTTPS request that would pass either way.

use std::sync::Arc;

use waldflam_proto::v1::GetDocumentRequest;
use waldflam_proto::v1::firestore_client::FirestoreClient;

/// The server's leaf certificate, and the CA that signed it. Two files
/// rather than one self-signed cert because rustls rightly refuses to serve
/// a CA certificate as a leaf (`CaUsedAsEndEntity`) — the chain here is the
/// same shape a real deployment presents.
const CERT: &str = include_str!("data/test-cert.pem");
const KEY: &str = include_str!("data/test-key.pem");
const CA: &str = include_str!("data/test-ca.pem");

/// Boots a TLS server on a free port and returns it.
///
/// `label` keeps each test's certificate files to itself; sharing one path
/// let concurrent tests read a half-written file.
async fn boot(label: &str) -> u16 {
    let mongo = std::env::var("WALDFLAM_TEST_MONGO")
        .unwrap_or_else(|_| "mongodb://127.0.0.1:27017/?directConnection=true".into());
    let store = waldflam_engine::store::Store::connect(&mongo)
        .await
        .expect("MongoDB not reachable — run `docker compose up -d`");

    let dir = std::env::temp_dir();
    let (cert_path, key_path) =
        (dir.join(format!("wf-{label}-cert.pem")), dir.join(format!("wf-{label}-key.pem")));
    std::fs::write(&cert_path, CERT).expect("write cert");
    std::fs::write(&key_path, KEY).expect("write key");
    let tls = waldflam_server::tls::load(&cert_path, &key_path).expect("test certificate loads");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let credentials = Arc::new(waldflam_server::credentials::Credentials::new(
        store.clone(),
        format!("https://localhost:{}", addr.port()),
    ));
    tokio::spawn(async move {
        if let Err(e) =
            waldflam_server::serve(addr, store, Default::default(), credentials, Some(tls)).await
        {
            // Without this the server dies silently and every client retry
            // loop below just spins until the harness is killed.
            eprintln!("TLS test server stopped: {e}");
        }
    });
    addr.port()
}

fn client_tls() -> tonic::transport::ClientTlsConfig {
    tonic::transport::ClientTlsConfig::new()
        .ca_certificate(tonic::transport::Certificate::from_pem(CA))
        // The certificate is issued for `localhost`; naming it explicitly
        // keeps the client verifying the name rather than skipping the check.
        .domain_name("localhost")
}

#[tokio::test]
async fn grpc_works_over_tls() {
    let port = boot("grpc").await;
    let endpoint = format!("https://localhost:{port}");

    let mut last = None;
    let mut channel = None;
    for _ in 0..100 {
        match tonic::transport::Channel::from_shared(endpoint.clone())
            .expect("endpoint")
            .tls_config(client_tls())
            .expect("client tls")
            .connect()
            .await
        {
            Ok(connected) => {
                channel = Some(connected);
                break;
            }
            Err(e) => {
                last = Some(e);
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    }
    let channel = channel
        .unwrap_or_else(|| panic!("could not connect over TLS: {:?}", last.expect("an error")));

    // A full gRPC round trip: this can only work if ALPN negotiated h2.
    let mut client = FirestoreClient::new(channel);
    let status = client
        .get_document(GetDocumentRequest {
            name: "projects/tls-demo/databases/(default)/documents/cities/nowhere".into(),
            ..Default::default()
        })
        .await
        .expect_err("the document does not exist");
    assert_eq!(
        status.code(),
        tonic::Code::NotFound,
        "gRPC over TLS should reach the service and answer NOT_FOUND, got {status:?}"
    );
}

/// The same port has to serve the browser/REST surfaces too, which speak
/// HTTP/1.1 — `auto::Builder` picking the wrong protocol would break one or
/// the other.
#[tokio::test]
async fn rest_works_over_tls() {
    let port = boot("rest").await;
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(CA.as_bytes()).expect("cert"))
        .build()
        .expect("client");
    let url = format!("https://localhost:{port}/");

    let mut last = None;
    let mut response = None;
    for _ in 0..100 {
        match client.get(&url).send().await {
            Ok(ok) => {
                response = Some(ok);
                break;
            }
            Err(e) => {
                last = Some(e);
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    }
    let response =
        response.unwrap_or_else(|| panic!("no HTTPS response: {:?}", last.expect("an error")));
    assert!(response.status().is_success());
    assert_eq!(
        response.version(),
        reqwest::Version::HTTP_11,
        "this client only offers HTTP/1.1, and must still be served"
    );
}

/// Asserts the server's own ALPN preference rather than inferring it from
/// whatever a particular HTTP client happens to offer.
///
/// Worth testing directly: if `h2` were dropped from the server's ALPN list,
/// an h2-capable client would quietly settle for HTTP/1.1 and every gRPC
/// caller would break while REST kept working — the exact silent regression
/// this file exists to catch.
#[tokio::test]
async fn the_server_prefers_h2_when_the_client_offers_both() {
    let port = boot("alpn").await;

    let mut roots = tokio_rustls::rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut CA.as_bytes()) {
        roots.add(cert.expect("ca pem")).expect("add ca");
    }
    let mut config = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

    let mut negotiated = None;
    for _ in 0..100 {
        let Ok(tcp) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await else {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            continue;
        };
        let name = tokio_rustls::rustls::pki_types::ServerName::try_from("localhost")
            .expect("server name");
        if let Ok(stream) = connector.connect(name, tcp).await {
            negotiated = stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(
        negotiated.as_deref(),
        Some(&b"h2"[..]),
        "the server must pick h2 for a client offering it, or gRPC over TLS breaks"
    );
}

/// Plaintext against a TLS port must fail rather than be served in the clear.
#[tokio::test]
async fn plaintext_is_not_served_on_a_tls_port() {
    let port = boot("plain").await;
    // Give the listener a moment; a connection refused here would pass the
    // assertion for the wrong reason, so wait for the port to be live first.
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let plaintext = reqwest::Client::new().get(format!("http://127.0.0.1:{port}/")).send().await;
    assert!(plaintext.is_err(), "a cleartext request must not get a response from a TLS port");
}
