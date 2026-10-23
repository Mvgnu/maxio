use super::*;
use crate::cluster::transport_identity::test_support::{TestCa, TestIdentity};
use openssl::ssl::{Ssl, SslFiletype};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread::{self, JoinHandle};
use std::time::Instant;

const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

#[derive(Debug)]
struct Observed {
    identity: Result<Option<String>, String>,
    request: Vec<u8>,
    tls_version: Option<String>,
}

fn listener() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test TLS server");
    let node_id = listener.local_addr().expect("bound address").to_string();
    (listener, node_id)
}

fn serve_once(
    listener: TcpListener,
    acceptor: SslAcceptor,
    revocations: Option<String>,
    response: &'static [u8],
) -> JoinHandle<Observed> {
    thread::spawn(move || {
        listener
            .set_nonblocking(true)
            .expect("nonblocking test accept");
        let deadline = Instant::now() + Duration::from_secs(4);
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("test server did not receive connection: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("read timeout");
        stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .expect("write timeout");
        let mut stream = match acceptor.accept(stream) {
            Ok(stream) => stream,
            Err(error) => {
                return Observed {
                    identity: Err(error.to_string()),
                    request: Vec::new(),
                    tls_version: None,
                };
            }
        };
        let tls_version = Some(stream.ssl().version_str().to_owned());
        let identity = verified_peer_identity_from_tls(stream.ssl(), revocations.as_deref())
            .map(|identity| identity.map(|identity| identity.node_id().to_owned()));
        if identity.is_err() {
            return Observed {
                identity,
                request: Vec::new(),
                tls_version,
            };
        }
        let mut request = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(length) => request.extend_from_slice(&buffer[..length]),
            }
            if let Some(end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&request[..end]);
                let body_len = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                if request.len() >= end + 4 + body_len {
                    break;
                }
            }
            assert!(request.len() < 16 * 1024, "test request unexpectedly large");
        }
        if !request.is_empty() {
            let _ = stream.write_all(response);
        }
        Observed {
            identity,
            request,
            tls_version,
        }
    })
}

fn peer_client(identity: &TestIdentity, destination: &str) -> reqwest::Client {
    build_peer_mtls_http_client(
        identity.config(),
        destination,
        Some(Duration::from_secs(2)),
        Duration::from_secs(3),
    )
    .expect("verified peer client")
}

fn ordinary_client(ca: &TestCa, identity: Option<&TestIdentity>) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(
            reqwest::Certificate::from_pem(&ca.cert.to_pem().expect("CA PEM")).expect("reqwest CA"),
        )
        .no_proxy()
        .timeout(Duration::from_secs(3));
    if let Some(identity) = identity {
        let mut pem = fs::read(&identity.cert_path).expect("read client cert");
        pem.extend(fs::read(&identity.key_path).expect("read client key"));
        builder = builder.identity(reqwest::Identity::from_pem(&pem).expect("reqwest identity"));
    }
    builder.build().expect("ordinary HTTPS client")
}

// Deliberately bypass local readiness checks to simulate a remote peer serving
// an invalid identity. The client must still reject it on its actual handshake.
fn remote_acceptor(identity: &TestIdentity) -> SslAcceptor {
    let mut builder =
        SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).expect("remote acceptor");
    builder
        .set_certificate_chain_file(&identity.cert_path)
        .expect("remote certificate");
    builder
        .set_private_key_file(&identity.key_path, SslFiletype::PEM)
        .expect("remote private key");
    builder.set_ca_file(&identity.ca_path).expect("remote CA");
    builder.set_verify(SslVerifyMode::PEER);
    builder.build()
}

#[test]
fn secure_uri_has_one_canonical_identity_including_port() {
    assert_eq!(
        peer_node_identity_uri(" NODE-A.LAN:009000 ").unwrap(),
        "maxio://node-a.lan:9000"
    );
    assert_eq!(
        peer_node_identity_uri("[2001:0DB8:0::1]:9000").unwrap(),
        "maxio://[2001:db8::1]:9000"
    );
    for node_id in [
        "node-a",
        "node-a:0",
        "node-a:65536",
        "node-a:9000/path",
        "user@node-a:9000",
        "::1:9000",
    ] {
        assert!(
            peer_node_identity_uri(node_id).is_err(),
            "accepted {node_id}"
        );
    }
}

#[test]
fn local_identity_requires_unique_canonical_uri_and_matching_key_without_pin() {
    let ca = TestCa::new();
    let node_id = "node-a.lan:9000";
    let valid = ca.issue(node_id);
    assert!(build_peer_tls_acceptor(valid.config()).is_ok());
    let alternate = ca.issue("node-b.lan:9000");
    let mut wrong_key = valid.config();
    wrong_key.key_path = &alternate.key_path;
    assert!(build_peer_tls_acceptor(wrong_key).is_err());
    for uris in [
        vec![],
        vec!["maxio://NODE-A.LAN:9000".to_owned()],
        vec!["MAXIO://node-a.lan:9000".to_owned()],
        vec!["maxio://node-a.lan:9000/".to_owned()],
        vec![
            "maxio://node-a.lan:9000".to_owned(),
            "maxio://node-a.lan:9001".to_owned(),
        ],
        vec![
            "maxio://node-a.lan:9000".to_owned(),
            "maxio://node-a.lan:9000".to_owned(),
        ],
        vec!["maxio://node-a.lan:9001".to_owned()],
    ] {
        let invalid = ca.issue_with_sans(node_id, &uris, None);
        assert!(
            build_peer_tls_acceptor(invalid.config()).is_err(),
            "accepted URI SANs {uris:?}"
        );
    }
    let other_scheme = ca.issue_with_sans(
        node_id,
        &[
            "https://example.test/id".to_owned(),
            format!("maxio://{node_id}"),
        ],
        None,
    );
    assert!(build_peer_tls_acceptor(other_scheme.config()).is_ok());
}

#[test]
fn local_identity_rejects_invalid_ca_hostname_pin_and_revocation() {
    let ca = TestCa::new();
    let other_ca = TestCa::new();
    let identity = ca.issue("127.0.0.1:9000");
    let untrusted = other_ca.issue("127.0.0.1:9001");
    let mut config = identity.config();
    config.ca_path = &untrusted.ca_path;
    assert!(build_peer_tls_acceptor(config).is_err());
    let wrong_host = ca.issue_with_sans(
        "127.0.0.1:9000",
        &["maxio://127.0.0.1:9000".to_owned()],
        Some("other.example"),
    );
    assert!(build_peer_tls_acceptor(wrong_host.config()).is_err());
    let fingerprint = identity.fingerprint();
    config = identity.config();
    config.certificate_policy.sha256_revocations = Some(&fingerprint);
    assert!(
        build_peer_tls_acceptor(config)
            .err()
            .expect("revoked local certificate")
            .contains("revoked")
    );
    config = identity.config();
    config.certificate_policy.sha256_pin = Some("not-a-fingerprint");
    assert!(build_peer_tls_acceptor(config).is_err());
    config.certificate_policy.sha256_pin = Some(&fingerprint);
    assert!(build_peer_tls_acceptor(config).is_ok());
    let another_fingerprint = untrusted.fingerprint();
    config.certificate_policy.sha256_pin = Some(&another_fingerprint);
    assert!(build_peer_tls_acceptor(config).is_err());
}

#[test]
fn unfinished_tls_cannot_mint_verified_identity() {
    let ca = TestCa::new();
    let identity = ca.issue("127.0.0.1:9000");
    let acceptor = build_peer_tls_acceptor(identity.config()).expect("acceptor");
    let ssl = Ssl::new(acceptor.context()).expect("SSL object");
    assert!(verified_peer_identity_from_tls(&ssl, None).is_err());
}

#[test]
fn malformed_or_private_key_sections_cannot_hide_after_a_valid_ca() {
    let ca = TestCa::new();
    let identity = ca.issue("127.0.0.1:9000");
    let valid_ca = ca.cert.to_pem().unwrap();
    for extra in [
        fs::read(&identity.key_path).unwrap(),
        b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nYQ==\n-----END ENCRYPTED PRIVATE KEY-----\n"
            .to_vec(),
        b"-----BEGIN CERTIFICATE-----\nnot-valid-base64!\n-----END CERTIFICATE-----\n".to_vec(),
    ] {
        let mut invalid_ca = valid_ca.clone();
        invalid_ca.extend(extra);
        fs::write(&identity.ca_path, invalid_ca).unwrap();
        assert!(build_peer_tls_acceptor(identity.config()).is_err());
    }
}

#[tokio::test]
async fn actual_tls_connection_binds_sender_and_carries_request_bytes() {
    let ca = TestCa::new();
    let (listener, server_id) = listener();
    let server = ca.issue(&server_id);
    let client = ca.issue("127.0.0.1:9001");
    let http = peer_client(&client, &server_id);
    let server = serve_once(
        listener,
        build_peer_tls_acceptor(server.config()).unwrap(),
        None,
        RESPONSE,
    );
    let response = http
        .post(format!("https://{server_id}/bucket/key"))
        .header("x-maxio-forwarded-by", "127.0.0.1:9002")
        .body("request payload")
        .send()
        .await
        .expect("mutually authenticated request");
    assert_eq!(response.text().await.unwrap(), "ok");
    let observed = server.join().expect("TLS server");
    assert_eq!(
        observed.identity.unwrap().as_deref(),
        Some(client.node_id.as_str())
    );
    assert_eq!(observed.tls_version.as_deref(), Some("TLSv1.3"));
    assert!(observed.request.ends_with(b"request payload"));
    assert!(
        String::from_utf8_lossy(&observed.request).contains("x-maxio-forwarded-by: 127.0.0.1:9002")
    );
}

#[tokio::test]
async fn same_host_other_port_certificate_is_rejected_before_payload() {
    let ca = TestCa::new();
    let (listener, server_id) = listener();
    let server = ca.issue("127.0.0.1:9002");
    let client = ca.issue("127.0.0.1:9001");
    let http = peer_client(&client, &server_id);
    let server = serve_once(
        listener,
        build_peer_tls_acceptor(server.config()).unwrap(),
        None,
        RESPONSE,
    );
    assert!(
        http.post(format!("https://{server_id}/internal"))
            .body("this payload must never reach the impostor")
            .send()
            .await
            .is_err()
    );
    assert!(server.join().unwrap().request.is_empty());
}

#[tokio::test]
async fn actual_handshake_rejects_remote_missing_duplicate_or_wrong_hostname_identity() {
    let ca = TestCa::new();
    let client = ca.issue("127.0.0.1:9001");
    for scenario in ["missing URI", "duplicate URI", "wrong hostname"] {
        let (listener, server_id) = listener();
        let uri = format!("maxio://{server_id}");
        let (uris, hostname) = match scenario {
            "missing URI" => (vec![], None),
            "duplicate URI" => (vec![uri.clone(), uri], None),
            _ => (vec![uri], Some("other.example")),
        };
        let server_identity = ca.issue_with_sans(&server_id, &uris, hostname);
        let http = peer_client(&client, &server_id);
        let server = serve_once(listener, remote_acceptor(&server_identity), None, RESPONSE);
        assert!(
            http.post(format!("https://{server_id}/"))
                .body("do not disclose")
                .send()
                .await
                .is_err(),
            "accepted {scenario}"
        );
        assert!(
            server.join().unwrap().request.is_empty(),
            "sent payload for {scenario}"
        );
    }
}

#[tokio::test]
async fn revoked_server_is_rejected_on_actual_handshake_before_payload() {
    let ca = TestCa::new();
    let (listener, server_id) = listener();
    let server_identity = ca.issue(&server_id);
    let client = ca.issue("127.0.0.1:9001");
    let fingerprint = server_identity.fingerprint();
    let mut config = client.config();
    config.certificate_policy.sha256_revocations = Some(&fingerprint);
    let http =
        build_peer_mtls_http_client(config, &server_id, None, Duration::from_secs(3)).unwrap();
    let server = serve_once(
        listener,
        build_peer_tls_acceptor(server_identity.config()).unwrap(),
        None,
        RESPONSE,
    );
    assert!(
        http.post(format!("https://{server_id}/"))
            .body("do not disclose")
            .send()
            .await
            .is_err()
    );
    assert!(server.join().unwrap().request.is_empty());
}

#[tokio::test]
async fn expired_server_is_rejected_locally_and_during_actual_handshake() {
    let ca = TestCa::new();
    let (listener, server_id) = listener();
    let server_identity = ca.issue_expired(&server_id);
    assert!(build_peer_tls_acceptor(server_identity.config()).is_err());
    let client = ca.issue("127.0.0.1:9001");
    let http = peer_client(&client, &server_id);
    let server = serve_once(listener, remote_acceptor(&server_identity), None, RESPONSE);
    assert!(
        http.post(format!("https://{server_id}/"))
            .body("do not disclose")
            .send()
            .await
            .is_err()
    );
    assert!(server.join().unwrap().request.is_empty());
}

#[tokio::test]
async fn every_configured_ca_in_the_bundle_can_authenticate_a_peer() {
    let ca = TestCa::new();
    let other_ca = TestCa::new();
    let (listener, server_id) = listener();
    let server_identity = other_ca.issue(&server_id);
    let client = ca.issue("127.0.0.1:9001");
    let mut bundle = ca.cert.to_pem().unwrap();
    bundle.extend(other_ca.cert.to_pem().unwrap());
    fs::write(&client.ca_path, &bundle).unwrap();
    fs::write(&server_identity.ca_path, &bundle).unwrap();
    let http = peer_client(&client, &server_id);
    let server = serve_once(
        listener,
        build_peer_tls_acceptor(server_identity.config()).unwrap(),
        None,
        RESPONSE,
    );
    assert!(
        http.get(format!("https://{server_id}/"))
            .send()
            .await
            .unwrap()
            .status()
            .is_success()
    );
    assert_eq!(
        server.join().unwrap().identity.unwrap().as_deref(),
        Some(client.node_id.as_str())
    );
}

#[tokio::test]
async fn wrong_ca_is_rejected_in_both_directions() {
    let ca = TestCa::new();
    let other_ca = TestCa::new();
    let client = other_ca.issue("127.0.0.1:9001");
    for inbound in [false, true] {
        let (listener, server_id) = listener();
        let server_identity = ca.issue(&server_id);
        let http = if inbound {
            ordinary_client(&ca, Some(&client))
        } else {
            peer_client(&client, &server_id)
        };
        let server = serve_once(
            listener,
            build_peer_tls_acceptor(server_identity.config()).unwrap(),
            None,
            RESPONSE,
        );
        assert!(
            http.post(format!("https://{server_id}/"))
                .body("do not admit")
                .send()
                .await
                .is_err()
        );
        let observed = server.join().unwrap();
        assert!(observed.identity.is_err());
        assert!(observed.request.is_empty());
    }
}

#[tokio::test]
async fn public_tls_allows_an_ordinary_client_without_minting_peer_identity() {
    let ca = TestCa::new();
    let (listener, server_id) = listener();
    let identity = ca.issue(&server_id);
    let http = ordinary_client(&ca, None);
    let server = serve_once(
        listener,
        build_peer_tls_acceptor(identity.config()).unwrap(),
        None,
        RESPONSE,
    );
    assert!(
        http.get(format!("https://{server_id}/"))
            .send()
            .await
            .unwrap()
            .status()
            .is_success()
    );
    assert!(server.join().unwrap().identity.unwrap().is_none());
}

#[tokio::test]
async fn inbound_revoked_or_unbound_certificate_never_mints_identity() {
    let ca = TestCa::new();
    for revoked in [false, true] {
        let (listener, server_id) = listener();
        let server_identity = ca.issue(&server_id);
        let client = if revoked {
            ca.issue("127.0.0.1:9001")
        } else {
            ca.issue_with_sans("127.0.0.1:9001", &[], None)
        };
        let revocations = revoked.then(|| client.fingerprint());
        let http = ordinary_client(&ca, Some(&client));
        let server = serve_once(
            listener,
            build_peer_tls_acceptor(server_identity.config()).unwrap(),
            revocations,
            RESPONSE,
        );
        assert!(
            http.get(format!("https://{server_id}/"))
                .send()
                .await
                .is_err()
        );
        let observed = server.join().unwrap();
        assert!(observed.identity.is_err());
        assert!(observed.request.is_empty());
    }
}

#[tokio::test]
async fn peer_client_refuses_plaintext_and_does_not_follow_redirects() {
    let ca = TestCa::new();
    let (listener, server_id) = listener();
    let server_identity = ca.issue(&server_id);
    let client = ca.issue("127.0.0.1:9001");
    let http = peer_client(&client, &server_id);
    assert!(
        http.get(format!("http://{server_id}/"))
            .send()
            .await
            .is_err()
    );
    let server = serve_once(listener, build_peer_tls_acceptor(server_identity.config()).unwrap(), None,
        b"HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1:1/should-not-connect\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    let response = http
        .get(format!("https://{server_id}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::FOUND);
    assert_eq!(
        server.join().unwrap().identity.unwrap().as_deref(),
        Some(client.node_id.as_str())
    );
}
