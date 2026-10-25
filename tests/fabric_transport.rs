#![cfg(unix)]
//! Live managed-device HTTPS acceptance. No cluster peer transport is exercised.
use maxio::fabric::authority::Authority;
use maxio::fabric::client::{ClientConfig, FabricClient};
use maxio::fabric::contract::*;
use maxio::fabric::transport::identity::DeviceKey;
use maxio::fabric::transport::{
    self, Challenge, ChallengeRequest, SessionRequest, SessionResponse,
};
use maxio::server::ServerTls;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::watch;

struct Harness {
    root: tempfile::TempDir,
    config: ClientConfig,
    owner: FabricClient,
    shutdown: watch::Sender<bool>,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}
fn certificates(root: &Path) -> (PathBuf, PathBuf, PathBuf) {
    fn openssl(args: &[&str], root: &Path) {
        let result = std::process::Command::new("openssl")
            .args(args)
            .current_dir(root)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "openssl failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    openssl(
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=MaxIO test CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-keyout",
            "ca.key",
            "-out",
            "ca.crt",
        ],
        root,
    );
    openssl(
        &[
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-keyout",
            "server.key",
            "-out",
            "server.csr",
        ],
        root,
    );
    std::fs::write(root.join("server.ext"), "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n").unwrap();
    openssl(
        &[
            "x509",
            "-req",
            "-in",
            "server.csr",
            "-CA",
            "ca.crt",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-days",
            "1",
            "-extfile",
            "server.ext",
            "-out",
            "server.crt",
        ],
        root,
    );
    (
        root.join("server.crt"),
        root.join("server.key"),
        root.join("ca.crt"),
    )
}
async fn harness() -> Harness {
    let root = tempfile::tempdir().unwrap();
    let device_id = uuid::Uuid::new_v4().to_string();
    let key_path = root.path().join("owner.pem");
    let key = DeviceKey::generate(&key_path).unwrap();
    let authority = Arc::new(
        Authority::initialize(
            &root.path().join("authority"),
            BootstrapOwner {
                device_id: device_id.clone(),
                display_name: "Owner".into(),
                public_key: key.public_key().unwrap(),
            },
        )
        .unwrap(),
    );
    let info = authority.info();
    let (cert, key, ca) = certificates(root.path());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("https://{}", listener.local_addr().unwrap());
    let tls = ServerTls::standalone(cert.to_str().unwrap(), key.to_str().unwrap()).unwrap();
    let (shutdown, receiver) = watch::channel(false);
    let spool = root.path().join("authority/spool");
    let task = tokio::spawn(transport::serve(authority, listener, tls, spool, receiver));
    let config = ClientConfig {
        endpoint,
        authority_id: info.authority_id,
        vault_id: info.vault_id,
        device_id,
        key_path,
        ca_cert: Some(ca),
    };
    let owner = FabricClient::connect(config.clone()).await.unwrap();
    Harness {
        root,
        config,
        owner,
        shutdown,
        task,
    }
}
async fn stop(h: Harness) {
    h.shutdown.send(true).unwrap();
    h.task.await.unwrap().unwrap();
}
fn request_id() -> String {
    uuid::Uuid::new_v4().to_string()
}
async fn create_workspace(client: &FabricClient) -> WorkspaceRecord {
    match client
        .control(&ControlRequest::CreateWorkspace {
            request_id: request_id(),
            name: "project".into(),
            import_source: None,
        })
        .await
        .unwrap()
    {
        ControlResponse::Workspace { workspace } => workspace,
        _ => panic!("wrong response"),
    }
}
async fn enroll(h: &Harness, name: &str) -> (ClientConfig, FabricClient) {
    let key_path = h.root.path().join(format!("{name}.pem"));
    let key = DeviceKey::generate(&key_path).unwrap();
    let device = match h
        .owner
        .control(&ControlRequest::EnrollDevice {
            request_id: request_id(),
            display_name: name.into(),
            public_key: key.public_key().unwrap(),
            role: DeviceRole::Device,
        })
        .await
        .unwrap()
    {
        ControlResponse::Device { device } => device,
        _ => panic!("wrong response"),
    };
    let config = ClientConfig {
        device_id: device.device_id,
        key_path,
        ..h.config.clone()
    };
    let client = FabricClient::connect(config.clone()).await.unwrap();
    (config, client)
}

#[tokio::test]
async fn live_device_proof_grants_and_revocation_are_independent() {
    let h = harness().await;
    let workspace = create_workspace(&h.owner).await;
    let (config, client) = enroll(&h, "reader").await;
    let request = ControlRequest::Current {
        workspace_id: workspace.workspace_id.clone(),
    };
    let error = client.control(&request).await.err().unwrap();
    assert_eq!(
        error.downcast_ref::<FabricError>().unwrap().code,
        ErrorCode::Forbidden
    );
    h.owner
        .control(&ControlRequest::SetGrant {
            request_id: request_id(),
            grant: WorkspaceGrant {
                device_id: config.device_id.clone(),
                workspace_id: workspace.workspace_id,
                catalog_read: true,
                read: vec![PathScope::Workspace],
                write: vec![],
                submit_jobs: false,
            },
        })
        .await
        .unwrap();
    assert!(matches!(
        client.control(&request).await.unwrap(),
        ControlResponse::Catalog { .. }
    ));
    let error = client
        .control(&ControlRequest::RevokeDevice {
            request_id: request_id(),
            device_id: h.config.device_id.clone(),
        })
        .await
        .err()
        .unwrap();
    assert_eq!(
        error.downcast_ref::<FabricError>().unwrap().code,
        ErrorCode::Forbidden
    );
    h.owner
        .control(&ControlRequest::RevokeDevice {
            request_id: request_id(),
            device_id: config.device_id,
        })
        .await
        .unwrap();
    let error = client.control(&request).await.err().unwrap();
    assert_eq!(
        error.downcast_ref::<FabricError>().unwrap().code,
        ErrorCode::Unauthenticated
    );
    assert!(matches!(
        h.owner.control(&ControlRequest::Info).await.unwrap(),
        ControlResponse::Info { .. }
    ));
    stop(h).await;
}

#[tokio::test]
async fn wrong_key_unenrolled_identity_and_wrong_authority_fail_closed() {
    let h = harness().await;
    let wrong_key = h.root.path().join("wrong.pem");
    DeviceKey::generate(&wrong_key).unwrap();
    let config = ClientConfig {
        key_path: wrong_key,
        ..h.config.clone()
    };
    assert!(FabricClient::connect(config).await.is_err());
    let config = ClientConfig {
        device_id: request_id(),
        ..h.config.clone()
    };
    assert!(FabricClient::connect(config).await.is_err());
    let config = ClientConfig {
        vault_id: request_id(),
        ..h.config.clone()
    };
    assert!(FabricClient::connect(config).await.is_err());
    let config = ClientConfig {
        endpoint: h.config.endpoint.replace("https:", "http:"),
        ..h.config.clone()
    };
    assert!(FabricClient::connect(config).await.is_err());
    let elsewhere = tempfile::tempdir().unwrap();
    let (_, _, wrong_ca) = certificates(elsewhere.path());
    let config = ClientConfig {
        ca_cert: Some(wrong_ca),
        ..h.config.clone()
    };
    assert!(FabricClient::connect(config).await.is_err());
    stop(h).await;
}

#[tokio::test]
async fn proof_challenge_is_single_use_and_binds_the_complete_challenge() {
    let h = harness().await;
    let ca =
        reqwest::Certificate::from_pem(&std::fs::read(h.config.ca_cert.as_ref().unwrap()).unwrap())
            .unwrap();
    let http = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .add_root_certificate(ca)
        .build()
        .unwrap();
    let key = DeviceKey::load(&h.config.key_path).unwrap();
    let challenge: Challenge = http
        .post(format!("{}/v1/auth/challenge", h.config.endpoint))
        .json(&ChallengeRequest {
            device_id: h.config.device_id.clone(),
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let proof = SessionRequest {
        device_id: h.config.device_id.clone(),
        challenge_id: challenge.challenge_id.clone(),
        signature: key.sign(&challenge).unwrap(),
    };
    let first = http
        .post(format!("{}/v1/auth/session", h.config.endpoint))
        .json(&proof)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), 200);
    let _: SessionResponse = first.json().await.unwrap();
    assert_eq!(
        http.post(format!("{}/v1/auth/session", h.config.endpoint))
            .json(&proof)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let mut changed: Challenge = http
        .post(format!("{}/v1/auth/challenge", h.config.endpoint))
        .json(&ChallengeRequest {
            device_id: h.config.device_id.clone(),
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    changed.authority.vault_id = request_id();
    let proof = SessionRequest {
        device_id: h.config.device_id.clone(),
        challenge_id: changed.challenge_id.clone(),
        signature: key.sign(&changed).unwrap(),
    };
    assert_eq!(
        http.post(format!("{}/v1/auth/session", h.config.endpoint))
            .json(&proof)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    stop(h).await;
}

#[tokio::test]
async fn actual_streaming_publication_and_exact_download_verify_bytes() {
    use maxio::workspace::contract::RevisionRef;
    let h = harness().await;
    let workspace = create_workspace(&h.owner).await;
    let lease = match h
        .owner
        .control(&ControlRequest::AcquireLease {
            request_id: request_id(),
            workspace_id: workspace.workspace_id.clone(),
            scopes: vec![PathScope::Workspace],
            ttl_seconds: 60,
        })
        .await
        .unwrap()
    {
        ControlResponse::Lease { lease } => lease,
        _ => panic!("wrong response"),
    };
    let source = h.root.path().join("payload");
    let bytes = (0..131_071).map(|i| (i % 251) as u8).collect::<Vec<_>>();
    std::fs::write(&source, &bytes).unwrap();
    let (sha256, size) = maxio::files::hash_file(&source).unwrap();
    let upload = h
        .owner
        .upload(
            &UploadRequest {
                request_id: request_id(),
                workspace_id: workspace.workspace_id.clone(),
                path: "docs/bytes.bin".into(),
                sha256,
                size,
                lease: lease.token.clone(),
                attempt: None,
            },
            &source,
        )
        .await
        .unwrap();
    let publication = PublishRequest {
        context: PublicationContext {
            request_id: request_id(),
            workspace_id: workspace.workspace_id.clone(),
            base: workspace.head,
            lease: lease.token,
            attempt: None,
        },
        changes: vec![PublicationChange::Put {
            path: upload.path.clone(),
            upload_id: upload.upload_id,
            expected: None,
        }],
    };
    let receipt = match h
        .owner
        .control(&ControlRequest::Publish { publication })
        .await
        .unwrap()
    {
        ControlResponse::Publication { receipt } => receipt,
        _ => panic!("wrong response"),
    };
    let file = FileRequest {
        workspace_id: workspace.workspace_id,
        revision: RevisionRef {
            revision: receipt.committed_head.revision.revision,
            sha256: receipt.committed_head.revision.sha256,
        },
        path: upload.path,
        expected: upload.version,
        attempt: None,
    };
    let destination = h.root.path().join("download");
    h.owner.download(&file, &destination).await.unwrap();
    assert_eq!(std::fs::read(&destination).unwrap(), bytes);
    assert_eq!(h.owner.stats().payload_uploaded, size);
    assert_eq!(h.owner.stats().payload_downloaded, size);
    assert!(h.owner.download(&file, &destination).await.is_err());
    assert_eq!(std::fs::read(destination).unwrap(), bytes);
    let retained = RetainedFile {
        workspace_id: file.workspace_id,
        revision: file.revision,
        path: file.path,
        version: file.expected,
    };
    let proof = h.owner.verify_retention(&[retained]).await.unwrap();
    assert_eq!(proof.verification().receipts.len(), 1);
    stop(h).await;
}
