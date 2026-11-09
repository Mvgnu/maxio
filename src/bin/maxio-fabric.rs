//! Optional managed-workspace CLI. Standalone maxio does not invoke this binary.
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::{Parser, Subcommand, ValueEnum};
use maxio::fabric::authority::Authority;
use maxio::fabric::cache::PrivateCache;
use maxio::fabric::client::{ClientConfig, FabricClient, ManagedReader};
use maxio::fabric::contract::*;
use maxio::fabric::transport::{self, identity::DeviceKey};
use maxio::workspace::{
    LocalWorkspace,
    contract::{Manifest, Publication, RevisionRef},
};
use serde::Serialize;
use serde_json::{Value, json};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "maxio-fabric",
    about = "Optional managed workspaces and storage-aware jobs",
    version
)]
struct Cli {
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Create an individual private Ed25519 key; prints its public key only.
    Keygen {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        public_key_out: Option<PathBuf>,
    },
    /// Initialize a new private authority; create the owner's client config.
    Init {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        owner_key: PathBuf,
        #[arg(long, default_value = "Owner")]
        name: String,
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        ca_cert: Option<PathBuf>,
        #[arg(long)]
        client_config: PathBuf,
    },
    /// Run the single optional coordinator over native HTTPS.
    Serve {
        #[arg(long)]
        root: PathBuf,
        #[arg(long, default_value = "127.0.0.1:9443")]
        bind: std::net::SocketAddr,
        #[arg(long)]
        tls_cert: PathBuf,
        #[arg(long)]
        tls_key: PathBuf,
    },
    Info,
    Device {
        #[command(subcommand)]
        command: DeviceCommand,
    },
    Workspace {
        #[command(subcommand)]
        command: WorkspaceCommand,
    },
    Cache {
        #[command(subcommand)]
        command: CacheCommand,
    },
    Lease {
        #[command(subcommand)]
        command: LeaseCommand,
    },
    Task {
        #[command(subcommand)]
        command: TaskCommand,
    },
    Workers,
    /// Advanced typed control request. Mutation request IDs must be retained for recovery.
    Rpc {
        #[arg(long)]
        request: PathBuf,
    },
}
#[derive(Clone, Copy, ValueEnum)]
enum Role {
    Device,
    Worker,
    Owner,
}
impl From<Role> for DeviceRole {
    fn from(role: Role) -> Self {
        match role {
            Role::Device => Self::Device,
            Role::Worker => Self::Worker,
            Role::Owner => Self::Owner,
        }
    }
}
#[derive(Subcommand)]
enum DeviceCommand {
    List,
    Enroll {
        #[arg(long)]
        name: String,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long, value_enum, default_value = "device")]
        role: Role,
        #[arg(long, requires = "key_path")]
        write_config: Option<PathBuf>,
        #[arg(long)]
        key_path: Option<PathBuf>,
        #[arg(long)]
        ca_cert: Option<PathBuf>,
    },
    Grant {
        #[arg(long)]
        device: String,
        #[arg(long)]
        workspace: String,
        #[arg(long)]
        catalog: bool,
        #[arg(long)]
        read: Vec<String>,
        #[arg(long)]
        write: Vec<String>,
        #[arg(long)]
        submit_jobs: bool,
    },
    Revoke {
        #[arg(long)]
        device: String,
        #[arg(long)]
        confirm: bool,
    },
    Rotate {
        #[arg(long)]
        device: String,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long)]
        expected_generation: u64,
        #[arg(long)]
        confirm: bool,
    },
}
#[derive(Subcommand)]
enum WorkspaceCommand {
    Create {
        name: String,
    },
    List,
    /// Metadata-only current catalog or exact immutable revision.
    Inspect {
        workspace: String,
        #[arg(long, requires = "sha256")]
        revision: Option<String>,
        #[arg(long)]
        sha256: Option<String>,
    },
    /// Observe current metadata; selected bytes move only if --path is provided.
    Pull {
        workspace: String,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        path: Vec<String>,
        #[arg(long, requires = "sha256")]
        revision: Option<String>,
        #[arg(long)]
        sha256: Option<String>,
    },
    /// Publish explicit local selections under renewable fenced authority.
    Publish {
        workspace: String,
        #[arg(long)]
        root: PathBuf,
        #[arg(long, required = true)]
        path: Vec<String>,
    },
    /// Replay one retained publication request after an uncertain response; never rerun a task.
    RecoverPublication {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        operation: PathBuf,
    },
    /// Inspect persisted metadata/local baseline without credentials or a connection.
    Status {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        verify: bool,
    },
    Pin {
        #[arg(long)]
        root: PathBuf,
        #[arg(long, required = true)]
        path: Vec<String>,
        #[arg(long)]
        unpin: bool,
    },
    /// Explicit global logical deletion. Vault history and local edits remain retained.
    Delete {
        workspace: String,
        #[arg(long)]
        path: String,
        #[arg(long)]
        confirm: bool,
    },
    Restore {
        workspace: String,
        #[arg(long)]
        path: String,
        #[arg(long)]
        revision: String,
        #[arg(long)]
        sha256: String,
        #[arg(long)]
        source_path: Option<String>,
        #[arg(long)]
        confirm: bool,
    },
    /// Save exact version references for offline pin/copy and explicit cache operations.
    References {
        workspace: String,
        #[arg(long, required = true)]
        path: Vec<String>,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}
#[derive(Subcommand)]
enum CacheCommand {
    Inspect {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        verify: bool,
    },
    Hydrate {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        references: PathBuf,
    },
    Import {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        references: PathBuf,
        #[arg(long)]
        source: PathBuf,
    },
    Pin {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        references: PathBuf,
        #[arg(long)]
        unpin: bool,
    },
    Copy {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        references: PathBuf,
        #[arg(long)]
        destination: PathBuf,
    },
    Evict {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        references: PathBuf,
        #[arg(long)]
        confirm: bool,
    },
}
#[derive(Subcommand)]
enum LeaseCommand {
    List {
        workspace: String,
    },
    Acquire {
        workspace: String,
        #[arg(long, required = true)]
        scope: Vec<String>,
        #[arg(long, default_value_t = 60)]
        ttl: u64,
        #[arg(long)]
        save: Option<PathBuf>,
    },
    Renew {
        workspace: String,
        #[arg(long)]
        lease: PathBuf,
        #[arg(long, default_value_t = 60)]
        ttl: u64,
    },
    Release {
        workspace: String,
        #[arg(long)]
        lease: PathBuf,
    },
}
#[derive(Subcommand)]
enum TaskCommand {
    Submit {
        workspace: String,
        #[arg(long)]
        profile: String,
        #[arg(long)]
        input: Vec<String>,
        #[arg(long)]
        output: Vec<String>,
        #[arg(long)]
        worker: Option<String>,
        #[arg(long, default_value_t = 3600)]
        timeout: u64,
        #[arg(long, default_value_t = 1000)]
        cpu_millis: u32,
        #[arg(long, default_value_t = 268435456)]
        memory_bytes: u64,
        #[arg(long)]
        prompt_file: Option<PathBuf>,
        #[arg(long)]
        publish: bool,
    },
    Status {
        job: String,
    },
    List {
        #[arg(long)]
        workspace: Option<String>,
    },
    Explain {
        job: String,
    },
    Cancel {
        job: String,
    },
    Retry {
        job: String,
        #[arg(long)]
        previous_attempt: String,
    },
    Logs {
        job: String,
        #[arg(long)]
        attempt: String,
        #[arg(long)]
        stderr: bool,
        #[arg(long, default_value_t = 0)]
        offset: u64,
        /// Print the decoded log page directly; omit for JSON pagination and transfer metadata.
        #[arg(long)]
        text: bool,
    },
}
fn id() -> String {
    uuid::Uuid::new_v4().to_string()
}
fn absolute(path: &Path) -> Result<PathBuf> {
    Ok(if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    })
}
fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let meta = std::fs::symlink_metadata(path)?;
    ensure!(
        meta.is_file() && !meta.file_type().is_symlink() && meta.len() <= 16 * 1024 * 1024,
        "input must be a bounded regular JSON file"
    );
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}
fn write(path: &Path, value: &impl Serialize) -> Result<()> {
    let path = absolute(path)?;
    let mut file = maxio::files::new_file(&path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    maxio::files::sync_directory(path.parent().context("output has no parent")?)
}
fn scope(value: &str) -> Result<PathScope> {
    if value == "." {
        return Ok(PathScope::Workspace);
    }
    let path = value.trim_end_matches('/');
    maxio::files::validate_workspace_relative(path)?;
    Ok(if value.ends_with('/') {
        PathScope::Tree { path: path.into() }
    } else {
        PathScope::Exact { path: path.into() }
    })
}
fn scopes(values: &[String]) -> Result<Vec<PathScope>> {
    values.iter().map(|v| scope(v)).collect()
}
fn selected(manifest: &Manifest, selectors: &[String]) -> Result<Vec<RetainedFile>> {
    let mut selected = std::collections::BTreeMap::new();
    let revision = RevisionRef {
        revision: manifest.revision.clone(),
        sha256: maxio::workspace::contract::manifest_hash(manifest)?,
    };
    for selector in selectors {
        let selector = selector.trim_end_matches('/');
        if selector != "." {
            maxio::files::validate_workspace_relative(selector)?;
        }
        let mut found = false;
        for (path, version) in &manifest.files {
            if selector == "." || path == selector || path.starts_with(&format!("{selector}/")) {
                found = true;
                selected.insert(
                    path.clone(),
                    RetainedFile {
                        workspace_id: manifest.workspace_id.clone(),
                        revision: revision.clone(),
                        path: path.clone(),
                        version: version.clone(),
                    },
                );
            }
        }
        ensure!(found, "selection has no published files: {selector}");
    }
    Ok(selected.into_values().collect())
}
async fn workspace(client: &FabricClient, value: &str) -> Result<String> {
    if maxio::workspace::contract::validate_id(value).is_ok() {
        return Ok(value.into());
    }
    let ControlResponse::Workspaces { workspaces } =
        client.control(&ControlRequest::ListWorkspaces).await?
    else {
        anyhow::bail!("unexpected workspace list");
    };
    let found: Vec<_> = workspaces.into_iter().filter(|w| w.name == value).collect();
    ensure!(
        found.len() == 1,
        "workspace name is unavailable or ambiguous; use its UUID"
    );
    Ok(found[0].workspace_id.clone())
}
async fn current(client: &FabricClient, workspace_id: &str) -> Result<ManagedCatalog> {
    let ControlResponse::Catalog { catalog } = client
        .control(&ControlRequest::Current {
            workspace_id: workspace_id.into(),
        })
        .await?
    else {
        anyhow::bail!("unexpected catalog response");
    };
    Ok(catalog)
}
async fn exact(
    client: &FabricClient,
    workspace_id: &str,
    revision: RevisionRef,
) -> Result<ManagedCatalog> {
    let ControlResponse::Catalog { catalog } = client
        .control(&ControlRequest::Revision {
            workspace_id: workspace_id.into(),
            revision,
        })
        .await?
    else {
        anyhow::bail!("unexpected revision response");
    };
    Ok(catalog)
}
fn target(client: &FabricClient, workspace_id: &str) -> ManagedTarget {
    let c = client.config();
    ManagedTarget {
        authority_id: c.authority_id.clone(),
        vault_id: c.vault_id.clone(),
        workspace_id: workspace_id.into(),
        origin: c.endpoint.clone(),
    }
}
async fn lease(
    client: &FabricClient,
    workspace_id: &str,
    scopes: Vec<PathScope>,
    ttl: u64,
) -> Result<WriteLease> {
    let ControlResponse::Lease { lease } = client
        .control(&ControlRequest::AcquireLease {
            request_id: id(),
            workspace_id: workspace_id.into(),
            scopes,
            ttl_seconds: ttl,
        })
        .await?
    else {
        anyhow::bail!("unexpected lease response");
    };
    Ok(lease)
}
async fn authority_info(client: &FabricClient) -> Result<AuthorityInfo> {
    let ControlResponse::Info { info } = client.control(&ControlRequest::Info).await? else {
        anyhow::bail!("unexpected authority info");
    };
    Ok(info)
}
async fn release(client: &FabricClient, workspace_id: &str, lease: &LeaseToken) {
    if let Err(error) = client
        .control(&ControlRequest::ReleaseLease {
            request_id: id(),
            workspace_id: workspace_id.into(),
            lease: lease.clone(),
        })
        .await
    {
        eprintln!("Lease release unconfirmed; it will expire: {error}");
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicationJournal {
    target: ManagedTarget,
    request: PublishRequest,
    stages: Vec<JournalStage>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalStage {
    path: String,
    source: PathBuf,
    sha256: String,
    size: u64,
}
impl JournalStage {
    fn publication(&self) -> Publication {
        Publication {
            path: self.path.clone(),
            source: self.source.clone(),
            sha256: self.sha256.clone(),
            size: self.size,
        }
    }
}
async fn accept_receipt(
    client: &FabricClient,
    local: &mut LocalWorkspace,
    receipt: &PublicationReceipt,
    files: &[Publication],
) -> Result<()> {
    let mut catalog = exact(
        client,
        &receipt.workspace_id,
        receipt.committed_head.revision.clone(),
    )
    .await?;
    catalog.head = Some(receipt.committed_head.clone());
    local.accept_managed_publication(&catalog, files)
}
async fn publish(
    client: &FabricClient,
    workspace_id: &str,
    root: &Path,
    selectors: &[String],
) -> Result<Value> {
    let target = target(client, workspace_id);
    let mut local = LocalWorkspace::open_managed(root, &target)?;
    local.observe_managed(&current(client, workspace_id).await?)?;
    let base = local.managed_head()?;
    let files = local.prepare_publish(selectors)?;
    let lease = lease(
        client,
        workspace_id,
        files
            .iter()
            .map(|f| PathScope::Exact {
                path: f.path.clone(),
            })
            .collect(),
        120,
    )
    .await?;
    let (stop, mut receiver) = tokio::sync::watch::channel(false);
    let healthy = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let alive = healthy.clone();
    let renew_client = client.clone();
    let renew_workspace = workspace_id.to_owned();
    let token = lease.token.clone();
    let renew = tokio::spawn(async move {
        loop {
            tokio::select! {
                _=receiver.changed()=>break,
                _=tokio::time::sleep(std::time::Duration::from_secs(30))=>{
                    if renew_client.control(&ControlRequest::RenewLease{request_id:id(),workspace_id:renew_workspace.clone(),lease:token.clone(),ttl_seconds:120}).await.is_err(){alive.store(false,std::sync::atomic::Ordering::SeqCst);break;}
                }
            }
        }
    });
    let result: Result<Value> = async {
        let mut changes = Vec::new();
        let snapshot = local.snapshot()?;
        for file in &files {
            ensure!(
                healthy.load(std::sync::atomic::Ordering::SeqCst),
                "lease renewal failed; staged local edits retained"
            );
            let prepared = client
                .upload(
                    &UploadRequest {
                        request_id: id(),
                        workspace_id: workspace_id.into(),
                        path: file.path.clone(),
                        sha256: file.sha256.clone(),
                        size: file.size,
                        lease: lease.token.clone(),
                        attempt: None,
                    },
                    &file.source,
                )
                .await?;
            changes.push(PublicationChange::Put {
                path: file.path.clone(),
                upload_id: prepared.upload_id,
                expected: snapshot.manifest.files.get(&file.path).cloned(),
            });
        }
        let request = PublishRequest {
            context: PublicationContext {
                request_id: id(),
                workspace_id: workspace_id.into(),
                base,
                lease: lease.token.clone(),
                attempt: None,
            },
            changes,
        };
        let operations = root.join(".maxio-workspace/managed-operations");
        maxio::files::directory(&operations)?;
        let operation = operations.join(format!("{}.json", request.context.request_id));
        write(
            &operation,
            &PublicationJournal {
                target,
                request: request.clone(),
                stages: files
                    .iter()
                    .map(|f| JournalStage {
                        path: f.path.clone(),
                        source: f.source.clone(),
                        sha256: f.sha256.clone(),
                        size: f.size,
                    })
                    .collect(),
            },
        )?;
        eprintln!("Publication recovery request: {}", operation.display());
        ensure!(
            healthy.load(std::sync::atomic::Ordering::SeqCst),
            "lease renewal failed; publication not attempted"
        );
        let ControlResponse::Publication { receipt } = client
            .control(&ControlRequest::Publish {
                publication: request,
            })
            .await?
        else {
            anyhow::bail!("unexpected publication response");
        };
        write(&operation.with_extension("receipt.json"), &receipt)?;
        accept_receipt(client, &mut local, &receipt, &files).await?;
        Ok(json!({"receipt":receipt,"operation":operation}))
    }
    .await;
    let _ = stop.send(true);
    let _ = renew.await;
    release(client, workspace_id, &lease.token).await;
    result
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::INFO)
        .try_init();
    let cli = Cli::parse();
    let text = matches!(
        &cli.command,
        Command::Task {
            command: TaskCommand::Logs { text: true, .. }
        }
    );
    let result = execute(cli).await.and_then(|value| {
        std::io::stdout()
            .lock()
            .write_all(&render_output(value, text)?)
            .context("write command output")
    });
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{}", json!({"error":format!("{error:#}")}));
            std::process::ExitCode::FAILURE
        }
    }
}

fn render_output(value: Value, text: bool) -> Result<Vec<u8>> {
    if text {
        let response: ControlResponse = serde_json::from_value(
            value
                .get("result")
                .context("log response has no result")?
                .clone(),
        )?;
        let ControlResponse::Log { page } = response else {
            anyhow::bail!("expected a log page for --text output");
        };
        // Print exact decoded bytes: no lossy Unicode conversion, extra newline,
        // or interpretation of escape sequences. JSON remains the binary-safe
        // metadata/pagination view; --offset addresses the next 64 KiB page.
        return STANDARD
            .decode(page.data_base64)
            .context("invalid log encoding");
    }
    let mut bytes = serde_json::to_vec_pretty(&value)?;
    bytes.push(b'\n');
    Ok(bytes)
}
async fn execute(cli: Cli) -> Result<Value> {
    match &cli.command {
        Command::Keygen {
            key,
            public_key_out,
        } => {
            let key = absolute(key)?;
            let public = DeviceKey::generate(&key)?.public_key()?;
            if let Some(path) = public_key_out {
                write(path, &json!({"public_key":public}))?;
            }
            return Ok(json!({"key_path":key,"public_key":public}));
        }
        Command::Init {
            root,
            owner_key,
            name,
            endpoint,
            ca_cert,
            client_config,
        } => {
            ensure!(
                !client_config.try_exists()?,
                "client configuration already exists"
            );
            let owner_key = absolute(owner_key)?;
            let device_id = id();
            let authority = Authority::initialize(
                &absolute(root)?,
                BootstrapOwner {
                    device_id: device_id.clone(),
                    display_name: name.clone(),
                    public_key: DeviceKey::load(&owner_key)?.public_key()?,
                },
            )?;
            let info = authority.info();
            let config = ClientConfig {
                endpoint: endpoint.trim_end_matches('/').into(),
                authority_id: info.authority_id.clone(),
                vault_id: info.vault_id.clone(),
                device_id: device_id.clone(),
                key_path: owner_key,
                ca_cert: ca_cert.as_ref().map(|p| absolute(p)).transpose()?,
            };
            write(client_config, &config)?;
            return Ok(
                json!({"authority":info,"owner_device_id":device_id,"client_config":absolute(client_config)?}),
            );
        }
        Command::Serve {
            root,
            bind,
            tls_cert,
            tls_key,
        } => {
            let root = absolute(root)?;
            let tls = maxio::server::ServerTls::standalone(
                tls_cert.to_str().context("TLS path is not UTF-8")?,
                tls_key.to_str().context("TLS path is not UTF-8")?,
            )
            .map_err(anyhow::Error::msg)?;
            let authority = Arc::new(Authority::open(&root)?);
            let info = authority.info();
            let listener = tokio::net::TcpListener::bind(bind).await?;
            eprintln!(
                "{}",
                json!({"listening":listener.local_addr()?.to_string(),"authority":info})
            );
            let (stop, receiver) = tokio::sync::watch::channel(false);
            tokio::spawn(async move {
                #[cfg(unix)]
                {
                    if let Ok(mut terminate) =
                        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    {
                        tokio::select! {_=tokio::signal::ctrl_c()=>{},_=terminate.recv()=>{}}
                    } else {
                        let _ = tokio::signal::ctrl_c().await;
                    }
                }
                #[cfg(not(unix))]
                {
                    let _ = tokio::signal::ctrl_c().await;
                }
                let _ = stop.send(true);
            });
            transport::serve(
                authority,
                listener,
                tls,
                root.join("transport-spool"),
                receiver,
            )
            .await?;
            return Ok(json!({"stopped":true}));
        }
        Command::Workspace {
            command: WorkspaceCommand::Status { root, verify },
        } => {
            let local = LocalWorkspace::open_offline(&absolute(root)?)?;
            return Ok(json!({"files":local.describe(*verify)?}));
        }
        Command::Workspace {
            command: WorkspaceCommand::Pin { root, path, unpin },
        } => {
            let mut local = LocalWorkspace::open_offline(&absolute(root)?)?;
            local.pin(path, !unpin)?;
            return Ok(json!({"pinned":!unpin,"paths":path}));
        }
        Command::Cache {
            command: CacheCommand::Inspect { root, verify },
        } => {
            let cache = PrivateCache::open_offline(&absolute(root)?)?;
            return Ok(serde_json::to_value(cache.inventory(*verify)?)?);
        }
        Command::Cache {
            command:
                CacheCommand::Pin {
                    root,
                    references,
                    unpin,
                },
        } => {
            let mut cache = PrivateCache::open_offline(&absolute(root)?)?;
            let files: Vec<RetainedFile> = read(references)?;
            cache.pin(&files, !unpin)?;
            return Ok(json!({"pinned":!unpin,"files":files}));
        }
        Command::Cache {
            command:
                CacheCommand::Copy {
                    root,
                    references,
                    destination,
                },
        } => {
            let cache = PrivateCache::open_offline(&absolute(root)?)?;
            let files: Vec<RetainedFile> = read(references)?;
            return Ok(serde_json::to_value(
                cache.copy_to(&files, &absolute(destination)?)?,
            )?);
        }
        _ => {}
    }
    let config: ClientConfig = read(
        cli.config
            .as_deref()
            .context("this operation requires --config PATH")?,
    )?;
    let client = FabricClient::connect(config).await?;
    let value = online(&client, cli.command).await?;
    Ok(json!({"result":value,"transfers":client.stats()}))
}
async fn online(client: &FabricClient, command: Command) -> Result<Value> {
    match command {
        Command::Info => Ok(serde_json::to_value(
            client.control(&ControlRequest::Info).await?,
        )?),
        Command::Workers => Ok(serde_json::to_value(
            client.control(&ControlRequest::ListWorkers).await?,
        )?),
        Command::Rpc { request } => Ok(serde_json::to_value(
            client.control(&read(&request)?).await?,
        )?),
        Command::Device { command } => device(client, command).await,
        Command::Workspace { command } => workspace_command(client, command).await,
        Command::Cache { command } => cache_command(client, command).await,
        Command::Lease { command } => lease_command(client, command).await,
        Command::Task { command } => task_command(client, command).await,
        _ => anyhow::bail!("offline command was not handled"),
    }
}
fn public_key(path: &Path) -> Result<String> {
    let value: Value = read(path)?;
    Ok(value
        .get("public_key")
        .and_then(Value::as_str)
        .context("expected keygen public-key JSON")?
        .into())
}
async fn device(client: &FabricClient, command: DeviceCommand) -> Result<Value> {
    let request = match command {
        DeviceCommand::List => ControlRequest::ListDevices,
        DeviceCommand::Enroll {
            name,
            public_key: key,
            role,
            write_config,
            key_path,
            ca_cert,
        } => {
            if let Some(path) = &write_config {
                ensure!(!path.try_exists()?, "output configuration already exists");
            }
            let response = client
                .control(&ControlRequest::EnrollDevice {
                    request_id: id(),
                    display_name: name,
                    public_key: public_key(&key)?,
                    role: role.into(),
                })
                .await?;
            if let Some(path) = write_config {
                let ControlResponse::Device { device } = &response else {
                    anyhow::bail!("unexpected enrollment response");
                };
                let config = ClientConfig {
                    device_id: device.device_id.clone(),
                    key_path: absolute(&key_path.context("key path required")?)?,
                    ca_cert: ca_cert
                        .map(|p| absolute(&p))
                        .transpose()?
                        .or_else(|| client.config().ca_cert.clone()),
                    ..client.config().clone()
                };
                write(&path, &config)?;
            }
            return Ok(serde_json::to_value(response)?);
        }
        DeviceCommand::Grant {
            device,
            workspace: name,
            catalog,
            read,
            write,
            submit_jobs,
        } => ControlRequest::SetGrant {
            request_id: id(),
            grant: WorkspaceGrant {
                device_id: device,
                workspace_id: workspace(client, &name).await?,
                catalog_read: catalog,
                read: scopes(&read)?,
                write: scopes(&write)?,
                submit_jobs,
            },
        },
        DeviceCommand::Revoke { device, confirm } => {
            ensure!(
                confirm,
                "device removal requires --confirm; previously delivered bytes cannot be recalled"
            );
            ControlRequest::RevokeDevice {
                request_id: id(),
                device_id: device,
            }
        }
        DeviceCommand::Rotate {
            device,
            public_key: key,
            expected_generation,
            confirm,
        } => {
            ensure!(confirm, "key rotation requires --confirm");
            ControlRequest::RotateDeviceKey {
                request_id: id(),
                device_id: device,
                expected_generation,
                public_key: public_key(&key)?,
            }
        }
    };
    Ok(serde_json::to_value(client.control(&request).await?)?)
}
async fn workspace_command(client: &FabricClient, command: WorkspaceCommand) -> Result<Value> {
    match command {
        WorkspaceCommand::Create { name } => Ok(serde_json::to_value(
            client
                .control(&ControlRequest::CreateWorkspace {
                    request_id: id(),
                    name,
                    import_source: None,
                })
                .await?,
        )?),
        WorkspaceCommand::List => Ok(serde_json::to_value(
            client.control(&ControlRequest::ListWorkspaces).await?,
        )?),
        WorkspaceCommand::Inspect {
            workspace: name,
            revision,
            sha256,
        } => {
            let w = workspace(client, &name).await?;
            let catalog = if let Some(revision) = revision {
                exact(
                    client,
                    &w,
                    RevisionRef {
                        revision,
                        sha256: sha256.context("revision hash required")?,
                    },
                )
                .await?
            } else {
                current(client, &w).await?
            };
            Ok(serde_json::to_value(catalog)?)
        }
        WorkspaceCommand::Pull {
            workspace: name,
            root,
            path,
            revision,
            sha256,
        } => {
            let w = workspace(client, &name).await?;
            let target = target(client, &w);
            let mut local = LocalWorkspace::open_managed(&absolute(&root)?, &target)?;
            let catalog = current(client, &w).await?;
            local.observe_managed(&catalog)?;
            let catalog = if let Some(revision) = revision {
                exact(
                    client,
                    &w,
                    RevisionRef {
                        revision,
                        sha256: sha256.context("revision hash required")?,
                    },
                )
                .await?
            } else {
                catalog
            };
            let paths = if path.is_empty() {
                vec![]
            } else {
                local
                    .pull(
                        &ManagedReader::new(client.clone(), target)?,
                        &catalog.snapshot,
                        &path,
                    )
                    .await?
            };
            Ok(json!({"catalog":catalog,"hydrated":paths,"files":local.describe(false)?}))
        }
        WorkspaceCommand::Publish {
            workspace: name,
            root,
            path,
        } => {
            publish(
                client,
                &workspace(client, &name).await?,
                &absolute(&root)?,
                &path,
            )
            .await
        }
        WorkspaceCommand::RecoverPublication { root, operation } => {
            let journal: PublicationJournal = read(&operation)?;
            let mut local = LocalWorkspace::open_managed(&absolute(&root)?, &journal.target)?;
            let response = client
                .control(&ControlRequest::Publish {
                    publication: journal.request,
                })
                .await?;
            let ControlResponse::Publication { receipt } = &response else {
                anyhow::bail!("unexpected publication response");
            };
            accept_receipt(
                client,
                &mut local,
                receipt,
                &journal
                    .stages
                    .iter()
                    .map(JournalStage::publication)
                    .collect::<Vec<_>>(),
            )
            .await?;
            Ok(serde_json::to_value(response)?)
        }
        WorkspaceCommand::References {
            workspace: name,
            path,
            output,
        } => {
            let w = workspace(client, &name).await?;
            let catalog = current(client, &w).await?;
            let files = selected(&catalog.snapshot.manifest, &path)?;
            if let Some(path) = output {
                write(&path, &files)?;
            }
            Ok(serde_json::to_value(files)?)
        }
        WorkspaceCommand::Delete {
            workspace: name,
            path,
            confirm,
        } => {
            ensure!(confirm, "global logical deletion requires --confirm");
            let w = workspace(client, &name).await?;
            let catalog = current(client, &w).await?;
            let expected = catalog
                .snapshot
                .manifest
                .files
                .get(&path)
                .context("path is not currently published")?
                .clone();
            mutate_one(
                client,
                &w,
                catalog,
                path.clone(),
                PublicationChange::Delete { path, expected },
            )
            .await
        }
        WorkspaceCommand::Restore {
            workspace: name,
            path,
            revision,
            sha256,
            source_path,
            confirm,
        } => {
            ensure!(confirm, "global restoration requires --confirm");
            let w = workspace(client, &name).await?;
            let catalog = current(client, &w).await?;
            let expected = catalog.snapshot.manifest.files.get(&path).cloned();
            mutate_one(
                client,
                &w,
                catalog,
                path.clone(),
                PublicationChange::Restore {
                    source_path: source_path.unwrap_or_else(|| path.clone()),
                    path,
                    from_revision: RevisionRef { revision, sha256 },
                    expected,
                },
            )
            .await
        }
        _ => anyhow::bail!("offline workspace command was not handled"),
    }
}
async fn mutate_one(
    client: &FabricClient,
    workspace_id: &str,
    catalog: ManagedCatalog,
    path: String,
    change: PublicationChange,
) -> Result<Value> {
    let lease = lease(client, workspace_id, vec![PathScope::Exact { path }], 60).await?;
    let request = PublishRequest {
        context: PublicationContext {
            request_id: id(),
            workspace_id: workspace_id.into(),
            base: catalog.head.context("missing current head")?,
            lease: lease.token.clone(),
            attempt: None,
        },
        changes: vec![change],
    };
    eprintln!("Publication request ID: {}", request.context.request_id);
    let result = client
        .control(&ControlRequest::Publish {
            publication: request,
        })
        .await;
    release(client, workspace_id, &lease.token).await;
    Ok(serde_json::to_value(result?)?)
}
async fn cache_command(client: &FabricClient, command: CacheCommand) -> Result<Value> {
    match command {
        CacheCommand::Hydrate { root, references } => {
            let files: Vec<RetainedFile> = read(&references)?;
            let mut cache = PrivateCache::open(
                &absolute(&root)?,
                &authority_info(client).await?,
                &client.config().device_id,
            )?;
            Ok(serde_json::to_value(
                cache.hydrate(client, &files, None).await?,
            )?)
        }
        CacheCommand::Import {
            root,
            references,
            source,
        } => {
            let files: Vec<RetainedFile> = read(&references)?;
            ensure!(
                files.len() == 1,
                "local import requires exactly one version reference"
            );
            let mut cache = PrivateCache::open(
                &absolute(&root)?,
                &authority_info(client).await?,
                &client.config().device_id,
            )?;
            cache.import(&files[0], &absolute(&source)?)?;
            Ok(json!({"imported":files[0]}))
        }
        CacheCommand::Evict {
            root,
            references,
            confirm,
        } => {
            ensure!(confirm, "private cache eviction requires --confirm");
            let files: Vec<RetainedFile> = read(&references)?;
            let mut cache = PrivateCache::open(
                &absolute(&root)?,
                &authority_info(client).await?,
                &client.config().device_id,
            )?;
            Ok(serde_json::to_value(cache.evict(client, &files).await?)?)
        }
        _ => anyhow::bail!("offline cache command was not handled"),
    }
}
async fn lease_command(client: &FabricClient, command: LeaseCommand) -> Result<Value> {
    let request = match command {
        LeaseCommand::List { workspace: name } => ControlRequest::ListLeases {
            workspace_id: workspace(client, &name).await?,
        },
        LeaseCommand::Acquire {
            workspace: name,
            scope,
            ttl,
            save,
        } => {
            let lease = lease(
                client,
                &workspace(client, &name).await?,
                scopes(&scope)?,
                ttl,
            )
            .await?;
            if let Some(path) = save {
                write(&path, &lease.token)?;
            }
            return Ok(serde_json::to_value(lease)?);
        }
        LeaseCommand::Renew {
            workspace: name,
            lease,
            ttl,
        } => ControlRequest::RenewLease {
            request_id: id(),
            workspace_id: workspace(client, &name).await?,
            lease: read(&lease)?,
            ttl_seconds: ttl,
        },
        LeaseCommand::Release {
            workspace: name,
            lease,
        } => ControlRequest::ReleaseLease {
            request_id: id(),
            workspace_id: workspace(client, &name).await?,
            lease: read(&lease)?,
        },
    };
    Ok(serde_json::to_value(client.control(&request).await?)?)
}
async fn task_command(client: &FabricClient, command: TaskCommand) -> Result<Value> {
    let request = match command {
        TaskCommand::Submit {
            workspace: name,
            profile,
            input,
            output,
            worker,
            timeout,
            cpu_millis,
            memory_bytes,
            prompt_file,
            publish,
        } => {
            let w = workspace(client, &name).await?;
            let catalog = current(client, &w).await?;
            let inputs = selected(&catalog.snapshot.manifest, &input)?
                .into_iter()
                .map(|f| JobInput {
                    path: f.path,
                    revision: f.revision,
                    version: f.version,
                })
                .collect();
            let prompt = if let Some(path) = prompt_file {
                ensure!(
                    std::fs::metadata(&path)?.len() <= 1024 * 1024,
                    "prompt exceeds 1 MiB"
                );
                Some(std::fs::read_to_string(path)?)
            } else {
                None
            };
            ControlRequest::SubmitJob {
                job: JobRequest {
                    request_id: id(),
                    workspace_id: w,
                    base: catalog.head.context("current head missing")?,
                    profile,
                    inputs,
                    output_selectors: scopes(&output)?,
                    resources: Resources {
                        cpu_millis,
                        memory_bytes,
                    },
                    timeout_seconds: timeout,
                    required_worker: worker,
                    output_policy: if publish {
                        OutputPolicy::Publish
                    } else {
                        OutputPolicy::Retain
                    },
                    prompt,
                },
            }
        }
        TaskCommand::Status { job } => ControlRequest::JobStatus { job_id: job },
        TaskCommand::List { workspace: name } => ControlRequest::ListJobs {
            workspace_id: if let Some(name) = name {
                Some(workspace(client, &name).await?)
            } else {
                None
            },
        },
        TaskCommand::Explain { job } => ControlRequest::ExplainPlacement { job_id: job },
        TaskCommand::Cancel { job } => ControlRequest::CancelJob {
            request_id: id(),
            job_id: job,
        },
        TaskCommand::Retry {
            job,
            previous_attempt,
        } => ControlRequest::RetryJob {
            request_id: id(),
            job_id: job,
            expected_attempt_id: previous_attempt,
        },
        TaskCommand::Logs {
            job,
            attempt,
            stderr,
            offset,
            text: _,
        } => ControlRequest::ReadLog {
            job_id: job,
            attempt_id: attempt,
            stream: if stderr {
                LogStream::Stderr
            } else {
                LogStream::Stdout
            },
            offset,
            max_bytes: 64 * 1024,
        },
    };
    Ok(serde_json::to_value(client.control(&request).await?)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_logs_exposes_readable_output_without_external_decoding() {
        let parsed = Cli::try_parse_from([
            "maxio-fabric",
            "task",
            "logs",
            "job-id",
            "--attempt",
            "attempt-id",
            "--text",
        ]);
        assert!(
            parsed.is_ok(),
            "documented human log inspection must be directly available"
        );
    }

    #[test]
    fn readable_logs_preserve_exact_bytes_and_default_json_keeps_pagination() {
        let bytes = "worker output: Grüße\n".as_bytes();
        let value = json!({"result":ControlResponse::Log { page: LogPage {
            offset: 4, next_offset: 4 + bytes.len() as u64,
            data_base64: STANDARD.encode(bytes), truncated: false, eof: true,
        } }, "transfers":{"metadata_downloaded":123}});
        assert_eq!(render_output(value.clone(), true).unwrap(), bytes);
        let encoded = render_output(value.clone(), false).unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&encoded).unwrap(), value);
        assert!(
            render_output(
                json!({"result":ControlResponse::Log {page:LogPage{
                    offset:0,next_offset:1,data_base64:"invalid!".into(),truncated:false,eof:true,
                }}}),
                true
            )
            .is_err()
        );
    }
}
