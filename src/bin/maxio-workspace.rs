//! Optional selective workspace client. No server startup or cluster dependency.
use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use maxio::workspace::{LocalWorkspace, RemoteConfig, TransferStats, WorkspaceRemote};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "maxio-workspace",
    version,
    about = "Discover, pull and publish selected versioned files through S3"
)]
struct Cli {
    /// Existing ordinary working directory. Its cache state stays on this device.
    #[arg(long)]
    root: PathBuf,
    /// Explicit S3 origin, required for network commands.
    #[arg(long, global = true, env = "MAXIO_WORKSPACE_ENDPOINT")]
    endpoint: Option<String>,
    #[arg(long, global = true, env = "MAXIO_WORKSPACE_BUCKET")]
    bucket: Option<String>,
    /// Logical workspace name within the bucket (not a device or full folder sync).
    #[arg(long, global = true, default_value = "projects")]
    workspace: String,
    #[arg(long, global = true, default_value = "us-east-1")]
    region: String,
    /// Trust only this PEM CA bundle, preserving hostname verification.
    #[arg(long, global = true, env = "MAXIO_WORKSPACE_CA_CERT")]
    ca_cert: Option<PathBuf>,
    /// Permit plaintext HTTP on an explicitly trusted local/encrypted network.
    #[arg(long, global = true)]
    allow_http: bool,
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Create a new empty published workspace. Refuses an existing one.
    Init,
    /// Fetch only current catalog metadata; never downloads file contents.
    Refresh,
    /// List the last observed catalog without contacting storage or hashing files.
    List,
    /// Verify local file hashes against their baselines and the observed catalog.
    Status,
    /// Hydrate exact files/directories. Dirty or conflicting local files are retained.
    Pull {
        #[arg(required = true, num_args = 1..)]
        paths: Vec<String>,
        /// Read this exact published historical revision; does not rewind the head.
        #[arg(long)]
        revision: Option<String>,
    },
    /// Publish selected local edits against the last observed head. No implicit refresh.
    Publish {
        #[arg(required = true, num_args = 1..)]
        paths: Vec<String>,
    },
    /// Pin currently hydrated and verified files in the observed snapshot.
    Pin {
        #[arg(required = true, num_args = 1..)]
        paths: Vec<String>,
    },
    /// Remove pins explicitly, without deleting local or published files.
    Unpin {
        #[arg(required = true, num_args = 1..)]
        paths: Vec<String>,
    },
    /// Currently refused: backend retention/durability enforcement is not implemented.
    Evict {
        #[arg(required = true, num_args = 1..)]
        paths: Vec<String>,
    },
}

impl Cli {
    fn connect(&self) -> Result<WorkspaceRemote> {
        WorkspaceRemote::connect(RemoteConfig {
            endpoint: self
                .endpoint
                .clone()
                .context("--endpoint is required for this network command")?,
            bucket: self
                .bucket
                .clone()
                .context("--bucket is required for this network command")?,
            name: self.workspace.clone(),
            region: self.region.clone(),
            access_key: std::env::var("MAXIO_ACCESS_KEY")
                .context("set MAXIO_ACCESS_KEY for this storage target")?,
            secret_key: std::env::var("MAXIO_SECRET_KEY")
                .context("set MAXIO_SECRET_KEY for this storage target")?,
            session_token: std::env::var("MAXIO_SESSION_TOKEN").ok(),
            ca_cert: self.ca_cert.clone(),
            allow_http: self.allow_http,
        })
    }
}

async fn execute(cli: &Cli, remote: Option<&WorkspaceRemote>) -> Result<Value> {
    if let Action::Evict { paths } = &cli.command {
        bail!(
            "eviction is unavailable: no enforced backend retention/durability contract; local files were left untouched ({paths:?})"
        );
    }
    let mut local = match remote {
        Some(remote) => LocalWorkspace::open(&cli.root, &remote.target_id())?,
        None => LocalWorkspace::open_offline(&cli.root)?,
    };
    let result = match &cli.command {
        Action::Init => {
            let snapshot = remote
                .context("storage connection missing")?
                .initialize()
                .await?;
            local.observe(snapshot)?;
            json!({"command":"init"})
        }
        Action::Refresh => {
            let snapshot = remote
                .context("storage connection missing")?
                .latest()
                .await?;
            local.observe(snapshot)?;
            json!({"command":"refresh","files":local.describe(false)?})
        }
        Action::List => {
            json!({"command":"list","files":local.describe(false)?,"source":"cached_catalog"})
        }
        Action::Status => {
            json!({"command":"status","files":local.describe(true)?,"source":"cached_catalog_and_local_hashes"})
        }
        Action::Pull { paths, revision } => {
            let remote = remote.context("storage connection missing")?;
            let latest = remote.latest().await?;
            local.observe(latest.clone())?;
            let snapshot = if let Some(revision) = revision {
                remote.revision(revision).await?
            } else {
                latest
            };
            let paths = local.pull(remote, &snapshot, paths).await?;
            json!({"command":"pull","paths":paths,"hydrated_revision":snapshot.manifest.revision})
        }
        Action::Publish { paths } => {
            let base = local.snapshot()?;
            let files = local.prepare_publish(paths)?;
            let snapshot = remote
                .context("storage connection missing")?
                .publish(&base, &files)
                .await?;
            local.accept_publication(snapshot, &files)?;
            json!({"command":"publish","paths":files.iter().map(|file| &file.path).collect::<Vec<_>>()})
        }
        Action::Pin { paths } => json!({"command":"pin","paths":local.pin(paths, true)?}),
        Action::Unpin { paths } => json!({"command":"unpin","paths":local.pin(paths, false)?}),
        Action::Evict { .. } => bail!("eviction unavailable"),
    };
    let snapshot = local.snapshot()?;
    let mut result = result;
    result["workspace_id"] = json!(snapshot.manifest.workspace_id);
    result["revision"] = json!(snapshot.manifest.revision);
    result["ok"] = json!(true);
    Ok(result)
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let online = matches!(
        cli.command,
        Action::Init | Action::Refresh | Action::Pull { .. } | Action::Publish { .. }
    );
    let remote = if online {
        match cli.connect() {
            Ok(remote) => Some(remote),
            Err(error) => {
                eprintln!(
                    "{}",
                    json!({"ok":false,"error":format!("{error:#}"),"transfer":TransferStats::default()})
                );
                return ExitCode::FAILURE;
            }
        }
    } else {
        None
    };
    let result = execute(&cli, remote.as_ref()).await;
    let stats = remote
        .as_ref()
        .map(WorkspaceRemote::stats)
        .unwrap_or_default();
    match result {
        Ok(mut result) => {
            result["transfer"] = json!(stats);
            println!("{result}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!(
                "{}",
                json!({"ok":false,"error":format!("{error:#}"),"transfer":stats})
            );
            ExitCode::FAILURE
        }
    }
}
