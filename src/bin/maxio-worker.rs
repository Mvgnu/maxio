use anyhow::{Context, Result, ensure};
use clap::Parser;
use maxio::fabric::client::{ClientConfig, FabricClient};
use maxio::fabric::contract::Resources;
use maxio::fabric::worker::{ExecutionProfile, WorkerOptions, serve};
use serde::de::DeserializeOwned;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "maxio-worker",
    version,
    about = "Execute admitted managed jobs using owner-configured local profiles",
    long_about = "Optional single-slot worker with a private immutable input cache and retained attempt directories. The coordinator chooses placement and authorizes publication. Profiles contain local executable paths and explicit environment values; tasks cannot select them over the wire. Native commands retain the owner's OS permissions. No automatic retry, provider login or cleanup is performed."
)]
struct Args {
    /// JSON ClientConfig with HTTPS endpoint, authority/vault/device IDs and key path.
    #[arg(long)]
    config: PathBuf,
    /// Dedicated private cache/attempt root, initially empty or previously bound.
    #[arg(long)]
    root: PathBuf,
    /// JSON array of local profiles: name, adapter, executable, args, permission, environment.
    #[arg(long)]
    profiles: PathBuf,
    #[arg(long, default_value = "MaxIO worker")]
    display_name: String,
    /// Advertised capacity; it is an admission hint, not an OS resource quota.
    #[arg(long, default_value_t = 1000)]
    cpu_millis: u32,
    #[arg(long, default_value_t = 1024 * 1024 * 1024)]
    memory_bytes: u64,
    #[arg(long, default_value_t = 1000)]
    poll_ms: u64,
    #[arg(long, default_value_t = 5000)]
    renew_ms: u64,
    #[arg(long, default_value_t = 60)]
    lease_seconds: u64,
    /// Keep polling until one attempt completes, then exit; never retry a job.
    #[arg(long)]
    once: bool,
}

fn read_config<T: DeserializeOwned>(path: &Path) -> Result<T> {
    const MAX: u64 = 1024 * 1024;
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= MAX,
        "configuration must be a regular file no larger than 1 MiB"
    );
    let mut bytes = Vec::new();
    File::open(path)?.take(MAX + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= MAX, "configuration grew beyond 1 MiB");
    // Serde's type/line error is sufficient. Never print the configuration bytes.
    serde_json::from_slice(&bytes).context("invalid local worker configuration")
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let config: ClientConfig = read_config(&args.config)?;
    let profiles: Vec<ExecutionProfile> = read_config(&args.profiles)?;
    let worker_id = config.device_id.clone();
    let root = if args.root.is_absolute() {
        args.root
    } else {
        std::env::current_dir()?.join(args.root)
    };
    let client = FabricClient::connect(config).await?;
    serve(
        client,
        WorkerOptions {
            root,
            worker_id,
            display_name: args.display_name,
            profiles,
            resources: Resources {
                cpu_millis: args.cpu_millis,
                memory_bytes: args.memory_bytes,
            },
            poll_interval: Duration::from_millis(args.poll_ms),
            renewal_interval: Duration::from_millis(args.renew_ms),
            lease_seconds: args.lease_seconds,
            once: args.once,
        },
    )
    .await
}
