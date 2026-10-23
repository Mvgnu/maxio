use anyhow::{Result, ensure};
use clap::Parser;
use maxio::sync::{SyncOptions, Synchronizer};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "maxio-sync",
    about = "Synchronize a local folder with an explicitly chosen S3 peer",
    long_about = "Additive folder synchronization with a directly reachable S3 peer. No cloud account, discovery service, or relay is used. The bucket must already exist. The peer must enforce conditional PUT requests. Conflicting local edits become .maxio-conflict-* siblings. Deletions are NOT propagated: surviving copies are restored. Stop all sync clients before intentionally removing a file from every copy. Local replacement history is retained under .maxio-sync/ and is never automatically pruned. Whole-file polling; no delta transfer, filesystem permissions, or symlink synchronization."
)]
struct Args {
    #[arg(long)]
    local: PathBuf,
    #[arg(long)]
    endpoint: String,
    /// PEM CA bundle to trust for this HTTPS peer instead of system roots.
    #[arg(long, env = "MAXIO_SYNC_CA_CERT")]
    ca_cert: Option<PathBuf>,
    #[arg(long)]
    bucket: String,
    #[arg(long, default_value = "")]
    prefix: String,
    #[arg(long, env = "MAXIO_ACCESS_KEY", hide_env_values = true)]
    access_key: String,
    #[arg(long, env = "MAXIO_SECRET_KEY", hide_env_values = true)]
    secret_key: String,
    #[arg(long, env = "MAXIO_REGION", default_value = "us-east-1")]
    region: String,
    /// Run one complete reconciliation and exit; errors return a nonzero status.
    #[arg(long)]
    once: bool,
    #[arg(long, default_value_t = 15)]
    interval_seconds: u64,
    /// Maximum size per file. Files are transferred whole and buffered in memory.
    #[arg(long, default_value_t = 64)]
    max_file_mib: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    ensure!(
        args.interval_seconds > 0,
        "--interval-seconds must be positive"
    );
    let max_file_bytes = args
        .max_file_mib
        .checked_mul(1024 * 1024)
        .filter(|size| *size > 0)
        .ok_or_else(|| anyhow::anyhow!("invalid --max-file-mib"))?;
    if args.endpoint.starts_with("http://") {
        eprintln!("HTTP peer: use a trusted LAN/VPN; use HTTPS for encrypted transport.");
    }
    eprintln!(
        "Additive sync: no deletion propagation. Conflicts are preserved; local replacement history is retained in .maxio-sync/."
    );
    let mut sync = Synchronizer::open(SyncOptions {
        local: args.local,
        endpoint: args.endpoint,
        ca_cert: args.ca_cert,
        bucket: args.bucket,
        prefix: args.prefix,
        access_key: args.access_key,
        secret_key: args.secret_key,
        region: args.region,
        max_file_bytes,
    })?;
    loop {
        let result = tokio::select! {
            result = sync.run_once() => result,
            signal = tokio::signal::ctrl_c() => { signal?; return Ok(()); }
        };
        match result {
            Ok(report) => println!("{}", serde_json::to_string(&report)?),
            Err(error) if args.once => return Err(error),
            Err(error) => eprintln!(
                "Sync incomplete; retrying in {}s: {error:#}",
                args.interval_seconds
            ),
        }
        if args.once {
            return Ok(());
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(args.interval_seconds)) => {}
            signal = tokio::signal::ctrl_c() => { signal?; return Ok(()); }
        }
    }
}
