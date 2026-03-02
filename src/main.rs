use clap::Parser;
use maxio::{config::Config, server, storage};
use std::net::SocketAddr;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

const LIFECYCLE_SWEEP_INTERVAL_SECS: u64 = 300;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = Config::parse();

    let state = server::AppState::from_config(config.clone()).await?;
    let topology = server::runtime_topology_snapshot(&state);
    let node_id = topology.node_id.clone();
    let cluster_peer_count = topology.cluster_peer_count();
    let membership_node_count = topology.membership_node_count();
    let distributed_mode = topology.is_distributed();
    let placement_epoch = topology.placement_epoch;

    spawn_lifecycle_worker(state.clone());

    let app = server::build_router(state);

    let addr = format!("{}:{}", config.address, config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    if config.access_key == "minioadmin" && config.secret_key == "minioadmin" {
        tracing::warn!(
            "WARNING: Using default credentials. Set MAXIO_ACCESS_KEY/MAXIO_SECRET_KEY (or MINIO_ROOT_USER/MINIO_ROOT_PASSWORD) for production use."
        );
    }

    tracing::info!("MaxIO v{} listening on {}", env!("MAXIO_VERSION"), addr);
    tracing::info!("Access Key: {}", config.access_key);
    tracing::info!("Secret Key: [REDACTED]");
    tracing::info!(
        "Configured credentials: {}",
        1 + config.additional_credentials.len()
    );
    tracing::info!("Node ID:    {}", node_id);
    tracing::info!(
        "Mode:       {} ({} peer{})",
        if distributed_mode {
            "distributed"
        } else {
            "standalone"
        },
        cluster_peer_count,
        if cluster_peer_count == 1 { "" } else { "s" }
    );
    tracing::info!("Members:    {} (self + peers)", membership_node_count);
    tracing::info!("Membership: {}", config.membership_protocol.as_str());
    let (_membership_protocol_ready, membership_protocol_warning) =
        server::membership_protocol_readiness(config.membership_protocol);
    if let Some(warning) = membership_protocol_warning {
        tracing::warn!("{}", warning);
    }
    tracing::info!("Placement:  epoch={}", placement_epoch);
    tracing::info!("Data dir:   {}", config.data_dir);
    tracing::info!("Region:     {}", config.region);
    if config.erasure_coding {
        tracing::info!(
            "Erasure coding: enabled (chunk size: {}MB)",
            config.chunk_size / (1024 * 1024)
        );
        if config.parity_shards > 0 {
            tracing::info!(
                "Parity shards: {} (can tolerate {} lost/corrupt chunks per object)",
                config.parity_shards,
                config.parity_shards
            );
        }
    } else if config.parity_shards > 0 {
        tracing::warn!("--parity-shards ignored: requires --erasure-coding to be enabled");
    }
    let display_host = if config.address == "0.0.0.0" {
        "localhost"
    } else {
        &config.address
    };
    tracing::info!("Web UI:     http://{}:{}/ui/", display_host, config.port);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(signal) => Some(signal),
            Err(err) => {
                tracing::warn!("Failed to install SIGTERM handler: {}", err);
                None
            }
        };

        if let Some(sigterm) = sigterm.as_mut() {
            tokio::select! {
                ctrl_c = tokio::signal::ctrl_c() => match ctrl_c {
                    Ok(()) => tracing::info!("Shutdown signal received (SIGINT), draining connections..."),
                    Err(err) => tracing::warn!("Failed to install CTRL+C signal handler: {}", err),
                },
                _ = sigterm.recv() => {
                    tracing::info!("Shutdown signal received (SIGTERM), draining connections...");
                }
            }
            return;
        }
    }

    match tokio::signal::ctrl_c().await {
        Ok(()) => tracing::info!("Shutdown signal received (SIGINT), draining connections..."),
        Err(err) => tracing::warn!("Failed to install CTRL+C signal handler: {}", err),
    }
}

fn spawn_lifecycle_worker(state: server::AppState) {
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(Duration::from_secs(LIFECYCLE_SWEEP_INTERVAL_SECS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            interval.tick().await;
            if let Err(err) = run_lifecycle_sweep(&state).await {
                tracing::warn!("Lifecycle sweep failed: {}", err);
            }
        }
    });
}

async fn run_lifecycle_sweep(state: &server::AppState) -> Result<(), storage::StorageError> {
    let buckets = state.storage.list_buckets().await?;
    let now = chrono::Utc::now();

    for bucket in buckets {
        match state.storage.apply_lifecycle_once(&bucket.name, now).await {
            Ok(deleted) => {
                if !deleted.is_empty() {
                    tracing::info!(
                        "Lifecycle sweep deleted {} object(s) in bucket {}",
                        deleted.len(),
                        bucket.name
                    );
                }
            }
            Err(storage::StorageError::NotFound(_)) => {
                // Bucket removed concurrently.
            }
            Err(err) => {
                tracing::warn!("Lifecycle sweep error for bucket {}: {}", bucket.name, err);
            }
        }
    }

    Ok(())
}
