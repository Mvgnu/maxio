use clap::Parser;
use maxio::{config::Config, server, storage};
use std::future::IntoFuture;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
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
    server::spawn_pending_replication_replay_worker(state.clone());
    server::spawn_pending_rebalance_replay_worker(state.clone());
    server::spawn_pending_membership_propagation_replay_worker(state.clone());
    server::spawn_pending_metadata_repair_replay_worker(state.clone());
    server::spawn_membership_convergence_probe_worker(state.clone());

    let addr = format!("{}:{}", config.address, config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    let internal_bind_addr = config.internal_bind_addr().map(str::to_string);

    let public_app = if internal_bind_addr.is_some() {
        server::build_public_router(state.clone())
    } else {
        server::build_router(state.clone())
    };

    let internal_listener = if let Some(bind_addr) = internal_bind_addr.as_ref() {
        if bind_addr == &addr {
            return Err(anyhow::anyhow!(
                "MAXIO_INTERNAL_BIND_ADDR ('{}') must differ from public listener '{}'",
                bind_addr,
                addr
            ));
        }
        Some(tokio::net::TcpListener::bind(bind_addr).await?)
    } else {
        None
    };
    let internal_app = internal_listener
        .as_ref()
        .map(|_| server::build_internal_router(state.clone()));

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
    if let Some(bind_addr) = internal_bind_addr.as_ref() {
        tracing::info!(
            "Internal:   http://{} (cluster control-plane only)",
            bind_addr
        );
    }

    if let (Some(internal_listener), Some(internal_app)) = (internal_listener, internal_app) {
        let shutdown = Arc::new(Notify::new());

        let public_server = axum::serve(
            listener,
            public_app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(wait_for_shutdown(shutdown.clone()))
        .into_future();

        let internal_server = axum::serve(
            internal_listener,
            internal_app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(wait_for_shutdown(shutdown.clone()))
        .into_future();

        tokio::pin!(public_server);
        tokio::pin!(internal_server);

        tokio::select! {
            _ = shutdown_signal() => {
                shutdown.notify_waiters();
                let (public_result, internal_result) =
                    tokio::join!(&mut public_server, &mut internal_server);
                public_result?;
                internal_result?;
            }
            public_result = &mut public_server => {
                shutdown.notify_waiters();
                let internal_result = (&mut internal_server).await;
                public_result?;
                internal_result?;
            }
            internal_result = &mut internal_server => {
                shutdown.notify_waiters();
                let public_result = (&mut public_server).await;
                internal_result?;
                public_result?;
            }
        }
    } else {
        axum::serve(
            listener,
            public_app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    }

    Ok(())
}

async fn wait_for_shutdown(shutdown: Arc<Notify>) {
    shutdown.notified().await;
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
