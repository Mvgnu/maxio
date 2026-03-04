use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub(super) struct PersistedPlacementState {
    pub(super) epoch: u64,
    pub(super) view_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub(super) struct PersistedClusterIdentityState {
    pub(super) cluster_id: String,
}

pub(super) fn placement_state_path(data_dir: &str) -> PathBuf {
    Path::new(data_dir)
        .join(PLACEMENT_STATE_DIR)
        .join(PLACEMENT_STATE_FILE)
}

pub(super) fn placement_state_temp_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(PLACEMENT_STATE_FILE);
    path.with_file_name(format!("{}.tmp-{}", file_name, uuid::Uuid::new_v4()))
}

#[cfg(not(target_os = "windows"))]
pub(super) async fn rename_placement_state(temp_path: &Path, path: &Path) -> std::io::Result<()> {
    tokio::fs::rename(temp_path, path).await
}

#[cfg(target_os = "windows")]
pub(super) async fn rename_placement_state(temp_path: &Path, path: &Path) -> std::io::Result<()> {
    match tokio::fs::rename(temp_path, path).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            tokio::fs::remove_file(path).await?;
            tokio::fs::rename(temp_path, path).await
        }
        Err(err) => Err(err),
    }
}

pub(super) async fn read_persisted_placement_state(
    path: &Path,
) -> anyhow::Result<Option<PersistedPlacementState>> {
    match tokio::fs::read(path).await {
        Ok(bytes) => {
            let state =
                serde_json::from_slice::<PersistedPlacementState>(&bytes).map_err(|err| {
                    anyhow::anyhow!(
                        "Failed to parse placement state '{}': {err}",
                        path.display()
                    )
                })?;
            Ok(Some(state))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(anyhow::anyhow!(
            "Failed to read placement state '{}': {err}",
            path.display()
        )),
    }
}

pub(super) async fn write_persisted_placement_state(
    path: &Path,
    state: &PersistedPlacementState,
) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|err| {
            anyhow::anyhow!(
                "Failed to create placement state directory '{}': {err}",
                parent.display()
            )
        })?;
    }

    let payload = serde_json::to_vec_pretty(state).map_err(|err| {
        anyhow::anyhow!(
            "Failed to serialize placement state '{}': {err}",
            path.display()
        )
    })?;
    let temp_path = placement_state_temp_path(path);
    let mut temp_file = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp_path)
        .await
        .map_err(|err| {
            anyhow::anyhow!(
                "Failed to create placement state temp file '{}': {err}",
                temp_path.display()
            )
        })?;
    temp_file.write_all(&payload).await.map_err(|err| {
        anyhow::anyhow!(
            "Failed to write placement state temp file '{}': {err}",
            temp_path.display()
        )
    })?;
    temp_file.sync_all().await.map_err(|err| {
        anyhow::anyhow!(
            "Failed to sync placement state temp file '{}': {err}",
            temp_path.display()
        )
    })?;
    drop(temp_file);

    if let Err(err) = rename_placement_state(temp_path.as_path(), path).await {
        let _ = tokio::fs::remove_file(&temp_path).await;
        return Err(anyhow::anyhow!(
            "Failed to atomically persist placement state '{}' via temp '{}': {err}",
            path.display(),
            temp_path.display()
        ));
    }

    Ok(())
}

pub(super) async fn load_or_bootstrap_placement_epoch(
    data_dir: &str,
    current_view_id: &str,
) -> anyhow::Result<u64> {
    let path = placement_state_path(data_dir);
    let persisted = read_persisted_placement_state(path.as_path()).await?;
    let next_state = match persisted {
        Some(mut state) => {
            if state.view_id != current_view_id {
                state.epoch = state.epoch.saturating_add(1);
                state.view_id = current_view_id.to_string();
                write_persisted_placement_state(path.as_path(), &state).await?;
            }
            state
        }
        None => {
            let state = PersistedPlacementState {
                epoch: 0,
                view_id: current_view_id.to_string(),
            };
            write_persisted_placement_state(path.as_path(), &state).await?;
            state
        }
    };

    Ok(next_state.epoch)
}

pub(super) fn cluster_identity_state_path(data_dir: &str) -> PathBuf {
    Path::new(data_dir)
        .join(PLACEMENT_STATE_DIR)
        .join(CLUSTER_ID_STATE_FILE)
}

pub(super) async fn read_persisted_cluster_identity_state(
    path: &Path,
) -> anyhow::Result<Option<PersistedClusterIdentityState>> {
    match tokio::fs::read(path).await {
        Ok(bytes) => {
            let state =
                serde_json::from_slice::<PersistedClusterIdentityState>(&bytes).map_err(|err| {
                    anyhow::anyhow!(
                        "Failed to parse cluster identity state '{}': {err}",
                        path.display()
                    )
                })?;
            Ok(Some(state))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(anyhow::anyhow!(
            "Failed to read cluster identity state '{}': {err}",
            path.display()
        )),
    }
}

pub(super) async fn write_persisted_cluster_identity_state(
    path: &Path,
    state: &PersistedClusterIdentityState,
) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|err| {
            anyhow::anyhow!(
                "Failed to create cluster identity directory '{}': {err}",
                parent.display()
            )
        })?;
    }

    let payload = serde_json::to_vec_pretty(state).map_err(|err| {
        anyhow::anyhow!(
            "Failed to serialize cluster identity state '{}': {err}",
            path.display()
        )
    })?;
    let temp_path = placement_state_temp_path(path);
    let mut temp_file = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp_path)
        .await
        .map_err(|err| {
            anyhow::anyhow!(
                "Failed to create cluster identity temp file '{}': {err}",
                temp_path.display()
            )
        })?;
    temp_file.write_all(&payload).await.map_err(|err| {
        anyhow::anyhow!(
            "Failed to write cluster identity temp file '{}': {err}",
            temp_path.display()
        )
    })?;
    temp_file.sync_all().await.map_err(|err| {
        anyhow::anyhow!(
            "Failed to sync cluster identity temp file '{}': {err}",
            temp_path.display()
        )
    })?;
    drop(temp_file);

    if let Err(err) = rename_placement_state(temp_path.as_path(), path).await {
        let _ = tokio::fs::remove_file(&temp_path).await;
        return Err(anyhow::anyhow!(
            "Failed to atomically persist cluster identity state '{}' via temp '{}': {err}",
            path.display(),
            temp_path.display()
        ));
    }

    Ok(())
}

pub(super) async fn load_or_bootstrap_cluster_id(
    data_dir: &str,
    bootstrap_cluster_id: &str,
) -> anyhow::Result<String> {
    let path = cluster_identity_state_path(data_dir);
    if let Some(state) = read_persisted_cluster_identity_state(path.as_path()).await? {
        let normalized = state.cluster_id.trim();
        if normalized.is_empty() {
            return Err(anyhow::anyhow!(
                "Cluster identity state '{}' is invalid: cluster_id is empty",
                path.display()
            ));
        }
        return Ok(normalized.to_string());
    }

    let normalized_bootstrap_cluster_id = bootstrap_cluster_id.trim();
    if normalized_bootstrap_cluster_id.is_empty() {
        return Err(anyhow::anyhow!(
            "Cannot bootstrap cluster identity: bootstrap cluster id is empty"
        ));
    }

    let state = PersistedClusterIdentityState {
        cluster_id: normalized_bootstrap_cluster_id.to_string(),
    };
    write_persisted_cluster_identity_state(path.as_path(), &state).await?;
    Ok(state.cluster_id)
}

pub(super) fn validate_cluster_id_binding(
    persisted_cluster_id: &str,
    configured_cluster_id: Option<&str>,
) -> anyhow::Result<()> {
    let Some(configured_cluster_id) = configured_cluster_id else {
        return Ok(());
    };
    if persisted_cluster_id == configured_cluster_id {
        return Ok(());
    }
    Err(anyhow::anyhow!(
        "Configured cluster id '{}' does not match persisted cluster identity '{}'",
        configured_cluster_id,
        persisted_cluster_id
    ))
}
