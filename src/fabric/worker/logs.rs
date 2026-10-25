//! Bounded, idempotent forwarding of the existing runner's retained logs.
use super::super::{client::FabricClient, contract::*};
use super::{control, local};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

const CHUNK: usize = 32 * 1024;
const LIMIT: u64 = 4 * 1024 * 1024;

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    stdout: u64,
    stderr: u64,
    pending: Option<Pending>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    request_id: String,
    stream: LogStream,
    offset: u64,
    data_base64: String,
    length: u64,
    truncated: bool,
}

async fn send_pending(
    client: &FabricClient,
    binding: &AttemptBinding,
    root: &Path,
    cursor: &mut Cursor,
) -> Result<()> {
    if let Some(pending) = &cursor.pending {
        let response = control(
            client,
            &ControlRequest::AppendLog {
                request_id: pending.request_id.clone(),
                attempt: binding.clone(),
                stream: pending.stream,
                offset: pending.offset,
                data_base64: pending.data_base64.clone(),
                truncated: pending.truncated,
            },
        )
        .await?;
        ensure!(
            matches!(response, ControlResponse::Ack { .. }),
            "unexpected log append response"
        );
        let next = pending
            .offset
            .checked_add(pending.length)
            .context("log offset overflow")?;
        match pending.stream {
            LogStream::Stdout => cursor.stdout = next,
            LogStream::Stderr => cursor.stderr = next,
        }
        cursor.pending = None;
        local::write_json(&root.join("log-forwarding.json"), cursor)?;
    }
    Ok(())
}

pub(super) async fn sync(
    client: &FabricClient,
    binding: &AttemptBinding,
    root: &Path,
) -> Result<()> {
    let path = root.join("log-forwarding.json");
    let mut cursor: Cursor = match local::read_json(&path) {
        Ok(cursor) => cursor,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            Cursor::default()
        }
        Err(error) => return Err(error),
    };
    ensure!(
        cursor.stdout <= LIMIT && cursor.stderr <= LIMIT,
        "invalid retained log cursor"
    );
    if let Some(pending) = &cursor.pending {
        ensure!(
            pending.length <= CHUNK as u64
                && pending.offset + pending.length <= LIMIT
                && STANDARD.decode(&pending.data_base64)?.len() as u64 == pending.length,
            "invalid retained pending log chunk"
        );
    }
    send_pending(client, binding, root, &mut cursor).await?;
    let Some((_, record)) = local::owned_run(&root.join("runs"))? else {
        return Ok(());
    };
    for (stream, path) in [
        (LogStream::Stdout, &record.stdout_log),
        (LogStream::Stderr, &record.stderr_log),
    ] {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "unsafe retained log path"
        );
        let mut file = File::open(path)?;
        let mut offset = match stream {
            LogStream::Stdout => cursor.stdout,
            LogStream::Stderr => cursor.stderr,
        };
        ensure!(
            metadata.len() >= offset,
            "retained log shrank after forwarding"
        );
        file.seek(SeekFrom::Start(offset))?;
        while offset < metadata.len().min(LIMIT) {
            let remaining = (metadata.len().min(LIMIT) - offset).min(CHUNK as u64) as usize;
            let mut data = vec![0; remaining];
            file.read_exact(&mut data)?;
            cursor.pending = Some(Pending {
                request_id: local::id(),
                stream,
                offset,
                data_base64: STANDARD.encode(&data),
                length: data.len() as u64,
                truncated: metadata.len() >= LIMIT,
            });
            // Persist the exact request before sending; a lost response repeats
            // this identity/offset/content rather than duplicating log bytes.
            local::write_json(&root.join("log-forwarding.json"), &cursor)?;
            send_pending(client, binding, root, &mut cursor).await?;
            offset += data.len() as u64;
        }
    }
    Ok(())
}
