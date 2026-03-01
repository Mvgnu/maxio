use super::ChunkManifest;
use sha2::{Digest, Sha256};
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::AsyncRead;

/// An `AsyncRead` implementation that reads chunks from disk,
/// verifies each chunk's SHA-256 checksum against the manifest,
/// and streams the verified data to the consumer.
pub struct VerifiedChunkReader {
    chunks_dir: PathBuf,
    manifest: ChunkManifest,
    current_chunk: u32,
    end_chunk: u32,
    skip_bytes: usize,
    remaining: u64,
    buf: Vec<u8>,
    buf_pos: usize,
    state: ReaderState,
}

enum ReaderState {
    /// Need to begin loading the next chunk from disk.
    NeedLoad,
    /// Chunk load is currently in-flight.
    Loading(Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send>>),
    /// Currently serving bytes from the loaded chunk.
    Serving,
    /// All done.
    Done,
}

impl VerifiedChunkReader {
    /// Create a reader that streams the full object.
    pub fn new(chunks_dir: PathBuf, manifest: ChunkManifest) -> Self {
        let total = manifest.total_size;
        let chunk_count = manifest.chunk_count;
        Self {
            chunks_dir,
            manifest,
            current_chunk: 0,
            end_chunk: chunk_count.saturating_sub(1),
            skip_bytes: 0,
            remaining: total,
            buf: Vec::new(),
            buf_pos: 0,
            state: if total == 0 {
                ReaderState::Done
            } else {
                ReaderState::NeedLoad
            },
        }
    }

    /// Create a reader for a byte range [offset, offset+length).
    pub fn with_range(
        chunks_dir: PathBuf,
        manifest: ChunkManifest,
        offset: u64,
        length: u64,
    ) -> Self {
        if length == 0 || manifest.total_size == 0 {
            return Self {
                chunks_dir,
                manifest,
                current_chunk: 0,
                end_chunk: 0,
                skip_bytes: 0,
                remaining: 0,
                buf: Vec::new(),
                buf_pos: 0,
                state: ReaderState::Done,
            };
        }
        let chunk_size = manifest.chunk_size;
        let start_chunk = (offset / chunk_size) as u32;
        let end_chunk = ((offset + length - 1) / chunk_size) as u32;
        let skip_bytes = (offset % chunk_size) as usize;

        Self {
            chunks_dir,
            manifest,
            current_chunk: start_chunk,
            end_chunk,
            skip_bytes,
            remaining: length,
            buf: Vec::new(),
            buf_pos: 0,
            state: ReaderState::NeedLoad,
        }
    }

    fn start_chunk_load(&mut self) {
        let chunks_dir = self.chunks_dir.clone();
        let manifest = self.manifest.clone();
        let current_chunk = self.current_chunk;
        self.state = ReaderState::Loading(Box::pin(async move {
            load_verified_chunk(chunks_dir, manifest, current_chunk).await
        }));
    }
}

/// Load a chunk from disk, verify its checksum, and return its bytes.
/// Falls back to Reed-Solomon reconstruction if the chunk is corrupt/missing
/// and parity shards are available.
async fn load_verified_chunk(
    chunks_dir: PathBuf,
    manifest: ChunkManifest,
    current_chunk: u32,
) -> io::Result<Vec<u8>> {
    let idx = current_chunk as usize;
    let chunk_info = &manifest.chunks[idx];
    let chunk_path = chunks_dir.join(format!("{:06}", current_chunk));

    // Try reading and verifying the chunk directly.
    let direct_result = tokio::fs::read(&chunk_path)
        .await
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("failed to read chunk {}: {}", current_chunk, e),
            )
        })
        .and_then(|data| {
            if data.len() as u64 != chunk_info.size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "chunk {} size mismatch: expected {}, got {}",
                        current_chunk,
                        chunk_info.size,
                        data.len()
                    ),
                ));
            }

            let hash = hex::encode(Sha256::digest(&data));
            if hash != chunk_info.sha256 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "checksum mismatch on chunk {}: expected {}, got {}",
                        current_chunk, chunk_info.sha256, hash
                    ),
                ));
            }

            Ok(data)
        });

    match direct_result {
        Ok(data) => Ok(data),
        Err(original_err) => {
            // Attempt RS recovery if parity is available.
            if manifest.parity_shards.unwrap_or(0) > 0 {
                tracing::warn!(
                    "chunk {} failed integrity check ({}), attempting Reed-Solomon recovery",
                    current_chunk,
                    original_err
                );
                try_reconstruct_data_chunk(&chunks_dir, &manifest, current_chunk).await
            } else {
                Err(original_err)
            }
        }
    }
}

/// Reconstruct a single data chunk using Reed-Solomon erasure coding.
/// Reads all available data and parity shards, reconstructs the missing one.
async fn try_reconstruct_data_chunk(
    chunks_dir: &Path,
    manifest: &ChunkManifest,
    target_index: u32,
) -> io::Result<Vec<u8>> {
    use reed_solomon_erasure::galois_8::ReedSolomon;

    let k = manifest.chunk_count as usize;
    let m = manifest.parity_shards.unwrap_or(0) as usize;
    let shard_size = manifest.shard_size.unwrap_or(manifest.chunk_size) as usize;

    let rs = ReedSolomon::new(k, m)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("RS init error: {e}")))?;

    // Load all shards as Option<Vec<u8>>.
    let total_shards = k + m;
    let mut shards: Vec<Option<Vec<u8>>> = Vec::with_capacity(total_shards);

    for i in 0..total_shards {
        let chunk_info = &manifest.chunks[i];
        let chunk_path = chunks_dir.join(format!("{:06}", i));

        let shard = match tokio::fs::read(&chunk_path).await {
            Ok(data) => {
                // Verify SHA-256.
                let hash = hex::encode(Sha256::digest(&data));
                if hash != chunk_info.sha256 {
                    None
                } else {
                    // Pad to shard_size for RS.
                    let mut padded = data;
                    padded.resize(shard_size, 0u8);
                    Some(padded)
                }
            }
            Err(_) => None,
        };

        shards.push(shard);
    }

    // Count available shards.
    let present = shards.iter().filter(|s| s.is_some()).count();
    if present < k {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "too many missing/corrupt shards: only {present} of {k} required shards available ({} missing)",
                total_shards - present
            ),
        ));
    }

    // Reconstruct.
    rs.reconstruct(&mut shards).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("RS reconstruction failed: {e}"),
        )
    })?;

    // Extract the target data chunk and truncate to its real size.
    let reconstructed = shards[target_index as usize].take().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Other,
            "reconstruction produced None for target shard",
        )
    })?;

    let real_size = manifest.chunks[target_index as usize].size as usize;
    let mut result = reconstructed;
    result.truncate(real_size);

    tracing::warn!(
        "successfully recovered chunk {} via Reed-Solomon",
        target_index
    );
    Ok(result)
}

impl AsyncRead for VerifiedChunkReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            match this.state {
                ReaderState::Done => return Poll::Ready(Ok(())),
                ReaderState::NeedLoad => {
                    if this.current_chunk > this.end_chunk || this.remaining == 0 {
                        this.state = ReaderState::Done;
                        return Poll::Ready(Ok(()));
                    }
                    this.start_chunk_load();
                }
                ReaderState::Loading(ref mut fut) => match fut.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(data)) => {
                        this.buf = data;
                        this.buf_pos = this.skip_bytes;
                        this.skip_bytes = 0;
                        this.state = ReaderState::Serving;
                    }
                },
                ReaderState::Serving => {
                    let available = &this.buf[this.buf_pos..];
                    if available.is_empty() {
                        this.current_chunk += 1;
                        this.state = ReaderState::NeedLoad;
                        continue;
                    }

                    let to_copy = available
                        .len()
                        .min(buf.remaining())
                        .min(this.remaining as usize);

                    buf.put_slice(&available[..to_copy]);
                    this.buf_pos += to_copy;
                    this.remaining -= to_copy as u64;

                    if this.remaining == 0 {
                        this.state = ReaderState::Done;
                    }
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}
