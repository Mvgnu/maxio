//! Authenticate received bytes before any HTTP handler can mutate data.
//!
//! Some S3 handlers intentionally ignore a request body. A lazy hashing stream
//! would let those handlers mutate before authentication completed. Keep small
//! bodies in bounded memory and spool larger bodies to a private anonymous file,
//! then replay the original bytes only after the complete payload is verified.

use axum::{body::Body, extract::Request};
use futures::{StreamExt, TryStreamExt};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader};
use tokio_util::io::{ReaderStream, StreamReader};

use crate::error::S3Error;

use super::signature_v4::{ChunkSignatureVerifier, ParsedAuth};

const MEMORY_LIMIT: usize = 64 * 1024;
const CHUNK_HEADER_LIMIT: u64 = 128;
const SIGNED_CHUNKS: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";

pub(super) async fn verify_request_payload(
    request: Request,
    signing: Option<(&ParsedAuth, &str)>,
) -> Result<Request, S3Error> {
    let hashes = request.headers().get_all("x-amz-content-sha256");
    let mut hashes = hashes.iter();
    let Some(hash) = hashes.next() else {
        // Retain the established unsigned-payload compatibility for clients
        // (including generated presigned URLs) that omit the checksum header.
        return Ok(request);
    };
    if hashes.next().is_some() {
        return Err(S3Error::invalid_argument(
            "Multiple x-amz-content-sha256 headers are not allowed",
        ));
    }
    let hash = hash
        .to_str()
        .map_err(|_| S3Error::invalid_argument("Invalid x-amz-content-sha256 header"))?;
    if hash == "UNSIGNED-PAYLOAD" {
        return Ok(request);
    }

    let verified = if hash == SIGNED_CHUNKS {
        let Some((parsed, secret)) = signing else {
            return Err(S3Error::not_implemented(
                "Signed streaming payloads require header-based SigV4 authentication",
            ));
        };
        let decoded_lengths = request.headers().get_all("x-amz-decoded-content-length");
        if decoded_lengths.iter().count() != 1 {
            return Err(S3Error::invalid_argument(
                "Signed streaming payloads require one x-amz-decoded-content-length header",
            ));
        }
        let decoded_length = decoded_lengths
            .iter()
            .next()
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| {
                S3Error::invalid_argument("Invalid x-amz-decoded-content-length header")
            })?;
        let timestamp = request
            .headers()
            .get("x-amz-date")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        let verifier = ChunkSignatureVerifier::new(parsed, timestamp, secret);
        let (parts, body) = request.into_parts();
        let spool = verify_signed_chunks(body, verifier, decoded_length).await?;
        Request::from_parts(parts, spool.into_body().await?)
    } else {
        if hash.starts_with("STREAMING-") {
            return Err(S3Error::not_implemented(
                "This streaming payload signature or trailer mode is not implemented",
            ));
        }
        let mut expected = [0u8; 32];
        hex::decode_to_slice(hash, &mut expected).map_err(|_| {
            S3Error::invalid_argument(
                "x-amz-content-sha256 must be a SHA-256 digest or supported payload mode",
            )
        })?;
        let (parts, body) = request.into_parts();
        let mut stream = body.into_data_stream();
        let mut digest = Sha256::new();
        let mut spool = PayloadSpool::default();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| body_error())?;
            digest.update(&chunk);
            spool.append(&chunk).await?;
        }
        if digest.finalize().as_slice() != expected {
            return Err(S3Error::bad_checksum("x-amz-content-sha256"));
        }
        Request::from_parts(parts, spool.into_body().await?)
    };
    Ok(verified)
}

async fn verify_signed_chunks(
    body: Body,
    mut verifier: ChunkSignatureVerifier,
    decoded_length: u64,
) -> Result<PayloadSpool, S3Error> {
    let stream = body.into_data_stream().map_err(std::io::Error::other);
    let mut reader = BufReader::new(StreamReader::new(stream));
    let mut spool = PayloadSpool::default();
    let mut total_length = 0u64;
    let mut buffer = [0u8; MEMORY_LIMIT];

    loop {
        let mut header = Vec::new();
        // Bound the framing line independently from the declared chunk size.
        (&mut reader)
            .take(CHUNK_HEADER_LIMIT)
            .read_until(b'\n', &mut header)
            .await
            .map_err(|_| body_error())?;
        let text = std::str::from_utf8(&header).map_err(|_| body_error())?;
        let text = text.strip_suffix("\r\n").ok_or_else(body_error)?;
        let (size, signature) = text
            .split_once(";chunk-signature=")
            .ok_or_else(body_error)?;
        if size.is_empty()
            || !size.bytes().all(|byte| byte.is_ascii_hexdigit())
            || signature.len() != 64
            || !signature.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(body_error());
        }
        let size = u64::from_str_radix(size, 16).map_err(|_| body_error())?;
        total_length = total_length.checked_add(size).ok_or_else(body_error)?;
        if total_length > decoded_length {
            return Err(body_error());
        }
        spool.append(&header).await?;
        let mut remaining = size;
        let mut digest = Sha256::new();
        while remaining > 0 {
            let count =
                usize::try_from(remaining.min(buffer.len() as u64)).map_err(|_| body_error())?;
            reader
                .read_exact(&mut buffer[..count])
                .await
                .map_err(|_| body_error())?;
            digest.update(&buffer[..count]);
            spool.append(&buffer[..count]).await?;
            remaining -= count as u64;
        }
        let mut terminator = [0u8; 2];
        reader
            .read_exact(&mut terminator)
            .await
            .map_err(|_| body_error())?;
        if terminator != *b"\r\n" {
            return Err(body_error());
        }
        if !verifier.verify(&digest.finalize(), signature) {
            return Err(S3Error::signature_mismatch());
        }
        spool.append(&terminator).await?;
        if size == 0 {
            if total_length != decoded_length
                || reader
                    .read(&mut buffer[..1])
                    .await
                    .map_err(|_| body_error())?
                    != 0
            {
                return Err(body_error());
            }
            return Ok(spool);
        }
    }
}

fn body_error() -> S3Error {
    S3Error::invalid_argument("Incomplete or invalid signed request body")
}

enum PayloadSpool {
    Memory(Vec<u8>),
    File(tokio::fs::File),
}

impl Default for PayloadSpool {
    fn default() -> Self {
        Self::Memory(Vec::new())
    }
}

impl PayloadSpool {
    async fn append(&mut self, bytes: &[u8]) -> Result<(), S3Error> {
        let staging_error = || S3Error::internal("Unable to stage signed request body");
        if let Self::Memory(memory) = self {
            if bytes.len() <= MEMORY_LIMIT.saturating_sub(memory.len()) {
                memory.extend_from_slice(bytes);
                return Ok(());
            }
            // tempfile uses a private, unpredictable file removed on close. It
            // has no persistent path to leak or clean up after cancellation.
            let file = tokio::task::spawn_blocking(tempfile::tempfile)
                .await
                .map_err(|_| staging_error())?
                .map_err(|_| staging_error())?;
            let mut file = tokio::fs::File::from_std(file);
            file.write_all(memory).await.map_err(|_| staging_error())?;
            *self = Self::File(file);
        }
        if let Self::File(file) = self {
            file.write_all(bytes).await.map_err(|_| staging_error())?;
        }
        Ok(())
    }

    async fn into_body(self) -> Result<Body, S3Error> {
        match self {
            Self::Memory(memory) => Ok(Body::from(memory)),
            Self::File(mut file) => {
                file.rewind()
                    .await
                    .map_err(|_| S3Error::internal("Unable to replay verified request body"))?;
                Ok(Body::from_stream(ReaderStream::with_capacity(
                    file,
                    MEMORY_LIMIT,
                )))
            }
        }
    }
}
