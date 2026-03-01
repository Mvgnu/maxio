use axum::{body::Body, http::HeaderMap};
use futures::TryStreamExt;
use tokio::io::{AsyncBufReadExt, AsyncReadExt};

use crate::error::S3Error;
use crate::server::AppState;
use crate::storage::{ChecksumAlgorithm, ObjectMeta, StorageError};

pub(super) async fn ensure_bucket_exists(state: &AppState, bucket: &str) -> Result<(), S3Error> {
    match state.storage.head_bucket(bucket).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(S3Error::no_such_bucket(bucket)),
        Err(err) => Err(S3Error::internal(err)),
    }
}

/// Extract checksum algorithm and optional expected value from request headers.
pub(crate) fn extract_checksum(headers: &HeaderMap) -> Option<(ChecksumAlgorithm, Option<String>)> {
    let pairs = [
        ("x-amz-checksum-crc32", ChecksumAlgorithm::CRC32),
        ("x-amz-checksum-crc32c", ChecksumAlgorithm::CRC32C),
        ("x-amz-checksum-sha1", ChecksumAlgorithm::SHA1),
        ("x-amz-checksum-sha256", ChecksumAlgorithm::SHA256),
    ];

    // Check for a value header first (implies the algorithm).
    for (header, algo) in &pairs {
        if let Some(val) = headers.get(*header).and_then(|v| v.to_str().ok()) {
            return Some((*algo, Some(val.to_string())));
        }
    }

    // Fall back to algorithm-only header (compute but don't validate).
    headers
        .get("x-amz-checksum-algorithm")
        .and_then(|v| v.to_str().ok())
        .and_then(ChecksumAlgorithm::from_header_str)
        .map(|algo| (algo, None))
}

pub(super) fn add_checksum_header(
    builder: http::response::Builder,
    meta: &ObjectMeta,
) -> http::response::Builder {
    if let (Some(algo), Some(val)) = (&meta.checksum_algorithm, &meta.checksum_value) {
        builder.header(algo.header_name(), val.as_str())
    } else {
        builder
    }
}

pub(super) enum DeleteObjectsOutcome {
    Deleted {
        key: String,
        version_id: Option<String>,
        is_delete_marker: bool,
    },
    Error {
        key: String,
        code: &'static str,
        message: String,
    },
}

pub(super) fn map_delete_storage_err(bucket: &str, err: StorageError) -> S3Error {
    match err {
        StorageError::NotFound(_) => S3Error::no_such_bucket(bucket),
        StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
        _ => S3Error::internal(err),
    }
}

pub(super) fn map_delete_objects_err(
    bucket: &str,
    key: String,
    err: StorageError,
) -> DeleteObjectsOutcome {
    match err {
        StorageError::InvalidKey(msg) => DeleteObjectsOutcome::Error {
            key,
            code: "InvalidArgument",
            message: msg,
        },
        StorageError::NotFound(_) => DeleteObjectsOutcome::Error {
            key,
            code: "NoSuchBucket",
            message: format!("The specified bucket does not exist: {bucket}"),
        },
        _ => DeleteObjectsOutcome::Error {
            key,
            code: "InternalError",
            message: err.to_string(),
        },
    }
}

pub(super) fn build_delete_objects_response_xml(
    outcomes: &[DeleteObjectsOutcome],
    quiet: bool,
) -> String {
    let mut deleted_xml = String::new();
    let mut error_xml = String::new();

    for outcome in outcomes {
        match outcome {
            DeleteObjectsOutcome::Deleted {
                key,
                version_id,
                is_delete_marker,
            } => {
                if quiet {
                    continue;
                }
                let mut entry = format!("<Deleted><Key>{}</Key>", quick_xml::escape::escape(key));
                if let Some(vid) = version_id {
                    entry.push_str(&format!(
                        "<VersionId>{}</VersionId>",
                        quick_xml::escape::escape(vid)
                    ));
                }
                if *is_delete_marker {
                    entry.push_str("<DeleteMarker>true</DeleteMarker>");
                }
                entry.push_str("</Deleted>");
                deleted_xml.push_str(&entry);
            }
            DeleteObjectsOutcome::Error { key, code, message } => {
                error_xml.push_str(&format!(
                    "<Error><Key>{}</Key><Code>{}</Code><Message>{}</Message></Error>",
                    quick_xml::escape::escape(key),
                    code,
                    quick_xml::escape::escape(message)
                ));
            }
        }
    }

    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">{}{}</DeleteResult>",
        deleted_xml, error_xml
    )
}

pub(crate) async fn body_to_reader(
    headers: &HeaderMap,
    body: Body,
) -> Result<std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>>, S3Error> {
    let is_aws_chunked = headers
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
        == Some("STREAMING-AWS4-HMAC-SHA256-PAYLOAD");

    let stream = body.into_data_stream();
    let raw_reader = tokio_util::io::StreamReader::new(
        stream.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)),
    );

    if is_aws_chunked {
        let framing_err = || S3Error::invalid_argument("invalid aws-chunked payload framing");
        let mut buf_reader = tokio::io::BufReader::new(raw_reader);
        let mut decoded = Vec::new();
        let mut saw_final_chunk = false;
        loop {
            let mut line = String::new();
            let n = buf_reader
                .read_line(&mut line)
                .await
                .map_err(S3Error::internal)?;
            if n == 0 {
                break;
            }
            let line = line.trim_end_matches(['\r', '\n']);
            let size_str = line.split(';').next().unwrap_or("0");
            let chunk_size =
                usize::from_str_radix(size_str.trim(), 16).map_err(|_| framing_err())?;
            if chunk_size == 0 {
                saw_final_chunk = true;
                break;
            }
            let mut chunk = vec![0u8; chunk_size];
            buf_reader
                .read_exact(&mut chunk)
                .await
                .map_err(|_| framing_err())?;
            decoded.extend_from_slice(&chunk);
            let mut crlf = [0u8; 2];
            buf_reader
                .read_exact(&mut crlf)
                .await
                .map_err(|_| framing_err())?;
            if crlf != *b"\r\n" {
                return Err(framing_err());
            }
        }
        if !saw_final_chunk {
            return Err(framing_err());
        }
        Ok(Box::pin(std::io::Cursor::new(decoded)))
    } else {
        Ok(Box::pin(raw_reader))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[test]
    fn extract_checksum_prefers_explicit_value_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-amz-checksum-algorithm", "SHA1".parse().unwrap());
        headers.insert("x-amz-checksum-sha256", "abc123=".parse().unwrap());

        let checksum = extract_checksum(&headers).expect("checksum should be extracted");
        assert_eq!(checksum.0, ChecksumAlgorithm::SHA256);
        assert_eq!(checksum.1.as_deref(), Some("abc123="));
    }

    #[test]
    fn extract_checksum_supports_algorithm_only_header() {
        let mut headers = HeaderMap::new();
        headers.insert("x-amz-checksum-algorithm", "CRC32C".parse().unwrap());

        let checksum = extract_checksum(&headers).expect("checksum should be extracted");
        assert_eq!(checksum.0, ChecksumAlgorithm::CRC32C);
        assert_eq!(checksum.1, None);
    }

    #[test]
    fn add_checksum_header_adds_header_for_known_checksum() {
        let meta = ObjectMeta {
            key: "a.txt".to_string(),
            size: 1,
            etag: "\"etag\"".to_string(),
            content_type: "text/plain".to_string(),
            last_modified: "2026-03-01T00:00:00Z".to_string(),
            version_id: None,
            is_delete_marker: false,
            storage_format: None,
            checksum_algorithm: Some(ChecksumAlgorithm::SHA256),
            checksum_value: Some("value==".to_string()),
        };

        let response = add_checksum_header(http::Response::builder(), &meta)
            .status(200)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            response
                .headers()
                .get("x-amz-checksum-sha256")
                .and_then(|v| v.to_str().ok()),
            Some("value==")
        );
    }

    #[tokio::test]
    async fn body_to_reader_decodes_streaming_chunked_payload() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-content-sha256",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD".parse().unwrap(),
        );
        let encoded =
            b"5;chunk-signature=a\r\nhello\r\n6;chunk-signature=b\r\n world\r\n0;chunk-signature=c\r\n\r\n";
        let mut reader = body_to_reader(&headers, Body::from(encoded.as_slice()))
            .await
            .expect("chunked payload should decode");
        let mut decoded = Vec::new();
        reader.read_to_end(&mut decoded).await.unwrap();
        assert_eq!(decoded, b"hello world");
    }

    #[tokio::test]
    async fn body_to_reader_keeps_regular_payload_unchanged() {
        let headers = HeaderMap::new();
        let expected = b"plain payload bytes";
        let mut reader = body_to_reader(&headers, Body::from(expected.as_slice()))
            .await
            .expect("plain payload should be readable");
        let mut actual = Vec::new();
        reader.read_to_end(&mut actual).await.unwrap();
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn body_to_reader_rejects_chunked_payload_without_final_chunk() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-content-sha256",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD".parse().unwrap(),
        );
        let encoded = b"5;chunk-signature=a\r\nhello\r\n";
        let err = match body_to_reader(&headers, Body::from(encoded.as_slice())).await {
            Ok(_) => panic!("payload without final chunk should fail"),
            Err(err) => err,
        };
        assert_eq!(err.code.as_str(), "InvalidArgument");
    }

    #[tokio::test]
    async fn body_to_reader_rejects_chunked_payload_with_invalid_size() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-content-sha256",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD".parse().unwrap(),
        );
        let encoded = b"zz;chunk-signature=a\r\nhello\r\n0;chunk-signature=b\r\n\r\n";
        let err = match body_to_reader(&headers, Body::from(encoded.as_slice())).await {
            Ok(_) => panic!("payload with invalid chunk size should fail"),
            Err(err) => err,
        };
        assert_eq!(err.code.as_str(), "InvalidArgument");
    }

    #[test]
    fn build_delete_objects_response_xml_includes_deleted_and_error_entries() {
        let xml = build_delete_objects_response_xml(
            &[
                DeleteObjectsOutcome::Deleted {
                    key: "a&b.txt".to_string(),
                    version_id: Some("v1".to_string()),
                    is_delete_marker: true,
                },
                DeleteObjectsOutcome::Error {
                    key: "bad<key>.txt".to_string(),
                    code: "InternalError",
                    message: "failed > reason".to_string(),
                },
            ],
            false,
        );

        assert!(xml.contains("<Deleted><Key>a&amp;b.txt</Key>"));
        assert!(xml.contains("<VersionId>v1</VersionId>"));
        assert!(xml.contains("<DeleteMarker>true</DeleteMarker>"));
        assert!(xml.contains("<Error><Key>bad&lt;key&gt;.txt</Key>"));
        assert!(xml.contains("<Code>InternalError</Code>"));
        assert!(xml.contains("<Message>failed &gt; reason</Message>"));
    }

    #[test]
    fn build_delete_objects_response_xml_honors_quiet_mode() {
        let xml = build_delete_objects_response_xml(
            &[DeleteObjectsOutcome::Deleted {
                key: "a.txt".to_string(),
                version_id: None,
                is_delete_marker: false,
            }],
            true,
        );

        assert!(!xml.contains("<Deleted>"));
        assert!(xml.contains("<DeleteResult"));
    }

    #[test]
    fn map_delete_storage_err_maps_invalid_key_to_invalid_argument() {
        let err = map_delete_storage_err("bucket", StorageError::InvalidKey("bad key".into()));
        assert_eq!(err.code.as_str(), "InvalidArgument");
        assert_eq!(err.message, "bad key");
    }

    #[test]
    fn map_delete_objects_err_maps_invalid_key_to_invalid_argument_entry() {
        let outcome = map_delete_objects_err(
            "bucket",
            "../oops.txt".to_string(),
            StorageError::InvalidKey("bad key".into()),
        );
        match outcome {
            DeleteObjectsOutcome::Error { code, message, .. } => {
                assert_eq!(code, "InvalidArgument");
                assert_eq!(message, "bad key");
            }
            _ => panic!("expected error outcome"),
        }
    }
}
