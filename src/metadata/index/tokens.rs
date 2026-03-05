use base64::Engine as _;
use serde::{Deserialize, Serialize};

use super::{
    METADATA_CONTINUATION_TOKEN_PREFIX, METADATA_VERSIONS_CONTINUATION_TOKEN_PREFIX,
    MetadataQueryError,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ContinuationTokenPayload {
    version: u8,
    bucket: String,
    prefix: Option<String>,
    view_id: Option<String>,
    snapshot_id: Option<String>,
    key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VersionsContinuationTokenPayload {
    version: u8,
    bucket: String,
    prefix: Option<String>,
    view_id: Option<String>,
    snapshot_id: Option<String>,
    key_marker: String,
    version_id_marker: String,
}

pub(super) fn encode_continuation_token(
    bucket: &str,
    prefix: Option<&str>,
    view_id: Option<&str>,
    snapshot_id: Option<&str>,
    key: &str,
) -> Option<String> {
    let normalized = key.trim();
    if normalized.is_empty() {
        return None;
    }
    let payload = ContinuationTokenPayload {
        version: 1,
        bucket: bucket.trim().to_string(),
        prefix: prefix.map(ToOwned::to_owned),
        view_id: view_id.map(ToOwned::to_owned),
        snapshot_id: snapshot_id.map(ToOwned::to_owned),
        key: normalized.to_string(),
    };
    let payload = serde_json::to_vec(&payload).ok()?;
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_slice());
    Some(format!("{METADATA_CONTINUATION_TOKEN_PREFIX}{encoded}"))
}

pub(super) fn decode_continuation_token(
    token: Option<&str>,
    bucket: &str,
    prefix: Option<&str>,
    view_id: Option<&str>,
    snapshot_id: Option<&str>,
) -> Result<Option<String>, MetadataQueryError> {
    let Some(raw_token) = token.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let token_body = raw_token
        .strip_prefix(METADATA_CONTINUATION_TOKEN_PREFIX)
        .ok_or(MetadataQueryError::InvalidContinuationToken)?;

    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token_body.as_bytes())
        .map_err(|_| MetadataQueryError::InvalidContinuationToken)?;
    let payload = serde_json::from_slice::<ContinuationTokenPayload>(decoded.as_slice())
        .map_err(|_| MetadataQueryError::InvalidContinuationToken)?;
    if payload.version != 1 {
        return Err(MetadataQueryError::InvalidContinuationToken);
    }
    if payload.bucket != bucket.trim() {
        return Err(MetadataQueryError::InvalidContinuationToken);
    }
    if payload.prefix.as_deref() != prefix {
        return Err(MetadataQueryError::InvalidContinuationToken);
    }
    if payload.view_id.as_deref() != view_id {
        return Err(MetadataQueryError::InvalidContinuationToken);
    }
    if payload.snapshot_id.as_deref() != snapshot_id {
        return Err(MetadataQueryError::InvalidContinuationToken);
    }
    let key = payload.key.trim();
    if key.is_empty() {
        return Err(MetadataQueryError::InvalidContinuationToken);
    }
    Ok(Some(key.to_string()))
}

pub(super) fn encode_versions_continuation_token(
    bucket: &str,
    prefix: Option<&str>,
    view_id: Option<&str>,
    snapshot_id: Option<&str>,
    key_marker: &str,
    version_id_marker: &str,
) -> Option<String> {
    let normalized_key = key_marker.trim();
    let normalized_version = version_id_marker.trim();
    if normalized_key.is_empty() || normalized_version.is_empty() {
        return None;
    }
    let payload = VersionsContinuationTokenPayload {
        version: 1,
        bucket: bucket.trim().to_string(),
        prefix: prefix.map(ToOwned::to_owned),
        view_id: view_id.map(ToOwned::to_owned),
        snapshot_id: snapshot_id.map(ToOwned::to_owned),
        key_marker: normalized_key.to_string(),
        version_id_marker: normalized_version.to_string(),
    };
    let payload = serde_json::to_vec(&payload).ok()?;
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_slice());
    Some(format!(
        "{METADATA_VERSIONS_CONTINUATION_TOKEN_PREFIX}{encoded}"
    ))
}

pub(super) fn decode_versions_continuation_token(
    token: Option<&str>,
    bucket: &str,
    prefix: Option<&str>,
    view_id: Option<&str>,
    snapshot_id: Option<&str>,
) -> Result<Option<(String, String)>, MetadataQueryError> {
    let Some(raw_token) = token.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let token_body = raw_token
        .strip_prefix(METADATA_VERSIONS_CONTINUATION_TOKEN_PREFIX)
        .ok_or(MetadataQueryError::InvalidVersionsMarker)?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token_body.as_bytes())
        .map_err(|_| MetadataQueryError::InvalidVersionsMarker)?;
    let payload = serde_json::from_slice::<VersionsContinuationTokenPayload>(decoded.as_slice())
        .map_err(|_| MetadataQueryError::InvalidVersionsMarker)?;
    if payload.version != 1 {
        return Err(MetadataQueryError::InvalidVersionsMarker);
    }
    if payload.bucket != bucket.trim() {
        return Err(MetadataQueryError::InvalidVersionsMarker);
    }
    if payload.prefix.as_deref() != prefix {
        return Err(MetadataQueryError::InvalidVersionsMarker);
    }
    if payload.view_id.as_deref() != view_id {
        return Err(MetadataQueryError::InvalidVersionsMarker);
    }
    if payload.snapshot_id.as_deref() != snapshot_id {
        return Err(MetadataQueryError::InvalidVersionsMarker);
    }
    let key_marker = payload.key_marker.trim();
    let version_id_marker = payload.version_id_marker.trim();
    if key_marker.is_empty() || version_id_marker.is_empty() {
        return Err(MetadataQueryError::InvalidVersionsMarker);
    }
    Ok(Some((
        key_marker.to_string(),
        version_id_marker.to_string(),
    )))
}
