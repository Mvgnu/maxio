//! Conditional mutations must be implemented atomically or rejected explicitly.
use axum::http::{HeaderMap, header};

use crate::{error::S3Error, storage::ObjectWriteCondition};

pub(crate) fn parse_write_condition(
    headers: &HeaderMap,
) -> Result<Option<ObjectWriteCondition>, S3Error> {
    let matches = headers.get_all(header::IF_MATCH).iter().collect::<Vec<_>>();
    let absent = headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .collect::<Vec<_>>();
    if matches.len() > 1 || absent.len() > 1 || (!matches.is_empty() && !absent.is_empty()) {
        return Err(S3Error::invalid_argument(
            "Use exactly one conditional write header",
        ));
    }
    if let Some(value) = absent.first() {
        if value.to_str().ok().map(str::trim) != Some("*") {
            return Err(S3Error::invalid_argument(
                "If-None-Match for PutObject must be *",
            ));
        }
        return Ok(Some(ObjectWriteCondition::IfAbsent));
    }
    if let Some(value) = matches.first() {
        let value = value
            .to_str()
            .map_err(|_| S3Error::invalid_argument("Invalid If-Match value"))?
            .trim();
        let Some(inner) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) else {
            return Err(S3Error::invalid_argument(
                "If-Match requires one exact quoted ETag",
            ));
        };
        if inner.is_empty() || inner.bytes().any(|b| b == b'"' || b < 0x21 || b == 0x7f) {
            return Err(S3Error::invalid_argument(
                "If-Match requires one exact quoted ETag",
            ));
        }
        return Ok(Some(ObjectWriteCondition::IfMatch(value.to_owned())));
    }
    Ok(None)
}

pub(crate) fn reject_unsupported_write_condition(headers: &HeaderMap) -> Result<(), S3Error> {
    if headers.contains_key(header::IF_MATCH)
        || headers.contains_key(header::IF_NONE_MATCH)
        || headers.contains_key("x-amz-if-match-last-modified-time")
        || headers.contains_key("x-amz-if-match-size")
    {
        return Err(S3Error::not_implemented(
            "Conditional writes are supported only for standalone PutObject",
        ));
    }
    Ok(())
}
