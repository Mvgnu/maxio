use crate::error::S3Error;

const DELETE_OBJECTS_MAX_KEYS: usize = 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DeleteObjectsRequest {
    pub keys: Vec<String>,
    pub quiet: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CopySource {
    pub bucket: String,
    pub key: String,
    pub version_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MetadataDirective {
    Copy,
    Replace,
}

/// Convert ISO 8601 timestamp to HTTP date (RFC 7231) for Last-Modified header.
pub(super) fn to_http_date(iso: &str) -> String {
    chrono::DateTime::parse_from_str(iso, "%Y-%m-%dT%H:%M:%S%.3fZ")
        .or_else(|_| chrono::DateTime::parse_from_rfc3339(iso))
        .map(|dt| dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string())
        .unwrap_or_else(|_| iso.to_string())
}

/// Parse an HTTP Range header value into (start, end_inclusive) byte positions.
/// Returns Ok(Some((start, end))) for valid ranges, Ok(None) for unparseable/ignored,
/// Err(()) for syntactically valid but unsatisfiable ranges.
pub(super) fn parse_range(header: &str, file_size: u64) -> Result<Option<(u64, u64)>, ()> {
    let header = header.trim();
    let spec = match header.strip_prefix("bytes=") {
        Some(s) => s.trim(),
        None => return Ok(None),
    };
    if spec.contains(',') {
        return Ok(None);
    }
    let (start_str, end_str) = match spec.split_once('-') {
        Some(parts) => parts,
        None => return Ok(None),
    };

    if file_size == 0 {
        return Err(());
    }

    if start_str.is_empty() {
        let suffix: u64 = end_str.parse().map_err(|_| ())?;
        if suffix == 0 {
            return Err(());
        }
        let start = file_size.saturating_sub(suffix);
        Ok(Some((start, file_size - 1)))
    } else if end_str.is_empty() {
        let start: u64 = start_str.parse().map_err(|_| ())?;
        if start >= file_size {
            return Err(());
        }
        Ok(Some((start, file_size - 1)))
    } else {
        let start: u64 = start_str.parse().map_err(|_| ())?;
        let end: u64 = end_str.parse().map_err(|_| ())?;
        if start >= file_size {
            return Err(());
        }
        let end = end.min(file_size - 1);
        if start > end {
            return Err(());
        }
        Ok(Some((start, end)))
    }
}

pub(super) fn parse_copy_source(copy_source: &str) -> Result<CopySource, S3Error> {
    let trimmed = copy_source.strip_prefix('/').unwrap_or(copy_source);
    let (raw_path, raw_query) = match trimmed.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (trimmed, None),
    };

    let decoded = percent_encoding::percent_decode_str(raw_path)
        .decode_utf8()
        .map_err(|_| S3Error::invalid_argument("invalid x-amz-copy-source encoding"))?;
    let (src_bucket, src_key) = decoded
        .split_once('/')
        .ok_or_else(|| S3Error::invalid_argument("invalid x-amz-copy-source format"))?;
    if src_bucket.is_empty() || src_key.is_empty() {
        return Err(S3Error::invalid_argument(
            "invalid x-amz-copy-source format",
        ));
    }

    let mut version_id = None;
    if let Some(query) = raw_query {
        for param in query.split('&') {
            if param.is_empty() {
                continue;
            }
            let (raw_key, raw_value) = match param.split_once('=') {
                Some((key, value)) => (key, value),
                None => (param, ""),
            };
            let key = percent_encoding::percent_decode_str(raw_key)
                .decode_utf8()
                .map_err(|_| S3Error::invalid_argument("invalid x-amz-copy-source query"))?;
            if key != "versionId" {
                continue;
            }
            if version_id.is_some() {
                return Err(S3Error::invalid_argument(
                    "duplicate versionId in x-amz-copy-source",
                ));
            }
            let value = percent_encoding::percent_decode_str(raw_value)
                .decode_utf8()
                .map_err(|_| S3Error::invalid_argument("invalid x-amz-copy-source query"))?;
            if value.is_empty() {
                return Err(S3Error::invalid_argument(
                    "invalid x-amz-copy-source versionId",
                ));
            }
            version_id = Some(value.into_owned());
        }
    }

    Ok(CopySource {
        bucket: src_bucket.to_string(),
        key: src_key.to_string(),
        version_id,
    })
}

pub(super) fn parse_metadata_directive(
    directive: Option<&str>,
) -> Result<MetadataDirective, S3Error> {
    let Some(directive) = directive else {
        return Ok(MetadataDirective::Copy);
    };
    let directive = directive.trim();
    if directive.eq_ignore_ascii_case("COPY") {
        return Ok(MetadataDirective::Copy);
    }
    if directive.eq_ignore_ascii_case("REPLACE") {
        return Ok(MetadataDirective::Replace);
    }
    Err(S3Error::invalid_argument(
        "invalid x-amz-metadata-directive",
    ))
}

pub(super) fn parse_delete_objects_request(xml: &str) -> Result<DeleteObjectsRequest, S3Error> {
    let mut keys = Vec::new();
    let mut quiet = false;
    let mut reader = quick_xml::Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut saw_delete_root = false;
    let mut in_delete = false;
    let mut in_object = false;
    let mut in_key = false;
    let mut in_quiet = false;

    loop {
        match reader.read_event() {
            Ok(quick_xml::events::Event::Start(e)) if e.name().as_ref() == b"Delete" => {
                if saw_delete_root || in_delete {
                    return Err(S3Error::malformed_xml());
                }
                saw_delete_root = true;
                in_delete = true;
            }
            Ok(quick_xml::events::Event::Start(e)) if e.name().as_ref() == b"Object" => {
                if !in_delete || in_object {
                    return Err(S3Error::malformed_xml());
                }
                in_object = true;
            }
            Ok(quick_xml::events::Event::Start(e)) if e.name().as_ref() == b"Key" => {
                if !in_object {
                    return Err(S3Error::malformed_xml());
                }
                in_key = true;
            }
            Ok(quick_xml::events::Event::Start(e)) if e.name().as_ref() == b"Quiet" => {
                if !in_delete {
                    return Err(S3Error::malformed_xml());
                }
                in_quiet = true;
            }
            Ok(quick_xml::events::Event::Text(e)) if in_key => {
                let key = e
                    .unescape()
                    .map_err(|_| S3Error::malformed_xml())?
                    .into_owned();
                keys.push(key);
                if keys.len() > DELETE_OBJECTS_MAX_KEYS {
                    return Err(S3Error::malformed_xml());
                }
                in_key = false;
            }
            Ok(quick_xml::events::Event::Text(e)) if in_quiet => {
                let quiet_value = e.unescape().map_err(|_| S3Error::malformed_xml())?;
                quiet = quiet_value.as_ref().trim().eq_ignore_ascii_case("true");
                in_quiet = false;
            }
            Ok(quick_xml::events::Event::End(e)) if e.name().as_ref() == b"Key" => {
                in_key = false;
            }
            Ok(quick_xml::events::Event::End(e)) if e.name().as_ref() == b"Quiet" => {
                in_quiet = false;
            }
            Ok(quick_xml::events::Event::End(e)) if e.name().as_ref() == b"Object" => {
                in_object = false;
            }
            Ok(quick_xml::events::Event::End(e)) if e.name().as_ref() == b"Delete" => {
                in_delete = false;
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Err(_) => return Err(S3Error::malformed_xml()),
            _ => {}
        }
    }

    if !saw_delete_root || in_delete || in_object || in_key || in_quiet {
        return Err(S3Error::malformed_xml());
    }

    Ok(DeleteObjectsRequest { keys, quiet })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_http_date_handles_iso_and_rfc3339_and_passthrough() {
        assert_eq!(
            to_http_date("2026-03-01T12:34:56.789Z"),
            "Sun, 01 Mar 2026 12:34:56 GMT"
        );
        assert_eq!(
            to_http_date("2026-03-01T12:34:56+00:00"),
            "Sun, 01 Mar 2026 12:34:56 GMT"
        );
        assert_eq!(to_http_date("invalid-date"), "invalid-date");
    }

    #[test]
    fn parse_range_supports_explicit_open_and_suffix() {
        assert_eq!(parse_range("bytes=10-19", 100).unwrap(), Some((10, 19)));
        assert_eq!(parse_range("bytes=90-", 100).unwrap(), Some((90, 99)));
        assert_eq!(parse_range("bytes=-10", 100).unwrap(), Some((90, 99)));
    }

    #[test]
    fn parse_range_handles_clamp_and_invalid() {
        assert_eq!(parse_range("bytes=0-999", 100).unwrap(), Some((0, 99)));
        assert!(parse_range("bytes=500-600", 100).is_err());
        assert!(parse_range("bytes=-0", 100).is_err());
        assert!(parse_range("bytes=20-10", 100).is_err());
        assert_eq!(parse_range("bytes=0-1,5-6", 100).unwrap(), None);
        assert_eq!(parse_range("something else", 100).unwrap(), None);
    }

    #[test]
    fn parse_copy_source_decodes_and_splits() {
        let parsed = parse_copy_source("/src-bucket/path%20with%20space.txt").unwrap();
        assert_eq!(parsed.bucket, "src-bucket");
        assert_eq!(parsed.key, "path with space.txt");
        assert!(parsed.version_id.is_none());

        let parsed = parse_copy_source("src-bucket/no-leading-slash.txt").unwrap();
        assert_eq!(parsed.bucket, "src-bucket");
        assert_eq!(parsed.key, "no-leading-slash.txt");
        assert!(parsed.version_id.is_none());
    }

    #[test]
    fn parse_copy_source_rejects_invalid_input() {
        assert!(parse_copy_source("missing-delimiter").is_err());
        assert!(parse_copy_source("/bucket/%FF").is_err());
        assert!(parse_copy_source("/bucket/").is_err());
        assert!(parse_copy_source("bucket/").is_err());
        assert!(parse_copy_source("/%2Fkey").is_err());
        assert!(parse_copy_source("//bucket/key").is_err());
        assert!(parse_copy_source("///bucket/key").is_err());
    }

    #[test]
    fn parse_copy_source_extracts_version_id() {
        let parsed = parse_copy_source("/src-bucket/path.txt?versionId=ver-1").unwrap();
        assert_eq!(parsed.bucket, "src-bucket");
        assert_eq!(parsed.key, "path.txt");
        assert_eq!(parsed.version_id.as_deref(), Some("ver-1"));
    }

    #[test]
    fn parse_copy_source_rejects_duplicate_or_empty_version_id() {
        assert!(parse_copy_source("/src-bucket/path.txt?versionId=").is_err());
        assert!(parse_copy_source("/src-bucket/path.txt?versionId=one&versionId=two").is_err());
    }

    #[test]
    fn parse_metadata_directive_defaults_and_accepts_case_insensitive_values() {
        assert_eq!(
            parse_metadata_directive(None).unwrap(),
            MetadataDirective::Copy
        );
        assert_eq!(
            parse_metadata_directive(Some("copy")).unwrap(),
            MetadataDirective::Copy
        );
        assert_eq!(
            parse_metadata_directive(Some(" RePlAcE ")).unwrap(),
            MetadataDirective::Replace
        );
    }

    #[test]
    fn parse_metadata_directive_rejects_unknown_values() {
        assert!(parse_metadata_directive(Some("invalid")).is_err());
    }

    #[test]
    fn parse_delete_objects_request_extracts_keys_in_order() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
            <Delete>
              <Object><Key>a.txt</Key></Object>
              <Object><Key>nested/path/b.txt</Key></Object>
              <Object><Key>with&amp;escaped.xml</Key></Object>
            </Delete>"#;
        let request = parse_delete_objects_request(xml).unwrap();
        assert_eq!(
            request.keys,
            vec![
                "a.txt".to_string(),
                "nested/path/b.txt".to_string(),
                "with&escaped.xml".to_string()
            ]
        );
    }

    #[test]
    fn parse_delete_objects_request_malformed_xml_fails() {
        let xml = "<Delete><Object><Key>bad</Object></Delete>";
        assert!(parse_delete_objects_request(xml).is_err());
    }

    #[test]
    fn parse_delete_objects_request_invalid_escaped_text_fails() {
        let xml = r#"<Delete><Object><Key>bad&amp</Key></Object></Delete>"#;
        assert!(parse_delete_objects_request(xml).is_err());
    }

    #[test]
    fn parse_delete_objects_request_empty_payload_is_ok() {
        let xml = "<Delete></Delete>";
        let request = parse_delete_objects_request(xml).unwrap();
        assert!(request.keys.is_empty());
    }

    #[test]
    fn parse_delete_objects_request_extracts_quiet_flag() {
        let xml = r#"<Delete>
          <Quiet>true</Quiet>
          <Object><Key>a.txt</Key></Object>
        </Delete>"#;
        let request = parse_delete_objects_request(xml).unwrap();
        assert_eq!(request.keys, vec!["a.txt".to_string()]);
        assert!(request.quiet);
    }

    #[test]
    fn parse_delete_objects_request_defaults_quiet_false() {
        let xml = r#"<Delete><Object><Key>a.txt</Key></Object></Delete>"#;
        let request = parse_delete_objects_request(xml).unwrap();
        assert!(!request.quiet);
    }

    #[test]
    fn parse_delete_objects_request_treats_non_true_quiet_as_false() {
        let xml = r#"<Delete><Quiet>FALSE</Quiet><Object><Key>a.txt</Key></Object></Delete>"#;
        let request = parse_delete_objects_request(xml).unwrap();
        assert!(!request.quiet);
    }

    #[test]
    fn parse_delete_objects_request_rejects_more_than_1000_keys() {
        let mut xml = String::from("<Delete>");
        for i in 0..1001 {
            xml.push_str(&format!("<Object><Key>k-{i}</Key></Object>"));
        }
        xml.push_str("</Delete>");
        assert!(parse_delete_objects_request(&xml).is_err());
    }

    #[test]
    fn parse_delete_objects_request_requires_delete_root() {
        let xml = r#"<NotDelete><Object><Key>a.txt</Key></Object></NotDelete>"#;
        assert!(parse_delete_objects_request(xml).is_err());
    }

    #[test]
    fn parse_delete_objects_request_rejects_key_outside_object() {
        let xml = r#"<Delete><Key>a.txt</Key></Delete>"#;
        assert!(parse_delete_objects_request(xml).is_err());
    }
}
