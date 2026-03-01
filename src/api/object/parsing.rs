use crate::error::S3Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DeleteObjectsRequest {
    pub keys: Vec<String>,
    pub quiet: bool,
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

pub(super) fn parse_copy_source(copy_source: &str) -> Result<(String, String), S3Error> {
    let decoded = percent_encoding::percent_decode_str(copy_source)
        .decode_utf8()
        .map_err(|_| S3Error::invalid_argument("invalid x-amz-copy-source encoding"))?;
    let trimmed = decoded.trim_start_matches('/');
    let (src_bucket, src_key) = trimmed
        .split_once('/')
        .ok_or_else(|| S3Error::invalid_argument("invalid x-amz-copy-source format"))?;
    Ok((src_bucket.to_string(), src_key.to_string()))
}

pub(super) fn parse_delete_objects_request(xml: &str) -> Result<DeleteObjectsRequest, S3Error> {
    let mut keys = Vec::new();
    let mut quiet = false;
    let mut reader = quick_xml::Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut in_key = false;
    let mut in_quiet = false;

    loop {
        match reader.read_event() {
            Ok(quick_xml::events::Event::Start(e)) if e.name().as_ref() == b"Key" => {
                in_key = true;
            }
            Ok(quick_xml::events::Event::Start(e)) if e.name().as_ref() == b"Quiet" => {
                in_quiet = true;
            }
            Ok(quick_xml::events::Event::Text(e)) if in_key => {
                keys.push(e.unescape().unwrap_or_default().into_owned());
                in_key = false;
            }
            Ok(quick_xml::events::Event::Text(e)) if in_quiet => {
                quiet = e
                    .unescape()
                    .unwrap_or_default()
                    .as_ref()
                    .trim()
                    .eq_ignore_ascii_case("true");
                in_quiet = false;
            }
            Ok(quick_xml::events::Event::End(e)) if e.name().as_ref() == b"Key" => {
                in_key = false;
            }
            Ok(quick_xml::events::Event::End(e)) if e.name().as_ref() == b"Quiet" => {
                in_quiet = false;
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Err(_) => return Err(S3Error::malformed_xml()),
            _ => {}
        }
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
        let (bucket, key) = parse_copy_source("/src-bucket/path%20with%20space.txt").unwrap();
        assert_eq!(bucket, "src-bucket");
        assert_eq!(key, "path with space.txt");

        let (bucket, key) = parse_copy_source("src-bucket/no-leading-slash.txt").unwrap();
        assert_eq!(bucket, "src-bucket");
        assert_eq!(key, "no-leading-slash.txt");
    }

    #[test]
    fn parse_copy_source_rejects_invalid_input() {
        assert!(parse_copy_source("missing-delimiter").is_err());
        assert!(parse_copy_source("/bucket/%FF").is_err());
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
}
