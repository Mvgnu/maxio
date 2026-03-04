use axum::body::Body;
use axum::http::StatusCode;
use axum::response::Response;
use http::HeaderMap;
use serde::Serialize;

use super::service::ListMetadataCoverage;
use crate::error::S3Error;
use crate::xml::response::to_xml;

const METADATA_COVERAGE_COMPLETE_HEADER: &str = "x-maxio-metadata-coverage-complete";
const METADATA_COVERAGE_EXPECTED_HEADER: &str = "x-maxio-metadata-coverage-expected-nodes";
const METADATA_COVERAGE_RESPONDED_HEADER: &str = "x-maxio-metadata-coverage-responded-nodes";
const METADATA_COVERAGE_MISSING_HEADER: &str = "x-maxio-metadata-coverage-missing-nodes";
const METADATA_COVERAGE_UNEXPECTED_HEADER: &str = "x-maxio-metadata-coverage-unexpected-nodes";
const METADATA_COVERAGE_SOURCE_HEADER: &str = "x-maxio-metadata-coverage-source";
const METADATA_COVERAGE_SNAPSHOT_ID_HEADER: &str = "x-maxio-metadata-coverage-snapshot-id";
const METADATA_COVERAGE_STRATEGY_CLUSTER_AUTHORITATIVE_HEADER: &str =
    "x-maxio-metadata-coverage-strategy-cluster-authoritative";
const METADATA_COVERAGE_STRATEGY_READY_HEADER: &str = "x-maxio-metadata-coverage-strategy-ready";
const METADATA_COVERAGE_STRATEGY_GAP_HEADER: &str = "x-maxio-metadata-coverage-strategy-gap";

fn xml_string_response(status: StatusCode, xml: String) -> Result<Response<Body>, S3Error> {
    Response::builder()
        .status(status)
        .header("content-type", "application/xml")
        .body(Body::from(xml))
        .map_err(S3Error::internal)
}

pub(super) fn xml_response<T: Serialize>(
    status: StatusCode,
    payload: &T,
) -> Result<Response<Body>, S3Error> {
    let xml = to_xml(payload).map_err(S3Error::internal)?;
    xml_string_response(status, xml)
}

pub(super) fn bucket_location_response(region: &str) -> Result<Response<Body>, S3Error> {
    let escaped_region = quick_xml::escape::escape(region);
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <LocationConstraint>{}</LocationConstraint>",
        escaped_region
    );
    xml_string_response(StatusCode::OK, xml)
}

pub(super) fn apply_metadata_coverage_headers(
    headers: &mut HeaderMap,
    coverage: Option<&ListMetadataCoverage>,
) {
    let Some(coverage) = coverage else {
        return;
    };

    headers.insert(
        METADATA_COVERAGE_COMPLETE_HEADER,
        http::HeaderValue::from_static(if coverage.complete { "true" } else { "false" }),
    );
    insert_usize_header(
        headers,
        METADATA_COVERAGE_EXPECTED_HEADER,
        coverage.expected_nodes,
    );
    insert_usize_header(
        headers,
        METADATA_COVERAGE_RESPONDED_HEADER,
        coverage.responded_nodes,
    );
    insert_usize_header(
        headers,
        METADATA_COVERAGE_MISSING_HEADER,
        coverage.missing_nodes,
    );
    insert_usize_header(
        headers,
        METADATA_COVERAGE_UNEXPECTED_HEADER,
        coverage.unexpected_nodes,
    );
    headers.insert(
        METADATA_COVERAGE_SOURCE_HEADER,
        http::HeaderValue::from_static(coverage.source),
    );
    if let Ok(snapshot_id) = http::HeaderValue::from_str(coverage.snapshot_id.as_str()) {
        headers.insert(METADATA_COVERAGE_SNAPSHOT_ID_HEADER, snapshot_id);
    }
    headers.insert(
        METADATA_COVERAGE_STRATEGY_CLUSTER_AUTHORITATIVE_HEADER,
        http::HeaderValue::from_static(if coverage.strategy_cluster_authoritative {
            "true"
        } else {
            "false"
        }),
    );
    headers.insert(
        METADATA_COVERAGE_STRATEGY_READY_HEADER,
        http::HeaderValue::from_static(if coverage.strategy_ready {
            "true"
        } else {
            "false"
        }),
    );
    if let Some(gap) = coverage.strategy_gap {
        headers.insert(
            METADATA_COVERAGE_STRATEGY_GAP_HEADER,
            http::HeaderValue::from_static(gap),
        );
    }
}

fn insert_usize_header(headers: &mut HeaderMap, name: &'static str, value: usize) {
    if let Ok(parsed) = http::HeaderValue::from_str(value.to_string().as_str()) {
        headers.insert(name, parsed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::types::VersioningConfiguration;
    use axum::body::to_bytes;
    use http::header;

    #[test]
    fn xml_response_sets_content_type_and_status() {
        let payload = VersioningConfiguration {
            status: Some("Enabled".to_string()),
        };
        let response = xml_response(StatusCode::OK, &payload).expect("xml response should build");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/xml")
        );
    }

    #[tokio::test]
    async fn bucket_location_response_escapes_region_xml() {
        let response = bucket_location_response("eu-1<&>").expect("response should build");
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should be readable");
        let body = String::from_utf8(body.to_vec()).expect("body should be utf-8");
        assert!(body.contains("<LocationConstraint>eu-1&lt;&amp;&gt;</LocationConstraint>"));
    }

    #[test]
    fn apply_metadata_coverage_headers_sets_distributed_diagnostics() {
        let mut headers = HeaderMap::new();
        let coverage = ListMetadataCoverage {
            expected_nodes: 3,
            responded_nodes: 1,
            missing_nodes: 2,
            unexpected_nodes: 1,
            complete: false,
            snapshot_id: "a".repeat(64),
            source: "local-node-only",
            strategy_cluster_authoritative: false,
            strategy_ready: false,
            strategy_gap: Some("strategy-not-cluster-authoritative"),
            strategy_reject_reason: None,
        };

        apply_metadata_coverage_headers(&mut headers, Some(&coverage));

        assert_eq!(
            headers
                .get(METADATA_COVERAGE_COMPLETE_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some("false")
        );
        assert_eq!(
            headers
                .get(METADATA_COVERAGE_EXPECTED_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some("3")
        );
        assert_eq!(
            headers
                .get(METADATA_COVERAGE_RESPONDED_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some("1")
        );
        assert_eq!(
            headers
                .get(METADATA_COVERAGE_MISSING_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some("2")
        );
        assert_eq!(
            headers
                .get(METADATA_COVERAGE_UNEXPECTED_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some("1")
        );
        assert_eq!(
            headers
                .get(METADATA_COVERAGE_SOURCE_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some("local-node-only")
        );
        assert_eq!(
            headers
                .get(METADATA_COVERAGE_SNAPSHOT_ID_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some(coverage.snapshot_id.as_str())
        );
        assert_eq!(
            headers
                .get(METADATA_COVERAGE_STRATEGY_CLUSTER_AUTHORITATIVE_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some("false")
        );
        assert_eq!(
            headers
                .get(METADATA_COVERAGE_STRATEGY_READY_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some("false")
        );
        assert_eq!(
            headers
                .get(METADATA_COVERAGE_STRATEGY_GAP_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some("strategy-not-cluster-authoritative")
        );
    }

    #[test]
    fn apply_metadata_coverage_headers_noop_without_coverage() {
        let mut headers = HeaderMap::new();
        apply_metadata_coverage_headers(&mut headers, None);
        assert!(headers.is_empty());
    }
}
