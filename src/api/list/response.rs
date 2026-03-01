use axum::body::Body;
use axum::http::StatusCode;
use axum::response::Response;
use serde::Serialize;

use crate::error::S3Error;
use crate::xml::response::to_xml;

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
}
