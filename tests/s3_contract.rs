//! Real HTTP regressions for response framing and conditional-write safety.
#[allow(dead_code)]
#[path = "integration/helpers.rs"]
mod helpers;

use reqwest::{Method, Response, StatusCode};

const QUERY_ENCODE: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

#[derive(serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListingPage {
    is_truncated: bool,
    next_continuation_token: Option<String>,
    next_marker: Option<String>,
    #[serde(default)]
    contents: Vec<ListingObject>,
    #[serde(default)]
    common_prefixes: Vec<ListingPrefix>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListingObject {
    key: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListingPrefix {
    prefix: String,
}

async fn request(
    base: &str,
    method: Method,
    path: &str,
    body: &[u8],
    extra: &[(&str, &str)],
) -> Response {
    let url = format!("{base}{path}");
    let mut headers = extra
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    helpers::sign_request(method.as_str(), &url, &mut headers, body);
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    let mut req = client.request(method, url).body(body.to_vec());
    for (key, value) in headers {
        req = req.header(key, value);
    }
    req.send().await.unwrap()
}

async fn server() -> (String, tempfile::TempDir) {
    let tmp = tempfile::TempDir::new().unwrap();
    let config = helpers::make_test_config(tmp.path().to_str().unwrap().to_owned(), false, 1024, 0);
    let (base, tmp) = helpers::start_server_with_config(config, tmp).await;
    assert_eq!(
        request(&base, Method::PUT, "/contract", b"", &[])
            .await
            .status(),
        StatusCode::OK
    );
    (base, tmp)
}

#[tokio::test]
async fn put_response_has_empty_body_framing() {
    let (base, _tmp) = server().await;
    let result = request(
        &base,
        Method::PUT,
        "/contract/object",
        b"complete payload",
        &[],
    )
    .await;
    assert_eq!(result.status(), StatusCode::OK);
    assert_eq!(result.content_length(), Some(0));
    assert!(result.bytes().await.unwrap().is_empty());
}

#[tokio::test]
async fn conditional_put_preserves_current_value_and_returns_s3_error() {
    let (base, _tmp) = server().await;
    let initial = request(
        &base,
        Method::PUT,
        "/contract/object",
        b"original",
        &[("if-none-match", "*")],
    )
    .await;
    assert_eq!(initial.status(), StatusCode::OK);
    let etag = initial.headers()["etag"].to_str().unwrap().to_owned();
    assert_eq!(
        request(
            &base,
            Method::PUT,
            "/contract/object",
            b"overwrite",
            &[("if-none-match", "*")]
        )
        .await
        .status(),
        StatusCode::PRECONDITION_FAILED
    );
    let stale = request(
        &base,
        Method::PUT,
        "/contract/object",
        b"stale",
        &[("if-match", "\"not-current\"")],
    )
    .await;
    assert_eq!(stale.status(), StatusCode::PRECONDITION_FAILED);
    assert!(
        stale
            .text()
            .await
            .unwrap()
            .contains("<Code>PreconditionFailed</Code>")
    );
    assert_eq!(
        request(&base, Method::GET, "/contract/object", b"", &[])
            .await
            .bytes()
            .await
            .unwrap(),
        &b"original"[..]
    );
    assert_eq!(
        request(
            &base,
            Method::PUT,
            "/contract/object",
            b"updated",
            &[("if-match", &etag)]
        )
        .await
        .status(),
        StatusCode::OK
    );
    assert_eq!(
        request(
            &base,
            Method::PUT,
            "/contract/missing",
            b"wrong",
            &[("if-match", &etag)]
        )
        .await
        .status(),
        StatusCode::PRECONDITION_FAILED
    );
}

#[tokio::test]
async fn competing_conditional_writes_cannot_both_win() {
    let (base, _tmp) = server().await;
    let initial = request(&base, Method::PUT, "/contract/object", b"base", &[]).await;
    let etag = initial.headers()["etag"].to_str().unwrap().to_owned();
    let conditions = [("if-match", etag.as_str())];
    let (a, b) = tokio::join!(
        request(
            &base,
            Method::PUT,
            "/contract/object",
            b"device-a",
            &conditions
        ),
        request(
            &base,
            Method::PUT,
            "/contract/object",
            b"device-b",
            &conditions
        )
    );
    let mut statuses = [a.status().as_u16(), b.status().as_u16()];
    statuses.sort();
    assert_eq!(statuses, [200, 412]);
}

#[tokio::test]
async fn unsupported_conditions_are_rejected_before_mutation() {
    let (base, _tmp) = server().await;
    assert_eq!(
        request(&base, Method::PUT, "/contract/object", b"base", &[])
            .await
            .status(),
        StatusCode::OK
    );
    for condition in [
        ("if-match", "\"never-this-etag\""),
        ("if-none-match", "*"),
        ("x-amz-if-match-size", "999"),
        (
            "x-amz-if-match-last-modified-time",
            "Wed, 21 Oct 2015 07:28:00 GMT",
        ),
    ] {
        let response = request(&base, Method::DELETE, "/contract/object", b"", &[condition]).await;
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        assert!(
            response
                .text()
                .await
                .unwrap()
                .contains("<Code>NotImplemented</Code>")
        );
    }
    let delete_body = b"<Delete><Object><Key>object</Key></Object></Delete>";
    assert_eq!(
        request(
            &base,
            Method::POST,
            "/contract?delete",
            delete_body,
            &[("if-match", "\"never-this-etag\"")]
        )
        .await
        .status(),
        StatusCode::NOT_IMPLEMENTED
    );
    for selector in ["ETag", "LastModifiedTime", "Size", "VersionId"] {
        let body = format!(
            "<Delete><Object><Key>object</Key><{selector}>stale</{selector}></Object></Delete>"
        );
        assert_eq!(
            request(
                &base,
                Method::POST,
                "/contract?delete",
                body.as_bytes(),
                &[]
            )
            .await
            .status(),
            StatusCode::NOT_IMPLEMENTED,
            "must not ignore {selector}"
        );
    }
    assert_eq!(
        request(&base, Method::GET, "/contract/object", b"", &[])
            .await
            .bytes()
            .await
            .unwrap(),
        &b"base"[..]
    );
    let copy = [
        ("x-amz-copy-source", "/contract/object"),
        ("if-none-match", "*"),
    ];
    assert_eq!(
        request(&base, Method::PUT, "/contract/copied", b"", &copy)
            .await
            .status(),
        StatusCode::NOT_IMPLEMENTED
    );
    assert_eq!(
        request(
            &base,
            Method::POST,
            "/contract/object?uploadId=missing",
            b"<CompleteMultipartUpload/>",
            &[("if-none-match", "*")]
        )
        .await
        .status(),
        StatusCode::NOT_IMPLEMENTED
    );
    assert_eq!(
        request(
            &base,
            Method::PUT,
            "/contract/object",
            b"bad",
            &[("if-none-match", "*"), ("if-match", "\"anything\"")]
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
}

async fn assert_retention_unsupported(response: Response, context: &str) {
    let status = response.status();
    let body = response.text().await.unwrap();
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "{context}: {body}");
    assert!(
        body.contains("<Code>NotImplemented</Code>"),
        "{context}: {body}"
    );
}

#[tokio::test]
async fn unsupported_retention_put_preserves_existing_bytes_and_version_history() {
    let (base, _tmp) = server().await;
    assert_eq!(
        request(
            &base,
            Method::PUT,
            "/contract?versioning",
            b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
            &[]
        )
        .await
        .status(),
        StatusCode::OK
    );
    let initial = request(&base, Method::PUT, "/contract/object", b"original", &[]).await;
    assert_eq!(initial.status(), StatusCode::OK);
    let version = initial.headers()["x-amz-version-id"]
        .to_str()
        .unwrap()
        .to_owned();
    let before = request(&base, Method::GET, "/contract?versions", b"", &[])
        .await
        .text()
        .await
        .unwrap();
    let retention = b"<Retention><Mode>COMPLIANCE</Mode><RetainUntilDate>2099-01-01T00:00:00Z</RetainUntilDate></Retention>";
    for subresource in ["retention", "legal-hold", "object-lock"] {
        let path = format!("/contract/object?{subresource}&versionId={version}");
        let response = request(&base, Method::PUT, &path, retention, &[]).await;
        // Check data first: the old dispatch silently writes retention XML as a new object.
        assert_eq!(
            request(&base, Method::GET, "/contract/object", b"", &[])
                .await
                .bytes()
                .await
                .unwrap(),
            &b"original"[..],
            "unsupported {subresource} replaced object bytes"
        );
        assert_retention_unsupported(response, subresource).await;
        for method in [Method::GET, Method::DELETE] {
            assert_retention_unsupported(
                request(&base, method, &path, b"", &[]).await,
                subresource,
            )
            .await;
        }
        assert_eq!(
            request(&base, Method::HEAD, &path, b"", &[]).await.status(),
            StatusCode::NOT_IMPLEMENTED
        );
    }
    assert_retention_unsupported(
        request(
            &base,
            Method::DELETE,
            &format!("/contract/object?versionId={version}"),
            b"",
            &[("x-amz-bypass-governance-retention", "true")],
        )
        .await,
        "version-specific retention bypass",
    )
    .await;
    assert_eq!(
        request(
            &base,
            Method::GET,
            &format!("/contract/object?versionId={version}"),
            b"",
            &[]
        )
        .await
        .bytes()
        .await
        .unwrap(),
        &b"original"[..]
    );
    assert_eq!(
        request(&base, Method::GET, "/contract?versions", b"", &[])
            .await
            .text()
            .await
            .unwrap(),
        before
    );
}

#[tokio::test]
async fn unsupported_retention_headers_cannot_put_copy_or_delete_objects() {
    let (base, _tmp) = server().await;
    assert_eq!(
        request(&base, Method::PUT, "/contract/object", b"original", &[])
            .await
            .status(),
        StatusCode::OK
    );
    let delete = b"<Delete><Object><Key>object</Key></Object></Delete>";
    assert_retention_unsupported(
        request(
            &base,
            Method::POST,
            "/contract?delete&retention",
            delete,
            &[],
        )
        .await,
        "batch delete retention query",
    )
    .await;
    for protection in [
        ("x-amz-object-lock-mode", "COMPLIANCE"),
        (
            "x-amz-object-lock-retain-until-date",
            "2099-01-01T00:00:00Z",
        ),
        ("x-amz-object-lock-legal-hold", "ON"),
        ("x-amz-object-lock-event-hold", "ON"),
        ("X-Amz-Object-Lock-Future-Setting", "enabled"),
        ("x-amz-bucket-object-lock-enabled", "true"),
        ("x-amz-bypass-governance-retention", "true"),
    ] {
        for (method, path, body) in [
            (Method::PUT, "/contract/object", &b"replacement"[..]),
            (Method::DELETE, "/contract/object", &b""[..]),
            (Method::POST, "/contract?delete", &delete[..]),
        ] {
            assert_retention_unsupported(
                request(&base, method, path, body, &[protection]).await,
                protection.0,
            )
            .await;
        }
        assert_retention_unsupported(
            request(
                &base,
                Method::PUT,
                "/contract/copied",
                b"",
                &[("x-amz-copy-source", "/contract/object"), protection],
            )
            .await,
            protection.0,
        )
        .await;
    }
    assert_eq!(
        request(&base, Method::GET, "/contract/object", b"", &[])
            .await
            .bytes()
            .await
            .unwrap(),
        &b"original"[..]
    );
    assert_eq!(
        request(&base, Method::HEAD, "/contract/copied", b"", &[])
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn unsupported_retention_bucket_requests_cannot_create_change_or_delete_buckets() {
    let (base, _tmp) = server().await;
    let before = request(&base, Method::GET, "/contract?versioning", b"", &[])
        .await
        .text()
        .await
        .unwrap();
    for subresource in ["object-lock", "retention", "legal-hold"] {
        assert_retention_unsupported(
            request(
                &base,
                Method::PUT,
                &format!("/uncreated?{subresource}"),
                b"<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>",
                &[],
            )
            .await,
            subresource,
        )
        .await;
        for method in [Method::GET, Method::DELETE] {
            assert_retention_unsupported(
                request(&base, method, &format!("/contract?{subresource}"), b"", &[]).await,
                subresource,
            )
            .await;
        }
        assert_retention_unsupported(
            request(
                &base,
                Method::PUT,
                &format!("/contract?versioning&{subresource}"),
                b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
                &[],
            )
            .await,
            subresource,
        )
        .await;
    }
    assert_retention_unsupported(
        request(
            &base,
            Method::PUT,
            "/uncreated",
            b"",
            &[("x-amz-bucket-object-lock-enabled", "true")],
        )
        .await,
        "CreateBucket Object Lock header",
    )
    .await;
    assert_eq!(
        request(&base, Method::HEAD, "/uncreated", b"", &[])
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        request(&base, Method::HEAD, "/contract", b"", &[])
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        request(&base, Method::GET, "/contract?versioning", b"", &[])
            .await
            .text()
            .await
            .unwrap(),
        before
    );
}

#[tokio::test]
async fn unsupported_retention_multipart_requests_preserve_upload_and_previous_object() {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct InitiatedUpload {
        upload_id: String,
    }
    let (base, _tmp) = server().await;
    assert_eq!(
        request(&base, Method::PUT, "/contract/object", b"original", &[])
            .await
            .status(),
        StatusCode::OK
    );
    let initiated = request(&base, Method::POST, "/contract/object?uploads", b"", &[]).await;
    assert_eq!(initiated.status(), StatusCode::OK);
    let initiated: InitiatedUpload =
        quick_xml::de::from_str(&initiated.text().await.unwrap()).unwrap();
    let upload_path = format!("/contract/object?uploadId={}", initiated.upload_id);
    let part_path = format!("{upload_path}&partNumber=1");
    let part = request(&base, Method::PUT, &part_path, b"complete part", &[]).await;
    assert_eq!(part.status(), StatusCode::OK);
    let etag = part.headers()["etag"].to_str().unwrap().to_owned();
    let complete = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part></CompleteMultipartUpload>"
    );
    let uploads_before = request(&base, Method::GET, "/contract?uploads", b"", &[])
        .await
        .text()
        .await
        .unwrap();
    let parts_before = request(&base, Method::GET, &upload_path, b"", &[])
        .await
        .text()
        .await
        .unwrap();
    for (query, headers) in [
        ("&retention", vec![]),
        ("&legal-hold", vec![]),
        ("&object-lock", vec![]),
        ("", vec![("x-amz-object-lock-mode", "COMPLIANCE")]),
        ("", vec![("x-amz-bypass-governance-retention", "true")]),
    ] {
        for (method, path, body) in [
            (Method::POST, "/contract/object?uploads", &b""[..]),
            (Method::PUT, part_path.as_str(), &b"wrong part"[..]),
            (Method::POST, upload_path.as_str(), complete.as_bytes()),
            (Method::DELETE, upload_path.as_str(), &b""[..]),
        ] {
            assert_retention_unsupported(
                request(&base, method, &format!("{path}{query}"), body, &headers).await,
                "multipart retention dispatch",
            )
            .await;
        }
    }
    assert_eq!(
        request(&base, Method::GET, "/contract?uploads", b"", &[])
            .await
            .text()
            .await
            .unwrap(),
        uploads_before
    );
    assert_eq!(
        request(&base, Method::GET, &upload_path, b"", &[])
            .await
            .text()
            .await
            .unwrap(),
        parts_before
    );
    assert_eq!(
        request(&base, Method::GET, "/contract/object", b"", &[])
            .await
            .bytes()
            .await
            .unwrap(),
        &b"original"[..]
    );
    assert_eq!(
        request(&base, Method::POST, &upload_path, complete.as_bytes(), &[])
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        request(&base, Method::GET, "/contract/object", b"", &[])
            .await
            .bytes()
            .await
            .unwrap(),
        &b"complete part"[..]
    );
}

#[tokio::test]
async fn distributed_conditional_write_fails_explicitly() {
    let tmp = tempfile::TempDir::new().unwrap();
    let mut config =
        helpers::make_test_config(tmp.path().to_str().unwrap().to_owned(), false, 1024, 0);
    config.node_id = "127.0.0.1:39001".into();
    config.cluster_peers = vec!["127.0.0.1:39002".into()];
    config.cluster_auth_token = Some("contract-test".into());
    let (base, _tmp) = helpers::start_server_with_config(config, tmp).await;
    assert_eq!(
        request(
            &base,
            Method::PUT,
            "/contract/object",
            b"x",
            &[("if-none-match", "*")]
        )
        .await
        .status(),
        StatusCode::NOT_IMPLEMENTED
    );
}

#[tokio::test]
async fn delimiter_pages_count_common_prefixes_once_and_resume_after_the_group() {
    let (base, _tmp) = server().await;
    for key in [
        "alpha.txt",
        "group-a/1",
        "group-a/2",
        "group-b/1",
        "group-b/2",
        "group-c/1",
        "group-c/2",
        "omega.txt",
    ] {
        assert_eq!(
            request(&base, Method::PUT, &format!("/contract/{key}"), b"x", &[])
                .await
                .status(),
            StatusCode::OK
        );
    }
    for version in [1, 2] {
        let mut all = Vec::new();
        let mut marker: Option<String> = None;
        let mut pages = 0;
        loop {
            let mut path = format!(
                "/contract?delimiter=%2F&max-keys=2{}",
                if version == 2 { "&list-type=2" } else { "" }
            );
            if let Some(marker) = &marker {
                path.push_str(&format!(
                    "&{}={}",
                    if version == 2 {
                        "continuation-token"
                    } else {
                        "marker"
                    },
                    percent_encoding::utf8_percent_encode(marker, QUERY_ENCODE)
                ));
            }
            let response = request(&base, Method::GET, &path, b"", &[]).await;
            assert_eq!(response.status(), StatusCode::OK);
            let page: ListingPage =
                quick_xml::de::from_str(&response.text().await.unwrap()).unwrap();
            let mut entries = page
                .contents
                .into_iter()
                .map(|o| o.key)
                .chain(page.common_prefixes.into_iter().map(|p| p.prefix))
                .collect::<Vec<_>>();
            entries.sort();
            assert!(entries.len() <= 2);
            all.extend(entries);
            pages += 1;
            if !page.is_truncated {
                break;
            }
            assert!(pages < 4, "a common prefix repeated instead of advancing");
            marker = if version == 2 {
                page.next_continuation_token
            } else {
                page.next_marker
            };
            assert!(marker.is_some());
        }
        assert_eq!(pages, 3);
        assert_eq!(
            all,
            ["alpha.txt", "group-a/", "group-b/", "group-c/", "omega.txt"]
        );
    }
    let response = request(
        &base,
        Method::GET,
        "/contract?list-type=2&delimiter=%2F&start-after=group-b%2F1",
        b"",
        &[],
    )
    .await;
    let page: ListingPage = quick_xml::de::from_str(&response.text().await.unwrap()).unwrap();
    assert_eq!(
        page.common_prefixes
            .into_iter()
            .map(|p| p.prefix)
            .collect::<Vec<_>>(),
        ["group-c/"]
    );
    assert_eq!(
        page.contents.into_iter().map(|o| o.key).collect::<Vec<_>>(),
        ["omega.txt"]
    );
}

#[tokio::test]
async fn version_listing_retains_null_after_generated_version_marker() {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct VersionPage {
        is_truncated: bool,
        next_key_marker: Option<String>,
        next_version_id_marker: Option<String>,
        #[serde(rename = "Version", default)]
        versions: Vec<Version>,
    }
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Version {
        version_id: String,
        is_latest: bool,
    }
    let (base, _tmp) = server().await;
    assert_eq!(
        request(&base, Method::PUT, "/contract/item", b"before-enable", &[])
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        request(
            &base,
            Method::PUT,
            "/contract?versioning",
            b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
            &[]
        )
        .await
        .status(),
        StatusCode::OK
    );
    let put = request(&base, Method::PUT, "/contract/item", b"after-enable", &[]).await;
    assert_eq!(put.status(), StatusCode::OK);
    let current_id = put.headers()["x-amz-version-id"]
        .to_str()
        .unwrap()
        .to_owned();
    let first = request(
        &base,
        Method::GET,
        "/contract?versions&max-keys=1",
        b"",
        &[],
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);
    let first: VersionPage = quick_xml::de::from_str(&first.text().await.unwrap()).unwrap();
    assert!(first.is_truncated);
    assert_eq!(first.versions.len(), 1);
    assert_eq!(first.versions[0].version_id, current_id);
    assert!(first.versions[0].is_latest);
    let path = format!(
        "/contract?versions&max-keys=1&key-marker={}&version-id-marker={}",
        first.next_key_marker.unwrap(),
        first.next_version_id_marker.unwrap()
    );
    let second = request(&base, Method::GET, &path, b"", &[]).await;
    assert_eq!(second.status(), StatusCode::OK);
    let second: VersionPage = quick_xml::de::from_str(&second.text().await.unwrap()).unwrap();
    assert!(!second.is_truncated);
    assert_eq!(second.versions.len(), 1);
    assert_eq!(second.versions[0].version_id, "null");
    assert!(!second.versions[0].is_latest);
    assert_eq!(
        request(
            &base,
            Method::GET,
            "/contract/item?versionId=null",
            b"",
            &[]
        )
        .await
        .bytes()
        .await
        .unwrap(),
        &b"before-enable"[..]
    );
}
