use axum::response::{IntoResponse, Response};
use http::StatusCode;

#[derive(Debug)]
pub struct S3Error {
    pub code: S3ErrorCode,
    pub message: String,
    pub resource: Option<String>,
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum S3ErrorCode {
    AccessDenied,
    BadDigest,
    BucketAlreadyOwnedByYou,
    BucketNotEmpty,
    InternalError,
    InvalidAccessKeyId,
    InvalidArgument,
    InvalidBucketName,
    InvalidPart,
    MalformedXML,
    NoSuchBucket,
    NoSuchKey,
    NoSuchUpload,
    NoSuchVersion,
    NoSuchLifecycleConfiguration,
    InvalidRange,
    NotImplemented,
    EntityTooSmall,
    ExpiredPresignedUrl,
    SignatureDoesNotMatch,
    ServiceUnavailable,
}

impl S3ErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AccessDenied => "AccessDenied",
            Self::BadDigest => "BadDigest",
            Self::BucketAlreadyOwnedByYou => "BucketAlreadyOwnedByYou",
            Self::BucketNotEmpty => "BucketNotEmpty",
            Self::InternalError => "InternalError",
            Self::InvalidAccessKeyId => "InvalidAccessKeyId",
            Self::InvalidArgument => "InvalidArgument",
            Self::InvalidBucketName => "InvalidBucketName",
            Self::InvalidPart => "InvalidPart",
            Self::MalformedXML => "MalformedXML",
            Self::NoSuchBucket => "NoSuchBucket",
            Self::NoSuchKey => "NoSuchKey",
            Self::NoSuchUpload => "NoSuchUpload",
            Self::NoSuchVersion => "NoSuchVersion",
            Self::NoSuchLifecycleConfiguration => "NoSuchLifecycleConfiguration",
            Self::InvalidRange => "InvalidRange",
            Self::NotImplemented => "NotImplemented",
            Self::EntityTooSmall => "EntityTooSmall",
            Self::ExpiredPresignedUrl => "AccessDenied",
            Self::SignatureDoesNotMatch => "SignatureDoesNotMatch",
            Self::ServiceUnavailable => "ServiceUnavailable",
        }
    }

    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::AccessDenied
            | Self::ExpiredPresignedUrl
            | Self::InvalidAccessKeyId
            | Self::SignatureDoesNotMatch => StatusCode::FORBIDDEN,
            Self::NoSuchBucket
            | Self::NoSuchKey
            | Self::NoSuchUpload
            | Self::NoSuchVersion
            | Self::NoSuchLifecycleConfiguration => StatusCode::NOT_FOUND,
            Self::BucketAlreadyOwnedByYou | Self::BucketNotEmpty => StatusCode::CONFLICT,
            Self::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
            Self::InvalidRange => StatusCode::RANGE_NOT_SATISFIABLE,
            Self::NotImplemented => StatusCode::NOT_IMPLEMENTED,
            Self::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::BAD_REQUEST,
        }
    }
}

impl S3Error {
    pub fn internal(err: impl std::fmt::Display) -> Self {
        tracing::error!("Internal error: {}", err);
        Self {
            code: S3ErrorCode::InternalError,
            message: "We encountered an internal error. Please try again.".into(),
            resource: None,
        }
    }

    pub fn no_such_bucket(bucket: &str) -> Self {
        Self {
            code: S3ErrorCode::NoSuchBucket,
            message: format!("The specified bucket does not exist: {}", bucket),
            resource: Some(format!("/{}", bucket)),
        }
    }

    pub fn no_such_key(key: &str) -> Self {
        Self {
            code: S3ErrorCode::NoSuchKey,
            message: "The specified key does not exist.".into(),
            resource: Some(key.to_string()),
        }
    }

    pub fn no_such_upload(upload_id: &str) -> Self {
        Self {
            code: S3ErrorCode::NoSuchUpload,
            message: "The specified multipart upload does not exist.".into(),
            resource: Some(upload_id.to_string()),
        }
    }

    pub fn bucket_already_owned(bucket: &str) -> Self {
        Self {
            code: S3ErrorCode::BucketAlreadyOwnedByYou,
            message: format!(
                "Your previous request to create the named bucket succeeded and you already own it: {}",
                bucket
            ),
            resource: Some(format!("/{}", bucket)),
        }
    }

    pub fn bucket_not_empty(bucket: &str) -> Self {
        Self {
            code: S3ErrorCode::BucketNotEmpty,
            message: "The bucket you tried to delete is not empty.".into(),
            resource: Some(format!("/{}", bucket)),
        }
    }

    pub fn invalid_bucket_name(name: &str) -> Self {
        Self {
            code: S3ErrorCode::InvalidBucketName,
            message: format!("The specified bucket is not valid: {}", name),
            resource: Some(format!("/{}", name)),
        }
    }

    pub fn invalid_argument(msg: &str) -> Self {
        Self {
            code: S3ErrorCode::InvalidArgument,
            message: msg.to_string(),
            resource: None,
        }
    }

    pub fn bad_digest() -> Self {
        Self {
            code: S3ErrorCode::BadDigest,
            message: "The Content-MD5 you specified did not match what we received.".into(),
            resource: None,
        }
    }

    pub fn bad_checksum(algo: &str) -> Self {
        Self {
            code: S3ErrorCode::BadDigest,
            message: format!(
                "The {} checksum you specified did not match what we received.",
                algo
            ),
            resource: None,
        }
    }

    pub fn malformed_xml() -> Self {
        Self {
            code: S3ErrorCode::MalformedXML,
            message: "The XML you provided was not well-formed.".into(),
            resource: None,
        }
    }

    pub fn invalid_part(msg: &str) -> Self {
        Self {
            code: S3ErrorCode::InvalidPart,
            message: msg.to_string(),
            resource: None,
        }
    }

    pub fn entity_too_small() -> Self {
        Self {
            code: S3ErrorCode::EntityTooSmall,
            message: "Your proposed upload is smaller than the minimum allowed object size.".into(),
            resource: None,
        }
    }

    pub fn expired_presigned_url() -> Self {
        Self {
            code: S3ErrorCode::ExpiredPresignedUrl,
            message: "Request has expired".into(),
            resource: None,
        }
    }

    pub fn access_denied(msg: &str) -> Self {
        Self {
            code: S3ErrorCode::AccessDenied,
            message: msg.to_string(),
            resource: None,
        }
    }

    pub fn service_unavailable(msg: &str) -> Self {
        Self {
            code: S3ErrorCode::ServiceUnavailable,
            message: msg.to_string(),
            resource: None,
        }
    }

    pub fn signature_mismatch() -> Self {
        Self {
            code: S3ErrorCode::SignatureDoesNotMatch,
            message:
                "The request signature we calculated does not match the signature you provided."
                    .into(),
            resource: None,
        }
    }

    pub fn invalid_access_key() -> Self {
        Self {
            code: S3ErrorCode::InvalidAccessKeyId,
            message: "The AWS Access Key Id you provided does not exist in our records.".into(),
            resource: None,
        }
    }

    pub fn no_such_version(version_id: &str) -> Self {
        Self {
            code: S3ErrorCode::NoSuchVersion,
            message: "The specified version does not exist.".into(),
            resource: Some(version_id.to_string()),
        }
    }

    pub fn no_such_lifecycle_configuration(bucket: &str) -> Self {
        Self {
            code: S3ErrorCode::NoSuchLifecycleConfiguration,
            message: "The lifecycle configuration does not exist.".into(),
            resource: Some(format!("/{}", bucket)),
        }
    }

    pub fn invalid_range() -> Self {
        Self {
            code: S3ErrorCode::InvalidRange,
            message: "The requested range is not satisfiable".into(),
            resource: None,
        }
    }

    pub fn not_implemented(msg: &str) -> Self {
        Self {
            code: S3ErrorCode::NotImplemented,
            message: msg.to_string(),
            resource: None,
        }
    }
}

impl IntoResponse for S3Error {
    fn into_response(self) -> Response {
        let resource = self.resource.as_deref().unwrap_or("");
        let request_id = uuid::Uuid::new_v4();
        let xml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <Error>\
             <Code>{}</Code>\
             <Message>{}</Message>\
             <Resource>{}</Resource>\
             <RequestId>{}</RequestId>\
             </Error>",
            self.code.as_str(),
            quick_xml::escape::escape(&self.message),
            quick_xml::escape::escape(resource),
            request_id,
        );

        let status = self.code.status_code();
        (
            status,
            [
                ("content-type", "application/xml"),
                ("x-amz-request-id", &request_id.to_string()),
            ],
            xml,
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::{S3Error, S3ErrorCode};
    use axum::body::to_bytes;
    use axum::response::IntoResponse;
    use http::StatusCode;

    #[test]
    fn error_code_status_mapping_matches_contract() {
        assert_eq!(
            S3ErrorCode::AccessDenied.status_code(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            S3ErrorCode::InvalidAccessKeyId.status_code(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            S3ErrorCode::SignatureDoesNotMatch.status_code(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            S3ErrorCode::NoSuchLifecycleConfiguration.status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            S3ErrorCode::BucketNotEmpty.status_code(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            S3ErrorCode::InvalidRange.status_code(),
            StatusCode::RANGE_NOT_SATISFIABLE
        );
        assert_eq!(
            S3ErrorCode::ServiceUnavailable.status_code(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn expired_presigned_url_maps_to_access_denied_code() {
        let err = S3Error::expired_presigned_url();
        assert_eq!(err.code.as_str(), "AccessDenied");
        assert_eq!(err.code.status_code(), StatusCode::FORBIDDEN);
        assert_eq!(err.message, "Request has expired");
    }

    #[tokio::test]
    async fn into_response_emits_xml_with_escaped_fields_and_request_id() {
        let err = S3Error {
            code: S3ErrorCode::InvalidArgument,
            message: "bad <input> & bad output".to_string(),
            resource: Some("/bucket/<key>&".to_string()),
        };

        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/xml")
        );

        let request_id = response
            .headers()
            .get("x-amz-request-id")
            .and_then(|v| v.to_str().ok())
            .expect("missing request id header");
        uuid::Uuid::parse_str(request_id).expect("request id should be a valid uuid");

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("<Code>InvalidArgument</Code>"));
        assert!(body.contains("<Message>bad &lt;input&gt; &amp; bad output</Message>"));
        assert!(body.contains("<Resource>/bucket/&lt;key&gt;&amp;</Resource>"));
        assert!(body.contains("<RequestId>"));
    }
}
