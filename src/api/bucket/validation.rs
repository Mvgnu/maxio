use crate::error::S3Error;
use crate::storage::lifecycle::LifecycleRule as StorageLifecycleRule;
use crate::xml::types::{
    LifecycleConfiguration, LifecycleExpiration, LifecycleFilter, LifecycleRule as XmlLifecycleRule,
};

pub(super) fn validate_bucket_name(name: &str) -> Result<(), S3Error> {
    if name.len() < 3 || name.len() > 63 {
        return Err(S3Error::invalid_bucket_name(name));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.')
    {
        return Err(S3Error::invalid_bucket_name(name));
    }
    if !name.as_bytes()[0].is_ascii_alphanumeric()
        || !name.as_bytes()[name.len() - 1].is_ascii_alphanumeric()
    {
        return Err(S3Error::invalid_bucket_name(name));
    }
    Ok(())
}

pub(super) fn parse_versioning_status(xml: &str) -> Result<bool, S3Error> {
    let mut reader = quick_xml::Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut in_status = false;
    let mut status: Option<String> = None;

    loop {
        match reader.read_event() {
            Ok(quick_xml::events::Event::Start(e)) if e.name().as_ref() == b"Status" => {
                in_status = true;
            }
            Ok(quick_xml::events::Event::Text(e)) if in_status => {
                let value = e
                    .unescape()
                    .map_err(|_| S3Error::malformed_xml())?
                    .into_owned();
                status = Some(value);
                in_status = false;
            }
            Ok(quick_xml::events::Event::End(e)) if e.name().as_ref() == b"Status" => {
                in_status = false;
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Err(_) => return Err(S3Error::malformed_xml()),
            _ => {}
        }
    }

    match status.as_deref() {
        Some("Enabled") => Ok(true),
        Some("Suspended") => Ok(false),
        Some(_) => Err(S3Error::invalid_argument(
            "Versioning Status must be Enabled or Suspended",
        )),
        None => Err(S3Error::malformed_xml()),
    }
}

pub(super) fn parse_lifecycle_rules(xml: &str) -> Result<Vec<StorageLifecycleRule>, S3Error> {
    let parsed: LifecycleConfiguration =
        quick_xml::de::from_str(xml).map_err(|_| S3Error::malformed_xml())?;

    parsed
        .rules
        .into_iter()
        .enumerate()
        .map(|(idx, rule)| {
            let enabled = match rule.status.as_str() {
                "Enabled" => true,
                "Disabled" => false,
                _ => {
                    return Err(S3Error::invalid_argument(
                        "Lifecycle rule Status must be Enabled or Disabled",
                    ));
                }
            };

            let id = match rule.id {
                Some(id) if !id.trim().is_empty() => id,
                Some(_) => {
                    return Err(S3Error::invalid_argument(
                        "Lifecycle rule ID must not be empty",
                    ));
                }
                None => format!("rule-{}", idx + 1),
            };

            let prefix = rule
                .filter
                .and_then(|f| f.prefix)
                .or(rule.prefix)
                .unwrap_or_default();

            Ok(StorageLifecycleRule {
                id,
                prefix,
                expiration_days: rule.expiration.days,
                enabled,
            })
        })
        .collect()
}

pub(super) fn serialize_lifecycle_rules(
    rules: Vec<StorageLifecycleRule>,
) -> LifecycleConfiguration {
    LifecycleConfiguration {
        rules: rules
            .into_iter()
            .map(|rule| XmlLifecycleRule {
                id: Some(rule.id),
                status: if rule.enabled {
                    "Enabled".to_string()
                } else {
                    "Disabled".to_string()
                },
                filter: Some(LifecycleFilter {
                    prefix: Some(rule.prefix),
                }),
                prefix: None,
                expiration: LifecycleExpiration {
                    days: rule.expiration_days,
                },
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_name_validation_accepts_valid_name() {
        assert!(validate_bucket_name("valid-bucket-123").is_ok());
    }

    #[test]
    fn bucket_name_validation_rejects_invalid_name() {
        assert!(validate_bucket_name("Abc").is_err());
        assert!(validate_bucket_name("ab").is_err());
        assert!(validate_bucket_name("-abc").is_err());
        assert!(validate_bucket_name("abc-").is_err());
        assert!(validate_bucket_name("abc_123").is_err());
    }

    #[test]
    fn parse_versioning_status_enabled() {
        let xml = "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>";
        assert!(parse_versioning_status(xml).unwrap());
    }

    #[test]
    fn parse_versioning_status_suspended() {
        let xml = "<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>";
        assert!(!parse_versioning_status(xml).unwrap());
    }

    #[test]
    fn parse_versioning_status_invalid_value() {
        let xml = "<VersioningConfiguration><Status>Invalid</Status></VersioningConfiguration>";
        assert!(parse_versioning_status(xml).is_err());
    }

    #[test]
    fn parse_versioning_status_missing_status() {
        let xml = "<VersioningConfiguration></VersioningConfiguration>";
        assert!(parse_versioning_status(xml).is_err());
    }

    #[test]
    fn parse_lifecycle_rules_valid() {
        let xml = r#"
            <LifecycleConfiguration>
              <Rule>
                <ID>expire-logs</ID>
                <Status>Enabled</Status>
                <Filter><Prefix>logs/</Prefix></Filter>
                <Expiration><Days>7</Days></Expiration>
              </Rule>
            </LifecycleConfiguration>
        "#;
        let rules = parse_lifecycle_rules(xml).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "expire-logs");
        assert_eq!(rules[0].prefix, "logs/");
        assert_eq!(rules[0].expiration_days, 7);
        assert!(rules[0].enabled);
    }

    #[test]
    fn parse_lifecycle_rules_allows_legacy_prefix() {
        let xml = r#"
            <LifecycleConfiguration>
              <Rule>
                <Status>Disabled</Status>
                <Prefix>tmp/</Prefix>
                <Expiration><Days>3</Days></Expiration>
              </Rule>
            </LifecycleConfiguration>
        "#;
        let rules = parse_lifecycle_rules(xml).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "rule-1");
        assert_eq!(rules[0].prefix, "tmp/");
        assert_eq!(rules[0].expiration_days, 3);
        assert!(!rules[0].enabled);
    }

    #[test]
    fn parse_lifecycle_rules_rejects_invalid_status() {
        let xml = r#"
            <LifecycleConfiguration>
              <Rule>
                <ID>rule1</ID>
                <Status>Suspended</Status>
                <Expiration><Days>3</Days></Expiration>
              </Rule>
            </LifecycleConfiguration>
        "#;
        assert!(parse_lifecycle_rules(xml).is_err());
    }

    #[test]
    fn serialize_lifecycle_rules_maps_status_and_filter() {
        let serialized = serialize_lifecycle_rules(vec![StorageLifecycleRule {
            id: "expire-cache".to_string(),
            prefix: "cache/".to_string(),
            expiration_days: 14,
            enabled: true,
        }]);
        assert_eq!(serialized.rules.len(), 1);
        assert_eq!(serialized.rules[0].id.as_deref(), Some("expire-cache"));
        assert_eq!(serialized.rules[0].status, "Enabled");
        assert_eq!(
            serialized.rules[0]
                .filter
                .as_ref()
                .and_then(|f| f.prefix.as_deref()),
            Some("cache/")
        );
        assert_eq!(serialized.rules[0].expiration.days, 14);
    }
}
