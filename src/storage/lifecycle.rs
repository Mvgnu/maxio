use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LifecycleRule {
    pub id: String,
    #[serde(default)]
    pub prefix: String,
    pub expiration_days: u32,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

pub fn validate_rules(rules: &[LifecycleRule]) -> Result<(), String> {
    let mut ids = HashSet::new();
    for rule in rules {
        if rule.id.trim().is_empty() {
            return Err("Lifecycle rule id must not be empty".to_string());
        }
        if !ids.insert(rule.id.as_str()) {
            return Err(format!("Duplicate lifecycle rule id: {}", rule.id));
        }
        if rule.expiration_days == 0 {
            return Err(format!(
                "Lifecycle rule {} must have expiration_days > 0",
                rule.id
            ));
        }
    }
    Ok(())
}

pub fn should_expire_object(
    key: &str,
    last_modified: &str,
    rules: &[LifecycleRule],
    now: DateTime<Utc>,
) -> bool {
    if key.ends_with('/') {
        return false;
    }

    let parsed = chrono::DateTime::parse_from_str(last_modified, "%Y-%m-%dT%H:%M:%S%.3fZ")
        .or_else(|_| chrono::DateTime::parse_from_rfc3339(last_modified))
        .ok()
        .map(|d| d.with_timezone(&Utc));

    let Some(last_modified_dt) = parsed else {
        return false;
    };

    let age_secs = now.signed_duration_since(last_modified_dt).num_seconds();
    if age_secs < 0 {
        return false;
    }

    rules.iter().any(|rule| {
        if !rule.enabled {
            return false;
        }
        if !key.starts_with(&rule.prefix) {
            return false;
        }
        age_secs >= (rule.expiration_days as i64) * 24 * 60 * 60
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn validate_rules_rejects_invalid_configurations() {
        let duplicate = vec![
            LifecycleRule {
                id: "rule-1".to_string(),
                prefix: "".to_string(),
                expiration_days: 7,
                enabled: true,
            },
            LifecycleRule {
                id: "rule-1".to_string(),
                prefix: "logs/".to_string(),
                expiration_days: 10,
                enabled: true,
            },
        ];
        assert!(validate_rules(&duplicate).is_err());

        let zero_days = vec![LifecycleRule {
            id: "rule-2".to_string(),
            prefix: "".to_string(),
            expiration_days: 0,
            enabled: true,
        }];
        assert!(validate_rules(&zero_days).is_err());
    }

    #[test]
    fn validate_rules_accepts_well_formed_rules() {
        let rules = vec![
            LifecycleRule {
                id: "expire-logs".to_string(),
                prefix: "logs/".to_string(),
                expiration_days: 30,
                enabled: true,
            },
            LifecycleRule {
                id: "expire-uploads".to_string(),
                prefix: "uploads/".to_string(),
                expiration_days: 7,
                enabled: false,
            },
        ];
        assert!(validate_rules(&rules).is_ok());
    }

    #[test]
    fn should_expire_object_matches_prefix_and_age() {
        let now = Utc.with_ymd_and_hms(2026, 3, 1, 12, 0, 0).unwrap();
        let rules = vec![
            LifecycleRule {
                id: "logs".to_string(),
                prefix: "logs/".to_string(),
                expiration_days: 7,
                enabled: true,
            },
            LifecycleRule {
                id: "disabled".to_string(),
                prefix: "tmp/".to_string(),
                expiration_days: 1,
                enabled: false,
            },
        ];

        assert!(should_expire_object(
            "logs/old.txt",
            "2026-02-20T12:00:00.000Z",
            &rules,
            now
        ));
        assert!(!should_expire_object(
            "logs/new.txt",
            "2026-02-27T12:00:00.000Z",
            &rules,
            now
        ));
        assert!(!should_expire_object(
            "tmp/file.txt",
            "2026-02-20T12:00:00.000Z",
            &rules,
            now
        ));
        assert!(!should_expire_object(
            "logs/folder/",
            "2026-02-20T12:00:00.000Z",
            &rules,
            now
        ));
    }
}
