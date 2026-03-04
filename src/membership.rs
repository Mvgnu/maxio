use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::MembershipProtocol;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MembershipEngineStatus {
    pub engine: String,
    pub protocol: String,
    pub ready: bool,
    pub converged: bool,
    pub last_update_unix_ms: u64,
    pub warning: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MembershipEngine {
    StaticBootstrap {
        last_update_unix_ms: u64,
    },
    GossipExperimental {
        last_update_unix_ms: u64,
    },
    Unimplemented {
        protocol: MembershipProtocol,
        last_update_unix_ms: u64,
    },
}

impl MembershipEngine {
    pub fn for_protocol(protocol: MembershipProtocol) -> Self {
        let now = unix_ms_now();
        match protocol {
            MembershipProtocol::StaticBootstrap => Self::StaticBootstrap {
                last_update_unix_ms: now,
            },
            MembershipProtocol::Gossip => Self::GossipExperimental {
                last_update_unix_ms: now,
            },
            MembershipProtocol::Raft => Self::Unimplemented {
                protocol,
                last_update_unix_ms: now,
            },
        }
    }

    pub fn status(&self) -> MembershipEngineStatus {
        self.status_with_last_update(self.last_update_unix_ms())
    }

    pub fn status_with_last_update(
        &self,
        observed_last_update_unix_ms: u64,
    ) -> MembershipEngineStatus {
        let last_update_unix_ms = observed_last_update_unix_ms.max(self.last_update_unix_ms());
        match self {
            Self::StaticBootstrap { .. } => MembershipEngineStatus {
                engine: "static-bootstrap".to_string(),
                protocol: MembershipProtocol::StaticBootstrap.as_str().to_string(),
                ready: true,
                converged: true,
                last_update_unix_ms,
                warning: None,
            },
            Self::GossipExperimental { .. } => MembershipEngineStatus {
                engine: "gossip-experimental".to_string(),
                protocol: MembershipProtocol::Gossip.as_str().to_string(),
                ready: true,
                converged: true,
                last_update_unix_ms,
                warning: Some(
                    "Membership protocol 'gossip' runs in experimental probe-driven mode; anti-entropy rounds and failure-detector gossip are not implemented yet."
                        .to_string(),
                ),
            },
            Self::Unimplemented { protocol, .. } => MembershipEngineStatus {
                engine: "unimplemented-placeholder".to_string(),
                protocol: protocol.as_str().to_string(),
                ready: false,
                converged: false,
                last_update_unix_ms,
                warning: Some(format!(
                    "Membership protocol '{}' is configured but not implemented yet; runtime currently uses static-bootstrap semantics.",
                    protocol.as_str()
                )),
            },
        }
    }

    pub fn last_update_unix_ms(&self) -> u64 {
        match self {
            Self::StaticBootstrap {
                last_update_unix_ms,
            } => *last_update_unix_ms,
            Self::GossipExperimental {
                last_update_unix_ms,
            } => *last_update_unix_ms,
            Self::Unimplemented {
                last_update_unix_ms,
                ..
            } => *last_update_unix_ms,
        }
    }
}

pub(crate) fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{MembershipEngine, MembershipEngineStatus};
    use crate::config::MembershipProtocol;

    #[test]
    fn static_bootstrap_engine_reports_ready_and_converged() {
        let status = MembershipEngine::for_protocol(MembershipProtocol::StaticBootstrap).status();
        assert_eq!(
            status,
            MembershipEngineStatus {
                engine: "static-bootstrap".to_string(),
                protocol: "static-bootstrap".to_string(),
                ready: true,
                converged: true,
                last_update_unix_ms: status.last_update_unix_ms,
                warning: None,
            }
        );
        assert!(status.last_update_unix_ms > 0);
    }

    #[test]
    fn gossip_engine_reports_ready_with_experimental_warning() {
        let status = MembershipEngine::for_protocol(MembershipProtocol::Gossip).status();
        assert_eq!(status.engine, "gossip-experimental");
        assert_eq!(status.protocol, "gossip");
        assert!(status.ready);
        assert!(status.converged);
        assert!(
            status
                .warning
                .is_some_and(|warning| warning.contains("experimental"))
        );
    }

    #[test]
    fn raft_engine_reports_not_ready_and_warning() {
        let status = MembershipEngine::for_protocol(MembershipProtocol::Raft).status();
        assert_eq!(status.engine, "unimplemented-placeholder");
        assert_eq!(status.protocol, "raft");
        assert!(!status.ready);
        assert!(!status.converged);
        assert!(
            status
                .warning
                .is_some_and(|warning| warning.contains("not implemented"))
        );
    }

    #[test]
    fn status_with_last_update_uses_monotonic_observed_timestamp() {
        let engine = MembershipEngine::for_protocol(MembershipProtocol::StaticBootstrap);
        let baseline = engine.last_update_unix_ms();
        let bumped = baseline.saturating_add(5000);

        let bumped_status = engine.status_with_last_update(bumped);
        assert_eq!(bumped_status.last_update_unix_ms, bumped);

        let regressed_status = engine.status_with_last_update(baseline.saturating_sub(1));
        assert_eq!(regressed_status.last_update_unix_ms, baseline);
    }
}
