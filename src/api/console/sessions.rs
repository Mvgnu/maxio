use std::collections::HashMap;
use std::sync::Mutex;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;
type SessionVerifier = [u8; 32];

pub(super) const SESSION_MAX_AGE_SECS: i64 = 7 * 24 * 60 * 60;
const MAX_ACTIVE_SESSIONS: usize = 4096;
const TOKEN_BYTES: usize = 32;

struct SessionRecord {
    access_key: String,
    credential_binding: [u8; 32],
    issued_at: i64,
    expires_at: i64,
}

impl SessionRecord {
    fn is_current(&self, now: i64) -> bool {
        now < self.expires_at && self.issued_at <= now.saturating_add(60)
    }

    fn credential_matches(&self, verifier: &SessionVerifier, secret: Option<&String>) -> bool {
        secret
            .and_then(|secret| credential_mac(secret, verifier))
            .is_some_and(|mac| mac.verify_slice(&self.credential_binding).is_ok())
    }
}

pub(super) struct AuthenticatedSession {
    pub access_key: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub verifier: SessionVerifier,
}

pub(super) struct IssuedSession {
    pub token: String,
    pub session: AuthenticatedSession,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum SessionIssueError {
    Full,
    Unavailable,
}

/// Bounded, process-local management sessions. Restart revokes every session.
///
/// The registry retains SHA-256 verifiers and credential bindings, never bearer
/// tokens or secret keys. A full registry refuses login without evicting a user.
pub struct ConsoleSessionStore {
    sessions: Mutex<HashMap<SessionVerifier, SessionRecord>>,
    capacity: usize,
}

impl Default for ConsoleSessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ConsoleSessionStore {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            capacity: MAX_ACTIVE_SESSIONS,
        }
    }

    pub(super) fn issue(
        &self,
        access_key: &str,
        credentials: &HashMap<String, String>,
    ) -> Result<IssuedSession, SessionIssueError> {
        self.issue_at(access_key, credentials, chrono::Utc::now().timestamp())
    }

    fn issue_at(
        &self,
        access_key: &str,
        credentials: &HashMap<String, String>,
        now: i64,
    ) -> Result<IssuedSession, SessionIssueError> {
        let secret = credentials
            .get(access_key)
            .ok_or(SessionIssueError::Unavailable)?;
        let expires_at = now
            .checked_add(SESSION_MAX_AGE_SECS)
            .ok_or(SessionIssueError::Unavailable)?;
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| SessionIssueError::Unavailable)?;
        sessions.retain(|verifier, session| {
            session.is_current(now)
                && session.credential_matches(verifier, credentials.get(&session.access_key))
        });
        if sessions.len() >= self.capacity {
            return Err(SessionIssueError::Full);
        }

        // Retry a collision without replacing an existing operator's session.
        for _ in 0..3 {
            let mut random = [0_u8; TOKEN_BYTES];
            openssl::rand::rand_bytes(&mut random).map_err(|_| SessionIssueError::Unavailable)?;
            let verifier: SessionVerifier = Sha256::digest(random).into();
            if sessions.contains_key(&verifier) {
                continue;
            }
            let credential_binding = credential_mac(secret, &verifier)
                .ok_or(SessionIssueError::Unavailable)?
                .finalize()
                .into_bytes()
                .into();
            sessions.insert(
                verifier,
                SessionRecord {
                    access_key: access_key.to_owned(),
                    credential_binding,
                    issued_at: now,
                    expires_at,
                },
            );
            return Ok(IssuedSession {
                token: hex::encode(random),
                session: AuthenticatedSession {
                    access_key: access_key.to_owned(),
                    issued_at: now,
                    expires_at,
                    verifier,
                },
            });
        }
        Err(SessionIssueError::Unavailable)
    }

    pub(super) fn authenticate(
        &self,
        token: &str,
        credentials: &HashMap<String, String>,
    ) -> Option<AuthenticatedSession> {
        self.authenticate_at(token, credentials, chrono::Utc::now().timestamp())
    }

    fn authenticate_at(
        &self,
        token: &str,
        credentials: &HashMap<String, String>,
        now: i64,
    ) -> Option<AuthenticatedSession> {
        let verifier = token_verifier(token)?;
        let mut sessions = self.sessions.lock().ok()?;
        let session = sessions.get(&verifier)?;
        if !session.credential_matches(&verifier, credentials.get(&session.access_key)) {
            let account = session.access_key.clone();
            // Remove every obsolete session for this account so restoring an old
            // credential cannot revive an unpresented sibling session.
            sessions.retain(|verifier, session| {
                session.access_key != account
                    || session.credential_matches(verifier, credentials.get(&account))
            });
            return None;
        }
        if !session.is_current(now) {
            sessions.remove(&verifier);
            return None;
        }
        Some(AuthenticatedSession {
            access_key: session.access_key.clone(),
            issued_at: session.issued_at,
            expires_at: session.expires_at,
            verifier,
        })
    }

    /// Returns false on an unavailable registry; a successful logout must revoke.
    pub(super) fn revoke(&self, verifier: &SessionVerifier) -> bool {
        let Ok(mut sessions) = self.sessions.lock() else {
            return false;
        };
        sessions.remove(verifier);
        true
    }
}

fn credential_mac(secret: &str, verifier: &SessionVerifier) -> Option<HmacSha256> {
    // HMAC accepts keys of any length. Domain separation prevents reuse of the
    // binding as another protocol's MAC; the verifier salts it per session.
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(b"MaxIO console session\0");
    mac.update(verifier);
    Some(mac)
}

fn token_verifier(token: &str) -> Option<SessionVerifier> {
    // Exact, canonical input bounds also reject every legacy stateless cookie.
    if token.len() != TOKEN_BYTES * 2
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut random = [0_u8; TOKEN_BYTES];
    hex::decode_to_slice(token, &mut random).ok()?;
    Some(Sha256::digest(random).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn credentials() -> HashMap<String, String> {
        HashMap::from([
            ("operator".to_owned(), "secret".to_owned()),
            ("other".to_owned(), "other-secret".to_owned()),
        ])
    }

    #[test]
    fn same_second_logins_are_distinct_and_revoke_independently() {
        let store = ConsoleSessionStore::new();
        let credentials = credentials();
        let first = store.issue_at("operator", &credentials, NOW).unwrap();
        let second = store.issue_at("operator", &credentials, NOW).unwrap();
        assert_eq!(first.token.len(), 64);
        assert_ne!(first.token, second.token);
        let identity = store
            .authenticate_at(&first.token, &credentials, NOW)
            .unwrap();
        assert_eq!(identity.access_key, "operator");
        assert_eq!(identity.issued_at, NOW);
        assert_eq!(identity.expires_at, NOW + SESSION_MAX_AGE_SECS);
        assert!(store.revoke(&identity.verifier));
        assert!(
            store
                .authenticate_at(&first.token, &credentials, NOW)
                .is_none()
        );
        assert!(
            store
                .authenticate_at(&second.token, &credentials, NOW)
                .is_some()
        );
    }

    #[test]
    fn expiry_is_absolute_and_expired_sessions_cannot_be_revived() {
        let store = ConsoleSessionStore::new();
        let credentials = credentials();
        let issued = store.issue_at("operator", &credentials, NOW).unwrap();
        assert!(
            store
                .authenticate_at(&issued.token, &credentials, NOW + SESSION_MAX_AGE_SECS - 1)
                .is_some()
        );
        assert!(
            store
                .authenticate_at(&issued.token, &credentials, NOW + SESSION_MAX_AGE_SECS)
                .is_none()
        );
        assert!(
            store
                .authenticate_at(&issued.token, &credentials, NOW)
                .is_none()
        );
    }

    #[test]
    fn changed_credentials_remove_obsolete_sibling_sessions() {
        let store = ConsoleSessionStore::new();
        let mut credentials = credentials();
        let first = store.issue_at("operator", &credentials, NOW).unwrap();
        let sibling = store.issue_at("operator", &credentials, NOW).unwrap();
        let other = store.issue_at("other", &credentials, NOW).unwrap();
        credentials.insert("operator".to_owned(), "replacement".to_owned());
        assert!(
            store
                .authenticate_at(&first.token, &credentials, NOW)
                .is_none()
        );
        credentials.insert("operator".to_owned(), "secret".to_owned());
        assert!(
            store
                .authenticate_at(&sibling.token, &credentials, NOW)
                .is_none()
        );
        assert!(
            store
                .authenticate_at(&other.token, &credentials, NOW)
                .is_some()
        );
    }

    #[test]
    fn removed_credentials_remove_obsolete_sibling_sessions() {
        let store = ConsoleSessionStore::new();
        let mut credentials = credentials();
        let first = store.issue_at("operator", &credentials, NOW).unwrap();
        let sibling = store.issue_at("operator", &credentials, NOW).unwrap();
        credentials.remove("operator");
        assert!(
            store
                .authenticate_at(&first.token, &credentials, NOW)
                .is_none()
        );
        credentials.insert("operator".to_owned(), "secret".to_owned());
        assert!(
            store
                .authenticate_at(&sibling.token, &credentials, NOW)
                .is_none()
        );
    }

    #[test]
    fn full_registry_refuses_without_eviction_and_reclaims_revoked_or_expired_slots() {
        let store = ConsoleSessionStore {
            sessions: Mutex::new(HashMap::new()),
            capacity: 2,
        };
        let credentials = credentials();
        let first = store.issue_at("operator", &credentials, NOW).unwrap();
        let second = store.issue_at("operator", &credentials, NOW).unwrap();
        assert!(matches!(
            store.issue_at("operator", &credentials, NOW),
            Err(SessionIssueError::Full)
        ));
        assert!(
            store
                .authenticate_at(&first.token, &credentials, NOW)
                .is_some()
        );
        assert!(
            store
                .authenticate_at(&second.token, &credentials, NOW)
                .is_some()
        );
        assert!(store.revoke(&first.session.verifier));
        let replacement = store.issue_at("operator", &credentials, NOW + 1).unwrap();
        let after_expiry = NOW + SESSION_MAX_AGE_SECS;
        assert!(
            store
                .issue_at("operator", &credentials, after_expiry)
                .is_ok()
        );
        assert!(
            store
                .authenticate_at(&second.token, &credentials, after_expiry)
                .is_none()
        );
        assert!(
            store
                .authenticate_at(&replacement.token, &credentials, after_expiry)
                .is_some()
        );
    }

    #[test]
    fn registry_is_local_and_tokens_must_be_canonical() {
        let store = ConsoleSessionStore::new();
        let credentials = credentials();
        let issued = store.issue_at("operator", &credentials, NOW).unwrap();
        assert!(
            ConsoleSessionStore::new()
                .authenticate_at(&issued.token, &credentials, NOW)
                .is_none()
        );
        for token in [
            "operator.6b49d200.signature".to_owned(),
            "a".repeat(65),
            "a".repeat(63),
            "a".repeat(10_000),
            "A".repeat(64),
            "0".repeat(64),
        ] {
            assert!(store.authenticate_at(&token, &credentials, NOW).is_none());
        }
    }
}
