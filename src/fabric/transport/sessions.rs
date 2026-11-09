use super::{Challenge, SessionRequest, SessionResponse, identity, protocol_error};
use crate::fabric::authority::Authority;
use crate::fabric::contract::{Actor, ErrorCode};
use anyhow::Result;
use axum::http::HeaderMap;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const SESSION_SECONDS: u64 = 600;
struct Pending {
    challenge: Challenge,
    deadline: Instant,
}
struct Session {
    device_id: String,
    generation: u64,
    deadline: Instant,
}
#[derive(Default)]
struct Registry {
    pending: BTreeMap<String, Pending>,
    sessions: BTreeMap<String, Session>,
}
pub(super) struct Sessions {
    registry: Mutex<Registry>,
}

fn unauthorized() -> anyhow::Error {
    protocol_error(
        ErrorCode::Unauthenticated,
        "device authentication is absent, expired, revoked or invalid",
    )
}
fn lock_error() -> anyhow::Error {
    protocol_error(
        ErrorCode::Unavailable,
        "authentication registry unavailable",
    )
}
impl Sessions {
    pub fn new() -> Self {
        Self {
            registry: Mutex::new(Registry::default()),
        }
    }
    pub fn challenge(&self, authority: &Authority, device_id: &str) -> Result<Challenge> {
        let device = authority.device(device_id).map_err(|_| unauthorized())?;
        if device.revoked {
            return Err(unauthorized());
        }
        let mut registry = self.registry.lock().map_err(|_| lock_error())?;
        registry.pending.retain(|_, p| p.deadline > Instant::now());
        if registry.pending.len() >= 1024 {
            return Err(protocol_error(
                ErrorCode::Capacity,
                "device challenge capacity reached",
            ));
        }
        let challenge = Challenge {
            authority: authority.info(),
            device_id: device_id.to_string(),
            key_generation: device.key_generation,
            challenge_id: uuid::Uuid::new_v4().to_string(),
            nonce: identity::random_secret()?,
            expires_at_unix_ms: identity::now_ms()? + 60_000,
        };
        registry.pending.insert(
            challenge.challenge_id.clone(),
            Pending {
                challenge: challenge.clone(),
                deadline: Instant::now() + Duration::from_secs(60),
            },
        );
        Ok(challenge)
    }
    pub fn complete(
        &self,
        authority: &Authority,
        request: SessionRequest,
    ) -> Result<SessionResponse> {
        let pending = self
            .registry
            .lock()
            .map_err(|_| lock_error())?
            .pending
            .remove(&request.challenge_id)
            .ok_or_else(unauthorized)?;
        if pending.deadline <= Instant::now() || pending.challenge.device_id != request.device_id {
            return Err(unauthorized());
        }
        let device = authority
            .device(&request.device_id)
            .map_err(|_| unauthorized())?;
        if device.revoked
            || device.key_generation != pending.challenge.key_generation
            || !identity::verify(&device.public_key, &pending.challenge, &request.signature)
                .unwrap_or(false)
        {
            return Err(unauthorized());
        }
        let token = identity::random_secret()?;
        let verifier = hex::encode(Sha256::digest(token.as_bytes()));
        let mut registry = self.registry.lock().map_err(|_| lock_error())?;
        registry.sessions.retain(|_, p| p.deadline > Instant::now());
        if registry.sessions.len() >= 4096 {
            return Err(protocol_error(
                ErrorCode::Capacity,
                "device session capacity reached",
            ));
        }
        registry.sessions.insert(
            verifier,
            Session {
                device_id: device.device_id,
                generation: device.key_generation,
                deadline: Instant::now() + Duration::from_secs(SESSION_SECONDS),
            },
        );
        Ok(SessionResponse {
            token,
            expires_in_seconds: SESSION_SECONDS,
        })
    }
    pub fn actor(&self, authority: &Authority, headers: &HeaderMap) -> Result<Actor> {
        if headers.get_all("authorization").iter().count() != 1 {
            return Err(unauthorized());
        }
        let token = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .filter(|v| v.len() == 64)
            .ok_or_else(unauthorized)?;
        let verifier = hex::encode(Sha256::digest(token.as_bytes()));
        let mut registry = self.registry.lock().map_err(|_| lock_error())?;
        let session = registry.sessions.get(&verifier).ok_or_else(unauthorized)?;
        let device = authority
            .device(&session.device_id)
            .map_err(|_| unauthorized())?;
        if session.deadline <= Instant::now()
            || device.revoked
            || device.key_generation != session.generation
        {
            registry.sessions.remove(&verifier);
            return Err(unauthorized());
        }
        Ok(Actor::authenticated(
            device.device_id,
            device.key_generation,
        ))
    }
}
