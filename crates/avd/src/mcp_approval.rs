//! Explicit operator enrollment of a trusted MCP harness. UI visibility is not authentication.
use crate::{Broker, Operation, RequestState, Review};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    sync::Mutex,
    time::{Duration, Instant},
};
use uuid::Uuid;
struct Enrollment {
    id: Uuid,
    epoch: u64,
    authorized: bool,
    deadline: Instant,
    requests: HashSet<Uuid>,
}
#[derive(Default)]
pub(crate) struct McpApprovals {
    sessions: Mutex<HashMap<String, Enrollment>>,
}
fn key(nonce: &str) -> Result<String> {
    ensure!(
        nonce.len() == 64 && nonce.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid MCP session proof"
    );
    Ok(hex::encode(Sha256::digest(nonce.as_bytes())))
}
pub fn review_digest(review: &Review) -> Result<String> {
    // State changes do not change intent. Command, limits, version and ID do.
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(
        &json!({"id":review.id,"operation":review.operation,"task_policy":review.task_policy}),
    )?)))
}
impl McpApprovals {
    pub(crate) fn enroll(&self, nonce: &str, epoch: u64) -> Result<Value> {
        let key = key(nonce)?;
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, s| s.epoch == epoch && s.deadline > Instant::now());
        if !sessions.contains_key(&key) {
            ensure!(sessions.len() < 8, "too many MCP sessions");
            sessions.insert(
                key.clone(),
                Enrollment {
                    id: Uuid::new_v4(),
                    epoch,
                    authorized: false,
                    deadline: Instant::now() + Duration::from_secs(120),
                    requests: HashSet::new(),
                },
            );
        }
        let session = &sessions[&key];
        Ok(
            json!({"pairing_id":session.id,"authorized":session.authorized,"expires_in":session.deadline.saturating_duration_since(Instant::now()).as_secs()}),
        )
    }
    pub(crate) fn list(&self, epoch: u64) -> Value {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, s| s.epoch == epoch && s.deadline > Instant::now());
        let mut records: Vec<_> = sessions.values().map(|s| json!({"id":s.id,"authorized":s.authorized,"expires_in":s.deadline.saturating_duration_since(Instant::now()).as_secs()})).collect();
        records.sort_by_key(|v| v["id"].to_string());
        json!({"sessions":records})
    }
    pub(crate) fn authorize(&self, id: Uuid, approve: bool, epoch: u64) -> Result<()> {
        let mut sessions = self.sessions.lock().unwrap();
        let entry = sessions
            .values_mut()
            .find(|s| s.id == id && s.epoch == epoch && s.deadline > Instant::now())
            .ok_or_else(|| anyhow::anyhow!("MCP enrollment expired"))?;
        ensure!(
            !entry.authorized || !approve,
            "MCP session already enrolled"
        );
        if approve {
            entry.authorized = true;
            entry.deadline = Instant::now() + Duration::from_secs(900);
        } else {
            sessions.retain(|_, s| s.id != id);
        }
        Ok(())
    }
    pub(crate) fn request(
        &self,
        nonce: &str,
        operation: Operation,
        broker: &Broker,
        epoch: u64,
    ) -> Result<Value> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions
            .get_mut(&key(nonce)?)
            .ok_or_else(|| anyhow::anyhow!("MCP session not enrolled"))?;
        ensure!(
            session.authorized && session.epoch == epoch && session.deadline > Instant::now(),
            "MCP enrollment expired"
        );
        ensure!(
            session.requests.len() < 32,
            "MCP session task limit reached"
        );
        let id = broker
            .request(operation)
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        session.requests.insert(id);
        let review = broker.review(id).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        Ok(json!({"review":review,"review_digest":review_digest(&review)?}))
    }
    fn owned(
        &self,
        nonce: &str,
        id: Uuid,
        epoch: u64,
    ) -> Result<std::sync::MutexGuard<'_, HashMap<String, Enrollment>>> {
        let sessions = self.sessions.lock().unwrap();
        let session = sessions
            .get(&key(nonce)?)
            .ok_or_else(|| anyhow::anyhow!("MCP session not enrolled"))?;
        ensure!(
            session.authorized
                && session.epoch == epoch
                && session.deadline > Instant::now()
                && session.requests.contains(&id),
            "task does not belong to an authorized MCP session"
        );
        Ok(sessions)
    }
    pub(crate) fn review(
        &self,
        nonce: &str,
        id: Uuid,
        broker: &Broker,
        epoch: u64,
    ) -> Result<Value> {
        let _gate = self.owned(nonce, id, epoch)?;
        let review = broker.review(id).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        Ok(json!({"review":review,"review_digest":review_digest(&review)?}))
    }
    pub(crate) fn decide(
        &self,
        nonce: &str,
        id: Uuid,
        digest: &str,
        approve: bool,
        broker: &Broker,
        epoch: u64,
    ) -> Result<Value> {
        let _gate = self.owned(nonce, id, epoch)?;
        let review = broker.review(id).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        ensure!(
            review.state == RequestState::Pending && review_digest(&review)? == digest,
            "review changed or already decided"
        );
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        broker
            .decide(id, approve, now, 60)
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let review = broker.review(id).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        Ok(json!({"review":review,"review_digest":review_digest(&review)?}))
    }
    pub(crate) fn clear(&self) {
        self.sessions.lock().unwrap().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn enrollment_is_bounded_revocable_and_epoch_bound() {
        let state = McpApprovals::default();
        let nonce = "a".repeat(64);
        let pair = state.enroll(&nonce, 0).unwrap();
        let id: Uuid = serde_json::from_value(pair["pairing_id"].clone()).unwrap();
        assert_eq!(pair, state.enroll(&nonce, 0).unwrap());
        assert!(state.owned(&nonce, Uuid::new_v4(), 0).is_err());
        state.authorize(id, true, 0).unwrap();
        assert!(state.authorize(id, true, 0).is_err());
        assert!(state.authorize(id, false, 1).is_err());
        state.authorize(id, false, 0).unwrap();
        assert!(state.authorize(id, true, 0).is_err());
        assert_ne!(state.enroll(&nonce, 1).unwrap()["pairing_id"], json!(id));
        for i in 0..7 {
            state.enroll(&format!("{i:064x}"), 1).unwrap();
        }
        assert!(state.enroll(&"f".repeat(64), 1).is_err());
        state.clear();
        assert_eq!(state.list(1)["sessions"], json!([]));
    }
    #[test]
    fn expired_pair_cannot_be_authorized_or_refreshed_in_place() {
        let state = McpApprovals::default();
        let nonce = "a".repeat(64);
        let pair = state.enroll(&nonce, 0).unwrap();
        let id: Uuid = serde_json::from_value(pair["pairing_id"].clone()).unwrap();
        state
            .sessions
            .lock()
            .unwrap()
            .get_mut(&key(&nonce).unwrap())
            .unwrap()
            .deadline = Instant::now();
        assert!(state.authorize(id, true, 0).is_err());
        assert_ne!(state.enroll(&nonce, 0).unwrap()["pairing_id"], json!(id));
    }
    #[test]
    fn review_digest_binds_id_command_version_host_and_quotas() {
        let review = Review {
            id: Uuid::new_v4(),
            operation: Operation {
                connection: "test/cli".into(),
                action: "proxy.run".into(),
                target: "api.example.test".into(),
                arguments: json!({"command":["/usr/bin/true"],"connection_version":1}),
            },
            state: RequestState::Pending,
            task_policy: Some(crate::TaskPolicySnapshot {
                host: "api.example.test".into(),
                command: vec!["/usr/bin/true".into()],
                connection_version: Some(1),
                max_connects: 2,
                max_requests: 3,
                max_runtime_seconds: 20,
            }),
        };
        let original = review_digest(&review).unwrap();
        let mut changed = review.clone();
        changed.id = Uuid::new_v4();
        assert_ne!(review_digest(&changed).unwrap(), original);
        let mut changed = review.clone();
        changed.operation.arguments["connection_version"] = json!(2);
        assert_ne!(review_digest(&changed).unwrap(), original);
        let mut changed = review.clone();
        changed.task_policy.as_mut().unwrap().max_requests = 4;
        assert_ne!(review_digest(&changed).unwrap(), original);
        let mut changed = review.clone();
        changed.task_policy.as_mut().unwrap().host = "other.example.test".into();
        assert_ne!(review_digest(&changed).unwrap(), original);
        let mut changed = review.clone();
        changed
            .task_policy
            .as_mut()
            .unwrap()
            .command
            .push("extra".into());
        assert_ne!(review_digest(&changed).unwrap(), original);
        let mut changed = review;
        changed.state = RequestState::Denied;
        assert_eq!(review_digest(&changed).unwrap(), original);
    }
}
