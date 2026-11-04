//! Append-only, tamper-evident audit log for DOJ/CFIUS oversight.
//!
//! Under a National Security Agreement (NSA), DOJ and CFIUS monitors must have
//! real-time access to gateway audit records with unilateral kill-switch
//! authority. This trait is the integration point for an append-only log
//! (e.g. CloudTrail, Azure Monitor, or an operator-run immutable ledger).
//!
//! The log must never be editable or deletable by the gateway operator.

use thiserror::Error;

/// Errors from audit log operations.
#[derive(Debug, Error)]
pub enum AuditLogError {
    #[error("audit log unavailable")]
    Unavailable,
    #[error("append failed: {0}")]
    AppendFailed(String),
    #[error("verification failed: tampered or missing entry")]
    VerificationFailed,
}

/// A single immutable audit record.
#[derive(Debug, Clone)]
pub struct AuditRecord {
    /// Monotonically increasing sequence number.
    pub seq: u64,
    /// Epoch milliseconds when the event occurred.
    pub timestamp_ms: i64,
    /// Event type: "envelope_dispatch", "envelope_reject", "kill_switch",
    /// "attestation_verify", "route_enable", "route_disable".
    pub event_type: String,
    /// Origin jurisdiction.
    pub origin: u32,
    /// Destination jurisdiction.
    pub destination: u32,
    /// Actor / gateway key ID involved.
    pub actor_key_id: String,
    /// Outcome: "allowed", "rejected", "killed".
    pub outcome: String,
    /// Optional reason code (drop reason, notice, etc.).
    pub reason: Option<String>,
    /// SHA-256 of the previous record hash (hash chain).
    pub prev_hash: Option<String>,
    /// SHA-256 of this record's content (for tamper evidence).
    pub record_hash: String,
}

/// Trait for an append-only, tamper-evident audit log.
pub trait AuditLog: Send + Sync {
    /// Appends an immutable record. Returns the assigned sequence number.
    fn append(&self, record: &AuditRecord) -> Result<u64, AuditLogError>;

    /// Verifies the hash chain from `from_seq` to `to_seq`.
    fn verify_chain(&self, from_seq: u64, to_seq: u64) -> Result<bool, AuditLogError>;

    /// Returns the latest sequence number.
    fn latest_seq(&self) -> Result<u64, AuditLogError>;
}

/// No-op audit log: accepts appends but does not persist. Unsafe for
/// production; replace before DOJ/CFIUS deployment.
pub struct NoopAuditLog;

impl AuditLog for NoopAuditLog {
    fn append(&self, _record: &AuditRecord) -> Result<u64, AuditLogError> {
        Ok(0)
    }

    fn verify_chain(&self, _from: u64, _to: u64) -> Result<bool, AuditLogError> {
        Ok(true)
    }

    fn latest_seq(&self) -> Result<u64, AuditLogError> {
        Ok(0)
    }
}

impl Default for NoopAuditLog {
    fn default() -> Self {
        Self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_audit_log_accepts_appends() {
        let log = NoopAuditLog;
        let record = AuditRecord {
            seq: 0,
            timestamp_ms: 0,
            event_type: "test".into(),
            origin: 1,
            destination: 2,
            actor_key_id: "key".into(),
            outcome: "allowed".into(),
            reason: None,
            prev_hash: None,
            record_hash: "hash".into(),
        };
        assert_eq!(log.append(&record).unwrap(), 0);
    }
}
