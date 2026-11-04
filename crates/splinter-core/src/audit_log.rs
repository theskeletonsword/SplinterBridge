//! Append-only, hash-chained audit log of gateway decisions.
//!
//! Records hold routing metadata and value-free codes only: no content, handles,
//! names, identifiers or matched terms. Each record commits to the previous one
//! with SHA-256, so an exported log can be checked independently with
//! [`verify_records`]. Truncating the newest records is only detectable if the
//! latest [`HashChainedAuditLog::head_hash`] is anchored somewhere the operator
//! cannot rewrite (a counterparty, an auditor, WORM storage).
//!
//! `HashChainedAuditLog` is in memory and is lost on restart. Production must
//! persist records to append-only storage, keeping the same hash format.

use sha2::{Digest, Sha256};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// Sequence number, starting at 1. Assigned by the log.
    pub seq: u64,
    /// Epoch milliseconds when the event occurred.
    pub timestamp_ms: i64,
    /// Event type, e.g. "envelope_export" or "envelope_accept".
    pub event_type: String,
    /// Origin jurisdiction.
    pub origin: u32,
    /// Destination jurisdiction.
    pub destination: u32,
    /// Gateway key ID from local configuration.
    pub actor_key_id: String,
    /// Outcome: "allowed" or "rejected".
    pub outcome: String,
    /// Optional value-free reason code (e.g. "POLICY_KEYWORD").
    pub reason: Option<String>,
    /// `record_hash` of the previous record; `None` for the first. Assigned by the log.
    pub prev_hash: Option<String>,
    /// Lowercase hex SHA-256 over this record (see [`compute_record_hash`]). Assigned by the log.
    pub record_hash: String,
}

impl AuditRecord {
    /// A record ready to append; the log assigns `seq` and both hashes.
    pub fn new(
        event_type: &str,
        origin: u32,
        destination: u32,
        actor_key_id: &str,
        outcome: &str,
        reason: Option<&str>,
    ) -> Self {
        Self {
            seq: 0,
            timestamp_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0),
            event_type: event_type.to_owned(),
            origin,
            destination,
            actor_key_id: actor_key_id.to_owned(),
            outcome: outcome.to_owned(),
            reason: reason.map(str::to_owned),
            prev_hash: None,
            record_hash: String::new(),
        }
    }
}

/// Trait for an append-only, tamper-evident audit log.
///
/// Implementations assign `seq`, `prev_hash` and `record_hash` themselves and
/// ignore values supplied by the caller.
pub trait AuditLog: Send + Sync {
    /// Appends an immutable record. Returns the assigned sequence number.
    fn append(&self, record: &AuditRecord) -> Result<u64, AuditLogError>;

    /// Verifies the hash chain from `from_seq` to `to_seq` inclusive.
    fn verify_chain(&self, from_seq: u64, to_seq: u64) -> Result<bool, AuditLogError>;

    /// Returns the latest sequence number (0 when empty).
    fn latest_seq(&self) -> Result<u64, AuditLogError>;
}

/// No-op audit log: discards records and cannot verify anything. Not for
/// production; gateways without an audit log simply do not audit.
pub struct NoopAuditLog;

impl AuditLog for NoopAuditLog {
    fn append(&self, _record: &AuditRecord) -> Result<u64, AuditLogError> {
        Ok(0)
    }

    fn verify_chain(&self, _from: u64, _to: u64) -> Result<bool, AuditLogError> {
        Err(AuditLogError::Unavailable)
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

const AUDIT_DOMAIN: &[u8] = b"splinterbridge.audit.record.v1\0";

/// Computes the lowercase hex SHA-256 of a record, binding every field except
/// `record_hash` itself. Strings are length-prefixed so field boundaries are
/// unambiguous.
pub fn compute_record_hash(record: &AuditRecord) -> String {
    fn put_str(hasher: &mut Sha256, value: &str) {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    fn put_opt(hasher: &mut Sha256, value: Option<&str>) {
        match value {
            None => hasher.update([0u8]),
            Some(v) => {
                hasher.update([1u8]);
                put_str(hasher, v);
            }
        }
    }
    let mut hasher = Sha256::new();
    hasher.update(AUDIT_DOMAIN);
    hasher.update(record.seq.to_be_bytes());
    hasher.update(record.timestamp_ms.to_be_bytes());
    put_str(&mut hasher, &record.event_type);
    hasher.update(record.origin.to_be_bytes());
    hasher.update(record.destination.to_be_bytes());
    put_str(&mut hasher, &record.actor_key_id);
    put_str(&mut hasher, &record.outcome);
    put_opt(&mut hasher, record.reason.as_deref());
    put_opt(&mut hasher, record.prev_hash.as_deref());
    hex::encode(hasher.finalize())
}

/// Verifies an exported, contiguous run of records: sequence numbers increase
/// by one, every hash recomputes, and each record links to the one before.
/// Pass `prev_hash` of the record preceding `records[0]` (`None` when the run
/// starts at seq 1).
pub fn verify_records(
    records: &[AuditRecord],
    prev_hash: Option<&str>,
) -> Result<(), AuditLogError> {
    let mut expected_prev = prev_hash.map(str::to_owned);
    let mut expected_seq = records.first().map(|r| r.seq);
    for record in records {
        if Some(record.seq) != expected_seq
            || record.seq == 0
            || (record.seq == 1 && prev_hash.is_some())
            || record.prev_hash != expected_prev
            || compute_record_hash(record) != record.record_hash
        {
            return Err(AuditLogError::VerificationFailed);
        }
        expected_prev = Some(record.record_hash.clone());
        expected_seq = record.seq.checked_add(1);
    }
    Ok(())
}

/// Default bound on records kept in memory before appends fail.
pub const DEFAULT_AUDIT_MAX_RECORDS: usize = 100_000;

/// In-memory hash-chained audit log for a single gateway process.
///
/// Appends fail once `max_records` is reached, so gateways configured with this
/// log stop accepting or exporting instead of dropping audit records.
pub struct HashChainedAuditLog {
    max_records: usize,
    records: Mutex<Vec<AuditRecord>>,
}

impl HashChainedAuditLog {
    pub fn new() -> Self {
        Self::with_max_records(DEFAULT_AUDIT_MAX_RECORDS)
    }

    pub fn with_max_records(max_records: usize) -> Self {
        Self {
            max_records: max_records.max(1),
            records: Mutex::new(Vec::new()),
        }
    }

    /// Copy of all records, for export to auditors and [`verify_records`].
    pub fn records(&self) -> Vec<AuditRecord> {
        self.records.lock().map(|r| r.clone()).unwrap_or_default()
    }

    /// Hash of the newest record, to anchor outside the operator's control.
    pub fn head_hash(&self) -> Option<String> {
        self.records
            .lock()
            .ok()
            .and_then(|r| r.last().map(|r| r.record_hash.clone()))
    }
}

impl Default for HashChainedAuditLog {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditLog for HashChainedAuditLog {
    fn append(&self, record: &AuditRecord) -> Result<u64, AuditLogError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| AuditLogError::Unavailable)?;
        if records.len() >= self.max_records {
            return Err(AuditLogError::AppendFailed("capacity reached".into()));
        }
        let mut entry = record.clone();
        entry.seq = records.len() as u64 + 1;
        entry.prev_hash = records.last().map(|r| r.record_hash.clone());
        entry.record_hash = compute_record_hash(&entry);
        let seq = entry.seq;
        records.push(entry);
        Ok(seq)
    }

    fn verify_chain(&self, from_seq: u64, to_seq: u64) -> Result<bool, AuditLogError> {
        let records = self
            .records
            .lock()
            .map_err(|_| AuditLogError::Unavailable)?;
        if from_seq == 0 || from_seq > to_seq || to_seq > records.len() as u64 {
            return Ok(false);
        }
        let start = (from_seq - 1) as usize;
        let prev = start
            .checked_sub(1)
            .map(|i| records[i].record_hash.as_str());
        Ok(verify_records(&records[start..to_seq as usize], prev).is_ok())
    }

    fn latest_seq(&self) -> Result<u64, AuditLogError> {
        self.records
            .lock()
            .map(|r| r.len() as u64)
            .map_err(|_| AuditLogError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filled(n: usize) -> HashChainedAuditLog {
        let log = HashChainedAuditLog::new();
        for i in 0..n {
            let outcome = if i % 2 == 0 { "allowed" } else { "rejected" };
            let reason = (i % 2 == 1).then_some("POLICY_KEYWORD");
            log.append(&AuditRecord::new(
                "envelope_export",
                1,
                2,
                "key",
                outcome,
                reason,
            ))
            .unwrap();
        }
        log
    }

    #[test]
    fn noop_audit_log_cannot_claim_verification() {
        let log = NoopAuditLog;
        let record = AuditRecord::new("test", 1, 2, "key", "allowed", None);
        assert_eq!(log.append(&record).unwrap(), 0);
        assert!(log.verify_chain(1, 1).is_err());
    }

    #[test]
    fn log_assigns_sequence_and_links_hashes() {
        let log = HashChainedAuditLog::new();
        let mut forged = AuditRecord::new("envelope_export", 1, 2, "key", "allowed", None);
        forged.seq = 99;
        forged.prev_hash = Some("forged".into());
        forged.record_hash = "forged".into();
        assert_eq!(log.append(&forged).unwrap(), 1);
        assert_eq!(log.append(&forged).unwrap(), 2);
        let records = log.records();
        assert_eq!(records[0].seq, 1);
        assert_eq!(records[0].prev_hash, None);
        assert_eq!(
            records[1].prev_hash.as_deref(),
            Some(records[0].record_hash.as_str())
        );
        assert_eq!(log.head_hash(), Some(records[1].record_hash.clone()));
        assert_eq!(log.latest_seq().unwrap(), 2);
        assert!(log.verify_chain(1, 2).unwrap());
        assert!(log.verify_chain(2, 2).unwrap());
        assert!(!log.verify_chain(0, 2).unwrap());
        assert!(!log.verify_chain(1, 3).unwrap());
    }

    #[test]
    fn exported_records_detect_edits_deletions_and_reordering() {
        let records = filled(5).records();
        assert!(verify_records(&records, None).is_ok());
        assert!(verify_records(&records[2..], Some(&records[1].record_hash)).is_ok());

        let mut edited = records.clone();
        edited[2].outcome = "rejected".into();
        assert!(verify_records(&edited, None).is_err());

        let mut rehashed = records.clone();
        rehashed[2].reason = Some("TAMPERED".into());
        rehashed[2].record_hash = compute_record_hash(&rehashed[2]);
        assert!(verify_records(&rehashed, None).is_err(), "next link breaks");

        let mut deleted = records.clone();
        deleted.remove(2);
        assert!(verify_records(&deleted, None).is_err());

        let mut reordered = records.clone();
        reordered.swap(1, 2);
        assert!(verify_records(&reordered, None).is_err());

        // A run that claims to start at 1 cannot be spliced onto other history.
        assert!(verify_records(&records, Some(&records[0].record_hash)).is_err());
    }

    #[test]
    fn hash_depends_on_field_boundaries() {
        let a = AuditRecord::new("ab", 1, 2, "c", "allowed", None);
        let mut b = a.clone();
        b.event_type = "a".into();
        b.actor_key_id = "bc".into();
        assert_ne!(compute_record_hash(&a), compute_record_hash(&b));
    }

    #[test]
    fn full_log_refuses_appends() {
        let log = HashChainedAuditLog::with_max_records(1);
        let record = AuditRecord::new("envelope_export", 1, 2, "key", "allowed", None);
        log.append(&record).unwrap();
        assert!(log.append(&record).is_err());
    }
}
