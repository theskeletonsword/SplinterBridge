//! Durable outbox / inbox interface for cross-border event delivery.
//!
//! Production deployments must back this with Kafka, Pulsar, Raft-based logs,
//! or a replicated SQL outbox table. The trait is intentionally minimal so
//! operators can plug their own durable bus.

use crate::{FederatedEventEnvelope, FederatedEventResponse};
use std::time::{SystemTime, UNIX_EPOCH};

/// Errors from the outbox/inbox.
#[derive(Debug, thiserror::Error)]
pub enum OutboxError {
    #[error("outbox unavailable")]
    Unavailable,
    #[error("envelope too large")]
    EnvelopeTooLarge,
    #[error("delivery failed: {0}")]
    DeliveryFailed(String),
    #[error("ack not found")]
    AckNotFound,
}

/// Trait for a durable outbox: persist signed envelopes before network dispatch.
pub trait Outbox: Send + Sync {
    /// Persists a signed envelope for durable delivery to `destination`.
    /// Returns a durable delivery ID the caller can use to track acknowledgment.
    fn enqueue(
        &self,
        destination: u32,
        envelope: &FederatedEventEnvelope,
    ) -> Result<u64, OutboxError>;

    /// Marks a delivery as acknowledged after the remote gateway confirmed
    /// acceptance. The entry may then be garbage-collected after retention.
    fn acknowledge(&self, delivery_id: u64) -> Result<(), OutboxError>;

    /// Returns envelopes pending delivery (older than `since_ms`) for retry.
    fn pending_since(&self, _since_ms: i64) -> Result<Vec<u64>, OutboxError> {
        Ok(vec![])
    }
}

/// Trait for a durable inbox: idempotent receipt of inbound envelopes.
pub trait Inbox: Send + Sync {
    /// Records receipt of an envelope idempotently. Returns `Ok(true)` if this
    /// is the first time this delivery ID is seen, `Ok(false)` if it was a
    /// duplicate (replay).
    fn record_receipt(&self, delivery_id: u64) -> Result<bool, OutboxError>;

    /// Stores the remote gateway's response for a delivery.
    fn store_response(
        &self,
        delivery_id: u64,
        response: &FederatedEventResponse,
    ) -> Result<(), OutboxError>;
}

/// No-op outbox: accepts envelopes but does not persist them. Suitable for
/// development and for gateways where the embedding application manages
/// durability externally.
pub struct NoopOutbox;

impl Outbox for NoopOutbox {
    fn enqueue(
        &self,
        _destination: u32,
        _envelope: &FederatedEventEnvelope,
    ) -> Result<u64, OutboxError> {
        Ok(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0))
    }

    fn acknowledge(&self, _delivery_id: u64) -> Result<(), OutboxError> {
        Ok(())
    }
}

/// No-op inbox: accepts every receipt as new. Not safe for production replay
/// protection; replace with a real idempotency store before deployment.
pub struct NoopInbox;

impl Inbox for NoopInbox {
    fn record_receipt(&self, _delivery_id: u64) -> Result<bool, OutboxError> {
        Ok(true)
    }

    fn store_response(
        &self,
        _delivery_id: u64,
        _response: &FederatedEventResponse,
    ) -> Result<(), OutboxError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FederatedEventEnvelope;

    #[test]
    fn noop_outbox_enqueue_and_ack() {
        let outbox = NoopOutbox;
        let envelope = FederatedEventEnvelope::default();
        let id = outbox.enqueue(2, &envelope).unwrap();
        assert!(outbox.acknowledge(id).is_ok());
    }

    #[test]
    fn noop_inbox_records_receipt() {
        let inbox = NoopInbox;
        assert!(inbox.record_receipt(1).unwrap());
        assert!(inbox.store_response(1, &FederatedEventResponse::default()).is_ok());
    }
}
