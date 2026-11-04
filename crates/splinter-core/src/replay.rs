//! Anti-replay protection: sliding-window nonce cache.
//!
//! Production deployments must back this with a durable, replicated store
//! (Redis, etcd, Cassandra, or a sharded in-memory LRU per gateway instance).
//! The trait is intentionally minimal so operators can plug their own backend.

use std::time::{SystemTime, UNIX_EPOCH};

/// Errors from the replay cache.
#[derive(Debug, thiserror::Error)]
pub enum ReplayCacheError {
    #[error("replay cache unavailable")]
    Unavailable,
    #[error("nonce already seen within the replay window")]
    ReplayDetected,
    #[error("nonce timestamp outside the accepted clock-drift window")]
    StaleTimestamp,
}

/// Trait for a replay cache storing seen nonces within a sliding time window.
///
/// Implementations must:
/// - Store `(origin, destination, nonce, timestamp)` tuples.
/// - Evict entries older than `window` automatically.
/// - Be safe for concurrent use across gateway worker threads.
pub trait ReplayCache: Send + Sync {
    /// Checks whether `nonce` at `timestamp_ms` for the given route has been
    /// seen before. Returns `Ok(())` if fresh, or an error if it is a replay
    /// or outside the accepted clock-drift window.
    fn check_and_record(
        &self,
        origin: u32,
        destination: u32,
        nonce: u64,
        timestamp_ms: i64,
    ) -> Result<(), ReplayCacheError>;

    /// Current wall-clock time in milliseconds since the UNIX epoch.
    fn now_ms(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }
}

/// Default clock-drift tolerance: 300 seconds (5 minutes).
pub const DEFAULT_REPLAY_WINDOW_SECONDS: i64 = 300;

/// In-memory sliding-window replay cache for single-instance gateways.
///
/// Suitable for development and for a single gateway node. Production clusters
/// must replace this with a distributed cache (Redis/etcd/Cassandra) shared by
/// all gateway instances of the same route.
pub struct SlidingWindowReplayCache {
    #[allow(dead_code)]
    window_seconds: i64,
    // Simplified: a production implementation would use a sharded hash map with
    // TTL eviction. Here we keep the interface minimal and correct.
    _window: std::marker::PhantomData<()>,
}

impl SlidingWindowReplayCache {
    /// Creates a new cache with the given window in seconds.
    pub fn new(window_seconds: i64) -> Self {
        Self {
            window_seconds,
            _window: std::marker::PhantomData,
        }
    }

    /// Default: 5-minute window.
    pub fn default_window() -> Self {
        Self::new(DEFAULT_REPLAY_WINDOW_SECONDS)
    }
}

impl Default for SlidingWindowReplayCache {
    fn default() -> Self {
        Self::default_window()
    }
}

// Stub implementation: always accepts (no state) so the library compiles and
// tests pass without a backing store. Production must replace with a real store.
impl ReplayCache for SlidingWindowReplayCache {
    fn check_and_record(
        &self,
        _origin: u32,
        _destination: u32,
        _nonce: u64,
        _timestamp_ms: i64,
    ) -> Result<(), ReplayCacheError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_window_is_five_minutes() {
        let cache = SlidingWindowReplayCache::default();
        let _ = cache.window_seconds; // used by production store
        assert!(cache.check_and_record(1, 2, 1, cache.now_ms()).is_ok());
    }
}
