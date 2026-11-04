//! Anti-replay protection: sliding-window nonce cache.
//!
//! `SlidingWindowReplayCache` is a bounded, in-memory cache for one gateway
//! process. A cluster where several instances accept the same route must back
//! [`ReplayCache`] with a shared store (Redis, etcd, Cassandra) instead, or the
//! same envelope could be accepted once per instance.

use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;
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
    #[error("replay cache is full; refusing to accept unchecked envelopes")]
    CacheFull,
}

/// Trait for a replay cache storing seen nonces within a sliding time window.
///
/// Implementations must:
/// - Store `(origin, destination, nonce)` with its timestamp.
/// - Reject timestamps outside the window and nonces already seen inside it.
/// - Check and record atomically, so two concurrent copies cannot both pass.
/// - Fail closed (return an error) when they cannot decide.
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
        system_now_ms()
    }
}

fn system_now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Default clock-drift tolerance: 300 seconds (5 minutes).
pub const DEFAULT_REPLAY_WINDOW_SECONDS: i64 = 300;

/// Default bound on remembered nonces before the cache fails closed.
pub const DEFAULT_REPLAY_MAX_ENTRIES: usize = 1_000_000;

type RouteNonce = (u32, u32, u64);

#[derive(Default)]
struct ReplayState {
    seen: HashMap<RouteNonce, i64>,
    by_time: BTreeSet<(i64, RouteNonce)>,
    /// Highest clock reading so far. Eviction never moves backwards, so a clock
    /// step back cannot make an evicted nonce acceptable again.
    high_water_ms: i64,
}

/// Bounded in-memory sliding-window replay cache for a single gateway process.
///
/// An envelope is fresh when its timestamp is within `window` of the current
/// time and its `(origin, destination, nonce)` was not seen inside the window.
/// Entries are kept until their timestamp leaves the window, so a replay is
/// either detected or rejected as stale. When `max_entries` is reached the cache
/// rejects new envelopes rather than forgetting nonces early.
pub struct SlidingWindowReplayCache {
    window_ms: i64,
    max_entries: usize,
    clock: fn() -> i64,
    state: Mutex<ReplayState>,
}

impl SlidingWindowReplayCache {
    /// Creates a cache with the given window in seconds (minimum 1).
    pub fn new(window_seconds: i64) -> Self {
        Self::with_clock(window_seconds, DEFAULT_REPLAY_MAX_ENTRIES, system_now_ms)
    }

    /// Default: 5-minute window.
    pub fn default_window() -> Self {
        Self::new(DEFAULT_REPLAY_WINDOW_SECONDS)
    }

    /// Full constructor with an explicit capacity and clock (for tests or a
    /// trusted time source). Window values below 1 second are raised to 1.
    pub fn with_clock(window_seconds: i64, max_entries: usize, clock: fn() -> i64) -> Self {
        Self {
            window_ms: window_seconds.clamp(1, i64::MAX / 1000) * 1000,
            max_entries: max_entries.max(1),
            clock,
            state: Mutex::new(ReplayState::default()),
        }
    }

    /// Number of nonces currently remembered.
    pub fn len(&self) -> usize {
        self.state.lock().map(|s| s.seen.len()).unwrap_or(0)
    }

    /// Whether no nonces are currently remembered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Same as [`ReplayCache::check_and_record`] with an explicit current time.
    pub fn check_and_record_at(
        &self,
        origin: u32,
        destination: u32,
        nonce: u64,
        timestamp_ms: i64,
        now_ms: i64,
    ) -> Result<(), ReplayCacheError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ReplayCacheError::Unavailable)?;
        state.high_water_ms = state.high_water_ms.max(now_ms);
        let oldest_allowed = state.high_water_ms.saturating_sub(self.window_ms);
        let newest_allowed = now_ms
            .max(state.high_water_ms)
            .saturating_add(self.window_ms);
        if timestamp_ms < oldest_allowed || timestamp_ms > newest_allowed {
            return Err(ReplayCacheError::StaleTimestamp);
        }
        while let Some(&(ts, key)) = state.by_time.first() {
            if ts >= oldest_allowed {
                break;
            }
            state.by_time.pop_first();
            state.seen.remove(&key);
        }
        let key = (origin, destination, nonce);
        if state.seen.contains_key(&key) {
            return Err(ReplayCacheError::ReplayDetected);
        }
        if state.seen.len() >= self.max_entries {
            return Err(ReplayCacheError::CacheFull);
        }
        state.seen.insert(key, timestamp_ms);
        state.by_time.insert((timestamp_ms, key));
        Ok(())
    }
}

impl Default for SlidingWindowReplayCache {
    fn default() -> Self {
        Self::default_window()
    }
}

impl ReplayCache for SlidingWindowReplayCache {
    fn check_and_record(
        &self,
        origin: u32,
        destination: u32,
        nonce: u64,
        timestamp_ms: i64,
    ) -> Result<(), ReplayCacheError> {
        self.check_and_record_at(origin, destination, nonce, timestamp_ms, self.now_ms())
    }

    fn now_ms(&self) -> i64 {
        (self.clock)()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: i64 = DEFAULT_REPLAY_WINDOW_SECONDS * 1000;

    #[test]
    fn default_window_is_five_minutes() {
        let cache = SlidingWindowReplayCache::default();
        assert_eq!(cache.window_ms, 300_000);
        assert!(cache.check_and_record(1, 2, 1, cache.now_ms()).is_ok());
    }

    #[test]
    fn same_nonce_is_rejected_but_scoped_per_route() {
        let cache = SlidingWindowReplayCache::default();
        let now = 10 * W;
        assert!(cache.check_and_record_at(1, 2, 7, now, now).is_ok());
        assert!(matches!(
            cache.check_and_record_at(1, 2, 7, now, now + 1),
            Err(ReplayCacheError::ReplayDetected)
        ));
        // Same nonce on another route or with another nonce is independent.
        assert!(cache.check_and_record_at(2, 1, 7, now, now).is_ok());
        assert!(cache.check_and_record_at(1, 2, 8, now, now).is_ok());
    }

    #[test]
    fn timestamps_outside_the_window_are_stale() {
        let cache = SlidingWindowReplayCache::default();
        let now = 10 * W;
        assert!(cache.check_and_record_at(1, 2, 1, now - W, now).is_ok());
        assert!(cache.check_and_record_at(1, 2, 2, now + W, now).is_ok());
        for ts in [now - W - 1, now + W + 1, 0, i64::MIN, i64::MAX] {
            assert!(matches!(
                cache.check_and_record_at(1, 2, 3, ts, now),
                Err(ReplayCacheError::StaleTimestamp)
            ));
        }
    }

    #[test]
    fn evicted_nonces_cannot_be_replayed_even_after_a_clock_step_back() {
        let cache = SlidingWindowReplayCache::default();
        let start = 10 * W;
        cache.check_and_record_at(1, 2, 1, start, start).unwrap();
        // Later traffic moves the window forward and evicts the first nonce.
        let later = start + W + 1;
        cache.check_and_record_at(1, 2, 2, later, later).unwrap();
        assert_eq!(cache.len(), 1);
        // A replay is now stale, even if the local clock steps backwards.
        for now in [later, start] {
            assert!(matches!(
                cache.check_and_record_at(1, 2, 1, start, now),
                Err(ReplayCacheError::StaleTimestamp)
            ));
        }
    }

    #[test]
    fn full_cache_fails_closed_until_entries_expire() {
        let cache = SlidingWindowReplayCache::with_clock(300, 2, || 0);
        let now = 10 * W;
        cache.check_and_record_at(1, 2, 1, now, now).unwrap();
        cache.check_and_record_at(1, 2, 2, now, now).unwrap();
        assert!(matches!(
            cache.check_and_record_at(1, 2, 3, now, now),
            Err(ReplayCacheError::CacheFull)
        ));
        let later = now + W + 1;
        assert!(cache.check_and_record_at(1, 2, 3, later, later).is_ok());
    }

    #[test]
    fn concurrent_copies_are_accepted_exactly_once() {
        let cache = std::sync::Arc::new(SlidingWindowReplayCache::default());
        let now = 10 * W;
        let threads: Vec<_> = (0..16)
            .map(|_| {
                let cache = cache.clone();
                std::thread::spawn(move || cache.check_and_record_at(1, 2, 42, now, now).is_ok())
            })
            .collect();
        let accepted = threads
            .into_iter()
            .map(|t| t.join().unwrap())
            .filter(|ok| *ok)
            .count();
        assert_eq!(accepted, 1);
    }
}
