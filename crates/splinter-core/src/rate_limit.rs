//! Rate limiting and backpressure hooks.
//!
//! `TokenBucket` limits one gateway process. Clusters that need a shared limit
//! across instances must back [`RateLimiter`] with a distributed store (Redis
//! token bucket, shared sliding-window counter) or an edge proxy.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Verdict returned by the rate limiter for an inbound or outbound request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitVerdict {
    /// Request is allowed to proceed.
    Allow,
    /// Request is rejected; caller should retry after `retry_after_ms`.
    RetryAfter { retry_after_ms: u64 },
}

/// Errors from the rate limiter.
#[derive(Debug, thiserror::Error)]
pub enum RateLimitError {
    #[error("rate limiter unavailable")]
    Unavailable,
}

/// Trait for a rate limiter.
///
/// Implementations must:
/// - Be safe for concurrent use across gateway worker threads.
/// - Return `Allow` or `RetryAfter` within a bounded deadline.
/// - Enforce per-route or per-peer limits independently.
pub trait RateLimiter: Send + Sync {
    /// Checks whether a request for `key` may proceed. `key` should be a route
    /// or peer identifier taken from local configuration, never from the
    /// unauthenticated request.
    fn check(&self, key: &str) -> Result<RateLimitVerdict, RateLimitError>;

    /// Current wall-clock time in milliseconds since the UNIX epoch.
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

/// No-op rate limiter: allows everything. Use only when an external proxy
/// (Envoy, NGINX, a load balancer) enforces limits at the network edge.
pub struct NoopRateLimiter;

impl RateLimiter for NoopRateLimiter {
    fn check(&self, _key: &str) -> Result<RateLimitVerdict, RateLimitError> {
        Ok(RateLimitVerdict::Allow)
    }
}

impl Default for NoopRateLimiter {
    fn default() -> Self {
        Self
    }
}

/// Default bound on tracked keys before unknown keys are refused.
pub const DEFAULT_RATE_LIMIT_MAX_KEYS: usize = 10_000;

/// Token amounts are tracked in thousandths so refill needs no floating point.
const MILLI: u64 = 1000;

struct Bucket {
    milli_tokens: u64,
    last_ms: u64,
}

/// In-memory token bucket per key for a single gateway process.
///
/// Each key starts with `capacity` tokens, refills at `refill_per_sec`, and
/// each request costs one token. At most `max_keys` keys are tracked; buckets
/// that have refilled completely are pruned first, and if the limit still
/// holds, requests for new keys fail with [`RateLimitError::Unavailable`].
pub struct TokenBucket {
    capacity: u64,
    refill_per_sec: u64,
    max_keys: usize,
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl TokenBucket {
    /// Creates a token bucket with `capacity` tokens and `refill_per_sec`
    /// refill rate. Values below 1 are raised to 1.
    pub fn new(capacity: u64, refill_per_sec: u64) -> Self {
        Self::with_max_keys(capacity, refill_per_sec, DEFAULT_RATE_LIMIT_MAX_KEYS)
    }

    /// Like [`TokenBucket::new`] with an explicit bound on tracked keys.
    pub fn with_max_keys(capacity: u64, refill_per_sec: u64, max_keys: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            refill_per_sec: refill_per_sec.max(1),
            max_keys: max_keys.max(1),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Same as [`RateLimiter::check`] with an explicit current time.
    pub fn check_at(&self, key: &str, now_ms: u64) -> Result<RateLimitVerdict, RateLimitError> {
        let full = self.capacity.saturating_mul(MILLI);
        let mut buckets = self
            .buckets
            .lock()
            .map_err(|_| RateLimitError::Unavailable)?;
        if !buckets.contains_key(key) && buckets.len() >= self.max_keys {
            buckets.retain(|_, b| self.refilled(b, now_ms) < full);
            if buckets.len() >= self.max_keys {
                return Err(RateLimitError::Unavailable);
            }
        }
        let bucket = buckets.entry(key.to_owned()).or_insert(Bucket {
            milli_tokens: full,
            last_ms: now_ms,
        });
        bucket.milli_tokens = self.refilled(bucket, now_ms);
        bucket.last_ms = bucket.last_ms.max(now_ms);
        if bucket.milli_tokens >= MILLI {
            bucket.milli_tokens -= MILLI;
            return Ok(RateLimitVerdict::Allow);
        }
        // refill_per_sec tokens per second == refill_per_sec milli-tokens per ms.
        let missing = MILLI - bucket.milli_tokens;
        Ok(RateLimitVerdict::RetryAfter {
            retry_after_ms: missing.div_ceil(self.refill_per_sec),
        })
    }

    fn refilled(&self, bucket: &Bucket, now_ms: u64) -> u64 {
        let elapsed = now_ms.saturating_sub(bucket.last_ms);
        bucket
            .milli_tokens
            .saturating_add(elapsed.saturating_mul(self.refill_per_sec))
            .min(self.capacity.saturating_mul(MILLI))
    }
}

impl Default for TokenBucket {
    fn default() -> Self {
        Self::new(10_000, 10_000)
    }
}

impl RateLimiter for TokenBucket {
    fn check(&self, key: &str) -> Result<RateLimitVerdict, RateLimitError> {
        self.check_at(key, self.now_ms())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_allows_everything() {
        let limiter = NoopRateLimiter;
        assert_eq!(limiter.check("route:1:2").unwrap(), RateLimitVerdict::Allow);
    }

    #[test]
    fn bucket_drains_then_refills_over_time() {
        let limiter = TokenBucket::new(3, 2);
        for _ in 0..3 {
            assert_eq!(
                limiter.check_at("peer", 0).unwrap(),
                RateLimitVerdict::Allow
            );
        }
        // Empty: one token at 2/s takes 500 ms.
        assert_eq!(
            limiter.check_at("peer", 0).unwrap(),
            RateLimitVerdict::RetryAfter {
                retry_after_ms: 500
            }
        );
        assert_eq!(
            limiter.check_at("peer", 250).unwrap(),
            RateLimitVerdict::RetryAfter {
                retry_after_ms: 250
            }
        );
        assert_eq!(
            limiter.check_at("peer", 500).unwrap(),
            RateLimitVerdict::Allow
        );
        // Refill is capped at capacity no matter how long the key was idle.
        for _ in 0..3 {
            assert_eq!(
                limiter.check_at("peer", 1_000_000).unwrap(),
                RateLimitVerdict::Allow
            );
        }
        assert!(matches!(
            limiter.check_at("peer", 1_000_000).unwrap(),
            RateLimitVerdict::RetryAfter { .. }
        ));
    }

    #[test]
    fn keys_are_independent_and_clock_steps_back_do_not_refill() {
        let limiter = TokenBucket::new(1, 1);
        assert_eq!(
            limiter.check_at("a", 5_000).unwrap(),
            RateLimitVerdict::Allow
        );
        assert_eq!(
            limiter.check_at("b", 5_000).unwrap(),
            RateLimitVerdict::Allow
        );
        assert!(matches!(
            limiter.check_at("a", 0).unwrap(),
            RateLimitVerdict::RetryAfter { .. }
        ));
    }

    #[test]
    fn tracked_keys_are_bounded() {
        let limiter = TokenBucket::with_max_keys(1, 1, 2);
        limiter.check_at("a", 0).unwrap();
        limiter.check_at("b", 0).unwrap();
        // Both buckets are drained, so a third key cannot evict them.
        assert!(limiter.check_at("c", 0).is_err());
        // Once they refill they are equivalent to fresh buckets and get pruned.
        assert_eq!(
            limiter.check_at("c", 1_000).unwrap(),
            RateLimitVerdict::Allow
        );
    }
}
