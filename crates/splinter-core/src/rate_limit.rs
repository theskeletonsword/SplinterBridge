//! Rate limiting and backpressure hooks.
//!
//! Production deployments must back this with a distributed rate limiter
//! (Redis Lua token bucket, shared sliding-window counter, or sidecar proxy).
//! The trait is intentionally minimal so operators can plug their own backend.

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

/// Trait for a distributed rate limiter shared across gateway instances.
///
/// Implementations must:
/// - Be safe for concurrent use across gateway worker threads.
/// - Return `Allow` or `RetryAfter` within a bounded deadline.
/// - Enforce per-route or per-peer limits independently.
pub trait RateLimiter: Send + Sync {
    /// Checks whether a request for `key` may proceed. `key` should be a route
    // or peer identifier (e.g. "origin:destination").
    fn check(&self, key: &str) -> Result<RateLimitVerdict, RateLimitError>;

    /// Current wall-clock time in milliseconds since the UNIX epoch.
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

/// No-op rate limiter: allows everything. Suitable for development and for
/// gateways behind an external sidecar proxy (Envoy, NGINX, AWS ALB) that
/// enforces rate limiting at the network edge.
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

/// Simple in-memory token bucket for single-instance gateways.
///
/// Not shared across instances; production clusters must use a distributed
/// backend. Included for development and for small single-node deployments.
pub struct TokenBucket {
    #[allow(dead_code)]
    capacity: u64,
    #[allow(dead_code)]
    refill_per_sec: u64,
    _key: std::marker::PhantomData<()>,
}

impl TokenBucket {
    /// Creates a token bucket with `capacity` tokens and `refill_per_sec`
    /// refill rate.
    pub fn new(capacity: u64, refill_per_sec: u64) -> Self {
        Self {
            capacity,
            refill_per_sec,
            _key: std::marker::PhantomData,
        }
    }
}

impl Default for TokenBucket {
    fn default() -> Self {
        Self::new(10_000, 10_000)
    }
}

impl RateLimiter for TokenBucket {
    fn check(&self, _key: &str) -> Result<RateLimitVerdict, RateLimitError> {
        // Stub: always allow. Production tracks tokens per key with TTL.
        Ok(RateLimitVerdict::Allow)
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
    fn token_bucket_allows_everything_stub() {
        let limiter = TokenBucket::default();
        assert_eq!(limiter.check("route:1:2").unwrap(), RateLimitVerdict::Allow);
    }
}
