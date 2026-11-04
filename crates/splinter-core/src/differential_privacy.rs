//! Differential-privacy and k-anonymity primitives for aggregated egress metrics.
//!
//! Intended for engagement counts, view trends and telemetry that cross the
//! border without an individual profile: inject noise at the gateway before
//! emitting counts, and emit only aggregates that mix at least `k` users.
//!
//! These are statistical safeguards, not a stand-alone legal anonymization
//! certificate. Pair them with field minimization, route policy and the
//! ephemeral-identity module. See docs/ANONYMIZATION.md.

use rand::rngs::OsRng;
use rand::Rng;
use thiserror::Error;

/// Errors from differential-privacy mechanisms.
#[derive(Debug, Error)]
pub enum DifferentialPrivacyError {
    #[error("epsilon must be greater than zero")]
    EpsilonMustBePositive,
    #[error("k-anonymity threshold must be greater than zero")]
    KMustBePositive,
}

/// Laplace noise with scale `b` (inverse-CDF draw from a CSPRNG).
pub fn laplace_noise(scale: f64) -> f64 {
    if scale <= 0.0 {
        return 0.0;
    }
    let mut rng = OsRng;
    let u: f64 = rng.gen_range(-0.5..0.5);
    -scale * u.signum() * (1.0 - 2.0 * u.abs()).ln()
}

/// Gaussian noise with standard deviation `sigma` (Box-Muller transform).
pub fn gaussian_noise(stddev: f64) -> f64 {
    if stddev <= 0.0 {
        return 0.0;
    }
    let mut rng = OsRng;
    let u1: f64 = rng.gen_range(0.0..1.0);
    let u2: f64 = rng.gen_range(0.0..1.0);
    let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
    z * stddev
}

/// Noisy count via the Laplace mechanism: `count + Laplace(1 / epsilon)`.
/// Unit sensitivity for a single-user contribution to the aggregate.
pub fn noisy_count(count: u64, epsilon: f64) -> Result<f64, DifferentialPrivacyError> {
    if epsilon <= 0.0 {
        return Err(DifferentialPrivacyError::EpsilonMustBePositive);
    }
    Ok(count as f64 + laplace_noise(1.0 / epsilon))
}

/// K-anonymity gate: emits `count` only if at least `k` users contribute;
/// otherwise suppresses (`None`) so no small bucket can be isolated.
/// Pair with l-diversity when the aggregate itself reveals sensitive categories.
pub fn k_anonymous_bucket(count: u64, k: u64) -> Result<Option<u64>, DifferentialPrivacyError> {
    if k == 0 {
        return Err(DifferentialPrivacyError::KMustBePositive);
    }
    Ok(if count >= k { Some(count) } else { None })
}

/// Generalizes an exact follower count into a k-anonymity bucket so the exact
/// value cannot act as a re-identification fingerprint (NIST SP 800-188).
///
/// Returns the greatest multiple of `k` not exceeding `count`. For example,
/// `generalize_followers_count(14_892, 50) == 14_850`. The UI can keep
/// rendering a formatted value (e.g. "14.8K") while the wire-level value is
/// statistically shared by at least `k` accounts.
pub fn generalize_followers_count(count: u64, k: u64) -> Result<u64, DifferentialPrivacyError> {
    if k == 0 {
        return Err(DifferentialPrivacyError::KMustBePositive);
    }
    Ok((count / k) * k)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn noisy_count_is_randomized() {
        let mut seen = HashSet::new();
        for _ in 0..200 {
            let v = noisy_count(10_000, 1.0).unwrap();
            seen.insert(v.round() as i64);
        }
        assert!(seen.len() > 1, "Laplace noise must randomize the count");
    }

    #[test]
    fn noisy_count_respects_epsilon() {
        // Larger epsilon -> tighter noise around the true count.
        let tight: Vec<f64> = (0..50).map(|_| noisy_count(1000, 10.0).unwrap()).collect();
        let loose: Vec<f64> = (0..50).map(|_| noisy_count(1000, 0.1).unwrap()).collect();
        let tight_mad = mean_abs_deviation(&tight, 1000.0);
        let loose_mad = mean_abs_deviation(&loose, 1000.0);
        assert!(tight_mad < loose_mad);
    }

    #[test]
    fn k_anonymous_suppresses_small_buckets() {
        assert_eq!(k_anonymous_bucket(5, 100).unwrap(), None);
        assert_eq!(k_anonymous_bucket(99, 100).unwrap(), None);
        assert_eq!(k_anonymous_bucket(100, 100).unwrap(), Some(100));
        assert_eq!(k_anonymous_bucket(101, 100).unwrap(), Some(101));
    }

    #[test]
    fn validates_inputs() {
        assert!(noisy_count(1, 0.0).is_err());
        assert!(noisy_count(1, -1.0).is_err());
        assert!(k_anonymous_bucket(1, 0).is_err());
        assert!(generalize_followers_count(1, 0).is_err());
    }

    #[test]
    fn generalize_followers_count_buckets_to_k() {
        assert_eq!(generalize_followers_count(14_892, 50).unwrap(), 14_850);
        assert_eq!(generalize_followers_count(14_892, 100).unwrap(), 14_800);
        assert_eq!(generalize_followers_count(42, 50).unwrap(), 0);
        assert_eq!(generalize_followers_count(100, 50).unwrap(), 100);
    }

    fn mean_abs_deviation(values: &[f64], center: f64) -> f64 {
        values.iter().map(|v| (v - center).abs()).sum::<f64>() / values.len() as f64
    }
}
