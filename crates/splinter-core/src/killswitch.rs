//! Kill switch that stops all exports and acceptances on a gateway.
//!
//! Gateways configured with a kill switch check it before doing any work and
//! reject everything while it is tripped. Who may trip it, and how that control
//! plane is authenticated, is deployment work.

use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, Ordering};
use thiserror::Error;

/// Errors from kill-switch operations.
#[derive(Debug, Error)]
pub enum KillSwitchError {
    #[error("kill-switch unavailable")]
    Unavailable,
    #[error("kill-switch already active")]
    AlreadyActive,
    #[error("activation failed: {0}")]
    ActivationFailed(String),
    #[error("invalid auditor token")]
    InvalidAuditorToken,
}

/// Status of the kill-switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillSwitchStatus {
    Armed,   // Traffic flows normally; switch can be flipped at any time.
    Tripped, // All cross-border traffic is blocked until rearmed.
}

/// Trait for a kill switch controllable by an auditor.
pub trait KillSwitch: Send + Sync {
    /// Returns the current status.
    fn status(&self) -> KillSwitchStatus;

    /// Trips the kill switch: gateways using it block all traffic immediately.
    fn trip(&self) -> Result<(), KillSwitchError>;

    /// Rearms the kill switch (auditor-only operation).
    fn rearm(&self, auditor_token: &str) -> Result<(), KillSwitchError>;
}

/// Placeholder that is always armed and can never be tripped.
#[deprecated(note = "cannot be tripped; use AtomicKillSwitch")]
pub struct DefaultKillSwitch;

#[allow(deprecated)]
impl KillSwitch for DefaultKillSwitch {
    fn status(&self) -> KillSwitchStatus {
        KillSwitchStatus::Armed
    }

    fn trip(&self) -> Result<(), KillSwitchError> {
        Err(KillSwitchError::Unavailable)
    }

    fn rearm(&self, _auditor_token: &str) -> Result<(), KillSwitchError> {
        Err(KillSwitchError::Unavailable)
    }
}

#[allow(deprecated)]
impl Default for DefaultKillSwitch {
    fn default() -> Self {
        Self
    }
}

/// In-process kill switch. Anyone holding a reference can trip it; rearming
/// requires the auditor token whose SHA-256 was configured at construction.
/// The token itself is never stored.
pub struct AtomicKillSwitch {
    tripped: AtomicBool,
    rearm_token_sha256: [u8; 32],
}

impl AtomicKillSwitch {
    /// Creates an armed switch from the SHA-256 of the auditor's rearm token.
    pub fn new(rearm_token_sha256: [u8; 32]) -> Self {
        Self {
            tripped: AtomicBool::new(false),
            rearm_token_sha256,
        }
    }

    /// Convenience constructor hashing `token`; prefer [`AtomicKillSwitch::new`]
    /// so the plaintext token never reaches the gateway host.
    pub fn from_token(token: &str) -> Self {
        Self::new(Sha256::digest(token.as_bytes()).into())
    }
}

impl KillSwitch for AtomicKillSwitch {
    fn status(&self) -> KillSwitchStatus {
        if self.tripped.load(Ordering::SeqCst) {
            KillSwitchStatus::Tripped
        } else {
            KillSwitchStatus::Armed
        }
    }

    fn trip(&self) -> Result<(), KillSwitchError> {
        if self.tripped.swap(true, Ordering::SeqCst) {
            return Err(KillSwitchError::AlreadyActive);
        }
        Ok(())
    }

    fn rearm(&self, auditor_token: &str) -> Result<(), KillSwitchError> {
        let digest: [u8; 32] = Sha256::digest(auditor_token.as_bytes()).into();
        // Constant-time comparison: do not leak how many bytes matched.
        let diff = digest
            .iter()
            .zip(self.rearm_token_sha256.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        if diff != 0 {
            return Err(KillSwitchError::InvalidAuditorToken);
        }
        self.tripped.store(false, Ordering::SeqCst);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(deprecated)]
    fn default_killswitch_is_armed_and_cannot_trip() {
        let ks = DefaultKillSwitch;
        assert_eq!(ks.status(), KillSwitchStatus::Armed);
        assert!(ks.trip().is_err());
    }

    #[test]
    fn atomic_killswitch_trips_and_only_the_auditor_token_rearms() {
        let ks = AtomicKillSwitch::from_token("auditor-secret");
        assert_eq!(ks.status(), KillSwitchStatus::Armed);
        ks.trip().unwrap();
        assert_eq!(ks.status(), KillSwitchStatus::Tripped);
        assert!(matches!(ks.trip(), Err(KillSwitchError::AlreadyActive)));
        assert!(matches!(
            ks.rearm("wrong"),
            Err(KillSwitchError::InvalidAuditorToken)
        ));
        assert_eq!(ks.status(), KillSwitchStatus::Tripped);
        ks.rearm("auditor-secret").unwrap();
        assert_eq!(ks.status(), KillSwitchStatus::Armed);
    }
}
