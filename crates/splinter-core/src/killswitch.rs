//! Unilateral kill-switch for DOJ / CFIUS monitors.
//!
//! Under a National Security Agreement, the DOJ and CFIUS must be able to
//! terminate cross-border traffic immediately if telemetry, civil identifiers,
//! or protected government data are detected crossing the border.
//!
//! This trait is the integration point for the fiduciary auditor's kill-switch
//! control plane.

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
}

/// Status of the kill-switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillSwitchStatus {
    Armed,   // Traffic flows normally; switch can be flipped at any time.
    Tripped, // All cross-border traffic is blocked until manually rearmed.
}

/// Trait for a kill-switch controllable by a fiduciary auditor.
pub trait KillSwitch: Send + Sync {
    /// Returns the current status.
    fn status(&self) -> KillSwitchStatus;

    /// Trips the kill-switch: all outbound/inbound cross-border traffic is
    /// blocked immediately. Can only be rearmed by the fiduciary auditor.
    fn trip(&self) -> Result<(), KillSwitchError>;

    /// Rearms the kill-switch (auditor-only operation).
    fn rearm(&self, auditor_token: &str) -> Result<(), KillSwitchError>;
}

/// Default kill-switch: armed but cannot be tripped without an operator
/// control plane. Production must wire this to the DOJ/CFIUS monitor panel.
pub struct DefaultKillSwitch;

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

impl Default for DefaultKillSwitch {
    fn default() -> Self {
        Self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_killswitch_is_armed() {
        let ks = DefaultKillSwitch;
        assert_eq!(ks.status(), KillSwitchStatus::Armed);
    }
}
