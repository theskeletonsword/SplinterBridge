//! Remote attestation for confidential computing enclaves (AMD SEV-SNP, Intel TDX).
//!
//! Production gateways deployed under DOJ/CFIUS oversight must run inside
//! attested enclaves and prove to the counterparty (and to the fiduciary
//! auditor) that the binary running is the exact audited build, with no
//! backdoors in the Unix sockets or local classifier.
//!
//! This trait is the integration point; operators plug their own attestation
//! service (Azure confidential computing, Oracle confidential computing, or
//! on-prem SEV-SNP/TDX fleet).

use thiserror::Error;

/// Errors from remote attestation.
#[derive(Debug, Error)]
pub enum AttestationError {
    #[error("attestation unavailable")]
    Unavailable,
    #[error("enclave attestation failed: {0}")]
    VerificationFailed(String),
    #[error("unsupported enclave type: {0}")]
    UnsupportedEnclave(String),
    #[error("measurement mismatch: expected {expected}, got {got}")]
    MeasurementMismatch { expected: String, got: String },
}

/// Enclave types supported for confidential computing gateways.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnclaveType {
    AmdSevSnp,
    IntelTdx,
    AppleSecureEnclave,
    AndroidStrongBox,
}

/// Result of a remote attestation verification.
#[derive(Debug, Clone)]
pub struct AttestationReport {
    pub enclave_type: EnclaveType,
    /// SHA-256 of the attested binary measurement.
    pub measurement_hex: String,
    /// Timestamp of attestation generation (epoch ms).
    pub timestamp_ms: i64,
    /// Whether the report was issued by a trusted fiduciary auditor.
    pub fiduciary_verified: bool,
}

/// Trait for verifying remote attestation reports before establishing mTLS.
pub trait AttestationVerifier: Send + Sync {
    /// Verifies an attestation report from a peer gateway. Returns `Ok(())`
    /// only if the measurement matches the audited build and the report is
    /// fresh within the allowed window.
    fn verify(&self, report: &AttestationReport) -> Result<(), AttestationError>;

    /// Returns the expected binary measurement hex for the current build.
    fn expected_measurement(&self) -> String;
}

/// Default verifier: rejects all attestations until the operator configures
/// the trusted measurement and fiduciary auditor.
pub struct DenyAllAttestation;

impl AttestationVerifier for DenyAllAttestation {
    fn verify(&self, _report: &AttestationReport) -> Result<(), AttestationError> {
        Err(AttestationError::Unavailable)
    }

    fn expected_measurement(&self) -> String {
        String::new()
    }
}

impl Default for DenyAllAttestation {
    fn default() -> Self {
        Self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_all_rejects_attestation() {
        let verifier = DenyAllAttestation;
        let report = AttestationReport {
            enclave_type: EnclaveType::AmdSevSnp,
            measurement_hex: "deadbeef".into(),
            timestamp_ms: 0,
            fiduciary_verified: false,
        };
        assert!(verifier.verify(&report).is_err());
    }
}
