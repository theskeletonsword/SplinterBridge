//! Hardware Security Module (HSM) abstraction.
//!
//! Production deployments must back this with a FIPS 140-3 Level 3 (West) or
//! OSCCA GM/T (China) certified HSM via PKCS#11 or vendor APIs. The trait is
//! intentionally minimal so operators can plug their own HSM backend.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Errors from HSM operations.
#[derive(Debug, thiserror::Error)]
pub enum HsmError {
    #[error("HSM unavailable")]
    Unavailable,
    #[error("key not found in HSM")]
    KeyNotFound,
    #[error("HSM operation failed: {0}")]
    OperationFailed(String),
    #[error("invalid key material: {0}")]
    InvalidKey(String),
}

/// Trait for an HSM-backed signing key store.
///
/// Implementations must:
/// - Never expose raw private key material to the Rust process.
/// - Perform signing inside the HSM boundary.
/// - Be safe for concurrent use across gateway worker threads.
pub trait HsmSigner: Send + Sync {
    /// Signs a message using the HSM-resident key identified by `key_id`.
    /// Returns the Ed25519 signature bytes.
    fn sign(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, HsmError>;

    /// Returns the public verifying key for `key_id`.
    fn verifying_key(&self, key_id: &str) -> Result<VerifyingKey, HsmError>;

    /// Rotates the key material for `key_id` inside the HSM.
    fn rotate_key(&self, _key_id: &str) -> Result<(), HsmError> {
        Err(HsmError::Unavailable)
    }
}

/// Software-backed HSM implementation for development and testing.
///
/// Private keys live in process memory. Production must replace this with a
/// real HSM (PKCS#11 or vendor API) that never exposes private key material.
pub struct SoftwareHsm {
    keys: Arc<RwLock<HashMap<String, SigningKey>>>,
}

impl SoftwareHsm {
    /// Creates a new software HSM with no preloaded keys.
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Loads an Ed25519 signing key into process memory.
    pub fn load_key(&self, key_id: &str, key: SigningKey) {
        self.keys
            .write()
            .expect("HSM key store lock poisoned")
            .insert(key_id.to_string(), key);
    }
}

impl Default for SoftwareHsm {
    fn default() -> Self {
        Self::new()
    }
}

impl HsmSigner for SoftwareHsm {
    fn sign(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, HsmError> {
        let keys = self.keys.read().expect("HSM key store lock poisoned");
        let key = keys.get(key_id).ok_or(HsmError::KeyNotFound)?;
        let signature = key.sign(message);
        Ok(signature.to_bytes().to_vec())
    }

    fn verifying_key(&self, key_id: &str) -> Result<VerifyingKey, HsmError> {
        let keys = self.keys.read().expect("HSM key store lock poisoned");
        let key = keys.get(key_id).ok_or(HsmError::KeyNotFound)?;
        Ok(key.verifying_key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn software_hsm_sign_and_verify() {
        let hsm = SoftwareHsm::default();
        let key = SigningKey::generate(&mut OsRng);
        let pubkey = key.verifying_key();
        hsm.load_key("dev-key", key);

        let sig = hsm.sign("dev-key", b"hello").unwrap();
        let sig_array: [u8; 64] = sig.try_into().unwrap();
        let signature = ed25519_dalek::Signature::from(sig_array);
        assert!(pubkey.verify_strict(b"hello", &signature).is_ok());
        assert!(hsm.verifying_key("missing-key").is_err());
    }
}
