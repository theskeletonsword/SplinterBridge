//! SplinterBridge Blind Identity Projection and Cryptographic Attestation.
//!
//! Enforces Zero-PII by mapping private internal database identifiers into
//! irreversible pseudonymous decentralized identifiers (`federated_did`) via
//! HMAC-SHA256 with regional pepper keys.
//!
//! Packages sanitized public profiles and generates Ed25519 signatures for
//! authentic cross-border gateway verification.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use splinter_proto::{Jurisdiction, SanitizedPublicProfile, VerifiedBadgeType};
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

/// Errors occurring during identity projection, sanitization, or signature verification.
#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("HMAC initialization failed: key length or structure invalid")]
    HmacInitError,

    #[error("Ed25519 signature verification failed: signature does not match canonical payload")]
    InvalidSignature,

    #[error("Serialization error during canonical payload encoding: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Invalid public key bytes: {0}")]
    InvalidPublicKey(#[from] ed25519_dalek::SignatureError),

    #[error("Unsupported origin jurisdiction for identity derivation: {0:?}")]
    UnsupportedJurisdiction(Jurisdiction),
}

/// Secret regional cryptographic pepper stored strictly inside the sovereign gateway's HSM/KMS.
/// Crucial invariant: regional peppers NEVER cross sovereign borders.
#[derive(Clone)]
pub struct RegionalPepper {
    key_bytes: Vec<u8>,
}

impl RegionalPepper {
    /// Constructs a regional pepper from raw secret bytes.
    pub fn new(key: &[u8]) -> Self {
        Self {
            key_bytes: key.to_vec(),
        }
    }

    /// Helper for testing with secure pseudo-random seeds.
    #[cfg(test)]
    pub fn new_test() -> Self {
        Self {
            key_bytes: b"splinterbridge-regional-pepper-test-secret-key-32b".to_vec(),
        }
    }
}

/// Raw internal user model resident strictly within the domestic cluster database.
/// Contains private data (PII) that MUST NOT cross sovereign boundaries.
#[derive(Debug, Clone)]
pub struct RawInternalUserProfile {
    pub internal_user_id: String,
    pub national_id_hash: Option<String>, // e.g. China Shimingzhi real-name compliance
    pub email: Option<String>,
    pub phone: Option<String>,
    pub internal_ip_address: Option<String>,
    pub handle: String,
    pub display_name: String,
    pub avatar_url: String,
    pub followers_count: u64,
    pub following_count: u64,
    pub is_private: bool,
    pub badges: Vec<VerifiedBadgeType>,
}

/// Generates an immutable, non-reversible `federated_did` using HMAC-SHA256 with regional pepper.
///
/// Output format: `did:splinter:<jurisdiction_code>:<hex_digest>`
pub fn derive_federated_did(
    internal_user_id: &str,
    jurisdiction: Jurisdiction,
    pepper: &RegionalPepper,
) -> Result<String, IdentityError> {
    let jur_code = match jurisdiction {
        Jurisdiction::JurisdictionGlobalGdpr => "global",
        Jurisdiction::JurisdictionCnPiplCac => "cn",
        Jurisdiction::JurisdictionRu152Fz => "ru",
        Jurisdiction::JurisdictionUnspecified => {
            return Err(IdentityError::UnsupportedJurisdiction(jurisdiction))
        }
    };

    let mut mac = HmacSha256::new_from_slice(&pepper.key_bytes)
        .map_err(|_| IdentityError::HmacInitError)?;

    mac.update(jur_code.as_bytes());
    mac.update(b":");
    mac.update(internal_user_id.as_bytes());

    let result = mac.finalize();
    let digest_hex = hex::encode(result.into_bytes());

    Ok(format!("did:splinter:{}:{}", jur_code, digest_hex))
}

/// Projects a domestic user profile into a clean, zero-PII sanitized profile.
/// Drops email, phone, IP, and real-name Shimingzhi data before cross-border transit.
pub fn project_blind_profile(
    raw: &RawInternalUserProfile,
    jurisdiction: Jurisdiction,
    pepper: &RegionalPepper,
) -> Result<SanitizedPublicProfile, IdentityError> {
    let federated_did = derive_federated_did(&raw.internal_user_id, jurisdiction, pepper)?;

    Ok(SanitizedPublicProfile {
        federated_did,
        handle: raw.handle.clone(),
        display_name: raw.display_name.clone(),
        public_avatar_url: raw.avatar_url.clone(),
        followers_count: raw.followers_count,
        following_count: raw.following_count,
        is_private: raw.is_private,
        badges: raw.badges.iter().map(|b| *b as i32).collect(),
        origin_jurisdiction: jurisdiction as i32,
    })
}

/// Canonical payload representation for deterministic Ed25519 signature computation.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct CanonicalProfilePayload<'a> {
    federated_did: &'a str,
    handle: &'a str,
    display_name: &'a str,
    followers_count: u64,
    following_count: u64,
    is_private: bool,
    origin_jurisdiction: i32,
}

/// Origin Gateway cryptographic signing agent.
pub struct GatewaySigner {
    signing_key: SigningKey,
}

impl GatewaySigner {
    /// Creates a signer from an Ed25519 private signing key.
    pub fn new(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }

    /// Returns the associated public verifying key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Produces a deterministic Ed25519 digital signature over a sanitized profile projection.
    pub fn sign_profile(&self, profile: &SanitizedPublicProfile) -> Result<Vec<u8>, IdentityError> {
        let canonical = CanonicalProfilePayload {
            federated_did: &profile.federated_did,
            handle: &profile.handle,
            display_name: &profile.display_name,
            followers_count: profile.followers_count,
            following_count: profile.following_count,
            is_private: profile.is_private,
            origin_jurisdiction: profile.origin_jurisdiction,
        };

        let serialized = serde_json::to_vec(&canonical)?;
        let signature = self.signing_key.sign(&serialized);
        Ok(signature.to_bytes().to_vec())
    }
}

/// Remote Gateway verification agent for authenticating cross-border assertions.
pub struct GatewayVerifier;

impl GatewayVerifier {
    /// Validates an incoming sanitized profile against the origin gateway's public verifying key.
    pub fn verify_profile(
        public_key_bytes: &[u8; 32],
        profile: &SanitizedPublicProfile,
        signature_bytes: &[u8],
    ) -> Result<(), IdentityError> {
        let verifying_key = VerifyingKey::from_bytes(public_key_bytes)?;
        let signature = Signature::from_slice(signature_bytes)
            .map_err(|_| IdentityError::InvalidSignature)?;

        let canonical = CanonicalProfilePayload {
            federated_did: &profile.federated_did,
            handle: &profile.handle,
            display_name: &profile.display_name,
            followers_count: profile.followers_count,
            following_count: profile.following_count,
            is_private: profile.is_private,
            origin_jurisdiction: profile.origin_jurisdiction,
        };

        let serialized = serde_json::to_vec(&canonical)?;
        verifying_key
            .verify(&serialized, &signature)
            .map_err(|_| IdentityError::InvalidSignature)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_blind_did_is_deterministic_and_irreversible() {
        let pepper = RegionalPepper::new_test();
        let internal_id = "user_uuid_948201_internal";

        let did1 = derive_federated_did(internal_id, Jurisdiction::JurisdictionGlobalGdpr, &pepper).unwrap();
        let did2 = derive_federated_did(internal_id, Jurisdiction::JurisdictionGlobalGdpr, &pepper).unwrap();

        assert_eq!(did1, did2);
        assert!(did1.starts_with("did:splinter:global:"));
        // Does not expose internal ID in raw or base64 format
        assert!(!did1.contains("user_uuid_948201_internal"));
    }

    #[test]
    fn test_project_blind_profile_scrubs_pii() {
        let pepper = RegionalPepper::new_test();
        let raw = RawInternalUserProfile {
            internal_user_id: "int_884920".into(),
            national_id_hash: Some("cn_id_110101199003072345".into()),
            email: Some("skels@example.com".into()),
            phone: Some("+8613800138000".into()),
            internal_ip_address: Some("192.168.1.100".into()),
            handle: "@theskeletonsword".into(),
            display_name: "perex".into(),
            avatar_url: "https://cdn.splinterbridge.org/avatars/skels.webp".into(),
            followers_count: 14200,
            following_count: 85,
            is_private: false,
            badges: vec![VerifiedBadgeType::VerifiedBadgeHardwareAttestedHuman],
        };

        let public_profile = project_blind_profile(&raw, Jurisdiction::JurisdictionGlobalGdpr, &pepper).unwrap();

        assert_eq!(public_profile.handle, "@theskeletonsword");
        assert_eq!(public_profile.display_name, "perex");
        assert_eq!(public_profile.followers_count, 14200);
        assert_eq!(public_profile.following_count, 85);
        assert!(!public_profile.is_private);
        assert_eq!(public_profile.badges.len(), 1);
        assert!(public_profile.federated_did.starts_with("did:splinter:global:"));
    }

    #[test]
    fn test_signature_and_verification_lifecycle() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let signer = GatewaySigner::new(signing_key.clone());
        let public_key_bytes = signer.verifying_key().to_bytes();

        let pepper = RegionalPepper::new_test();
        let raw = RawInternalUserProfile {
            internal_user_id: "int_user_12345".into(),
            national_id_hash: None,
            email: None,
            phone: None,
            internal_ip_address: None,
            handle: "@theskeletonsword".into(),
            display_name: "perex".into(),
            avatar_url: "https://cdn.splinterbridge.org/avatars/perex.webp".into(),
            followers_count: 500,
            following_count: 120,
            is_private: false,
            badges: vec![VerifiedBadgeType::VerifiedBadgeCreatorPartner],
        };

        let profile = project_blind_profile(&raw, Jurisdiction::JurisdictionGlobalGdpr, &pepper).unwrap();
        let sig = signer.sign_profile(&profile).unwrap();

        // Remote gateway verifies the signature
        assert!(GatewayVerifier::verify_profile(&public_key_bytes, &profile, &sig).is_ok());

        // Tamper test: modify display_name
        let mut tampered = profile.clone();
        tampered.display_name = "impersonator".into();
        assert!(GatewayVerifier::verify_profile(&public_key_bytes, &tampered, &sig).is_err());
    }
}
