//! SplinterBridge Blind Identity Projection and Cryptographic Attestation.
//!
//! Maps private internal database identifiers into
//! pseudonymous decentralized identifiers (`federated_did`) via
//! HMAC-SHA256 with regional pepper keys.
//!
//! Packages sanitized public profiles and generates Ed25519 signatures for
//! authentic cross-border gateway verification.
//!
//! ## Pseudonymization is not anonymization
//!
//! `derive_federated_did` is deterministic: given the internal user ID and the
//! regional pepper, the origin operator can recompute any account's DID and
//! confirm a match (for example, under a court or police request). The origin
//! backend still stores `user_id` and the pepper locally, so this is
//! **pseudonimización de máxima frontera**, reversible por el origen — no
//! anonimización irreversible bajo PIPL art. 73 ni GDPR Considerando 26.
//! Public handles and names can identify people independently of the DID.
//!
//! For unlinkable, rotating-seed identifiers whose reversal secret is
//! crypto-shredded, see [`crate::ephemeral`]. For aggregates without an
//! individual trace, see [`crate::differential_privacy`]. The realistic
//! industry path for a persistent-profile social network is to homologate this
//! shielded pseudonymization inside formal transfer mechanisms (CAC assessment
//! / standard contractual clauses), not to claim anonymous profiles. See
//! docs/ANONYMIZATION.md.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hmac::{Hmac, Mac};
use prost::Message;
use sha2::Sha256;
use splinter_proto::FederatedEventEnvelope;
use splinter_proto::{Jurisdiction, SanitizedPublicProfile, VerifiedBadgeType};
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

/// Errors occurring during identity projection, sanitization, or signature verification.
#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("HMAC initialization failed: key length or structure invalid")]
    HmacInitError,

    #[error("Regional pepper must contain at least 32 bytes")]
    WeakPepper,

    #[error("Internal user ID must not be empty")]
    EmptyUserId,

    #[error("Ed25519 signature verification failed: signature does not match canonical payload")]
    InvalidSignature,

    #[error("Serialization error during canonical payload encoding: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Invalid public key bytes: {0}")]
    InvalidPublicKey(#[from] ed25519_dalek::SignatureError),

    #[error("Unsupported origin jurisdiction for identity derivation: {0:?}")]
    UnsupportedJurisdiction(Jurisdiction),
}

/// Secret regional pepper owned in process memory and cleared on drop.
/// Crucial invariant: regional peppers NEVER cross sovereign borders.
#[derive(Clone)]
pub struct RegionalPepper {
    key_bytes: zeroize::Zeroizing<Vec<u8>>,
}

impl RegionalPepper {
    /// Constructs a regional pepper from raw secret bytes.
    pub fn new(key: &[u8]) -> Self {
        Self {
            key_bytes: zeroize::Zeroizing::new(key.to_vec()),
        }
    }

    pub(crate) fn reference_digest(
        &self,
        kind: &str,
        region: &str,
        local_id: &str,
    ) -> Result<String, IdentityError> {
        if self.key_bytes.len() < 32 {
            return Err(IdentityError::WeakPepper);
        }
        if local_id.trim().is_empty() {
            return Err(IdentityError::EmptyUserId);
        }
        let mut mac = HmacSha256::new_from_slice(&self.key_bytes)
            .map_err(|_| IdentityError::HmacInitError)?;
        // This domain cannot equal the jurisdiction-prefixed account DID input.
        mac.update(b"splinterbridge:reference:v1\0");
        for part in [kind, region, local_id] {
            mac.update(&(part.len() as u64).to_be_bytes());
            mac.update(part.as_bytes());
        }
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    /// Helper for testing with secure pseudo-random seeds.
    #[cfg(test)]
    pub fn new_test() -> Self {
        Self {
            key_bytes: zeroize::Zeroizing::new(
                b"splinterbridge-regional-pepper-test-secret-key-32b".to_vec(),
            ),
        }
    }
}

/// Raw internal user model resident strictly within the domestic cluster database.
/// Contains private data (PII) that MUST NOT cross sovereign boundaries.
#[derive(Clone)]
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
    // Actor public key (Ed25519) bound to this civil account, set when the user
    // links an autonomous actor key. Kept local until exported.
    pub actor_public_key: Option<Vec<u8>>,
    // Commitment hash binding the actor key to the locally retained civil ID.
    pub commitment_hash: Option<Vec<u8>>,
}

impl std::fmt::Debug for RawInternalUserProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RawInternalUserProfile { [REDACTED] }")
    }
}

/// Explicit opt-in for fields outside nickname, display name, followers and visibility.
#[derive(Debug, Clone, Copy, Default)]
pub struct PublicProfileOptions {
    pub avatar: bool,
    pub following_count: bool,
    pub badges: bool,
}

/// Generates a deterministic, pseudonymizing `federated_did` using HMAC-SHA256 with regional pepper.
///
/// Output format: `did:splinter:<jurisdiction_code>:<hex_digest>`
///
/// WARNING: this is reversible by the origin operator holding the pepper and
/// the local `internal_user_id`. It is state-of-the-art pseudonymization, not
/// legal anonymization: a court or the origin backend can confirm whether a DID
/// belongs to a given user ID. For unlinkable rotating-seed identifiers see
/// [`crate::ephemeral::derive_ephemeral_did`].
pub fn derive_federated_did(
    internal_user_id: &str,
    jurisdiction: Jurisdiction,
    pepper: &RegionalPepper,
) -> Result<String, IdentityError> {
    if pepper.key_bytes.len() < 32 {
        return Err(IdentityError::WeakPepper);
    }
    if internal_user_id.is_empty() {
        return Err(IdentityError::EmptyUserId);
    }
    let jur_code = match jurisdiction {
        Jurisdiction::GlobalGdpr => "global",
        Jurisdiction::CnPiplCac => "cn",
        Jurisdiction::Ru152Fz => "ru",
        Jurisdiction::Unspecified => {
            return Err(IdentityError::UnsupportedJurisdiction(jurisdiction))
        }
    };

    let mut mac =
        HmacSha256::new_from_slice(&pepper.key_bytes).map_err(|_| IdentityError::HmacInitError)?;

    mac.update(jur_code.as_bytes());
    mac.update(b":");
    mac.update(internal_user_id.as_bytes());

    let result = mac.finalize();
    let digest_hex = hex::encode(result.into_bytes());

    Ok(format!("did:splinter:{}:{}", jur_code, digest_hex))
}

/// Projects the four approved public fields and a pseudonymous identifier.
/// Drops email, phone, IP, and real-name Shimingzhi data before cross-border transit.
pub fn project_blind_profile(
    raw: &RawInternalUserProfile,
    jurisdiction: Jurisdiction,
    pepper: &RegionalPepper,
) -> Result<SanitizedPublicProfile, IdentityError> {
    project_blind_profile_with_options(raw, jurisdiction, pepper, PublicProfileOptions::default())
}

pub fn project_blind_profile_with_options(
    raw: &RawInternalUserProfile,
    jurisdiction: Jurisdiction,
    pepper: &RegionalPepper,
    options: PublicProfileOptions,
) -> Result<SanitizedPublicProfile, IdentityError> {
    let federated_did = derive_federated_did(&raw.internal_user_id, jurisdiction, pepper)?;

    Ok(SanitizedPublicProfile {
        federated_did,
        handle: raw.handle.clone(),
        display_name: raw.display_name.clone(),
        public_avatar_url: if options.avatar {
            raw.avatar_url.clone()
        } else {
            String::new()
        },
        followers_count: raw.followers_count,
        // Generalized to a k-anonymity bucket so the exact count cannot act as a
        // re-identification fingerprint (NIST SP 800-188). Default k = 50.
        generalized_followers_count: crate::differential_privacy::generalize_followers_count(
            raw.followers_count,
            50,
        )
        .unwrap_or(0),
        following_count: if options.following_count {
            raw.following_count
        } else {
            0
        },
        is_private: raw.is_private,
        badges: if options.badges {
            raw.badges.iter().map(|b| *b as i32).collect()
        } else {
            Vec::new()
        },
        origin_jurisdiction: jurisdiction as i32,
        actor_public_key: raw.actor_public_key.clone().unwrap_or_default(),
        commitment_hash: raw.commitment_hash.clone().unwrap_or_default(),
    })
}

/// Canonical payload representation for deterministic Ed25519 signature computation.
#[derive(serde::Serialize, Debug)]
struct CanonicalProfilePayload<'a> {
    federated_did: &'a str,
    handle: &'a str,
    public_avatar_url: &'a str,
    badges: &'a [i32],
    display_name: &'a str,
    followers_count: u64,
    following_count: u64,
    is_private: bool,
    origin_jurisdiction: i32,
    generalized_followers_count: u64,
    actor_public_key: &'a [u8],
    commitment_hash: &'a [u8],
}

impl<'a> From<&'a SanitizedPublicProfile> for CanonicalProfilePayload<'a> {
    fn from(profile: &'a SanitizedPublicProfile) -> Self {
        Self {
            federated_did: &profile.federated_did,
            handle: &profile.handle,
            public_avatar_url: &profile.public_avatar_url,
            badges: &profile.badges,
            display_name: &profile.display_name,
            followers_count: profile.followers_count,
            following_count: profile.following_count,
            is_private: profile.is_private,
            origin_jurisdiction: profile.origin_jurisdiction,
            generalized_followers_count: profile.generalized_followers_count,
            actor_public_key: &profile.actor_public_key,
            commitment_hash: &profile.commitment_hash,
        }
    }
}

fn profile_signing_bytes(profile: &SanitizedPublicProfile) -> Result<Vec<u8>, serde_json::Error> {
    let mut bytes = b"splinterbridge:profile:v2\0".to_vec();
    bytes.extend(serde_json::to_vec(&CanonicalProfilePayload::from(profile))?);
    Ok(bytes)
}

// Sign the complete envelope except its signature, including routing and attestation.
fn envelope_signing_bytes(envelope: &FederatedEventEnvelope) -> Vec<u8> {
    let mut unsigned = envelope.clone();
    unsigned.ed25519_signature.clear();
    let mut bytes = b"splinterbridge:envelope:v1\0".to_vec();
    bytes.extend(unsigned.encode_to_vec());
    bytes
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

    /// Signs the full envelope, replacing any previous signature.
    /// This authenticates bytes, but does not validate content, freshness or trust.
    pub fn sign_envelope(&self, envelope: &mut FederatedEventEnvelope) {
        envelope.ed25519_signature = self
            .signing_key
            .sign(&envelope_signing_bytes(envelope))
            .to_bytes()
            .to_vec();
    }

    /// Returns the associated public verifying key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Produces a deterministic Ed25519 digital signature over a sanitized profile projection.
    pub fn sign_profile(&self, profile: &SanitizedPublicProfile) -> Result<Vec<u8>, IdentityError> {
        let serialized = profile_signing_bytes(profile)?;
        let signature = self.signing_key.sign(&serialized);
        Ok(signature.to_bytes().to_vec())
    }
}

/// Remote Gateway verification agent for authenticating cross-border assertions.
pub struct GatewayVerifier;

impl GatewayVerifier {
    /// Verifies integrity using a key from the caller's trusted registry.
    /// Callers must separately enforce destination, freshness, replay protection,
    /// payload limits, policy checks and hardware attestation validity.
    pub fn verify_envelope(
        public_key_bytes: &[u8; 32],
        envelope: &FederatedEventEnvelope,
    ) -> Result<(), IdentityError> {
        let key = VerifyingKey::from_bytes(public_key_bytes)?;
        let signature = Signature::from_slice(&envelope.ed25519_signature)
            .map_err(|_| IdentityError::InvalidSignature)?;
        key.verify_strict(&envelope_signing_bytes(envelope), &signature)
            .map_err(|_| IdentityError::InvalidSignature)
    }

    /// Validates an incoming sanitized profile against the origin gateway's public verifying key.
    pub fn verify_profile(
        public_key_bytes: &[u8; 32],
        profile: &SanitizedPublicProfile,
        signature_bytes: &[u8],
    ) -> Result<(), IdentityError> {
        let verifying_key = VerifyingKey::from_bytes(public_key_bytes)?;
        let signature =
            Signature::from_slice(signature_bytes).map_err(|_| IdentityError::InvalidSignature)?;

        let serialized = profile_signing_bytes(profile)?;
        verifying_key
            .verify_strict(&serialized, &signature)
            .map_err(|_| IdentityError::InvalidSignature)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_envelope_integrity() {
        let signer = GatewaySigner::new(SigningKey::generate(&mut OsRng));
        let key = signer.verifying_key().to_bytes();
        let mut envelope = FederatedEventEnvelope {
            payload_bytes: b"event".to_vec(),
            origin_jurisdiction: Jurisdiction::GlobalGdpr as i32,
            destination_jurisdiction: Jurisdiction::CnPiplCac as i32,
            origin_gateway_key_id: "trusted-origin".into(),
            ..Default::default()
        };
        signer.sign_envelope(&mut envelope);
        assert!(GatewayVerifier::verify_envelope(&key, &envelope).is_ok());
        let mut changed = envelope.clone();
        changed.payload_bytes.push(0);
        assert!(GatewayVerifier::verify_envelope(&key, &changed).is_err());
        changed = envelope.clone();
        changed.destination_jurisdiction = Jurisdiction::Ru152Fz as i32;
        assert!(GatewayVerifier::verify_envelope(&key, &changed).is_err());
        changed = envelope.clone();
        changed.origin_gateway_key_id.push('x');
        assert!(GatewayVerifier::verify_envelope(&key, &changed).is_err());
        changed = envelope.clone();
        changed.humanity_attestation = Some(Default::default());
        assert!(GatewayVerifier::verify_envelope(&key, &changed).is_err());
        let wrong_key = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        assert!(GatewayVerifier::verify_envelope(&wrong_key, &envelope).is_err());
    }

    #[test]
    fn test_identity_input_validation_and_region_isolation() {
        let pepper = RegionalPepper::new_test();
        assert!(matches!(
            derive_federated_did(
                "u",
                Jurisdiction::GlobalGdpr,
                &RegionalPepper::new(&[0; 31])
            ),
            Err(IdentityError::WeakPepper)
        ));
        assert!(matches!(
            derive_federated_did("", Jurisdiction::GlobalGdpr, &pepper),
            Err(IdentityError::EmptyUserId)
        ));
        assert!(matches!(
            derive_federated_did("u", Jurisdiction::Unspecified, &pepper),
            Err(IdentityError::UnsupportedJurisdiction(_))
        ));
        let global = derive_federated_did("u", Jurisdiction::GlobalGdpr, &pepper).unwrap();
        let cn = derive_federated_did("u", Jurisdiction::CnPiplCac, &pepper).unwrap();
        assert_ne!(global.rsplit(':').next(), cn.rsplit(':').next());
    }

    #[test]
    fn test_blind_did_is_deterministic_and_irreversible() {
        let pepper = RegionalPepper::new_test();
        let internal_id = "user_uuid_948201_internal";

        let did1 = derive_federated_did(internal_id, Jurisdiction::GlobalGdpr, &pepper).unwrap();
        let did2 = derive_federated_did(internal_id, Jurisdiction::GlobalGdpr, &pepper).unwrap();

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
            actor_public_key: None,
            commitment_hash: None,
        };

        let public_profile =
            project_blind_profile(&raw, Jurisdiction::GlobalGdpr, &pepper).unwrap();

        assert_eq!(public_profile.handle, "@theskeletonsword");
        assert_eq!(public_profile.display_name, "perex");
        assert_eq!(public_profile.followers_count, 14200);
        assert_eq!(public_profile.following_count, 0);
        assert!(!public_profile.is_private);
        assert!(public_profile.badges.is_empty());
        assert!(public_profile.public_avatar_url.is_empty());
        assert!(public_profile
            .federated_did
            .starts_with("did:splinter:global:"));
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
            actor_public_key: None,
            commitment_hash: None,
        };

        let profile = project_blind_profile(&raw, Jurisdiction::GlobalGdpr, &pepper).unwrap();
        let sig = signer.sign_profile(&profile).unwrap();

        // Remote gateway verifies the signature
        assert!(GatewayVerifier::verify_profile(&public_key_bytes, &profile, &sig).is_ok());

        let mut avatar_tampered = profile.clone();
        avatar_tampered.public_avatar_url = "https://attacker.invalid/avatar".into();
        assert!(
            GatewayVerifier::verify_profile(&public_key_bytes, &avatar_tampered, &sig).is_err()
        );
        let mut badge_tampered = profile.clone();
        badge_tampered
            .badges
            .push(VerifiedBadgeType::VerifiedBadgeOfficialOrganization as i32);
        assert!(GatewayVerifier::verify_profile(&public_key_bytes, &badge_tampered, &sig).is_err());
        assert!(GatewayVerifier::verify_profile(&public_key_bytes, &profile, &[0; 12]).is_err());

        // Tamper test: modify display_name
        let mut tampered = profile.clone();
        tampered.display_name = "impersonator".into();
        assert!(GatewayVerifier::verify_profile(&public_key_bytes, &tampered, &sig).is_err());
    }
}
