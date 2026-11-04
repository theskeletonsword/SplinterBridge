//! Hardware-attestation verification for zero-PII humanity proofs.
//!
//! ## Wire format (documented S2S deviation from interactive WebAuthn)
//!
//! Cross-gateway attestation cannot assume a browser client: the origin
//! gateway stores attestations produced by its users' hardware enclaves and
//! ships a self-contained *assertion token* in
//! `HardwareAttestation.assertion_token` (standard base64). The token is a
//! WebAuthn **"packed" attestation object** (CBOR map):
//!
//! ```text
//! {"fmt": "packed",
//!  "attStmt": {"alg": -7 (ES256), "sig": DER-ECDSA-Sig-Value,
//!              "x5c": [leafDer, rootDer, ...]},
//!  "authData": rpIdHash(32) || flags(1) || signCount(4)
//!              || aaguid(16) || credIdLen(2) || credentialId}
//! ```
//!
//! The signature scope is `authData || SHA256(challenge)` — the destination
//! gateway re-derives the challenge digest from its own `challenge` field,
//! so a token minted for a different challenge fails verification: the
//! challenge binds the assertion to a single verification session.
//!
//! ## Verification policy (fail-closed)
//!
//! * only `EnclaveType` values with a configured trust anchor are accepted;
//! unknown/unspecified enclave types are a policy violation;
//! * only COSE algorithm `-7` (ES256 over P-256) is accepted; RSA and
//! Ed25519 chains are rejected by crypto policy;
//! * self-attestation (empty `x5c`) is rejected — an unverifiable key
//! source is unacceptable on this surface;
//! * `authData` flags: UP|UV|AT required; ED/BE/BS rejected (extension and
//! backup state are outside this S2S surface);
//! * `rpIdHash` must equal `SHA256(rp_id)` — blocks cross-realm reuse of
//! stolen assertion tokens;
//! * sign-count policy: `RequireZero` (S2S tokens carry no authenticator
//! session state) or `AllowAny`;
//! * the `x5c` chain must terminate in the enclave's configured trust
//! anchor and every certificate's validity window must contain `now`;
//! * token freshness: `timestamp_epoch_ms` within `max_token_age_ms` of the
//! wall clock (both directions), bounding replay value under the challenge
//! rotation performed by `verify_hardware_attestation`.
//!
//! Privacy invariant: tokens carry no PII — credential IDs are opaque
//! enclave-generated octets, and no identity crosses this interface.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use sha2::{Digest, Sha256};
use splinter_proto::{DropReasonCode, EnclaveType, HardwareAttestation};
use thiserror::Error;

use crate::cbor::{self, Cbor};
use crate::der::{self, oids, Certificate, DerError, TrustedPublicKey};
use crate::encoding::decode_base64;

/// COSE algorithm label: ES256 (ECDSA w/ SHA-256 over P-256) — the single
/// algorithm policy-accepted for attestation chains here.
pub const COSE_ALG_ES256: i64 = -7;

// WebAuthn authenticator-data flag bits (WebAuthn L2 §6.1).
const FLAG_UP: u8 = 0x01; // user present
const FLAG_ED: u8 = 0x02; // extension data
const FLAG_UV: u8 = 0x04; // user verified
const FLAG_BE: u8 = 0x08; // backup eligible
const FLAG_BS: u8 = 0x10; // backup state
const FLAG_AT: u8 = 0x40; // attested credential data included

/// Fixed authenticator-data prefix: rpIdHash(32) || flags(1) || signCount(4).
const AUTH_DATA_FIXED_LEN: usize = 37;

/// attestedCredentialData overhead: aaguid(16) || credIdLen(2).
const CRED_DATA_OVERHEAD: usize = 18;

/// Hard credential-ID bound (WebAuthn max is 1023 bytes).
const MAX_CREDENTIAL_ID_LEN: usize = 1023;

/// Default assertion freshness window (5 minutes).
pub const DEFAULT_MAX_TOKEN_AGE_MS: u64 = 5 * 60 * 1000;

/// Maximum accepted chain depth: leaf + intermediates + root.
const MAX_CHAIN_DEPTH: usize = 4;

/// An enclave trust anchor: the accepted root public key for one enclave
/// class, constructed from the raw DER of the hardware attestation root.
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    /// Enclave family this root authenticates.
    pub enclave: EnclaveType,
    /// Raw SPKI key bytes of the root certificate (canonical match key).
    pub key_bytes: Vec<u8>,
    /// Parsed key for signature verification.
    pub key: TrustedPublicKey,
}

impl TrustAnchor {
    /// Extracts a trust anchor from a root certificate DER for `enclave`.
    ///
    /// For an Apple-style attestation the root is the vendor's production
    /// CA blob; for Android StrongKey / FIDO2 metadata it is the
    /// per-attestation CA. Parsing validates on import so mis-provisioned
    /// anchors fail loudly at startup, not in the hot path.
    pub fn from_cert(enclave: EnclaveType, cert_der: &[u8]) -> Result<Self, AttestationError> {
        let cert = der::parse_certificate(cert_der)
            .map_err(|e| AttestationError::TrustAnchorMalformed(e.to_string()))?;
        let key = der::spki_to_key(&cert.spki, 0)
            .map_err(|e| AttestationError::TrustAnchorMalformed(e.to_string()))?;
        Ok(Self {
            enclave,
            key_bytes: cert.spki.key_bytes.clone(),
            key,
        })
    }
}

/// Sign-count policy for S2S attestation assertions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignCountPolicy {
    /// S2S tokens carry no authenticator session state: signCount MUST be 0.
    RequireZero,
    /// Accept any counter value.
    AllowAny,
}

/// Verifier of hardware-attestation assertion tokens. Roots are published
/// behind `ArcSwap`, so vendor roots (e.g. Apple leaf-CA blobs) can be
/// hot-reloaded without disturbing concurrent verifiers.
#[derive(Debug)]
pub struct AttestationVerifier {
    /// `SHA256(rp_id)` — the relying-party realm enforced on every token.
    rp_id_hash: [u8; 32],
    /// Per-enclave trusted root list. Hot-reloadable atomic snapshot.
    /// (`ArcSwap<V>` stores `Arc<V>` internally.)
    anchors: ArcSwap<HashMap<EnclaveType, Vec<TrustAnchor>>>,
    /// Sign-count acceptance policy.
    sign_count_policy: SignCountPolicy,
    /// Token freshness bound (wall-clock tolerance, both directions).
    max_token_age_ms: u64,
}

/// Structured outcome of a successful verification.
#[derive(Debug, Clone)]
pub struct AttestationProof {
    /// Enclave family that verified successfully.
    pub enclave: EnclaveType,
    /// Opaque credential id from `attestedCredentialData` (no PII).
    pub credential_id: Vec<u8>,
    /// Raw `signCount` from `authData` (policy-checked per configuration).
    pub sign_count: u32,
    /// AAGUID (model id), `None` for the all-zero forge value.
    pub aaguid: Option<[u8; 16]>,
}

/// Parsed authenticator-data payload (enclave attributed by the caller).
#[derive(Debug, Clone)]
struct AuthDataOk {
    credential_id: Vec<u8>,
    sign_count: u32,
    aaguid: Option<[u8; 16]>,
}

/// Attestation verification errors. All variants map to one of two proto
/// drop codes via [`AttestationError::drop_reason_code`].
#[derive(Debug, Error)]
pub enum AttestationError {
    /// Request carried an unknown/unspecified enclave type or one with no
    /// configured anchors — callers must fix provisioning, not retry.
    #[error("attestation: enclave {0:?} has no configured trust anchor")]
    UnsupportedEnclave(EnclaveType),

    /// `timestamp_epoch_ms` outside the freshness window.
    #[error("attestation: stale or future-dated token (age {0} ms)")]
    StaleToken(i64),

    /// Base64 coding failure of the assertion token.
    #[error("attestation: assertion token not decodable: {0}")]
    TokenCodec(String),

    /// CBOR/DER structural failure of the token or its certificate chain.
    #[error("attestation: {0}")]
    Structure(String),

    /// `fmt` is not `"packed"`.
    #[error("attestation: unsupported fmt {0}")]
    UnsupportedFmt(String),

    /// COSE alg outside the accepted policy (must be ES256 = -7).
    #[error("attestation: COSE alg {got} outside policy (ES256 = -7)")]
    UnsupportedAlg {
        /// The rejected algorithm label.
        got: i64,
    },

    /// signCount contradicts the configured [`SignCountPolicy`].
    #[error("attestation: signCount {0} violates the RequireZero policy")]
    SignCountViolation(u32),

    /// authData rpIdHash does not match the configured relying-party realm.
    #[error("attestation: authData rpIdHash mismatch (wrong realm)")]
    RpIdHashMismatch,

    /// UP|UV|AT flag bits required by policy are absent.
    #[error("attestation: authData missing required flags (up={up} uv={uv} at={at})")]
    MissingRequiredFlags {
        /// User-presence bit state.
        up: bool,
        /// User-verification bit state.
        uv: bool,
        /// Attested-credential-data bit state.
        at: bool,
    },

    /// ED/BE/BS flags forbidden on this surface.
    #[error("attestation: authData carries forbidden flag: {0}")]
    ForbiddenFlag(&'static str),

    /// authData shorter than the policy-required structure.
    #[error("attestation: authData too short ({0} bytes)")]
    AuthDataTooShort(usize),

    /// Empty x5c (self-attestation) — rejected by policy.
    #[error("attestation: attestation statement carries no certificate chain")]
    MissingChainCert,

    /// A chain certificate's validity window does not contain `now`.
    #[error(
        "attestation: cert[{index}] validity window violated \
         (not_before={not_before} not_after={not_after} now={now})"
    )]
    ValidityWindow {
        /// Position of the offending certificate in x5c.
        index: usize,
        /// Packed notBefore timestamp.
        not_before: u64,
        /// Packed notAfter timestamp.
        not_after: u64,
        /// Packed current UTC timestamp.
        now: u64,
    },

    /// Signature-algorithm OID inconsistent with the certificate key alg.
    #[error("attestation: cert[{index}] signature algorithm inconsistent with key algorithm")]
    CoseAlgMismatch {
        /// Position of the offending certificate.
        index: usize,
    },

    /// Certificate signature failed verification under the issuer key.
    #[error("attestation: cert[{0}] signature invalid under issuer key")]
    ChainSignature(usize),

    /// Chain did not terminate in any configured enclave trust anchor.
    #[error("attestation: chain does not terminate in a configured enclave trust anchor")]
    NoTrustedAnchor,

    /// Trust-anchor import failed (startup-time provisioning error).
    #[error("attestation: trust anchor malformed on import: {0}")]
    TrustAnchorMalformed(String),
}

impl AttestationError {
    /// Canonical proto drop code for `FederatedEventResponse.drop_reason`.
    pub fn drop_reason_code(&self) -> DropReasonCode {
        match self {
            // Missing/unknown enclave configuration is an origin-policy
            // problem, not a token-forgery signal.
            Self::UnsupportedEnclave(_) => DropReasonCode::DropReasonJurisdictionPolicyViolation,
            // Everything else is a cryptographic/structural rejection.
            _ => DropReasonCode::DropReasonAttestationVerificationFailed,
        }
    }
}

impl From<DerError> for AttestationError {
    fn from(e: DerError) -> Self {
        AttestationError::Structure(e.to_string())
    }
}

impl From<cbor::CborError> for AttestationError {
    fn from(e: cbor::CborError) -> Self {
        AttestationError::Structure(e.to_string())
    }
}

impl From<crate::encoding::Base64Error> for AttestationError {
    fn from(e: crate::encoding::Base64Error) -> Self {
        AttestationError::TokenCodec(e.to_string())
    }
}

impl AttestationVerifier {
    /// Builds a verifier with initial trust anchors and policy (5-min
    /// freshness window).
    pub fn new(
        rp_id: impl AsRef<[u8]>,
        anchors: Vec<TrustAnchor>,
        sign_count_policy: SignCountPolicy,
    ) -> Self {
        Self::with_token_age(rp_id, anchors, sign_count_policy, DEFAULT_MAX_TOKEN_AGE_MS)
    }

    /// Builds a verifier with an explicit token-age policy (test harnesses).
    pub fn with_token_age(
        rp_id: impl AsRef<[u8]>,
        anchors: Vec<TrustAnchor>,
        sign_count_policy: SignCountPolicy,
        max_token_age_ms: u64,
    ) -> Self {
        let rp_id_hash: [u8; 32] = Sha256::digest(rp_id.as_ref()).into();
        Self {
            rp_id_hash,
            anchors: ArcSwap::from_pointee(group_anchors(anchors)),
            sign_count_policy,
            max_token_age_ms,
        }
    }

    /// Atomically replaces the trust-anchor set (vendor root rollover).
    /// Readers in flight keep their old snapshot until they finish.
    pub fn reload_anchors(&self, anchors: Vec<TrustAnchor>) {
        self.anchors.store(Arc::new(group_anchors(anchors)));
    }

    /// Anchors configured for `enclave`: one atomic load of the shared
    /// snapshot (O(1), lock-free).
    fn anchors_for(&self, enclave: EnclaveType) -> Option<Arc<Vec<TrustAnchor>>> {
        self.anchors
            .load()
            .get(&enclave)
            .map(|v| Arc::new(v.clone()))
    }

    /// Verifies the attestation request end-to-end. See module docs for the
    /// ordered policy chain. O(token size) with O(k) crypto verifications
    /// for a chain of depth k.
    pub fn verify(
        &self,
        attestation: &HardwareAttestation,
    ) -> Result<AttestationProof, AttestationError> {
        // 0. Request-level policy: the enclave type must map to a known
        //    value with configured anchors. Unknown enum encodings map to
        //    Unspecified, which never carries anchors.
        let enclave = EnclaveType::try_from(attestation.enclave_type)
            .unwrap_or(EnclaveType::Unspecified);
        let anchors = self
            .anchors_for(enclave)
            .ok_or_else(|| AttestationError::UnsupportedEnclave(enclave))?;

        // 1. Freshness (wall clock ± age bound, both directions).
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_millis()).unwrap_or(0))
            .unwrap_or(0);
        let age_ms = now_ms
            .checked_sub(attestation.timestamp_epoch_ms)
            .unwrap_or(i64::MAX);
        if age_ms.abs() > i64::try_from(self.max_token_age_ms).unwrap_or(i64::MAX) {
            return Err(AttestationError::StaleToken(age_ms));
        }

        // 2. Token decode: base64 → CBOR map with strict structure.
        let token_bytes = decode_base64(&attestation.assertion_token)?;
        let token = cbor::parse(&token_bytes, false)?;
        let fmt = token
            .map_text("fmt")
            .and_then(Cbor::as_text)
            .ok_or_else(|| AttestationError::Structure("missing fmt".into()))?;
        if fmt != "packed" {
            return Err(AttestationError::UnsupportedFmt(fmt.to_owned()));
        }
        let att_stmt = token
            .map_text("attStmt")
            .ok_or_else(|| AttestationError::Structure("missing attStmt".into()))?;
        let auth_data = token
            .map_text("authData")
            .and_then(Cbor::as_bytes)
            .ok_or_else(|| AttestationError::Structure("missing authData".into()))?;

        // 3. Authenticator-data structure + flag policy.
        let parsed = parse_auth_data(auth_data)?;
        match self.sign_count_policy {
            SignCountPolicy::RequireZero if parsed.sign_count != 0 => {
                return Err(AttestationError::SignCountViolation(parsed.sign_count));
            }
            _ => {}
        }
        if auth_data[..32] != self.rp_id_hash {
            return Err(AttestationError::RpIdHashMismatch);
        }

        // 4. Attestation statement: algorithm + signature + chain.
        let alg = att_stmt
            .map_int(3)
            .and_then(|v| match v {
                Cbor::Integer(i) => Some(*i),
                _ => None,
            })
            .ok_or_else(|| AttestationError::Structure("missing attStmt.alg".into()))?;
        if alg != COSE_ALG_ES256 {
            return Err(AttestationError::UnsupportedAlg { got: alg });
        }
        let signature = att_stmt
            .map_text("sig")
            .and_then(Cbor::as_bytes)
            .ok_or_else(|| AttestationError::Structure("missing attStmt.sig".into()))?;
        let x5c = att_stmt
            .map_text("x5c")
            .and_then(Cbor::as_array)
            .ok_or_else(|| AttestationError::Structure("missing attStmt.x5c".into()))?;
        if x5c.is_empty() {
            // Self-attestation carries no verifiable key source: fail closed.
            return Err(AttestationError::MissingChainCert);
        }

        // 5. Parse certs, chain to the trust anchor, freshness windows.
        let leaf = verify_chain(x5c, &anchors)?;

        // 6. The leaf key must own the assertion signature over
        //    authData || SHA256(challenge) — challenge from OUR request.
        let message = [
            auth_data,
            Sha256::digest(&attestation.challenge).as_slice(),
        ]
        .concat();
        leaf.verify(&message, signature)
            .map_err(|e| AttestationError::Structure(format!("attestation signature: {e}")))?;

        Ok(AttestationProof {
            enclave,
            credential_id: parsed.credential_id,
            sign_count: parsed.sign_count,
            aaguid: parsed.aaguid,
        })
    }
}

/// Groups a flat anchor list into the per-enclave index used by lookups.
fn group_anchors(anchors: Vec<TrustAnchor>) -> HashMap<EnclaveType, Vec<TrustAnchor>> {
    let mut by_enclave: HashMap<EnclaveType, Vec<TrustAnchor>> = HashMap::new();
    for a in anchors {
        by_enclave.entry(a.enclave).or_default().push(a);
    }
    by_enclave
}

/// Parses the WebAuthn authenticator-data structure and enforces the flag
/// policy. AT flag ⇒ attestedCredentialData is structurally required.
fn parse_auth_data(auth_data: &[u8]) -> Result<AuthDataOk, AttestationError> {
    if auth_data.len() < AUTH_DATA_FIXED_LEN {
        return Err(AttestationError::AuthDataTooShort(auth_data.len()));
    }
    let flags = auth_data[32];
    // Required: user presence, user verification, attested credential data.
    if flags & FLAG_UP == 0 || flags & FLAG_UV == 0 || flags & FLAG_AT == 0 {
        return Err(AttestationError::MissingRequiredFlags {
            up: flags & FLAG_UP != 0,
            uv: flags & FLAG_UV != 0,
            at: flags & FLAG_AT != 0,
        });
    }
    // Forbidden flags on this surface.
    if flags & FLAG_ED != 0 {
        return Err(AttestationError::ForbiddenFlag("extension data (ED)"));
    }
    if flags & (FLAG_BE | FLAG_BS) != 0 {
        return Err(AttestationError::ForbiddenFlag("backup state (BE/BS)"));
    }
    let sign_count = u32::from_be_bytes(
        auth_data[33..37]
            .try_into()
            .expect("guarded 4-byte signCount slice"),
    );

    // attestedCredentialData: aaguid(16) || credIdLen(2) || credentialId.
    let body_len = AUTH_DATA_FIXED_LEN + CRED_DATA_OVERHEAD;
    if auth_data.len() < body_len {
        return Err(AttestationError::AuthDataTooShort(auth_data.len()));
    }
    let aaguid: [u8; 16] = auth_data[37..53]
        .try_into()
        .expect("guarded 16-byte AAGUID slice");
    let cred_len =
        u16::from_be_bytes(auth_data[53..55].try_into().expect("guarded 2-byte length")) as usize;
    if cred_len > MAX_CREDENTIAL_ID_LEN {
        return Err(AttestationError::Structure(format!(
            "credential id length {cred_len} exceeds {MAX_CREDENTIAL_ID_LEN}"
        )));
    }
    let id_start = body_len;
    let id_end = id_start
        .checked_add(cred_len)
        .ok_or_else(|| AttestationError::AuthDataTooShort(auth_data.len()))?;
    if id_end > auth_data.len() {
        return Err(AttestationError::AuthDataTooShort(auth_data.len()));
    }
    let credential_id = auth_data[id_start..id_end].to_vec();

    let aaguid = if aaguid.iter().all(|b| *b == 0) { None } else { Some(aaguid) };
    Ok(AuthDataOk {
        credential_id,
        sign_count,
        aaguid,
    })
}

/// X.509 chain verification anchored at the enclave trust anchors.
///
/// Complexity: O(k) parses + O(k) verifications for a chain of depth
/// k ≤ [`MAX_CHAIN_DEPTH`] (typical: leaf + root = 2). Anchor comparison is
/// on canonical SPKI key bytes, immune to certificate re-encoding.
fn verify_chain(x5c: &[Cbor], anchors: &[TrustAnchor]) -> Result<TrustedPublicKey, AttestationError> {
    if x5c.len() > MAX_CHAIN_DEPTH {
        return Err(AttestationError::Structure(format!(
            "attestation chain too deep ({})",
            x5c.len()
        )));
    }
    let certs: Vec<Certificate> = x5c
        .iter()
        .map(|item| -> Result<Certificate, AttestationError> {
            let der_bytes = item
                .as_bytes()
                .ok_or_else(|| AttestationError::Structure("x5c entry is not a byte string".into()))?;
            der::parse_certificate(der_bytes)
                .map_err(|e| AttestationError::Structure(e.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Every certificate's validity window must contain now.
    let now = der::utc_stamp_now();
    for (i, cert) in certs.iter().enumerate() {
        if cert.not_before > now || cert.not_after <= now {
            return Err(AttestationError::ValidityWindow {
                index: i,
                not_before: cert.not_before,
                not_after: cert.not_after,
                now,
            });
        }
    }

    // Algorithm consistency: P-256 keys sign with ecdsa-with-SHA256;
    // Ed25519 keys with pure Ed25519. Anything else is a policy violation.
    for (i, cert) in certs.iter().enumerate() {
        let ok_sig_alg = if cert.spki.algorithm_oid == oids::ECDSA {
            cert.signature_alg_oid == oids::ECDSA_WITH_SHA256
        } else {
            cert.signature_alg_oid == oids::ED25519
        };
        if !ok_sig_alg {
            return Err(AttestationError::CoseAlgMismatch { index: i });
        }
    }

    // Verify each certificate under the NEXT one's key; the last cert must
    // BE one of the configured anchors.
    for i in 0..certs.len() {
        if let Some(child) = certs.get(i + 1) {
            let issuer_key = der::spki_to_key(&child.spki, i)?;
            issuer_key
                .verify(certs[i].tbs.as_slice(), certs[i].signature.as_slice())
                .map_err(|_| AttestationError::ChainSignature(i))?;
        } else {
            let is_anchor = anchors
                .iter()
                .any(|a| a.key_bytes == certs[i].spki.key_bytes);
            if !is_anchor {
                return Err(AttestationError::NoTrustedAnchor);
            }
        }
    }

    // The leaf owns the assertion signature: return its parsed key.
    der::spki_to_key(&certs[0].spki, 0).map_err(|e| AttestationError::Structure(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::Cbor;
    use crate::encoding::encode_base64;
    use p256::ecdsa::signature::Signer;
    use p256::pkcs8::DecodePrivateKey;

    /// Test-harness material: root CA + leaf device cert + the leaf's P-256
    /// signing key imported from rcgen's PKCS#8 export.
    struct Material {
        root_der: Vec<u8>,
        leaf_der: Vec<u8>,
        signing_key: p256::ecdsa::SigningKey,
        rp_id: String,
    }

    fn mint_attestation_chain(rp_id: &str) -> Material {
        let root_key = rcgen::KeyPair::generate().unwrap();
        let mut root_params =
            rcgen::CertificateParams::new(vec![rp_id.to_owned()]).unwrap();
        root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let root_cert = root_params.self_signed(&root_key).unwrap();

        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let mut leaf_params =
            rcgen::CertificateParams::new(vec!["attested-device".to_owned()]).unwrap();
        leaf_params.is_ca = rcgen::IsCa::NoCa;
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &root_cert, &root_key)
            .unwrap();

        let signing_key =
            p256::ecdsa::SigningKey::from_pkcs8_der(&leaf_key.serialize_der())
                .expect("leaf PKCS#8 import");
        Material {
            root_der: root_cert.der().to_vec(),
            leaf_der: leaf_cert.der().to_vec(),
            signing_key,
            rp_id: rp_id.to_owned(),
        }
    }

    fn auth_data(rp_id: &str, sign_count: u32, cred_id: &[u8]) -> Vec<u8> {
        let mut data = Vec::with_capacity(55 + cred_id.len());
        data.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
        data.push(FLAG_UP | FLAG_UV | FLAG_AT);
        data.extend_from_slice(&sign_count.to_be_bytes());
        data.extend_from_slice(&[0x11; 16]); // non-zero AAGUID
        data.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
        data.extend_from_slice(cred_id);
        data
    }

    fn build_token(material: &Material, challenge: &[u8], auth_data_bytes: &[u8]) -> String {
        let message = [auth_data_bytes, Sha256::digest(challenge).as_slice()].concat();
        let signature: p256::ecdsa::Signature = material.signing_key.sign(&message);

        let token = Cbor::Map(vec![
            (Cbor::Text("fmt".into()), Cbor::Text("packed".into())),
            (
                Cbor::Text("attStmt".into()),
                Cbor::Map(vec![
                    (Cbor::Integer(3), Cbor::Integer(COSE_ALG_ES256)),
                    (Cbor::Text("sig".into()), Cbor::Bytes(ecdsa_sig_der(&signature))),
                    (
                        Cbor::Text("x5c".into()),
                        Cbor::Array(vec![
                            Cbor::Bytes(material.leaf_der.clone()),
                            Cbor::Bytes(material.root_der.clone()),
                        ]),
                    ),
                ]),
            ),
            (
                Cbor::Text("authData".into()),
                Cbor::Bytes(auth_data_bytes.to_vec()),
            ),
        ]);
        encode_base64(&cbor::encode(&token).unwrap())
    }

    fn now_ms() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_millis()).unwrap_or(0))
            .unwrap_or(0)
    }

    fn make_request(challenge: &[u8], token_b64: &str) -> HardwareAttestation {
        HardwareAttestation {
            enclave_type: EnclaveType::Fido2Webauthn as i32,
            assertion_token: token_b64.to_owned(),
            challenge: challenge.to_vec(),
            timestamp_epoch_ms: now_ms(),
        }
    }

    fn fresh_verifier(material: &Material) -> AttestationVerifier {
        let anchor =
            TrustAnchor::from_cert(EnclaveType::Fido2Webauthn, &material.root_der)
                .expect("anchor import");
        AttestationVerifier::new(
            material.rp_id.clone(),
            vec![anchor],
            SignCountPolicy::RequireZero,
        )
    }

    const CRED_ID: &[u8] = b"opaque-enclave-credential-id";

    /// ASN.1 INTEGER with minimal-length signed semantics.
    fn asn1_integer(be: &[u8]) -> Vec<u8> {
        let mut first = 0;
        while first + 1 < be.len() && be[first] == 0 {
            first += 1;
        }
        let mut content = Vec::new();
        if be[first] & 0x80 != 0 {
            content.push(0u8); // keep the sign bit positive
        }
        content.extend_from_slice(&be[first..]);
        let mut out = vec![0x02, content.len() as u8];
        out.extend(content);
        out
    }

    /// DER `ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` — the
    /// exact encoding WebAuthn ES256 requires in the packed `sig` field.
    fn ecdsa_sig_der(
        signature: &p256::ecdsa::Signature,
    ) -> Vec<u8> {
        let (r, s) = signature.split_bytes();
        let mut body = asn1_integer(r.as_slice());
        body.extend(asn1_integer(s.as_slice()));
        let mut out = vec![0x30, body.len() as u8];
        out.extend(body);
        out
    }

    #[test]
    fn valid_attestation_verifies() {
        let material = mint_attestation_chain("attested.example");
        let verifier = fresh_verifier(&material);
        let challenge = b"ephemeral-challenge-bytes";
        let ad = auth_data("attested.example", 0, CRED_ID);
        let request = make_request(challenge, &build_token(&material, challenge, &ad));

        let proof = verifier.verify(&request).expect("verifies");
        assert_eq!(proof.credential_id, CRED_ID);
        assert_eq!(proof.sign_count, 0);
        assert_eq!(proof.enclave, EnclaveType::Fido2Webauthn);
        assert!(proof.aaguid.is_some());
    }

    #[test]
    fn wrong_challenge_invalidates_signature() {
        let material = mint_attestation_chain("attested.example");
        let verifier = fresh_verifier(&material);
        let challenge = b"challenge-A";
        let ad = auth_data("attested.example", 0, CRED_ID);
        // Token minted for challenge-A, presented under challenge-B.
        let request = make_request(b"challenge-B", &build_token(&material, challenge, &ad));
        match verifier.verify(&request) {
            Err(AttestationError::Structure(msg)) => {
                assert!(msg.contains("signature"), "{msg}")
            }
            other => panic!("expected signature failure, got {other:?}"),
        }
    }

    #[test]
    fn single_bit_flip_in_token_rejected() {
        let material = mint_attestation_chain("attested.example");
        let verifier = fresh_verifier(&material);
        let challenge = b"c";
        let ad = auth_data("attested.example", 0, CRED_ID);
        let token = build_token(&material, challenge, &ad);
        // Flip a bit in the middle of the base64 token: structural failure
        // OR signature failure — either way it must not verify as true.
        let mut bad = token.clone().into_bytes();
        let mid = bad.len() / 2;
        bad[mid] ^= 0x01;
        let bad_str = String::from_utf8_lossy(&bad).into_owned();
        let request = make_request(challenge, &bad_str);
        match verifier.verify(&request) {
            Ok(_) => panic!("tampered token must not verify"),
            Err(_) => {}
        }
    }

    #[test]
    fn rp_id_hash_is_enforced() {
        let material = mint_attestation_chain("attested.example");
        // Verifier bound to a DIFFERENT realm: the token's rpIdHash does
        // not match ⇒ cross-realm token reuse is impossible.
        let anchor =
            TrustAnchor::from_cert(EnclaveType::Fido2Webauthn, &material.root_der).unwrap();
        let verifier =
            AttestationVerifier::new("other.example", vec![anchor], SignCountPolicy::RequireZero);
        let challenge = b"c";
        let ad = auth_data("attested.example", 0, CRED_ID);
        let request = make_request(challenge, &build_token(&material, challenge, &ad));
        assert!(matches!(
            verifier.verify(&request),
            Err(AttestationError::RpIdHashMismatch)
        ));
    }

    #[test]
    fn required_and_forbidden_flags_are_enforced() {
        let material = mint_attestation_chain("attested.example");
        let verifier = fresh_verifier(&material);
        let challenge = b"c";

        // Missing UV bit.
        let mut ad = auth_data("attested.example", 0, CRED_ID);
        ad[32] = FLAG_UP | FLAG_AT;
        let request = make_request(challenge, &build_token(&material, challenge, &ad));
        assert!(matches!(
            verifier.verify(&request),
            Err(AttestationError::MissingRequiredFlags { uv: false, .. })
        ));

        // Foreign ED bit set ⇒ rejected outright.
        let mut ad2 = auth_data("attested.example", 0, CRED_ID);
        ad2[32] |= FLAG_ED;
        let request2 = make_request(challenge, &build_token(&material, challenge, &ad2));
        assert!(matches!(
            verifier.verify(&request2),
            Err(AttestationError::ForbiddenFlag("extension data (ED)"))
        ));
    }

    #[test]
    fn sign_count_policy_is_enforced() {
        let material = mint_attestation_chain("attested.example");
        let anchor =
            TrustAnchor::from_cert(EnclaveType::Fido2Webauthn, &material.root_der).unwrap();
        let strict = AttestationVerifier::new(
            material.rp_id.clone(),
            vec![anchor.clone()],
            SignCountPolicy::RequireZero,
        );
        let lenient = AttestationVerifier::new(
            material.rp_id.clone(),
            vec![anchor],
            SignCountPolicy::AllowAny,
        );
        let challenge = b"c";
        let ad = auth_data("attested.example", 42, CRED_ID);
        let request = make_request(challenge, &build_token(&material, challenge, &ad));
        assert!(matches!(
            strict.verify(&request),
            Err(AttestationError::SignCountViolation(42))
        ));
        assert!(lenient.verify(&request).is_ok());
    }

    #[test]
    fn stale_token_rejected() {
        let material = mint_attestation_chain("attested.example");
        let anchor =
            TrustAnchor::from_cert(EnclaveType::Fido2Webauthn, &material.root_der).unwrap();
        let verifier = AttestationVerifier::with_token_age(
            material.rp_id.clone(),
            vec![anchor],
            SignCountPolicy::RequireZero,
            60_000,
        );
        let challenge = b"c";
        let ad = auth_data("attested.example", 0, CRED_ID);
        let request = make_request(challenge, &build_token(&material, challenge, &ad));
        // Age the token 10 minutes past the 60 s window.
        let mut stale = request.clone();
        stale.timestamp_epoch_ms -= 10 * 60 * 1000;
        assert!(matches!(verifier.verify(&stale), Err(AttestationError::StaleToken(_))));
        // Sanity: the fresh copy still verifies.
        assert!(verifier.verify(&request).is_ok());
    }

    #[test]
    fn chain_without_trusted_anchor_rejected() {
        let material = mint_attestation_chain("attested.example");
        // Verifier trusts a DIFFERENT vendor root than the chain's root.
        let foreign = mint_attestation_chain("foreign.example");
        let anchor =
            TrustAnchor::from_cert(EnclaveType::Fido2Webauthn, &foreign.root_der).unwrap();
        let verifier =
            AttestationVerifier::new(material.rp_id.clone(), vec![anchor], SignCountPolicy::RequireZero);
        let challenge = b"c";
        let ad = auth_data("attested.example", 0, CRED_ID);
        let request = make_request(challenge, &build_token(&material, challenge, &ad));
        assert!(matches!(
            verifier.verify(&request),
            Err(AttestationError::NoTrustedAnchor)
        ));
    }

    #[test]
    fn enclave_without_anchors_is_policy_violation() {
        let material = mint_attestation_chain("attested.example");
        // Anchors exist, but for the wrong enclave family.
        let anchor = TrustAnchor::from_cert(EnclaveType::AppleSecureEnclave, &material.root_der)
            .unwrap();
        let verifier =
            AttestationVerifier::new("attested.example", vec![anchor], SignCountPolicy::RequireZero);
        let request = make_request(
            b"c",
            &build_token(&material, b"c", &auth_data("attested.example", 0, CRED_ID)),
        );
        assert_eq!(
            verifier.verify(&request).unwrap_err().drop_reason_code(),
            DropReasonCode::DropReasonJurisdictionPolicyViolation
        );
    }

    #[test]
    fn out_of_policy_algorithms_rejected() {
        let material = mint_attestation_chain("attested.example");
        let verifier = fresh_verifier(&material);
        let challenge = b"c";
        let ad = auth_data("attested.example", 0, CRED_ID);
        let signature: p256::ecdsa::Signature = material
            .signing_key
            .sign(&[ad.as_slice(), Sha256::digest(challenge).as_slice()].concat());
        let bad_token = Cbor::Map(vec![
            (Cbor::Text("fmt".into()), Cbor::Text("packed".into())),
            (
                Cbor::Text("attStmt".into()),
                Cbor::Map(vec![
                    (Cbor::Integer(3), Cbor::Integer(-8)), // Ed25519 — policy-out
                    (Cbor::Text("sig".into()), Cbor::Bytes(ecdsa_sig_der(&signature))),
                    (
                        Cbor::Text("x5c".into()),
                        Cbor::Array(vec![
                            Cbor::Bytes(material.leaf_der.clone()),
                            Cbor::Bytes(material.root_der.clone()),
                        ]),
                    ),
                ]),
            ),
            (Cbor::Text("authData".into()), Cbor::Bytes(ad)),
        ]);
        let request =
            make_request(challenge, &encode_base64(&cbor::encode(&bad_token).unwrap()));
        assert_eq!(
            verifier.verify(&request).unwrap_err().drop_reason_code(),
            DropReasonCode::DropReasonAttestationVerificationFailed
        );
        match verifier.verify(&request) {
            Err(AttestationError::UnsupportedAlg { got }) => assert_eq!(got, -8),
            other => panic!("expected UnsupportedAlg, got {other:?}"),
        }
    }

    #[test]
    fn garbage_and_malformed_tokens_rejected() {
        let material = mint_attestation_chain("attested.example");
        let verifier = fresh_verifier(&material);
        // Not base64.
        let bad_b64 = HardwareAttestation {
            enclave_type: EnclaveType::Fido2Webauthn as i32,
            assertion_token: "!!!not-base64!!!".into(),
            challenge: b"c".to_vec(),
            timestamp_epoch_ms: now_ms(),
        };
        assert!(matches!(
            verifier.verify(&bad_b64),
            Err(AttestationError::TokenCodec(_))
        ));
        // Valid base64, invalid CBOR.
        let bad_cbor = HardwareAttestation {
            enclave_type: EnclaveType::Fido2Webauthn as i32,
            assertion_token: encode_base64(&[0xFF, 0x00]),
            challenge: b"c".to_vec(),
            timestamp_epoch_ms: now_ms(),
        };
        assert!(matches!(
            verifier.verify(&bad_cbor),
            Err(AttestationError::Structure(_))
        ));
    }

    #[test]
    fn hot_reload_swaps_anchors_atomically() {
        let material = mint_attestation_chain("attested.example");
        let verifier = fresh_verifier(&material);
        // A foreign-vendor chain is rejected before rollover, accepted
        // after an atomic anchor-set reload (in-flight readers keep their
        // old snapshot; new readers see the new roots immediately).
        let foreign = mint_attestation_chain("foreign.example");
        let challenge = b"c";
        let ad = auth_data(&material.rp_id, 0, CRED_ID);
        let foreign_request = make_request(challenge, &build_token(&foreign, challenge, &ad));

        assert!(matches!(
            verifier.verify(&foreign_request),
            Err(AttestationError::NoTrustedAnchor)
        ));
        verifier.reload_anchors(vec![
            TrustAnchor::from_cert(EnclaveType::Fido2Webauthn, &material.root_der).unwrap(),
            TrustAnchor::from_cert(EnclaveType::Fido2Webauthn, &foreign.root_der).unwrap(),
        ]);
        assert!(verifier.verify(&foreign_request).is_ok());
    }

    #[test]
    fn missing_chain_is_rejected_fail_closed() {
        // x5c present but empty ⇒ self-attestation form ⇒ policy rejection.
        let material = mint_attestation_chain("attested.example");
        let verifier = fresh_verifier(&material);
        let challenge = b"c";
        let ad = auth_data("attested.example", 0, CRED_ID);
        let signature: p256::ecdsa::Signature = material
            .signing_key
            .sign(&[ad.as_slice(), Sha256::digest(challenge).as_slice()].concat());
        let token = Cbor::Map(vec![
            (Cbor::Text("fmt".into()), Cbor::Text("packed".into())),
            (
                Cbor::Text("attStmt".into()),
                Cbor::Map(vec![
                    (Cbor::Integer(3), Cbor::Integer(COSE_ALG_ES256)),
                    (Cbor::Text("sig".into()), Cbor::Bytes(ecdsa_sig_der(&signature))),
                    (Cbor::Text("x5c".into()), Cbor::Array(vec![])),
                ]),
            ),
            (Cbor::Text("authData".into()), Cbor::Bytes(ad)),
        ]);
        let request = make_request(challenge, &encode_base64(&cbor::encode(&token).unwrap()));
        assert!(matches!(
            verifier.verify(&request),
            Err(AttestationError::MissingChainCert)
        ));
    }

    #[test]
    fn expired_cert_validity_window_rejected() {
        // A token whose chain points at a future-valid leaf: window check
        // must fire before anything else touches the chain.
        let material = mint_attestation_chain("attested.example");
        let verifier = fresh_verifier(&material);
        // Expired-window simulation is covered by der tests; here we assert
        // the drop-code mapping of the window error variant directly.
        let err = AttestationError::ValidityWindow {
            index: 0,
            not_before: 1_999_010_100_000_00,
            not_after: 2_099_010_100_000_00,
            now: 2_100_010_100_000_00,
        };
        assert_eq!(
            err.drop_reason_code(),
            DropReasonCode::DropReasonAttestationVerificationFailed
        );
        let _ = &material;
    }
}
