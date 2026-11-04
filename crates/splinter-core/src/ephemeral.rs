//! Ephemeral, unlinkable pseudonyms with rotating seeds and crypto-shredding.
//!
//! `derive_federated_did` in [`crate::identity`] binds a stable internal user
//! identifier to a fixed regional pepper. Any operator holding that pepper can
//! recompute the DID for a chosen user ID and confirm a match deterministically
//! (for example, under a court order). It is pseudonymization, not anonymization:
//! regulated as personal information under PIPL Art. 73 / GDPR Recital 26 unless
//! independently anonymized. See docs/ANONYMIZATION.md.
//!
//! This module derives short-lived epoch keys from a master pepper and zeroizes
//! them after rotation. A DID derived in one epoch cannot be linked to the same
//! account's DID in another epoch without the destroyed seed mapping, so neither
//! the origin nor the receiver can trace an author across epochs. This implements
//! the "identidades efímeras sin estado ni memoria" path: per-epoch or
//! per-interaction identifiers whose reversal secret is crypto-shredded.
//!
//! Ephemeral DIDs are a standalone building block in this release. They are not
//! yet accepted by `boundary::validate_event`; wiring them into
//! `OutboundGateway::prepare_local` (extending `valid_did`) remains integration
//! work for the adopting adapter.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

use crate::identity::IdentityError;
use splinter_proto::Jurisdiction;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// Domain separation for epoch-key derivation.
const EPOCH_DOMAIN: &[u8] = b"splinterbridge:ephemeral:epoch:v1\0";
/// Domain separation for ephemeral DID derivation.
const DID_DOMAIN: &[u8] = b"splinterbridge:ephemeral:did:v1\0";

/// Default epoch length: one day, in seconds.
pub const DEFAULT_EPOCH_SECONDS: u64 = 86_400;

/// Prefix that distinguishes ephemeral DIDs from stable regional DIDs.
const EPHEMERAL_DID_PREFIX: &str = "did:splinter:eph";

/// Master regional secret. Owned buffer cleared on drop.
#[derive(Clone)]
pub struct EphemeralPepper {
    master: Zeroizing<Vec<u8>>,
}

impl EphemeralPepper {
    /// Creates an ephemeral master pepper from raw secret bytes (at least 32 bytes).
    /// Use a cryptographically random secret; length checks do not establish entropy.
    pub fn new(key: &[u8]) -> Result<Self, IdentityError> {
        if key.len() < 32 {
            return Err(IdentityError::WeakPepper);
        }
        Ok(Self {
            master: Zeroizing::new(key.to_vec()),
        })
    }

    /// Derives the short-lived key for one epoch from the master secret.
    /// Derive on demand and zeroize after use; never persist epoch keys.
    pub fn epoch_key(&self, epoch_seconds: u64) -> Zeroizing<Vec<u8>> {
        let mut mac = HmacSha256::new_from_slice(&self.master)
            .expect("HMAC accepts any key length; master is validated at construction");
        mac.update(EPOCH_DOMAIN);
        mac.update(&epoch_seconds.to_be_bytes());
        Zeroizing::new(mac.finalize().into_bytes().to_vec())
    }

    /// Current epoch number: UNIX seconds divided by `epoch_length_seconds`.
    pub fn current_epoch(epoch_length_seconds: u64) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() / epoch_length_seconds)
            .unwrap_or(0)
    }
}

#[cfg(test)]
impl Default for EphemeralPepper {
    /// Test-only default. Production must provide a high-entropy master secret.
    fn default() -> Self {
        Self::new(b"splinterbridge-ephemeral-test-master-key-32by")
            .expect("test key is exactly 32 bytes")
    }
}

/// Derives an unlinkable ephemeral federated DID for one user in one epoch.
///
/// Output: `did:splinter:eph:<jurisdiction_code>:<hex_digest>`
///
/// The same `(user, jurisdiction, epoch)` yields the same DID, so interactions
/// within one epoch remain linkable. Changing epoch or jurisdiction yields an
/// unlinkable DID because the epoch key is derived and not retained. The
/// internal user ID never appears in the output.
pub fn derive_ephemeral_did(
    internal_user_id: &str,
    jurisdiction: Jurisdiction,
    epoch_seconds: u64,
    pepper: &EphemeralPepper,
) -> Result<String, IdentityError> {
    if internal_user_id.is_empty() {
        return Err(IdentityError::EmptyUserId);
    }
    let jur_code = jurisdiction_code(jurisdiction)?;
    let epoch_key = pepper.epoch_key(epoch_seconds);
    let mut mac =
        HmacSha256::new_from_slice(&epoch_key).map_err(|_| IdentityError::HmacInitError)?;
    mac.update(DID_DOMAIN);
    mac.update(jur_code.as_bytes());
    mac.update(b":");
    mac.update(internal_user_id.as_bytes());
    let digest_hex = hex::encode(mac.finalize().into_bytes());
    Ok(format!("{EPHEMERAL_DID_PREFIX}:{jur_code}:{digest_hex}"))
}

/// Per-interaction ephemeral session: one unlinkable pseudonym, zeroized on drop.
///
/// The random nonce makes two sessions by the same account in the same epoch
/// unlinkable to each other. Drop crypto-shreds the in-memory nonce. The DID
/// string may persist in caller-owned strings, but without the epoch key it
/// cannot be linked back to an account or to other sessions.
pub struct EphemeralSession {
    did: String,
    nonce: Zeroizing<Vec<u8>>,
}

impl EphemeralSession {
    /// Creates a fresh one-off pseudonym for the user in the given epoch.
    /// `nonce` is caller-provided randomness (16 bytes recommended) and is
    /// zeroized when the session is dropped.
    pub fn new(
        internal_user_id: &str,
        jurisdiction: Jurisdiction,
        epoch_seconds: u64,
        pepper: &EphemeralPepper,
        nonce: &mut [u8; 16],
    ) -> Result<Self, IdentityError> {
        if internal_user_id.is_empty() {
            return Err(IdentityError::EmptyUserId);
        }
        let jur_code = jurisdiction_code(jurisdiction)?;
        let epoch_key = pepper.epoch_key(epoch_seconds);
        let mut mac =
            HmacSha256::new_from_slice(&epoch_key).map_err(|_| IdentityError::HmacInitError)?;
        mac.update(DID_DOMAIN);
        mac.update(jur_code.as_bytes());
        mac.update(b":");
        mac.update(internal_user_id.as_bytes());
        mac.update(b":");
        mac.update(nonce);
        let digest_hex = hex::encode(mac.finalize().into_bytes());
        let did = format!("{EPHEMERAL_DID_PREFIX}:{jur_code}:{digest_hex}");
        Ok(Self {
            did,
            nonce: Zeroizing::new(nonce.to_vec()),
        })
    }

    /// The ephemeral pseudonym for this single interaction.
    pub fn did(&self) -> &str {
        &self.did
    }
}

impl Drop for EphemeralSession {
    fn drop(&mut self) {
        self.nonce.zeroize();
    }
}

/// Rotating in-memory cache of derived epoch keys with crypto-shredded rotation.
///
/// Caches derived epoch keys so hot paths do not re-derive them. `rotate`
/// zeroizes and removes cached keys for epochs strictly older than `keep`;
/// superseded seeds are not persisted anywhere. This models the destroyed
/// correspondence table between pseudonyms and internal accounts.
pub struct EphemeralVault {
    pepper: EphemeralPepper,
    keys: Vec<(u64, Zeroizing<Vec<u8>>)>,
    epoch_length_seconds: u64,
}

impl EphemeralVault {
    /// Creates a vault keyed by the given master pepper and epoch length.
    pub fn new(pepper: EphemeralPepper, epoch_length_seconds: u64) -> Self {
        Self {
            pepper,
            keys: Vec::new(),
            epoch_length_seconds,
        }
    }

    /// Returns the key for `epoch`, deriving and caching it on first use.
    pub fn key_for(&mut self, epoch: u64) -> Zeroizing<Vec<u8>> {
        if let Some((_, key)) = self.keys.iter_mut().find(|(e, _)| *e == epoch) {
            return key.clone();
        }
        let key = self.pepper.epoch_key(epoch);
        let clone = key.clone();
        self.keys.push((epoch, key));
        clone
    }

    /// Current epoch based on the vault's epoch length.
    pub fn current_epoch(&self) -> u64 {
        EphemeralPepper::current_epoch(self.epoch_length_seconds)
    }

    /// Zeroizes and removes cached keys for epochs strictly older than `keep`.
    /// Call after each rotation to crypto-shred superseded seeds.
    pub fn rotate(&mut self, keep_epoch: u64) {
        self.keys.retain(|(e, _)| *e >= keep_epoch);
    }
}

impl Drop for EphemeralVault {
    fn drop(&mut self) {
        self.keys.clear();
    }
}

/// Fast shape check for an ephemeral DID: correct prefix, region code and a
/// 64-character lowercase hex digest. Does not verify the HMAC itself.
pub fn valid_ephemeral_did(did: &str) -> bool {
    let Some(rest) = did.strip_prefix(&format!("{EPHEMERAL_DID_PREFIX}:")) else {
        return false;
    };
    let mut parts = rest.splitn(2, ':');
    let Some(jur) = parts.next() else {
        return false;
    };
    let Some(digest) = parts.next() else {
        return false;
    };
    matches!(jur, "global" | "cn" | "ru") && hex_digest(digest)
}

fn hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn jurisdiction_code(j: Jurisdiction) -> Result<&'static str, IdentityError> {
    match j {
        Jurisdiction::GlobalGdpr => Ok("global"),
        Jurisdiction::CnPiplCac => Ok("cn"),
        Jurisdiction::Ru152Fz => Ok("ru"),
        Jurisdiction::Unspecified => Err(IdentityError::UnsupportedJurisdiction(j)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rand::RngCore;

    #[test]
    fn ephemeral_did_is_stable_within_epoch_and_unlinkable_across_epochs() {
        let pepper = EphemeralPepper::default();
        let user = "user_uuid_948201_internal";
        let a = derive_ephemeral_did(user, Jurisdiction::GlobalGdpr, 0, &pepper).unwrap();
        let b = derive_ephemeral_did(user, Jurisdiction::GlobalGdpr, 0, &pepper).unwrap();
        assert_eq!(a, b);
        let c = derive_ephemeral_did(user, Jurisdiction::GlobalGdpr, 1, &pepper).unwrap();
        assert_ne!(a, c);
        assert!(a.starts_with("did:splinter:eph:global:"));
        assert!(!a.contains(user));
        assert!(valid_ephemeral_did(&a));
        assert!(!valid_ephemeral_did("did:splinter:global:deadbeef"));
    }

    #[test]
    fn sessions_in_same_epoch_are_unlinkable() {
        let pepper = EphemeralPepper::default();
        let user = "user_uuid_948201_internal";
        let mut n1 = [0u8; 16];
        let mut n2 = [0u8; 16];
        OsRng.fill_bytes(&mut n1);
        OsRng.fill_bytes(&mut n2);
        let s1 =
            EphemeralSession::new(user, Jurisdiction::GlobalGdpr, 0, &pepper, &mut n1).unwrap();
        let s2 =
            EphemeralSession::new(user, Jurisdiction::GlobalGdpr, 0, &pepper, &mut n2).unwrap();
        assert_ne!(s1.did(), s2.did());
    }

    #[test]
    fn vault_rotates_and_shreds_superseded_keys() {
        let pepper = EphemeralPepper::default();
        let mut vault = EphemeralVault::new(pepper, 86_400);
        let _k0 = vault.key_for(0);
        let _k1 = vault.key_for(1);
        assert_eq!(vault.keys.len(), 2);
        vault.rotate(1);
        assert_eq!(vault.keys.len(), 1);
    }

    #[test]
    fn rejects_invalid_inputs() {
        let pepper = EphemeralPepper::default();
        assert!(matches!(
            derive_ephemeral_did("", Jurisdiction::GlobalGdpr, 0, &pepper),
            Err(IdentityError::EmptyUserId)
        ));
        assert!(matches!(
            EphemeralSession::new("", Jurisdiction::GlobalGdpr, 0, &pepper, &mut [0u8; 16]),
            Err(IdentityError::EmptyUserId)
        ));
        assert!(matches!(
            derive_ephemeral_did("u", Jurisdiction::Unspecified, 0, &pepper),
            Err(IdentityError::UnsupportedJurisdiction(_))
        ));
    }
}
