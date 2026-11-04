//! SplinterBridge Zero-Knowledge StopNCII Digital Safety Engine.
//!
//! Compares supplied 256-bit fingerprints with a local in-memory catalog.
//! No media decoding, PDQ generation, TMK evaluation or external feed retrieval
//! is implemented. Local hash matching is not a zero-knowledge proof.

use splinter_proto::DropReasonCode;
use std::sync::RwLock;
use thiserror::Error;

/// Default inclusive matching threshold, out of 256 bits.
/// Actual similarity and false-positive rates depend on the hash source and media.
pub const DEFAULT_PDQ_HAMMING_THRESHOLD: u32 = 31;

/// Represents a 256-bit perceptual hash (PDQ) as four 64-bit words for fast vectorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PdqHash(pub [u64; 4]);

impl PdqHash {
    /// Constructs a PdqHash from 32 raw bytes (little-endian word interpretation).
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut words = [0u64; 4];
        for i in 0..4 {
            let chunk: [u8; 8] = bytes[i * 8..(i + 1) * 8]
                .try_into()
                .expect("Exact 8-byte chunk guaranteed");
            words[i] = u64::from_le_bytes(chunk);
        }
        Self(words)
    }

    /// Converts back to 32 raw bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            let chunk = self.0[i].to_le_bytes();
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&chunk);
        }
        bytes
    }

    /// Parses a 64-character hexadecimal representation of a 256-bit PDQ hash.
    pub fn from_hex(hex_str: &str) -> Result<Self, hex::FromHexError> {
        let mut raw = [0u8; 32];
        hex::decode_to_slice(hex_str, &mut raw)?;
        Ok(Self::from_bytes(&raw))
    }

    /// Computes Hamming distance using XOR and population counts.
    #[inline(always)]
    pub fn hamming_distance(&self, other: &Self) -> u32 {
        let mut dist = 0u32;
        // Native instruction selection depends on the target and compiler settings.
        for i in 0..4 {
            dist += (self.0[i] ^ other.0[i]).count_ones();
        }
        dist
    }
}

/// Error returned when candidate media matches known prohibited StopNCII perceptual fingerprints.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum StopNciiError {
    #[error("StopNCII match detected: Hamming distance {min_distance} <= threshold {threshold}")]
    ProhibitedMediaMatch {
        min_distance: u32,
        threshold: u32,
        drop_code: DropReasonCode,
    },

    #[error("Invalid hash length: expected 32 bytes (256 bits), received {0} bytes")]
    InvalidHashLength(usize),
}

impl StopNciiError {
    pub fn drop_reason_code(&self) -> DropReasonCode {
        match self {
            Self::ProhibitedMediaMatch { drop_code, .. } => *drop_code,
            Self::InvalidHashLength(_) => DropReasonCode::DropReasonStopnciiPerceptualHashMatch,
        }
    }
}

/// In-memory engine storing known StopNCII perceptual signatures.
/// Supports zero-allocation evaluation in the critical network dispatch path.
pub struct StopNciiEngine {
    match_threshold: u32,
    signatures: RwLock<Vec<PdqHash>>,
}

impl Default for StopNciiEngine {
    fn default() -> Self {
        Self::new(DEFAULT_PDQ_HAMMING_THRESHOLD)
    }
}

impl StopNciiEngine {
    /// Creates a new in-memory engine with a specific Hamming distance threshold.
    pub fn new(match_threshold: u32) -> Self {
        Self {
            match_threshold,
            signatures: RwLock::new(Vec::new()),
        }
    }

    /// Inserts a new known prohibited PDQ hash into the local in-memory filter.
    pub fn register_signature(&self, hash: PdqHash) {
        let mut lock = self.signatures.write().expect("RwLock poisoned");
        lock.push(hash);
    }

    /// Bulk loads signatures during gateway initialization.
    pub fn load_signatures(&self, hashes: Vec<PdqHash>) {
        let mut lock = self.signatures.write().expect("RwLock poisoned");
        lock.extend(hashes);
    }

    /// Number of registered perceptual signatures in memory.
    pub fn count(&self) -> usize {
        let lock = self.signatures.read().expect("RwLock poisoned");
        lock.len()
    }

    /// Whether no known fingerprints are loaded. Callers should refuse dispatch
    /// when their policy requires a populated safety catalog.
    pub fn is_empty(&self) -> bool {
        self.count() == 0
    }

    /// Evaluates a candidate 32-byte PDQ hash against all registered signatures.
    /// Returns `Ok(())` if clean, or `Err(StopNciiError::ProhibitedMediaMatch)`
    /// for immediate hot discard.
    pub fn evaluate_raw_bytes(&self, candidate_bytes: &[u8]) -> Result<(), StopNciiError> {
        if candidate_bytes.len() != 32 {
            return Err(StopNciiError::InvalidHashLength(candidate_bytes.len()));
        }

        let mut fixed = [0u8; 32];
        fixed.copy_from_slice(candidate_bytes);
        let candidate = PdqHash::from_bytes(&fixed);
        self.evaluate(&candidate)
    }

    /// Evaluates a candidate `PdqHash` against in-memory signatures.
    pub fn evaluate(&self, candidate: &PdqHash) -> Result<(), StopNciiError> {
        let lock = self.signatures.read().expect("RwLock poisoned");

        for registered in lock.iter() {
            let dist = candidate.hamming_distance(registered);
            if dist <= self.match_threshold {
                return Err(StopNciiError::ProhibitedMediaMatch {
                    min_distance: dist,
                    threshold: self.match_threshold,
                    drop_code: DropReasonCode::DropReasonStopnciiPerceptualHashMatch,
                });
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threshold_boundary_and_invalid_length() {
        let engine = StopNciiEngine::default();
        assert!(engine.is_empty());
        engine.register_signature(PdqHash([0; 4]));
        assert!(!engine.is_empty());
        assert!(engine
            .evaluate(&PdqHash([(1u64 << 31) - 1, 0, 0, 0]))
            .is_err());
        assert!(engine
            .evaluate(&PdqHash([(1u64 << 32) - 1, 0, 0, 0]))
            .is_ok());
        for size in [0, 31, 33] {
            assert_eq!(
                engine.evaluate_raw_bytes(&vec![0; size]),
                Err(StopNciiError::InvalidHashLength(size))
            );
        }
        let bytes = [0x5a; 32];
        assert_eq!(PdqHash::from_bytes(&bytes).to_bytes(), bytes);
    }

    #[test]
    fn test_hamming_distance_exact_match() {
        let hash = PdqHash([
            0xAAAAAAAAAAAAAAAA,
            0x5555555555555555,
            0x0F0F0F0F0F0F0F0F,
            0xF0F0F0F0F0F0F0F0,
        ]);
        assert_eq!(hash.hamming_distance(&hash), 0);
    }

    #[test]
    fn test_hamming_distance_differing_bits() {
        let h1 = PdqHash([0, 0, 0, 0]);
        // Single bit set in word 0, two bits set in word 1
        let h2 = PdqHash([0b0001, 0b0011, 0, 0]);
        assert_eq!(h1.hamming_distance(&h2), 3);
    }

    #[test]
    fn test_stopncii_hot_discard_within_threshold() {
        let engine = StopNciiEngine::default(); // threshold = 31

        // Registered prohibited hash
        let base_raw = [0x42u8; 32];
        let base_hash = PdqHash::from_bytes(&base_raw);
        engine.register_signature(base_hash);

        // Candidate with 10 mutated bits (perceptual variation, compression artifact)
        let mut mutated_raw = base_raw;
        mutated_raw[0] ^= 0b0000_1111; // 4 bit flips
        mutated_raw[1] ^= 0b0011_1111; // 6 bit flips (total 10 bits)
        let mutated_hash = PdqHash::from_bytes(&mutated_raw);

        let res = engine.evaluate(&mutated_hash);
        assert!(res.is_err());
        match res.unwrap_err() {
            StopNciiError::ProhibitedMediaMatch {
                min_distance,
                threshold,
                drop_code,
            } => {
                assert_eq!(min_distance, 10);
                assert_eq!(threshold, 31);
                assert_eq!(
                    drop_code,
                    DropReasonCode::DropReasonStopnciiPerceptualHashMatch
                );
            }
            _ => panic!("Expected ProhibitedMediaMatch"),
        }
    }

    #[test]
    fn test_stopncii_allows_clean_media() {
        let engine = StopNciiEngine::default();

        let base_hash = PdqHash::from_bytes(&[0x00u8; 32]);
        engine.register_signature(base_hash);

        // Completely unrelated image with > 100 bit flips
        let clean_hash = PdqHash::from_bytes(&[0xFFu8; 32]); // 256 bit flips
        assert!(engine.evaluate(&clean_hash).is_ok());
    }
}
