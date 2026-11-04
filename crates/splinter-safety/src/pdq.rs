//! 256-bit PDQ perceptual hash primitives with hardware-accelerated
//! Hamming distance over `[u64; 4]` limbs.
//!
//! The compiler emits native `popcnt` (x86_64 SSE4.2/BMI2, `cnt` on aarch64)
//! for `count_ones()`, so the tight XOR/popcnt loop in `hamming_distance`
//! is virtually latency-bound rather than loop-bound, and the four limbs
//! are unrolled and auto-vectorized where the target ISA allows it
//! (e.g. AVX2 `simd` variants via LLVM's SLP vectorizer).

use std::sync::OnceLock;

/// Industry-standard maximum Hamming distance for PDQ perceptual hash
/// matching (out of 256 bits). Hashes with distance ≤ 31 represent visually
/// identical or near-identical media variants (e.g. compression artifacts,
/// resolution changes, watermarks).
pub const DEFAULT_PDQ_HAMMING_THRESHOLD: u32 = 31;

/// Represents a 256-bit perceptual hash (PDQ) as four 64-bit words for fast
/// vectorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PdqHash(pub [u64; 4]);

impl PdqHash {
    /// Size in bytes of the PDQ representation (256 bits).
    pub const BYTE_LEN: usize = 32;

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

    /// Splits the 256-bit hash into 16 disjoint 16-bit blocks, laid out
    /// little-endian across the four 64-bit limbs.
    ///
    /// This is the exact partition consumed by [`crate::mih::MihIndex`]
    /// (Multi-Index Hashing); build and query MUST use this one function so
    /// that block identities match bit-for-bit.
    #[inline(always)]
    pub fn blocks16(&self) -> [u16; 16] {
        let mut out = [0u16; 16];
        for limb in 0..4 {
            for quarter in 0..4 {
                let shift = 16 * quarter as u32;
                out[limb * 4 + quarter] = (self.0[limb] >> shift) as u16;
            }
        }
        out
    }

    /// Computes hardware-accelerated Hamming distance between two 256-bit
    /// hashes using `popcnt`.
    ///
    /// Complexity: O(1) — four unrolled XOR+popcnt operations, no branches.
    #[inline(always)]
    pub fn hamming_distance(&self, other: &Self) -> u32 {
        let mut dist = 0u32;
        // The compiler unrolls this loop and emits native x86_64 `popcnt` /
        // aarch64 `cnt` instructions.
        for i in 0..4 {
            dist += (self.0[i] ^ other.0[i]).count_ones();
        }
        dist
    }

    /// Per-bit flip of every bit of the hash — returns the "buddy" mask list
    /// used by Multi-Index Hashing neighbor generation: all values at
    /// Hamming distance exactly 1 within a single 16-bit block.
    ///
    /// Kept private to the MIH engine; exposed here only as the canonical
    /// neighbor-generation primitive.
    #[inline]
    pub(crate) fn neighbor_masks_16bit() -> &'static [u16] {
        static MASKS: OnceLock<Vec<u16>> = OnceLock::new();
        MASKS.get_or_init(|| (0..16u32).map(|b| 1u16 << b).collect()).as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_bytes_and_hex() {
        let raw = [0xA5u8; 32];
        let hash = PdqHash::from_bytes(&raw);
        assert_eq!(hash.to_bytes(), raw);
        let hex_repr = "A5".repeat(32);
        assert_eq!(PdqHash::from_hex(&hex_repr).unwrap(), hash);
    }

    #[test]
    fn hamming_distance_exact_match() {
        let hash = PdqHash([0xAAAAAAAAAAAAAAAA, 0x5555555555555555, 0x0F0F0F0F0F0F0F0F, 0xF0F0F0F0F0F0F0F0]);
        assert_eq!(hash.hamming_distance(&hash), 0);
    }

    #[test]
    fn hamming_distance_differing_bits() {
        let h1 = PdqHash([0, 0, 0, 0]);
        // Single bit set in word 0, two bits set in word 1
        let h2 = PdqHash([0b0001, 0b0011, 0, 0]);
        assert_eq!(h1.hamming_distance(&h2), 3);
    }

    #[test]
    fn hamming_distance_max() {
        assert_eq!(PdqHash([0, 0, 0, 0]).hamming_distance(&PdqHash([u64::MAX; 4])), 256);
    }

    #[test]
    fn blocks16_restore_full_hash() {
        let hash = PdqHash([0x0123456789ABCDEF, 0xFEDCBA9876543210, 1, u64::MAX]);
        let chunks = hash.blocks16();
        assert_eq!(chunks.len(), 16);
        // Blocks must reconstruct all 256 bits exactly.
        let mut rebuilt = [0u64; 4];
        for (b, chunk) in chunks.iter().enumerate() {
            rebuilt[b / 4] |= (*chunk as u64) << (16 * (b % 4));
        }
        assert_eq!(PdqHash(rebuilt), hash);
    }

    #[test]
    fn block_distance_bound_matches_pigeonhole() {
        // Distance exactly 31 spread across the 16-block partition:
        // 15 blocks differ by 2 bits and one by 1 — pigeonhole then forces
        // at least one block with ≤ 1 differing bit.
        let a = PdqHash([0, 0, 0, 0]);
        let mut bits: Vec<usize> = Vec::with_capacity(31);
        for block in 0..16 {
            let block_base = block * 16;
            if block == 15 {
                bits.push(block_base); // this block differs by exactly 1 bit
            } else {
                bits.push(block_base);
                bits.push(block_base + 1); // 2-bit difference
            }
        }
        assert_eq!(bits.len(), 31);
        let mut b_words = a.0;
        for &pos in &bits {
            b_words[pos / 64] ^= 1u64 << (pos % 64);
        }
        let b = PdqHash(b_words);
        assert_eq!(a.hamming_distance(&b), 31, "fixture must flip exactly 31 distinct bits");
        let (ca, cb) = (a.blocks16(), b.blocks16());
        let block_diffs: [u32; 16] = std::array::from_fn(|i| (ca[i] ^ cb[i]).count_ones());
        assert_eq!(block_diffs.iter().sum::<u32>(), 31);
        assert_eq!(block_diffs[15], 1, "last block differs by exactly 1 bit");
        assert!(block_diffs.iter().any(|d| *d <= 1), "pigeonhole: some block must differ by ≤1 bit");
    }
}
