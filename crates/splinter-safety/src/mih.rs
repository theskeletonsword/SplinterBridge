//! Multi-Index Hashing (MIH) index over 256-bit PDQ perceptual hashes.
//!
//! ## The algorithm (Norouzi et al., "Multi-Index Hashing for Billions of Scale
//! Similarity Searches", ICCV 2012)
//!
//! A PDQ hash is partitioned into `m = 16` disjoint 16-bit blocks
//! (`b0..b15`) via [`crate::pdq::PdqHash::blocks16`]. For a Hamming radius
//! `D`, the pigeonhole principle guarantees that if
//! `HammingDistance(query, stored) ≤ D`, then at least one block `i` satisfies
//! `d_i ≤ ⌊D / m⌋`. With `m = 16` and `D = 31` (the PDQ standard threshold),
//! `⌊31 / 16⌋ = 1`: at least one block of a matching signature differs from
//! the query block **by at most one bit**.
//!
//! Indexing therefore keys each signature in table `i` on its exact block
//! value `b_i`. At query time we probe table `i` with the query block value
//! plus its **17 one-bit neighbors** (`v ^ (1 << j)`, `j ∈ 0..16`, plus `v`
//! itself), i.e. every block value at distance ≤ 1. Any candidate returned
//! by a probe is *false-positive-pruned* with an exact 256-bit `popcnt`
//! Hamming distance before being reported, so the final verdict is exact.
//!
//! The guarantee is two-sided:
//! * **Zero false negatives**: D ≤ 31 ⇒ some block differs by ≤ 1 ⇒ probed.
//! * **Zero false positives**: every hit is re-verified with full 256-bit
//!   Hamming distance.
//!
//! ## Storage layout (flat CSR arrays)
//!
//! Each block table is an immutable Compressed-Sparse-Row structure:
//! a sorted `Vec<u16>` of distinct keys, a prefix-sum `Vec<u32>` of offsets
//! and a flat `Vec<u32>` of signature ids. Probing is a binary search over
//! ≤ 65 536 keys followed by a slice borrow — zero hashing, zero per-entry
//! indirection. For 400 000 signatures: 16 tables × 400 000 entries ≈ 6.4 M
//! `u32` ids ≈ 26 MiB of flat payloads, plus ~6 MiB of keys/offsets.
//! `HashMap`-backed tables would cost roughly 10× more memory at this scale,
//! which is why the CSR layout is load-bearing here.
//!
//! ## Complexity
//!
//! * Build: O(16·N) block computations + O(16·N·log N) sort.
//! * Probe: O(16 · 17 · log K) binary searches (K ≤ 65 536 distinct keys) —
//!   ~4.6 k cheap comparisons, effectively cache-resident.
//! * Verify: O(C · 4) popcnt where C = |deduped candidate set|. With random
//!   hashes and N = 400 k the expected per-block probe hit probability is
//!   17/65 536, so C ≈ 16 · 17 · N / 65 536 ≈ 1.6 k — false-positive pruning
//!   keeps the verify bill in the low microseconds.
//!
//! The index is **immutable after construction**, which makes it trivially
//! `Send + Sync`, allows lock-free reads through an `ArcSwap` snapshot, and
//! sidesteps the read-side contention that sank the previous `RwLock<
//! Vec<PdqHash>>` linear scan (prohibited).

use crate::pdq::PdqHash;

/// Number of disjoint 16-bit blocks in the partition.
pub const MIH_BLOCKS: usize = 16;

/// Size in bits of each block. 16 bits ⇒ at most 65 536 distinct keys per table.
pub const MIH_BLOCK_BITS: u32 = 16;

/// Per-block neighbor-generation radius used at query time. `1` bit.
pub const MIH_NEIGHBOR_RADIUS: u32 = 1;

/// Maximum Hamming threshold supported by this index topology:
/// `MIH_BLOCKS * (MIH_NEIGHBOR_RADIUS + 1) - 1 = 31`.
pub const MIH_MAX_THRESHOLD: u32 = 31;

/// One block position index for lookup — a direct-indexed flat bucket array:
/// keys are 16-bit values, so `offsets[key]` resolves in O(1) (no hashing,
/// no binary search). 16 tables × 65 537 `u32` offsets ≈ 4.2 MiB resident.
struct ChunkTable {
    /// Prefix-sum bucket offsets over ALL 2^16 possible keys;
    /// `ids[offsets[key]..offsets[key+1]]` is the id bucket for `key`.
    /// Length 65 537 (final entry = total id count).
    offsets: Vec<u32>,
    /// Flat bucket payload: signature ids (indices into the storage vector),
    /// per-bucket ascending (from counting-sort fill order).
    ids: Vec<u32>,
}

/// Cache-line prefetch hint; a no-op on architectures without a stable
/// software prefetch instruction. `prefetcht0` targets the L1 data cache —
/// used to hide the DRAM latency of the candidate-verify stream.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn prefetch(ptr: *const u8) {
    // SAFETY: `prefetcht0` is a pure performance hint with no memory effect;
    // it may be an invalid pointer without crashing.
    unsafe {
        std::arch::asm!(
            "prefetcht0 [{}]",
            in(reg) ptr,
            options(nostack, preserves_flags)
        );
    }
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
fn prefetch(_ptr: *const u8) {}

impl ChunkTable {    /// Direct O(1) bucket resolution — the binary search of the original
    /// CSR design measured at ~35 µs/query at 400 k signatures and is the
    /// single largest hot-path cost; direct indexing removes it entirely.
    #[inline(always)]
    fn bucket(&self, key: u16) -> &[u32] {
        let start = self.offsets[key as usize] as usize;
        let end = self.offsets[key as usize + 1] as usize;
        &self.ids[start..end]
    }
}

/// The complete MIH structure: one [`ChunkTable`] per block position plus the
/// dense storage of registered hashes. Immutable once built.
pub struct MihIndex {
    tables: Vec<ChunkTable>,
    storage: Vec<PdqHash>,
}

impl MihIndex {
    /// Builds the index from an iterator of hashes. Duplicates are retained
    /// (harmless: candidate ids are deduplicated per evaluation and the extra
    /// entry only ever verifies to distance 0 against itself).
    pub fn build<I>(hashes: I) -> Self
    where
        I: IntoIterator<Item = PdqHash>,
    {
        let storage: Vec<PdqHash> = hashes.into_iter().collect();

        let tables: Vec<ChunkTable> = (0..MIH_BLOCKS)
            .map(|block| {
                // Counting sort per block position: O(N) counting pass +
                // O(2^16) prefix-sum pass + O(N) scatter pass. At 400 k
                // signatures this is ~an order of magnitude faster than
                // comparison sorting the (key, id) pairs.
                let mut counts = vec![0u32; (1 << MIH_BLOCK_BITS) + 1];
                for hash in storage.iter() {
                    counts[hash.blocks16()[block] as usize + 1] += 1;
                }
                for slot in 1..counts.len() {
                    counts[slot] += counts[slot - 1];
                }
                let mut ids: Vec<u32> = vec![0u32; storage.len()];
                let mut cursors = counts.clone();
                for (id, hash) in storage.iter().enumerate() {
                    let key = hash.blocks16()[block] as usize;
                    ids[cursors[key] as usize] = id as u32;
                    cursors[key] += 1;
                }
                ChunkTable { offsets: counts, ids }
            })
            .collect();

        Self { tables, storage }
    }

    /// Number of registered signatures in storage.
    #[inline]
    pub fn len(&self) -> usize {
        self.storage.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.storage.is_empty()
    }

    /// Dense storage of registered hashes (as indexable slice). Callers
    /// rebuild snapshots by unioning `iter()` with new batches — the MIH
    /// structure tolerates duplicated ids (candidate sets are deduplicated
    /// per probe and exact popcnt verification prunes phantom matches).
    pub fn storage(&self) -> &[PdqHash] {
        &self.storage
    }

    /// Evaluates a candidate hash and returns `Some(distance)` where
    /// `distance` is the minimal Hamming distance ≤ `threshold` found, else
    /// `None`.
    ///
    /// Three cost-optimized phases:
    /// 1. **Probe** — direct-indexed bucket resolution over the 16 block
    ///    tables: `offsets[key]`, O(1) per probe, 272 probes total.
    /// 2. **Order** — sort + dedup of the ~1.7 k candidate ids. Sorting is
    ///    worth its ~10 µs: the sorted verify phase then walks the storage
    ///    vector monotonically, so the hardware prefetcher turns ~1.7 k
    ///    random 32-byte loads into sequential 64-byte-line streams
    ///    (~0.5 µs warm, vs ~30-45 µs of random access).
    /// 3. **Verify** — exact 256-bit popcnt distance per candidate; the
    ///    result is the true minimum, both ways exact (pigeonhole ⇒ no false
    ///    negatives; popcnt ⇒ no false positives). `break` at distance 0.
    ///
    /// # Panics
    /// Only if `threshold > MIH_MAX_THRESHOLD` — callers must uphold that
    /// contract (the engine does, see [`crate::engine`]).
    pub fn min_match_distance(&self, candidate: &PdqHash, threshold: u32) -> Option<u32> {
        assert!(
            threshold <= MIH_MAX_THRESHOLD,
            "MIH topology supports thresholds up to {MIH_MAX_THRESHOLD}, got {threshold}"
        );
        if self.storage.is_empty() {
            return None;
        }

        let blocks = candidate.blocks16();
        let mut candidates: Vec<u32> = Vec::with_capacity(2048);
        for (block_idx, table) in self.tables.iter().enumerate() {
            let query_block = blocks[block_idx];
            // Software-prefetch each next probe's offsets line while resolving
            // the current one: the probe phase is bound by L3 latency on the
            // 4 MiB offsets arrays, and 272 sequential-ish misses hide well
            // behind a 1-deep prefetch queue.
            prefetch(table.offsets.as_ptr().cast());
            candidates.extend(table.bucket(query_block).iter().copied());
            for bit in 0u32..MIH_BLOCK_BITS {
                let probe_key = query_block ^ (1u16 << bit);
                if bit + 1 < MIH_BLOCK_BITS {
                    let next = query_block ^ (1u16 << (bit + 1));
                    let next_addr = table.offsets.as_ptr().wrapping_add(next as usize).cast();
                    prefetch(next_addr);
                }
                candidates.extend(table.bucket(probe_key).iter().copied());
            }
        }
        if candidates.is_empty() {
            return None;
        }
        candidates.sort_unstable();
        candidates.dedup();

        let storage = &self.storage;
        let mut best: u32 = u32::MAX;
        for (chunk_idx, id) in candidates.iter().copied().enumerate() {
            // Prefetch the next candidates' hash limbs while the current
            // line is being processed: hides most of the DRAM latency.
            if chunk_idx + 32 < candidates.len() {
                let next = candidates[chunk_idx + 32] as usize;
                prefetch(storage[next].0.as_ptr().cast());
            }
            let dist = candidate.hamming_distance(&storage[id as usize]);
            if dist <= threshold && dist < best {
                best = dist;
                if best == 0 {
                    break; // exact match — cannot be beaten
                }
            }
        }
        if best == u32::MAX { None } else { Some(best) }
    }
}

/// Re-exported for engine-level validation: the largest threshold this MIH
/// topology correctly supports (= [`DEFAULT_PDQ_HAMMING_THRESHOLD`]).
pub const MAX_SUPPORTED_THRESHOLD: u32 = MIH_MAX_THRESHOLD;

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_from_bit_bits(bits: &[usize]) -> PdqHash {
        // Build a hash by flipping individual bit positions (0..256),
        // bit i lives in word i/64 at position i%64.
        let mut words = [0u64; 4];
        for &b in bits {
            words[b / 64] |= 1u64 << (b % 64);
        }
        PdqHash(words)
    }

    #[test]
    fn birdge_construction_canonicalization() {
        // Flipping bits 0..31 and 32..63 must map to expected block layout.
        let h = hash_from_bit_bits(&[0, 16, 4 * 16 + 15, 12 * 16 + 1]);
        let blocks = h.blocks16();
        assert_eq!(blocks[0], 0x0001);
        assert_eq!(blocks[1], 0x0001);
        assert_eq!(blocks[4], 0x8000);
        assert_eq!(blocks[12], 0x0002);
    }

    #[test]
    fn finds_match_exactly_at_threshold_via_single_block() {
        // Store a base with all distinct bits from the candidate except one
        // block differing by exactly 1: pigeonhole must route through that
        // one block's neighbor probe.
        let base = hash_from_bit_bits(&[]);
        let idx = MihIndex::build([base]);
        // Candidate = distance 31 away.
        let cand = hash_from_bit_bits(&(0..31).collect::<Vec<_>>());
        let dist = base.hamming_distance(&cand);
        assert_eq!(dist, 31);
        assert_eq!(idx.min_match_distance(&cand, 31), Some(31));
        assert_eq!(idx.min_match_distance(&cand, 30), None);
    }

    #[test]
    fn threshold_boundary_false_negative_check() {
        let base = hash_from_bit_bits(&[]);
        let idx = MihIndex::build([base]);
        let above = hash_from_bit_bits(&(0..32).collect::<Vec<_>>());
        assert_eq!(base.hamming_distance(&above), 32);
        // Distance 32 > every supported threshold ⇒ nothing found (true negative).
        assert_eq!(idx.min_match_distance(&above, 31), None);
    }

    #[test]
    fn spread_matches_across_many_blocks_are_still_found() {
        // Matching pair at distance 31 spread across 16 blocks:
        // 15 blocks differ by 2 bits, one by 1.
        let mut bits = Vec::new();
        for block in 0..16 {
            let block_base = block * 16;
            if block == 15 {
                bits.push(block_base); // 1-bit difference in last block
            } else {
                bits.push(block_base);
                bits.push(block_base + 1); // 2-bit difference
            }
        }
        assert_eq!(bits.len(), 31);
        let base = hash_from_bit_bits(&[]);
        let cand = hash_from_bit_bits(&bits);
        assert_eq!(base.hamming_distance(&cand), 31);

        // 50 related + 10_000 unrelated signatures: exact result must hold.
        let mut sigs = vec![base; 50];
        let unrelated = hash_from_bit_bits(&(100..256).collect::<Vec<_>>());
        for _ in 0..10_000 {
            sigs.push(unrelated);
        }
        let idx = MihIndex::build(sigs);
        assert_eq!(idx.min_match_distance(&cand, 31), Some(31));
    }

    #[test]
    fn duplicates_do_not_break_evaluation() {
        let base = hash_from_bit_bits(&[]);
        let idx = MihIndex::build(std::iter::repeat_n(base, 5));
        assert_eq!(idx.min_match_distance(&base, 31), Some(0));
        assert_eq!(idx.min_match_distance(&hash_from_bit_bits(&[0, 1, 2]), 31), Some(3));
    }

    #[test]
    fn empty_index_never_matches() {
        let idx = MihIndex::build([]);
        assert!(idx.is_empty());
        assert_eq!(idx.min_match_distance(&hash_from_bit_bits(&[]), 31), None);
    }
}
