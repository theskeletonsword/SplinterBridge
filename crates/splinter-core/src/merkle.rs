//! Lightweight Merkle commitment tree for binding a public actor to a
//! locally-retained civil identity.
//!
//! The origin backend stores the leaf mapping (actor public key <-> civil ID
//! Shimingzhi / passport / etc.) exclusively inside its own jurisdiction. Only
//! the Merkle root (or a per-actor commitment hash) crosses the border. The
//! full opening (civil ID + sibling path) remains under local threshold escrow
//! and can be produced only under a motivated local judicial order (CSL Art. 24
//! / PIPL Art. 73 local audit path).
//!
//! This is a commitment primitive, not a zero-knowledge proof. A real ZKP
//! (zk-SNARK / Groth16) of "valid civil account, no active sanctions" is the
//! next integration phase and is intentionally not bundled here.

use sha2::{Digest, Sha256};

/// Leaf of the commitment tree: a civil-identity commitment bound to an actor key.
#[derive(Debug, Clone)]
pub struct CommitmentLeaf {
    /// Hash of the locally retained civil identifier (e.g. Shimingzhi hash).
    pub civil_id_commitment: [u8; 32],
    /// Actor public key (Ed25519) bound to this civil identity.
    pub actor_public_key: [u8; 32],
}

/// Merkle tree built over commitment leaves. Only the root is exported.
#[derive(Debug, Clone)]
pub struct CommitmentTree {
    root: [u8; 32],
    leaf_count: usize,
}

impl CommitmentTree {
    /// Hashes a single leaf into a tree node.
    fn leaf_hash(leaf: &CommitmentLeaf) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"splinterbridge:merkle:leaf:v1\0");
        hasher.update(leaf.civil_id_commitment);
        hasher.update(leaf.actor_public_key);
        hasher.finalize().into()
    }

    /// Hashes an internal node from two children.
    fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"splinterbridge:merkle:node:v1\0");
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().into()
    }

    /// Builds a tree from leaves. Returns the tree whose root may be exported.
    pub fn build(leaves: &[CommitmentLeaf]) -> Self {
        if leaves.is_empty() {
            let mut hasher = Sha256::new();
            hasher.update(b"splinterbridge:merkle:empty:v1\0");
            return Self {
                root: hasher.finalize().into(),
                leaf_count: 0,
            };
        }

        let mut level: Vec<[u8; 32]> = leaves.iter().map(Self::leaf_hash).collect();
        // Pad to a power of two by duplicating the last element.
        let mut count = level.len();
        while count > 1 && (count & (count - 1)) != 0 {
            let last = *level.last().unwrap();
            level.push(last);
            count += 1;
        }

        let mut current = level;
        while current.len() > 1 {
            let mut next = Vec::with_capacity(current.len() / 2);
            for pair in current.chunks(2) {
                next.push(Self::node_hash(&pair[0], &pair[1]));
            }
            current = next;
        }

        Self {
            root: current[0],
            leaf_count: leaves.len(),
        }
    }

    /// The Merkle root commitment. This is the value that may cross the border.
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Number of leaves committed in this tree.
    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    /// Produces an inclusion proof for the leaf at `index` (path of sibling
    /// hashes from leaf to root). The full proof is retained by the local
    /// escrow service and is not exported across the border.
    pub fn prove(&self, _index: usize) -> Option<Vec<[u8; 32]>> {
        if self.leaf_count == 0 {
            return None;
        }
        // Stub: the local escrow service builds the real sibling path from its
        // own leaf store. The border only ever sees the root commitment.
        Some(vec![])
    }
}

/// Commitment hash for a single actor: binds civil ID commitment + actor key.
/// Exported as `commitment_hash` on `SanitizedPublicProfile`.
pub fn actor_commitment_hash(
    civil_id_commitment: &[u8; 32],
    actor_public_key: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"splinterbridge:actor:commitment:v1\0");
    hasher.update(civil_id_commitment);
    hasher.update(actor_public_key);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(civil: u8, actor: u8) -> CommitmentLeaf {
        CommitmentLeaf {
            civil_id_commitment: [civil; 32],
            actor_public_key: [actor; 32],
        }
    }

    #[test]
    fn root_is_deterministic_and_sensitive_to_leaves() {
        let t1 = CommitmentTree::build(&[leaf(1, 10), leaf(2, 20)]);
        let t2 = CommitmentTree::build(&[leaf(1, 10), leaf(2, 20)]);
        assert_eq!(t1.root(), t2.root());

        let t3 = CommitmentTree::build(&[leaf(1, 10), leaf(3, 20)]);
        assert_ne!(t1.root(), t3.root());
    }

    #[test]
    fn empty_tree_has_a_defined_root() {
        let t = CommitmentTree::build(&[]);
        assert_eq!(t.leaf_count(), 0);
        let t2 = CommitmentTree::build(&[]);
        assert_eq!(t.root(), t2.root());
    }

    #[test]
    fn commitment_hash_binds_both_inputs() {
        let c = actor_commitment_hash(&[1; 32], &[2; 32]);
        assert_ne!(c, actor_commitment_hash(&[1; 32], &[3; 32]));
        assert_ne!(c, actor_commitment_hash(&[4; 32], &[2; 32]));
    }
}
