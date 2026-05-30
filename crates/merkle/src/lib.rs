// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Craig Wright

//! Merkle Proof Entity (WO 2022/100946 A1) over the BSV block Merkle convention.
//!
//! Node rule:
//! - `N(i, i) = H(D_i)` for leaves where `D_i` is the i-th leaf payload.
//! - `N(i, j) = H(N(i, k) || N(k+1, j))` for internal nodes.
//! - `H` is the BSV double-SHA256 (`bsv::double_sha256`).
//! - Odd-node rule (BSV convention): when a level has an odd number of nodes,
//!   the last node is duplicated and concatenated with itself before hashing.
//!
//! A Merkle proof is the leaf index and the ordered list of sibling hashes
//! climbing from leaf to root. Verification recomputes the root and accepts iff
//! it matches the anchored root.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use tee_bsv::{double_sha256, Hash, HASH_LEN};

#[derive(Debug, thiserror::Error)]
pub enum MerkleError {
    #[error("empty leaf set")]
    EmptyLeaves,
    #[error("leaf index {0} out of range for {1} leaves")]
    IndexOutOfRange(usize, usize),
    #[error("reconstructed root does not match anchored root")]
    RootMismatch,
    #[error("proof has wrong length for leaf set depth")]
    ProofLengthMismatch,
}

/// A single inclusion proof for a leaf.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_index: usize,
    pub total_leaves: usize,
    pub siblings_hex: Vec<String>,
}

/// Hash one payload into a leaf.
pub fn leaf_hash(payload: &[u8]) -> Hash {
    double_sha256(payload)
}

/// Hash two child nodes into a parent.
pub fn parent_hash(left: &Hash, right: &Hash) -> Hash {
    let mut buf = [0u8; HASH_LEN * 2];
    buf[..HASH_LEN].copy_from_slice(left);
    buf[HASH_LEN..].copy_from_slice(right);
    double_sha256(&buf)
}

/// Compute the BSV-canonical Merkle root over already-hashed leaves.
pub fn merkle_root_of_leaves(leaves: &[Hash]) -> Result<Hash, MerkleError> {
    if leaves.is_empty() {
        return Err(MerkleError::EmptyLeaves);
    }
    let mut level: Vec<Hash> = leaves.to_vec();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().expect("non-empty"));
        }
        let mut next = Vec::with_capacity(level.len() / 2);
        let mut i = 0;
        while i < level.len() {
            next.push(parent_hash(&level[i], &level[i + 1]));
            i += 2;
        }
        level = next;
    }
    Ok(level[0])
}

/// Compute the Merkle root over a slice of leaf payloads (hashes each first).
pub fn merkle_root_of_payloads(payloads: &[Vec<u8>]) -> Result<Hash, MerkleError> {
    let leaves: Vec<Hash> = payloads.iter().map(|p| leaf_hash(p)).collect();
    merkle_root_of_leaves(&leaves)
}

/// Build an inclusion proof for `leaf_index` against the leaf set.
pub fn build_proof(leaves: &[Hash], leaf_index: usize) -> Result<MerkleProof, MerkleError> {
    if leaves.is_empty() {
        return Err(MerkleError::EmptyLeaves);
    }
    if leaf_index >= leaves.len() {
        return Err(MerkleError::IndexOutOfRange(leaf_index, leaves.len()));
    }
    let mut siblings: Vec<Hash> = Vec::new();
    let mut idx = leaf_index;
    let mut level: Vec<Hash> = leaves.to_vec();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().expect("non-empty"));
        }
        let sib_idx = idx ^ 1;
        siblings.push(level[sib_idx]);
        let mut next = Vec::with_capacity(level.len() / 2);
        let mut i = 0;
        while i < level.len() {
            next.push(parent_hash(&level[i], &level[i + 1]));
            i += 2;
        }
        level = next;
        idx /= 2;
    }
    Ok(MerkleProof {
        leaf_index,
        total_leaves: leaves.len(),
        siblings_hex: siblings.iter().map(hex::encode).collect(),
    })
}

/// Verify an inclusion proof against the anchored root.
pub fn verify_proof(
    proof: &MerkleProof,
    leaf: &Hash,
    anchored_root: &Hash,
) -> Result<(), MerkleError> {
    let expected_depth = depth_for(proof.total_leaves);
    if proof.siblings_hex.len() != expected_depth {
        return Err(MerkleError::ProofLengthMismatch);
    }
    let mut node = *leaf;
    let mut idx = proof.leaf_index;
    for s_hex in &proof.siblings_hex {
        let sib_bytes = hex::decode(s_hex).map_err(|_| MerkleError::ProofLengthMismatch)?;
        if sib_bytes.len() != HASH_LEN {
            return Err(MerkleError::ProofLengthMismatch);
        }
        let mut sib = [0u8; HASH_LEN];
        sib.copy_from_slice(&sib_bytes);
        node = if idx % 2 == 0 {
            parent_hash(&node, &sib)
        } else {
            parent_hash(&sib, &node)
        };
        idx /= 2;
    }
    if &node == anchored_root {
        Ok(())
    } else {
        Err(MerkleError::RootMismatch)
    }
}

/// Number of levels above the leaves required to climb to the root,
/// accounting for the odd-duplication rule.
pub fn depth_for(n: usize) -> usize {
    let mut d = 0usize;
    let mut count = n;
    while count > 1 {
        if count % 2 == 1 {
            count += 1;
        }
        count /= 2;
        d += 1;
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(b: &[u8]) -> Hash {
        leaf_hash(b)
    }

    #[test]
    fn root_single_leaf_is_just_the_leaf() {
        let r = merkle_root_of_leaves(&[h(b"only")]).unwrap();
        assert_eq!(r, h(b"only"));
    }

    #[test]
    fn round_trip_8_leaves() {
        let leaves: Vec<Hash> = (0..8u32).map(|i| h(&i.to_be_bytes())).collect();
        let root = merkle_root_of_leaves(&leaves).unwrap();
        for i in 0..leaves.len() {
            let p = build_proof(&leaves, i).unwrap();
            verify_proof(&p, &leaves[i], &root).unwrap();
            // Tamper leaf — must reject.
            let mut bad = leaves[i];
            bad[0] ^= 0xff;
            assert!(verify_proof(&p, &bad, &root).is_err());
        }
    }

    #[test]
    fn round_trip_odd_count_5_leaves() {
        let leaves: Vec<Hash> = (0..5u32).map(|i| h(&i.to_be_bytes())).collect();
        let root = merkle_root_of_leaves(&leaves).unwrap();
        for i in 0..leaves.len() {
            let p = build_proof(&leaves, i).unwrap();
            verify_proof(&p, &leaves[i], &root).unwrap();
        }
    }

    #[test]
    fn bsv_mainnet_block_round_trip() {
        // Real BSV mainnet block fixture: two txids in canonical order.
        // Internal (LE) bytes of the two txids and the expected Merkle root.
        // Source: WhatsOnChain BSV mainnet block
        // hash 00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee
        // (display-BE); committed under vectors/merkle/bsv_block_v1.json.
        let tx1_be =
            hex::decode("b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082")
                .unwrap();
        let tx2_be =
            hex::decode("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16")
                .unwrap();
        let expected_root_be =
            hex::decode("7dac2c5666815c17a3b36427de37bb9d2e2c5ccec3f8633eb91a4205cb4c10ff")
                .unwrap();
        let to_le = |mut v: Vec<u8>| -> Hash {
            v.reverse();
            let mut a = [0u8; 32];
            a.copy_from_slice(&v);
            a
        };
        let leaves = vec![to_le(tx1_be), to_le(tx2_be)];
        let mut root = merkle_root_of_leaves(&leaves).unwrap();
        root.reverse();
        assert_eq!(&root[..], &expected_root_be[..]);
    }
}
