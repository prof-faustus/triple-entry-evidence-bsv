// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Craig Wright

//! Selective Verification / proof-sharding (WO 2025/119666 A1).
//!
//! Anchors a population of leaves, indexes them by BSV transaction attributes,
//! and on a query returns only the proof fragment needed to verify that one
//! item. The fragment is the **lower shard** (siblings from leaf up to the
//! predetermined level `k`). The upper shard, from `k` to root, is the same
//! for every leaf and is published on BSV as **proof-assistance** data.
//!
//! Index keys are drawn from the on-chain BSV transaction attributes
//! (per claims 5–6 of the patent): transaction identifier, input/output
//! flag, input/output position, locking script, unlocking script, amount in
//! **minor units**, and position of the transaction in the block.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tee_bsv::{Hash, HASH_LEN};
use tee_merkle::{
    build_proof, depth_for, merkle_root_of_leaves, parent_hash, verify_proof, MerkleError,
    MerkleProof,
};

#[derive(Debug, thiserror::Error)]
pub enum ProofStoreError {
    #[error(transparent)]
    Merkle(#[from] MerkleError),
    #[error("index key not found in store")]
    IndexNotFound,
    #[error("predetermined level k = {0} exceeds tree depth {1}")]
    KOutOfRange(usize, usize),
}

/// Reconstruction posture exposed to callers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconstructionMode {
    /// Reconstruct the Merkle path against published node labels and the
    /// BSV-anchored root. The only mode the audit path accepts.
    Adversarial,
    /// Verify using the patent's optional EC homomorphic compression of the
    /// proof-assistance labels on the BSV curve. Faster, easier to manipulate,
    /// not adversarially secure. The audit path rejects results from this mode.
    TrustedOperational,
}

/// Identifies an anchored leaf via its BSV transaction context.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IndexKey {
    pub txid_be: String,
    pub in_or_out: InOrOut,
    pub position: u32,
    pub locking_script_hex: String,
    pub unlocking_script_hex: String,
    /// Amount in **minor units** (the smallest accounting unit on this medium).
    pub amount: u64,
    pub block_position: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InOrOut {
    Input,
    Output,
}

/// A stored leaf and its lower-shard proof fragment.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredProof {
    pub leaf_index: usize,
    pub leaf_hex: String,
    /// Lower shard: sibling hashes from leaf up to the predetermined level k.
    pub lower_shard_hex: Vec<String>,
}

/// The patent's "proof-assistance" data: the node labels at the predetermined
/// level k. Published on BSV in plain form (and optionally compressed on the
/// BSV curve under TrustedOperational mode).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofAssistance {
    pub predetermined_level: usize,
    pub node_labels_hex: Vec<String>,
}

/// In-memory selective-verification store.
#[derive(Clone, Debug)]
pub struct ProofStore {
    leaves: Vec<Hash>,
    index: HashMap<IndexKey, usize>,
    root: Hash,
    assistance: ProofAssistance,
    k: usize,
}

impl ProofStore {
    /// Anchor a population of leaves with their index keys. The predetermined
    /// level defaults to `floor(log2(N) / 2)` if `k` is `None`.
    pub fn anchor(
        keys_and_leaves: Vec<(IndexKey, Hash)>,
        predetermined_level: Option<usize>,
    ) -> Result<Self, ProofStoreError> {
        let leaves: Vec<Hash> = keys_and_leaves.iter().map(|(_, h)| *h).collect();
        let mut index: HashMap<IndexKey, usize> = HashMap::with_capacity(keys_and_leaves.len());
        for (i, (k, _)) in keys_and_leaves.into_iter().enumerate() {
            index.insert(k, i);
        }
        let depth = depth_for(leaves.len());
        let k = match predetermined_level {
            Some(k) => {
                if k > depth {
                    return Err(ProofStoreError::KOutOfRange(k, depth));
                }
                k
            }
            None => {
                let n = leaves.len();
                ((63 - (n as u64).leading_zeros()) as usize) / 2
            }
        };
        let root = merkle_root_of_leaves(&leaves)?;
        let assistance = compute_assistance(&leaves, k);
        Ok(ProofStore {
            leaves,
            index,
            root,
            assistance,
            k,
        })
    }

    pub fn root(&self) -> &Hash {
        &self.root
    }

    pub fn predetermined_level(&self) -> usize {
        self.k
    }

    pub fn assistance(&self) -> &ProofAssistance {
        &self.assistance
    }

    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    /// Return only the requested fragment for one query — nothing about any other
    /// anchored leaf is revealed (selective disclosure).
    pub fn query(&self, key: &IndexKey) -> Result<StoredProof, ProofStoreError> {
        let idx = *self.index.get(key).ok_or(ProofStoreError::IndexNotFound)?;
        let full: MerkleProof = build_proof(&self.leaves, idx)?;
        // Lower shard = first k siblings.
        let lower: Vec<String> = full.siblings_hex.into_iter().take(self.k).collect();
        Ok(StoredProof {
            leaf_index: idx,
            leaf_hex: hex::encode(self.leaves[idx]),
            lower_shard_hex: lower,
        })
    }

    /// Adversarial reconstruction: rebuild the Merkle path from leaf up using
    /// the lower shard (private) and the proof-assistance labels (public),
    /// then check the recomputed root equals the anchored root.
    pub fn verify_adversarial(
        &self,
        leaf: &Hash,
        stored: &StoredProof,
    ) -> Result<(), ProofStoreError> {
        // Climb the lower shard.
        let mut node = *leaf;
        let mut idx = stored.leaf_index;
        for s_hex in &stored.lower_shard_hex {
            let sib = parse_hash_hex(s_hex)?;
            node = if idx % 2 == 0 {
                parent_hash(&node, &sib)
            } else {
                parent_hash(&sib, &node)
            };
            idx /= 2;
        }
        // At level k, `node` should equal one of the published assistance labels.
        let assist_idx = idx;
        let expected = parse_hash_hex(
            self.assistance
                .node_labels_hex
                .get(assist_idx)
                .ok_or(ProofStoreError::IndexNotFound)?,
        )?;
        if node != expected {
            return Err(ProofStoreError::Merkle(MerkleError::RootMismatch));
        }
        // Climb from k to root using the assistance labels.
        let mut upper_nodes: Vec<Hash> = self
            .assistance
            .node_labels_hex
            .iter()
            .map(|s| parse_hash_hex(s).unwrap_or_default())
            .collect();
        while upper_nodes.len() > 1 {
            if upper_nodes.len() % 2 == 1 {
                upper_nodes.push(*upper_nodes.last().expect("non-empty"));
            }
            let mut next = Vec::with_capacity(upper_nodes.len() / 2);
            let mut i = 0;
            while i < upper_nodes.len() {
                next.push(parent_hash(&upper_nodes[i], &upper_nodes[i + 1]));
                i += 2;
            }
            upper_nodes = next;
        }
        if upper_nodes[0] != self.root {
            return Err(ProofStoreError::Merkle(MerkleError::RootMismatch));
        }
        Ok(())
    }

    /// Convenience: also runs the upstream Merkle proof verification check.
    pub fn verify_full_merkle(&self, key: &IndexKey, leaf: &Hash) -> Result<(), ProofStoreError> {
        let idx = *self.index.get(key).ok_or(ProofStoreError::IndexNotFound)?;
        let proof = build_proof(&self.leaves, idx)?;
        verify_proof(&proof, leaf, &self.root)?;
        Ok(())
    }
}

fn compute_assistance(leaves: &[Hash], k: usize) -> ProofAssistance {
    // Walk up exactly k levels, applying BSV odd-duplication, and capture the
    // node labels at that level.
    let mut level: Vec<Hash> = leaves.to_vec();
    for _ in 0..k {
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
    ProofAssistance {
        predetermined_level: k,
        node_labels_hex: level.iter().map(hex::encode).collect(),
    }
}

fn parse_hash_hex(s: &str) -> Result<Hash, ProofStoreError> {
    let v =
        hex::decode(s).map_err(|_| ProofStoreError::Merkle(MerkleError::ProofLengthMismatch))?;
    if v.len() != HASH_LEN {
        return Err(ProofStoreError::Merkle(MerkleError::ProofLengthMismatch));
    }
    let mut h = [0u8; HASH_LEN];
    h.copy_from_slice(&v);
    Ok(h)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tee_merkle::leaf_hash;

    fn fake_key(i: u64) -> IndexKey {
        IndexKey {
            txid_be: format!("{:064x}", i),
            in_or_out: InOrOut::Output,
            position: 0,
            locking_script_hex: "76a9".to_string(),
            unlocking_script_hex: String::new(),
            amount: 1000 + i,
            block_position: i,
        }
    }

    #[test]
    fn anchor_query_verify_adversarial() {
        let n = 16usize;
        let pairs: Vec<(IndexKey, Hash)> = (0..n)
            .map(|i| (fake_key(i as u64), leaf_hash(&(i as u32).to_be_bytes())))
            .collect();
        let store = ProofStore::anchor(pairs.clone(), None).unwrap();
        assert_eq!(store.predetermined_level(), 2); // floor(log2(16)/2) = 2

        for (key, leaf) in &pairs {
            let q = store.query(key).unwrap();
            store.verify_adversarial(leaf, &q).expect("verify ok");
            store.verify_full_merkle(key, leaf).expect("full ok");
        }
    }

    #[test]
    fn unknown_key_rejected() {
        let pairs: Vec<(IndexKey, Hash)> = (0..4)
            .map(|i| (fake_key(i as u64), leaf_hash(&(i as u32).to_be_bytes())))
            .collect();
        let store = ProofStore::anchor(pairs, Some(1)).unwrap();
        let bogus = fake_key(999);
        assert!(matches!(
            store.query(&bogus),
            Err(ProofStoreError::IndexNotFound)
        ));
    }

    #[test]
    fn assistance_size_matches_level() {
        let n = 32usize;
        let pairs: Vec<(IndexKey, Hash)> = (0..n)
            .map(|i| (fake_key(i as u64), leaf_hash(&(i as u32).to_be_bytes())))
            .collect();
        let store = ProofStore::anchor(pairs, Some(2)).unwrap();
        // Two levels above 32 leaves => 32/4 = 8 assistance labels.
        assert_eq!(store.assistance().node_labels_hex.len(), 8);
    }
}
