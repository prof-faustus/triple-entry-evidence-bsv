// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Craig Wright

//! BSV anchoring of TEA notes.
//!
//! TEA notes are leaves; many notes are batched into a single Merkle root,
//! which is the value embedded in a BSV data-carrier output. Verification of
//! any note's presence terminates in the BSV block header chain by traversing
//!
//!   note body  →  leaf hash (double_sha256(body))
//!              →  batch Merkle root (BSV-canonical odd-duplicating tree)
//!              →  BSV transaction containing the root in a data-carrier output
//!              →  BSV block containing that transaction
//!              →  BSV block header Merkle root over the block's txids
//!              →  validated BSV block header chain.
//!
//! The crate models the batching step and the envelope that records which
//! root was anchored in which BSV transaction; the on-chain side (broadcast,
//! confirmation, header validation) is left to the deploying integration.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use tee_bsv::{double_sha256, Hash};
use tee_merkle::{build_proof, merkle_root_of_leaves, verify_proof, MerkleError, MerkleProof};
use tee_tea::SignedNote;

#[derive(Debug, thiserror::Error)]
pub enum AnchorError {
    #[error(transparent)]
    Merkle(#[from] MerkleError),
    #[error("batch is empty")]
    EmptyBatch,
    #[error("hex decode error in stored field {0}")]
    BadHex(&'static str),
}

/// A batch of notes anchored under one Merkle root.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnchoredBatch {
    pub batch_id: u64,
    pub leaf_hashes_hex: Vec<String>,
    pub merkle_root_hex: String,
    /// Identifier of the BSV transaction that carries the root in a data-carrier
    /// output. Stored in display (big-endian) orientation, matching how block
    /// explorers render BSV txids.
    pub bsv_anchor_txid_be: String,
    /// Amount in **minor units** spent on the anchor output (informational).
    pub anchor_minor_units: u64,
}

/// Build a batch by hashing each signed note's body, computing the
/// BSV-canonical Merkle root, and returning the batch envelope.
pub fn build_batch(
    batch_id: u64,
    notes: &[SignedNote],
    bsv_anchor_txid_be: impl Into<String>,
    anchor_minor_units: u64,
) -> Result<AnchoredBatch, AnchorError> {
    if notes.is_empty() {
        return Err(AnchorError::EmptyBatch);
    }
    let leaves: Vec<Hash> = notes
        .iter()
        .map(|n| {
            let body = hex::decode(&n.body_hex).map_err(|_| AnchorError::BadHex("body_hex"))?;
            Ok::<Hash, AnchorError>(double_sha256(&body))
        })
        .collect::<Result<_, _>>()?;
    let root = merkle_root_of_leaves(&leaves)?;
    Ok(AnchoredBatch {
        batch_id,
        leaf_hashes_hex: leaves.iter().map(hex::encode).collect(),
        merkle_root_hex: hex::encode(root),
        bsv_anchor_txid_be: bsv_anchor_txid_be.into(),
        anchor_minor_units,
    })
}

/// Build an inclusion proof for one note within a batch.
pub fn build_inclusion_proof(
    batch: &AnchoredBatch,
    leaf_index: usize,
) -> Result<MerkleProof, AnchorError> {
    let leaves: Vec<Hash> = batch
        .leaf_hashes_hex
        .iter()
        .map(|s| {
            let v = hex::decode(s).map_err(|_| AnchorError::BadHex("leaf_hashes_hex"))?;
            let mut h = [0u8; 32];
            h.copy_from_slice(&v);
            Ok::<Hash, AnchorError>(h)
        })
        .collect::<Result<_, _>>()?;
    let p = build_proof(&leaves, leaf_index)?;
    Ok(p)
}

/// Verify that `note_body` is in `batch` at `proof.leaf_index`.
pub fn verify_inclusion(
    note_body: &[u8],
    batch: &AnchoredBatch,
    proof: &MerkleProof,
) -> Result<(), AnchorError> {
    let leaf = double_sha256(note_body);
    let root_bytes =
        hex::decode(&batch.merkle_root_hex).map_err(|_| AnchorError::BadHex("merkle_root_hex"))?;
    let mut root = [0u8; 32];
    root.copy_from_slice(&root_bytes);
    verify_proof(proof, &leaf, &root)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tee_bsvcurve::BsvScalar;
    use tee_tea::{
        build_note_body, commit_one, derive_key_material, derive_subkey, sign_note,
        NoteBuilderInputs, NoteKind, SignedNote,
    };

    fn make_note(idx: u32) -> SignedNote {
        let sk_a = BsvScalar::from_bytes(&[0x11u8; 32]).unwrap();
        let sk_b = BsvScalar::from_bytes(&[0x22u8; 32]).unwrap();
        let a = derive_subkey(&sk_a, idx).unwrap();
        let b = derive_subkey(&sk_b, idx).unwrap();
        let mat = derive_key_material(&a.scalar, &b.point);
        let note_id = format!("INV-{:05}", idx);
        let fields = [
            ("InvID", note_id.as_str()),
            ("Curr", "EUR"),
            ("Net", "10000.00"),
            ("Gross", "12100.00"),
            ("Tax", "2100.00"),
        ];
        let cs: Vec<_> = fields
            .iter()
            .map(|(l, v)| commit_one(&mat.k_master, &note_id, l, v).1)
            .collect();
        let body = build_note_body(&NoteBuilderInputs {
            kind: NoteKind::Invoice,
            version: 1,
            primary_tag: mat.l_inv,
            secondary_tag: [0u8; 32],
            issuer_pk: a.point,
            counterparty_pk: b.point,
            commitments: &cs,
        });
        let (h, sig) = sign_note(&a.scalar, &body);
        SignedNote {
            kind: NoteKind::Invoice,
            version: 1,
            note_id: note_id.clone(),
            primary_tag_hex: hex::encode(mat.l_inv),
            secondary_tag_hex: hex::encode([0u8; 32]),
            issuer_pk_hex: hex::encode(a.point.to_compressed()),
            counterparty_pk_hex: hex::encode(b.point.to_compressed()),
            fields_pub: fields
                .iter()
                .map(|(l, _)| tee_tea::Field {
                    label: (*l).to_string(),
                    value: String::new(),
                })
                .collect(),
            commitments_hex: cs.iter().map(hex::encode).collect(),
            body_hex: hex::encode(&body),
            body_hash_hex: hex::encode(h),
            signature_hex: hex::encode(sig),
        }
    }

    #[test]
    fn batch_round_trip() {
        let notes: Vec<SignedNote> = (1u32..=8).map(make_note).collect();
        let batch = build_batch(42, &notes, "ab".repeat(32), 1).unwrap();
        for (i, n) in notes.iter().enumerate() {
            let p = build_inclusion_proof(&batch, i).unwrap();
            let body = hex::decode(&n.body_hex).unwrap();
            verify_inclusion(&body, &batch, &p).expect("inclusion verifies");
        }
    }

    #[test]
    fn tampered_body_rejected() {
        let notes: Vec<SignedNote> = (1u32..=4).map(make_note).collect();
        let batch = build_batch(7, &notes, "cd".repeat(32), 1).unwrap();
        let p = build_inclusion_proof(&batch, 1).unwrap();
        let mut tampered = hex::decode(&notes[1].body_hex).unwrap();
        tampered[5] ^= 0x01;
        assert!(verify_inclusion(&tampered, &batch, &p).is_err());
    }
}
