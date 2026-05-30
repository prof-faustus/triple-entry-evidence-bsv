// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Craig Wright

//! Triple-entry evidence protocol on the BSV curve.
//!
//! The protocol turns a bilateral invoice / payment relationship into a
//! verifiable public-evidence object:
//!
//! 1. Each party has a master scalar on the BSV curve.
//! 2. Per-note **sub-keys** are derived as `sk_i = sk_master + H(sk_master || u32(i)) mod n`
//!    on the BSV curve, with the corresponding public sub-key `pk_i = sk_i * G`.
//! 3. The two parties run ECDH against their sub-keys to derive a shared 32-byte
//!    value `S` (the affine x of the shared point in big-endian).
//! 4. From `S` they derive a per-note master key
//!    `K_master = HKDF-Extract(salt = "TEA-v1", ikm = S)`,
//!    and two **linkage tags** `L_inv = HKDF-Expand(K_master, "inv-tag")`
//!    and `L_pay = HKDF-Expand(K_master, "pay-tag")`.
//! 5. For every field of the note, a **field key** is derived
//!    `K_field = HKDF-Expand(K_master, "commit" || note_id || field_label)`,
//!    and the public **commitment** is `C_field = SHA256(K_field || field_label || value)`.
//! 6. The note body bundles `(L_inv, L_pay, pk_A_i, pk_B_i, [C_field...])` and is
//!    signed under `sk_A_i` (deterministic ECDSA, low-S enforced).
//!
//! The disclosure crate exposes a separately-signed envelope that releases one
//! `K_field` to one named verifier under expiry and engagement bounds; nothing
//! else about any other field or any other note is revealed.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tee_bsv::{double_sha256, Hash};
use tee_bsvcurve::{
    ecdh_shared_x, ecdsa_sign_prehash, ecdsa_verify_prehash, hash_to_scalar, hkdf_expand_one_block,
    hkdf_extract, BsvPoint, BsvScalar, CurveError, COMPRESSED_POINT_BYTES, SIGNATURE_BYTES,
};

#[derive(Debug, thiserror::Error)]
pub enum TeaError {
    #[error("curve error: {0}")]
    Curve(#[from] CurveError),
    #[error("note body decoding failed")]
    BadBody,
    #[error("subkey index out of range")]
    BadSubkeyIndex,
}

/// 32-byte per-note master key (output of `HKDF-Extract`).
pub type MasterKey = [u8; 32];
/// 32-byte linkage tag.
pub type LinkageTag = [u8; 32];
/// 32-byte per-field key.
pub type FieldKey = [u8; 32];
/// 32-byte per-field commitment.
pub type FieldCommitment = [u8; 32];

/// A single field of an invoice or payment note.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Field {
    pub label: String,
    pub value: String,
}

/// Output of subkey derivation.
#[derive(Clone, Debug)]
pub struct Subkey {
    pub index: u32,
    pub scalar: BsvScalar,
    pub point: BsvPoint,
}

/// Derive sub-key `i` from a master scalar.
///
/// `sk_i = sk_master + H_n(sk_master_be || u32_be(i)) mod n` on the BSV curve.
/// Returns `Err(BadSubkeyIndex)` if the index produces a degenerate scalar after
/// a small number of retries (probability ~2^-128, included for completeness).
pub fn derive_subkey(sk_master: &BsvScalar, index: u32) -> Result<Subkey, TeaError> {
    let mut idx = index;
    for _ in 0..16 {
        let mut buf = [0u8; 36];
        buf[..32].copy_from_slice(&sk_master.to_bytes());
        buf[32..].copy_from_slice(&idx.to_be_bytes());
        let h = hash_to_scalar(&buf);
        if let Ok(sk_i) = sk_master.add(&h) {
            let pk_i = sk_i.mul_base();
            return Ok(Subkey {
                index,
                scalar: sk_i,
                point: pk_i,
            });
        }
        idx = idx.wrapping_add(1);
    }
    Err(TeaError::BadSubkeyIndex)
}

/// Material derived from ECDH between the local sub-key and the counterparty's
/// sub-key public point: shared `S`, per-note `K_master`, and the two linkage
/// tags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyMaterial {
    pub shared_s: [u8; 32],
    pub k_master: MasterKey,
    pub l_inv: LinkageTag,
    pub l_pay: LinkageTag,
}

/// Derive shared `S` and the per-note keying material.
pub fn derive_key_material(sk_self: &BsvScalar, pk_other: &BsvPoint) -> KeyMaterial {
    let s = ecdh_shared_x(sk_self, pk_other);
    let k_master = hkdf_extract(b"TEA-v1", &s);
    let l_inv = hkdf_expand_one_block(&k_master, b"inv-tag");
    let l_pay = hkdf_expand_one_block(&k_master, b"pay-tag");
    KeyMaterial {
        shared_s: s,
        k_master,
        l_inv,
        l_pay,
    }
}

/// Derive a per-field key for the given note and label.
pub fn field_key(k_master: &MasterKey, note_id: &str, label: &str) -> FieldKey {
    let mut info = Vec::with_capacity(8 + note_id.len() + label.len());
    info.extend_from_slice(b"commit");
    info.push(note_id.len() as u8);
    info.extend_from_slice(note_id.as_bytes());
    info.push(label.len() as u8);
    info.extend_from_slice(label.as_bytes());
    hkdf_expand_one_block(k_master, &info)
}

/// Compute the per-field commitment for a given key, label, and value.
///
/// `C_field = SHA256( K_field || u8(len(label)) || label || u32_be(len(value)) || value )`
pub fn commit_field(k_field: &FieldKey, label: &str, value: &str) -> FieldCommitment {
    let mut h = Sha256::new();
    h.update(k_field);
    h.update([label.len() as u8]);
    h.update(label.as_bytes());
    h.update((value.len() as u32).to_be_bytes());
    h.update(value.as_bytes());
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// Compute per-field key and commitment in one call.
pub fn commit_one(
    k_master: &MasterKey,
    note_id: &str,
    label: &str,
    value: &str,
) -> (FieldKey, FieldCommitment) {
    let k = field_key(k_master, note_id, label);
    let c = commit_field(&k, label, value);
    (k, c)
}

/// Note kind discriminator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NoteKind {
    /// Invoice note issued by party A.
    Invoice,
    /// Payment note issued by party B.
    Payment,
}

impl NoteKind {
    pub fn marker_byte(&self) -> u8 {
        match self {
            NoteKind::Invoice => 0x01,
            NoteKind::Payment => 0x02,
        }
    }
}

/// Inputs to building a note body.
#[derive(Clone, Debug)]
pub struct NoteBuilderInputs<'a> {
    pub kind: NoteKind,
    pub version: u8,
    pub primary_tag: LinkageTag, // for invoice notes: L_inv. for payments: L_pay.
    pub secondary_tag: LinkageTag, // for payments: L_inv of the linked invoice; for invoices: zeros.
    pub issuer_pk: BsvPoint,
    pub counterparty_pk: BsvPoint,
    pub commitments: &'a [FieldCommitment],
}

/// Build the canonical byte-encoded note body that is signed and anchored.
///
/// Layout:
///   `version (1) || kind_marker (1) || primary_tag (32) || secondary_tag (32) ||`
///   `issuer_pk (33) || counterparty_pk (33) || u8(num_fields) || C_1 || C_2 || ... || C_n`
pub fn build_note_body(inputs: &NoteBuilderInputs) -> Vec<u8> {
    let n = inputs.commitments.len();
    assert!(n <= u8::MAX as usize, "at most 255 fields per note");
    let mut body = Vec::with_capacity(1 + 1 + 32 + 32 + COMPRESSED_POINT_BYTES * 2 + 1 + n * 32);
    body.push(inputs.version);
    body.push(inputs.kind.marker_byte());
    body.extend_from_slice(&inputs.primary_tag);
    body.extend_from_slice(&inputs.secondary_tag);
    body.extend_from_slice(&inputs.issuer_pk.to_compressed());
    body.extend_from_slice(&inputs.counterparty_pk.to_compressed());
    body.push(n as u8);
    for c in inputs.commitments {
        body.extend_from_slice(c);
    }
    body
}

/// Note hash = `double_sha256(body)` (the leaf hash anchored on BSV).
pub fn note_hash(body: &[u8]) -> Hash {
    double_sha256(body)
}

/// A signed note ready to anchor.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedNote {
    pub kind: NoteKind,
    pub version: u8,
    pub note_id: String,
    pub primary_tag_hex: String,
    pub secondary_tag_hex: String,
    pub issuer_pk_hex: String,
    pub counterparty_pk_hex: String,
    pub fields_pub: Vec<Field>, // labels only — values stay private until disclosed
    pub commitments_hex: Vec<String>,
    pub body_hex: String,
    pub body_hash_hex: String,
    pub signature_hex: String,
}

/// Sign a note body under the issuer's sub-key with deterministic ECDSA.
pub fn sign_note(sk: &BsvScalar, body: &[u8]) -> (Hash, [u8; SIGNATURE_BYTES]) {
    let h = note_hash(body);
    let sig = ecdsa_sign_prehash(sk, &h);
    (h, sig)
}

/// Verify the signature on a note body.
pub fn verify_note(
    pk: &BsvPoint,
    body: &[u8],
    sig: &[u8; SIGNATURE_BYTES],
) -> Result<(), TeaError> {
    let h = note_hash(body);
    ecdsa_verify_prehash(pk, &h, sig)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdh_round_trip_with_subkeys() {
        let sk_a = BsvScalar::from_bytes(&[0x11u8; 32]).unwrap();
        let sk_b = BsvScalar::from_bytes(&[0x22u8; 32]).unwrap();
        let a_sub = derive_subkey(&sk_a, 1).unwrap();
        let b_sub = derive_subkey(&sk_b, 1).unwrap();
        let mat_a = derive_key_material(&a_sub.scalar, &b_sub.point);
        let mat_b = derive_key_material(&b_sub.scalar, &a_sub.point);
        assert_eq!(mat_a.shared_s, mat_b.shared_s);
        assert_eq!(mat_a.k_master, mat_b.k_master);
        assert_eq!(mat_a.l_inv, mat_b.l_inv);
        assert_eq!(mat_a.l_pay, mat_b.l_pay);
    }

    #[test]
    fn commitment_recomputation_matches() {
        let k_master: MasterKey = [0xab; 32];
        let (k_field, c) = commit_one(&k_master, "INV-0001", "Gross", "12100.00");
        let c2 = commit_field(&k_field, "Gross", "12100.00");
        assert_eq!(c, c2);
    }

    #[test]
    fn sign_verify_round_trip() {
        let sk_a = BsvScalar::from_bytes(&[0x11u8; 32]).unwrap();
        let sk_b = BsvScalar::from_bytes(&[0x22u8; 32]).unwrap();
        let a_sub = derive_subkey(&sk_a, 1).unwrap();
        let b_sub = derive_subkey(&sk_b, 1).unwrap();
        let mat = derive_key_material(&a_sub.scalar, &b_sub.point);
        let fields = [
            ("InvID", "INV-0001"),
            ("Curr", "EUR"),
            ("Net", "10000.00"),
            ("Gross", "12100.00"),
            ("Tax", "2100.00"),
            ("Due", "2026-04-30"),
            ("Terms", "NET30"),
            ("MeasPol", "STD-ROUND"),
        ];
        let cs: Vec<FieldCommitment> = fields
            .iter()
            .map(|(l, v)| commit_one(&mat.k_master, "INV-0001", l, v).1)
            .collect();
        let body = build_note_body(&NoteBuilderInputs {
            kind: NoteKind::Invoice,
            version: 1,
            primary_tag: mat.l_inv,
            secondary_tag: [0u8; 32],
            issuer_pk: a_sub.point,
            counterparty_pk: b_sub.point,
            commitments: &cs,
        });
        let (h, sig) = sign_note(&a_sub.scalar, &body);
        assert_eq!(h, double_sha256(&body));
        verify_note(&a_sub.point, &body, &sig).expect("verification succeeds");
        // Tampered body must reject.
        let mut tampered = body.clone();
        tampered[5] ^= 0x01;
        assert!(verify_note(&a_sub.point, &tampered, &sig).is_err());
    }

    #[test]
    fn subkey_derivation_is_deterministic() {
        let sk = BsvScalar::from_bytes(&[0x44u8; 32]).unwrap();
        let s1 = derive_subkey(&sk, 7).unwrap();
        let s2 = derive_subkey(&sk, 7).unwrap();
        assert_eq!(s1.scalar.to_bytes(), s2.scalar.to_bytes());
        assert_eq!(s1.point.to_compressed(), s2.point.to_compressed());
    }
}
