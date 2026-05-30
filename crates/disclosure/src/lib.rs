// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Craig Wright

//! Scoped disclosure envelope.
//!
//! The envelope releases **one** field key (`K_field`) to **one** named verifier
//! for a stated engagement and purpose, under an explicit expiry. The recipient
//! checks the issuer's signature, recomputes the field commitment from the
//! released `K_field` and the disclosed value, and matches it against the
//! commitment in the published note body.
//!
//! The signed authorisation binds:
//!
//!   `note_id || field_label || H(K_field) || verifier_id || engagement_id || purpose || u64(expiry) || nonce`
//!
//! Past-expiry envelopes are rejected before signature checking. There is no
//! way to "un-disclose" a value — once `K_field` and the value are released,
//! post-engagement misuse is governed by professional, contractual, and legal
//! controls (this crate enforces only the cryptographic side).

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tee_bsv::Hash;
use tee_bsvcurve::{
    ecdsa_sign_prehash, ecdsa_verify_prehash, BsvPoint, BsvScalar, CurveError, SIGNATURE_BYTES,
};
use tee_tea::{commit_field, FieldCommitment, FieldKey};

#[derive(Debug, thiserror::Error)]
pub enum DisclosureError {
    #[error("curve error: {0}")]
    Curve(#[from] CurveError),
    #[error("envelope has expired")]
    Expired,
    #[error("released key + value do not recompute to the published commitment")]
    CommitmentMismatch,
    #[error("hex decoding failed")]
    BadHex,
}

/// What the issuer signs (canonical byte layout for the prehash).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisclosureClaims {
    pub note_id: String,
    pub field_label: String,
    pub k_field_hash_hex: String,
    pub verifier_id: String,
    pub engagement_id: String,
    pub purpose: String,
    /// UNIX epoch seconds.
    pub expiry_unix: u64,
    pub nonce_hex: String,
}

impl DisclosureClaims {
    /// Canonical byte-encoding for hashing/signing.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let nonce = hex::decode(&self.nonce_hex).unwrap_or_default();
        let k_hash = hex::decode(&self.k_field_hash_hex).unwrap_or_default();
        let mut out = Vec::with_capacity(
            1 + self.note_id.len()
                + 1
                + self.field_label.len()
                + 32
                + 1
                + self.verifier_id.len()
                + 1
                + self.engagement_id.len()
                + 2
                + self.purpose.len()
                + 8
                + 1
                + nonce.len(),
        );
        push_short(&mut out, self.note_id.as_bytes());
        push_short(&mut out, self.field_label.as_bytes());
        out.extend_from_slice(&k_hash);
        push_short(&mut out, self.verifier_id.as_bytes());
        push_short(&mut out, self.engagement_id.as_bytes());
        push_short_u16(&mut out, self.purpose.as_bytes());
        out.extend_from_slice(&self.expiry_unix.to_be_bytes());
        push_short(&mut out, &nonce);
        out
    }

    pub fn prehash(&self) -> Hash {
        let bytes = self.canonical_bytes();
        let mut h = Sha256::new();
        h.update(&bytes);
        let first = h.finalize();
        let mut h2 = Sha256::new();
        h2.update(first);
        let second = h2.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&second);
        out
    }
}

fn push_short(out: &mut Vec<u8>, b: &[u8]) {
    assert!(b.len() <= u8::MAX as usize);
    out.push(b.len() as u8);
    out.extend_from_slice(b);
}

fn push_short_u16(out: &mut Vec<u8>, b: &[u8]) {
    assert!(b.len() <= u16::MAX as usize);
    out.extend_from_slice(&(b.len() as u16).to_be_bytes());
    out.extend_from_slice(b);
}

/// A signed disclosure envelope: claims + signature + the released material.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScopedDisclosure {
    pub claims: DisclosureClaims,
    pub signature_hex: String,
    pub k_field_hex: String,
    pub disclosed_value: String,
    pub issuer_pk_hex: String,
}

/// Issue a disclosure envelope releasing one field key + value.
#[allow(clippy::too_many_arguments)]
pub fn issue_disclosure(
    issuer_sk: &BsvScalar,
    issuer_pk: &BsvPoint,
    note_id: impl Into<String>,
    field_label: impl Into<String>,
    k_field: &FieldKey,
    disclosed_value: impl Into<String>,
    verifier_id: impl Into<String>,
    engagement_id: impl Into<String>,
    purpose: impl Into<String>,
    expiry_unix: u64,
    nonce: &[u8],
) -> Result<ScopedDisclosure, DisclosureError> {
    let k_hash = {
        let mut h = Sha256::new();
        h.update(k_field);
        h.finalize()
    };
    let claims = DisclosureClaims {
        note_id: note_id.into(),
        field_label: field_label.into(),
        k_field_hash_hex: hex::encode(k_hash),
        verifier_id: verifier_id.into(),
        engagement_id: engagement_id.into(),
        purpose: purpose.into(),
        expiry_unix,
        nonce_hex: hex::encode(nonce),
    };
    let prehash = claims.prehash();
    let sig = ecdsa_sign_prehash(issuer_sk, &prehash);
    Ok(ScopedDisclosure {
        claims,
        signature_hex: hex::encode(sig),
        k_field_hex: hex::encode(k_field),
        disclosed_value: disclosed_value.into(),
        issuer_pk_hex: hex::encode(issuer_pk.to_compressed()),
    })
}

/// Verifier-side check.
///
/// Steps, in order:
/// 1. Reject if `now_unix > expiry_unix`.
/// 2. Recompute the claims prehash; verify the signature with the issuer's
///    public sub-key.
/// 3. Recompute the field commitment from the released `K_field` and value.
/// 4. Compare against the published `expected_commitment`. Reject on mismatch.
pub fn verify_disclosure(
    disclosure: &ScopedDisclosure,
    expected_commitment: &FieldCommitment,
    now_unix: u64,
) -> Result<(), DisclosureError> {
    if now_unix > disclosure.claims.expiry_unix {
        return Err(DisclosureError::Expired);
    }
    let pk_bytes = hex::decode(&disclosure.issuer_pk_hex).map_err(|_| DisclosureError::BadHex)?;
    if pk_bytes.len() != 33 {
        return Err(DisclosureError::BadHex);
    }
    let mut compressed = [0u8; 33];
    compressed.copy_from_slice(&pk_bytes);
    let issuer_pk = BsvPoint::from_compressed(&compressed)?;
    let sig_bytes = hex::decode(&disclosure.signature_hex).map_err(|_| DisclosureError::BadHex)?;
    if sig_bytes.len() != SIGNATURE_BYTES {
        return Err(DisclosureError::BadHex);
    }
    let mut sig = [0u8; SIGNATURE_BYTES];
    sig.copy_from_slice(&sig_bytes);
    let prehash = disclosure.claims.prehash();
    ecdsa_verify_prehash(&issuer_pk, &prehash, &sig)?;
    let k_field_bytes =
        hex::decode(&disclosure.k_field_hex).map_err(|_| DisclosureError::BadHex)?;
    if k_field_bytes.len() != 32 {
        return Err(DisclosureError::BadHex);
    }
    let mut k_field = [0u8; 32];
    k_field.copy_from_slice(&k_field_bytes);
    let recomputed = commit_field(
        &k_field,
        &disclosure.claims.field_label,
        &disclosure.disclosed_value,
    );
    if &recomputed != expected_commitment {
        return Err(DisclosureError::CommitmentMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tee_tea::{commit_one, derive_key_material, derive_subkey};

    #[test]
    fn issue_and_verify_round_trip() {
        let sk_a = BsvScalar::from_bytes(&[0x11u8; 32]).unwrap();
        let sk_b = BsvScalar::from_bytes(&[0x22u8; 32]).unwrap();
        let a = derive_subkey(&sk_a, 1).unwrap();
        let b = derive_subkey(&sk_b, 1).unwrap();
        let mat = derive_key_material(&a.scalar, &b.point);
        let (k_field, c_field) = commit_one(&mat.k_master, "INV-0001", "Gross", "12100.00");

        let env = issue_disclosure(
            &a.scalar,
            &a.point,
            "INV-0001",
            "Gross",
            &k_field,
            "12100.00",
            "auditor:acme-cpa",
            "engagement:Q2-2026",
            "audit:revenue-cutoff",
            2_000_000_000,
            &[0xa5; 16],
        )
        .unwrap();

        verify_disclosure(&env, &c_field, 1_900_000_000).expect("verify ok");
    }

    #[test]
    fn expired_envelope_rejected() {
        let sk_a = BsvScalar::from_bytes(&[0x11u8; 32]).unwrap();
        let sk_b = BsvScalar::from_bytes(&[0x22u8; 32]).unwrap();
        let a = derive_subkey(&sk_a, 1).unwrap();
        let b = derive_subkey(&sk_b, 1).unwrap();
        let mat = derive_key_material(&a.scalar, &b.point);
        let (k_field, c_field) = commit_one(&mat.k_master, "INV-0001", "Gross", "12100.00");

        let env = issue_disclosure(
            &a.scalar,
            &a.point,
            "INV-0001",
            "Gross",
            &k_field,
            "12100.00",
            "auditor:acme-cpa",
            "engagement:Q2-2026",
            "audit:revenue-cutoff",
            1_000,
            &[0xa5; 16],
        )
        .unwrap();
        let err = verify_disclosure(&env, &c_field, 9_999_999).unwrap_err();
        assert!(matches!(err, DisclosureError::Expired));
    }

    #[test]
    fn lying_about_value_rejected() {
        let sk_a = BsvScalar::from_bytes(&[0x11u8; 32]).unwrap();
        let sk_b = BsvScalar::from_bytes(&[0x22u8; 32]).unwrap();
        let a = derive_subkey(&sk_a, 1).unwrap();
        let b = derive_subkey(&sk_b, 1).unwrap();
        let mat = derive_key_material(&a.scalar, &b.point);
        let (k_field, c_field) = commit_one(&mat.k_master, "INV-0001", "Gross", "12100.00");

        let mut env = issue_disclosure(
            &a.scalar,
            &a.point,
            "INV-0001",
            "Gross",
            &k_field,
            "12100.00",
            "auditor:acme-cpa",
            "engagement:Q2-2026",
            "audit:revenue-cutoff",
            2_000_000_000,
            &[0xa5; 16],
        )
        .unwrap();
        env.disclosed_value = "99999.99".into();
        let err = verify_disclosure(&env, &c_field, 1).unwrap_err();
        assert!(matches!(err, DisclosureError::CommitmentMismatch));
    }
}
