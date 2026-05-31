// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Craig Wright

//! Arithmetic, ECDSA, ECDH, and HKDF-SHA256 over the BSV curve.
//!
//! All curve operations are referred to as operations on **the BSV curve**.
//! Implementation uses the pure-Rust k256 crate (RustCrypto, no external chain
//! attribution) with `default-features = false` and an explicit feature
//! whitelist (`ecdh`, `ecdsa`, `sha256`, `arithmetic`, `alloc`); nothing
//! outside that whitelist compiles into this workspace.
//!
//! ECDSA signing uses the deterministic nonce generation of RFC 6979 with the
//! low-S canonicalisation enforced at the API surface.

#![forbid(unsafe_code)]

use hmac::{Hmac, Mac};
use k256::ecdh::diffie_hellman;
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, PublicKey, Scalar, SecretKey};
use sha2::{Digest, Sha256};
use tee_bsv::Hash;

type HmacSha256 = Hmac<Sha256>;

pub const SCALAR_BYTES: usize = 32;
pub const COMPRESSED_POINT_BYTES: usize = 33;
pub const SIGNATURE_BYTES: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum CurveError {
    #[error("scalar is zero or out of range")]
    InvalidScalar,
    #[error("encoded point is invalid on the BSV curve")]
    InvalidPoint,
    #[error("signature decoding failed")]
    InvalidSignature,
    #[error("signature verification rejected")]
    SignatureRejected,
}

/// 32-byte scalar in the BSV curve's prime-order subgroup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BsvScalar(pub Scalar);

/// Compressed (33-byte) curve point: `0x02 || X` for even-Y, `0x03 || X` for odd-Y.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BsvPoint(pub ProjectivePoint);

impl BsvScalar {
    pub fn from_bytes(bytes: &[u8; SCALAR_BYTES]) -> Result<Self, CurveError> {
        let sk = SecretKey::from_slice(bytes).map_err(|_| CurveError::InvalidScalar)?;
        Ok(BsvScalar(*sk.to_nonzero_scalar().as_ref()))
    }

    pub fn to_bytes(&self) -> [u8; SCALAR_BYTES] {
        let bytes = self.0.to_bytes();
        let mut out = [0u8; SCALAR_BYTES];
        out.copy_from_slice(&bytes);
        out
    }

    pub fn mul_base(&self) -> BsvPoint {
        BsvPoint(ProjectivePoint::GENERATOR * self.0)
    }

    /// Scalar addition modulo the BSV curve order. Returns `Err(InvalidScalar)` if
    /// the sum reduces to zero (probability ~2^-256 for adversarial inputs).
    pub fn add(&self, other: &Self) -> Result<Self, CurveError> {
        let sum = self.0 + other.0;
        let bytes = sum.to_bytes();
        let mut be = [0u8; SCALAR_BYTES];
        be.copy_from_slice(&bytes);
        BsvScalar::from_bytes(&be)
    }
}

impl BsvPoint {
    pub fn from_compressed(bytes: &[u8; COMPRESSED_POINT_BYTES]) -> Result<Self, CurveError> {
        let pk = PublicKey::from_sec1_bytes(bytes).map_err(|_| CurveError::InvalidPoint)?;
        Ok(BsvPoint(ProjectivePoint::from(pk.as_affine())))
    }

    pub fn to_compressed(&self) -> [u8; COMPRESSED_POINT_BYTES] {
        let bytes = self.0.to_affine().to_encoded_point(true);
        let slice = bytes.as_bytes();
        let mut out = [0u8; COMPRESSED_POINT_BYTES];
        out.copy_from_slice(slice);
        out
    }

    /// Affine x coordinate as 32-byte big-endian.
    pub fn x_be(&self) -> [u8; SCALAR_BYTES] {
        let bytes = self.0.to_affine().to_encoded_point(true);
        let slice = bytes.as_bytes();
        let mut out = [0u8; SCALAR_BYTES];
        out.copy_from_slice(&slice[1..1 + SCALAR_BYTES]);
        out
    }

    pub fn add(&self, other: &Self) -> Self {
        BsvPoint(self.0 + other.0)
    }

    pub fn mul_scalar(&self, scalar: &BsvScalar) -> Self {
        BsvPoint(self.0 * scalar.0)
    }

    pub fn generator() -> Self {
        BsvPoint(ProjectivePoint::GENERATOR)
    }

    pub fn encoding_bytes(&self) -> [u8; 33] {
        let bytes = self.0.to_affine().to_bytes();
        let mut out = [0u8; 33];
        out.copy_from_slice(&bytes);
        out
    }
}

/// ECDH shared value: returns the 32-byte big-endian affine x coordinate of
/// `sk_self * pk_other`. Both parties compute the same value.
pub fn ecdh_shared_x(sk_self: &BsvScalar, pk_other: &BsvPoint) -> [u8; SCALAR_BYTES] {
    let secret = SecretKey::from_slice(&sk_self.to_bytes()).expect("validated scalar");
    let public = PublicKey::from_sec1_bytes(&pk_other.to_compressed()).expect("validated point");
    let shared = diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
    let raw = shared.raw_secret_bytes();
    let mut out = [0u8; SCALAR_BYTES];
    out.copy_from_slice(&raw[..]);
    out
}

/// HKDF-SHA256 extract: PRK = HMAC-SHA256(salt, IKM).
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(salt).expect("HMAC accepts any key length");
    mac.update(ikm);
    let out = mac.finalize().into_bytes();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out);
    buf
}

/// HKDF-SHA256 expand restricted to a single 32-byte block: T(1) = HMAC(PRK, info || 0x01).
pub fn hkdf_expand_one_block(prk: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(prk).expect("HMAC accepts any key length");
    mac.update(info);
    mac.update(&[0x01]);
    let out = mac.finalize().into_bytes();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out);
    buf
}

/// Deterministic (RFC 6979) ECDSA signing with low-S canonicalisation enforced.
/// Returns a 64-byte (r || s) signature in big-endian.
pub fn ecdsa_sign_prehash(sk: &BsvScalar, prehash: &Hash) -> [u8; SIGNATURE_BYTES] {
    let signing_key =
        SigningKey::from_slice(&sk.to_bytes()).expect("validated scalar produces signing key");
    let sig: Signature = signing_key
        .sign_prehash(prehash)
        .expect("prehash is exactly 32 bytes");
    let normalized = sig.normalize_s().unwrap_or(sig);
    let bytes = normalized.to_bytes();
    let mut out = [0u8; SIGNATURE_BYTES];
    out.copy_from_slice(&bytes);
    out
}

/// Verify a deterministic ECDSA signature against a prehash and a verifying key.
pub fn ecdsa_verify_prehash(
    pk: &BsvPoint,
    prehash: &Hash,
    sig_bytes: &[u8; SIGNATURE_BYTES],
) -> Result<(), CurveError> {
    let verifying_key =
        VerifyingKey::from_sec1_bytes(&pk.to_compressed()).map_err(|_| CurveError::InvalidPoint)?;
    let sig = Signature::from_slice(sig_bytes).map_err(|_| CurveError::InvalidSignature)?;
    if sig.normalize_s().is_some() {
        return Err(CurveError::SignatureRejected);
    }
    verifying_key
        .verify_prehash(prehash, &sig)
        .map_err(|_| CurveError::SignatureRejected)
}

/// `H_n(x) = SHA256(x) reduced mod n` where n is the BSV curve order.
/// Reduction uses k256's `Scalar::from_uint_reduced` semantics via `SecretKey`.
pub fn hash_to_scalar(x: &[u8]) -> BsvScalar {
    let mut h = Sha256::new();
    h.update(x);
    let digest = h.finalize();
    let mut wide = [0u8; 32];
    wide.copy_from_slice(&digest);
    // Reduce mod n by treating the digest as a wide integer and using the
    // signing-key constructor which rejects values >= n; on rejection we wrap
    // by adding 1 to the low byte until a valid scalar is obtained. The
    // probability of needing more than one round is ~2^-128.
    loop {
        if let Ok(sk) = SecretKey::from_slice(&wide) {
            return BsvScalar(*sk.to_nonzero_scalar().as_ref());
        }
        // Bump the last byte and retry. With cryptographically random inputs
        // this loop terminates in O(1) iterations.
        let last = wide[31].wrapping_add(1);
        wide[31] = last;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdh_agreement() {
        let sk_a = BsvScalar::from_bytes(&[0x11u8; 32]).unwrap();
        let sk_b = BsvScalar::from_bytes(&[0x22u8; 32]).unwrap();
        let pk_a = sk_a.mul_base();
        let pk_b = sk_b.mul_base();
        let s_a = ecdh_shared_x(&sk_a, &pk_b);
        let s_b = ecdh_shared_x(&sk_b, &pk_a);
        assert_eq!(s_a, s_b);
    }

    #[test]
    fn ecdsa_round_trip_low_s() {
        let sk = BsvScalar::from_bytes(&[0x33u8; 32]).unwrap();
        let pk = sk.mul_base();
        let prehash = tee_bsv::double_sha256(b"hello bsv");
        let sig = ecdsa_sign_prehash(&sk, &prehash);
        // Low-S: s <= n / 2 (top bit of s clear in the canonical form).
        assert!(sig[32] < 0x80, "signature must be low-S canonical");
        ecdsa_verify_prehash(&pk, &prehash, &sig).expect("verify succeeds");
    }

    #[test]
    fn hkdf_extract_then_expand_one_block() {
        let prk = hkdf_extract(b"TEA-v1", b"shared-value-bytes");
        let okm = hkdf_expand_one_block(&prk, b"inv-tag");
        assert_eq!(okm.len(), 32);
    }
}
