// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Craig Wright

//! BSV double-SHA256 primitive and byte-order helpers.
//!
//! The hash used at every layer of this workspace is `H(x) = SHA256(SHA256(x))`,
//! the standard BSV double-SHA256 primitive. Byte order convention follows BSV:
//! values are stored internally in little-endian and displayed in big-endian
//! (the display orientation auditors expect when reading a block header).

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

use sha2::{Digest, Sha256};

pub const HASH_LEN: usize = 32;

/// 32-byte BSV double-SHA256 digest. Stored in internal (little-endian) order.
pub type Hash = [u8; HASH_LEN];

/// BSV double-SHA256: `SHA256(SHA256(input))`.
pub fn double_sha256(input: &[u8]) -> Hash {
    let first = Sha256::digest(input);
    let second = Sha256::digest(first);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&second);
    out
}

/// Flip a 32-byte hash between internal (LE) and display (BE) orientation.
pub fn flip_hash(h: &Hash) -> Hash {
    let mut out = *h;
    out.reverse();
    out
}

pub mod hash {
    //! Re-export of the canonical hash entry point.
    pub use super::{double_sha256, flip_hash, Hash, HASH_LEN};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn double_sha256_empty_known_vector() {
        // SHA256("") = e3b0...b855
        // SHA256(e3b0...b855) = 5df6...456 (BSV double-SHA256 of empty input)
        let h = double_sha256(b"");
        assert_eq!(
            hex_lower(&h),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
        );
    }

    #[test]
    fn flip_round_trips() {
        let h: Hash = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        assert_eq!(flip_hash(&flip_hash(&h)), h);
    }

    fn hex_lower(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for byte in b {
            s.push_str(&format!("{:02x}", byte));
        }
        s
    }
}
