//! 32-byte SHA-256 identifier used throughout I2P.
//!
//! [`Hash`] is the fundamental identifier in I2P — router hashes, destination
//! hashes, and XOR-based NetDB routing keys are all `Hash` values.
//!
//! Java equivalent: `net.i2p.data.Hash`

use std::fmt;

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::{Error, Result};

/// Length of a `Hash` in bytes.
pub const HASH_LEN: usize = 32;

/// A 32-byte SHA-256 hash used as a router/destination identifier.
///
/// Hashes are compared by their raw bytes. XOR distance is used by the NetDB
/// Kademlia algorithm to determine closeness between two identifiers.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Zeroize)]
pub struct Hash([u8; HASH_LEN]);

impl Hash {
    /// Create a `Hash` from a 32-byte slice.
    ///
    /// Returns [`Error::DataFormat`] when `bytes` is not exactly 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != HASH_LEN {
            return Err(Error::DataFormat(format!(
                "expected {HASH_LEN} bytes for Hash, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; HASH_LEN];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// Compute the SHA-256 hash of `data`.
    pub fn sha256(data: &[u8]) -> Self {
        let digest = Sha256::digest(data);
        let mut arr = [0u8; HASH_LEN];
        arr.copy_from_slice(&digest);
        Self(arr)
    }

    /// Return the raw bytes of this hash.
    pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    /// Compute the XOR distance between `self` and `other`.
    ///
    /// Used by the NetDB Kademlia algorithm; closer means more similar prefix.
    pub fn xor_distance(&self, other: &Hash) -> [u8; HASH_LEN] {
        let mut dist = [0u8; HASH_LEN];
        for i in 0..HASH_LEN {
            dist[i] = self.0[i] ^ other.0[i];
        }
        dist
    }

    /// Return `true` if this hash is closer to `target` than `other` is,
    /// using the XOR metric.
    pub fn is_closer_than(&self, other: &Hash, target: &Hash) -> bool {
        let d_self = self.xor_distance(target);
        let d_other = other.xor_distance(target);
        d_self < d_other
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash(")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Display the first 8 bytes as hex for brevity.
        for b in &self.0[..8] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "…")
    }
}

impl PartialOrd for Hash {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Hash {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_value() {
        // SHA-256 of empty string is a known constant.
        let h = Hash::sha256(b"");
        let expected: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
            0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
            0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(h.as_bytes(), &expected);
    }

    #[test]
    fn xor_distance_self_is_zero() {
        let h = Hash::sha256(b"test");
        assert_eq!(h.xor_distance(&h), [0u8; 32]);
    }

    #[test]
    fn xor_distance_symmetry() {
        let a = Hash::sha256(b"a");
        let b = Hash::sha256(b"b");
        assert_eq!(a.xor_distance(&b), b.xor_distance(&a));
    }

    #[test]
    fn is_closer_than() {
        let target = Hash::sha256(b"target");
        let close = Hash::sha256(b"close");
        let far = Hash::sha256(b"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz");
        // We don't know which is actually closer without running the XOR,
        // but the function should return consistently.
        let result = close.is_closer_than(&far, &target);
        assert_eq!(result, !far.is_closer_than(&close, &target));
    }

    #[test]
    fn from_bytes_rejects_wrong_length() {
        assert!(Hash::from_bytes(&[0u8; 31]).is_err());
        assert!(Hash::from_bytes(&[0u8; 33]).is_err());
    }
}
