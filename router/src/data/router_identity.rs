//! Router identity — the public-key identity of an I2P router.
//!
//! A [`RouterIdentity`] consists of:
//! - An ElGamal-2048 or X25519 **encryption public key** (256 bytes legacy /
//!   32 bytes ECIES)
//! - An **signing public key** (DSA-SHA1 128 bytes / EdDSA-25519 32 bytes /
//!   ECDSA-256 64 bytes / …)
//! - A **certificate** that records the key types
//!
//! The SHA-256 hash of the serialised identity bytes is the router's [`Hash`],
//! its unique identifier in the NetDB.
//!
//! Java equivalent: `net.i2p.data.router.RouterIdentity`

use sha2::{Digest, Sha256};

use crate::data::hash::Hash;
use crate::error::{Error, Result};

// ── Key-type codes (subset of I2P spec) ──────────────────────────────────────

/// Encryption type: legacy 2048-bit ElGamal.
pub const CRYPTO_TYPE_ELGAMAL: u16 = 0;
/// Encryption type: ECIES-X25519 (modern, used for ECIES-Ratchet).
pub const CRYPTO_TYPE_X25519: u16 = 4;

/// Signature type: DSA-SHA1 (legacy).
pub const SIG_TYPE_DSA_SHA1: u16 = 0;
/// Signature type: EdDSA-SHA512-Ed25519 (current default).
pub const SIG_TYPE_EDDSA_SHA512_ED25519: u16 = 7;

// ── Key lengths ───────────────────────────────────────────────────────────────

/// Byte length of an ElGamal-2048 public key.
pub const ELGAMAL_PUB_KEY_LEN: usize = 256;
/// Byte length of an X25519 public key.
pub const X25519_PUB_KEY_LEN: usize = 32;
/// Byte length of a DSA-SHA1 signing public key.
pub const DSA_PUB_KEY_LEN: usize = 128;
/// Byte length of an Ed25519 signing public key.
pub const ED25519_PUB_KEY_LEN: usize = 32;

/// The public-key identity of an I2P router.
///
/// The router's [`Hash`] is derived from the SHA-256 of the canonical wire
/// encoding, and is cached after the first computation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterIdentity {
    /// Raw encryption public key bytes.
    pub encryption_key: Vec<u8>,
    /// Numeric encryption key type (see `CRYPTO_TYPE_*` constants).
    pub crypto_type: u16,
    /// Raw signing public key bytes.
    pub signing_key: Vec<u8>,
    /// Numeric signature type (see `SIG_TYPE_*` constants).
    pub sig_type: u16,
    /// Raw certificate bytes (may be empty for `NULL` certificate).
    pub certificate: Vec<u8>,
}

impl RouterIdentity {
    /// Construct an [`RouterIdentity`] from its raw component parts.
    ///
    /// This does **not** validate key lengths; call [`validate`](Self::validate)
    /// separately if needed.
    pub fn new(
        encryption_key: Vec<u8>,
        crypto_type: u16,
        signing_key: Vec<u8>,
        sig_type: u16,
        certificate: Vec<u8>,
    ) -> Self {
        Self {
            encryption_key,
            crypto_type,
            signing_key,
            sig_type,
            certificate,
        }
    }

    /// Validate key lengths against the declared type codes.
    ///
    /// Returns [`Error::DataFormat`] when a key has an unexpected length.
    pub fn validate(&self) -> Result<()> {
        let expected_enc_len = match self.crypto_type {
            CRYPTO_TYPE_ELGAMAL => ELGAMAL_PUB_KEY_LEN,
            CRYPTO_TYPE_X25519 => X25519_PUB_KEY_LEN,
            t => {
                return Err(Error::DataFormat(format!(
                    "unknown crypto type {t}"
                )))
            }
        };
        if self.encryption_key.len() != expected_enc_len {
            return Err(Error::DataFormat(format!(
                "encryption key: expected {expected_enc_len} bytes, got {}",
                self.encryption_key.len()
            )));
        }

        let expected_sig_len = match self.sig_type {
            SIG_TYPE_DSA_SHA1 => DSA_PUB_KEY_LEN,
            SIG_TYPE_EDDSA_SHA512_ED25519 => ED25519_PUB_KEY_LEN,
            t => {
                return Err(Error::DataFormat(format!(
                    "unknown sig type {t}"
                )))
            }
        };
        if self.signing_key.len() != expected_sig_len {
            return Err(Error::DataFormat(format!(
                "signing key: expected {expected_sig_len} bytes, got {}",
                self.signing_key.len()
            )));
        }

        Ok(())
    }

    /// Compute the router's [`Hash`] (SHA-256 of the canonical identity bytes).
    ///
    /// The canonical form is: `encryption_key || signing_key || certificate`.
    pub fn hash(&self) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(&self.encryption_key);
        hasher.update(&self.signing_key);
        hasher.update(&self.certificate);
        let digest = hasher.finalize();
        Hash::from_bytes(&digest).expect("SHA-256 always produces 32 bytes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ed25519_identity() -> RouterIdentity {
        RouterIdentity::new(
            vec![0u8; X25519_PUB_KEY_LEN],
            CRYPTO_TYPE_X25519,
            vec![1u8; ED25519_PUB_KEY_LEN],
            SIG_TYPE_EDDSA_SHA512_ED25519,
            vec![],
        )
    }

    #[test]
    fn validate_ok() {
        assert!(make_ed25519_identity().validate().is_ok());
    }

    #[test]
    fn validate_wrong_enc_key_len() {
        let mut id = make_ed25519_identity();
        id.encryption_key = vec![0u8; 10]; // wrong length
        assert!(id.validate().is_err());
    }

    #[test]
    fn hash_is_deterministic() {
        let id = make_ed25519_identity();
        assert_eq!(id.hash(), id.hash());
    }

    #[test]
    fn different_keys_different_hashes() {
        let id1 = make_ed25519_identity();
        let mut id2 = make_ed25519_identity();
        id2.signing_key = vec![2u8; ED25519_PUB_KEY_LEN];
        assert_ne!(id1.hash(), id2.hash());
    }
}
