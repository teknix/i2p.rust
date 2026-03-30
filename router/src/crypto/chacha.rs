//! ChaCha20-Poly1305 AEAD — used for ECIES-X25519-AEAD-Ratchet and transports.
//!
//! From the tech-intro:
//! *"ChaCha20/Poly1305 is used for authenticated symmetric encryption."*
//! Used in NTCP2, SSU2, and the ECIES-Ratchet garlic layer.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// ChaCha20-Poly1305 key length in bytes.
pub const KEY_LEN: usize = 32;
/// ChaCha20-Poly1305 nonce length in bytes.
pub const NONCE_LEN: usize = 12;
/// ChaCha20-Poly1305 authentication tag length in bytes.
pub const TAG_LEN: usize = 16;

/// Encrypt and authenticate `plaintext` returning `ciphertext || tag`.
///
/// `aad` is additional authenticated data (authenticated but not encrypted).
pub fn encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| Error::Crypto(e.to_string()))
}

/// Decrypt and verify `ciphertext` (which must include the trailing 16-byte tag).
///
/// Returns the plaintext on success or [`Error::Crypto`] if authentication fails.
pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Crypto("ChaCha20-Poly1305 decryption failed (bad tag)".into()))
}

/// Generate a random ChaCha20-Poly1305 key.
pub fn generate_key() -> Zeroizing<[u8; KEY_LEN]> {
    use rand_core::{OsRng, RngCore};
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    OsRng.fill_bytes(key.as_mut());
    key
}

/// Produce a 12-byte nonce from a 64-bit counter (zero-padded to 12 bytes).
///
/// This matches the counter-based nonce construction used in NTCP2 and SSU2.
pub fn nonce_from_counter(counter: u64) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[4..].copy_from_slice(&counter.to_be_bytes());
    n
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = [0x11u8; KEY_LEN];
        let nonce = [0x22u8; NONCE_LEN];
        let aad = b"additional data";
        let plaintext = b"hello I2P router";

        let ct = encrypt(&key, &nonce, aad, plaintext).unwrap();
        assert_ne!(ct.as_slice(), plaintext.as_slice());
        assert_eq!(ct.len(), plaintext.len() + TAG_LEN);

        let pt = decrypt(&key, &nonce, aad, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn wrong_key_fails_authentication() {
        let key = [0x11u8; KEY_LEN];
        let nonce = [0u8; NONCE_LEN];
        let ct = encrypt(&key, &nonce, b"", b"data").unwrap();

        let bad_key = [0xFFu8; KEY_LEN];
        assert!(decrypt(&bad_key, &nonce, b"", &ct).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = [0x33u8; KEY_LEN];
        let nonce = [0u8; NONCE_LEN];
        let mut ct = encrypt(&key, &nonce, b"", b"message").unwrap();
        ct[0] ^= 0xFF; // flip bits
        assert!(decrypt(&key, &nonce, b"", &ct).is_err());
    }

    #[test]
    fn nonce_from_counter_structure() {
        let n = nonce_from_counter(1);
        assert_eq!(&n[..4], &[0u8; 4]);
        assert_eq!(u64::from_be_bytes(n[4..].try_into().unwrap()), 1);
    }
}
