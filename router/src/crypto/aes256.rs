//! AES-256/CBC encryption — used for tunnel layer encryption.
//!
//! From the tech-intro:
//! *"AES256 is still used for tunnel layer encryption."*
//!
//! Each intermediate tunnel hop applies one AES-256/CBC encrypt pass (with
//! IV derived from the message content) to the 1028-byte tunnel data payload.
//! The gateway pre-applies decryptions so that after all hops have added their
//! layers, the endpoint sees plaintext.

use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// AES-256 key length in bytes.
pub const KEY_LEN: usize = 32;
/// AES-256 block / IV length in bytes.
pub const BLOCK_LEN: usize = 16;

/// Encrypt `data` in-place using AES-256/CBC with the given key and IV.
///
/// `data` must be a multiple of 16 bytes (the AES block size).
/// For tunnel layer encryption this is the 1024-byte data portion of a
/// [`TunnelDataMessage`](crate::i2np::tunnel_data::TunnelDataMessage)
/// (the 4-byte tunnel ID header is excluded from AES processing).
pub fn encrypt_in_place(key: &[u8; KEY_LEN], iv: &[u8; BLOCK_LEN], data: &mut [u8]) -> Result<()> {
    if data.len() % BLOCK_LEN != 0 {
        return Err(Error::Crypto(format!(
            "AES-256/CBC: data length {} is not a multiple of block size {}",
            data.len(),
            BLOCK_LEN
        )));
    }
    let enc = Aes256CbcEnc::new(key.into(), iv.into());
    enc.encrypt_padded_mut::<NoPadding>(data, data.len())
        .map_err(|e| Error::Crypto(e.to_string()))?;
    Ok(())
}

/// Decrypt `data` in-place using AES-256/CBC with the given key and IV.
pub fn decrypt_in_place(key: &[u8; KEY_LEN], iv: &[u8; BLOCK_LEN], data: &mut [u8]) -> Result<()> {
    if data.len() % BLOCK_LEN != 0 {
        return Err(Error::Crypto(format!(
            "AES-256/CBC: data length {} is not a multiple of block size {}",
            data.len(),
            BLOCK_LEN
        )));
    }
    Aes256CbcDec::new(key.into(), iv.into())
        .decrypt_padded_mut::<NoPadding>(data)
        .map_err(|e| Error::Crypto(e.to_string()))?;
    Ok(())
}

/// Generate a random AES-256 key.
pub fn generate_key() -> Zeroizing<[u8; KEY_LEN]> {
    use rand_core::{OsRng, RngCore};
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    OsRng.fill_bytes(key.as_mut());
    key
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = [0x42u8; KEY_LEN];
        let iv = [0x24u8; BLOCK_LEN];
        // AES layer encrypts the 1024-byte data portion of a TunnelDataMessage
        // (the 4-byte tunnel_id header is excluded). 1024 = 64 × 16.
        let plaintext = [0xABu8; 1024];

        let mut data = plaintext;
        encrypt_in_place(&key, &iv, &mut data).unwrap();
        assert_ne!(data, plaintext, "encryption should change data");

        decrypt_in_place(&key, &iv, &mut data).unwrap();
        assert_eq!(data, plaintext, "decryption should restore plaintext");
    }

    #[test]
    fn non_multiple_of_block_size_is_error() {
        let key = [0u8; KEY_LEN];
        let iv = [0u8; BLOCK_LEN];
        let mut data = [0u8; 100]; // not a multiple of 16
        assert!(encrypt_in_place(&key, &iv, &mut data).is_err());
    }
}
