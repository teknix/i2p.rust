//! Ed25519 signing — used for RouterInfo and LeaseSet signatures.
//!
//! From the tech-intro:
//! *"EdDSA signatures … All of this information is signed by the publishing
//! party and verified by any I2P router using or storing the information."*
//!
//! RouterInfo and LeaseSet records must be signed by the owner's Ed25519
//! signing key, and every router verifies those signatures before accepting
//! entries into its NetDB.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;

use crate::error::{Error, Result};

/// Ed25519 signing key length in bytes.
pub const SIGNING_KEY_LEN: usize = 32;
/// Ed25519 verifying (public) key length in bytes.
pub const VERIFYING_KEY_LEN: usize = 32;
/// Ed25519 signature length in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// An Ed25519 signing key pair.
///
/// `SigningKey` implements `Zeroize` via `ed25519-dalek`'s built-in support,
/// ensuring the private key bytes are wiped from memory on drop.
pub struct Ed25519Keypair {
    signing: SigningKey,
    /// The verifying (public) key.
    pub verifying: VerifyingKey,
}

impl Ed25519Keypair {
    /// Generate a new random key pair.
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        Self {
            signing,
            verifying,
        }
    }

    /// Return the raw 32-byte verifying (public) key bytes.
    pub fn verifying_bytes(&self) -> [u8; VERIFYING_KEY_LEN] {
        self.verifying.to_bytes()
    }

    /// Sign `message` and return the 64-byte signature.
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.signing.sign(message).to_bytes()
    }
}

/// Verify an Ed25519 `signature` over `message` using `public_key_bytes`.
///
/// Returns `Ok(())` on success or [`Error::InvalidSignature`] on failure.
pub fn verify(
    public_key_bytes: &[u8; VERIFYING_KEY_LEN],
    message: &[u8],
    signature_bytes: &[u8; SIGNATURE_LEN],
) -> Result<()> {
    let vk = VerifyingKey::from_bytes(public_key_bytes)
        .map_err(|e| Error::Crypto(format!("invalid Ed25519 public key: {e}")))?;
    let sig = Signature::from_bytes(signature_bytes);
    vk.verify(message, &sig)
        .map_err(|_| Error::InvalidSignature("Ed25519 signature verification failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let kp = Ed25519Keypair::generate();
        let msg = b"RouterInfo payload";
        let sig = kp.sign(msg);
        assert!(verify(&kp.verifying_bytes(), msg, &sig).is_ok());
    }

    #[test]
    fn wrong_message_fails() {
        let kp = Ed25519Keypair::generate();
        let sig = kp.sign(b"correct");
        assert!(verify(&kp.verifying_bytes(), b"wrong", &sig).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let kp1 = Ed25519Keypair::generate();
        let kp2 = Ed25519Keypair::generate();
        let sig = kp1.sign(b"message");
        assert!(verify(&kp2.verifying_bytes(), b"message", &sig).is_err());
    }
}
