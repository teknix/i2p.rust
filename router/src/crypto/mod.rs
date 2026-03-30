//! Cryptographic primitives used by the I2P router.
//!
//! From the tech-intro (2025-01, accurate for 0.9.65):
//! *"The current primitives used in most protocol layers are X25519 key
//! exchange, EdDSA signatures, ChaCha20/Poly1305 authenticated symmetric
//! encryption, and SHA-256 hashes. AES256 is still used for tunnel layer
//! encryption."*
//!
//! This module re-exports the key crypto utilities needed across the router:
//! - [`sha256`] — SHA-256 hashing
//! - [`aes256`] — AES-256/CBC used for tunnel layer encryption
//! - [`chacha`] — ChaCha20-Poly1305 used for ECIES-Ratchet and transports
//! - [`x25519`] — X25519 key exchange used for session key establishment
//! - [`ed25519`] — Ed25519 signing used for RouterInfo / LeaseSet signatures

pub mod aes256;
pub mod chacha;
pub mod ed25519;
pub mod x25519;

// Re-export SHA-256 hash function through the data module's `Hash::sha256`.
// Users should call `Hash::sha256(data)` rather than using `sha2` directly.
