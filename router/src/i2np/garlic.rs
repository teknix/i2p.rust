//! Garlic message (TYPE=11) — end-to-end encrypted multi-clove container.
//!
//! From the tech-intro:
//! *"Garlic messages are an extension of 'onion' layered encryption, allowing
//! the contents of a single message to contain multiple 'cloves' — fully
//! formed messages alongside their own instructions for delivery."*
//!
//! A [`GarlicMessage`] bundles one or more [`GarlicClove`]s into a single
//! payload that is encrypted to the recipient's public key (using
//! ECIES-X25519-AEAD-Ratchet or legacy ElGamal/AES+SessionTags).
//!
//! This module models the *decrypted* structure; the encryption layer is
//! handled in [`crate::crypto`].
//!
//! Java equivalent: `net.i2p.data.i2np.GarlicMessage`, `GarlicClove`

use crate::error::Result;
use crate::i2np::{I2npHeader, I2npMessage, TYPE_GARLIC};

// ── Delivery instructions ─────────────────────────────────────────────────────

/// How a clove should be delivered after it is decrypted by the recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryInstructions {
    /// Deliver locally to the receiving router.
    Local,
    /// Forward to a remote router identified by its hash.
    Router { hash: crate::data::hash::Hash },
    /// Forward into an inbound tunnel at the specified gateway.
    Tunnel {
        gateway: crate::data::hash::Hash,
        tunnel_id: u32,
    },
}

// ── GarlicClove ───────────────────────────────────────────────────────────────

/// A single message inside a [`GarlicMessage`].
///
/// *"Each of these applications may make their own anonymity, latency, and
/// throughput tradeoffs"* — a clove bundles a message with delivery
/// instructions and an optional delay.
#[derive(Debug, Clone)]
pub struct GarlicClove {
    /// Where this clove should be sent after decryption.
    pub delivery: DeliveryInstructions,
    /// Unique clove identifier (used for deduplication).
    pub clove_id: u32,
    /// Absolute expiry timestamp in milliseconds since epoch.
    pub expiration: u64,
    /// Raw I2NP message payload of this clove.
    pub message: Vec<u8>,
}

impl GarlicClove {
    /// Create a new clove.
    pub fn new(
        delivery: DeliveryInstructions,
        clove_id: u32,
        expiration: u64,
        message: Vec<u8>,
    ) -> Self {
        Self {
            delivery,
            clove_id,
            expiration,
            message,
        }
    }

    /// Return `true` if this clove has expired.
    pub fn is_expired(&self, now_ms: u64) -> bool {
        self.expiration < now_ms
    }
}

// ── GarlicMessage ─────────────────────────────────────────────────────────────

/// An end-to-end encrypted container carrying one or more [`GarlicClove`]s.
///
/// The raw `encrypted_payload` field holds the ciphertext as it arrives off
/// the wire.  The `cloves` field holds the decrypted cloves once the
/// encryption layer has unwrapped the message.
#[derive(Debug, Clone)]
pub struct GarlicMessage {
    pub(crate) header: I2npHeader,
    /// Raw encrypted payload (before decryption by the crypto layer).
    pub encrypted_payload: Vec<u8>,
    /// Decrypted cloves — populated by the crypto layer after decryption.
    pub cloves: Vec<GarlicClove>,
}

impl GarlicMessage {
    /// Create a [`GarlicMessage`] from raw ciphertext.
    pub fn from_encrypted(header: I2npHeader, encrypted_payload: Vec<u8>) -> Self {
        Self {
            header,
            encrypted_payload,
            cloves: Vec::new(),
        }
    }

    /// Create a [`GarlicMessage`] from already-decrypted cloves (for
    /// constructing outbound messages before encryption).
    pub fn from_cloves(header: I2npHeader, cloves: Vec<GarlicClove>) -> Self {
        Self {
            header,
            encrypted_payload: Vec::new(),
            cloves,
        }
    }
}

impl I2npMessage for GarlicMessage {
    fn msg_type(&self) -> u8 {
        TYPE_GARLIC
    }

    fn header(&self) -> &I2npHeader {
        &self.header
    }

    fn write_payload(&self, buf: &mut Vec<u8>) -> Result<usize> {
        let start = buf.len();
        // On the wire a garlic is always the encrypted form.
        let len = self.encrypted_payload.len() as u32;
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&self.encrypted_payload);
        Ok(buf.len() - start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::hash::Hash;

    fn header() -> I2npHeader {
        I2npHeader::new(TYPE_GARLIC, 5, u64::MAX)
    }

    #[test]
    fn clove_expiry() {
        let clove = GarlicClove::new(
            DeliveryInstructions::Local,
            1,
            1_000,
            vec![],
        );
        assert!(clove.is_expired(2_000));
        assert!(!clove.is_expired(500));
    }

    #[test]
    fn write_payload_length_prefix() {
        let payload = vec![0xAAu8; 50];
        let msg = GarlicMessage::from_encrypted(header(), payload);
        let mut buf = Vec::new();
        msg.write_payload(&mut buf).unwrap();
        // 4-byte length prefix + 50 bytes payload
        assert_eq!(buf.len(), 54);
        let len = u32::from_be_bytes(buf[..4].try_into().unwrap());
        assert_eq!(len, 50);
    }

    #[test]
    fn tunnel_delivery() {
        let gw = Hash::sha256(b"gw");
        let clove = GarlicClove::new(
            DeliveryInstructions::Tunnel { gateway: gw, tunnel_id: 999 },
            2,
            u64::MAX,
            vec![],
        );
        assert!(matches!(clove.delivery, DeliveryInstructions::Tunnel { .. }));
    }
}
