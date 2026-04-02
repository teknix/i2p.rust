//! Tunnel build record construction — ECIES-X25519 per-hop encryption.

#![allow(dead_code)]

use hkdf::Hkdf;
use sha2::Sha256;

use crate::crypto::{chacha, x25519};
use crate::error::{Error, Result};
use crate::i2np::tunnel_build::{BuildRecord, TunnelBuildMessage, BUILD_RECORD_SIZE};
use crate::i2np::{I2npHeader, TYPE_VARIABLE_TUNNEL_BUILD};
use crate::tunnel::HopConfig;

/// Role flag: this hop is the tunnel gateway.
pub const FLAG_GATEWAY: u8 = 0x00;
/// Role flag: this hop is an intermediate participant.
pub const FLAG_PARTICIPANT: u8 = 0x01;
/// Role flag: this hop is the tunnel endpoint.
pub const FLAG_ENDPOINT: u8 = 0x02;

/// Plaintext record payload size before AEAD (222 bytes).
const PLAINTEXT_LEN: usize = 222;
/// AEAD tag appended by ChaCha20-Poly1305 (16 bytes).
const AEAD_TAG_LEN: usize = 16;
/// Ciphertext size = plaintext + tag.
const CIPHERTEXT_LEN: usize = PLAINTEXT_LEN + AEAD_TAG_LEN; // 238
/// Ephemeral public key prepended to the record.
const EPHEMERAL_PUB_LEN: usize = 32;
/// Trailing zero padding to reach BUILD_RECORD_SIZE (528).
const PADDING_LEN: usize = BUILD_RECORD_SIZE - EPHEMERAL_PUB_LEN - CIPHERTEXT_LEN; // 258

/// HKDF info string for tunnel build records.
const HKDF_INFO: &[u8] = b"BuildRequestRecord";

/// Create a single 528-byte ECIES-X25519-encrypted build record.
///
/// # Arguments
/// * `hop` — per-hop tunnel parameters
/// * `hop_x25519_public_key` — the hop router's X25519 static public key
/// * `flag` — [`FLAG_GATEWAY`], [`FLAG_PARTICIPANT`], or [`FLAG_ENDPOINT`]
/// * `request_time_hours` — hours since Unix epoch (for replay protection)
/// * `send_message_id` — message ID for this build request
pub fn build_request_record(
    hop: &HopConfig,
    hop_x25519_public_key: &[u8; 32],
    flag: u8,
    request_time_hours: u32,
    send_message_id: u32,
) -> Result<BuildRecord> {
    // Step 1: generate ephemeral X25519 keypair.
    let (ephemeral_pub, shared_secret) = x25519::ephemeral_dh(hop_x25519_public_key);

    // Step 2: HKDF to derive ChaCha20-Poly1305 key.
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(&ephemeral_pub);
    salt.extend_from_slice(hop_x25519_public_key);

    let hk = Hkdf::<Sha256>::new(Some(&salt), &*shared_secret);
    let mut key_material = [0u8; 32];
    hk.expand(HKDF_INFO, &mut key_material)
        .map_err(|_| Error::Crypto("HKDF expand failed".into()))?;

    // Step 3: build 222-byte plaintext record.
    let plaintext = build_plaintext(hop, flag, request_time_hours, send_message_id);
    debug_assert_eq!(plaintext.len(), PLAINTEXT_LEN);

    // Step 4: encrypt with ChaCha20-Poly1305 (nonce = 0).
    // Zero nonce is safe here because the HKDF key is derived from a
    // freshly-generated ephemeral DH keypair that is never reused.
    let nonce = [0u8; chacha::NONCE_LEN];
    let ciphertext = chacha::encrypt(&key_material, &nonce, &[], &plaintext)?;
    debug_assert_eq!(ciphertext.len(), CIPHERTEXT_LEN);

    // Step 5: assemble 528-byte record.
    let mut record = Vec::with_capacity(BUILD_RECORD_SIZE);
    record.extend_from_slice(&ephemeral_pub);
    record.extend_from_slice(&ciphertext);
    record.extend_from_slice(&[0u8; PADDING_LEN]);
    debug_assert_eq!(record.len(), BUILD_RECORD_SIZE);

    Ok(BuildRecord::new(record))
}

/// Build the 222-byte plaintext content of a hop record.
fn build_plaintext(
    hop: &HopConfig,
    flag: u8,
    request_time_hours: u32,
    send_message_id: u32,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(PLAINTEXT_LEN);

    // receive_tunnel_id: 4 bytes
    buf.extend_from_slice(&hop.receive_tunnel_id.to_be_bytes());
    // send_tunnel_id: 4 bytes (0 if endpoint)
    let send_id = hop.send_tunnel_id.unwrap_or(0);
    buf.extend_from_slice(&send_id.to_be_bytes());
    // next_router_hash: 32 bytes (zeros if endpoint)
    match &hop.next_router {
        Some(h) => buf.extend_from_slice(h.as_bytes()),
        None => buf.extend_from_slice(&[0u8; 32]),
    }
    // layer_key: 32 bytes
    buf.extend_from_slice(&hop.layer_key);
    // iv_key: 32 bytes
    buf.extend_from_slice(&hop.iv_key);
    // reply_key: 32 bytes (zeroed for now)
    buf.extend_from_slice(&[0u8; 32]);
    // reply_iv: 16 bytes (zeroed for now)
    buf.extend_from_slice(&[0u8; 16]);
    // flag: 1 byte
    buf.push(flag);
    // request_time: 4 bytes
    buf.extend_from_slice(&request_time_hours.to_be_bytes());
    // send_message_id: 4 bytes
    buf.extend_from_slice(&send_message_id.to_be_bytes());

    // Current size: 4+4+32+32+32+32+16+1+4+4 = 161 bytes
    // Pad to PLAINTEXT_LEN (222):
    let padding = PLAINTEXT_LEN - buf.len();
    buf.extend_from_slice(&vec![0u8; padding]);

    buf
}

/// Constructs complete tunnel build messages.
pub struct TunnelBuilder;

impl TunnelBuilder {
    /// Create a complete [`TunnelBuildMessage`] for the given hops.
    ///
    /// `hop_public_keys` must have the same length as `hops`.
    pub fn build_tunnel_message(
        hops: &[HopConfig],
        hop_public_keys: &[[u8; 32]],
        now_ms: u64,
    ) -> Result<TunnelBuildMessage> {
        if hops.len() != hop_public_keys.len() {
            return Err(Error::DataFormat(
                "hops and hop_public_keys must have the same length".into(),
            ));
        }

        let request_time_hours = (now_ms / 1000 / 3600) as u32;
        let mut records = Vec::with_capacity(hops.len());

        for (i, (hop, pubkey)) in hops.iter().zip(hop_public_keys.iter()).enumerate() {
            let flag = if i == 0 && hops.len() == 1 {
                FLAG_ENDPOINT
            } else if i == 0 {
                FLAG_GATEWAY
            } else if i == hops.len() - 1 {
                FLAG_ENDPOINT
            } else {
                FLAG_PARTICIPANT
            };
            let record = build_request_record(hop, pubkey, flag, request_time_hours, i as u32)?;
            records.push(record);
        }

        let header = I2npHeader::new(TYPE_VARIABLE_TUNNEL_BUILD, 0, now_ms);
        Ok(TunnelBuildMessage::new(header, records))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::crypto::x25519::StaticKeypair;
    use crate::data::hash::Hash;

    fn make_hop(seed: u8) -> HopConfig {
        HopConfig::new(
            Hash::sha256(&[seed]),
            seed as u32 * 10,
            Some(seed as u32 * 10 + 1),
            Some(Hash::sha256(&[seed + 1])),
            [seed; 32],
            [seed.wrapping_add(1); 32],
        )
    }

    #[test]
    fn build_record_correct_size() {
        let hop = make_hop(1);
        let kp = StaticKeypair::generate();
        let pub_key = kp.public_bytes();
        let rec = build_request_record(&hop, &pub_key, FLAG_PARTICIPANT, 0, 42).unwrap();
        assert_eq!(rec.data.len(), BUILD_RECORD_SIZE);
    }

    #[test]
    fn build_record_starts_with_ephemeral_pub() {
        let hop = make_hop(2);
        let kp = StaticKeypair::generate();
        let pub_key = kp.public_bytes();
        let rec = build_request_record(&hop, &pub_key, FLAG_GATEWAY, 0, 0).unwrap();
        // First 32 bytes are the ephemeral public key (non-zero with high probability)
        assert_eq!(rec.data.len(), BUILD_RECORD_SIZE);
        // The ephemeral pub key should NOT equal the hop pub key
        assert_ne!(&rec.data[..32], pub_key.as_slice());
    }

    #[test]
    fn build_tunnel_message_three_hops() {
        let hops: Vec<HopConfig> = (0u8..3).map(make_hop).collect();
        let keys: Vec<[u8; 32]> = (0u8..3)
            .map(|_| StaticKeypair::generate().public_bytes())
            .collect();
        let msg = TunnelBuilder::build_tunnel_message(&hops, &keys, 1_000_000).unwrap();
        assert_eq!(msg.records.len(), 3);
        for rec in &msg.records {
            assert_eq!(rec.data.len(), BUILD_RECORD_SIZE);
        }
    }

    #[test]
    fn build_tunnel_message_mismatch_lengths() {
        let hops: Vec<HopConfig> = (0u8..3).map(make_hop).collect();
        let keys: Vec<[u8; 32]> = (0u8..2)
            .map(|_| StaticKeypair::generate().public_bytes())
            .collect();
        assert!(TunnelBuilder::build_tunnel_message(&hops, &keys, 0).is_err());
    }

    #[test]
    fn plaintext_correct_length() {
        let hop = make_hop(5);
        let pt = build_plaintext(&hop, FLAG_ENDPOINT, 12345, 99);
        assert_eq!(pt.len(), PLAINTEXT_LEN);
    }
}
