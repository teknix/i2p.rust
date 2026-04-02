//! NTCP2 transport — Noise_XK_25519_ChaChaPoly_SHA256.
//!
//! Provides TCP-based router-to-router transport using X25519 key exchange
//! and ChaCha20-Poly1305 for authenticated encryption.

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::RwLock;

use async_trait::async_trait;

use crate::crypto::{chacha, x25519};
use crate::data::{Hash, RouterInfo};
use crate::error::{Error, Result};
use crate::transport::{Transport, TransportBid};

/// State of an NTCP2 session.
pub enum SessionState {
    /// Outbound: SessionRequest has been sent.
    Handshake1Sent,
    /// Inbound: SessionCreated has been sent.
    Handshake2Sent,
    /// Fully established session with send/recv counters.
    Established { send_counter: u64, recv_counter: u64 },
}

/// An established or in-progress NTCP2 session with one peer.
pub struct Ntcp2Session {
    peer_hash: Hash,
    state: SessionState,
    send_key: [u8; 32],
    recv_key: [u8; 32],
}

impl Ntcp2Session {
    /// Create a new established session directly (for testing / after handshake).
    pub fn new_established(peer_hash: Hash, send_key: [u8; 32], recv_key: [u8; 32]) -> Self {
        Self {
            peer_hash,
            state: SessionState::Established {
                send_counter: 0,
                recv_counter: 0,
            },
            send_key,
            recv_key,
        }
    }

    /// Frame a message for sending: 2-byte big-endian length || ChaCha20-Poly1305 ciphertext.
    pub fn frame_message(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let counter = match &mut self.state {
            SessionState::Established { send_counter, .. } => {
                let c = *send_counter;
                *send_counter += 1;
                c
            }
            _ => return Err(Error::State("session not established".into())),
        };

        let nonce = chacha::nonce_from_counter(counter);
        let ciphertext = chacha::encrypt(&self.send_key, &nonce, &[], plaintext)?;

        let len = ciphertext.len() as u16;
        let mut frame = Vec::with_capacity(2 + ciphertext.len());
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(&ciphertext);
        Ok(frame)
    }

    /// Unframe a received message: strip 2-byte length header, decrypt, verify.
    pub fn unframe_message(&mut self, frame: &[u8]) -> Result<Vec<u8>> {
        if frame.len() < 2 {
            return Err(Error::DataFormat("frame too short".into()));
        }
        let len = u16::from_be_bytes([frame[0], frame[1]]) as usize;
        if frame.len() < 2 + len {
            return Err(Error::DataFormat("frame data truncated".into()));
        }

        let counter = match &mut self.state {
            SessionState::Established { recv_counter, .. } => {
                let c = *recv_counter;
                *recv_counter += 1;
                c
            }
            _ => return Err(Error::State("session not established".into())),
        };

        let nonce = chacha::nonce_from_counter(counter);
        chacha::decrypt(&self.recv_key, &nonce, &[], &frame[2..2 + len])
    }
}

/// NTCP2 transport manager.
pub struct Ntcp2Transport {
    local_static: x25519::StaticKeypair,
    local_addr: Option<SocketAddr>,
    sessions: RwLock<HashMap<Hash, Ntcp2Session>>,
}

impl Ntcp2Transport {
    /// Create a new NTCP2 transport with a freshly-generated static keypair.
    pub fn new(local_addr: Option<SocketAddr>) -> Self {
        Self {
            local_static: x25519::StaticKeypair::generate(),
            local_addr,
            sessions: RwLock::new(HashMap::new()),
        }
    }

    /// Add a pre-established session (for testing).
    pub fn add_session(&self, session: Ntcp2Session) {
        let hash = session.peer_hash;
        self.sessions.write().unwrap().insert(hash, session);
    }

    /// Return the local static public key bytes.
    pub fn static_public_key(&self) -> [u8; 32] {
        self.local_static.public_bytes()
    }
}

#[async_trait]
impl Transport for Ntcp2Transport {
    fn style(&self) -> &str {
        "NTCP2"
    }

    fn bid(&self, peer: &RouterInfo, _size: usize) -> Option<TransportBid> {
        let hash = peer.router_hash();
        let has_session = self.sessions.read().unwrap().contains_key(&hash);

        if has_session {
            return Some(TransportBid::existing_session("NTCP2", 0));
        }

        // Check if peer has an NTCP2 address.
        let has_ntcp2 = peer
            .addresses
            .iter()
            .any(|a| a.transport_style == "NTCP2");

        if has_ntcp2 {
            Some(TransportBid::new_session("NTCP2", 50))
        } else {
            None
        }
    }

    async fn send(&self, peer: &RouterInfo, data: Vec<u8>) -> Result<()> {
        let hash = peer.router_hash();
        let mut sessions = self.sessions.write().unwrap();
        match sessions.get_mut(&hash) {
            Some(session) => {
                let _frame = session.frame_message(&data)?;
                // In a real implementation: write frame to TCP stream.
                Ok(())
            }
            None => Err(Error::State("no session".into())),
        }
    }

    fn is_connected(&self, peer_hash: &Hash) -> bool {
        self.sessions.read().unwrap().contains_key(peer_hash)
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }
}

// ── Handshake helpers ─────────────────────────────────────────────────────────

/// Build the NTCP2 SessionRequest (handshake message 1).
///
/// Returns `(request_bytes, ephemeral_public, obfs_key)`.
pub fn build_session_request(
    remote_static_pub: &[u8; 32],
    padding_len: usize,
) -> Result<(Vec<u8>, [u8; 32], [u8; 32])> {
    let (ephemeral_pub, shared_secret) = x25519::ephemeral_dh(remote_static_pub);

    // Encrypt 16 zero bytes as the options block.
    let options = [0u8; 16];
    // Zero nonce is safe here: the key is derived from a single-use ephemeral DH
    // secret, so it is never reused with the same nonce.
    let nonce = [0u8; chacha::NONCE_LEN];
    let mut obfs_key = [0u8; 32];
    obfs_key.copy_from_slice(&*shared_secret);

    let enc_options = chacha::encrypt(&obfs_key, &nonce, &[], &options)?;

    let mut request = Vec::new();
    request.extend_from_slice(&ephemeral_pub);
    request.extend_from_slice(&enc_options);
    request.extend_from_slice(&vec![0u8; padding_len]);

    Ok((request, ephemeral_pub, obfs_key))
}

/// Process a received SessionRequest and produce the SessionCreated reply.
pub fn process_session_request(
    local_static: &x25519::StaticKeypair,
    request: &[u8],
) -> Result<Vec<u8>> {
    if request.len() < 48 {
        return Err(Error::DataFormat("SessionRequest too short".into()));
    }

    let mut sender_ephemeral = [0u8; 32];
    sender_ephemeral.copy_from_slice(&request[..32]);

    // DH with sender's ephemeral and our static key.
    let shared_secret = local_static.dh(&sender_ephemeral);

    // Generate our own ephemeral for the reply.
    let (our_ephemeral_pub, _) = x25519::ephemeral_dh(&sender_ephemeral);

    let options = [0u8; 16];
    // Zero nonce is safe here: the reply key is derived from a single-use
    // ephemeral DH secret, so it is never reused with the same nonce.
    let nonce = [0u8; chacha::NONCE_LEN];
    let mut reply_key = [0u8; 32];
    reply_key.copy_from_slice(&*shared_secret);
    let enc_options = chacha::encrypt(&reply_key, &nonce, &[], &options)?;

    let mut reply = Vec::new();
    reply.extend_from_slice(&our_ephemeral_pub);
    reply.extend_from_slice(&enc_options);

    Ok(reply)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn frame_unframe_round_trip() {
        let peer_hash = Hash::sha256(b"peer");
        let send_key = [0x11u8; 32];
        let recv_key = [0x11u8; 32]; // same key for loopback

        let mut session_a = Ntcp2Session::new_established(peer_hash, send_key, recv_key);
        let mut session_b = Ntcp2Session::new_established(peer_hash, recv_key, send_key);

        let plaintext = b"hello NTCP2";
        let frame = session_a.frame_message(plaintext).unwrap();
        let recovered = session_b.unframe_message(&frame).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn frame_has_length_prefix() {
        let peer_hash = Hash::sha256(b"p");
        let key = [0x22u8; 32];
        let mut session = Ntcp2Session::new_established(peer_hash, key, key);
        let msg = b"test";
        let frame = session.frame_message(msg).unwrap();
        // Length field
        let len = u16::from_be_bytes([frame[0], frame[1]]) as usize;
        assert_eq!(frame.len(), 2 + len);
    }

    #[test]
    fn unframe_not_established_errors() {
        let mut session = Ntcp2Session {
            peer_hash: Hash::sha256(b"x"),
            state: SessionState::Handshake1Sent,
            send_key: [0u8; 32],
            recv_key: [0u8; 32],
        };
        assert!(session.unframe_message(&[0u8; 10]).is_err());
    }

    #[test]
    fn build_session_request_structure() {
        let remote_kp = x25519::StaticKeypair::generate();
        let (req, eph_pub, _obfs) = build_session_request(&remote_kp.public_bytes(), 0).unwrap();
        // ephemeral_pub (32) + encrypted_options (16+16=32 with tag)
        assert!(req.len() >= 48);
        assert_ne!(eph_pub, [0u8; 32]);
    }

    #[test]
    fn process_session_request_produces_reply() {
        let remote_kp = x25519::StaticKeypair::generate();
        let local_kp = x25519::StaticKeypair::generate();
        let (req, _, _) = build_session_request(&remote_kp.public_bytes(), 0).unwrap();
        // process_session_request uses local_kp for the reply
        let reply = process_session_request(&local_kp, &req).unwrap();
        assert!(reply.len() >= 48);
    }

    #[test]
    fn ntcp2_transport_bid_no_session() {
        use crate::data::router_identity::{
            RouterIdentity, CRYPTO_TYPE_X25519, ED25519_PUB_KEY_LEN,
            SIG_TYPE_EDDSA_SHA512_ED25519, X25519_PUB_KEY_LEN,
        };
        use crate::data::RouterAddress;
        use std::collections::HashMap;

        let transport = Ntcp2Transport::new(None);
        let id = RouterIdentity::new(
            vec![0u8; X25519_PUB_KEY_LEN],
            CRYPTO_TYPE_X25519,
            vec![1u8; ED25519_PUB_KEY_LEN],
            SIG_TYPE_EDDSA_SHA512_ED25519,
            vec![],
        );
        let mut addr = RouterAddress::new("NTCP2", 10);
        addr.set_option("host", "1.2.3.4");
        let ri = RouterInfo::new(id, 0, vec![addr], HashMap::new());
        let bid = transport.bid(&ri, 100);
        assert!(bid.is_some());
        assert_eq!(bid.unwrap().transport_style, "NTCP2");
    }
}
