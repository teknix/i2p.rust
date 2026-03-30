//! X25519 Diffie-Hellman key exchange.
//!
//! From the tech-intro:
//! *"X25519 is used for key exchange"* (in ECIES-X25519-AEAD-Ratchet, NTCP2,
//! and SSU2).
//!
//! The local static key pair is generated at startup and published in the
//! router's [`RouterAddress`](crate::data::router_address::RouterAddress)
//! options.

use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Length of an X25519 public key in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;

/// An X25519 static key pair (long-lived, published in the NetDB).
pub struct StaticKeypair {
    secret: StaticSecret,
    /// Corresponding public key.
    pub public: PublicKey,
}

impl StaticKeypair {
    /// Generate a new random static keypair.
    pub fn generate() -> Self {
        use rand_core::OsRng;
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Return the raw 32-byte public key.
    pub fn public_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.public.to_bytes()
    }

    /// Perform a static DH with a remote public key.
    pub fn dh(&self, remote: &[u8; PUBLIC_KEY_LEN]) -> Zeroizing<[u8; 32]> {
        let remote_pk = PublicKey::from(*remote);
        let shared = self.secret.diffie_hellman(&remote_pk);
        Zeroizing::new(*shared.as_bytes())
    }
}

/// Perform an ephemeral X25519 DH and return `(ephemeral_public, shared_secret)`.
///
/// Used for the handshake phase where the router creates a fresh key pair for
/// each session.
pub fn ephemeral_dh(remote_public: &[u8; PUBLIC_KEY_LEN]) -> ([u8; PUBLIC_KEY_LEN], Zeroizing<[u8; 32]>) {
    use rand_core::OsRng;
    let ephemeral = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_pk = PublicKey::from(&ephemeral);
    let remote_pk = PublicKey::from(*remote_public);
    let shared = ephemeral.diffie_hellman(&remote_pk);
    (ephemeral_pk.to_bytes(), Zeroizing::new(*shared.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_dh_agreement() {
        let alice = StaticKeypair::generate();
        let bob = StaticKeypair::generate();

        let ab = alice.dh(&bob.public_bytes());
        let ba = bob.dh(&alice.public_bytes());
        assert_eq!(*ab, *ba, "DH shared secrets must agree");
    }

    #[test]
    fn ephemeral_dh_agreement() {
        let static_kp = StaticKeypair::generate();
        let (eph_pub, eph_shared) = ephemeral_dh(&static_kp.public_bytes());
        let static_shared = static_kp.dh(&eph_pub);
        assert_eq!(*eph_shared, *static_shared, "ephemeral DH must agree");
    }
}
