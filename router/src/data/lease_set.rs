//! LeaseSet — the set of active tunnel endpoints for a [`Destination`].
//!
//! From the tech-intro:
//! *"A leaseSet contains a number of 'leases'. Each of these leases specifies
//! a tunnel gateway, which allows reaching a specific destination."*
//!
//! A [`Lease`] records one inbound tunnel gateway: the hash of the gateway
//! router, the tunnel ID at that router, and the expiry time.
//! A [`LeaseSet`] bundles several such leases with the destination's public
//! keys and a signature.
//!
//! Java equivalent: `net.i2p.data.LeaseSet`

use crate::data::destination::Destination;
use crate::data::hash::Hash;
use crate::error::{Error, Result};

/// Maximum number of leases in a [`LeaseSet`] (spec limit).
pub const MAX_LEASES: usize = 16;

/// A single inbound tunnel endpoint for a destination.
///
/// *"The inbound gateway for a tunnel that allows reaching a specific
///  destination; the time when a tunnel expires."*  (tech-intro)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    /// SHA-256 hash of the tunnel gateway router's identity.
    pub tunnel_gateway: Hash,
    /// The tunnel ID at the gateway router that accepts messages for this
    /// lease.
    pub tunnel_id: u32,
    /// Absolute expiry timestamp in milliseconds since the Unix epoch.
    /// Tunnels are typically short-lived (~10 minutes).
    pub expiration: u64,
}

impl Lease {
    /// Create a new `Lease`.
    pub fn new(tunnel_gateway: Hash, tunnel_id: u32, expiration: u64) -> Self {
        Self {
            tunnel_gateway,
            tunnel_id,
            expiration,
        }
    }

    /// Return `true` if this lease has expired relative to `now_ms`.
    pub fn is_expired(&self, now_ms: u64) -> bool {
        self.expiration < now_ms
    }
}

/// The published set of inbound tunnel endpoints for a [`Destination`].
///
/// Routers look up the [`LeaseSet`] for a destination in the NetDB when they
/// want to send a message to it.  The lease-set is signed by the destination's
/// signing key; it is stored anonymously (sent through outbound tunnels to
/// avoid correlating a router with its destinations).
#[derive(Debug, Clone)]
pub struct LeaseSet {
    /// The destination this lease-set belongs to.
    pub destination: Destination,
    /// Encryption public key used to encrypt garlic messages to this destination.
    pub encryption_key: Vec<u8>,
    /// Active leases (inbound tunnel endpoints).
    pub leases: Vec<Lease>,
    /// Raw signature bytes from the destination's signing key.
    pub signature: Vec<u8>,
}

impl LeaseSet {
    /// Create an unsigned [`LeaseSet`].
    pub fn new(
        destination: Destination,
        encryption_key: Vec<u8>,
        leases: Vec<Lease>,
    ) -> Result<Self> {
        if leases.len() > MAX_LEASES {
            return Err(Error::DataFormat(format!(
                "too many leases: {} (max {})",
                leases.len(),
                MAX_LEASES
            )));
        }
        Ok(Self {
            destination,
            encryption_key,
            leases,
            signature: Vec::new(),
        })
    }

    /// Return the routing [`Hash`] (SHA-256 of the destination).
    pub fn destination_hash(&self) -> Hash {
        self.destination.hash()
    }

    /// Return the first non-expired lease relative to `now_ms`, if any.
    pub fn earliest_expiring_lease(&self, now_ms: u64) -> Option<&Lease> {
        self.leases
            .iter()
            .filter(|l| !l.is_expired(now_ms))
            .min_by_key(|l| l.expiration)
    }

    /// Return `true` if **all** leases have expired.
    pub fn is_expired(&self, now_ms: u64) -> bool {
        self.leases.iter().all(|l| l.is_expired(now_ms))
    }

    /// Attach a raw signature to this record.
    pub fn sign(&mut self, signature: Vec<u8>) -> Result<()> {
        if signature.is_empty() {
            return Err(Error::InvalidSignature("empty signature".into()));
        }
        self.signature = signature;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::destination::Destination;
    use crate::data::router_identity::{
        CRYPTO_TYPE_X25519, ED25519_PUB_KEY_LEN, SIG_TYPE_EDDSA_SHA512_ED25519,
        X25519_PUB_KEY_LEN,
    };

    fn make_dest() -> Destination {
        Destination::new(
            vec![0u8; X25519_PUB_KEY_LEN],
            CRYPTO_TYPE_X25519,
            vec![1u8; ED25519_PUB_KEY_LEN],
            SIG_TYPE_EDDSA_SHA512_ED25519,
            vec![],
        )
    }

    fn make_lease(exp: u64) -> Lease {
        Lease::new(Hash::sha256(b"gateway"), 42, exp)
    }

    #[test]
    fn expired_lease() {
        let lease = make_lease(1_000);
        assert!(lease.is_expired(2_000));
        assert!(!lease.is_expired(500));
    }

    #[test]
    fn too_many_leases() {
        let leases: Vec<Lease> = (0..=MAX_LEASES).map(|i| make_lease(i as u64 + 9000)).collect();
        assert!(LeaseSet::new(make_dest(), vec![0u8; 32], leases).is_err());
    }

    #[test]
    fn earliest_expiring_lease() {
        let leases = vec![make_lease(5_000), make_lease(3_000), make_lease(7_000)];
        let ls = LeaseSet::new(make_dest(), vec![0u8; 32], leases).unwrap();
        let earliest = ls.earliest_expiring_lease(1_000).unwrap();
        assert_eq!(earliest.expiration, 3_000);
    }

    #[test]
    fn all_expired() {
        let leases = vec![make_lease(100), make_lease(200)];
        let ls = LeaseSet::new(make_dest(), vec![0u8; 32], leases).unwrap();
        assert!(ls.is_expired(300));
        assert!(!ls.is_expired(150));
    }
}
