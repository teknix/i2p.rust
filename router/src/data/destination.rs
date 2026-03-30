//! I2P Destination — the cryptographic endpoint identity for an application.
//!
//! A [`Destination`] is the public identity of an I2P endpoint (website,
//! IRC server, mail server, …).  It contains an encryption public key and a
//! signing public key; its SHA-256 hash is the routing key used to look up
//! its [`LeaseSet`](super::lease_set::LeaseSet) in the NetDB.
//!
//! From the tech-intro: *"I2P takes on the role of the message-oriented
//! middleware — applications say that they want to send some data to a
//! cryptographic identifier (a 'destination')."*
//!
//! Java equivalent: `net.i2p.data.Destination`

use crate::data::hash::Hash;
use crate::data::router_identity::RouterIdentity;
use crate::error::Result;

/// The public identity of an I2P application endpoint.
///
/// A destination is structurally identical to a [`RouterIdentity`] — both
/// carry an encryption key, a signing key, and a certificate — but the two
/// serve different purposes:
///
/// - [`RouterIdentity`] identifies a **router** (network participant).
/// - [`Destination`] identifies an **application endpoint** (service / client).
///
/// Routing through the network uses the SHA-256 of the destination bytes as a
/// lookup key in the NetDB to find the destination's current [`LeaseSet`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination(RouterIdentity);

impl Destination {
    /// Construct a `Destination` from its component keys.
    pub fn new(
        encryption_key: Vec<u8>,
        crypto_type: u16,
        signing_key: Vec<u8>,
        sig_type: u16,
        certificate: Vec<u8>,
    ) -> Self {
        Self(RouterIdentity::new(
            encryption_key,
            crypto_type,
            signing_key,
            sig_type,
            certificate,
        ))
    }

    /// Validate key lengths.
    pub fn validate(&self) -> Result<()> {
        self.0.validate()
    }

    /// Return the SHA-256 routing hash of this destination.
    ///
    /// This hash is used as the DHT key to look up the destination's
    /// [`LeaseSet`](super::lease_set::LeaseSet) in the NetDB.
    pub fn hash(&self) -> Hash {
        self.0.hash()
    }

    /// Access the underlying [`RouterIdentity`] representation.
    pub fn identity(&self) -> &RouterIdentity {
        &self.0
    }

    /// Return the encryption public key bytes.
    pub fn encryption_key(&self) -> &[u8] {
        &self.0.encryption_key
    }

    /// Return the signing public key bytes.
    pub fn signing_key(&self) -> &[u8] {
        &self.0.signing_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::router_identity::{
        CRYPTO_TYPE_X25519, ED25519_PUB_KEY_LEN, SIG_TYPE_EDDSA_SHA512_ED25519, X25519_PUB_KEY_LEN,
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

    #[test]
    fn validate_ok() {
        assert!(make_dest().validate().is_ok());
    }

    #[test]
    fn hash_is_deterministic() {
        let d = make_dest();
        assert_eq!(d.hash(), d.hash());
    }
}
