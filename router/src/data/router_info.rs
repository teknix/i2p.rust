//! Router descriptor — the complete published record of a router.
//!
//! A [`RouterInfo`] bundles a router's [`RouterIdentity`], its transport
//! [`RouterAddress`]es, capability flags, published timestamp, and a
//! self-signature over all of that data.  It is what routers store in and
//! look up from the NetDB.
//!
//! Java equivalent: `net.i2p.data.router.RouterInfo`

use std::collections::HashMap;

use crate::data::hash::Hash;
use crate::data::router_address::RouterAddress;
use crate::data::router_identity::RouterIdentity;
use crate::error::{Error, Result};

/// Router capability flags published in the NetDB.
///
/// Multiple flags may be combined (they are stored as a free-form string in
/// the Java implementation; here we represent the well-known ones).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Capabilities {
    /// `f` — this router participates as a floodfill.
    pub floodfill: bool,
    /// `H` — this router is "hidden" (does not want to be a floodfill
    /// and does not publish reachable addresses).
    pub hidden: bool,
    /// `R` — this router is reachable (has at least one published transport).
    pub reachable: bool,
    /// `U` — this router is unreachable (behind a strict NAT/firewall).
    pub unreachable: bool,
}

impl Capabilities {
    /// Parse the capability string used in RouterInfo options (e.g. `"Rf"`).
    pub fn from_str(s: &str) -> Self {
        Self {
            floodfill: s.contains('f'),
            hidden: s.contains('H'),
            reachable: s.contains('R'),
            unreachable: s.contains('U'),
        }
    }

    /// Encode the capabilities back to the standard flag string.
    pub fn to_flag_string(&self) -> String {
        let mut s = String::new();
        if self.floodfill { s.push('f'); }
        if self.hidden    { s.push('H'); }
        if self.reachable { s.push('R'); }
        if self.unreachable { s.push('U'); }
        s
    }
}

/// The complete published descriptor of an I2P router.
///
/// A `RouterInfo` is signed by the router's signing key and verified by any
/// peer that fetches it from the NetDB.  The hash of its identity is the
/// router's unique identifier.
#[derive(Debug, Clone)]
pub struct RouterInfo {
    /// The router's public-key identity (determines its [`Hash`]).
    pub identity: RouterIdentity,
    /// Milliseconds since the Unix epoch when this `RouterInfo` was published.
    pub published: u64,
    /// Transport addresses at which this router can be reached.
    pub addresses: Vec<RouterAddress>,
    /// Router-level key/value options (includes `"caps"`, `"netId"`, etc.).
    pub options: HashMap<String, String>,
    /// Raw signature bytes over the canonical serialisation of this record.
    pub signature: Vec<u8>,
}

impl RouterInfo {
    /// Create an unsigned `RouterInfo`.  Call [`RouterInfo::sign`] before
    /// publishing.
    pub fn new(
        identity: RouterIdentity,
        published: u64,
        addresses: Vec<RouterAddress>,
        options: HashMap<String, String>,
    ) -> Self {
        Self {
            identity,
            published,
            addresses,
            options,
            signature: Vec::new(),
        }
    }

    /// Return the SHA-256 [`Hash`] of this router's identity.
    pub fn router_hash(&self) -> Hash {
        self.identity.hash()
    }

    /// Return the router's capability flags, parsed from the `"caps"` option.
    pub fn capabilities(&self) -> Capabilities {
        self.options
            .get("caps")
            .map(|s| Capabilities::from_str(s))
            .unwrap_or_default()
    }

    /// Return `true` if this router is configured as a floodfill.
    pub fn is_floodfill(&self) -> bool {
        self.capabilities().floodfill
    }

    /// Return `true` if this `RouterInfo` is older than `max_age_ms`
    /// milliseconds relative to `now_ms`.
    pub fn is_expired(&self, now_ms: u64, max_age_ms: u64) -> bool {
        now_ms.saturating_sub(self.published) > max_age_ms
    }

    /// Return the transport address with the lowest cost, if any.
    pub fn best_address(&self) -> Option<&RouterAddress> {
        self.addresses.iter().min_by_key(|a| a.cost)
    }

    /// Attach a raw signature to this record.
    ///
    /// In a full implementation, the signing key from [`RouterIdentity`] would
    /// sign the canonical serialisation of this record.  Here we store the
    /// signature as provided and leave verification to the [`crate::crypto`]
    /// layer.
    pub fn sign(&mut self, signature: Vec<u8>) -> Result<()> {
        if signature.is_empty() {
            return Err(Error::InvalidSignature("empty signature".into()));
        }
        self.signature = signature;
        Ok(())
    }

    /// Return `true` when a signature has been attached.
    pub fn is_signed(&self) -> bool {
        !self.signature.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::router_identity::{
        RouterIdentity, CRYPTO_TYPE_X25519, ED25519_PUB_KEY_LEN,
        SIG_TYPE_EDDSA_SHA512_ED25519, X25519_PUB_KEY_LEN,
    };

    fn make_identity() -> RouterIdentity {
        RouterIdentity::new(
            vec![0u8; X25519_PUB_KEY_LEN],
            CRYPTO_TYPE_X25519,
            vec![1u8; ED25519_PUB_KEY_LEN],
            SIG_TYPE_EDDSA_SHA512_ED25519,
            vec![],
        )
    }

    #[test]
    fn capabilities_floodfill() {
        let mut opts = HashMap::new();
        opts.insert("caps".into(), "Rf".into());
        let ri = RouterInfo::new(make_identity(), 0, vec![], opts);
        assert!(ri.is_floodfill());
        assert!(ri.capabilities().reachable);
    }

    #[test]
    fn best_address_lowest_cost() {
        let mut a1 = RouterAddress::new("NTCP2", 20);
        a1.set_option("host", "1.2.3.4");
        a1.set_option("port", "4567");
        let mut a2 = RouterAddress::new("SSU2", 5);
        a2.set_option("host", "1.2.3.4");
        a2.set_option("port", "7654");

        let ri = RouterInfo::new(make_identity(), 0, vec![a1, a2], HashMap::new());
        assert_eq!(ri.best_address().unwrap().cost, 5);
    }

    #[test]
    fn is_expired() {
        let ri = RouterInfo::new(make_identity(), 1_000, vec![], HashMap::new());
        assert!(ri.is_expired(3_000, 1_500)); // 2000 ms old, max 1500
        assert!(!ri.is_expired(2_000, 1_500)); // 1000 ms old, within limit
    }

    #[test]
    fn sign_and_is_signed() {
        let mut ri = RouterInfo::new(make_identity(), 0, vec![], HashMap::new());
        assert!(!ri.is_signed());
        ri.sign(vec![0xAB; 64]).unwrap();
        assert!(ri.is_signed());
    }
}
