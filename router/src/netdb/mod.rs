//! Network Database (NetDB) — Kademlia DHT for RouterInfos and LeaseSets.
//!
//! From the tech-intro:
//! *"I2P's netDb works to share the network's metadata … routerInfo gives
//! routers the data necessary for contacting a particular router … leaseSet
//! gives routers the information necessary for contacting a particular
//! destination."*
//!
//! This module provides:
//! - The XOR-based Kademlia distance metric ([`xor_distance`], [`KBucket`])
//! - The [`NetDb`] trait that abstracts storage and lookup
//! - A simple in-memory [`MemoryNetDb`] implementation

pub mod kademlia;
pub mod lookup;

pub use kademlia::{KBucket, KBUCKET_SIZE};
pub use lookup::IterativeLookup;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::data::hash::Hash;
use crate::data::lease_set::LeaseSet;
use crate::data::router_info::RouterInfo;

// ── NetDb trait ───────────────────────────────────────────────────────────────

/// Abstraction over the Network Database.
///
/// A `NetDb` stores and retrieves the two fundamental types of metadata:
/// [`RouterInfo`] records (how to contact a router) and [`LeaseSet`] records
/// (the tunnel endpoints for a destination).
pub trait NetDb: Send + Sync {
    /// Store or update a [`RouterInfo`].
    fn store_router_info(&self, ri: RouterInfo);

    /// Look up a [`RouterInfo`] by the router's identity hash.
    fn get_router_info(&self, hash: &Hash) -> Option<Arc<RouterInfo>>;

    /// Store or update a [`LeaseSet`].
    fn store_lease_set(&self, ls: LeaseSet);

    /// Look up a [`LeaseSet`] by its destination hash.
    fn get_lease_set(&self, hash: &Hash) -> Option<Arc<LeaseSet>>;

    /// Return up to `count` router hashes that are *closest* (XOR distance)
    /// to `target`, excluding `exclude`.  Used for iterative DHT lookups.
    fn find_closest_routers(
        &self,
        target: &Hash,
        count: usize,
        exclude: &[Hash],
    ) -> Vec<Hash>;

    /// Return the total number of stored [`RouterInfo`] entries.
    fn router_count(&self) -> usize;
}

// ── MemoryNetDb ───────────────────────────────────────────────────────────────

/// A simple in-memory [`NetDb`] implementation.
///
/// Suitable for testing and as the foundation for a persistent implementation.
/// A production implementation would add disk persistence, expiry sweeps, and
/// floodfill flooding logic.
#[derive(Default)]
pub struct MemoryNetDb {
    routers: RwLock<HashMap<Hash, Arc<RouterInfo>>>,
    leases: RwLock<HashMap<Hash, Arc<LeaseSet>>>,
}

impl MemoryNetDb {
    /// Create an empty `MemoryNetDb`.
    pub fn new() -> Self {
        Self::default()
    }
}

impl NetDb for MemoryNetDb {
    fn store_router_info(&self, ri: RouterInfo) {
        let hash = ri.router_hash();
        self.routers.write().unwrap().insert(hash, Arc::new(ri));
    }

    fn get_router_info(&self, hash: &Hash) -> Option<Arc<RouterInfo>> {
        self.routers.read().unwrap().get(hash).cloned()
    }

    fn store_lease_set(&self, ls: LeaseSet) {
        let hash = ls.destination_hash();
        self.leases.write().unwrap().insert(hash, Arc::new(ls));
    }

    fn get_lease_set(&self, hash: &Hash) -> Option<Arc<LeaseSet>> {
        self.leases.read().unwrap().get(hash).cloned()
    }

    fn find_closest_routers(
        &self,
        target: &Hash,
        count: usize,
        exclude: &[Hash],
    ) -> Vec<Hash> {
        let guard = self.routers.read().unwrap();
        let exclude_set: std::collections::HashSet<&Hash> = exclude.iter().collect();

        let mut candidates: Vec<Hash> = guard
            .keys()
            .filter(|h| !exclude_set.contains(h))
            .cloned()
            .collect();

        // Sort by XOR distance to target.
        candidates.sort_by(|a, b| {
            let da = a.xor_distance(target);
            let db = b.xor_distance(target);
            da.cmp(&db)
        });

        candidates.truncate(count);
        candidates
    }

    fn router_count(&self) -> usize {
        self.routers.read().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::router_identity::{
        RouterIdentity, CRYPTO_TYPE_X25519, ED25519_PUB_KEY_LEN,
        SIG_TYPE_EDDSA_SHA512_ED25519, X25519_PUB_KEY_LEN,
    };
    use std::collections::HashMap;

    fn make_ri(seed: u8) -> RouterInfo {
        let id = RouterIdentity::new(
            vec![seed; X25519_PUB_KEY_LEN],
            CRYPTO_TYPE_X25519,
            vec![seed + 1; ED25519_PUB_KEY_LEN],
            SIG_TYPE_EDDSA_SHA512_ED25519,
            vec![],
        );
        RouterInfo::new(id, 0, vec![], HashMap::new())
    }

    #[test]
    fn store_and_retrieve_router_info() {
        let db = MemoryNetDb::new();
        let ri = make_ri(1);
        let hash = ri.router_hash();
        db.store_router_info(ri);
        assert!(db.get_router_info(&hash).is_some());
        assert_eq!(db.router_count(), 1);
    }

    #[test]
    fn find_closest_returns_sorted() {
        let db = MemoryNetDb::new();
        for seed in 0u8..10 {
            db.store_router_info(make_ri(seed));
        }
        let target = Hash::sha256(b"target");
        let closest = db.find_closest_routers(&target, 3, &[]);
        assert_eq!(closest.len(), 3);
        // Verify they are in XOR-sorted order.
        for i in 1..closest.len() {
            assert!(!closest[i].is_closer_than(&closest[i - 1], &target));
        }
    }

    #[test]
    fn excluded_peers_not_returned() {
        let db = MemoryNetDb::new();
        let ri = make_ri(42);
        let hash = ri.router_hash();
        db.store_router_info(ri);
        let result = db.find_closest_routers(&Hash::sha256(b"x"), 10, &[hash]);
        assert!(!result.contains(&hash));
    }
}
