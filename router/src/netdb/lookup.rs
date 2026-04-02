//! Iterative Kademlia lookup over the in-memory NetDB.

#![allow(dead_code)]

use crate::data::hash::Hash;
use crate::netdb::NetDb;

/// Performs iterative Kademlia-style lookups against the local NetDB.
///
/// In a live router this would exchange `DatabaseLookup` and
/// `DatabaseSearchReply` messages with remote peers.  This implementation
/// operates locally over whatever is already stored.
pub struct IterativeLookup<'a> {
    netdb: &'a dyn NetDb,
}

impl<'a> IterativeLookup<'a> {
    /// Create a new lookup against `netdb`.
    pub fn new(netdb: &'a dyn NetDb) -> Self {
        Self { netdb }
    }

    /// Return up to `count` router hashes closest (XOR) to `target`.
    pub fn find_closest(&self, target: &Hash, count: usize) -> Vec<Hash> {
        self.netdb.find_closest_routers(target, count, &[])
    }

    /// Select `count` routers suitable for building a tunnel hop.
    ///
    /// Excludes the hashes in `exclude` and returns results sorted by XOR
    /// distance to a freshly-derived routing key.
    pub fn select_for_tunnel(&self, exclude: &[Hash], count: usize) -> Vec<Hash> {
        // Use a fixed key as the "routing target" for tunnel hop selection;
        // in practice this would be derived from the tunnel ID.
        let routing_target = Hash::sha256(b"tunnel-hop-selection");
        self.netdb
            .find_closest_routers(&routing_target, count, exclude)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::data::router_identity::{
        RouterIdentity, CRYPTO_TYPE_X25519, ED25519_PUB_KEY_LEN,
        SIG_TYPE_EDDSA_SHA512_ED25519, X25519_PUB_KEY_LEN,
    };
    use crate::data::router_info::RouterInfo;
    use crate::netdb::MemoryNetDb;
    use std::collections::HashMap;

    fn make_ri(seed: u8) -> RouterInfo {
        let id = RouterIdentity::new(
            vec![seed; X25519_PUB_KEY_LEN],
            CRYPTO_TYPE_X25519,
            vec![seed.wrapping_add(1); ED25519_PUB_KEY_LEN],
            SIG_TYPE_EDDSA_SHA512_ED25519,
            vec![],
        );
        RouterInfo::new(id, 0, vec![], HashMap::new())
    }

    #[test]
    fn find_closest_returns_at_most_count() {
        let db = MemoryNetDb::new();
        for i in 0u8..10 {
            db.store_router_info(make_ri(i));
        }
        let lookup = IterativeLookup::new(&db);
        let target = Hash::sha256(b"test");
        let result = lookup.find_closest(&target, 3);
        assert!(result.len() <= 3);
    }

    #[test]
    fn find_closest_sorted_by_xor() {
        let db = MemoryNetDb::new();
        for i in 0u8..8 {
            db.store_router_info(make_ri(i));
        }
        let lookup = IterativeLookup::new(&db);
        let target = Hash::sha256(b"xor-sort");
        let result = lookup.find_closest(&target, 8);
        for i in 1..result.len() {
            assert!(!result[i].is_closer_than(&result[i - 1], &target));
        }
    }

    #[test]
    fn select_for_tunnel_excludes() {
        let db = MemoryNetDb::new();
        let mut hashes = vec![];
        for i in 0u8..5 {
            let ri = make_ri(i);
            hashes.push(ri.router_hash());
            db.store_router_info(ri);
        }
        let lookup = IterativeLookup::new(&db);
        let exclude = vec![hashes[0], hashes[1]];
        let result = lookup.select_for_tunnel(&exclude, 10);
        assert!(!result.contains(&hashes[0]));
        assert!(!result.contains(&hashes[1]));
    }
}
