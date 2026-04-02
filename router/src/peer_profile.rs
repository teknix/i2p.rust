//! Per-peer performance profiles used for tunnel selection.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use crate::data::hash::Hash;

/// Tracks per-router statistics for tunnel selection and peer ranking.
#[derive(Debug, Clone)]
pub struct PeerProfile {
    pub hash: Hash,
    pub latency_ms: u32,
    pub tunnels_agreed: u32,
    pub tunnels_rejected: u32,
    pub tunnels_failed: u32,
    pub last_heard_from: u64,
    pub is_failing: bool,
}

impl PeerProfile {
    pub fn new(hash: Hash) -> Self {
        Self {
            hash,
            latency_ms: 0,
            tunnels_agreed: 0,
            tunnels_rejected: 0,
            tunnels_failed: 0,
            last_heard_from: 0,
            is_failing: false,
        }
    }

    pub fn record_tunnel_response(&mut self, accepted: bool) {
        if accepted {
            self.tunnels_agreed += 1;
        } else {
            self.tunnels_rejected += 1;
        }
        self.update_failing();
    }

    pub fn record_failure(&mut self) {
        self.tunnels_failed += 1;
        self.update_failing();
    }

    pub fn record_latency(&mut self, latency_ms: u32) {
        if self.latency_ms == 0 {
            self.latency_ms = latency_ms;
        } else {
            // Rolling average: 80% old + 20% new
            self.latency_ms = (self.latency_ms * 4 / 5).saturating_add(latency_ms / 5);
        }
    }

    pub fn acceptance_rate(&self) -> f64 {
        let total = self.tunnels_agreed + self.tunnels_rejected;
        if total == 0 {
            1.0
        } else {
            self.tunnels_agreed as f64 / total as f64
        }
    }

    pub fn is_good_for_tunnel(&self) -> bool {
        self.acceptance_rate() > 0.3 && !self.is_failing
    }

    fn update_failing(&mut self) {
        let total = self.tunnels_agreed + self.tunnels_rejected;
        if total > 5 {
            self.is_failing = self.acceptance_rate() < 0.1
                || self.tunnels_failed > self.tunnels_agreed;
        }
    }
}

/// Stores and provides access to peer profiles indexed by router hash.
#[derive(Default)]
pub struct PeerProfileStore {
    profiles: RwLock<HashMap<Hash, Arc<Mutex<PeerProfile>>>>,
}

impl PeerProfileStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_or_create(&self, hash: &Hash) -> Arc<Mutex<PeerProfile>> {
        // Fast path: read lock
        {
            let guard = self.profiles.read().unwrap();
            if let Some(p) = guard.get(hash) {
                return Arc::clone(p);
            }
        }
        // Slow path: write lock
        let mut guard = self.profiles.write().unwrap();
        guard
            .entry(*hash)
            .or_insert_with(|| Arc::new(Mutex::new(PeerProfile::new(*hash))))
            .clone()
    }

    pub fn get_good_peers(&self, exclude: &[Hash]) -> Vec<Hash> {
        let exclude_set: std::collections::HashSet<&Hash> = exclude.iter().collect();
        let guard = self.profiles.read().unwrap();
        guard
            .iter()
            .filter(|(h, p)| {
                !exclude_set.contains(h)
                    && p.lock().unwrap().is_good_for_tunnel()
            })
            .map(|(h, _)| *h)
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn make_hash(seed: u8) -> Hash {
        Hash::sha256(&[seed])
    }

    #[test]
    fn new_profile_defaults() {
        let h = make_hash(1);
        let p = PeerProfile::new(h);
        assert_eq!(p.acceptance_rate(), 1.0);
        assert!(p.is_good_for_tunnel());
    }

    #[test]
    fn record_tunnel_response_tracks_counts() {
        let h = make_hash(2);
        let mut p = PeerProfile::new(h);
        p.record_tunnel_response(true);
        p.record_tunnel_response(true);
        p.record_tunnel_response(false);
        assert_eq!(p.tunnels_agreed, 2);
        assert_eq!(p.tunnels_rejected, 1);
        let rate = p.acceptance_rate();
        assert!((rate - 2.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn record_latency_rolling_average() {
        let h = make_hash(3);
        let mut p = PeerProfile::new(h);
        p.record_latency(100);
        assert_eq!(p.latency_ms, 100);
        p.record_latency(200);
        // 100 * 4/5 + 200/5 = 80 + 40 = 120
        assert_eq!(p.latency_ms, 120);
    }

    #[test]
    fn peer_profile_store_get_or_create() {
        let store = PeerProfileStore::new();
        let h = make_hash(4);
        let p1 = store.get_or_create(&h);
        let p2 = store.get_or_create(&h);
        // Same Arc pointer
        assert!(Arc::ptr_eq(&p1, &p2));
    }

    #[test]
    fn get_good_peers_excludes() {
        let store = PeerProfileStore::new();
        let h1 = make_hash(5);
        let h2 = make_hash(6);
        store.get_or_create(&h1);
        store.get_or_create(&h2);
        let good = store.get_good_peers(&[h1]);
        assert!(!good.contains(&h1));
        assert!(good.contains(&h2));
    }
}
