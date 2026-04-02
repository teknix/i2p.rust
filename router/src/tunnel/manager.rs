//! Tunnel pool — manages active inbound and outbound tunnels.

#![allow(dead_code)]

use std::sync::RwLock;

use crate::data::hash::Hash;
use crate::tunnel::{TunnelId, TunnelInfo};

/// The lifecycle state of a tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelState {
    /// Tunnel build message has been sent; awaiting replies.
    Building,
    /// All hops agreed; the tunnel is usable.
    Active,
    /// Tunnel will expire soon; a replacement is being built.
    Expiring,
    /// One or more hops failed; tunnel is unusable.
    Failed,
}

/// An entry in the tunnel pool.
struct TunnelEntry {
    info: TunnelInfo,
    state: TunnelState,
    created_ms: u64,
}

/// Manages a pool of active inbound and outbound tunnels.
///
/// Thread-safe via internal `RwLock`s.
#[derive(Default)]
pub struct TunnelPool {
    inbound: RwLock<Vec<TunnelEntry>>,
    outbound: RwLock<Vec<TunnelEntry>>,
}

impl TunnelPool {
    /// Create an empty tunnel pool.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new inbound tunnel (starts in `Building` state).
    pub fn add_inbound(&self, info: TunnelInfo) {
        let entry = TunnelEntry {
            info,
            state: TunnelState::Building,
            created_ms: 0,
        };
        self.inbound.write().unwrap().push(entry);
    }

    /// Register a new outbound tunnel (starts in `Building` state).
    pub fn add_outbound(&self, info: TunnelInfo) {
        let entry = TunnelEntry {
            info,
            state: TunnelState::Building,
            created_ms: 0,
        };
        self.outbound.write().unwrap().push(entry);
    }

    /// Mark a tunnel as [`TunnelState::Active`].
    pub fn mark_active(&self, gateway: &Hash, tunnel_id: TunnelId) {
        Self::update_state(&self.inbound, gateway, tunnel_id, TunnelState::Active);
        Self::update_state(&self.outbound, gateway, tunnel_id, TunnelState::Active);
    }

    /// Mark a tunnel as [`TunnelState::Failed`].
    pub fn mark_failed(&self, gateway: &Hash, tunnel_id: TunnelId) {
        Self::update_state(&self.inbound, gateway, tunnel_id, TunnelState::Failed);
        Self::update_state(&self.outbound, gateway, tunnel_id, TunnelState::Failed);
    }

    /// Remove all tunnels that have expired according to [`TunnelInfo::is_expired`].
    pub fn expire_old(&self, now_ms: u64) {
        self.inbound
            .write()
            .unwrap()
            .retain(|e| !e.info.is_expired(now_ms));
        self.outbound
            .write()
            .unwrap()
            .retain(|e| !e.info.is_expired(now_ms));
    }

    /// Return clones of all active inbound tunnels.
    pub fn active_inbound(&self) -> Vec<TunnelInfo> {
        self.inbound
            .read()
            .unwrap()
            .iter()
            .filter(|e| e.state == TunnelState::Active)
            .map(|e| e.info.clone())
            .collect()
    }

    /// Return clones of all active outbound tunnels.
    pub fn active_outbound(&self) -> Vec<TunnelInfo> {
        self.outbound
            .read()
            .unwrap()
            .iter()
            .filter(|e| e.state == TunnelState::Active)
            .map(|e| e.info.clone())
            .collect()
    }

    /// Total number of inbound tunnels (all states).
    pub fn inbound_count(&self) -> usize {
        self.inbound.read().unwrap().len()
    }

    /// Total number of outbound tunnels (all states).
    pub fn outbound_count(&self) -> usize {
        self.outbound.read().unwrap().len()
    }

    fn update_state(
        pool: &RwLock<Vec<TunnelEntry>>,
        gateway: &Hash,
        tunnel_id: TunnelId,
        new_state: TunnelState,
    ) {
        for entry in pool.write().unwrap().iter_mut() {
            if entry.info.gateway() == Some(gateway)
                && entry
                    .info
                    .hops
                    .first()
                    .map(|h| h.receive_tunnel_id == tunnel_id)
                    .unwrap_or(false)
            {
                entry.state = new_state.clone();
                return;
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::tunnel::{HopConfig, TunnelDirection};

    fn make_tunnel(seed: u8, expiration: u64) -> TunnelInfo {
        let hop = HopConfig::new(
            Hash::sha256(&[seed]),
            seed as u32,
            None,
            None,
            [seed; 32],
            [seed; 32],
        );
        TunnelInfo {
            direction: TunnelDirection::Inbound,
            hops: vec![hop],
            expiration,
        }
    }

    #[test]
    fn add_and_count() {
        let pool = TunnelPool::new();
        pool.add_inbound(make_tunnel(1, 9999));
        pool.add_outbound(make_tunnel(2, 9999));
        assert_eq!(pool.inbound_count(), 1);
        assert_eq!(pool.outbound_count(), 1);
    }

    #[test]
    fn mark_active_and_query() {
        let pool = TunnelPool::new();
        let ti = make_tunnel(3, 99999);
        let gw = *ti.hops[0].router.as_bytes();
        let gw_hash = Hash::from_bytes(&gw).unwrap();
        let tid = ti.hops[0].receive_tunnel_id;
        pool.add_inbound(ti);
        assert_eq!(pool.active_inbound().len(), 0);
        pool.mark_active(&gw_hash, tid);
        assert_eq!(pool.active_inbound().len(), 1);
    }

    #[test]
    fn expire_old_removes_expired() {
        let pool = TunnelPool::new();
        pool.add_inbound(make_tunnel(4, 100)); // expires at 100ms
        pool.add_inbound(make_tunnel(5, 99999)); // far future
        pool.expire_old(200);
        assert_eq!(pool.inbound_count(), 1);
    }

    #[test]
    fn mark_failed_excludes_from_active() {
        let pool = TunnelPool::new();
        let ti = make_tunnel(6, 99999);
        let gw_hash = ti.hops[0].router;
        let tid = ti.hops[0].receive_tunnel_id;
        pool.add_inbound(ti);
        pool.mark_active(&gw_hash, tid);
        assert_eq!(pool.active_inbound().len(), 1);
        pool.mark_failed(&gw_hash, tid);
        assert_eq!(pool.active_inbound().len(), 0);
    }
}
