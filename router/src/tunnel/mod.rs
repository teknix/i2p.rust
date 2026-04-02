//! Tunnel layer — building and operating layered-encrypted directed paths.
//!
//! From the tech-intro:
//! *"A tunnel is a directed path through an explicitly selected list of
//! routers. Layered encryption is used, so each of the routers can only
//! decrypt a single layer."*
//!
//! This module defines:
//! - [`TunnelId`] — the 4-byte identifier used at each hop
//! - [`TunnelInfo`] — the structural description of a tunnel
//! - [`HopConfig`] — per-hop parameters used during tunnel construction
//! - [`TunnelRole`] — whether this router is the gateway, participant, or endpoint
//! - The pipeline traits: [`TunnelGateway`], [`TunnelParticipant`],
//!   [`TunnelEndpoint`]

pub mod pipeline;
pub mod builder;
pub mod manager;

pub use pipeline::{TunnelEndpoint, TunnelGateway, TunnelParticipant};

use crate::data::hash::Hash;

// ── TunnelId ──────────────────────────────────────────────────────────────────

/// A 4-byte tunnel identifier.
///
/// Each hop in a tunnel receives messages addressed to a specific `TunnelId`.
/// The gateway, each intermediate hop, and the endpoint all have distinct IDs.
pub type TunnelId = u32;

// ── TunnelRole ────────────────────────────────────────────────────────────────

/// This router's role in a given tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelRole {
    /// The first hop — receives fragmented/preprocessed data from the creator
    /// and begins forwarding it into the tunnel.
    Gateway,
    /// An intermediate hop — peels one encryption layer and forwards on.
    Participant,
    /// The last hop — fully decrypts and delivers the messages.
    Endpoint,
}

// ── HopConfig ─────────────────────────────────────────────────────────────────

/// Per-hop configuration embedded in a tunnel build record.
///
/// Each hop in the proposed tunnel receives a [`HopConfig`] (encrypted to its
/// public key) describing its part in the tunnel.
///
/// Java equivalent: `net.i2p.router.tunnel.HopConfig`
#[derive(Debug, Clone)]
pub struct HopConfig {
    /// Identity hash of the router that will fill this hop.
    pub router: Hash,
    /// Tunnel ID at which this hop receives inbound messages.
    pub receive_tunnel_id: TunnelId,
    /// Tunnel ID this hop sends messages on to the next hop.  `None` for the
    /// endpoint (it delivers messages locally).
    pub send_tunnel_id: Option<TunnelId>,
    /// Identity hash of the *next* hop, or `None` for the endpoint.
    pub next_router: Option<Hash>,
    /// AES-256 layer key for this hop (used to add/remove the encryption layer).
    pub layer_key: [u8; 32],
    /// AES-256 IV key for this hop.
    pub iv_key: [u8; 32],
}

impl HopConfig {
    /// Create a new hop configuration.
    pub fn new(
        router: Hash,
        receive_tunnel_id: TunnelId,
        send_tunnel_id: Option<TunnelId>,
        next_router: Option<Hash>,
        layer_key: [u8; 32],
        iv_key: [u8; 32],
    ) -> Self {
        Self {
            router,
            receive_tunnel_id,
            send_tunnel_id,
            next_router,
            layer_key,
            iv_key,
        }
    }
}

// ── TunnelInfo ────────────────────────────────────────────────────────────────

/// The structural description of a tunnel — who is at each hop, in order.
///
/// The creator stores this to know how to build and use the tunnel.
///
/// Java equivalent: `net.i2p.router.TunnelInfo`
#[derive(Debug, Clone)]
pub struct TunnelInfo {
    /// Whether this is an inbound or outbound tunnel.
    pub direction: TunnelDirection,
    /// Ordered list of hops, index 0 = gateway.
    pub hops: Vec<HopConfig>,
    /// Absolute expiry timestamp (milliseconds since epoch).  Tunnels are
    /// typically valid for ~10 minutes.
    pub expiration: u64,
}

/// Whether a tunnel carries messages toward or away from the creator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelDirection {
    /// Sends messages *away* from the creator.
    Outbound,
    /// Delivers messages *to* the creator.
    Inbound,
}

impl TunnelInfo {
    /// Number of hops in this tunnel.
    pub fn len(&self) -> usize {
        self.hops.len()
    }

    /// Return `true` when the tunnel has no hops (should not happen in practice).
    pub fn is_empty(&self) -> bool {
        self.hops.is_empty()
    }

    /// Identity hash of the gateway router (first hop).
    pub fn gateway(&self) -> Option<&Hash> {
        self.hops.first().map(|h| &h.router)
    }

    /// Identity hash of the endpoint router (last hop).
    pub fn endpoint(&self) -> Option<&Hash> {
        self.hops.last().map(|h| &h.router)
    }

    /// Return `true` if this tunnel has expired relative to `now_ms`.
    pub fn is_expired(&self, now_ms: u64) -> bool {
        self.expiration < now_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hop(seed: u8) -> HopConfig {
        HopConfig::new(
            Hash::sha256(&[seed]),
            seed as u32,
            Some(seed as u32 + 1),
            Some(Hash::sha256(&[seed + 1])),
            [seed; 32],
            [seed + 1; 32],
        )
    }

    #[test]
    fn tunnel_info_gateway_endpoint() {
        let hops = vec![make_hop(1), make_hop(2), make_hop(3)];
        let ti = TunnelInfo {
            direction: TunnelDirection::Outbound,
            hops,
            expiration: 9999,
        };
        assert_eq!(ti.gateway(), Some(&Hash::sha256(&[1])));
        assert_eq!(ti.endpoint(), Some(&Hash::sha256(&[3])));
        assert_eq!(ti.len(), 3);
    }

    #[test]
    fn expiry() {
        let ti = TunnelInfo {
            direction: TunnelDirection::Inbound,
            hops: vec![make_hop(1)],
            expiration: 500,
        };
        assert!(ti.is_expired(600));
        assert!(!ti.is_expired(400));
    }
}
