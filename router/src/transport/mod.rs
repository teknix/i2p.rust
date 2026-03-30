//! Transport layer — router-to-router communication (NTCP2 / SSU2).
//!
//! From the tech-intro:
//! *"I2P currently supports two transport protocols, NTCP2 over TCP, and SSU2
//! over UDP … I2P supports multiple transports simultaneously. A particular
//! transport for an outbound connection is selected with 'bids'."*
//!
//! This module defines the [`Transport`] trait and [`TransportBid`] type that
//! are used by the router to select the best transport for each outbound
//! message.  Concrete implementations (NTCP2, SSU2) are separate crates.

pub mod bandwidth;

use std::net::SocketAddr;

use async_trait::async_trait;

use crate::data::hash::Hash;
use crate::data::router_info::RouterInfo;
use crate::error::Result;

// ── TransportBid ──────────────────────────────────────────────────────────────

/// A cost estimate returned by a transport when asked whether it can deliver
/// a message.
///
/// Lower bid values are preferred.  A transport returns `None` from
/// [`Transport::bid`] when it cannot handle the message at all.
///
/// Java equivalent: `net.i2p.router.transport.TransportBid`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportBid {
    /// Transport style that made this bid (e.g. `"NTCP2"`, `"SSU2"`).
    pub transport_style: String,
    /// Estimated latency in milliseconds.
    pub latency_ms: u32,
    /// Whether there is already an established session to this peer.
    pub reuse_existing: bool,
}

impl TransportBid {
    /// Base cost for a new session.
    pub const NEW_SESSION_COST: u32 = 1_000;
    /// Base cost when reusing an existing session (much cheaper).
    pub const EXISTING_SESSION_COST: u32 = 100;

    /// Create a bid for a new session.
    pub fn new_session(transport_style: impl Into<String>, latency_ms: u32) -> Self {
        Self {
            transport_style: transport_style.into(),
            latency_ms: latency_ms + Self::NEW_SESSION_COST,
            reuse_existing: false,
        }
    }

    /// Create a bid reusing an existing session.
    pub fn existing_session(transport_style: impl Into<String>, latency_ms: u32) -> Self {
        Self {
            transport_style: transport_style.into(),
            latency_ms: latency_ms + Self::EXISTING_SESSION_COST,
            reuse_existing: true,
        }
    }
}

impl PartialOrd for TransportBid {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TransportBid {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.latency_ms.cmp(&other.latency_ms)
    }
}

// ── Transport trait ───────────────────────────────────────────────────────────

/// Abstraction over a single transport protocol (NTCP2 or SSU2).
///
/// The router holds a list of transports and calls [`Transport::bid`] on each
/// when it wants to send a message.  The transport with the lowest bid wins.
///
/// Java equivalent: `net.i2p.router.transport.Transport`
#[async_trait]
pub trait Transport: Send + Sync {
    /// Human-readable identifier, e.g. `"NTCP2"` or `"SSU2"`.
    fn style(&self) -> &str;

    /// Return a bid if this transport can deliver `size` bytes to `peer`,
    /// or `None` if it cannot.
    fn bid(&self, peer: &RouterInfo, size: usize) -> Option<TransportBid>;

    /// Send `data` to `peer` asynchronously.
    async fn send(&self, peer: &RouterInfo, data: Vec<u8>) -> Result<()>;

    /// Return `true` when an active session to `peer_hash` already exists.
    fn is_connected(&self, peer_hash: &Hash) -> bool;

    /// Return the local address this transport is bound to, if applicable.
    fn local_addr(&self) -> Option<SocketAddr>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bid_ordering() {
        let cheap = TransportBid::existing_session("SSU2", 10);
        let expensive = TransportBid::new_session("NTCP2", 10);
        assert!(cheap < expensive);
    }

    #[test]
    fn new_session_cost_higher() {
        let b = TransportBid::new_session("NTCP2", 0);
        assert_eq!(b.latency_ms, TransportBid::NEW_SESSION_COST);
    }

    #[test]
    fn existing_session_cost_lower() {
        let b = TransportBid::existing_session("SSU2", 0);
        assert_eq!(b.latency_ms, TransportBid::EXISTING_SESSION_COST);
    }
}
