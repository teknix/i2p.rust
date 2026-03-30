//! Tunnel pipeline traits — gateway, participant, and endpoint processing.
//!
//! From the tech-intro:
//! *"The tunnel gateway accumulates a number of tunnel messages, eventually
//! preprocessing them into something for tunnel delivery … the endpoint
//! receives the fully decrypted messages and delivers them."*
//!
//! Java equivalents:
//! - [`TunnelGateway`] ← `TunnelGateway` (abstract class)
//! - [`TunnelParticipant`] ← `TunnelParticipant` (interface)
//! - [`TunnelEndpoint`] ← `InboundEndpointProcessor` / `OutboundTunnelEndpoint`

use async_trait::async_trait;

use crate::error::Result;
use crate::i2np::tunnel_data::TunnelDataMessage;
use crate::tunnel::TunnelId;

// ── TunnelGateway ─────────────────────────────────────────────────────────────

/// The first hop in a tunnel — fragments and encrypts application messages
/// before sending them into the tunnel.
///
/// The gateway accumulates messages, pre-applies the necessary encryption
/// layers (for outbound tunnels the creator pre-decrypts so that after all
/// intermediate hops add their layers, the endpoint sees plaintext), and
/// emits fixed-size [`TunnelDataMessage`]s.
#[async_trait]
pub trait TunnelGateway: Send + Sync {
    /// Accept a raw I2NP message payload and queue it for tunnel delivery.
    ///
    /// The gateway fragments large payloads and coalesces small ones to fill
    /// the fixed 1028-byte tunnel data frame.
    async fn send(&self, payload: Vec<u8>) -> Result<()>;

    /// Return the outbound tunnel ID at this gateway.
    fn tunnel_id(&self) -> TunnelId;
}

// ── TunnelParticipant ─────────────────────────────────────────────────────────

/// An intermediate hop in a tunnel — peels one AES-256 layer and forwards on.
///
/// The participant cannot read the plaintext payload; it only sees the
/// partially decrypted (and therefore opaque) bytes after removing its layer.
///
/// Java equivalent: `TunnelParticipant`
#[async_trait]
pub trait TunnelParticipant: Send + Sync {
    /// Process an inbound [`TunnelDataMessage`]: decrypt one layer and forward
    /// it to the next hop.
    async fn process(&self, msg: TunnelDataMessage) -> Result<()>;

    /// Tunnel ID at which this participant receives messages.
    fn receive_tunnel_id(&self) -> TunnelId;
}

// ── TunnelEndpoint ────────────────────────────────────────────────────────────

/// The last hop in a tunnel — fully decrypts the payload and delivers it.
///
/// For an **inbound** tunnel the endpoint is the tunnel creator, who holds all
/// the keys.  For an **outbound** tunnel the endpoint receives the fully-clear
/// payload and routes it according to the delivery instructions.
///
/// Java equivalents: `InboundEndpointProcessor`, `OutboundTunnelEndpoint`
#[async_trait]
pub trait TunnelEndpoint: Send + Sync {
    /// Receive a fully-decrypted I2NP message payload and deliver it.
    async fn deliver(&self, payload: Vec<u8>) -> Result<()>;

    /// Tunnel ID at which this endpoint receives messages.
    fn receive_tunnel_id(&self) -> TunnelId;
}
