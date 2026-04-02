//! I2P Router — Rust implementation of the I2P network router.
//!
//! This crate implements the I2P **router** as described in the
//! [I2P Technical Introduction](https://geti2p.net/en/docs/how/tech-intro).
//!
//! # What is "the router"?
//!
//! From the tech-intro:
//! > *"I2P makes a strict separation between the software participating in the
//! > network (a 'router') and the anonymous endpoints ('destinations')
//! > associated with individual applications."*
//!
//! The **router** handles:
//!
//! | Subsystem | Description |
//! |-----------|-------------|
//! | [`data`] | Core I2P data structures (RouterInfo, LeaseSet, Destination, Hash) |
//! | [`i2np`] | I2P Network Protocol messages (TunnelData, TunnelBuild, DatabaseStore/Lookup, Garlic) |
//! | [`netdb`] | Network Database — Kademlia DHT storing RouterInfos and LeaseSets |
//! | [`transport`] | Router-to-router transport layer (NTCP2 / SSU2 traits, bandwidth limiter) |
//! | [`tunnel`] | Tunnel pipeline — gateway, participant, endpoint |
//! | [`crypto`] | Cryptographic primitives: SHA-256, AES-256/CBC, ChaCha20-Poly1305, X25519, Ed25519 |
//!
//! # What is NOT in this crate
//!
//! The following are **application-layer** components that run *on top of* the
//! router and are intentionally kept in Java:
//!
//! - **SAM bridge** (`apps/sam/`) — application API for third-party clients
//! - **I2PTunnel** (`apps/i2ptunnel/`) — TCP proxying
//! - **I2PSnark** — BitTorrent client
//! - **Susimail** — e-mail client
//! - **Streaming library** — TCP-like streams over I2P
//! - **Naming / Address Book** — human-readable `.i2p` names
//!
//! # Cryptography
//!
//! Per the 2025-01 tech-intro, the primary primitives are:
//! - **X25519** — key exchange (NTCP2, SSU2, ECIES-Ratchet)
//! - **Ed25519** — signing (RouterInfo, LeaseSet)
//! - **ChaCha20-Poly1305** — authenticated encryption (NTCP2, SSU2, ECIES-Ratchet)
//! - **SHA-256** — hashing (routing keys, integrity)
//! - **AES-256/CBC** — tunnel layer encryption

pub mod crypto;
pub mod data;
pub mod error;
pub mod i2np;
pub mod netdb;
pub mod peer_profile;
pub mod reseed;
pub mod router;
pub mod transport;
pub mod tunnel;

// Convenience re-exports of the most commonly used types.
pub use data::{Destination, Hash, Lease, LeaseSet, RouterAddress, RouterIdentity, RouterInfo};
pub use error::{Error, Result};
pub use netdb::{MemoryNetDb, NetDb};
pub use peer_profile::PeerProfileStore;
pub use router::{Router, RouterConfig, RouterHandle};
pub use transport::{Transport, TransportBid};
pub use transport::ntcp2::Ntcp2Transport;
pub use tunnel::{HopConfig, TunnelDirection, TunnelId, TunnelInfo, TunnelRole};
pub use tunnel::manager::TunnelPool;
pub use tunnel::builder::TunnelBuilder;
