//! I2P Network Protocol (I2NP) messages.
//!
//! I2NP is the message protocol that routers use to communicate with each
//! other.  Every I2NP message has a common header:
//!
//! ```text
//! type        (1 byte)
//! message_id  (4 bytes, big-endian u32)
//! expiration  (8 bytes, big-endian u64, milliseconds since epoch)
//! size        (2 bytes, big-endian u16, payload length)
//! payload     (<size> bytes)
//! ```
//!
//! Java equivalent: `net.i2p.data.i2np.I2NPMessage` and its implementations.

pub mod database_lookup;
pub mod database_search_reply;
pub mod database_store;
pub mod garlic;
pub mod tunnel_build;
pub mod tunnel_data;

pub use database_lookup::DatabaseLookupMessage;
pub use database_search_reply::DatabaseSearchReplyMessage;
pub use database_store::DatabaseStoreMessage;
pub use garlic::{GarlicClove, GarlicMessage};
pub use tunnel_build::{BuildRecord, TunnelBuildMessage};
pub use tunnel_data::TunnelDataMessage;

use crate::error::Result;

// ── Message type codes ────────────────────────────────────────────────────────

/// I2NP message type: `DatabaseStore` (TYPE=1).
pub const TYPE_DATABASE_STORE: u8 = 1;
/// I2NP message type: `DatabaseLookup` (TYPE=2).
pub const TYPE_DATABASE_LOOKUP: u8 = 2;
/// I2NP message type: `DatabaseSearchReply` (TYPE=3).
pub const TYPE_DATABASE_SEARCH_REPLY: u8 = 3;
/// I2NP message type: `DeliveryStatus` (TYPE=10).
pub const TYPE_DELIVERY_STATUS: u8 = 10;
/// I2NP message type: `Garlic` (TYPE=11).
pub const TYPE_GARLIC: u8 = 11;
/// I2NP message type: `TunnelData` (TYPE=20).
pub const TYPE_TUNNEL_DATA: u8 = 20;
/// I2NP message type: `TunnelBuild` (TYPE=21).
pub const TYPE_TUNNEL_BUILD: u8 = 21;
/// I2NP message type: `TunnelBuildReply` (TYPE=22).
pub const TYPE_TUNNEL_BUILD_REPLY: u8 = 22;
/// I2NP message type: `VariableTunnelBuild` (TYPE=23).
pub const TYPE_VARIABLE_TUNNEL_BUILD: u8 = 23;
/// I2NP message type: `VariableTunnelBuildReply` (TYPE=24).
pub const TYPE_VARIABLE_TUNNEL_BUILD_REPLY: u8 = 24;
/// I2NP message type: `ShortTunnelBuild` (TYPE=25).
pub const TYPE_SHORT_TUNNEL_BUILD: u8 = 25;
/// I2NP message type: `TunnelGateway` (TYPE=26).
pub const TYPE_TUNNEL_GATEWAY: u8 = 26;
/// I2NP message type: `Data` (TYPE=18).
pub const TYPE_DATA: u8 = 18;

// ── Common I2NP header ────────────────────────────────────────────────────────

/// The fixed-length common header that precedes every I2NP message payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct I2npHeader {
    /// Message type byte.
    pub msg_type: u8,
    /// Unique 32-bit message identifier (random, used for deduplication).
    pub message_id: u32,
    /// Absolute expiry time in milliseconds since the Unix epoch.
    pub expiration: u64,
}

impl I2npHeader {
    /// Total wire size of the common header in bytes (type + id + expiry + size).
    pub const WIRE_LEN: usize = 1 + 4 + 8 + 2;

    /// Create a new header.
    pub fn new(msg_type: u8, message_id: u32, expiration: u64) -> Self {
        Self {
            msg_type,
            message_id,
            expiration,
        }
    }

    /// Return `true` if this message has expired relative to `now_ms`.
    pub fn is_expired(&self, now_ms: u64) -> bool {
        self.expiration < now_ms
    }
}

// ── I2npMessage trait ─────────────────────────────────────────────────────────

/// A parsed I2NP message.
///
/// Every concrete I2NP message type implements this trait so that generic
/// router code can handle them uniformly — verify expiry, log type, etc.
pub trait I2npMessage: Send + Sync {
    /// Return the I2NP type byte for this message (one of the `TYPE_*`
    /// constants).
    fn msg_type(&self) -> u8;

    /// Return the common header.
    fn header(&self) -> &I2npHeader;

    /// Return `true` if the message has expired relative to `now_ms`
    /// (milliseconds since epoch).
    fn is_expired(&self, now_ms: u64) -> bool {
        self.header().is_expired(now_ms)
    }

    /// Serialise the message payload (excluding the common header) into
    /// `buf`.  Returns the number of bytes written.
    fn write_payload(&self, buf: &mut Vec<u8>) -> Result<usize>;
}
