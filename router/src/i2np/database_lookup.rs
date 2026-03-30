//! DatabaseLookup (TYPE=2) — query the NetDB for a RouterInfo or LeaseSet.
//!
//! Java equivalent: `net.i2p.data.i2np.DatabaseLookupMessage`

use crate::data::hash::Hash;
use crate::error::Result;
use crate::i2np::{I2npHeader, I2npMessage, TYPE_DATABASE_LOOKUP};

/// Delivery type flags embedded in the lookup flags byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupType {
    /// Standard `RouterInfo` lookup (flag bits `0b00`).
    RouterInfo = 0,
    /// `LeaseSet` lookup (flag bits `0b01`).
    LeaseSet = 1,
    /// Encrypted `LeaseSet2` lookup (flag bits `0b10`).
    EncryptedLeaseSet = 2,
    /// Exploratory lookup (flag bits `0b11`).
    Exploratory = 3,
}

/// Query the NetDB for a router or destination by its SHA-256 key.
///
/// If `reply_tunnel_id` / `reply_gateway` are set, the response is sent back
/// through the specified inbound tunnel instead of directly.
#[derive(Debug, Clone)]
pub struct DatabaseLookupMessage {
    pub(crate) header: I2npHeader,
    /// SHA-256 key to look up.
    pub key: Hash,
    /// Hash of the router that is asking; used to avoid sending the reply to
    /// the originator's own floodfill.
    pub from: Hash,
    /// What kind of entry is being requested.
    pub lookup_type: LookupType,
    /// Tunnel ID for the reply, or `0` to reply directly.
    pub reply_tunnel_id: u32,
    /// Gateway router hash for tunnelled replies; ignored when
    /// `reply_tunnel_id == 0`.
    pub reply_gateway: Option<Hash>,
    /// Hashes of peers that have already been queried (exclude them from the
    /// `DatabaseSearchReply`).
    pub excluded_peers: Vec<Hash>,
}

impl DatabaseLookupMessage {
    /// Create a new lookup message.
    pub fn new(
        header: I2npHeader,
        key: Hash,
        from: Hash,
        lookup_type: LookupType,
    ) -> Self {
        Self {
            header,
            key,
            from,
            lookup_type,
            reply_tunnel_id: 0,
            reply_gateway: None,
            excluded_peers: Vec::new(),
        }
    }

    /// Request that the reply be delivered via a specific inbound tunnel.
    pub fn with_reply_tunnel(mut self, gateway: Hash, tunnel_id: u32) -> Self {
        self.reply_gateway = Some(gateway);
        self.reply_tunnel_id = tunnel_id;
        self
    }
}

impl I2npMessage for DatabaseLookupMessage {
    fn msg_type(&self) -> u8 {
        TYPE_DATABASE_LOOKUP
    }

    fn header(&self) -> &I2npHeader {
        &self.header
    }

    fn write_payload(&self, buf: &mut Vec<u8>) -> Result<usize> {
        let start = buf.len();
        buf.extend_from_slice(self.key.as_bytes());
        buf.extend_from_slice(self.from.as_bytes());

        // Flags byte: bit0 = reply tunnel flag, bits 3-2 = lookup type
        let mut flags: u8 = (self.lookup_type as u8) << 2;
        if self.reply_tunnel_id != 0 {
            flags |= 0x01;
        }
        if !self.excluded_peers.is_empty() {
            flags |= 0x02;
        }
        buf.push(flags);

        if self.reply_tunnel_id != 0 {
            if let Some(gw) = &self.reply_gateway {
                buf.extend_from_slice(gw.as_bytes());
            } else {
                buf.extend_from_slice(&[0u8; 32]);
            }
            buf.extend_from_slice(&self.reply_tunnel_id.to_be_bytes());
        }

        if !self.excluded_peers.is_empty() {
            let count = self.excluded_peers.len() as u16;
            buf.extend_from_slice(&count.to_be_bytes());
            for peer in &self.excluded_peers {
                buf.extend_from_slice(peer.as_bytes());
            }
        }

        Ok(buf.len() - start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> I2npHeader {
        I2npHeader::new(TYPE_DATABASE_LOOKUP, 7, u64::MAX)
    }

    #[test]
    fn simple_lookup_payload() {
        let key = Hash::sha256(b"key");
        let from = Hash::sha256(b"from");
        let msg = DatabaseLookupMessage::new(header(), key, from, LookupType::RouterInfo);
        let mut buf = Vec::new();
        msg.write_payload(&mut buf).unwrap();
        // 32 (key) + 32 (from) + 1 (flags) = 65
        assert_eq!(buf.len(), 65);
    }

    #[test]
    fn lookup_with_reply_tunnel() {
        let key = Hash::sha256(b"key");
        let from = Hash::sha256(b"from");
        let gw = Hash::sha256(b"gw");
        let msg = DatabaseLookupMessage::new(header(), key, from, LookupType::LeaseSet)
            .with_reply_tunnel(gw, 12345);
        let mut buf = Vec::new();
        msg.write_payload(&mut buf).unwrap();
        // 32 + 32 + 1 (flags) + 32 (gw) + 4 (tunnel_id) = 101
        assert_eq!(buf.len(), 101);
    }
}
