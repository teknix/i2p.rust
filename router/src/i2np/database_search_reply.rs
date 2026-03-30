//! DatabaseSearchReply (TYPE=3) — NetDB reply listing closer peers.
//!
//! When a floodfill cannot answer a `DatabaseLookupMessage` directly, it
//! replies with a list of router hashes that are closer (in XOR distance) to
//! the requested key.  The querying router then repeats the lookup to those
//! peers — this is I2P's iterative DHT lookup.
//!
//! Java equivalent: `net.i2p.data.i2np.DatabaseSearchReplyMessage`

use crate::data::hash::Hash;
use crate::error::Result;
use crate::i2np::{I2npHeader, I2npMessage, TYPE_DATABASE_SEARCH_REPLY};

/// Reply to a `DatabaseLookupMessage` containing up to 3 closer peer hashes.
#[derive(Debug, Clone)]
pub struct DatabaseSearchReplyMessage {
    pub(crate) header: I2npHeader,
    /// The key that was looked up (echoed back so the querier can correlate).
    pub key: Hash,
    /// Hashes of routers that are closer to `key` than the replying peer.
    /// The spec allows up to 3 entries per reply.
    pub peers: Vec<Hash>,
    /// Hash of the router that sent this reply.
    pub from: Hash,
}

impl DatabaseSearchReplyMessage {
    /// Maximum number of peer hashes per reply (spec limit).
    pub const MAX_PEERS: usize = 3;

    /// Create a new reply.
    pub fn new(header: I2npHeader, key: Hash, peers: Vec<Hash>, from: Hash) -> Self {
        Self {
            header,
            key,
            peers,
            from,
        }
    }
}

impl I2npMessage for DatabaseSearchReplyMessage {
    fn msg_type(&self) -> u8 {
        TYPE_DATABASE_SEARCH_REPLY
    }

    fn header(&self) -> &I2npHeader {
        &self.header
    }

    fn write_payload(&self, buf: &mut Vec<u8>) -> Result<usize> {
        let start = buf.len();
        buf.extend_from_slice(self.key.as_bytes());
        buf.push(self.peers.len() as u8);
        for peer in &self.peers {
            buf.extend_from_slice(peer.as_bytes());
        }
        buf.extend_from_slice(self.from.as_bytes());
        Ok(buf.len() - start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> I2npHeader {
        I2npHeader::new(TYPE_DATABASE_SEARCH_REPLY, 3, u64::MAX)
    }

    #[test]
    fn write_payload_with_peers() {
        let key = Hash::sha256(b"k");
        let from = Hash::sha256(b"me");
        let peers = vec![Hash::sha256(b"p1"), Hash::sha256(b"p2")];
        let msg = DatabaseSearchReplyMessage::new(header(), key, peers, from);
        let mut buf = Vec::new();
        msg.write_payload(&mut buf).unwrap();
        // 32 (key) + 1 (count) + 2*32 (peers) + 32 (from) = 129
        assert_eq!(buf.len(), 129);
        assert_eq!(buf[32], 2); // peer count byte
    }
}
