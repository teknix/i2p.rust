//! DatabaseStore (TYPE=1) — publish a RouterInfo or LeaseSet to the NetDB.
//!
//! Java equivalent: `net.i2p.data.i2np.DatabaseStoreMessage`

use crate::data::hash::Hash;
use crate::error::Result;
use crate::i2np::{I2npHeader, I2npMessage, TYPE_DATABASE_STORE};

/// Whether the stored entry is a `RouterInfo` or a `LeaseSet`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreType {
    /// `0` — a `RouterInfo`.
    RouterInfo = 0,
    /// `1` — a `LeaseSet`.
    LeaseSet = 1,
    /// `3` — an encrypted `LeaseSet2` (modern).
    EncryptedLeaseSet2 = 3,
}

impl TryFrom<u8> for StoreType {
    type Error = crate::error::Error;
    fn try_from(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::RouterInfo),
            1 => Ok(Self::LeaseSet),
            3 => Ok(Self::EncryptedLeaseSet2),
            _ => Err(crate::error::Error::DataFormat(format!(
                "unknown DatabaseStore type byte {v}"
            ))),
        }
    }
}

/// Publish a `RouterInfo` or `LeaseSet` to the NetDB.
///
/// If `reply_token` is non-zero the publishing router expects a
/// `DeliveryStatus` reply to confirm receipt.
#[derive(Debug, Clone)]
pub struct DatabaseStoreMessage {
    pub(crate) header: I2npHeader,
    /// SHA-256 key under which the entry is stored in the DHT.
    pub key: Hash,
    /// Whether this is a `RouterInfo` or `LeaseSet`.
    pub store_type: StoreType,
    /// Non-zero when a delivery-status reply is requested.
    pub reply_token: u32,
    /// Raw (optionally gzip-compressed) payload bytes of the stored entry.
    pub data: Vec<u8>,
}

impl DatabaseStoreMessage {
    /// Create a new `DatabaseStoreMessage`.
    pub fn new(
        header: I2npHeader,
        key: Hash,
        store_type: StoreType,
        reply_token: u32,
        data: Vec<u8>,
    ) -> Self {
        Self {
            header,
            key,
            store_type,
            reply_token,
            data,
        }
    }
}

impl I2npMessage for DatabaseStoreMessage {
    fn msg_type(&self) -> u8 {
        TYPE_DATABASE_STORE
    }

    fn header(&self) -> &I2npHeader {
        &self.header
    }

    fn write_payload(&self, buf: &mut Vec<u8>) -> Result<usize> {
        let start = buf.len();
        buf.extend_from_slice(self.key.as_bytes());
        buf.push(self.store_type.clone() as u8);
        buf.extend_from_slice(&self.reply_token.to_be_bytes());
        let len = self.data.len() as u16;
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&self.data);
        Ok(buf.len() - start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> I2npHeader {
        I2npHeader::new(TYPE_DATABASE_STORE, 42, u64::MAX)
    }

    #[test]
    fn store_type_round_trip() {
        assert_eq!(StoreType::try_from(0).unwrap(), StoreType::RouterInfo);
        assert_eq!(StoreType::try_from(1).unwrap(), StoreType::LeaseSet);
        assert!(StoreType::try_from(99).is_err());
    }

    #[test]
    fn write_payload_structure() {
        let key = Hash::sha256(b"key");
        let msg = DatabaseStoreMessage::new(
            header(),
            key,
            StoreType::RouterInfo,
            0,
            vec![0xBEu8; 10],
        );
        let mut buf = Vec::new();
        msg.write_payload(&mut buf).unwrap();
        // 32 (key) + 1 (type) + 4 (reply_token) + 2 (len) + 10 (data)
        assert_eq!(buf.len(), 32 + 1 + 4 + 2 + 10);
    }
}
