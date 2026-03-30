//! TunnelData (TYPE=20) — the core tunnel message carrying 1028 bytes of
//! opaque, layered-encrypted data through a tunnel hop.
//!
//! Java equivalent: `net.i2p.data.i2np.TunnelDataMessage`

use crate::error::{Error, Result};
use crate::i2np::{I2npHeader, I2npMessage, TYPE_TUNNEL_DATA};

/// Fixed payload size of a `TunnelDataMessage` in bytes (I2P spec §4.3).
pub const TUNNEL_DATA_SIZE: usize = 1028;

/// Carries 1028 bytes of layered-encrypted data through one tunnel hop.
///
/// Each router in the tunnel decrypts one layer, reads the tunnel ID in the
/// clear, and forwards the message (still partially encrypted) to the next hop.
///
/// The payload is always exactly [`TUNNEL_DATA_SIZE`] bytes so that all
/// tunnel messages look identical on the wire — this prevents traffic-analysis
/// attacks based on message size.
#[derive(Debug, Clone)]
pub struct TunnelDataMessage {
    pub(crate) header: I2npHeader,
    /// Tunnel ID at the *receiving* end of this hop.
    pub tunnel_id: u32,
    /// Opaque, layered-encrypted 1028-byte payload.
    pub data: Box<[u8; TUNNEL_DATA_SIZE]>,
}

impl TunnelDataMessage {
    /// Create a new `TunnelDataMessage`.
    ///
    /// Returns [`Error::DataFormat`] when `data` is not exactly
    /// [`TUNNEL_DATA_SIZE`] bytes.
    pub fn new(header: I2npHeader, tunnel_id: u32, data: &[u8]) -> Result<Self> {
        if data.len() != TUNNEL_DATA_SIZE {
            return Err(Error::DataFormat(format!(
                "TunnelData payload must be exactly {TUNNEL_DATA_SIZE} bytes, got {}",
                data.len()
            )));
        }
        let mut arr = Box::new([0u8; TUNNEL_DATA_SIZE]);
        arr.copy_from_slice(data);
        Ok(Self {
            header,
            tunnel_id,
            data: arr,
        })
    }
}

impl I2npMessage for TunnelDataMessage {
    fn msg_type(&self) -> u8 {
        TYPE_TUNNEL_DATA
    }

    fn header(&self) -> &I2npHeader {
        &self.header
    }

    fn write_payload(&self, buf: &mut Vec<u8>) -> Result<usize> {
        buf.extend_from_slice(&self.tunnel_id.to_be_bytes());
        buf.extend_from_slice(self.data.as_ref());
        Ok(4 + TUNNEL_DATA_SIZE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> I2npHeader {
        I2npHeader::new(TYPE_TUNNEL_DATA, 1, u64::MAX)
    }

    #[test]
    fn new_ok() {
        let msg = TunnelDataMessage::new(header(), 99, &[0u8; TUNNEL_DATA_SIZE]);
        assert!(msg.is_ok());
    }

    #[test]
    fn wrong_size_rejected() {
        let msg = TunnelDataMessage::new(header(), 99, &[0u8; 100]);
        assert!(matches!(msg, Err(crate::error::Error::DataFormat(_))));
    }

    #[test]
    fn write_payload_size() {
        let msg = TunnelDataMessage::new(header(), 99, &[0u8; TUNNEL_DATA_SIZE]).unwrap();
        let mut buf = Vec::new();
        let n = msg.write_payload(&mut buf).unwrap();
        assert_eq!(n, 4 + TUNNEL_DATA_SIZE);
        assert_eq!(buf.len(), n);
    }
}
