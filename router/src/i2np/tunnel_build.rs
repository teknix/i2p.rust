//! Tunnel build messages — used to negotiate the construction of a tunnel.
//!
//! Three variants exist (from the I2P spec):
//! - **TunnelBuildMessage** (TYPE=21): 8 fixed 528-byte records
//! - **VariableTunnelBuildMessage** (TYPE=23): variable record count
//! - **ShortTunnelBuildMessage** (TYPE=25): 4-byte records (optimised)
//!
//! Each record is addressed to one hop in the proposed tunnel and is
//! encrypted to that hop's public key.  A router that receives a build message
//! finds the record addressed to it, decrypts it, and either agrees or refuses
//! to participate, replacing the record with an encrypted reply.
//!
//! Java equivalent: `net.i2p.data.i2np.TunnelBuildMessage` (and variants)

use crate::error::Result;
use crate::i2np::{I2npHeader, I2npMessage, TYPE_TUNNEL_BUILD, TYPE_VARIABLE_TUNNEL_BUILD};

/// Byte length of a standard build record (encrypted, opaque to intermediaries).
pub const BUILD_RECORD_SIZE: usize = 528;
/// Byte length of a short build record (ShortTunnelBuild, TYPE=25).
pub const SHORT_BUILD_RECORD_SIZE: usize = 218;
/// Number of records in a standard TunnelBuildMessage.
pub const STANDARD_RECORD_COUNT: usize = 8;

/// One encrypted hop record inside a tunnel build message.
///
/// An intermediary router decrypts the record addressed to it (identified by
/// the encrypted `router_hash` prefix), and fills in the reply bits before
/// passing the message on.
#[derive(Debug, Clone)]
pub struct BuildRecord {
    /// Raw encrypted record bytes.  Size is either [`BUILD_RECORD_SIZE`] or
    /// [`SHORT_BUILD_RECORD_SIZE`].
    pub data: Vec<u8>,
}

impl BuildRecord {
    /// Create a [`BuildRecord`] from raw bytes.
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}

/// A tunnel build request message.
///
/// Contains `records.len()` [`BuildRecord`]s, one per proposed tunnel hop
/// (plus decoys to hide the tunnel length).
///
/// The type byte written to the wire depends on whether the record count is
/// the standard 8 (`TYPE_TUNNEL_BUILD`) or variable
/// (`TYPE_VARIABLE_TUNNEL_BUILD`).
#[derive(Debug, Clone)]
pub struct TunnelBuildMessage {
    pub(crate) header: I2npHeader,
    /// Encrypted hop records.
    pub records: Vec<BuildRecord>,
}

impl TunnelBuildMessage {
    /// Create a [`TunnelBuildMessage`].
    pub fn new(header: I2npHeader, records: Vec<BuildRecord>) -> Self {
        Self { header, records }
    }
}

impl I2npMessage for TunnelBuildMessage {
    fn msg_type(&self) -> u8 {
        if self.records.len() == STANDARD_RECORD_COUNT {
            TYPE_TUNNEL_BUILD
        } else {
            TYPE_VARIABLE_TUNNEL_BUILD
        }
    }

    fn header(&self) -> &I2npHeader {
        &self.header
    }

    fn write_payload(&self, buf: &mut Vec<u8>) -> Result<usize> {
        let start = buf.len();
        // Variable-count messages prefix with the record count byte.
        if self.msg_type() == TYPE_VARIABLE_TUNNEL_BUILD {
            buf.push(self.records.len() as u8);
        }
        for rec in &self.records {
            buf.extend_from_slice(&rec.data);
        }
        Ok(buf.len() - start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(t: u8) -> I2npHeader {
        I2npHeader::new(t, 1, u64::MAX)
    }

    #[test]
    fn standard_type_byte() {
        let records: Vec<_> = (0..STANDARD_RECORD_COUNT)
            .map(|_| BuildRecord::new(vec![0u8; BUILD_RECORD_SIZE]))
            .collect();
        let msg = TunnelBuildMessage::new(header(TYPE_TUNNEL_BUILD), records);
        assert_eq!(msg.msg_type(), TYPE_TUNNEL_BUILD);
    }

    #[test]
    fn variable_type_byte() {
        let records: Vec<_> = (0..3)
            .map(|_| BuildRecord::new(vec![0u8; BUILD_RECORD_SIZE]))
            .collect();
        let msg = TunnelBuildMessage::new(header(TYPE_VARIABLE_TUNNEL_BUILD), records);
        assert_eq!(msg.msg_type(), TYPE_VARIABLE_TUNNEL_BUILD);
    }

    #[test]
    fn write_payload_variable_has_count_prefix() {
        let records: Vec<_> = (0..3)
            .map(|_| BuildRecord::new(vec![0xAA; BUILD_RECORD_SIZE]))
            .collect();
        let msg = TunnelBuildMessage::new(header(TYPE_VARIABLE_TUNNEL_BUILD), records);
        let mut buf = Vec::new();
        msg.write_payload(&mut buf).unwrap();
        // First byte is record count.
        assert_eq!(buf[0], 3);
        assert_eq!(buf.len(), 1 + 3 * BUILD_RECORD_SIZE);
    }
}
