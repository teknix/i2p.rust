use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

use crate::error::{Result, SamError};

/// An I2P Destination — the public identity of an I2P endpoint.
///
/// A `Destination` consists of a 256-byte ElGamal public key, a 128-byte
/// DSA signing public-key, and a variable-length certificate.  The minimum
/// wire size for a DSA_SHA1 destination is 387 bytes (516 base-64 characters).
///
/// This type stores the raw binary form and exposes helpers for base-64
/// encoding/decoding that match the I2P base-64 alphabet (which is the
/// standard RFC 4648 alphabet, but with `+` replaced by `-` and `/` replaced
/// by `~`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    data: Vec<u8>,
}

/// Minimum byte length of a DSA_SHA1 (legacy) destination.
const MIN_DEST_BYTES: usize = 387;
/// Minimum base-64 character length of a DSA_SHA1 destination.
pub const MIN_DEST_B64_LEN: usize = 516;

impl Destination {
    /// Create a `Destination` from its raw binary representation.
    ///
    /// Returns [`SamError::DataFormat`] when the slice is shorter than the
    /// minimum valid destination length.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < MIN_DEST_BYTES {
            return Err(SamError::DataFormat(format!(
                "destination too short: {} bytes (minimum {})",
                data.len(),
                MIN_DEST_BYTES
            )));
        }
        Ok(Self {
            data: data.to_vec(),
        })
    }

    /// Decode a destination from the I2P base-64 representation.
    ///
    /// I2P base-64 uses `-` and `~` in place of `+` and `/`.
    ///
    /// Returns [`SamError::BadBase64Dest`] when the string cannot be decoded,
    /// and [`SamError::DataFormat`] when the decoded bytes are too short.
    pub fn from_base64(s: &str) -> Result<Self> {
        let normalised = s.replace('-', "+").replace('~', "/");
        let bytes = BASE64
            .decode(normalised.as_bytes())
            .map_err(|e| SamError::BadBase64Dest(e.to_string()))?;
        Self::from_bytes(&bytes)
    }

    /// Encode the destination as I2P base-64.
    pub fn to_base64(&self) -> String {
        BASE64
            .encode(&self.data)
            .replace('+', "-")
            .replace('/', "~")
    }

    /// Return the raw binary data of this destination.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Length of the binary destination in bytes.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` when the internal byte buffer is empty.
    ///
    /// Note: a valid `Destination` is never empty (minimum 387 bytes), so this
    /// will only be `true` for instances constructed unsafely.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal (387 zero bytes) synthetic destination used only in unit tests.
    fn dummy_dest_bytes() -> Vec<u8> {
        vec![0u8; MIN_DEST_BYTES]
    }

    #[test]
    fn round_trip_base64() {
        let dest = Destination::from_bytes(&dummy_dest_bytes()).unwrap();
        let encoded = dest.to_base64();
        let decoded = Destination::from_base64(&encoded).unwrap();
        assert_eq!(dest, decoded);
    }

    #[test]
    fn rejects_too_short() {
        let result = Destination::from_bytes(&[0u8; 100]);
        assert!(matches!(result, Err(SamError::DataFormat(_))));
    }

    #[test]
    fn rejects_bad_base64() {
        let result = Destination::from_base64("not-valid-base64!!!");
        assert!(matches!(result, Err(SamError::BadBase64Dest(_))));
    }
}
