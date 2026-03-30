/// Errors that can occur in the SAM protocol layer.
///
/// This maps to the exception hierarchy used in the Java implementation:
/// - [`SamError::DataFormat`]  ← `net.i2p.data.DataFormatException`
/// - [`SamError::Session`]     ← `net.i2p.client.I2PSessionException`
/// - [`SamError::Protocol`]    ← `net.i2p.sam.SAMException`
/// - [`SamError::Io`]          ← `java.io.IOException`
#[derive(Debug, thiserror::Error)]
pub enum SamError {
    /// An I/O error occurred on the underlying transport.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A destination or key could not be decoded or was otherwise malformed.
    #[error("Data format error: {0}")]
    DataFormat(String),

    /// The I2CP/I2P session reported an error (e.g. session closed, timeout).
    #[error("Session error: {0}")]
    Session(String),

    /// The SAM client sent a malformed or unsupported message.
    #[error("SAM protocol error: {0}")]
    Protocol(String),

    /// A name or base-64 destination could not be resolved.
    #[error("Name not found: {0}")]
    NameNotFound(String),

    /// A lease-set for a `.b32.i2p` address was not found in the netDB.
    #[error("Lease set not found: {0}")]
    LeaseSetNotFound(String),

    /// The supplied base-64 destination string is invalid.
    #[error("Bad base64 destination: {0}")]
    BadBase64Dest(String),
}

/// Convenience `Result` alias with [`SamError`] as the error type.
pub type Result<T> = std::result::Result<T, SamError>;
