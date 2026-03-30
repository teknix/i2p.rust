//! Core I2P error type.

/// All errors that can be produced by the I2P router library.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A data structure was malformed or had an unexpected length.
    #[error("data format error: {0}")]
    DataFormat(String),

    /// A cryptographic operation failed.
    #[error("crypto error: {0}")]
    Crypto(String),

    /// Message serialisation / deserialisation failed.
    #[error("encoding error: {0}")]
    Encoding(String),

    /// A required signature was missing or invalid.
    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    /// An I/O error from the underlying transport.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// An operation timed out.
    #[error("timeout")]
    Timeout,

    /// The router is in a state that does not permit this operation.
    #[error("router state error: {0}")]
    State(String),
}

/// Convenience `Result` alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;
