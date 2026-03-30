//! SAM session traits and types.
//!
//! This module defines:
//!
//! - [`I2cpSession`] — a trait abstracting an active I2CP connection to the
//!   router (used for in-session name lookups).  Corresponds to
//!   `net.i2p.client.I2PSession`.
//!
//! - [`SamSession`] — the core SAM session trait whose implementors represent
//!   a single SAM STREAM / DATAGRAM / RAW session.  Corresponds to the
//!   `net.i2p.sam.SAMMessageSess` interface.
//!
//! - [`MessageSession`] — a concrete base type that wraps an [`I2cpSession`]
//!   and provides the shared `lookup_dest` implementation used by both
//!   DATAGRAM/RAW sessions and STREAM sessions.  Corresponds to
//!   `net.i2p.sam.SAMMessageSession`.

use async_trait::async_trait;

use crate::error::Result;
use crate::types::Destination;

// ──────────────────────────────────────────────────────────────────────────────
// I2cpSession trait
// ──────────────────────────────────────────────────────────────────────────────

/// Abstraction over an active I2CP connection to an I2P router.
///
/// Implementations must be `Send + Sync` so they can be shared across async
/// tasks.  The trait mirrors the small subset of
/// `net.i2p.client.I2PSession` used by the SAM bridge.
#[async_trait]
pub trait I2cpSession: Send + Sync {
    /// Return the local [`Destination`] for this session.
    fn my_destination(&self) -> &Destination;

    /// Look up the [`Destination`] for `name` using this session's tunnels.
    ///
    /// `timeout_ms` is the maximum time to wait in milliseconds.
    ///
    /// Returns `Ok(Some(dest))` on success, `Ok(None)` when not found, or
    /// `Err` on session error.
    async fn lookup_dest(
        &self,
        name: &str,
        timeout_ms: u64,
    ) -> Result<Option<Destination>>;
}

// ──────────────────────────────────────────────────────────────────────────────
// SamSession trait
// ──────────────────────────────────────────────────────────────────────────────

/// Core SAM session trait — the Rust equivalent of `SAMMessageSess`.
///
/// Implementors represent an active SAM STREAM, DATAGRAM, or RAW session.
/// All methods are asynchronous to allow non-blocking I/O.
#[async_trait]
pub trait SamSession: Send + Sync {
    /// Start the session.  Must be called after construction.
    async fn start(&self);

    /// Shut down the session and release all resources.
    async fn close(&self);

    /// Return the local [`Destination`] for this session.
    fn destination(&self) -> &Destination;

    /// Send `data` through the session to `dest`.
    ///
    /// `proto`, `from_port`, and `to_port` are I2CP-level fields.
    ///
    /// Returns `true` if the data was accepted for delivery.
    async fn send_bytes(
        &self,
        dest: &str,
        data: &[u8],
        proto: u8,
        from_port: u16,
        to_port: u16,
    ) -> Result<bool>;

    /// Return the I2CP protocol number this session listens on.
    fn listen_protocol(&self) -> u8;

    /// Return the I2CP port this session listens on.
    fn listen_port(&self) -> u16;

    /// Look up a destination through this session's I2CP connection.
    ///
    /// Preferred over the out-of-session path for `.b32.i2p` addresses
    /// because the router will use the client's tunnels to fetch the
    /// lease-set and store it in the client's netDB partition.
    ///
    /// Returns `Ok(Some(dest))` on success or `Ok(None)` when not found.
    ///
    /// Since 0.9.69.
    async fn lookup_dest(&self, name: &str) -> Result<Option<Destination>>;
}

// ──────────────────────────────────────────────────────────────────────────────
// MessageSession — shared base for DATAGRAM/RAW sessions
// ──────────────────────────────────────────────────────────────────────────────

/// Shared base for SAM DATAGRAM and RAW sessions.
///
/// Wraps an [`I2cpSession`] and provides the `lookup_dest` implementation
/// used by [`SamSession::lookup_dest`] in the Java
/// `SAMMessageSession.lookupDest` method.
///
/// STREAM sessions hold an `I2PSocketManager` rather than a bare
/// `I2PSession`, so they use a separate implementation; see
/// [`StreamSession`].
pub struct MessageSession<S: I2cpSession> {
    session: S,
    destination: Destination,
    listen_protocol: u8,
    listen_port: u16,
}

impl<S: I2cpSession> MessageSession<S> {
    /// Wrap an existing [`I2cpSession`].
    ///
    /// `listen_protocol` and `listen_port` are the I2CP-level filter values
    /// for inbound messages; pass `0` for "any".
    pub fn new(session: S, listen_protocol: u8, listen_port: u16) -> Self {
        let destination = session.my_destination().clone();
        Self {
            session,
            destination,
            listen_protocol,
            listen_port,
        }
    }

    /// Return the local [`Destination`].
    pub fn destination(&self) -> &Destination {
        &self.destination
    }

    /// Return the listen protocol filter.
    pub fn listen_protocol(&self) -> u8 {
        self.listen_protocol
    }

    /// Return the listen port filter.
    pub fn listen_port(&self) -> u16 {
        self.listen_port
    }

    /// Look up a destination through this session's I2CP connection.
    ///
    /// Rust equivalent of `SAMMessageSession.lookupDest(I2PSession, String)`.
    pub async fn lookup_dest(&self, name: &str) -> Result<Option<Destination>> {
        crate::naming::lookup_dest(&self.session, name).await
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// StreamSession helper
// ──────────────────────────────────────────────────────────────────────────────

/// Helper for SAM STREAM sessions that obtain their [`I2cpSession`] from a
/// socket manager.
///
/// The Java `SAMStreamSession.lookupDest` method calls:
/// ```java
/// SAMMessageSession.lookupDest(socketMgr.getSession(), name)
/// ```
/// This struct captures the same pattern: an inner [`I2cpSession`] obtained
/// from the socket manager is used for the lookup.
pub struct StreamSession<S: I2cpSession> {
    inner: MessageSession<S>,
}

impl<S: I2cpSession> StreamSession<S> {
    /// Wrap the [`I2cpSession`] that was retrieved from a socket manager.
    pub fn new(session: S, listen_protocol: u8, listen_port: u16) -> Self {
        Self {
            inner: MessageSession::new(session, listen_protocol, listen_port),
        }
    }

    /// Delegate to the inner [`MessageSession::lookup_dest`].
    pub async fn lookup_dest(&self, name: &str) -> Result<Option<Destination>> {
        self.inner.lookup_dest(name).await
    }

    /// Return the local [`Destination`].
    pub fn destination(&self) -> &Destination {
        self.inner.destination()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Mock implementation for tests
// ──────────────────────────────────────────────────────────────────────────────

/// A mock [`I2cpSession`] used only in unit tests.
#[cfg(any(test, feature = "test-utils"))]
pub struct MockI2cpSession {
    dest: Destination,
    lookup_result: Option<Destination>,
}

#[cfg(any(test, feature = "test-utils"))]
impl MockI2cpSession {
    /// Create a mock session whose `lookup_dest` returns `lookup_result`.
    pub fn new(lookup_result: Option<Destination>) -> Self {
        Self {
            dest: Destination::from_bytes(&vec![0u8; 387]).unwrap(),
            lookup_result,
        }
    }
}

#[cfg(any(test, feature = "test-utils"))]
#[async_trait]
impl I2cpSession for MockI2cpSession {
    fn my_destination(&self) -> &Destination {
        &self.dest
    }

    async fn lookup_dest(
        &self,
        _name: &str,
        _timeout_ms: u64,
    ) -> Result<Option<Destination>> {
        Ok(self.lookup_result.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn message_session_lookup_found() {
        let expected = Destination::from_bytes(&vec![1u8; 387]).unwrap();
        let mock = MockI2cpSession::new(Some(expected.clone()));
        let sess = MessageSession::new(mock, 0, 0);
        let result = sess.lookup_dest("some.b32.i2p").await.unwrap();
        assert_eq!(result, Some(expected));
    }

    #[tokio::test]
    async fn message_session_lookup_not_found() {
        let mock = MockI2cpSession::new(None);
        let sess = MessageSession::new(mock, 0, 0);
        let result = sess.lookup_dest("unknown.b32.i2p").await.unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn stream_session_lookup_delegates() {
        let expected = Destination::from_bytes(&vec![2u8; 387]).unwrap();
        let mock = MockI2cpSession::new(Some(expected.clone()));
        let sess = StreamSession::new(mock, 0, 0);
        let result = sess.lookup_dest("some.b32.i2p").await.unwrap();
        assert_eq!(result, Some(expected));
    }
}
