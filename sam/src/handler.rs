//! SAM version 1 protocol handler.
//!
//! This module provides [`SamV1Handler`], which processes SAM v1 client
//! connections and is the Rust equivalent of
//! `net.i2p.sam.SAMv1Handler`.
//!
//! The naming-lookup logic — including the 0.9.69 change that routes
//! `.b32.i2p` lookups *through the active session* when one exists — is
//! implemented in [`SamV1Handler::exec_naming_message`].

use std::sync::Arc;

use crate::error::{Result, SamError};
use crate::naming;
use crate::session::{I2cpSession, StreamSession};
use crate::types::{Destination, MIN_DEST_B64_LEN};

/// Suffix for base-32 I2P addresses.
const B32_SUFFIX: &str = ".b32.i2p";
/// Minimum length for a plausible base-32 address.
const MIN_B32_LEN: usize = 60;

// ──────────────────────────────────────────────────────────────────────────────
// Active-session holders
// ──────────────────────────────────────────────────────────────────────────────

/// An active SAM message-based session (DATAGRAM or RAW) that can perform
/// in-session name lookups.
///
/// This is a thin wrapper so that the handler can hold heterogeneous session
/// types (stream, datagram, raw) through a single interface.
pub trait MessageSess: Send + Sync {
    /// Return the local destination for this session.
    fn destination(&self) -> &Destination;

    /// Look up a destination through this session's I2CP connection.
    fn lookup_dest<'a>(
        &'a self,
        name: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Option<Destination>>> + Send + 'a>>;
}

// ──────────────────────────────────────────────────────────────────────────────
// SamV1Handler
// ──────────────────────────────────────────────────────────────────────────────

/// SAM version 1 protocol handler.
///
/// Holds references to the three possible session types (STREAM, DATAGRAM,
/// RAW) — at most one of which is active at a time for a SAM v1 connection.
/// The naming-lookup handler picks the appropriate session automatically.
///
/// A `NamingService` callback is injected so that out-of-session lookups
/// (e.g. hostnames and full base-64 destinations) can be resolved without
/// coupling this type to a concrete router implementation.
pub struct SamV1Handler<NS> {
    /// Active STREAM session, if established.
    pub stream_session: Option<Arc<dyn MessageSess>>,
    /// Active DATAGRAM session, if established.
    pub datagram_session: Option<Arc<dyn MessageSess>>,
    /// Active RAW session, if established.
    pub raw_session: Option<Arc<dyn MessageSess>>,
    /// Out-of-session naming service (returns `None` when not found).
    naming_service: NS,
}

impl<NS> SamV1Handler<NS>
where
    NS: Fn(&str) -> Option<Destination> + Send + Sync,
{
    /// Create a new handler with the given naming-service callback.
    pub fn new(naming_service: NS) -> Self {
        Self {
            stream_session: None,
            datagram_session: None,
            raw_session: None,
            naming_service,
        }
    }

    // ── NAMING message ────────────────────────────────────────────────────────

    /// Handle a `NAMING LOOKUP NAME=<name>` command and return the SAM
    /// protocol reply string.
    ///
    /// Implements the logic from `SAMv1Handler.execNamingMessage` (Java),
    /// including the 0.9.69 change that routes `.b32.i2p` lookups through
    /// the active session when one is available.
    ///
    /// # Return value
    ///
    /// Returns the SAM reply line, e.g.:
    /// ```text
    /// NAMING REPLY RESULT=OK NAME=zzz.i2p VALUE=<base64>\n
    /// NAMING REPLY RESULT=KEY_NOT_FOUND NAME=zzz.i2p\n
    /// ```
    pub async fn exec_naming_message(
        &self,
        opcode: &str,
        name: Option<&str>,
    ) -> Result<String> {
        if opcode != "LOOKUP" {
            return Err(SamError::Protocol(format!(
                "Unrecognized NAMING opcode: '{opcode}'"
            )));
        }

        let name = match name {
            Some(n) if !n.is_empty() => n,
            _ => {
                return Ok(
                    "NAMING REPLY RESULT=KEY_NOT_FOUND NAME=\"\" \
                     MESSAGE=\"Must specify NAME\"\n"
                        .to_owned(),
                );
            }
        };

        // Special case: NAME=ME returns the local destination of the active
        // session.
        if name == "ME" {
            let dest = self
                .stream_session
                .as_deref()
                .or(self.datagram_session.as_deref())
                .or(self.raw_session.as_deref())
                .map(|s| s.destination().to_base64());

            return match dest {
                Some(b64) => Ok(format!("NAMING REPLY RESULT=OK NAME=ME VALUE={b64}\n")),
                None => Ok(
                    "NAMING REPLY RESULT=KEY_NOT_FOUND NAME=\"\" \
                     MESSAGE=\"Name=ME requires established session\"\n"
                        .to_owned(),
                ),
            };
        }

        // Decide between in-session (b32) and out-of-session lookup.
        let is_b32 = name.len() >= MIN_B32_LEN
            && name.len() < MIN_DEST_B64_LEN
            && name.to_lowercase().ends_with(B32_SUFFIX);

        let dest_result: Result<Option<Destination>> = if !is_b32 {
            // Full base-64 destinations, hostnames, and everything that is not
            // a plain b32 address: use the out-of-session naming service.
            naming::get_dest(name, &self.naming_service).map(Some)
        } else {
            // b32 address: prefer in-session lookup so the router uses the
            // client's tunnels to fetch the lease-set.
            let active_session = self
                .stream_session
                .as_deref()
                .or(self.datagram_session.as_deref())
                .or(self.raw_session.as_deref());

            match active_session {
                Some(sess) => {
                    // In-session lookup.
                    sess.lookup_dest(name).await
                }
                None => {
                    // No active session: fall back to the out-of-session path.
                    // The lease-set will end up in the main netDB.
                    naming::get_dest(name, &self.naming_service).map(Some)
                }
            }
        };

        match dest_result {
            Ok(Some(dest)) => Ok(format!(
                "NAMING REPLY RESULT=OK NAME={name} VALUE={}\n",
                dest.to_base64()
            )),
            Ok(None) => Ok(format!(
                "NAMING REPLY RESULT=KEY_NOT_FOUND NAME={name}\n"
            )),
            Err(e) => Ok(format!(
                "NAMING REPLY RESULT=KEY_NOT_FOUND NAME={name} MESSAGE=\"{e}\"\n"
            )),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Convenience blanket impl for session types
// ──────────────────────────────────────────────────────────────────────────────

/// Blanket implementation of [`MessageSess`] for [`StreamSession`].
impl<S: I2cpSession + 'static> MessageSess for StreamSession<S> {
    fn destination(&self) -> &Destination {
        StreamSession::destination(self)
    }

    fn lookup_dest<'a>(
        &'a self,
        name: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Option<Destination>>> + Send + 'a>>
    {
        Box::pin(StreamSession::lookup_dest(self, name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::MockI2cpSession;

    fn make_dest() -> Destination {
        Destination::from_bytes(&vec![0u8; 387]).unwrap()
    }

    fn known_ns(name: &str) -> Option<Destination> {
        if name == "example.i2p" {
            Some(make_dest())
        } else {
            None
        }
    }

    #[tokio::test]
    async fn lookup_missing_name_param() {
        let handler: SamV1Handler<_> = SamV1Handler::new(known_ns);
        let reply = handler.exec_naming_message("LOOKUP", None).await.unwrap();
        assert!(reply.contains("KEY_NOT_FOUND"));
        assert!(reply.contains("Must specify NAME"));
    }

    #[tokio::test]
    async fn lookup_me_no_session() {
        let handler: SamV1Handler<_> = SamV1Handler::new(known_ns);
        let reply = handler
            .exec_naming_message("LOOKUP", Some("ME"))
            .await
            .unwrap();
        assert!(reply.contains("KEY_NOT_FOUND"));
        assert!(reply.contains("requires established session"));
    }

    #[tokio::test]
    async fn lookup_me_with_session() {
        let mock = MockI2cpSession::new(None);
        let sess: Arc<dyn MessageSess> =
            Arc::new(StreamSession::new(mock, 0, 0));
        let mut handler: SamV1Handler<_> = SamV1Handler::new(known_ns);
        handler.stream_session = Some(sess);
        let reply = handler
            .exec_naming_message("LOOKUP", Some("ME"))
            .await
            .unwrap();
        assert!(reply.contains("RESULT=OK"));
        assert!(reply.contains("NAME=ME"));
    }

    #[tokio::test]
    async fn lookup_known_hostname() {
        let handler: SamV1Handler<_> = SamV1Handler::new(known_ns);
        let reply = handler
            .exec_naming_message("LOOKUP", Some("example.i2p"))
            .await
            .unwrap();
        assert!(reply.contains("RESULT=OK"));
        assert!(reply.contains("NAME=example.i2p"));
    }

    #[tokio::test]
    async fn lookup_unknown_hostname() {
        let handler: SamV1Handler<_> = SamV1Handler::new(|_| None);
        let reply = handler
            .exec_naming_message("LOOKUP", Some("unknown.i2p"))
            .await
            .unwrap();
        assert!(reply.contains("KEY_NOT_FOUND"));
    }

    #[tokio::test]
    async fn lookup_b32_with_session_found() {
        let b32 = "a".repeat(52) + ".b32.i2p";
        let expected = Destination::from_bytes(&vec![5u8; 387]).unwrap();
        let mock = MockI2cpSession::new(Some(expected));
        let sess: Arc<dyn MessageSess> = Arc::new(StreamSession::new(mock, 0, 0));
        let mut handler: SamV1Handler<_> = SamV1Handler::new(|_| None);
        handler.stream_session = Some(sess);
        let reply = handler
            .exec_naming_message("LOOKUP", Some(&b32))
            .await
            .unwrap();
        assert!(reply.contains("RESULT=OK"));
    }

    #[tokio::test]
    async fn lookup_b32_with_session_not_found() {
        let b32 = "a".repeat(52) + ".b32.i2p";
        let mock = MockI2cpSession::new(None);
        let sess: Arc<dyn MessageSess> = Arc::new(StreamSession::new(mock, 0, 0));
        let mut handler: SamV1Handler<_> = SamV1Handler::new(|_| None);
        handler.stream_session = Some(sess);
        let reply = handler
            .exec_naming_message("LOOKUP", Some(&b32))
            .await
            .unwrap();
        assert!(reply.contains("KEY_NOT_FOUND"));
    }

    #[tokio::test]
    async fn lookup_b32_no_session_falls_back_to_naming_service() {
        let b32 = "a".repeat(52) + ".b32.i2p";
        // Naming service knows the b32 address (unusual, but tests the path).
        let b32_clone = b32.clone();
        let handler: SamV1Handler<_> =
            SamV1Handler::new(move |n| if n == b32_clone { Some(make_dest()) } else { None });
        let reply = handler
            .exec_naming_message("LOOKUP", Some(&b32))
            .await
            .unwrap();
        assert!(reply.contains("RESULT=OK"));
    }

    #[tokio::test]
    async fn unknown_opcode_is_error() {
        let handler: SamV1Handler<_> = SamV1Handler::new(|_| None);
        let result = handler.exec_naming_message("STORE", Some("x")).await;
        assert!(matches!(result, Err(SamError::Protocol(_))));
    }
}
