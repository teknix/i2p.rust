//! Naming and destination resolution utilities.
//!
//! This module provides the Rust equivalents of:
//!
//! - `SAMUtils.getDest(String)` → [`get_dest`]
//! - `SAMMessageSession.lookupDest(I2PSession, String)` → [`lookup_dest`]
//!
//! The main behavioural difference introduced in I2P 0.9.69 (reflected in
//! this module) is that `.b32.i2p` address lookups are preferentially routed
//! *through an active session* so that the router uses the client's tunnels
//! to fetch the lease-set and stores it in the client's netDB partition.
//!
//! For out-of-session lookups (non-b32, or no session available) the global
//! naming service is used instead; the resolved lease-set ends up in the
//! main netDB and must be fetched again when a message is actually sent.

use crate::error::{Result, SamError};
use crate::session::I2cpSession;
use crate::types::{Destination, MIN_DEST_B64_LEN};

/// Suffix that identifies a base-32 I2P address.
const B32_SUFFIX: &str = ".b32.i2p";
/// Minimum base-32 address length (hash 52 chars + ".b32.i2p" 8 chars).
const MIN_B32_LEN: usize = 60;
/// Lookup timeout in milliseconds, matching the Java implementation (10 s).
const LOOKUP_TIMEOUT_MS: u64 = 10_000;

/// Resolve a destination *out of session* using the naming service.
///
/// This is the Rust equivalent of `SAMUtils.getDest(String s)`.
///
/// # Resolution order
///
/// 1. If `name` looks like a base-64 destination (≥ [`MIN_DEST_B64_LEN`]
///    characters) it is decoded directly.
/// 2. Otherwise the provided `naming_service` is consulted.
///
/// # Errors
///
/// | Condition | Error variant |
/// |-----------|---------------|
/// | `name` is ≥ `MIN_DEST_B64_LEN` chars but invalid base-64 | [`SamError::BadBase64Dest`] |
/// | `name` looks like a b32 address but the lease-set was not found | [`SamError::LeaseSetNotFound`] |
/// | `name` is a hostname that the naming service does not know | [`SamError::NameNotFound`] |
pub fn get_dest<F>(name: &str, naming_service: F) -> Result<Destination>
where
    F: Fn(&str) -> Option<Destination>,
{
    // Try the naming service (which also handles base-64 for us).
    if let Some(d) = naming_service(name) {
        return Ok(d);
    }

    // The naming service returned nothing — build a meaningful error.
    let err = if name.len() >= MIN_DEST_B64_LEN {
        SamError::BadBase64Dest(String::new())
    } else if name.len() >= MIN_B32_LEN && name.to_lowercase().ends_with(B32_SUFFIX) {
        SamError::LeaseSetNotFound(String::new())
    } else {
        SamError::NameNotFound(String::new())
    };
    Err(err)
}

/// Resolve a destination *through an active I2CP session*.
///
/// This is the Rust equivalent of
/// `SAMMessageSession.lookupDest(I2PSession session, String name)`.
///
/// The session will use its own tunnels to perform the netDB lookup so that
/// the lease-set is cached in the client's netDB partition rather than the
/// main router netDB.
///
/// The operation blocks (awaits) for up to [`LOOKUP_TIMEOUT_MS`] milliseconds.
///
/// # Returns
///
/// `Ok(Some(dest))` on success, `Ok(None)` when the session lookup returns
/// nothing, or `Err(SamError::Session(_))` on session error.
pub async fn lookup_dest(session: &dyn I2cpSession, name: &str) -> Result<Option<Destination>> {
    session.lookup_dest(name, LOOKUP_TIMEOUT_MS).await
}

/// Choose the best lookup strategy based on the name and the available
/// sessions, matching the logic in `SAMv1Handler.execNamingMessage`.
///
/// Decision table:
///
/// | Condition | Strategy |
/// |-----------|----------|
/// | `name` is ≥ `MIN_DEST_B64_LEN` chars (base-64 dest) | out-of-session via `naming_service` |
/// | `name` does **not** end with `.b32.i2p` | out-of-session via `naming_service` |
/// | b32 address **and** a session is provided | in-session via `session.lookup_dest` |
/// | b32 address **and** no session | out-of-session via `naming_service` |
///
/// See also: [`get_dest`], [`lookup_dest`].
pub async fn resolve<F>(
    name: &str,
    session: Option<&dyn I2cpSession>,
    naming_service: F,
) -> Result<Option<Destination>>
where
    F: Fn(&str) -> Option<Destination>,
{
    let is_b32 = name.len() >= MIN_B32_LEN
        && name.to_lowercase().ends_with(B32_SUFFIX)
        && name.len() < MIN_DEST_B64_LEN;

    if !is_b32 {
        // Out-of-session: full base-64 destinations, hostnames, and
        // everything else that isn't a plain b32 address.
        return get_dest(name, naming_service).map(Some);
    }

    match session {
        Some(sess) => {
            // In-session b32 lookup: use the client tunnels so the LS ends
            // up in the client's netDB partition.
            lookup_dest(sess, name).await
        }
        None => {
            // No active session — fall back to the out-of-session path.
            // The lease-set will land in the main netDB and the router
            // must look it up again when a message is actually sent.
            get_dest(name, naming_service).map(Some)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::MockI2cpSession;
    use crate::types::Destination;

    fn make_dest() -> Destination {
        Destination::from_bytes(&vec![0u8; 387]).unwrap()
    }

    // A naming service that knows a single host.
    fn known_ns(name: &str) -> Option<Destination> {
        if name == "example.i2p" {
            Some(make_dest())
        } else {
            None
        }
    }

    #[test]
    fn get_dest_known_host() {
        assert!(get_dest("example.i2p", known_ns).is_ok());
    }

    #[test]
    fn get_dest_unknown_host() {
        let err = get_dest("unknown.i2p", |_| None).unwrap_err();
        assert!(matches!(err, SamError::NameNotFound(_)));
    }

    #[test]
    fn get_dest_unknown_b32() {
        let b32 = "a".repeat(52) + ".b32.i2p";
        let err = get_dest(&b32, |_| None).unwrap_err();
        assert!(matches!(err, SamError::LeaseSetNotFound(_)));
    }

    #[test]
    fn get_dest_bad_base64() {
        let long = "!".repeat(MIN_DEST_B64_LEN);
        let err = get_dest(&long, |_| None).unwrap_err();
        assert!(matches!(err, SamError::BadBase64Dest(_)));
    }

    #[tokio::test]
    async fn resolve_non_b32_uses_naming_service() {
        let result = resolve("example.i2p", None, known_ns).await;
        assert!(result.unwrap().is_some());
    }

    #[tokio::test]
    async fn resolve_b32_no_session_uses_naming_service() {
        let b32 = "a".repeat(52) + ".b32.i2p";
        let result = resolve(&b32, None, |_| None).await;
        assert!(matches!(result, Err(SamError::LeaseSetNotFound(_))));
    }

    #[tokio::test]
    async fn resolve_b32_with_session() {
        let b32 = "a".repeat(52) + ".b32.i2p";
        let session = MockI2cpSession::new(Some(make_dest()));
        let result = resolve(&b32, Some(&session), |_| None).await;
        assert!(result.unwrap().is_some());
    }

    #[tokio::test]
    async fn resolve_b32_with_session_not_found() {
        let b32 = "a".repeat(52) + ".b32.i2p";
        let session = MockI2cpSession::new(None);
        let result = resolve(&b32, Some(&session), |_| None).await;
        assert_eq!(result.unwrap(), None);
    }
}
