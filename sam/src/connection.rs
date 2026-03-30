//! Per-connection SAM protocol handler.
//!
//! [`SamConnection`] is the Rust equivalent of the combined
//! `SAMHandler` + `SAMHandlerFactory` classes from the Java implementation.
//! It owns one accepted TCP connection from a SAM client and is responsible
//! for:
//!
//! 1. **HELLO handshake** — reading the first `HELLO VERSION` line and
//!    replying with `HELLO REPLY RESULT=OK VERSION=x.y` (or `NOVERSION`).
//! 2. **Command dispatch** — reading subsequent lines and routing each
//!    command to the right handler method (currently SAM v1 `NAMING LOOKUP`
//!    is implemented; other commands return a `TODO` response until the
//!    rest of the protocol is ported).
//!
//! This module is **server-side only**.  SAM *client* code (the Java classes
//! in `net.i2p.sam.client.*`) is not ported here and remains in Java.

use std::net::SocketAddr;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::error::{Result, SamError};
use crate::handler::SamV1Handler;
use crate::params::{parse_params, COMMAND_KEY, OPCODE_KEY};

// ──────────────────────────────────────────────────────────────────────────────
// Protocol constants
// ──────────────────────────────────────────────────────────────────────────────

/// The highest SAM version this server supports.
pub const SERVER_VERSION: &str = "3.3";

/// All versions that the server can speak, from newest to oldest.
const SUPPORTED_VERSIONS: &[&str] = &[
    "3.3", "3.2", "3.1", "3.0", "2.0", "1.0",
];

// ──────────────────────────────────────────────────────────────────────────────
// SamConnection
// ──────────────────────────────────────────────────────────────────────────────

/// Handles a single SAM client connection from HELLO through command dispatch.
///
/// This is the server side only — it speaks *to* SAM clients (applications)
/// and *to* the I2P router via I2CP.  It does not implement the client-side
/// SAM API.
pub struct SamConnection {
    stream: TcpStream,
    peer_addr: SocketAddr,
}

impl SamConnection {
    /// Wrap an accepted TCP stream.
    pub fn new(stream: TcpStream, peer_addr: SocketAddr) -> Self {
        Self { stream, peer_addr }
    }

    /// Run the connection to completion.
    ///
    /// Performs the HELLO handshake, then processes commands until the client
    /// closes the connection or an error occurs.
    pub async fn run(self) -> Result<()> {
        let peer = self.peer_addr;
        let (reader, mut writer) = self.stream.into_split();
        let mut lines = BufReader::new(reader).lines();

        // ── HELLO handshake ──────────────────────────────────────────────────

        let first_line = match lines.next_line().await? {
            Some(l) => l,
            None => return Ok(()), // client disconnected immediately
        };

        tracing::debug!(%peer, line = %first_line, "SAM HELLO");

        let params = parse_params(&first_line)?;

        if params.get(COMMAND_KEY).map(String::as_str) != Some("HELLO")
            || params.get(OPCODE_KEY).map(String::as_str) != Some("VERSION")
        {
            writer
                .write_all(
                    b"HELLO REPLY RESULT=I2P_ERROR MESSAGE=\"Must start with HELLO VERSION\"\n",
                )
                .await?;
            return Err(SamError::Protocol(
                "Must start with HELLO VERSION".to_owned(),
            ));
        }

        let min_ver = params
            .get("MIN")
            .map(String::as_str)
            .unwrap_or("1");
        let max_ver = params
            .get("MAX")
            .map(String::as_str)
            .unwrap_or("99.99");

        match choose_version(min_ver, max_ver) {
            None => {
                writer
                    .write_all(b"HELLO REPLY RESULT=NOVERSION\n")
                    .await?;
                return Ok(());
            }
            Some(ver) => {
                let reply = format!("HELLO REPLY RESULT=OK VERSION={ver}\n");
                writer.write_all(reply.as_bytes()).await?;
                tracing::debug!(%peer, %ver, "SAM version negotiated");
            }
        }

        // ── Command loop ─────────────────────────────────────────────────────

        // Build a v1 handler with a no-op naming service.
        // A real deployment would inject a proper naming/I2CP-backed resolver.
        let handler: SamV1Handler<_> = SamV1Handler::new(|_| None);

        while let Some(line) = lines.next_line().await? {
            if line.is_empty() {
                continue;
            }
            tracing::debug!(%peer, %line, "SAM command");

            let reply = dispatch_line(&handler, &line).await;
            writer.write_all(reply.as_bytes()).await?;
        }

        tracing::debug!(%peer, "SAM client disconnected");
        Ok(())
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Version negotiation
// ──────────────────────────────────────────────────────────────────────────────

/// Choose the best mutually-supported version.
///
/// Returns the highest version in [`SUPPORTED_VERSIONS`] that satisfies
/// `min_ver <= chosen <= max_ver`.  Returns `None` when no version matches.
///
/// Equivalent to `SAMHandlerFactory.chooseBestVersion`.
fn choose_version<'a>(min_ver: &str, max_ver: &str) -> Option<&'a str> {
    SUPPORTED_VERSIONS.iter().copied().find(|&v| {
        version_cmp(v, min_ver) >= 0 && version_cmp(v, max_ver) <= 0
    })
}

/// Simple numeric version comparator for dotted-decimal version strings.
///
/// Equivalent to `VersionComparator.comp` in the Java implementation.
/// Returns negative / zero / positive like `Ord::cmp`.
fn version_cmp(a: &str, b: &str) -> i32 {
    let parse = |s: &str| -> Vec<u32> {
        s.split('.').map(|p| p.parse().unwrap_or(0)).collect()
    };
    let av = parse(a);
    let bv = parse(b);
    let len = av.len().max(bv.len());
    for i in 0..len {
        let ai = av.get(i).copied().unwrap_or(0);
        let bi = bv.get(i).copied().unwrap_or(0);
        match ai.cmp(&bi) {
            std::cmp::Ordering::Equal => continue,
            std::cmp::Ordering::Less => return -1,
            std::cmp::Ordering::Greater => return 1,
        }
    }
    0
}

// ──────────────────────────────────────────────────────────────────────────────
// Command dispatcher
// ──────────────────────────────────────────────────────────────────────────────

/// Parse one SAM command line and return the reply string to send.
async fn dispatch_line<NS>(handler: &SamV1Handler<NS>, line: &str) -> String
where
    NS: Fn(&str) -> Option<crate::types::Destination> + Send + Sync,
{
    let params = match parse_params(line) {
        Ok(p) => p,
        Err(e) => {
            return format!(
                "GENERIC REPLY RESULT=I2P_ERROR MESSAGE=\"Parse error: {e}\"\n"
            );
        }
    };

    let command = params
        .get(COMMAND_KEY)
        .map(String::as_str)
        .unwrap_or("");
    let opcode = params
        .get(OPCODE_KEY)
        .map(String::as_str)
        .unwrap_or("");

    match command {
        "NAMING" => {
            let name = params.get("NAME").map(String::as_str);
            match handler.exec_naming_message(opcode, name).await {
                Ok(reply) => reply,
                Err(e) => format!(
                    "NAMING REPLY RESULT=I2P_ERROR MESSAGE=\"{e}\"\n"
                ),
            }
        }
        // Additional commands (SESSION, STREAM, DATAGRAM, RAW, DEST, PING,
        // PONG) will be dispatched here once their handlers are implemented.
        other => {
            tracing::debug!(command = %other, "unimplemented SAM command");
            format!(
                "{other} REPLY RESULT=I2P_ERROR \
                 MESSAGE=\"Command not yet implemented\"\n"
            )
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── version chooser ──────────────────────────────────────────────────────

    #[test]
    fn choose_exact_server_version() {
        assert_eq!(
            choose_version(SERVER_VERSION, SERVER_VERSION),
            Some(SERVER_VERSION)
        );
    }

    #[test]
    fn choose_highest_when_range_spans_all() {
        assert_eq!(choose_version("1.0", "99.99"), Some("3.3"));
    }

    #[test]
    fn choose_v1_when_max_is_1() {
        assert_eq!(choose_version("1.0", "1.0"), Some("1.0"));
    }

    #[test]
    fn no_version_when_min_too_high() {
        assert_eq!(choose_version("4.0", "99.99"), None);
    }

    #[test]
    fn no_version_when_max_too_low() {
        assert_eq!(choose_version("1.0", "0.9"), None);
    }

    // ── version comparator ───────────────────────────────────────────────────

    #[test]
    fn version_cmp_equal() {
        assert_eq!(version_cmp("3.3", "3.3"), 0);
    }

    #[test]
    fn version_cmp_major_difference() {
        assert!(version_cmp("3.0", "2.0") > 0);
        assert!(version_cmp("2.0", "3.0") < 0);
    }

    #[test]
    fn version_cmp_minor_difference() {
        assert!(version_cmp("3.3", "3.2") > 0);
        assert!(version_cmp("3.1", "3.3") < 0);
    }

    // ── connection: HELLO handshake ──────────────────────────────────────────

    #[tokio::test]
    async fn hello_version_ok() {
        // Simulate a client that sends HELLO VERSION and then closes.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            SamConnection::new(stream, peer).run().await
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        use tokio::io::AsyncWriteExt;
        client
            .write_all(b"HELLO VERSION MIN=1.0 MAX=3.3\n")
            .await
            .unwrap();
        // close the write side so the server's read loop ends
        drop(client);

        let result = server.await.unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn hello_bad_command_returns_error() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            SamConnection::new(stream, peer).run().await
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        use tokio::io::AsyncReadExt;
        use tokio::io::AsyncWriteExt;
        client.write_all(b"SESSION CREATE\n").await.unwrap();
        let mut buf = vec![0u8; 256];
        let n = client.read(&mut buf).await.unwrap();
        let reply = String::from_utf8_lossy(&buf[..n]);
        assert!(reply.contains("I2P_ERROR") || reply.contains("NOVERSION") || reply.contains("Must start"));
        drop(client);

        let _ = server.await.unwrap();
    }

    #[tokio::test]
    async fn hello_no_version_match() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            SamConnection::new(stream, peer).run().await
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        use tokio::io::AsyncReadExt;
        use tokio::io::AsyncWriteExt;
        // Request a version range the server doesn't support.
        client
            .write_all(b"HELLO VERSION MIN=9.0 MAX=9.9\n")
            .await
            .unwrap();
        let mut buf = vec![0u8; 256];
        let n = client.read(&mut buf).await.unwrap();
        let reply = String::from_utf8_lossy(&buf[..n]);
        assert!(reply.contains("NOVERSION"));
        drop(client);

        let _ = server.await.unwrap();
    }
}
