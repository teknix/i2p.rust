//! SAM Bridge — TCP server that accepts client connections.
//!
//! [`SamBridge`] is the Rust equivalent of `net.i2p.sam.SAMBridge`.  It
//! binds a TCP listener socket (default port 7656) and, for every incoming
//! connection, spawns a [`crate::connection::SamConnection`] task on the
//! Tokio runtime.
//!
//! # Security note
//!
//! Matching the Java implementation, the bridge logs a warning when it is
//! configured to listen on a non-loopback address without TLS, because doing
//! so may expose local services to remote parties.
//!
//! # Example
//!
//! ```no_run
//! # use sam::bridge::{SamBridge, BridgeConfig};
//! # use std::net::SocketAddr;
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let config = BridgeConfig::default();        // 127.0.0.1:7656
//! let bridge = SamBridge::bind(config).await?;
//! bridge.run().await;
//! # Ok(())
//! # }
//! ```

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;

use crate::connection::SamConnection;
use crate::error::{Result, SamError};

/// Default TCP host the SAM bridge listens on.
pub const DEFAULT_HOST: &str = "127.0.0.1";
/// Default TCP port the SAM bridge listens on.
pub const DEFAULT_PORT: u16 = 7656;

// ──────────────────────────────────────────────────────────────────────────────
// BridgeConfig
// ──────────────────────────────────────────────────────────────────────────────

/// Configuration for the SAM bridge server.
///
/// Create with `BridgeConfig::default()` for the standard `127.0.0.1:7656`
/// binding, or with [`BridgeConfig::new`] for custom addresses.
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    /// Address and port the bridge should listen on.
    pub listen_addr: SocketAddr,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            listen_addr: format!("{DEFAULT_HOST}:{DEFAULT_PORT}")
                .parse()
                .expect("default SAM listen address is valid"),
        }
    }
}

impl BridgeConfig {
    /// Create a new `BridgeConfig` with a custom listen address.
    pub fn new(addr: SocketAddr) -> Self {
        Self { listen_addr: addr }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// SamBridge
// ──────────────────────────────────────────────────────────────────────────────

/// SAM bridge server.
///
/// Wraps a bound TCP listener.  Call [`SamBridge::run`] to begin accepting
/// connections (this runs forever until the task is cancelled).
pub struct SamBridge {
    listener: TcpListener,
    config: Arc<BridgeConfig>,
}

impl SamBridge {
    /// Bind the TCP listener and return a ready-to-run bridge.
    ///
    /// # Security warning
    ///
    /// A warning is emitted when `config.listen_addr` is not a loopback
    /// address, mirroring the Java implementation's behaviour.
    pub async fn bind(config: BridgeConfig) -> Result<Self> {
        let addr = config.listen_addr;

        if !addr.ip().is_loopback() {
            tracing::warn!(
                addr = %addr,
                "SAM bridge is not restricted to localhost. \
                 Remote access to local I2P services may be possible. \
                 Consider restricting the listen address."
            );
        }

        let listener = TcpListener::bind(addr)
            .await
            .map_err(SamError::Io)?;

        tracing::info!(addr = %addr, "SAM bridge listening");

        Ok(Self {
            listener,
            config: Arc::new(config),
        })
    }

    /// Return the configuration used to create this bridge.
    pub fn config(&self) -> &BridgeConfig {
        &self.config
    }

    /// Return the local address the bridge is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.listener.local_addr().map_err(SamError::Io)
    }

    /// Run the accept loop.
    ///
    /// For each accepted TCP connection a [`SamConnection`] is spawned as an
    /// independent Tokio task.  This method runs indefinitely until the
    /// underlying listener is closed (e.g. by dropping `self`) or the
    /// surrounding task is cancelled.
    pub async fn run(self) {
        loop {
            match self.listener.accept().await {
                Ok((stream, peer_addr)) => {
                    tracing::debug!(%peer_addr, "new SAM client connection");
                    let conn = SamConnection::new(stream, peer_addr);
                    tokio::spawn(async move {
                        if let Err(e) = conn.run().await {
                            tracing::debug!(%peer_addr, error = %e, "SAM connection closed with error");
                        }
                    });
                }
                Err(e) => {
                    tracing::error!(error = %e, "SAM bridge accept error");
                    // Transient errors (e.g. too many open files) should not
                    // crash the whole bridge; give the OS a moment to recover.
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bind_and_report_local_addr() {
        let config = BridgeConfig::new("127.0.0.1:0".parse().unwrap());
        let bridge = SamBridge::bind(config).await.unwrap();
        let addr = bridge.local_addr().unwrap();
        assert!(addr.port() > 0);
        assert!(addr.ip().is_loopback());
    }
}
