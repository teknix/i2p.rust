//! Top-level router struct — wires all subsystems together.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

use crate::crypto::{ed25519::Ed25519Keypair, x25519::StaticKeypair};
use crate::data::{RouterAddress, RouterIdentity, RouterInfo};
use crate::data::router_identity::{
    CRYPTO_TYPE_X25519, SIG_TYPE_EDDSA_SHA512_ED25519,
};
use crate::error::Result;
use crate::netdb::{MemoryNetDb, NetDb};
use crate::peer_profile::PeerProfileStore;
use crate::transport::ntcp2::Ntcp2Transport;
use crate::tunnel::manager::TunnelPool;
use crate::data::Hash;

/// Configuration for starting an I2P router.
#[derive(Debug, Clone)]
pub struct RouterConfig {
    /// TCP port for NTCP2 (0 = OS-assigned ephemeral port).
    pub ntcp2_port: u16,
    /// Maximum number of active inbound tunnels.
    pub max_inbound_tunnels: usize,
    /// Maximum number of active outbound tunnels.
    pub max_outbound_tunnels: usize,
    /// Whether to run as a floodfill router.
    pub floodfill: bool,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            ntcp2_port: 4567,
            max_inbound_tunnels: 10,
            max_outbound_tunnels: 10,
            floodfill: false,
        }
    }
}

/// The I2P router — central coordinator of all subsystems.
///
/// # Lifecycle
/// 1. Create with [`Router::new`] — generates identity keys.
/// 2. Call [`Router::start`] to begin listening and building tunnels.
/// 3. Call [`Router::stop`] to gracefully shut down.
pub struct Router {
    config: RouterConfig,
    identity: RouterIdentity,
    signing_key: Ed25519Keypair,
    encryption_key: StaticKeypair,
    pub netdb: Arc<MemoryNetDb>,
    pub profiles: Arc<PeerProfileStore>,
    pub tunnels: Arc<TunnelPool>,
    ntcp2: Arc<Ntcp2Transport>,
    running: Arc<AtomicBool>,
}

impl Router {
    /// Create a new router with freshly-generated identity keys.
    pub fn new(config: RouterConfig) -> Self {
        let signing_key = Ed25519Keypair::generate();
        let encryption_key = StaticKeypair::generate();

        let identity = RouterIdentity::new(
            encryption_key.public_bytes().to_vec(),
            CRYPTO_TYPE_X25519,
            signing_key.verifying_bytes().to_vec(),
            SIG_TYPE_EDDSA_SHA512_ED25519,
            vec![],
        );

        let local_addr = if config.ntcp2_port > 0 {
            format!("0.0.0.0:{}", config.ntcp2_port)
                .parse()
                .ok()
        } else {
            None
        };

        let ntcp2 = Arc::new(Ntcp2Transport::new(local_addr));

        Self {
            config,
            identity,
            signing_key,
            encryption_key,
            netdb: Arc::new(MemoryNetDb::new()),
            profiles: Arc::new(PeerProfileStore::new()),
            tunnels: Arc::new(TunnelPool::new()),
            ntcp2,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Return an unsigned [`RouterInfo`] describing this router.
    pub fn router_info(&self) -> RouterInfo {
        let mut opts = HashMap::new();
        let caps = if self.config.floodfill { "Rf" } else { "R" };
        opts.insert("caps".into(), caps.into());
        opts.insert("netId".into(), "2".into());

        let mut addr = RouterAddress::new("NTCP2", 10);
        addr.set_option(
            "s",
            &base64_encode(&self.encryption_key.public_bytes()),
        );
        if self.config.ntcp2_port > 0 {
            addr.set_option("port", &self.config.ntcp2_port.to_string());
        }

        RouterInfo::new(
            self.identity.clone(),
            current_time_ms(),
            vec![addr],
            opts,
        )
    }

    /// Sign and return the router's [`RouterInfo`].
    pub fn signed_router_info(&self) -> RouterInfo {
        let mut ri = self.router_info();
        // Produce a canonical serialisation to sign.
        let payload = canonical_ri_bytes(&ri);
        let sig = self.signing_key.sign(&payload);
        let _ = ri.sign(sig.to_vec());
        ri
    }

    /// Store this router's own signed [`RouterInfo`] in the NetDB.
    pub fn publish_self(&self) {
        let ri = self.signed_router_info();
        self.netdb.store_router_info(ri);
    }

    /// Start the router and spawn background maintenance tasks.
    pub async fn start(&self) -> Result<RouterHandle> {
        self.running.store(true, Ordering::SeqCst);

        let tunnels = Arc::clone(&self.tunnels);
        let running = Arc::clone(&self.running);

        tokio::spawn(async move {
            while running.load(Ordering::SeqCst) {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                let now = current_time_ms();
                tunnels.expire_old(now);
            }
        });

        Ok(RouterHandle {
            _marker: std::marker::PhantomData,
        })
    }

    /// Stop the router gracefully.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Return `true` if the router is currently running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Return the router's identity hash.
    pub fn hash(&self) -> Hash {
        self.identity.hash()
    }

    /// Return a reference to the in-memory NetDB.
    pub fn netdb(&self) -> &MemoryNetDb {
        &self.netdb
    }
}

/// A handle to a running router.  Drop to allow background tasks to terminate.
pub struct RouterHandle {
    _marker: std::marker::PhantomData<()>,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn base64_encode(bytes: &[u8]) -> String {
    // Simple hex encoding as placeholder (real I2P uses base64).
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn canonical_ri_bytes(ri: &RouterInfo) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&ri.identity.encryption_key);
    buf.extend_from_slice(&ri.identity.signing_key);
    buf.extend_from_slice(ri.identity.certificate.as_slice());
    buf.extend_from_slice(&ri.published.to_be_bytes());
    buf
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_router_creation() {
        let router = Router::new(RouterConfig::default());
        assert!(!router.is_running());
    }

    #[test]
    fn test_router_hash_stable() {
        let router = Router::new(RouterConfig::default());
        let h1 = router.hash();
        let h2 = router.hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_publish_self() {
        let router = Router::new(RouterConfig::default());
        assert_eq!(router.netdb.router_count(), 0);
        router.publish_self();
        assert_eq!(router.netdb.router_count(), 1);
    }

    #[test]
    fn test_stop() {
        let router = Router::new(RouterConfig::default());
        router.stop();
        assert!(!router.is_running());
    }

    #[test]
    fn test_signed_router_info_is_signed() {
        let router = Router::new(RouterConfig::default());
        let ri = router.signed_router_info();
        assert!(ri.is_signed());
    }
}
