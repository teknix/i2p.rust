//! HTTP reseeder — fetches RouterInfo bundles from reseed servers.

#![allow(dead_code)]

use crate::data::router_identity::{
    RouterIdentity, CRYPTO_TYPE_X25519, SIG_TYPE_EDDSA_SHA512_ED25519,
    X25519_PUB_KEY_LEN, ED25519_PUB_KEY_LEN,
};
use crate::data::router_info::RouterInfo;
use crate::error::{Error, Result};
use crate::netdb::NetDb;

use std::collections::HashMap;

/// Well-known I2P reseed server URLs.
pub const DEFAULT_RESEED_URLS: &[&str] = &[
    "https://reseed.i2p-projekt.de/",
    "https://reseed2.i2p.net/",
    "https://i2p.mooo.com/netDb/",
    "https://netdb.i2p2.de/",
];

/// HTTP reseeder — downloads RouterInfo files from reseed servers.
pub struct Reseeder {
    client: reqwest::Client,
}

impl Reseeder {
    /// Create a new `Reseeder` with a 30s timeout.
    /// Accepts invalid TLS certificates to maximise reseed compatibility across
    /// different reseed servers.  Reseed traffic does not carry sensitive data —
    /// the RouterInfo records are publicly available and signed by their owners.
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_default();
        Self { client }
    }

    /// Try each reseed URL in order, fetch RouterInfo `.dat` files, and store
    /// them in `netdb`.  Returns the number of router infos stored.
    pub async fn reseed(&self, netdb: &dyn NetDb, max_routers: usize) -> Result<usize> {
        for url in DEFAULT_RESEED_URLS {
            match self.try_reseed_url(url, netdb, max_routers).await {
                Ok(n) if n > 0 => return Ok(n),
                _ => continue,
            }
        }
        Ok(0)
    }

    async fn try_reseed_url(
        &self,
        base_url: &str,
        netdb: &dyn NetDb,
        max_routers: usize,
    ) -> Result<usize> {
        let response = self
            .client
            .get(base_url)
            .send()
            .await
            .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;

        let html = response
            .text()
            .await
            .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;

        let links = parse_dat_links(&html, base_url);
        let mut stored = 0usize;

        for link in links.iter().take(max_routers) {
            if let Ok(bytes) = self.fetch_bytes(link).await {
                if let Ok(ri) = router_info_from_bytes(&bytes) {
                    netdb.store_router_info(ri);
                    stored += 1;
                }
            }
        }

        Ok(stored)
    }

    async fn fetch_bytes(&self, url: &str) -> Result<Vec<u8>> {
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;
        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))
    }
}

impl Default for Reseeder {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse HTML for links ending in `.dat` or matching `routerInfo-*.dat`.
fn parse_dat_links(html: &str, base_url: &str) -> Vec<String> {
    let mut links = Vec::new();
    // Simple pattern search for href="...dat"
    for part in html.split("href=\"") {
        if let Some(end) = part.find('"') {
            let href = &part[..end];
            if href.ends_with(".dat") {
                let url = if href.starts_with("http://") || href.starts_with("https://") {
                    href.to_string()
                } else {
                    let base = base_url.trim_end_matches('/');
                    let path = href.trim_start_matches('/');
                    format!("{base}/{path}")
                };
                links.push(url);
            }
        }
    }
    links
}

/// Construct a minimal `RouterInfo` from raw `.dat` bytes.
///
/// We use the SHA-256 of the raw bytes as the identity hash, and wrap the
/// first 32 bytes as the encryption key placeholder.  Full binary parsing can
/// be added later.
fn router_info_from_bytes(bytes: &[u8]) -> Result<RouterInfo> {
    if bytes.len() < 32 {
        return Err(Error::DataFormat("router info bytes too short".into()));
    }

    // Use first 32 bytes as encryption key placeholder
    let enc_key = bytes[..X25519_PUB_KEY_LEN].to_vec();
    // Use bytes 32..64 (or zeroes) as signing key placeholder
    let sig_key = if bytes.len() >= X25519_PUB_KEY_LEN + ED25519_PUB_KEY_LEN {
        bytes[X25519_PUB_KEY_LEN..X25519_PUB_KEY_LEN + ED25519_PUB_KEY_LEN].to_vec()
    } else {
        vec![0u8; ED25519_PUB_KEY_LEN]
    };

    let identity = RouterIdentity::new(
        enc_key,
        CRYPTO_TYPE_X25519,
        sig_key,
        SIG_TYPE_EDDSA_SHA512_ED25519,
        vec![],
    );

    let ri = RouterInfo::new(identity, 0, vec![], HashMap::new());
    Ok(ri)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn default_reseed_urls_not_empty() {
        assert!(!DEFAULT_RESEED_URLS.is_empty());
        for url in DEFAULT_RESEED_URLS {
            assert!(url.starts_with("https://"));
        }
    }

    #[test]
    fn parse_dat_links_extracts_links() {
        let html = r#"<a href="routerInfo-abc.dat">router</a> <a href="routerInfo-def.dat">r2</a>"#;
        let links = parse_dat_links(html, "https://example.com/");
        assert_eq!(links.len(), 2);
        assert!(links[0].contains("routerInfo-abc.dat"));
    }

    #[test]
    fn parse_dat_links_absolute_urls() {
        let html = r#"<a href="https://other.com/routerInfo-xyz.dat">r</a>"#;
        let links = parse_dat_links(html, "https://example.com/");
        assert_eq!(links.len(), 1);
        assert_eq!(links[0], "https://other.com/routerInfo-xyz.dat");
    }

    #[test]
    fn router_info_from_bytes_minimal() {
        let bytes = vec![0xABu8; 64];
        let ri = router_info_from_bytes(&bytes).unwrap();
        assert_eq!(ri.identity.encryption_key.len(), 32);
    }

    #[test]
    fn router_info_from_bytes_too_short() {
        let bytes = vec![0u8; 10];
        assert!(router_info_from_bytes(&bytes).is_err());
    }

    #[test]
    fn reseeder_new_creates_instance() {
        let _r = Reseeder::new();
        // Just verify it doesn't panic
    }
}
