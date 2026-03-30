//! Router transport address.
//!
//! A [`RouterAddress`] describes one reachable endpoint of a router —
//! the transport style (e.g. `"NTCP2"`, `"SSU2"`), the IP:port, and
//! any additional transport-specific options.
//!
//! Java equivalent: `net.i2p.data.router.RouterAddress`

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};

/// Transport cost (lower is better) — used by the transport bidding system.
pub type Cost = u8;

/// A single reachable transport address published by a router.
///
/// Routers publish one [`RouterAddress`] per transport per IP family in the
/// NetDB.  Peers select the address with the lowest cost when bidding for a
/// connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterAddress {
    /// Transport identifier, e.g. `"NTCP2"` or `"SSU2"`.
    pub transport_style: String,
    /// Relative cost (lower = preferred).  The router uses this when
    /// multiple transports are available to the same peer.
    pub cost: Cost,
    /// Expiration timestamp (milliseconds since epoch), or `None` for
    /// permanent addresses.
    pub expiration: Option<u64>,
    /// Transport-specific key/value options (e.g. `"host"`, `"port"`,
    /// `"s"` for the static public key, `"i"` for the introduction key).
    pub options: HashMap<String, String>,
}

impl RouterAddress {
    /// Create a new transport address.
    pub fn new(transport_style: impl Into<String>, cost: Cost) -> Self {
        Self {
            transport_style: transport_style.into(),
            cost,
            expiration: None,
            options: HashMap::new(),
        }
    }

    /// Insert or update a transport option.
    pub fn set_option(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.options.insert(key.into(), value.into());
    }

    /// Return the socket address (`host:port`) for this transport, if
    /// available as a standard IP+port pair in the options.
    ///
    /// NTCP2 and SSU2 both publish `"host"` and `"port"` options.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        let host = self.options.get("host")?;
        let port: u16 = self.options.get("port")?.parse().ok()?;
        let ip: IpAddr = host.parse().ok()?;
        Some(SocketAddr::new(ip, port))
    }

    /// Return `true` if this address has expired relative to `now_ms`
    /// (milliseconds since epoch).
    pub fn is_expired(&self, now_ms: u64) -> bool {
        self.expiration.map_or(false, |exp| exp < now_ms)
    }
}

impl fmt::Display for RouterAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.transport_style)?;
        if let Some(addr) = self.socket_addr() {
            write!(f, " @ {addr}")?;
        }
        write!(f, " (cost={})", self.cost)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_addr_parsed() {
        let mut addr = RouterAddress::new("NTCP2", 10);
        addr.set_option("host", "203.0.113.1");
        addr.set_option("port", "4567");
        let sa = addr.socket_addr().unwrap();
        assert_eq!(sa.port(), 4567);
    }

    #[test]
    fn missing_port_returns_none() {
        let mut addr = RouterAddress::new("SSU2", 5);
        addr.set_option("host", "203.0.113.1");
        assert!(addr.socket_addr().is_none());
    }

    #[test]
    fn expiration_check() {
        let mut addr = RouterAddress::new("SSU2", 5);
        addr.expiration = Some(1_000);
        assert!(addr.is_expired(2_000));
        assert!(!addr.is_expired(500));
    }
}
