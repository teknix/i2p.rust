//! Token-bucket bandwidth limiter.
//!
//! The I2P router rate-limits outbound and inbound traffic using a FIFO token
//! bucket as described in `FIFOBandwidthLimiter.java`.  Tokens refill at a
//! configured rate; senders must acquire tokens before transmitting.

use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// A token-bucket rate limiter.
///
/// Tokens accumulate at `rate_bytes_per_sec` up to `burst_bytes`.  A sender
/// calls [`BandwidthLimiter::acquire`] to consume tokens; the call is async
/// and will wait until enough tokens are available.
pub struct BandwidthLimiter {
    state: Mutex<LimiterState>,
}

struct LimiterState {
    /// Available tokens (bytes that may be sent immediately).
    tokens: f64,
    /// Maximum burst size in bytes.
    burst: f64,
    /// Token refill rate in bytes per second.
    rate: f64,
    /// When we last refilled.
    last_refill: Instant,
}

impl BandwidthLimiter {
    /// Create a new limiter.
    ///
    /// - `rate_bytes_per_sec`: sustained throughput cap.
    /// - `burst_bytes`: maximum instantaneous burst size.
    pub fn new(rate_bytes_per_sec: f64, burst_bytes: f64) -> Self {
        Self {
            state: Mutex::new(LimiterState {
                tokens: burst_bytes,
                burst: burst_bytes,
                rate: rate_bytes_per_sec,
                last_refill: Instant::now(),
            }),
        }
    }

    /// Acquire `bytes` tokens, sleeping if necessary.
    ///
    /// Returns when the tokens have been consumed.
    pub async fn acquire(&self, bytes: usize) {
        let needed = bytes as f64;
        loop {
            let wait = {
                let mut s = self.state.lock().await;
                let now = Instant::now();
                let elapsed = now.duration_since(s.last_refill).as_secs_f64();
                s.tokens = (s.tokens + elapsed * s.rate).min(s.burst);
                s.last_refill = now;

                if s.tokens >= needed {
                    s.tokens -= needed;
                    None
                } else {
                    let deficit = needed - s.tokens;
                    Some(Duration::from_secs_f64(deficit / s.rate))
                }
            };

            match wait {
                None => return,
                Some(d) => tokio::time::sleep(d).await,
            }
        }
    }

    /// Return the current token count (approximate, for monitoring).
    pub async fn available_bytes(&self) -> f64 {
        self.state.lock().await.tokens
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn acquire_within_burst() {
        // 1 MB burst, unlimited rate — acquire should be instant.
        let lim = BandwidthLimiter::new(1_000_000.0, 1_000_000.0);
        lim.acquire(512).await;
        let remaining = lim.available_bytes().await;
        assert!(remaining < 1_000_000.0);
    }
}
