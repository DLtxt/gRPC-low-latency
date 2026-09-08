//! Per-identity token-bucket rate limiting.
//!
//! Keyed by workload identity rather than by connection or IP, because the thing worth
//! protecting is fair share between *callers*. A single client opening fifty connections
//! is still one workload and should get one workload's share.

use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter as Governor};
use moka::sync::Cache;

type DirectLimiter = Governor<NotKeyed, InMemoryState, DefaultClock>;

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Sustained requests per second allowed per identity.
    pub per_second: u32,
    /// Additional requests tolerated in a burst.
    pub burst: u32,
    /// Cap on tracked identities, so the map cannot grow without bound.
    pub max_identities: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            // Deliberately high. The default exists to stop one caller monopolising the
            // service, not to be a quota -- a limit set below real capacity would turn
            // this from a safety net into the bottleneck it is meant to prevent.
            per_second: 20_000,
            burst: 2_000,
            max_identities: 4_096,
        }
    }
}

impl RateLimitConfig {
    pub fn from_env() -> Option<Self> {
        // Absent configuration means no rate limiting. Enabling it silently with a
        // guessed number would risk rejecting legitimate load nobody asked us to reject.
        let per_second: u32 = std::env::var("RATE_LIMIT_PER_SECOND").ok()?.parse().ok()?;
        let d = Self::default();
        Some(Self {
            per_second,
            burst: std::env::var("RATE_LIMIT_BURST")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(d.burst),
            max_identities: d.max_identities,
        })
    }
}

/// Token buckets, one per identity, evicted by a bounded cache.
pub struct RateLimiter {
    buckets: Cache<Arc<str>, Arc<DirectLimiter>>,
    quota: Quota,
    pub allowed: AtomicU64,
    pub rejected: AtomicU64,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        let per_second = NonZeroU32::new(config.per_second.max(1)).expect("non-zero");
        let burst = NonZeroU32::new(config.burst.max(1)).expect("non-zero");

        Self {
            buckets: Cache::builder().max_capacity(config.max_identities).build(),
            quota: Quota::per_second(per_second).allow_burst(burst),
            allowed: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
        }
    }

    /// Consume one token for `identity`. False means the caller is over their limit.
    pub fn check(&self, identity: &Arc<str>) -> bool {
        let limiter = self
            .buckets
            .get_with_by_ref(identity, || Arc::new(Governor::direct(self.quota)));

        match limiter.check() {
            Ok(()) => {
                self.allowed.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(_) => {
                self.rejected.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_within_burst() {
        let limiter = RateLimiter::new(RateLimitConfig {
            per_second: 10,
            burst: 5,
            max_identities: 16,
        });
        let identity: Arc<str> = "spiffe://local/ns/default/sa/test".into();

        for i in 0..5 {
            assert!(limiter.check(&identity), "request {i} should be allowed");
        }
    }

    #[test]
    fn rejects_beyond_burst() {
        let limiter = RateLimiter::new(RateLimitConfig {
            per_second: 1,
            burst: 2,
            max_identities: 16,
        });
        let identity: Arc<str> = "greedy".into();

        assert!(limiter.check(&identity));
        assert!(limiter.check(&identity));
        assert!(!limiter.check(&identity), "third request exceeds the burst");
        assert_eq!(limiter.rejected.load(Ordering::Relaxed), 1);
    }

    /// One caller exhausting its bucket must not affect anyone else -- the entire point
    /// of keying per identity.
    #[test]
    fn identities_are_isolated() {
        let limiter = RateLimiter::new(RateLimitConfig {
            per_second: 1,
            burst: 2,
            max_identities: 16,
        });
        let greedy: Arc<str> = "greedy".into();
        let quiet: Arc<str> = "quiet".into();

        for _ in 0..5 {
            let _ = limiter.check(&greedy);
        }
        assert!(!limiter.check(&greedy), "greedy caller is limited");
        assert!(limiter.check(&quiet), "quiet caller is unaffected");
    }
}
