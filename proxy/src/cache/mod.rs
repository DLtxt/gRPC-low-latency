//! In-process caching of public key material.
//!
//! Only public artifacts are ever cached. Private keys never leave the token, and
//! signatures, plaintext, decrypt results, and PINs are never stored -- see plan.md 4.4.
//! This is the most important invariant in the file: the cache exists to remove the HSM
//! from paths that do not need it, never to shortcut paths that do.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use moka::future::Cache;

/// A public key as the token gave it to us, re-encoded as DER SubjectPublicKeyInfo.
#[derive(Clone, Debug)]
pub struct CachedPublicKey {
    pub spki_der: Arc<Vec<u8>>,
    pub key_type: Arc<str>,
}

/// Cached lookup outcome. Negative results are cached too, on a much shorter TTL:
/// without that, a client hammering a nonexistent label turns every request into a
/// `C_FindObjects` across all workers -- a cache-miss stampede driven by bad input.
#[derive(Clone, Debug)]
pub enum Lookup {
    Found(CachedPublicKey),
    NotFound,
}

#[derive(Default, Debug)]
pub struct CacheMetrics {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub negative_hits: AtomicU64,
}

impl CacheMetrics {
    pub fn hit_ratio(&self) -> f64 {
        let hits = self.hits.load(Ordering::Relaxed) as f64;
        let misses = self.misses.load(Ordering::Relaxed) as f64;
        if hits + misses == 0.0 {
            0.0
        } else {
            hits / (hits + misses)
        }
    }
}

#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub ttl: Duration,
    pub negative_ttl: Duration,
    pub max_entries: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            // Long enough to matter, short enough that a key rotated under the same
            // label starts verifying against the new key within minutes rather than
            // requiring a restart.
            ttl: Duration::from_secs(300),
            negative_ttl: Duration::from_secs(30),
            max_entries: 1024,
        }
    }
}

impl CacheConfig {
    pub fn from_env() -> Self {
        let defaults = Self::default();
        let secs = |key: &str| -> Option<Duration> {
            std::env::var(key)
                .ok()?
                .parse()
                .ok()
                .map(Duration::from_secs)
        };
        Self {
            ttl: secs("CACHE_TTL_SECS").unwrap_or(defaults.ttl),
            negative_ttl: secs("CACHE_NEGATIVE_TTL_SECS").unwrap_or(defaults.negative_ttl),
            max_entries: std::env::var("CACHE_MAX_ENTRIES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(defaults.max_entries),
        }
    }
}

/// Public key cache with per-outcome TTLs and single-flight loading.
pub struct PublicKeyCache {
    entries: Cache<String, Lookup>,
    metrics: Arc<CacheMetrics>,
}

impl PublicKeyCache {
    pub fn new(config: CacheConfig) -> Self {
        let entries = Cache::builder()
            .max_capacity(config.max_entries)
            // Per-entry expiry so a negative result can live 30s while a real key lives
            // 5 minutes. One cache-wide TTL would force one of the two to be wrong.
            .expire_after(TtlByOutcome {
                positive_ttl: config.ttl,
                negative_ttl: config.negative_ttl,
            })
            .build();

        Self {
            entries,
            metrics: Arc::new(CacheMetrics::default()),
        }
    }

    pub fn metrics(&self) -> &Arc<CacheMetrics> {
        &self.metrics
    }

    pub fn entry_count(&self) -> u64 {
        self.entries.entry_count()
    }

    /// Fetch `key_label`, loading it through `load` on a miss.
    ///
    /// Uses `try_get_with`, so a cold key under heavy concurrent load produces exactly
    /// one HSM lookup rather than one per in-flight request. Without single-flight, the
    /// first request for a popular key at 5,000 QPS would fire 5,000 `C_FindObjects`
    /// calls and stall every worker at once.
    /// Returns the entry and whether it was already cached, which the API surfaces to
    /// callers as `served_from_cache` so a client can see the HSM leaving the path.
    pub async fn get_or_load<F, Fut, E>(
        &self,
        key_label: &str,
        load: F,
    ) -> Result<(Lookup, bool), Arc<E>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<Lookup, E>>,
        // moka may hand the error to other waiters on the same key, so it has to
        // outlive and cross threads.
        E: Send + Sync + 'static,
    {
        // A cheap probe used only to attribute hits and misses. `try_get_with_by_ref`
        // below is what actually decides, and it is race-free.
        let was_present = self.entries.contains_key(key_label);

        let result = self.entries.try_get_with_by_ref(key_label, load()).await?;

        if was_present {
            self.metrics.hits.fetch_add(1, Ordering::Relaxed);
            if matches!(result, Lookup::NotFound) {
                self.metrics.negative_hits.fetch_add(1, Ordering::Relaxed);
            }
        } else {
            self.metrics.misses.fetch_add(1, Ordering::Relaxed);
        }

        Ok((result, was_present))
    }

    /// Drop a cached entry, so a rotated key takes effect without waiting out the TTL.
    pub async fn invalidate(&self, key_label: &str) {
        self.entries.invalidate(key_label).await;
    }
}

/// Expiry policy that distinguishes found from not-found.
struct TtlByOutcome {
    positive_ttl: Duration,
    negative_ttl: Duration,
}

impl moka::Expiry<String, Lookup> for TtlByOutcome {
    fn expire_after_create(
        &self,
        _key: &String,
        value: &Lookup,
        _created_at: std::time::Instant,
    ) -> Option<Duration> {
        Some(match value {
            Lookup::Found(_) => self.positive_ttl,
            Lookup::NotFound => self.negative_ttl,
        })
    }
}
