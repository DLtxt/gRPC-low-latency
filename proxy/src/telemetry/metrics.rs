//! Prometheus metrics.
//!
//! The histogram buckets are the part worth attention. Default Prometheus buckets start
//! at 5 ms, which is useless here: the entire latency budget is 2 ms, so every request
//! would land in the first bucket and p99 would be unmeasurable from the histogram. The
//! buckets below start at 100 microseconds and are dense through the budget, so the
//! dashboard can actually show where the tail sits relative to the target.

use std::time::Duration;

use anyhow::{Context, Result};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};

// --- metric names ------------------------------------------------------------------
// Prefixed `hsm_` per plan.md. Suffixes follow Prometheus convention: _total for
// counters, _seconds for durations.

pub const REQUESTS_TOTAL: &str = "hsm_requests_total";
pub const REQUEST_DURATION: &str = "hsm_request_duration_seconds";
pub const QUEUE_WAIT: &str = "hsm_queue_wait_seconds";
pub const HSM_SERVICE: &str = "hsm_service_duration_seconds";

pub const QUEUE_DEPTH: &str = "hsm_queue_depth";
pub const WORKERS: &str = "hsm_workers";

pub const CACHE_HITS: &str = "hsm_cache_hits_total";
pub const CACHE_MISSES: &str = "hsm_cache_misses_total";
pub const CACHE_ENTRIES: &str = "hsm_cache_entries";

pub const AUTHZ_DENIED: &str = "hsm_authz_denied_total";
pub const AUTHZ_ALLOWED: &str = "hsm_authz_allowed_total";
pub const UNAUTHENTICATED: &str = "hsm_unauthenticated_total";

pub const SHED_TOTAL: &str = "hsm_shed_total";
pub const RATE_LIMITED: &str = "hsm_rate_limited_total";
pub const BREAKER_STATE: &str = "hsm_circuit_breaker_state";
pub const BREAKER_TRIPS: &str = "hsm_circuit_breaker_trips_total";
pub const SESSION_RESETS: &str = "hsm_session_resets_total";

/// End-to-end request latency, in seconds.
///
/// Dense from 100 us to 2 ms because that range is where the acceptance criterion lives;
/// sparse above it, because once a request is past 10 ms the only question is how bad.
const REQUEST_BUCKETS: &[f64] = &[
    0.0001, 0.00025, 0.0005, 0.00075, // 100-750 us
    0.001, 0.00125, 0.0015, 0.00175, 0.002, // 1-2 ms: the budget
    0.003, 0.005, 0.0075, 0.01, // 3-10 ms: over budget
    0.025, 0.05, 0.1, 0.5, 1.0, // pathological
];

/// Queue wait and HSM service time separately. Their ratio is the graph that makes the
/// pool legible: service time is what the token costs, queue wait is what the design
/// costs under load.
const INTERNAL_BUCKETS: &[f64] = &[
    0.00001, 0.000025, 0.00005, 0.0001, 0.00025, 0.0005, 0.00075, 0.001, 0.0025, 0.005, 0.01, 0.05,
    0.1,
];

/// Install the Prometheus recorder and return a handle that renders the exposition text.
pub fn install() -> Result<PrometheusHandle> {
    let handle = PrometheusBuilder::new()
        .set_buckets_for_metric(Matcher::Full(REQUEST_DURATION.to_string()), REQUEST_BUCKETS)
        .context("failed to set request buckets")?
        .set_buckets_for_metric(Matcher::Full(QUEUE_WAIT.to_string()), INTERNAL_BUCKETS)
        .context("failed to set queue buckets")?
        .set_buckets_for_metric(Matcher::Full(HSM_SERVICE.to_string()), INTERNAL_BUCKETS)
        .context("failed to set service buckets")?
        // Idle timeout on nothing: these series are few and long-lived, and expiring
        // them would make a quiet key look like it vanished rather than went quiet.
        .install_recorder()
        .context("failed to install the Prometheus recorder")?;

    describe();
    Ok(handle)
}

/// Register descriptions so `/metrics` is self-documenting.
fn describe() {
    use metrics::{describe_counter, describe_gauge, describe_histogram, Unit};

    describe_counter!(REQUESTS_TOTAL, "gRPC requests by operation and result");
    describe_histogram!(
        REQUEST_DURATION,
        Unit::Seconds,
        "End-to-end request latency, measured inside the handler"
    );
    describe_histogram!(QUEUE_WAIT, Unit::Seconds, "Time a job waited for a worker");
    describe_histogram!(HSM_SERVICE, Unit::Seconds, "Time a worker spent in PKCS#11");
    describe_gauge!(QUEUE_DEPTH, "Jobs currently waiting for a worker");
    describe_gauge!(WORKERS, "Worker threads, each owning one PKCS#11 session");
    describe_counter!(CACHE_HITS, "Public key cache hits");
    describe_counter!(CACHE_MISSES, "Public key cache misses");
    describe_gauge!(CACHE_ENTRIES, "Public keys currently cached");
    describe_counter!(AUTHZ_DENIED, "Requests denied by the authorization policy");
    describe_counter!(
        AUTHZ_ALLOWED,
        "Requests permitted by the authorization policy"
    );
    describe_counter!(
        UNAUTHENTICATED,
        "Requests with no usable client certificate"
    );
    describe_counter!(SHED_TOTAL, "Requests shed because the queue was full");
    describe_counter!(
        RATE_LIMITED,
        "Requests rejected by the per-identity rate limit"
    );
    describe_gauge!(
        BREAKER_STATE,
        "Circuit breaker: 0 closed, 1 open, 2 half-open"
    );
    describe_counter!(BREAKER_TRIPS, "Times the circuit breaker has opened");
    describe_counter!(
        SESSION_RESETS,
        "PKCS#11 sessions reopened after a fatal error"
    );
}

/// Serve `/metrics` on its own port.
///
/// Deliberately separate from the gRPC port: scraping should not require a client
/// certificate, and the metrics endpoint should stay reachable when the gRPC service is
/// shedding load -- an observability endpoint that fails under overload is worthless
/// exactly when it is needed.
pub async fn serve(handle: PrometheusHandle, addr: std::net::SocketAddr) -> Result<()> {
    use axum::{routing::get, Router};

    let app = Router::new()
        .route(
            "/metrics",
            get(move || {
                let handle = handle.clone();
                async move { handle.render() }
            }),
        )
        .route("/healthz", get(|| async { "ok" }));

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind the metrics listener on {addr}"))?;

    tracing::info!(%addr, "metrics endpoint listening on /metrics");

    axum::serve(listener, app)
        .await
        .context("metrics server failed")
}

/// Sample the gauges that are not event-driven.
///
/// Counters are incremented where the events happen; these are levels that have to be
/// read from the owning structure, so a periodic sampler is simpler than threading a
/// recorder handle through the pool and cache.
pub fn spawn_gauge_sampler(
    pool: std::sync::Arc<crate::pkcs11::Pool>,
    cache: std::sync::Arc<crate::cache::PublicKeyCache>,
    breaker: std::sync::Arc<crate::resilience::CircuitBreaker>,
    interval: Duration,
) {
    use crate::pkcs11::metrics::PoolMetrics;
    use metrics::{counter, gauge};
    use std::sync::atomic::Ordering;

    tokio::spawn(async move {
        // Counters here are absolute totals, so track the previous value and report the
        // delta -- `counter!().increment()` is additive, and feeding it a total would
        // make the series grow quadratically.
        let mut last_hits = 0u64;
        let mut last_misses = 0u64;
        let mut last_shed = 0u64;
        let mut last_resets = 0u64;
        let mut ticker = tokio::time::interval(interval);

        loop {
            ticker.tick().await;

            gauge!(QUEUE_DEPTH).set(pool.queue_len() as f64);
            gauge!(CACHE_ENTRIES).set(cache.entry_count() as f64);
            gauge!(BREAKER_STATE).set(match breaker.state() {
                crate::resilience::BreakerState::Closed => 0.0,
                crate::resilience::BreakerState::Open => 1.0,
                crate::resilience::BreakerState::HalfOpen => 2.0,
            });

            let m = cache.metrics();
            let hits = m.hits.load(Ordering::Relaxed);
            let misses = m.misses.load(Ordering::Relaxed);
            counter!(CACHE_HITS).increment(hits.saturating_sub(last_hits));
            counter!(CACHE_MISSES).increment(misses.saturating_sub(last_misses));
            last_hits = hits;
            last_misses = misses;

            let pm = pool.metrics();
            let shed = PoolMetrics::get(&pm.jobs_rejected_queue_full);
            let resets = PoolMetrics::get(&pm.session_resets);
            counter!(SHED_TOTAL).increment(shed.saturating_sub(last_shed));
            counter!(SESSION_RESETS).increment(resets.saturating_sub(last_resets));
            last_shed = shed;
            last_resets = resets;

            counter!(BREAKER_TRIPS).absolute(breaker.trips.load(Ordering::Relaxed));
        }
    });
}
