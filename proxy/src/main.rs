//! The proxy server.
//!
//! Two backends serve the same API and are selected with `PROXY_MODE`:
//!
//! * `pool` (default) -- M3's worker pool: N OS threads, N sessions, bounded queue.
//! * `single` -- M2's baseline: one session behind a mutex, blocking the runtime.
//!
//! Keeping the baseline runnable is what makes the improvement measurable: flipping one
//! variable with the gRPC stack, codec, and handlers held identical isolates the pool's
//! contribution far better than comparing two separately written programs.

use std::sync::Arc;

use anyhow::{Context, Result};
use grpc_low_latency_proxy::authz::{Authorizer, Policy};
use grpc_low_latency_proxy::cache::{CacheConfig, PublicKeyCache};
use grpc_low_latency_proxy::grpc::{PooledService, SingleSessionService};
use grpc_low_latency_proxy::pkcs11::{Pool, PoolConfig, TokenConfig};
use grpc_low_latency_proxy::proto::v1::hsm_service_server::HsmServiceServer;
use grpc_low_latency_proxy::proto::v1::FILE_DESCRIPTOR_SET;
use grpc_low_latency_proxy::resilience::{
    BreakerConfig, CircuitBreaker, RateLimitConfig, RateLimiter,
};
use grpc_low_latency_proxy::telemetry;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    // rustls refuses to pick a crypto provider when more than one is available, and
    // this crate makes two reachable: tonic's tls-ring feature, and the `ring` used
    // directly for in-process ECDSA verification (M5). Without an explicit choice the
    // server panics on the first TLS handshake -- which only shows up when TLS is on,
    // so local plaintext benchmarking never hit it.
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        tracing::debug!("a rustls crypto provider was already installed");
    }

    // Installed before anything else records: metrics emitted before the recorder exists
    // are silently dropped, which shows up later as a dashboard panel that is empty for
    // no discoverable reason.
    let prometheus = telemetry::install()?;

    let token = TokenConfig::from_env()?;
    let listen_addr: std::net::SocketAddr = std::env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:50051".to_string())
        .parse()
        .context("LISTEN_ADDR is not a valid socket address")?;

    // mTLS and the policy travel together: without a client certificate there is no
    // identity, and without an identity the policy cannot be evaluated. Enabling one
    // without the other would be security theatre, so they are configured as a unit.
    let security = load_security()?;
    let admission = AdmissionConfig::from_env();
    tracing::info!(
        max_concurrent_streams = ?admission.max_concurrent_streams,
        concurrency_limit_per_connection = ?admission.concurrency_limit_per_connection,
        request_timeout_ms = ?admission.request_timeout.map(|d| d.as_millis()),
        "admission control"
    );

    let reflection = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
        .build_v1()
        .context("failed to build the gRPC reflection service")?;

    let mode = std::env::var("PROXY_MODE").unwrap_or_else(|_| "pool".to_string());
    tracing::info!(
        module = %token.module_path,
        token = %token.token_label,
        %mode,
        "opening PKCS#11 token"
    );

    match mode.as_str() {
        "pool" => {
            let pool_config = PoolConfig::from_env();
            let pool_workers = pool_config.workers;
            let pool = Arc::new(
                Pool::start(token, pool_config)
                    .map_err(|e| anyhow::anyhow!("failed to start worker pool: {e}"))?,
            );

            let authorizer = security.as_ref().map(|s| Arc::clone(&s.authorizer));
            let cache_config = CacheConfig::from_env();
            tracing::info!(
                ttl_secs = cache_config.ttl.as_secs(),
                negative_ttl_secs = cache_config.negative_ttl.as_secs(),
                max_entries = cache_config.max_entries,
                "public key cache enabled"
            );
            let cache = Arc::new(PublicKeyCache::new(cache_config));

            let breaker = Arc::new(CircuitBreaker::new(BreakerConfig::from_env()));

            let rate_limiter = RateLimitConfig::from_env().map(|config| {
                tracing::info!(
                    per_second = config.per_second,
                    burst = config.burst,
                    "per-identity rate limiting enabled"
                );
                Arc::new(RateLimiter::new(config))
            });
            if rate_limiter.is_none() {
                tracing::info!("rate limiting disabled (set RATE_LIMIT_PER_SECOND to enable)");
            }

            metrics::gauge!(telemetry::metrics::WORKERS).set(pool_workers as f64);
            telemetry::spawn_gauge_sampler(
                Arc::clone(&pool),
                Arc::clone(&cache),
                Arc::clone(&breaker),
                std::time::Duration::from_secs(1),
            );

            let metrics_addr: std::net::SocketAddr = std::env::var("METRICS_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:9090".to_string())
                .parse()
                .context("METRICS_ADDR is not a valid socket address")?;
            tokio::spawn(async move {
                if let Err(e) = telemetry::serve(prometheus, metrics_addr).await {
                    tracing::error!(error = %e, "metrics endpoint stopped");
                }
            });

            let service = PooledService::new(
                Arc::clone(&pool),
                authorizer,
                Arc::clone(&cache),
                rate_limiter.clone(),
                Arc::clone(&breaker),
            );
            tracing::info!(%listen_addr, tls = security.is_some(), "gRPC server listening");

            server_builder(&security, &admission)?
                .add_service(HsmServiceServer::new(service))
                .add_service(reflection)
                .serve_with_shutdown(listen_addr, shutdown_signal())
                .await
                .context("gRPC server failed")?;

            report_pool_metrics(&pool);
            {
                use std::sync::atomic::Ordering;
                tracing::info!(
                    state = breaker.state().as_str(),
                    trips = breaker.trips.load(Ordering::Relaxed),
                    rejected = breaker.rejected.load(Ordering::Relaxed),
                    "circuit breaker metrics"
                );
                if let Some(limiter) = &rate_limiter {
                    tracing::info!(
                        allowed = limiter.allowed.load(Ordering::Relaxed),
                        rejected = limiter.rejected.load(Ordering::Relaxed),
                        "rate limiter metrics"
                    );
                }
            }
            {
                let m = cache.metrics();
                tracing::info!(
                    hits = m.hits.load(std::sync::atomic::Ordering::Relaxed),
                    misses = m.misses.load(std::sync::atomic::Ordering::Relaxed),
                    negative_hits = m.negative_hits.load(std::sync::atomic::Ordering::Relaxed),
                    hit_ratio = format!("{:.4}", m.hit_ratio()),
                    entries = cache.entry_count(),
                    "public key cache metrics"
                );
            }
            if let Some(security) = &security {
                let m = security.authorizer.metrics();
                tracing::info!(
                    allowed = m.allowed_total.load(std::sync::atomic::Ordering::Relaxed),
                    denied = m.denied_total.load(std::sync::atomic::Ordering::Relaxed),
                    unauthenticated = m
                        .unauthenticated_total
                        .load(std::sync::atomic::Ordering::Relaxed),
                    "authorization metrics"
                );
            }

            // Drain in-flight work before the module is finalized.
            match Arc::try_unwrap(pool) {
                Ok(pool) => pool.shutdown(),
                Err(_) => tracing::warn!("pool still referenced at shutdown; skipping drain"),
            }
        }

        "single" => {
            let service = SingleSessionService::connect(&token)?;
            tracing::info!(%listen_addr, tls = security.is_some(), "gRPC server listening (M2 baseline)");

            server_builder(&security, &admission)?
                .add_service(HsmServiceServer::new(service))
                .add_service(reflection)
                .serve_with_shutdown(listen_addr, shutdown_signal())
                .await
                .context("gRPC server failed")?;
        }

        other => anyhow::bail!("PROXY_MODE must be 'pool' or 'single', got '{other}'"),
    }

    tracing::info!("shutdown complete");
    Ok(())
}

/// Queue wait against service time is the pair that makes the pool legible: service time
/// is what the token costs, queue wait is what the design costs under load.
fn report_pool_metrics(pool: &Pool) {
    use grpc_low_latency_proxy::pkcs11::metrics::PoolMetrics;

    let m = pool.metrics();
    tracing::info!(
        submitted = PoolMetrics::get(&m.jobs_submitted),
        completed = PoolMetrics::get(&m.jobs_completed),
        failed = PoolMetrics::get(&m.jobs_failed),
        rejected_queue_full = PoolMetrics::get(&m.jobs_rejected_queue_full),
        timed_out = PoolMetrics::get(&m.jobs_timed_out),
        session_resets = PoolMetrics::get(&m.session_resets),
        handle_cache_hits = PoolMetrics::get(&m.handle_cache_hits),
        handle_cache_misses = PoolMetrics::get(&m.handle_cache_misses),
        mean_queue_wait_us = m.mean_queue_wait_micros(),
        mean_service_us = m.mean_service_micros(),
        "pool metrics"
    );
}

/// TLS material plus the policy compiled from it.
struct Security {
    tls: ServerTlsConfig,
    authorizer: Arc<Authorizer>,
}

/// Admission control applied at the transport, before a request becomes a task.
///
/// M6 measured where overload latency actually accrues: with the pool's bounded queue
/// as the only defence, queue wait was 308 us and HSM service 259 us, while the p99 of
/// *accepted* requests reached ~9 ms. Roughly 97% of that was spent before the request
/// ever reached the shedding point -- in HTTP/2 stream handling and Tokio scheduling
/// under heavy contention.
///
/// Shedding at the pool queue protects the pool. It does not protect the tail, because
/// by then the damage is done. These limits push the refusal upstream:
///
/// * `max_concurrent_streams` bounds how many requests HTTP/2 will accept at once, so
///   excess waits at the protocol level instead of becoming a scheduled task.
/// * `concurrency_limit_per_connection` bounds in-flight handler work.
/// * `load_shed` turns "at the limit" into an immediate rejection rather than a queue.
struct AdmissionConfig {
    max_concurrent_streams: Option<u32>,
    concurrency_limit_per_connection: Option<usize>,
    request_timeout: Option<std::time::Duration>,
}

impl AdmissionConfig {
    fn from_env() -> Self {
        fn env_parse<T: std::str::FromStr>(key: &str) -> Option<T> {
            std::env::var(key).ok()?.parse().ok()
        }
        Self {
            max_concurrent_streams: env_parse("MAX_CONCURRENT_STREAMS"),
            concurrency_limit_per_connection: env_parse("CONCURRENCY_LIMIT_PER_CONNECTION"),
            request_timeout: env_parse::<u64>("REQUEST_TIMEOUT_MS")
                .map(std::time::Duration::from_millis),
        }
    }
}

/// A server builder with TLS and admission control applied.
fn server_builder(security: &Option<Security>, admission: &AdmissionConfig) -> Result<Server> {
    let mut builder = match security {
        Some(security) => Server::builder()
            .tls_config(security.tls.clone())
            .context("failed to apply TLS configuration")?,
        None => Server::builder(),
    };

    if let Some(streams) = admission.max_concurrent_streams {
        builder = builder.max_concurrent_streams(Some(streams));
    }

    if let Some(limit) = admission.concurrency_limit_per_connection {
        // load_shed is what makes the limit protect the tail rather than merely cap
        // it: without it, requests over the limit wait in a tower queue, which is the
        // unbounded-queueing failure this whole milestone exists to avoid.
        builder = builder
            .concurrency_limit_per_connection(limit)
            .load_shed(true);
    }

    if let Some(timeout) = admission.request_timeout {
        builder = builder.timeout(timeout);
    }

    Ok(builder)
}

/// Load certificates and the authorization policy.
///
/// Defaults to requiring mTLS. Running without it is possible -- the benchmark A/B needs
/// a plaintext baseline to measure TLS cost against -- but it must be asked for
/// explicitly and it announces itself loudly, because a server that silently accepts
/// anonymous callers is the failure this whole milestone exists to prevent.
fn load_security() -> Result<Option<Security>> {
    let enabled = std::env::var("PROXY_TLS").unwrap_or_else(|_| "on".to_string());
    if enabled == "off" {
        tracing::warn!(
            "PROXY_TLS=off: serving PLAINTEXT with NO client authentication and NO \
             authorization policy. Every caller is anonymous and every key is reachable. \
             This is for benchmarking only."
        );
        return Ok(None);
    }

    let cert_dir = std::env::var("CERT_DIR").unwrap_or_else(|_| "certs".to_string());
    let policy_path =
        std::env::var("AUTHZ_POLICY").unwrap_or_else(|_| "policy/authz.toml".to_string());

    let read = |name: &str| -> Result<Vec<u8>> {
        let path = std::path::Path::new(&cert_dir).join(name);
        std::fs::read(&path).with_context(|| {
            format!(
                "failed to read {}; run scripts/gen-certs.sh, or set PROXY_TLS=off",
                path.display()
            )
        })
    };

    let identity = Identity::from_pem(read("server.crt")?, read("server.key")?);
    let client_ca = Certificate::from_pem(read("ca.crt")?);

    // client_ca_root is what turns TLS into *mutual* TLS: without it the server proves
    // its own identity and accepts anyone. Rejection happens during the handshake, so an
    // unauthenticated caller never reaches a handler.
    let tls = ServerTlsConfig::new()
        .identity(identity)
        .client_ca_root(client_ca);

    let policy = Policy::load(&policy_path)?;
    tracing::info!(
        policy = %policy_path,
        identities = policy.identity_count(),
        grants = policy.grant_count(),
        "mTLS enabled; authorization policy loaded"
    );

    Ok(Some(Security {
        tls,
        authorizer: Arc::new(Authorizer::new(policy)),
    }))
}

fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,grpc_low_latency_proxy=debug"));

    fmt().with_env_filter(filter).with_target(true).init();
}

/// Resolve on SIGINT or SIGTERM. SIGTERM matters because that is what Docker sends;
/// without it every `docker compose down` would be a 10-second timeout and a kill.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install SIGINT handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("received SIGINT, shutting down"),
        _ = terminate => tracing::info!("received SIGTERM, shutting down"),
    }
}
