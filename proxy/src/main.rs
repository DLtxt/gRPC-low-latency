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
use grpc_low_latency_proxy::grpc::{PooledService, SingleSessionService};
use grpc_low_latency_proxy::pkcs11::{Pool, PoolConfig, TokenConfig};
use grpc_low_latency_proxy::proto::v1::hsm_service_server::HsmServiceServer;
use grpc_low_latency_proxy::proto::v1::FILE_DESCRIPTOR_SET;
use tonic::transport::Server;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let token = TokenConfig::from_env()?;
    let listen_addr: std::net::SocketAddr = std::env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:50051".to_string())
        .parse()
        .context("LISTEN_ADDR is not a valid socket address")?;

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
            let pool = Arc::new(
                Pool::start(token, PoolConfig::from_env())
                    .map_err(|e| anyhow::anyhow!("failed to start worker pool: {e}"))?,
            );

            let service = PooledService::new(Arc::clone(&pool));
            tracing::info!(%listen_addr, "gRPC server listening");

            Server::builder()
                .add_service(HsmServiceServer::new(service))
                .add_service(reflection)
                .serve_with_shutdown(listen_addr, shutdown_signal())
                .await
                .context("gRPC server failed")?;

            report_pool_metrics(&pool);

            // Drain in-flight work before the module is finalized.
            match Arc::try_unwrap(pool) {
                Ok(pool) => pool.shutdown(),
                Err(_) => tracing::warn!("pool still referenced at shutdown; skipping drain"),
            }
        }

        "single" => {
            let service = SingleSessionService::connect(&token)?;
            tracing::info!(%listen_addr, "gRPC server listening (M2 baseline)");

            Server::builder()
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
