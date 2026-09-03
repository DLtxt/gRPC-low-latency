//! The proxy server.
//!
//! M2: serves the `hsm.v1` API from a single PKCS#11 session behind a mutex, plus gRPC
//! reflection so `grpcurl` can drive it without a copy of the `.proto`.

use anyhow::{Context, Result};
use grpc_low_latency_proxy::grpc::SingleSessionService;
use grpc_low_latency_proxy::pkcs11::TokenConfig;
use grpc_low_latency_proxy::proto::v1::hsm_service_server::HsmServiceServer;
use grpc_low_latency_proxy::proto::v1::FILE_DESCRIPTOR_SET;
use tonic::transport::Server;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let config = TokenConfig::from_env()?;
    let listen_addr: std::net::SocketAddr = std::env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:50051".to_string())
        .parse()
        .context("LISTEN_ADDR is not a valid socket address")?;

    tracing::info!(
        module = %config.module_path,
        token = %config.token_label,
        "opening PKCS#11 token"
    );
    let service = SingleSessionService::connect(&config)?;
    tracing::info!("token open; one session, mutex-serialized (M2)");

    let reflection = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
        .build_v1()
        .context("failed to build the gRPC reflection service")?;

    tracing::info!(%listen_addr, "gRPC server listening");

    Server::builder()
        .add_service(HsmServiceServer::new(service))
        .add_service(reflection)
        .serve_with_shutdown(listen_addr, shutdown_signal())
        .await
        .context("gRPC server failed")?;

    tracing::info!("shutdown complete");
    Ok(())
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
