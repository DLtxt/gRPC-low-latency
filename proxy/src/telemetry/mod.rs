//! Metrics and tracing.

pub mod metrics;

pub use metrics::{install, serve, spawn_gauge_sampler};
