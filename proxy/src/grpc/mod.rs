//! The gRPC surface.
//!
//! Two backends implement the same service. `SingleSessionService` is the M2 baseline --
//! one session behind a mutex -- and `PooledService` is the M3 worker pool. Keeping both
//! behind one env switch means the pool's contribution can be measured by changing a
//! single variable, with the gRPC stack, codec, and handlers held identical.

pub mod pooled;
pub mod service;

pub use pooled::PooledService;
pub use service::SingleSessionService;
