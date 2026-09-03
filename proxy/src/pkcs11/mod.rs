//! PKCS#11 access layer.
//!
//! `session` opens and searches a token; `pool` and `worker` provide the blocking-safe
//! execution model that keeps synchronous C calls off the async runtime.

pub mod errors;
pub mod job;
pub mod metrics;
pub mod pool;
pub mod provision;
pub mod session;
pub mod worker;

pub use errors::PoolError;
pub use job::{JobRequest, JobResponse};
pub use pool::{Pool, PoolConfig};
pub use session::{find_object, find_object_pair, load_module, open_token, TokenConfig};
