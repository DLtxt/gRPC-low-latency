//! PKCS#11 access layer.
//!
//! At M1 this is just connection and lookup. The blocking-safe worker pool
//! (`pool`, `worker`) arrives in M3; until then callers own their own session.

pub mod session;

pub use session::{find_object, find_object_pair, open_token, TokenConfig};
