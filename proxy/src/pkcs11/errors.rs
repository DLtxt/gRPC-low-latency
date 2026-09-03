//! Errors that cross the worker-pool boundary.

use cryptoki::error::{Error as CryptokiError, RvError};

/// A failure from the pool, phrased so the gRPC layer can pick a status code without
/// knowing anything about PKCS#11.
#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    #[error("no key labelled '{0}' on the token")]
    KeyNotFound(String),

    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// The bounded queue was full. Shedding here is deliberate: queueing this request
    /// would raise the tail latency of every request already accepted, which is exactly
    /// the failure mode the project exists to avoid.
    #[error("overloaded: the request queue is full")]
    Overloaded,

    #[error("timed out waiting for a worker")]
    Timeout,

    #[error("the worker pool is shutting down")]
    ShuttingDown,

    #[error("{operation} failed: {source}")]
    Hsm {
        operation: &'static str,
        #[source]
        source: CryptokiError,
    },

    #[error("{0}")]
    Internal(String),
}

impl PoolError {
    pub fn hsm(operation: &'static str, source: CryptokiError) -> Self {
        Self::Hsm { operation, source }
    }
}

/// Does this error mean the session itself is unusable?
///
/// These are the cases where retrying on the same session is pointless: the worker has
/// to close it, open a fresh one, log in again, and drop its cached object handles,
/// because handles are scoped to the session that found them.
pub fn is_session_fatal(error: &CryptokiError) -> bool {
    matches!(
        error,
        CryptokiError::Pkcs11(
            RvError::SessionHandleInvalid
                | RvError::SessionClosed
                | RvError::DeviceError
                | RvError::DeviceRemoved
                | RvError::TokenNotPresent
                | RvError::UserNotLoggedIn,
            _
        )
    )
}
