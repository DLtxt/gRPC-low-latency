//! The unit of work handed to a pool worker.
//!
//! Every field here is owned and `Send`. That is not incidental: `cryptoki::Mechanism`
//! carries raw pointers and is `!Send`, so a job describes *which* algorithm to use and
//! the worker constructs the mechanism on its own thread.

use std::time::Instant;

use crate::crypto::SignAlgorithm;

use super::errors::PoolError;

/// Which class of object a label refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyKind {
    Private,
    Public,
    Secret,
}

#[derive(Debug)]
pub enum JobRequest {
    Sign {
        key_label: String,
        algorithm: SignAlgorithm,
        payload: Vec<u8>,
    },
    Verify {
        key_label: String,
        algorithm: SignAlgorithm,
        payload: Vec<u8>,
        signature: Vec<u8>,
    },
    Encrypt {
        key_label: String,
        plaintext: Vec<u8>,
        associated_data: Vec<u8>,
        iv: Vec<u8>,
    },
    Decrypt {
        key_label: String,
        ciphertext: Vec<u8>,
        associated_data: Vec<u8>,
        iv: Vec<u8>,
    },
    GetPublicKey {
        key_label: String,
    },
}

impl JobRequest {
    /// Short label for metrics and tracing.
    pub fn operation(&self) -> &'static str {
        match self {
            JobRequest::Sign { .. } => "sign",
            JobRequest::Verify { .. } => "verify",
            JobRequest::Encrypt { .. } => "encrypt",
            JobRequest::Decrypt { .. } => "decrypt",
            JobRequest::GetPublicKey { .. } => "get_public_key",
        }
    }
}

#[derive(Debug)]
pub enum JobResponse {
    Signature(Vec<u8>),
    /// `false` means the signature did not check out -- a legitimate answer, not an error.
    Verified(bool),
    Ciphertext(Vec<u8>),
    Plaintext(Vec<u8>),
    PublicKey {
        spki_der: Vec<u8>,
        key_type: String,
    },
}

pub struct Job {
    pub request: JobRequest,
    pub responder: tokio::sync::oneshot::Sender<Result<JobResponse, PoolError>>,
    /// Stamped on submission so the worker can separate queue wait from service time.
    /// Those two are the numbers that make the pool's behaviour legible on a dashboard.
    pub enqueued_at: Instant,
}
