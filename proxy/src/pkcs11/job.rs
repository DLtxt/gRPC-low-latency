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
    /// Sign the SHA-256 digest of a canonical transfer with a transfer-only key.
    ///
    /// Separate from `Sign` so the worker can tell the two apart: `Sign` is refused on
    /// a key marked transfer-only, and this is refused on any key that is not. Only the
    /// transfer path constructs it, after the guard has checked the transfer.
    SignTransfer {
        key_label: String,
        digest: [u8; 32],
    },
    /// Report whether a key is marked transfer-only, so the server can check at startup
    /// that the transfer policy and the token agree.
    DescribeKey {
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
            JobRequest::SignTransfer { .. } => "sign_transfer",
            JobRequest::DescribeKey { .. } => "describe_key",
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
    KeyDescription {
        transfer_only: bool,
    },
}

pub struct Job {
    pub request: JobRequest,
    pub responder: tokio::sync::oneshot::Sender<Result<JobResponse, PoolError>>,
    /// Stamped on submission so the worker can separate queue wait from service time.
    /// Those two are the numbers that make the pool's behaviour legible on a dashboard.
    pub enqueued_at: Instant,
}
