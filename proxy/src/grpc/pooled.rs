//! M3 service implementation: requests are dispatched to the worker pool.
//!
//! The async handlers do no PKCS#11 work themselves. They translate the wire types,
//! hand a `Send` job to the pool, and await a oneshot -- so a slow `C_Sign` occupies a
//! dedicated worker thread instead of a Tokio runtime thread.

use std::sync::Arc;

use rand::RngCore;
use tonic::{Request, Response, Status};

use crate::crypto::{self, SigningInput};
use crate::pkcs11::{JobRequest, JobResponse, Pool, PoolError};
use crate::proto::v1::{
    hsm_service_server::HsmService, signing_input, CipherMechanism, DecryptRequest, DecryptResponse,
    EncryptRequest, EncryptResponse, GetPublicKeyRequest, GetPublicKeyResponse, SignRequest,
    SignResponse, VerifyRequest, VerifyResponse,
};

/// 96-bit IV: the standard GCM size and the fast path in most implementations.
const GCM_IV_LEN: usize = 12;

pub struct PooledService {
    pool: Arc<Pool>,
}

impl PooledService {
    pub fn new(pool: Arc<Pool>) -> Self {
        Self { pool }
    }
}

/// Map pool failures onto gRPC statuses.
///
/// The distinctions matter to a caller deciding whether to retry: `RESOURCE_EXHAUSTED`
/// and `UNAVAILABLE` are worth retrying, `INVALID_ARGUMENT` and `NOT_FOUND` never are,
/// and `INTERNAL` means the token misbehaved and a retry is a guess.
fn to_status(error: PoolError) -> Status {
    match error {
        PoolError::KeyNotFound(label) => {
            Status::not_found(format!("no key labelled '{label}' on the token"))
        }
        PoolError::InvalidRequest(message) => Status::invalid_argument(message),
        PoolError::Overloaded => {
            Status::resource_exhausted("request queue is full; retry after backing off")
        }
        PoolError::Timeout => Status::deadline_exceeded("timed out waiting for a worker"),
        PoolError::ShuttingDown => Status::unavailable("server is shutting down"),
        PoolError::Hsm { operation, source } => {
            // Logged in full; the client learns which operation failed, not the internals.
            tracing::error!(operation, error = %source, "HSM operation failed");
            Status::internal(format!("{operation} failed"))
        }
        PoolError::Internal(message) => {
            tracing::error!(error = %message, "internal error");
            Status::internal("internal error")
        }
    }
}

fn extract_input(input: Option<crate::proto::v1::SigningInput>) -> Result<SigningInput, Status> {
    let input = input
        .and_then(|i| i.input)
        .ok_or_else(|| Status::invalid_argument("input must be set to either message or digest"))?;

    Ok(match input {
        signing_input::Input::Message(message) => SigningInput::Message(message),
        signing_input::Input::Digest(digest) => SigningInput::Digest(digest),
    })
}

fn require_aes_gcm(mechanism: i32) -> Result<(), Status> {
    match CipherMechanism::try_from(mechanism) {
        Ok(CipherMechanism::AesGcm) => Ok(()),
        _ => Err(Status::invalid_argument(
            "only CIPHER_MECHANISM_AES_GCM is supported",
        )),
    }
}

fn unexpected(response: JobResponse) -> Status {
    tracing::error!(?response, "worker returned the wrong response variant");
    Status::internal("internal error")
}

#[tonic::async_trait]
impl HsmService for PooledService {
    async fn sign(&self, request: Request<SignRequest>) -> Result<Response<SignResponse>, Status> {
        let request = request.into_inner();
        let input = extract_input(request.input)?;
        let prepared = crypto::prepare(request.mechanism, input)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        let response = self
            .pool
            .submit(JobRequest::Sign {
                key_label: request.key_label.clone(),
                algorithm: prepared.algorithm,
                payload: prepared.payload,
            })
            .await
            .map_err(to_status)?;

        match response {
            JobResponse::Signature(signature) => Ok(Response::new(SignResponse {
                signature,
                key_label: request.key_label,
            })),
            other => Err(unexpected(other)),
        }
    }

    async fn verify(
        &self,
        request: Request<VerifyRequest>,
    ) -> Result<Response<VerifyResponse>, Status> {
        let request = request.into_inner();
        let input = extract_input(request.input)?;
        let prepared = crypto::prepare(request.mechanism, input)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        let response = self
            .pool
            .submit(JobRequest::Verify {
                key_label: request.key_label,
                algorithm: prepared.algorithm,
                payload: prepared.payload,
                signature: request.signature,
            })
            .await
            .map_err(to_status)?;

        match response {
            JobResponse::Verified(valid) => Ok(Response::new(VerifyResponse {
                valid,
                // M5 adds the public key cache; until then every verify reaches the token.
                served_from_cache: false,
            })),
            other => Err(unexpected(other)),
        }
    }

    async fn encrypt(
        &self,
        request: Request<EncryptRequest>,
    ) -> Result<Response<EncryptResponse>, Status> {
        let request = request.into_inner();
        require_aes_gcm(request.mechanism)?;

        // A reused GCM IV leaks the keystream and breaks authentication, so the proxy
        // generates one per request rather than trusting the caller to.
        let mut iv = vec![0u8; GCM_IV_LEN];
        rand::thread_rng().fill_bytes(&mut iv);

        let response = self
            .pool
            .submit(JobRequest::Encrypt {
                key_label: request.key_label,
                plaintext: request.plaintext,
                associated_data: request.associated_data,
                iv: iv.clone(),
            })
            .await
            .map_err(to_status)?;

        match response {
            JobResponse::Ciphertext(ciphertext) => {
                Ok(Response::new(EncryptResponse { ciphertext, iv }))
            }
            other => Err(unexpected(other)),
        }
    }

    async fn decrypt(
        &self,
        request: Request<DecryptRequest>,
    ) -> Result<Response<DecryptResponse>, Status> {
        let request = request.into_inner();
        require_aes_gcm(request.mechanism)?;

        if request.iv.len() != GCM_IV_LEN {
            return Err(Status::invalid_argument(format!(
                "iv must be {GCM_IV_LEN} bytes, got {}",
                request.iv.len()
            )));
        }

        let response = self
            .pool
            .submit(JobRequest::Decrypt {
                key_label: request.key_label,
                ciphertext: request.ciphertext,
                associated_data: request.associated_data,
                iv: request.iv,
            })
            .await
            .map_err(to_status)?;

        match response {
            JobResponse::Plaintext(plaintext) => Ok(Response::new(DecryptResponse { plaintext })),
            other => Err(unexpected(other)),
        }
    }

    async fn get_public_key(
        &self,
        request: Request<GetPublicKeyRequest>,
    ) -> Result<Response<GetPublicKeyResponse>, Status> {
        let request = request.into_inner();

        let response = self
            .pool
            .submit(JobRequest::GetPublicKey {
                key_label: request.key_label,
            })
            .await
            .map_err(to_status)?;

        match response {
            JobResponse::PublicKey { spki_der, key_type } => {
                Ok(Response::new(GetPublicKeyResponse {
                    spki_der,
                    key_type,
                    served_from_cache: false,
                }))
            }
            other => Err(unexpected(other)),
        }
    }
}
