//! M3 service implementation: requests are dispatched to the worker pool.
//!
//! The async handlers do no PKCS#11 work themselves. They translate the wire types,
//! hand a `Send` job to the pool, and await a oneshot -- so a slow `C_Sign` occupies a
//! dedicated worker thread instead of a Tokio runtime thread.

use std::sync::Arc;

use rand::RngCore;
use tonic::{Request, Response, Status};

use crate::authz::{Authorizer, Operation};
use crate::cache::{CachedPublicKey, Lookup, PublicKeyCache};
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
    /// `None` when TLS is disabled. Without mTLS there is no client certificate, so
    /// there is no identity to authorize -- the server logs a prominent warning at
    /// startup rather than pretending to enforce a policy it cannot evaluate.
    authorizer: Option<Arc<Authorizer>>,
    /// Public keys only. Nothing derived from a private key is ever stored here.
    cache: Arc<PublicKeyCache>,
}

impl PooledService {
    pub fn new(
        pool: Arc<Pool>,
        authorizer: Option<Arc<Authorizer>>,
        cache: Arc<PublicKeyCache>,
    ) -> Self {
        Self {
            pool,
            authorizer,
            cache,
        }
    }

    /// Resolve a public key, reaching the token only on a miss.
    ///
    /// A missing key is cached as a negative result rather than propagated as an error,
    /// so a client looping on a bad label cannot turn every request into a token lookup.
    async fn public_key(&self, key_label: &str) -> Result<(Lookup, bool), Status> {
        let pool = Arc::clone(&self.pool);
        let label = key_label.to_string();

        self.cache
            .get_or_load(key_label, || async move {
                match pool
                    .submit(JobRequest::GetPublicKey { key_label: label })
                    .await
                {
                    Ok(JobResponse::PublicKey { spki_der, key_type }) => {
                        Ok(Lookup::Found(CachedPublicKey {
                            spki_der: Arc::new(spki_der),
                            key_type: key_type.into(),
                        }))
                    }
                    Ok(_) => Err(PoolError::Internal(
                        "worker returned the wrong response variant".to_string(),
                    )),
                    Err(PoolError::KeyNotFound(_)) => Ok(Lookup::NotFound),
                    Err(other) => Err(other),
                }
            })
            .await
            .map_err(|e| to_status(PoolError::Internal(e.to_string())))
    }

    /// Authorize, or pass through when running without mTLS.
    fn check<T>(
        &self,
        request: &Request<T>,
        key_label: &str,
        operation: Operation,
    ) -> Result<(), Status> {
        match &self.authorizer {
            Some(authorizer) => authorizer.authorize(request, key_label, operation).map(|_| ()),
            None => Ok(()),
        }
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

fn key_not_found(label: &str) -> Status {
    Status::not_found(format!("no key labelled '{label}' on the token"))
}

fn unexpected(response: JobResponse) -> Status {
    tracing::error!(?response, "worker returned the wrong response variant");
    Status::internal("internal error")
}

#[tonic::async_trait]
impl HsmService for PooledService {
    async fn sign(&self, request: Request<SignRequest>) -> Result<Response<SignResponse>, Status> {
        self.check(&request, &request.get_ref().key_label, Operation::Sign)?;
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
        self.check(&request, &request.get_ref().key_label, Operation::Verify)?;
        let request = request.into_inner();
        let input = extract_input(request.input)?;

        let (lookup, served_from_cache) = self.public_key(&request.key_label).await?;
        let Lookup::Found(key) = lookup else {
            return Err(key_not_found(&request.key_label));
        };

        // Verification needs only the public key, so once it is cached the token is not
        // in this path at all -- that is the whole point of M5.
        let valid = crypto::verify_public(
            &key.spki_der,
            request.mechanism,
            &input,
            &request.signature,
        )
        .map_err(|e| {
            tracing::error!(error = %e, "in-process verification failed");
            Status::internal("verification failed")
        })?;

        Ok(Response::new(VerifyResponse {
            valid,
            served_from_cache,
        }))
    }

    async fn encrypt(
        &self,
        request: Request<EncryptRequest>,
    ) -> Result<Response<EncryptResponse>, Status> {
        self.check(&request, &request.get_ref().key_label, Operation::Encrypt)?;
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
        self.check(&request, &request.get_ref().key_label, Operation::Decrypt)?;
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
        self.check(&request, &request.get_ref().key_label, Operation::GetPublicKey)?;
        let request = request.into_inner();

        let (lookup, served_from_cache) = self.public_key(&request.key_label).await?;
        let Lookup::Found(key) = lookup else {
            return Err(key_not_found(&request.key_label));
        };

        Ok(Response::new(GetPublicKeyResponse {
            spki_der: key.spki_der.as_ref().clone(),
            key_type: key.key_type.to_string(),
            served_from_cache,
        }))
    }
}
