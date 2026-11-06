//! M3 service implementation: requests are dispatched to the worker pool.
//!
//! The async handlers do no PKCS#11 work themselves. They translate the wire types,
//! hand a `Send` job to the pool, and await a oneshot -- so a slow `C_Sign` occupies a
//! dedicated worker thread instead of a Tokio runtime thread.

use std::sync::Arc;
use std::time::Instant;

use rand::RngCore;
use tonic::{Request, Response, Status};

use crate::authz::{Authorizer, Operation};
use crate::cache::{CachedPublicKey, Lookup, PublicKeyCache};
use crate::crypto::{self, SigningInput};
use crate::pkcs11::{JobRequest, JobResponse, Pool, PoolError};
use crate::proto::v1::{
    hsm_service_server::HsmService, signing_input, ApproveTransferRequest, ApproveTransferResponse,
    CipherMechanism, DecryptRequest, DecryptResponse, EncryptRequest, EncryptResponse,
    GetPendingTransferRequest, GetPublicKeyRequest, GetPublicKeyResponse, PendingTransfer,
    SignRequest, SignResponse, SignTransferRequest, SignTransferResponse, TransferStatus,
    VerifyRequest, VerifyResponse,
};
use crate::resilience::{CircuitBreaker, RateLimiter};
use crate::telemetry::metrics as m;
use crate::transfer::canonical::to_hex;
use crate::transfer::{self, HoldStatus, Outcome, Refusal, TransferGuard, TransferRequest};

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
    /// `None` disables rate limiting. Absent configuration means no limit rather than a
    /// guessed one, since a limit below real capacity becomes the bottleneck it exists
    /// to prevent.
    rate_limiter: Option<Arc<RateLimiter>>,
    breaker: Arc<CircuitBreaker>,
    /// Always present, even with no transfer policy: it is what refuses `Sign` on a
    /// transfer key, and that must not depend on whether a policy file was found.
    transfers: Arc<TransferGuard>,
}

impl PooledService {
    pub fn new(
        pool: Arc<Pool>,
        authorizer: Option<Arc<Authorizer>>,
        cache: Arc<PublicKeyCache>,
        rate_limiter: Option<Arc<RateLimiter>>,
        breaker: Arc<CircuitBreaker>,
        transfers: Arc<TransferGuard>,
    ) -> Self {
        Self {
            pool,
            authorizer,
            cache,
            rate_limiter,
            breaker,
            transfers,
        }
    }

    /// Admission control, run before any work is done. Returns the caller's identity,
    /// or `None` when mTLS is off and there is none.
    ///
    /// Order matters and is chosen so the cheapest rejection happens first: the circuit
    /// breaker is a single atomic load, the rate limiter is a hash lookup, and
    /// authorization parses nothing but does consult the policy. Doing expensive checks
    /// before cheap ones would mean paying the most for requests we are about to refuse.
    fn admit<T>(
        &self,
        request: &Request<T>,
        key_label: &str,
        operation: Operation,
    ) -> Result<Option<Arc<str>>, Status> {
        // 1. Is the dependency healthy? If not, fail immediately rather than spending a
        //    worker slot and the caller's deadline to discover it again.
        if !self.breaker.allow() {
            return Err(Status::unavailable(
                "circuit breaker is open; the HSM is failing. Retry after backoff.",
            ));
        }

        // 2. Who is calling, and are they allowed?
        let identity = match &self.authorizer {
            Some(authorizer) => Some(authorizer.authorize(request, key_label, operation)?),
            None => None,
        };

        // 3. Are they within their share? Checked after authorization so an unauthorized
        //    caller cannot consume a legitimate identity's tokens.
        if let (Some(limiter), Some(identity)) = (&self.rate_limiter, &identity) {
            if !limiter.check(identity) {
                tracing::debug!(%identity, "rate limit exceeded");
                return Err(Status::resource_exhausted(
                    "rate limit exceeded for this workload identity",
                ));
            }
        }

        Ok(identity)
    }

    /// Admission for the transfer RPCs, which additionally require an identity.
    ///
    /// A held transfer is bound to the identity that requested it, and approvals are
    /// relayed by an identity granted to do so. With mTLS off there is neither, and a
    /// transfer key reachable by anonymous callers would undo the point of having one.
    fn admit_transfer<T>(
        &self,
        request: &Request<T>,
        key_label: &str,
        operation: Operation,
    ) -> Result<Arc<str>, Status> {
        self.admit(request, key_label, operation)?.ok_or_else(|| {
            Status::failed_precondition(
                "transfer keys are served only with mTLS on (PROXY_TLS=on): a transfer is \
                 bound to the identity that requested it",
            )
        })
    }

    /// Record a completed request: its latency, and its result by operation.
    ///
    /// Labelled by operation and gRPC status code rather than by key label or identity.
    /// Those are caller-controlled, and an unbounded label set is how a metrics endpoint
    /// turns into an out-of-memory incident.
    fn record<T>(
        &self,
        operation: &'static str,
        started: std::time::Instant,
        result: &Result<T, Status>,
    ) {
        let code = match result {
            Ok(_) => "ok",
            Err(status) => status.code().description(),
        };
        metrics::counter!(m::REQUESTS_TOTAL, "operation" => operation, "result" => code)
            .increment(1);
        metrics::histogram!(m::REQUEST_DURATION, "operation" => operation)
            .record(started.elapsed().as_secs_f64());

        if let Err(status) = result {
            match status.code() {
                tonic::Code::ResourceExhausted => {
                    metrics::counter!(m::RATE_LIMITED, "operation" => operation).increment(1)
                }
                tonic::Code::PermissionDenied => {
                    metrics::counter!(m::AUTHZ_DENIED, "operation" => operation).increment(1)
                }
                tonic::Code::Unauthenticated => metrics::counter!(m::UNAUTHENTICATED).increment(1),
                _ => {}
            }
        } else {
            metrics::counter!(m::AUTHZ_ALLOWED, "operation" => operation).increment(1);
        }
    }

    /// Report an outcome to the breaker.
    ///
    /// Only failures that indicate the *token* is unhealthy count. A bad key label or a
    /// malformed request is the caller's fault, and counting those would let one
    /// misbehaving client trip the circuit for everyone.
    fn observe<T>(&self, result: &Result<T, Status>) {
        match result {
            Ok(_) => self.breaker.record_success(),
            Err(status) => match status.code() {
                tonic::Code::Internal | tonic::Code::DeadlineExceeded => {
                    self.breaker.record_failure()
                }
                // Overload is a capacity signal, not a health signal: the token is fine,
                // there is simply more work than slots. Tripping on it would convert a
                // busy service into an unavailable one.
                _ => self.breaker.record_success(),
            },
        }
    }

    /// Resolve a public key, reaching the token only on a miss.
    ///
    /// A missing key is cached as a negative result rather than propagated as an error,
    /// so a client looping on a bad label cannot turn every request into a token lookup.
    async fn public_key(&self, key_label: &str) -> Result<(Lookup, bool), Status> {
        let pool = Arc::clone(&self.pool);
        let label = key_label.to_string();

        let outcome = self
            .cache
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
            .map_err(|e| to_status(PoolError::Internal(e.to_string())));

        self.observe(&outcome);
        outcome
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
        PoolError::TransferOnly(label) => {
            Status::permission_denied(transfer::raw_sign_refusal(&label))
        }
        PoolError::NotTransferKey(label) => {
            // The policy calls this a transfer key and the token disagrees. Startup
            // checks for this, so reaching it means the token changed underneath us.
            tracing::error!(key = %label, "transfer key is not marked transfer-only on the token");
            Status::failed_precondition(format!(
                "key '{label}' is not marked transfer-only on the token"
            ))
        }
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

/// Map a transfer refusal onto a gRPC status. As with pool errors, the code is what a
/// caller decides retries on: a policy refusal never succeeds on retry, a rate refusal
/// does once the minute passes.
fn refusal_status(refusal: &Refusal) -> Status {
    let message = refusal.to_string();
    match refusal {
        Refusal::Invalid(_) => Status::invalid_argument(message),
        Refusal::NotATransferKey(_) | Refusal::ApproverKeyMissing(_) => {
            Status::failed_precondition(message)
        }
        Refusal::RateLimited { .. } | Refusal::TooManyHolds { .. } => {
            Status::resource_exhausted(message)
        }
        Refusal::NoSuchHold | Refusal::StaleHold => Status::not_found(message),
        Refusal::Internal => Status::internal(message),
        Refusal::AssetNotAllowed { .. }
        | Refusal::DestinationNotAllowed { .. }
        | Refusal::OverMaxPerTransfer { .. }
        | Refusal::HeldForAnotherRequester
        | Refusal::NotAnApprover { .. }
        | Refusal::BadApprovalSignature(_) => Status::permission_denied(message),
    }
}

fn digest_from(bytes: &[u8]) -> Result<[u8; 32], Status> {
    bytes
        .try_into()
        .map_err(|_| Status::invalid_argument("digest must be the 32-byte SHA-256 of the transfer"))
}

fn held_response(status: &HoldStatus) -> SignTransferResponse {
    SignTransferResponse {
        status: TransferStatus::PendingApproval as i32,
        canonical_transfer: status.transfer.encode(),
        digest: status.transfer.digest().to_vec(),
        signature: Vec::new(),
        hold_reason: status.reason.clone(),
        approvals_required: status.required as u32,
        approvals_received: status.received() as u32,
    }
}

impl PooledService {
    /// Count a transfer decision. Labelled by key only once the key is known to be a
    /// configured transfer key, so a caller cannot grow the label set by inventing names.
    fn count_transfer(&self, key_label: &str, outcome: &'static str, reason: &'static str) {
        let key = if self.transfers.is_transfer_key(key_label) {
            key_label.to_string()
        } else {
            "other".to_string()
        };
        metrics::counter!(m::TRANSFERS_TOTAL, "key_label" => key, "outcome" => outcome, "reason" => reason)
            .increment(1);
    }

    async fn sign_inner(
        &self,
        request: Request<SignRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        self.admit(&request, &request.get_ref().key_label, Operation::Sign)?;
        // With mTLS on, no identity can hold `sign` on a transfer key -- the policy
        // refuses to load such a grant -- so this matters with mTLS off, where admission
        // lets everything through. The worker refuses again on the token's marker.
        if self.transfers.is_transfer_key(&request.get_ref().key_label) {
            return Err(Status::permission_denied(transfer::raw_sign_refusal(
                &request.get_ref().key_label,
            )));
        }
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
            .map_err(to_status);
        self.observe(&response);
        let response = response?;

        match response {
            JobResponse::Signature(signature) => Ok(Response::new(SignResponse {
                signature,
                key_label: request.key_label,
            })),
            other => Err(unexpected(other)),
        }
    }

    async fn verify_inner(
        &self,
        request: Request<VerifyRequest>,
    ) -> Result<Response<VerifyResponse>, Status> {
        self.admit(&request, &request.get_ref().key_label, Operation::Verify)?;
        let request = request.into_inner();
        let input = extract_input(request.input)?;

        let (lookup, served_from_cache) = self.public_key(&request.key_label).await?;
        let Lookup::Found(key) = lookup else {
            return Err(key_not_found(&request.key_label));
        };

        // Verification needs only the public key, so once it is cached the token is not
        // in this path at all -- that is the whole point of M5.
        let valid =
            crypto::verify_public(&key.spki_der, request.mechanism, &input, &request.signature)
                .map_err(|e| {
                    tracing::error!(error = %e, "in-process verification failed");
                    Status::internal("verification failed")
                })?;

        Ok(Response::new(VerifyResponse {
            valid,
            served_from_cache,
        }))
    }

    async fn encrypt_inner(
        &self,
        request: Request<EncryptRequest>,
    ) -> Result<Response<EncryptResponse>, Status> {
        self.admit(&request, &request.get_ref().key_label, Operation::Encrypt)?;
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
            .map_err(to_status);
        self.observe(&response);
        let response = response?;

        match response {
            JobResponse::Ciphertext(ciphertext) => {
                Ok(Response::new(EncryptResponse { ciphertext, iv }))
            }
            other => Err(unexpected(other)),
        }
    }

    async fn decrypt_inner(
        &self,
        request: Request<DecryptRequest>,
    ) -> Result<Response<DecryptResponse>, Status> {
        self.admit(&request, &request.get_ref().key_label, Operation::Decrypt)?;
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
            .map_err(to_status);
        self.observe(&response);
        let response = response?;

        match response {
            JobResponse::Plaintext(plaintext) => Ok(Response::new(DecryptResponse { plaintext })),
            other => Err(unexpected(other)),
        }
    }

    async fn get_public_key_inner(
        &self,
        request: Request<GetPublicKeyRequest>,
    ) -> Result<Response<GetPublicKeyResponse>, Status> {
        self.admit(
            &request,
            &request.get_ref().key_label,
            Operation::GetPublicKey,
        )?;
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

    async fn sign_transfer_inner(
        &self,
        request: Request<SignTransferRequest>,
    ) -> Result<Response<SignTransferResponse>, Status> {
        let requester = self.admit_transfer(
            &request,
            &request.get_ref().key_label,
            Operation::SignTransfer,
        )?;
        let request = request.into_inner();
        let key_label = request.key_label;
        let transfer = request
            .transfer
            .ok_or_else(|| Status::invalid_argument("transfer must be set"))?;
        let ask = TransferRequest {
            chain: &transfer.chain,
            asset: &transfer.asset,
            destination: &transfer.destination,
            amount: &transfer.amount,
            nonce: transfer.nonce,
        };

        let outcome = match self
            .transfers
            .submit(&requester, &key_label, &ask, Instant::now())
        {
            Ok(outcome) => outcome,
            Err(refusal) => {
                self.count_transfer(&key_label, "refused", refusal.reason());
                tracing::warn!(
                    target: "audit",
                    requester = %requester,
                    key = %key_label,
                    destination = ?transfer.destination,
                    amount = ?transfer.amount,
                    asset = ?transfer.asset,
                    nonce = transfer.nonce,
                    reason = refusal.reason(),
                    "transfer refused: {refusal}"
                );
                return Err(refusal_status(&refusal));
            }
        };

        let (transfer, reservation) = match outcome {
            Outcome::Held(status) => {
                self.count_transfer(&key_label, "held", status.kind.as_str());
                tracing::info!(
                    target: "audit",
                    requester = %requester,
                    transfer = %status.transfer.summary(),
                    digest = %to_hex(&status.transfer.digest()),
                    approvals = status.received(),
                    required = status.required,
                    "transfer held: {}",
                    status.reason
                );
                return Ok(Response::new(held_response(&status)));
            }
            Outcome::Sign {
                transfer,
                reservation,
            } => (transfer, reservation),
        };

        let digest = transfer.digest();
        let approved_by = reservation.approvers();
        let response = self
            .pool
            .submit(JobRequest::SignTransfer {
                key_label: key_label.clone(),
                digest,
            })
            .await
            .map_err(to_status);
        self.observe(&response);

        let signature = match response {
            Ok(JobResponse::Signature(signature)) => signature,
            failed => {
                // No signature exists, so it must not count against the limits -- and if
                // it was releasing an approved hold, the approvals go back with it.
                self.transfers.release(reservation);
                self.count_transfer(&key_label, "failed", "hsm");
                return Err(match failed {
                    Ok(other) => unexpected(other),
                    Err(status) => status,
                });
            }
        };

        self.count_transfer(
            &key_label,
            "signed",
            if approved_by.is_empty() {
                "auto"
            } else {
                "approved"
            },
        );
        tracing::info!(
            target: "audit",
            requester = %requester,
            transfer = %transfer.summary(),
            digest = %to_hex(&digest),
            approved_by = ?approved_by,
            "transfer signed"
        );

        let required = if approved_by.is_empty() {
            0
        } else {
            self.transfers
                .policy()
                .key(&key_label)
                .map_or(0, |rules| rules.quorum as u32)
        };
        Ok(Response::new(SignTransferResponse {
            status: TransferStatus::Signed as i32,
            canonical_transfer: transfer.encode(),
            digest: digest.to_vec(),
            signature,
            hold_reason: String::new(),
            approvals_required: required,
            approvals_received: approved_by.len() as u32,
        }))
    }

    async fn get_pending_transfer_inner(
        &self,
        request: Request<GetPendingTransferRequest>,
    ) -> Result<Response<PendingTransfer>, Status> {
        self.admit_transfer(
            &request,
            &request.get_ref().key_label,
            Operation::ApproveTransfer,
        )?;
        let request = request.into_inner();
        let digest = digest_from(&request.digest)?;

        let status = self
            .transfers
            .pending(&request.key_label, &digest, Instant::now())
            .map_err(|refusal| refusal_status(&refusal))?;

        Ok(Response::new(PendingTransfer {
            key_label: request.key_label,
            canonical_transfer: status.transfer.encode(),
            digest: digest.to_vec(),
            hold_reason: status.reason.clone(),
            approvals_required: status.required as u32,
            approved_by: status.approved_by.clone(),
            expires_in_seconds: status.expires_in.as_secs(),
            hold_id: status.hold_id.to_vec(),
        }))
    }

    async fn approve_transfer_inner(
        &self,
        request: Request<ApproveTransferRequest>,
    ) -> Result<Response<ApproveTransferResponse>, Status> {
        let relayed_by = self.admit_transfer(
            &request,
            &request.get_ref().key_label,
            Operation::ApproveTransfer,
        )?;
        let request = request.into_inner();
        let digest = digest_from(&request.digest)?;

        let result = self.transfers.approve(
            &request.key_label,
            &digest,
            &request.hold_id,
            &request.approver,
            &request.signature,
            Instant::now(),
        );
        match result {
            Ok(status) => {
                metrics::counter!(m::TRANSFER_APPROVALS, "result" => "accepted", "reason" => "ok")
                    .increment(1);
                tracing::info!(
                    target: "audit",
                    approver = %request.approver,
                    relayed_by = %relayed_by,
                    transfer = %status.transfer.summary(),
                    digest = %to_hex(&digest),
                    approvals = status.received(),
                    required = status.required,
                    "transfer approval accepted"
                );
                Ok(Response::new(ApproveTransferResponse {
                    approvals_required: status.required as u32,
                    approvals_received: status.received() as u32,
                    approved: status.approved(),
                }))
            }
            Err(refusal) => {
                metrics::counter!(m::TRANSFER_APPROVALS, "result" => "rejected", "reason" => refusal.reason())
                    .increment(1);
                // A signature that does not verify is someone trying to approve without
                // the approver's key. That is worth more than a debug line.
                tracing::warn!(
                    target: "audit",
                    approver = ?request.approver,
                    relayed_by = %relayed_by,
                    digest = %to_hex(&digest),
                    reason = refusal.reason(),
                    "transfer approval rejected: {refusal}"
                );
                Err(refusal_status(&refusal))
            }
        }
    }
}

#[tonic::async_trait]
impl HsmService for PooledService {
    async fn sign(&self, request: Request<SignRequest>) -> Result<Response<SignResponse>, Status> {
        let started = std::time::Instant::now();
        let result = self.sign_inner(request).await;
        self.record("sign", started, &result);
        result
    }

    async fn verify(
        &self,
        request: Request<VerifyRequest>,
    ) -> Result<Response<VerifyResponse>, Status> {
        let started = std::time::Instant::now();
        let result = self.verify_inner(request).await;
        self.record("verify", started, &result);
        result
    }

    async fn encrypt(
        &self,
        request: Request<EncryptRequest>,
    ) -> Result<Response<EncryptResponse>, Status> {
        let started = std::time::Instant::now();
        let result = self.encrypt_inner(request).await;
        self.record("encrypt", started, &result);
        result
    }

    async fn decrypt(
        &self,
        request: Request<DecryptRequest>,
    ) -> Result<Response<DecryptResponse>, Status> {
        let started = std::time::Instant::now();
        let result = self.decrypt_inner(request).await;
        self.record("decrypt", started, &result);
        result
    }

    async fn get_public_key(
        &self,
        request: Request<GetPublicKeyRequest>,
    ) -> Result<Response<GetPublicKeyResponse>, Status> {
        let started = std::time::Instant::now();
        let result = self.get_public_key_inner(request).await;
        self.record("get_public_key", started, &result);
        result
    }

    async fn sign_transfer(
        &self,
        request: Request<SignTransferRequest>,
    ) -> Result<Response<SignTransferResponse>, Status> {
        let started = std::time::Instant::now();
        let result = self.sign_transfer_inner(request).await;
        self.record("sign_transfer", started, &result);
        result
    }

    async fn get_pending_transfer(
        &self,
        request: Request<GetPendingTransferRequest>,
    ) -> Result<Response<PendingTransfer>, Status> {
        let started = std::time::Instant::now();
        let result = self.get_pending_transfer_inner(request).await;
        self.record("get_pending_transfer", started, &result);
        result
    }

    async fn approve_transfer(
        &self,
        request: Request<ApproveTransferRequest>,
    ) -> Result<Response<ApproveTransferResponse>, Status> {
        let started = std::time::Instant::now();
        let result = self.approve_transfer_inner(request).await;
        self.record("approve_transfer", started, &result);
        result
    }
}
