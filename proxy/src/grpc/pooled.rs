//! M3 service implementation: requests are dispatched to the worker pool.
//!
//! The async handlers do no PKCS#11 work themselves. They translate the wire types,
//! hand a `Send` job to the pool, and await a oneshot -- so a slow `C_Sign` occupies a
//! dedicated worker thread instead of a Tokio runtime thread.

use std::sync::Arc;
use std::time::Instant;

use rand::RngCore;
use tonic::{Request, Response, Status};

use crate::approval::{ApprovalRefusal, HoldStatus, Statement};
use crate::authz::{Authorizer, Operation};
use crate::cache::{CachedPublicKey, Lookup, PublicKeyCache};
use crate::crypto::{self, SigningInput};
use crate::encoding::to_hex;
use crate::pkcs11::{JobRequest, JobResponse, Pool, PoolError, Purpose};
use crate::proto::v1::{
    hsm_service_server::HsmService, signing_input, ApproveRequest, ApproveResponse,
    CipherMechanism, DecryptRequest, DecryptResponse, EncryptRequest, EncryptResponse,
    GetPendingApprovalRequest, GetPublicKeyRequest, GetPublicKeyResponse, PendingApproval,
    SignReleaseRequest, SignReleaseResponse, SignRequest, SignResponse, SignTransferRequest,
    SignTransferResponse, SigningStatus, VerifyRequest, VerifyResponse,
};
use crate::release::{self, Release, ReleaseGuard, ReleaseRequest};
use crate::resilience::{CircuitBreaker, RateLimiter};
use crate::telemetry::metrics as m;
use crate::transfer::{self, Refusal, Transfer, TransferGuard, TransferRequest};

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
    /// The same for release keys.
    releases: Arc<ReleaseGuard>,
}

impl PooledService {
    pub fn new(
        pool: Arc<Pool>,
        authorizer: Option<Arc<Authorizer>>,
        cache: Arc<PublicKeyCache>,
        rate_limiter: Option<Arc<RateLimiter>>,
        breaker: Arc<CircuitBreaker>,
        transfers: Arc<TransferGuard>,
        releases: Arc<ReleaseGuard>,
    ) -> Self {
        Self {
            pool,
            authorizer,
            cache,
            rate_limiter,
            breaker,
            transfers,
            releases,
        }
    }

    /// The purpose the policies give `key_label`, if it is a transfer or release key.
    fn purpose_of(&self, key_label: &str) -> Option<Purpose> {
        if self.transfers.is_transfer_key(key_label) {
            Some(Purpose::Transfer)
        } else if self.releases.is_release_key(key_label) {
            Some(Purpose::Release)
        } else {
            None
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

    /// Admission for the transfer, release and approval RPCs, which additionally require
    /// an identity.
    ///
    /// A held request is bound to the identity that made it, and approvals are relayed by
    /// an identity granted to do so. With mTLS off there is neither, and a purpose-bound
    /// key reachable by anonymous callers would undo the point of having one.
    fn admit_bound<T>(
        &self,
        request: &Request<T>,
        key_label: &str,
        operation: Operation,
    ) -> Result<Arc<str>, Status> {
        self.admit(request, key_label, operation)?.ok_or_else(|| {
            Status::failed_precondition(
                "transfer and release keys are served only with mTLS on (PROXY_TLS=on): a \
                 request is bound to the identity that made it",
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
        PoolError::PurposeBound { key_label, purpose } => {
            Status::permission_denied(purpose.raw_sign_refusal(&key_label))
        }
        PoolError::WrongPurpose {
            key_label,
            expected,
        } => {
            // The policy gives this key a purpose and the token disagrees. Startup checks
            // for this, so reaching it means the token changed underneath us.
            tracing::error!(
                key = %key_label,
                purpose = expected.as_str(),
                "key is not marked for its purpose on the token"
            );
            Status::failed_precondition(format!(
                "key '{key_label}' is not marked {}-only on the token",
                expected.as_str()
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

/// Map an approval refusal onto a gRPC status. As with pool errors, the code is what a
/// caller decides retries on: a policy refusal never succeeds on retry, a full set of
/// holds does once some are approved or lapse.
fn approval_status(refusal: &ApprovalRefusal) -> Status {
    let message = refusal.to_string();
    match refusal {
        ApprovalRefusal::Invalid(_) => Status::invalid_argument(message),
        ApprovalRefusal::NotApprovable(_) | ApprovalRefusal::ApproverKeyMissing(_) => {
            Status::failed_precondition(message)
        }
        ApprovalRefusal::TooManyHolds { .. } => Status::resource_exhausted(message),
        ApprovalRefusal::NoSuchHold | ApprovalRefusal::StaleHold => Status::not_found(message),
        ApprovalRefusal::Internal => Status::internal(message),
        ApprovalRefusal::HeldForAnotherRequester
        | ApprovalRefusal::NotAnApprover { .. }
        | ApprovalRefusal::BadApprovalSignature(_) => Status::permission_denied(message),
    }
}

/// Map a transfer refusal onto a gRPC status: a policy refusal never succeeds on retry,
/// a rate refusal does once the minute passes.
fn refusal_status(refusal: &Refusal) -> Status {
    let message = refusal.to_string();
    match refusal {
        Refusal::Invalid(_) => Status::invalid_argument(message),
        Refusal::NotATransferKey(_) => Status::failed_precondition(message),
        Refusal::RateLimited { .. } => Status::resource_exhausted(message),
        Refusal::Internal => Status::internal(message),
        Refusal::Approval(refusal) => approval_status(refusal),
        Refusal::AssetNotAllowed { .. }
        | Refusal::DestinationNotAllowed { .. }
        | Refusal::OverMaxPerTransfer { .. } => Status::permission_denied(message),
    }
}

/// Map a release refusal onto a gRPC status, on the same terms.
fn release_refusal_status(refusal: &release::Refusal) -> Status {
    use release::Refusal as R;
    let message = refusal.to_string();
    match refusal {
        R::Invalid(_) => Status::invalid_argument(message),
        R::NotAReleaseKey(_) => Status::failed_precondition(message),
        R::RateLimited { .. } => Status::resource_exhausted(message),
        R::Internal => Status::internal(message),
        R::Approval(refusal) => approval_status(refusal),
        R::ArtifactNotAllowed { .. }
        | R::ChannelNotAllowed { .. }
        | R::VersionTaken { .. }
        | R::VersionHeld { .. } => Status::permission_denied(message),
    }
}

fn digest_from(bytes: &[u8]) -> Result<[u8; 32], Status> {
    bytes.try_into().map_err(|_| {
        Status::invalid_argument("digest must be the 32-byte SHA-256 of the held request")
    })
}

fn held_transfer(status: &HoldStatus<Transfer>) -> SignTransferResponse {
    SignTransferResponse {
        status: SigningStatus::PendingApproval as i32,
        canonical_transfer: status.statement.encode(),
        digest: status.statement.digest().to_vec(),
        signature: Vec::new(),
        hold_reason: status.reason.clone(),
        approvals_required: status.required as u32,
        approvals_received: status.received() as u32,
    }
}

fn held_release(status: &HoldStatus<Release>) -> SignReleaseResponse {
    SignReleaseResponse {
        status: SigningStatus::PendingApproval as i32,
        canonical_release: status.statement.encode(),
        digest: status.statement.digest().to_vec(),
        signature: Vec::new(),
        hold_reason: status.reason.clone(),
        approvals_required: status.required as u32,
        approvals_received: status.received() as u32,
    }
}

fn pending_approval<S: Statement>(
    key_label: &str,
    digest: &[u8; 32],
    status: &HoldStatus<S>,
) -> PendingApproval {
    PendingApproval {
        key_label: key_label.to_string(),
        canonical: status.statement.encode(),
        digest: digest.to_vec(),
        hold_reason: status.reason.clone(),
        approvals_required: status.required as u32,
        approved_by: status.approved_by.clone(),
        expires_in_seconds: status.expires_in.as_secs(),
        hold_id: status.hold_id.to_vec(),
    }
}

/// What an accepted approval reports, whichever kind of request it was for.
struct Approved {
    summary: String,
    received: usize,
    required: usize,
}

impl Approved {
    fn from_status<S: Statement>(status: &HoldStatus<S>) -> Self {
        Self {
            summary: status.statement.summary(),
            received: status.received(),
            required: status.required,
        }
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

    /// Count a release decision, on the same terms.
    fn count_release(&self, key_label: &str, outcome: &'static str, reason: &'static str) {
        let key = if self.releases.is_release_key(key_label) {
            key_label.to_string()
        } else {
            "other".to_string()
        };
        metrics::counter!(m::RELEASES_TOTAL, "key_label" => key, "outcome" => outcome, "reason" => reason)
            .increment(1);
    }

    async fn sign_inner(
        &self,
        request: Request<SignRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        self.admit(&request, &request.get_ref().key_label, Operation::Sign)?;
        // With mTLS on, no identity can hold `sign` on a transfer or release key -- the
        // policy refuses to load such a grant -- so this matters with mTLS off, where
        // admission lets everything through. The worker refuses again on the token's
        // marker.
        let key_label = &request.get_ref().key_label;
        if let Some(purpose) = self.purpose_of(key_label) {
            return Err(Status::permission_denied(
                purpose.raw_sign_refusal(key_label),
            ));
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
        let requester = self.admit_bound(
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
            transfer::Outcome::Held(status) => {
                self.count_transfer(&key_label, "held", status.kind);
                tracing::info!(
                    target: "audit",
                    requester = %requester,
                    transfer = %status.statement.summary(),
                    digest = %to_hex(&status.statement.digest()),
                    approvals = status.received(),
                    required = status.required,
                    "transfer held: {}",
                    status.reason
                );
                return Ok(Response::new(held_transfer(&status)));
            }
            transfer::Outcome::Sign {
                transfer,
                reservation,
            } => (transfer, reservation),
        };

        let digest = transfer.digest();
        let approved_by = reservation.approvers();
        let response = self
            .pool
            .submit(JobRequest::SignStatement {
                purpose: Purpose::Transfer,
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
                .map_or(0, |rules| rules.holds.quorum as u32)
        };
        Ok(Response::new(SignTransferResponse {
            status: SigningStatus::Signed as i32,
            canonical_transfer: transfer.encode(),
            digest: digest.to_vec(),
            signature,
            hold_reason: String::new(),
            approvals_required: required,
            approvals_received: approved_by.len() as u32,
        }))
    }

    async fn sign_release_inner(
        &self,
        request: Request<SignReleaseRequest>,
    ) -> Result<Response<SignReleaseResponse>, Status> {
        let requester = self.admit_bound(
            &request,
            &request.get_ref().key_label,
            Operation::SignRelease,
        )?;
        let request = request.into_inner();
        let key_label = request.key_label;
        let asked = request
            .release
            .ok_or_else(|| Status::invalid_argument("release must be set"))?;
        let ask = ReleaseRequest {
            artifact: &asked.artifact,
            version: &asked.version,
            channel: &asked.channel,
            sha256: &asked.sha256,
        };

        let outcome = match self
            .releases
            .submit(&requester, &key_label, &ask, Instant::now())
        {
            Ok(outcome) => outcome,
            Err(refusal) => {
                self.count_release(&key_label, "refused", refusal.reason());
                tracing::warn!(
                    target: "audit",
                    requester = %requester,
                    key = %key_label,
                    artifact = ?asked.artifact,
                    version = ?asked.version,
                    channel = ?asked.channel,
                    sha256 = %to_hex(&asked.sha256),
                    reason = refusal.reason(),
                    "release refused: {refusal}"
                );
                return Err(release_refusal_status(&refusal));
            }
        };

        let (release, reservation) = match outcome {
            release::Outcome::Held(status) => {
                self.count_release(&key_label, "held", status.kind);
                tracing::info!(
                    target: "audit",
                    requester = %requester,
                    release = %status.statement.summary(),
                    digest = %to_hex(&status.statement.digest()),
                    approvals = status.received(),
                    required = status.required,
                    "release held: {}",
                    status.reason
                );
                return Ok(Response::new(held_release(&status)));
            }
            release::Outcome::Sign {
                release,
                reservation,
            } => (release, reservation),
        };

        let digest = release.digest();
        let approved_by = reservation.approvers();
        let response = self
            .pool
            .submit(JobRequest::SignStatement {
                purpose: Purpose::Release,
                key_label: key_label.clone(),
                digest,
            })
            .await
            .map_err(to_status);
        self.observe(&response);

        let signature = match response {
            Ok(JobResponse::Signature(signature)) => signature,
            failed => {
                // No signature exists: give back the hour and any approvals. The version
                // stays bound to this file; see `ReleaseGuard::release`.
                self.releases.release(reservation);
                self.count_release(&key_label, "failed", "hsm");
                return Err(match failed {
                    Ok(other) => unexpected(other),
                    Err(status) => status,
                });
            }
        };

        self.count_release(
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
            release = %release.summary(),
            digest = %to_hex(&digest),
            approved_by = ?approved_by,
            "release signed"
        );

        let required = if approved_by.is_empty() {
            0
        } else {
            self.releases
                .policy()
                .key(&key_label)
                .map_or(0, |rules| rules.holds.quorum as u32)
        };
        Ok(Response::new(SignReleaseResponse {
            status: SigningStatus::Signed as i32,
            canonical_release: release.encode(),
            digest: digest.to_vec(),
            signature,
            hold_reason: String::new(),
            approvals_required: required,
            approvals_received: approved_by.len() as u32,
        }))
    }

    async fn get_pending_approval_inner(
        &self,
        request: Request<GetPendingApprovalRequest>,
    ) -> Result<Response<PendingApproval>, Status> {
        self.admit_bound(&request, &request.get_ref().key_label, Operation::Approve)?;
        let request = request.into_inner();
        let digest = digest_from(&request.digest)?;
        let key_label = &request.key_label;
        let now = Instant::now();

        let pending = match self.purpose_of(key_label) {
            Some(Purpose::Transfer) => self
                .transfers
                .pending(key_label, &digest, now)
                .map(|status| pending_approval(key_label, &digest, &status)),
            Some(Purpose::Release) => self
                .releases
                .pending(key_label, &digest, now)
                .map(|status| pending_approval(key_label, &digest, &status)),
            None => Err(ApprovalRefusal::NotApprovable(key_label.clone())),
        };
        pending
            .map(Response::new)
            .map_err(|refusal| approval_status(&refusal))
    }

    async fn approve_inner(
        &self,
        request: Request<ApproveRequest>,
    ) -> Result<Response<ApproveResponse>, Status> {
        let relayed_by =
            self.admit_bound(&request, &request.get_ref().key_label, Operation::Approve)?;
        let request = request.into_inner();
        let digest = digest_from(&request.digest)?;
        let key_label = &request.key_label;
        let now = Instant::now();

        let purpose = self.purpose_of(key_label);
        let result = match purpose {
            Some(Purpose::Transfer) => self
                .transfers
                .approve(
                    key_label,
                    &digest,
                    &request.hold_id,
                    &request.approver,
                    &request.signature,
                    now,
                )
                .map(|status| Approved::from_status(&status)),
            Some(Purpose::Release) => self
                .releases
                .approve(
                    key_label,
                    &digest,
                    &request.hold_id,
                    &request.approver,
                    &request.signature,
                    now,
                )
                .map(|status| Approved::from_status(&status)),
            None => Err(ApprovalRefusal::NotApprovable(key_label.clone())),
        };
        let kind = purpose.map_or("other", Purpose::as_str);

        match result {
            Ok(approved) => {
                metrics::counter!(m::APPROVALS_TOTAL, "purpose" => kind, "result" => "accepted", "reason" => "ok")
                    .increment(1);
                tracing::info!(
                    target: "audit",
                    approver = %request.approver,
                    relayed_by = %relayed_by,
                    request = %approved.summary,
                    digest = %to_hex(&digest),
                    approvals = approved.received,
                    required = approved.required,
                    "{kind} approval accepted"
                );
                Ok(Response::new(ApproveResponse {
                    approvals_required: approved.required as u32,
                    approvals_received: approved.received as u32,
                    approved: approved.received >= approved.required,
                }))
            }
            Err(refusal) => {
                metrics::counter!(m::APPROVALS_TOTAL, "purpose" => kind, "result" => "rejected", "reason" => refusal.reason())
                    .increment(1);
                // A signature that does not verify is someone trying to approve without
                // the approver's key. That is worth more than a debug line.
                tracing::warn!(
                    target: "audit",
                    approver = ?request.approver,
                    relayed_by = %relayed_by,
                    digest = %to_hex(&digest),
                    reason = refusal.reason(),
                    "{kind} approval rejected: {refusal}"
                );
                Err(approval_status(&refusal))
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

    async fn sign_release(
        &self,
        request: Request<SignReleaseRequest>,
    ) -> Result<Response<SignReleaseResponse>, Status> {
        let started = std::time::Instant::now();
        let result = self.sign_release_inner(request).await;
        self.record("sign_release", started, &result);
        result
    }

    async fn get_pending_approval(
        &self,
        request: Request<GetPendingApprovalRequest>,
    ) -> Result<Response<PendingApproval>, Status> {
        let started = std::time::Instant::now();
        let result = self.get_pending_approval_inner(request).await;
        self.record("get_pending_approval", started, &result);
        result
    }

    async fn approve(
        &self,
        request: Request<ApproveRequest>,
    ) -> Result<Response<ApproveResponse>, Status> {
        let started = std::time::Instant::now();
        let result = self.approve_inner(request).await;
        self.record("approve", started, &result);
        result
    }
}
