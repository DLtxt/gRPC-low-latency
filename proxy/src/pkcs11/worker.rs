//! A pool worker: one OS thread that owns one PKCS#11 session for its entire life.
//!
//! The session never moves between threads. `cryptoki::Session` is `Send` but
//! deliberately not `Sync`, which is the API encoding the same rule: a session may be
//! given to a thread, never shared between them.
//!
//! Two things make this fast rather than merely correct:
//!
//! 1. **The per-worker handle cache.** Object handles are scoped to the session that
//!    found them, so they cannot be shared across workers -- each worker keeps its own.
//!    Without it every request pays a `C_FindObjects`, which M0 measured at ~57 microseconds,
//!    roughly the cost of the ECDSA signature itself.
//! 2. **No reactor blocking.** These are dedicated OS threads, so a blocking `C_Sign`
//!    stalls only this worker rather than a Tokio runtime thread.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use cryptoki::context::Pkcs11;
use cryptoki::mechanism::aead::GcmParams;
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{ObjectClass, ObjectHandle};
use cryptoki::session::Session;
use cryptoki::slot::Slot;

use crate::crypto;

use super::errors::{is_session_fatal, PoolError};
use super::job::{Job, JobRequest, JobResponse, KeyKind};
use super::metrics::PoolMetrics;
use super::session::{find_object, login_session, TokenConfig};

/// AES-GCM: 96-bit IV, 128-bit tag.
const GCM_TAG_BITS: u64 = 128;

/// Handles for one label, filled in lazily as each class is first needed.
#[derive(Default, Clone, Copy)]
struct KeyHandles {
    private: Option<ObjectHandle>,
    public: Option<ObjectHandle>,
    secret: Option<ObjectHandle>,
}

impl KeyHandles {
    fn get(&self, kind: KeyKind) -> Option<ObjectHandle> {
        match kind {
            KeyKind::Private => self.private,
            KeyKind::Public => self.public,
            KeyKind::Secret => self.secret,
        }
    }

    fn set(&mut self, kind: KeyKind, handle: ObjectHandle) {
        match kind {
            KeyKind::Private => self.private = Some(handle),
            KeyKind::Public => self.public = Some(handle),
            KeyKind::Secret => self.secret = Some(handle),
        }
    }
}

impl KeyKind {
    fn object_class(self) -> ObjectClass {
        match self {
            KeyKind::Private => ObjectClass::PRIVATE_KEY,
            KeyKind::Public => ObjectClass::PUBLIC_KEY,
            KeyKind::Secret => ObjectClass::SECRET_KEY,
        }
    }
}

pub struct Worker {
    id: usize,
    pkcs11: Pkcs11,
    slot: Slot,
    token: TokenConfig,
    session: Session,
    handles: HashMap<String, KeyHandles>,
    metrics: Arc<PoolMetrics>,
}

impl Worker {
    pub fn new(
        id: usize,
        pkcs11: Pkcs11,
        slot: Slot,
        token: TokenConfig,
        metrics: Arc<PoolMetrics>,
    ) -> Result<Self, PoolError> {
        let session = open_worker_session(&pkcs11, slot, &token)?;
        Ok(Self {
            id,
            pkcs11,
            slot,
            token,
            session,
            handles: HashMap::new(),
            metrics,
        })
    }

    /// Receive jobs until the channel closes, then log out and let the session drop.
    pub fn run(mut self, rx: flume::Receiver<Job>) {
        tracing::debug!(worker = self.id, "worker started");

        while let Ok(job) = rx.recv() {
            let queue_wait = job.enqueued_at.elapsed();
            let started = Instant::now();
            let operation_label = job.request.operation();

            let result = self.execute(job.request);

            let service = started.elapsed();
            PoolMetrics::add(
                &self.metrics.queue_wait_nanos_total,
                queue_wait.as_nanos() as u64,
            );
            PoolMetrics::add(&self.metrics.service_nanos_total, service.as_nanos() as u64);

            // Also as Prometheus histograms. The atomic totals above give means; the
            // histograms give the tail, and the tail is the whole question here.
            // Recorded from the worker thread rather than the handler because only the
            // worker can separate queue wait from HSM service time -- from outside,
            // the two are one number.
            metrics::histogram!(crate::telemetry::metrics::QUEUE_WAIT)
                .record(queue_wait.as_secs_f64());
            metrics::histogram!(
                crate::telemetry::metrics::HSM_SERVICE,
                "operation" => operation_label
            )
            .record(service.as_secs_f64());
            match &result {
                Ok(_) => PoolMetrics::incr(&self.metrics.jobs_completed),
                Err(_) => {
                    PoolMetrics::incr(&self.metrics.jobs_completed);
                    PoolMetrics::incr(&self.metrics.jobs_failed);
                }
            }

            // A dropped receiver means the caller gave up (timed out or disconnected).
            // That is normal under load and must not take the worker down.
            let _ = job.responder.send(result);
        }

        tracing::debug!(worker = self.id, "channel closed, worker shutting down");
        let _ = self.session.logout();
    }

    fn execute(&mut self, request: JobRequest) -> Result<JobResponse, PoolError> {
        let operation = request.operation();
        let result = self.dispatch(&request);

        // A session-level failure poisons every cached handle, so recover before the
        // next job rather than failing every subsequent request on this worker.
        if let Err(PoolError::Hsm { source, .. }) = &result {
            if is_session_fatal(source) {
                tracing::warn!(
                    worker = self.id,
                    operation,
                    error = %source,
                    "session is unusable, reopening"
                );
                self.reset_session();
            }
        }

        result
    }

    fn dispatch(&mut self, request: &JobRequest) -> Result<JobResponse, PoolError> {
        match request {
            JobRequest::Sign {
                key_label,
                algorithm,
                payload,
            } => {
                let key = self.handle(KeyKind::Private, key_label)?;
                let signature = self
                    .session
                    .sign(&algorithm.mechanism(), key, payload)
                    .map_err(|e| PoolError::hsm("C_Sign", e))?;
                Ok(JobResponse::Signature(signature))
            }

            JobRequest::Verify {
                key_label,
                algorithm,
                payload,
                signature,
            } => {
                let key = self.handle(KeyKind::Public, key_label)?;
                match self
                    .session
                    .verify(&algorithm.mechanism(), key, payload, signature)
                {
                    Ok(()) => Ok(JobResponse::Verified(true)),
                    Err(cryptoki::error::Error::Pkcs11(
                        cryptoki::error::RvError::SignatureInvalid
                        | cryptoki::error::RvError::SignatureLenRange,
                        _,
                    )) => Ok(JobResponse::Verified(false)),
                    Err(e) => Err(PoolError::hsm("C_Verify", e)),
                }
            }

            JobRequest::Encrypt {
                key_label,
                plaintext,
                associated_data,
                iv,
            } => {
                let key = self.handle(KeyKind::Secret, key_label)?;
                let mut iv = iv.clone();
                let params = GcmParams::new(&mut iv, associated_data, GCM_TAG_BITS.into())
                    .map_err(|e| PoolError::InvalidRequest(e.to_string()))?;
                let ciphertext = self
                    .session
                    .encrypt(&Mechanism::AesGcm(params), key, plaintext)
                    .map_err(|e| PoolError::hsm("C_Encrypt", e))?;
                Ok(JobResponse::Ciphertext(ciphertext))
            }

            JobRequest::Decrypt {
                key_label,
                ciphertext,
                associated_data,
                iv,
            } => {
                let key = self.handle(KeyKind::Secret, key_label)?;
                let mut iv = iv.clone();
                let params = GcmParams::new(&mut iv, associated_data, GCM_TAG_BITS.into())
                    .map_err(|e| PoolError::InvalidRequest(e.to_string()))?;
                match self
                    .session
                    .decrypt(&Mechanism::AesGcm(params), key, ciphertext)
                {
                    Ok(plaintext) => Ok(JobResponse::Plaintext(plaintext)),
                    // Failed authentication is the caller's problem, not a broken token.
                    Err(cryptoki::error::Error::Pkcs11(
                        cryptoki::error::RvError::EncryptedDataInvalid
                        | cryptoki::error::RvError::EncryptedDataLenRange,
                        _,
                    )) => Err(PoolError::InvalidRequest(
                        "ciphertext failed authentication".to_string(),
                    )),
                    Err(e) => Err(PoolError::hsm("C_Decrypt", e)),
                }
            }

            JobRequest::GetPublicKey { key_label } => {
                let key = self.handle(KeyKind::Public, key_label)?;
                let (spki_der, key_type) = crypto::public_key_to_spki_der(&self.session, key)
                    .map_err(|e| PoolError::Internal(e.to_string()))?;
                Ok(JobResponse::PublicKey { spki_der, key_type })
            }
        }
    }

    /// Resolve a label to an object handle, caching the result for this session.
    fn handle(&mut self, kind: KeyKind, label: &str) -> Result<ObjectHandle, PoolError> {
        if let Some(handle) = self.handles.get(label).and_then(|h| h.get(kind)) {
            PoolMetrics::incr(&self.metrics.handle_cache_hits);
            return Ok(handle);
        }

        PoolMetrics::incr(&self.metrics.handle_cache_misses);

        let handle = find_object(&self.session, kind.object_class(), label)
            .map_err(|e| PoolError::Internal(e.to_string()))?
            .ok_or_else(|| PoolError::KeyNotFound(label.to_string()))?;

        self.handles
            .entry(label.to_string())
            .or_default()
            .set(kind, handle);

        Ok(handle)
    }

    /// Close the broken session, open a fresh one, and drop every cached handle --
    /// handles from the old session are meaningless in the new one.
    fn reset_session(&mut self) {
        self.handles.clear();
        self.metrics.session_resets.fetch_add(1, Ordering::Relaxed);

        match open_worker_session(&self.pkcs11, self.slot, &self.token) {
            Ok(session) => {
                self.session = session;
                tracing::info!(worker = self.id, "session reopened");
            }
            Err(e) => {
                // Leave the old session in place and try again on the next failure;
                // tearing the worker down would silently shrink the pool.
                tracing::error!(worker = self.id, error = %e, "failed to reopen session");
            }
        }
    }
}

/// Open a session and ensure it is logged in.
///
/// PKCS#11 login state is per-token for the whole application, not per-session, so the
/// second and later workers find themselves already logged in. That is success, not an
/// error -- and treating it as such is how this code stays correct whether or not the
/// module actually behaves the way the specification is usually read.
fn open_worker_session(
    pkcs11: &Pkcs11,
    slot: Slot,
    token: &TokenConfig,
) -> Result<Session, PoolError> {
    match login_session(pkcs11, slot, token) {
        Ok(session) => Ok(session),
        Err(err) => {
            let already_logged_in = err
                .downcast_ref::<cryptoki::error::Error>()
                .map(|e| {
                    matches!(
                        e,
                        cryptoki::error::Error::Pkcs11(
                            cryptoki::error::RvError::UserAlreadyLoggedIn,
                            _
                        )
                    )
                })
                .unwrap_or(false);

            if already_logged_in {
                pkcs11
                    .open_rw_session(slot)
                    .map_err(|e| PoolError::hsm("C_OpenSession", e))
            } else {
                Err(PoolError::Internal(format!("{err:#}")))
            }
        }
    }
}
