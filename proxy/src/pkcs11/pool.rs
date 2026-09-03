//! The blocking-safe worker pool.
//!
//! N dedicated OS threads, each owning one PKCS#11 session, fed by a single bounded
//! MPMC channel. The bound is the backpressure signal: when the queue is full the
//! request is rejected immediately rather than queued, because an unbounded queue
//! converts an overload into unbounded latency for everyone already in flight.
//!
//! `tokio::task::spawn_blocking` is deliberately not used. Its pool grows on demand,
//! threads are not pinned, and a session handle cannot safely migrate between threads
//! under concurrent use -- and crucially, its queue depth is invisible, which is the
//! one number this design needs to expose.

use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use cryptoki::context::Pkcs11;

use super::errors::PoolError;
use super::job::{Job, JobRequest, JobResponse};
use super::metrics::PoolMetrics;
use super::session::{load_module, TokenConfig};
use super::worker::Worker;

#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// One session and one OS thread each.
    pub workers: usize,
    /// Bounded queue depth across all workers.
    pub queue_depth: usize,
    /// How long a submitted job may wait for a result before the caller gives up.
    pub job_timeout: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        let workers = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        Self {
            workers,
            // Deep enough to ride out a burst, shallow enough that a queued request
            // still has a chance of meeting its deadline. Two per worker keeps the
            // worst-case queue wait near two service times.
            queue_depth: workers * 2,
            job_timeout: Duration::from_secs(5),
        }
    }
}

impl PoolConfig {
    pub fn from_env() -> Self {
        let defaults = Self::default();
        Self {
            workers: env_usize("HSM_WORKERS").unwrap_or(defaults.workers),
            queue_depth: env_usize("HSM_QUEUE_DEPTH").unwrap_or(defaults.queue_depth),
            job_timeout: env_usize("HSM_JOB_TIMEOUT_MS")
                .map(|ms| Duration::from_millis(ms as u64))
                .unwrap_or(defaults.job_timeout),
        }
    }
}

fn env_usize(key: &str) -> Option<usize> {
    std::env::var(key).ok()?.parse().ok()
}

pub struct Pool {
    tx: flume::Sender<Job>,
    workers: Vec<JoinHandle<()>>,
    job_timeout: Duration,
    metrics: Arc<PoolMetrics>,
    /// Held so the module outlives every session derived from it. Dropping the context
    /// calls `C_Finalize`, which invalidates all sessions.
    _pkcs11: Pkcs11,
}

impl Pool {
    pub fn start(token: TokenConfig, config: PoolConfig) -> Result<Self, PoolError> {
        let (pkcs11, slot) = load_module(&token)
            .map_err(|e| PoolError::Internal(format!("failed to open token: {e:#}")))?;

        let metrics = Arc::new(PoolMetrics::default());
        let (tx, rx) = flume::bounded::<Job>(config.queue_depth);

        // Each worker opens its own session *on its own thread*, so a session is never
        // created on one thread and used on another.
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), PoolError>>();
        let mut workers = Vec::with_capacity(config.workers);

        for id in 0..config.workers {
            let pkcs11 = pkcs11.clone();
            let token = token.clone();
            let metrics = Arc::clone(&metrics);
            let rx = rx.clone();
            let ready_tx = ready_tx.clone();

            let handle = std::thread::Builder::new()
                .name(format!("hsm-worker-{id}"))
                .spawn(move || match Worker::new(id, pkcs11, slot, token, metrics) {
                    Ok(worker) => {
                        let _ = ready_tx.send(Ok(()));
                        worker.run(rx);
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                    }
                })
                .map_err(|e| PoolError::Internal(format!("failed to spawn worker: {e}")))?;

            workers.push(handle);
        }
        drop(ready_tx);
        drop(rx);

        // Fail startup loudly rather than serving traffic from a half-built pool.
        for _ in 0..config.workers {
            match ready_rx.recv() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    return Err(PoolError::Internal(
                        "a worker thread died during startup".to_string(),
                    ))
                }
            }
        }

        tracing::info!(
            workers = config.workers,
            queue_depth = config.queue_depth,
            job_timeout_ms = config.job_timeout.as_millis() as u64,
            "worker pool started"
        );

        Ok(Self {
            tx,
            workers,
            job_timeout: config.job_timeout,
            metrics,
            _pkcs11: pkcs11,
        })
    }

    pub fn metrics(&self) -> &Arc<PoolMetrics> {
        &self.metrics
    }

    /// Current queue depth. Cheap enough to sample per scrape.
    pub fn queue_len(&self) -> usize {
        self.tx.len()
    }

    /// Submit a job and await its result.
    ///
    /// Rejects immediately when the queue is full: shedding preserves the tail latency
    /// of accepted requests, whereas queueing sacrifices it for everyone.
    pub async fn submit(&self, request: JobRequest) -> Result<JobResponse, PoolError> {
        let (responder, result_rx) = tokio::sync::oneshot::channel();

        PoolMetrics::incr(&self.metrics.jobs_submitted);

        let job = Job {
            request,
            responder,
            enqueued_at: Instant::now(),
        };

        self.tx.try_send(job).map_err(|e| match e {
            flume::TrySendError::Full(_) => {
                PoolMetrics::incr(&self.metrics.jobs_rejected_queue_full);
                PoolError::Overloaded
            }
            flume::TrySendError::Disconnected(_) => PoolError::ShuttingDown,
        })?;

        match tokio::time::timeout(self.job_timeout, result_rx).await {
            Ok(Ok(result)) => result,
            // The worker dropped the responder without sending: it panicked or exited.
            Ok(Err(_)) => Err(PoolError::ShuttingDown),
            Err(_) => {
                PoolMetrics::incr(&self.metrics.jobs_timed_out);
                Err(PoolError::Timeout)
            }
        }
    }

    /// Close the queue, let workers drain what they already accepted, and join them.
    pub fn shutdown(self) {
        tracing::info!("draining worker pool");
        drop(self.tx);
        for handle in self.workers {
            let _ = handle.join();
        }
        tracing::info!("worker pool drained");
    }
}
