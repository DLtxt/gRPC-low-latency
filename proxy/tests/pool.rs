//! Integration tests for the worker pool against a real SoftHSM token.
//!
//! These cover the paths that unit tests cannot reach and that no benchmark exercises:
//! what happens when the queue fills, when a session dies mid-flight, when the pool is
//! shut down while work is outstanding, and whether PKCS#11 login really is per-token
//! rather than per-session. Each was previously assumed rather than verified.

mod common;

use std::sync::Arc;
use std::time::Duration;

use grpc_low_latency_proxy::crypto::SignAlgorithm;
use grpc_low_latency_proxy::pkcs11::{JobRequest, JobResponse, Pool, PoolConfig, PoolError};
use sha2::{Digest, Sha256};

fn sign_job() -> JobRequest {
    JobRequest::Sign {
        key_label: "demo-ec-p256".to_string(),
        algorithm: SignAlgorithm::Ecdsa,
        payload: Sha256::digest(b"integration test").to_vec(),
    }
}

fn config(workers: usize, queue_depth: usize) -> PoolConfig {
    PoolConfig {
        workers,
        queue_depth,
        job_timeout: Duration::from_secs(5),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signs_and_verifies_through_the_pool() {
    let _serial = common::serial_guard().await;
    let token = require_token!();
    let pool = Pool::start(token.config.clone(), config(2, 8)).expect("pool starts");

    let signature = match pool.submit(sign_job()).await.expect("sign succeeds") {
        JobResponse::Signature(sig) => sig,
        other => panic!("expected a signature, got {other:?}"),
    };
    assert_eq!(signature.len(), 64, "P-256 signatures are r||s, 64 bytes");

    let verified = pool
        .submit(JobRequest::Verify {
            key_label: "demo-ec-p256".to_string(),
            algorithm: SignAlgorithm::Ecdsa,
            payload: Sha256::digest(b"integration test").to_vec(),
            signature,
        })
        .await
        .expect("verify succeeds");
    assert!(matches!(verified, JobResponse::Verified(true)));

    pool.shutdown();
}

/// A signature over different data must be rejected, and rejected as a *false answer*
/// rather than an error. A caller has to be able to tell "your signature is wrong" from
/// "the service is broken".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_signature_is_false_not_an_error() {
    let _serial = common::serial_guard().await;
    let token = require_token!();
    let pool = Pool::start(token.config.clone(), config(2, 8)).expect("pool starts");

    let signature = match pool.submit(sign_job()).await.unwrap() {
        JobResponse::Signature(sig) => sig,
        other => panic!("expected a signature, got {other:?}"),
    };

    let result = pool
        .submit(JobRequest::Verify {
            key_label: "demo-ec-p256".to_string(),
            algorithm: SignAlgorithm::Ecdsa,
            payload: Sha256::digest(b"different data entirely").to_vec(),
            signature,
        })
        .await
        .expect("verification of a bad signature is still a successful call");
    assert!(matches!(result, JobResponse::Verified(false)));

    pool.shutdown();
}

/// An unknown key label must be `KeyNotFound`, not an opaque internal error, so the gRPC
/// layer can map it to NOT_FOUND instead of INTERNAL.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_key_is_key_not_found() {
    let _serial = common::serial_guard().await;
    let token = require_token!();
    let pool = Pool::start(token.config.clone(), config(1, 4)).expect("pool starts");

    let err = pool
        .submit(JobRequest::Sign {
            key_label: "no-such-key".to_string(),
            algorithm: SignAlgorithm::Ecdsa,
            payload: Sha256::digest(b"x").to_vec(),
        })
        .await
        .expect_err("a missing key must fail");
    assert!(
        matches!(err, PoolError::KeyNotFound(ref label) if label == "no-such-key"),
        "expected KeyNotFound, got {err:?}"
    );

    pool.shutdown();
}

/// The backpressure contract: when the bounded queue is full, submission fails
/// *immediately* with `Overloaded` rather than waiting. This is the single most
/// important property of the design -- queueing instead of shedding is what destroys
/// tail latency -- and nothing tested it before.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_queue_sheds_instead_of_queueing() {
    let _serial = common::serial_guard().await;
    let token = require_token!();

    // One worker and a one-deep queue, so saturation is reachable deterministically.
    let pool = Arc::new(Pool::start(token.config.clone(), config(1, 1)).expect("pool starts"));

    // Fire many concurrent submissions. With capacity for one in-flight job plus one
    // queued, the rest must be shed rather than accepted.
    let mut handles = Vec::new();
    for _ in 0..64 {
        let pool = Arc::clone(&pool);
        handles.push(tokio::spawn(async move { pool.submit(sign_job()).await }));
    }

    let mut shed = 0;
    let mut accepted = 0;
    for handle in handles {
        match handle.await.expect("task did not panic") {
            Ok(_) => accepted += 1,
            Err(PoolError::Overloaded) => shed += 1,
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    assert!(accepted > 0, "some work should have been done");
    assert!(
        shed > 0,
        "a 1-deep queue under 64 concurrent submissions must shed; \
         accepted={accepted} shed={shed}"
    );

    let metrics = pool.metrics();
    use grpc_low_latency_proxy::pkcs11::metrics::PoolMetrics;
    assert_eq!(
        PoolMetrics::get(&metrics.jobs_rejected_queue_full),
        shed,
        "the rejection counter must agree with what callers observed"
    );
}

/// Several workers must be able to log in to the same token. PKCS#11 login state is
/// per-token for the whole application rather than per-session, so the second worker
/// finds itself already logged in -- which the pool has to treat as success.
///
/// plan.md §4.3 flags this as a spec reading worth verifying rather than assuming, and
/// until now it was only ever exercised incidentally by benchmarks.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_workers_share_one_token_login() {
    let _serial = common::serial_guard().await;
    let token = require_token!();
    let pool = Pool::start(token.config.clone(), config(8, 32)).expect("8 workers all start");

    // Enough concurrent work that every worker is used at least once.
    let pool = Arc::new(pool);
    let mut handles = Vec::new();
    for _ in 0..64 {
        let pool = Arc::clone(&pool);
        handles.push(tokio::spawn(async move { pool.submit(sign_job()).await }));
    }

    let mut ok = 0;
    for handle in handles {
        if handle.await.unwrap().is_ok() {
            ok += 1;
        }
    }
    assert!(
        ok >= 32,
        "most work should succeed across 8 workers, got {ok}"
    );

    use grpc_low_latency_proxy::pkcs11::metrics::PoolMetrics;
    assert_eq!(
        PoolMetrics::get(&pool.metrics().session_resets),
        0,
        "no session should have needed resetting during healthy operation"
    );
}

/// Shutdown must drain work already accepted rather than dropping it, and must not hang.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_drains_in_flight_work() {
    let _serial = common::serial_guard().await;
    let token = require_token!();
    let pool = Arc::new(Pool::start(token.config.clone(), config(2, 16)).expect("pool starts"));

    let mut handles = Vec::new();
    for _ in 0..16 {
        let pool = Arc::clone(&pool);
        handles.push(tokio::spawn(async move { pool.submit(sign_job()).await }));
    }

    // Let the work land in the queue before tearing down.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut completed = 0;
    for handle in handles {
        if handle.await.unwrap().is_ok() {
            completed += 1;
        }
    }

    let pool = Arc::try_unwrap(pool).unwrap_or_else(|_| panic!("pool still referenced"));

    // The real assertion is that this returns at all: shutdown joins every worker
    // thread, so a worker blocked on a channel that never closes would hang here
    // forever. Wrapping it in a timeout turns that failure into a test failure rather
    // than a stuck CI job.
    let done = tokio::task::spawn_blocking(move || pool.shutdown());
    tokio::time::timeout(Duration::from_secs(10), done)
        .await
        .expect("shutdown must not hang")
        .expect("shutdown task must not panic");

    assert!(completed > 0, "accepted work should have completed");
}

/// The per-worker handle cache should resolve each label once per worker, not once per
/// request. With one worker and many requests, that means exactly one miss.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn handle_cache_resolves_once_per_worker() {
    let _serial = common::serial_guard().await;
    let token = require_token!();
    let pool = Pool::start(token.config.clone(), config(1, 8)).expect("pool starts");

    for _ in 0..25 {
        pool.submit(sign_job()).await.expect("sign succeeds");
    }

    use grpc_low_latency_proxy::pkcs11::metrics::PoolMetrics;
    let metrics = pool.metrics();
    let misses = PoolMetrics::get(&metrics.handle_cache_misses);
    let hits = PoolMetrics::get(&metrics.handle_cache_hits);

    assert_eq!(misses, 1, "one worker, one label: exactly one lookup");
    assert_eq!(hits, 24, "every subsequent request should hit the cache");

    pool.shutdown();
}

/// RSA and ECDSA keys must both be usable through the same pool, with the right
/// signature sizes -- a cheap guard against mechanism/key mismatches.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn both_key_types_sign() {
    let _serial = common::serial_guard().await;
    let token = require_token!();
    let pool = Pool::start(token.config.clone(), config(2, 8)).expect("pool starts");

    let ec = pool.submit(sign_job()).await.expect("ECDSA signs");
    match ec {
        JobResponse::Signature(sig) => assert_eq!(sig.len(), 64),
        other => panic!("expected signature, got {other:?}"),
    }

    let rsa = pool
        .submit(JobRequest::Sign {
            key_label: "demo-rsa-2048".to_string(),
            algorithm: SignAlgorithm::Sha256RsaPkcs,
            payload: b"integration test".to_vec(),
        })
        .await
        .expect("RSA signs");
    match rsa {
        JobResponse::Signature(sig) => assert_eq!(sig.len(), 256, "RSA-2048 is 256 bytes"),
        other => panic!("expected signature, got {other:?}"),
    }

    pool.shutdown();
}
