//! Measure the token's own parallel ceiling, with no gRPC, no Tokio, and no proxy.
//!
//! The M3 pool showed ECDSA service time doubling as workers doubled while RSA scaled
//! nearly linearly. That pattern is what a fixed *serialized section* inside the module
//! looks like: an operation costing S microseconds of parallel work plus L microseconds
//! behind a lock scales like Amdahl's law, so a cheap operation (ECDSA, ~55 microseconds)
//! stops scaling almost immediately while an expensive one (RSA, ~836 microseconds)
//! keeps going.
//!
//! This binary tests that directly -- N threads, N sessions, tight sign loops -- so the
//! proxy's throughput can be stated as a fraction of what the token itself allows,
//! rather than being confused with it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::ObjectClass;
use grpc_low_latency_proxy::pkcs11::{
    find_object, load_module, session::login_session, TokenConfig,
};
use sha2::{Digest, Sha256};

/// `SIGNATURE_MECHANISM_ECDSA_SHA256` from the proto, as an i32.
const ECDSA_SHA256_MECHANISM: i32 = 1;

fn main() -> Result<()> {
    let config = TokenConfig::from_env()?;
    let (pkcs11, slot) = load_module(&config)?;

    let duration = Duration::from_millis(
        std::env::var("CEILING_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3000),
    );
    let thread_counts: Vec<usize> = std::env::var("CEILING_THREADS")
        .unwrap_or_else(|_| "1 2 4 6 8 12 16".to_string())
        .split_whitespace()
        .filter_map(|v| v.parse().ok())
        .collect();

    println!("token ceiling: raw PKCS#11, no gRPC, {duration:?} per point\n");

    for (label, mechanism_name) in [
        ("demo-ec-p256", "ECDSA P-256"),
        ("demo-rsa-2048", "RSA-2048"),
    ] {
        println!("-- {mechanism_name} ({label}) --");
        println!(
            "{:<9} {:<14} {:<14} {:<10}",
            "threads", "ops/sec", "per-op", "scaling"
        );

        let mut baseline = 0.0f64;
        for &threads in &thread_counts {
            let ops_per_sec = run_point(&pkcs11, slot, &config, label, threads, duration)?;
            if baseline == 0.0 {
                baseline = ops_per_sec;
            }
            println!(
                "{:<9} {:<14.0} {:<14} {:<10}",
                threads,
                ops_per_sec,
                format!("{:.1} us", 1_000_000.0 * threads as f64 / ops_per_sec),
                format!("{:.2}x", ops_per_sec / baseline),
            );
        }
        println!();
    }

    verify_cost(&pkcs11, slot, &config)?;

    Ok(())
}

/// Compare verifying in this process against verifying on the token.
///
/// M5 moved Verify off the token on the assumption that removing the HSM must make it
/// faster. It did not, so the two have to be priced directly. ECDSA verification is
/// inherently dearer than signing -- signing is one fixed-base scalar multiplication,
/// verification is two, one of them variable-base -- and a pure-Rust implementation is
/// not obliged to beat the token's OpenSSL.
fn verify_cost(
    pkcs11: &cryptoki::context::Pkcs11,
    slot: cryptoki::slot::Slot,
    config: &TokenConfig,
) -> Result<()> {
    use cryptoki::object::ObjectClass;
    use grpc_low_latency_proxy::crypto::{public_key_to_spki_der, verify_public, SigningInput};

    let session = login_session(pkcs11, slot, config)
        .or_else(|_| pkcs11.open_rw_session(slot).map_err(anyhow::Error::from))?;

    let private = find_object(&session, ObjectClass::PRIVATE_KEY, "demo-ec-p256")?
        .ok_or_else(|| anyhow!("demo-ec-p256 not found"))?;
    let public = find_object(&session, ObjectClass::PUBLIC_KEY, "demo-ec-p256")?
        .ok_or_else(|| anyhow!("demo-ec-p256 public key not found"))?;

    let digest = Sha256::digest(b"verify cost probe").to_vec();
    let signature = session.sign(&Mechanism::Ecdsa, private, &digest)?;
    let (spki, _) = public_key_to_spki_der(&session, public)?;

    let iterations = 3000;

    let start = Instant::now();
    for _ in 0..iterations {
        session.verify(&Mechanism::Ecdsa, public, &digest, &signature)?;
    }
    let token = start.elapsed();

    let start = Instant::now();
    for _ in 0..iterations {
        assert!(verify_public(
            &spki,
            crate::ECDSA_SHA256_MECHANISM,
            &SigningInput::Digest(digest.clone()),
            &signature
        )?);
    }
    let in_process = start.elapsed();

    let start = Instant::now();
    for _ in 0..iterations {
        session.sign(&Mechanism::Ecdsa, private, &digest)?;
    }
    let sign = start.elapsed();

    println!("-- ECDSA P-256 single-threaded cost, no gRPC --");
    println!(
        "{:<28} {:>10}",
        "sign (token)",
        format!("{:.1} us", sign.as_micros() as f64 / iterations as f64)
    );
    println!(
        "{:<28} {:>10}",
        "verify (token, OpenSSL)",
        format!("{:.1} us", token.as_micros() as f64 / iterations as f64)
    );
    println!(
        "{:<28} {:>10}",
        "verify (in-process, p256)",
        format!(
            "{:.1} us",
            in_process.as_micros() as f64 / iterations as f64
        )
    );

    // ring is what plan.md 2 actually specified for the in-process path. It carries
    // assembly for P-256; the RustCrypto implementation is portable Rust.
    // ring hashes the message itself, so this measures message-input verification.
    {
        use grpc_low_latency_proxy::crypto::sec1_point_from_spki;
        let point = sec1_point_from_spki(&spki)?;
        let message = b"verify cost probe";
        let ring_sig = session.sign(&Mechanism::Ecdsa, private, &Sha256::digest(message))?;
        let key = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_FIXED,
            &point,
        );
        key.verify(message, &ring_sig)
            .map_err(|_| anyhow!("ring rejected a signature the token produced"))?;

        let start = Instant::now();
        for _ in 0..iterations {
            key.verify(message, &ring_sig)
                .map_err(|_| anyhow!("ring verification failed"))?;
        }
        let ring_elapsed = start.elapsed();
        println!(
            "{:<28} {:>10}",
            "verify (in-process, ring)",
            format!(
                "{:.1} us",
                ring_elapsed.as_micros() as f64 / iterations as f64
            )
        );
    }
    println!();

    Ok(())
}

/// Run `threads` sessions in tight sign loops for `duration`, return aggregate ops/sec.
fn run_point(
    pkcs11: &cryptoki::context::Pkcs11,
    slot: cryptoki::slot::Slot,
    config: &TokenConfig,
    label: &str,
    threads: usize,
    duration: Duration,
) -> Result<f64> {
    let is_rsa = label.contains("rsa");
    let digest = Sha256::digest(b"ceiling probe").to_vec();

    // Every thread starts measuring at the same instant, so a slow session open on one
    // thread does not count as idle time against the others.
    let barrier = Arc::new(Barrier::new(threads + 1));
    let stop = Arc::new(AtomicBool::new(false));

    let mut handles = Vec::with_capacity(threads);
    for _ in 0..threads {
        let pkcs11 = pkcs11.clone();
        let config = config.clone();
        let barrier = Arc::clone(&barrier);
        let stop = Arc::clone(&stop);
        let digest = digest.clone();
        let label = label.to_string();

        handles.push(std::thread::spawn(move || -> Result<u64> {
            let session = login_session(&pkcs11, slot, &config).or_else(|_| {
                // Already logged in: login state is per-token for the application.
                pkcs11.open_rw_session(slot).map_err(anyhow::Error::from)
            })?;

            let key = find_object(&session, ObjectClass::PRIVATE_KEY, &label)?
                .ok_or_else(|| anyhow!("key '{label}' not found"))?;

            let payload: &[u8] = if is_rsa { b"ceiling probe" } else { &digest };

            barrier.wait();

            let mut count = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let mechanism = if is_rsa {
                    Mechanism::Sha256RsaPkcs
                } else {
                    Mechanism::Ecdsa
                };
                session.sign(&mechanism, key, payload)?;
                count += 1;
            }
            Ok(count)
        }));
    }

    barrier.wait();
    let started = Instant::now();
    std::thread::sleep(duration);
    stop.store(true, Ordering::Relaxed);
    let elapsed = started.elapsed();

    let mut total = 0u64;
    for handle in handles {
        total += handle
            .join()
            .map_err(|_| anyhow!("a probe thread panicked"))??;
    }

    Ok(total as f64 / elapsed.as_secs_f64())
}
