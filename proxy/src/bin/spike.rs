//! M0 spike: prove the risky part of the whole project before anything else is built.
//!
//! Loads `libsofthsm2.so` into this process via `cryptoki`, logs in to the token,
//! generates an ECDSA P-256 key pair, signs a digest, and verifies it. If this runs,
//! the PKCS#11 FFI foundation the rest of the proxy sits on is sound.
//!
//! Exit criterion (plan.md M0): one successful ECDSA signature printed to stdout.
//!
//! It also runs a short single-session sign loop. That is strictly more than M0 asks for,
//! but it prices SoftHSM2's per-operation cost, which is the thing risk R2 in plan.md 9
//! is about: success criterion S1 (>= 4,000 QPS) is only reachable if one session can do
//! a meaningful fraction of that. Cheaper to learn here than at M3.

use anyhow::{anyhow, Context, Result};
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use sha2::{Digest, Sha256};

/// DER encoding of the named-curve OID for secp256r1 / prime256v1 (1.2.840.10045.3.1.7).
/// PKCS#11 wants CKA_EC_PARAMS as a DER-encoded ANSI X9.62 `Parameters` choice.
const SECP256R1_OID_DER: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

const KEY_LABEL: &str = "demo-ec-p256";
const RSA_KEY_LABEL: &str = "demo-rsa-2048";

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn main() -> Result<()> {
    let module = env_or("PKCS11_MODULE", "/usr/lib/softhsm/libsofthsm2.so");
    let token_label = env_or("TOKEN_LABEL", "grpc-low-latency");
    let user_pin = env_or("USER_PIN", "1234");

    println!("== M0 spike: cryptoki -> SoftHSM2 ==");
    println!("module      : {module}");
    println!("token label : {token_label}");

    // 1. Load the PKCS#11 module into this address space and initialize it.
    //    CKF_OS_LOCKING_OK tells the module to use OS locking primitives; the M3 worker pool depends
    //    on the module being safe to call from multiple threads.
    let pkcs11 = Pkcs11::new(&module).with_context(|| format!("dlopen/load failed: {module}"))?;
    pkcs11
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .context("C_Initialize(CKF_OS_LOCKING_OK) failed")?;

    let info = pkcs11.get_library_info().context("C_GetInfo failed")?;
    println!(
        "library     : {} {}.{}",
        info.manufacturer_id().trim(),
        info.library_version().major(),
        info.library_version().minor()
    );

    // 2. Find the slot holding our token.
    let slot = pkcs11
        .get_slots_with_token()
        .context("C_GetSlotList failed")?
        .into_iter()
        .find(|slot| {
            pkcs11
                .get_token_info(*slot)
                .map(|t| t.label().trim() == token_label)
                .unwrap_or(false)
        })
        .ok_or_else(|| anyhow!("no slot holds a token labelled '{token_label}'"))?;
    println!("slot        : {}", slot.id());

    // 3. Open a R/W session and log in as the user.
    let session = pkcs11.open_rw_session(slot).context("C_OpenSession failed")?;
    session
        .login(UserType::User, Some(&AuthPin::new(user_pin.into())))
        .context("C_Login(CKU_USER) failed -- wrong PIN?")?;
    println!("login       : ok");

    // 4. Get a signing key: reuse the demo key if the token already has one, else make it.
    let (private_key, public_key) = match find_key_pair(&session, KEY_LABEL)? {
        Some(pair) => {
            println!("key         : found existing '{KEY_LABEL}'");
            pair
        }
        None => {
            let pair = generate_ec_key_pair(&session, KEY_LABEL)?;
            println!("key         : generated '{KEY_LABEL}'");
            pair
        }
    };

    // 5. Sign. CKM_ECDSA signs a pre-computed digest rather than raw data, which is also
    //    what the proxy will do in anger: hash in Rust, send 32 bytes across the FFI
    //    boundary instead of the whole payload.
    let message = b"gRPC-low-latency M0 spike";
    let digest = Sha256::digest(message);

    let signature = session
        .sign(&Mechanism::Ecdsa, private_key, &digest)
        .context("C_Sign(CKM_ECDSA) failed")?;

    println!("digest      : {}", hex(&digest));
    println!("signature   : {} ({} bytes)", hex(&signature), signature.len());

    // 6. Verify through the token, proving the signature is real rather than just bytes.
    session
        .verify(&Mechanism::Ecdsa, public_key, &digest, &signature)
        .context("C_Verify(CKM_ECDSA) failed -- signature did not round-trip")?;
    println!("verify      : ok");

    // 7. A tampered digest must be rejected. A spike that only tests the happy path
    //    cannot tell a working signature from a stubbed one.
    let mut tampered = digest.to_vec();
    tampered[0] ^= 0xFF;
    match session.verify(&Mechanism::Ecdsa, public_key, &tampered, &signature) {
        Err(_) => println!("negative    : ok (tampered digest rejected)"),
        Ok(()) => return Err(anyhow!("SECURITY: tampered digest verified successfully")),
    }

    // 8. Price a single session. This is the denominator for the M3 worker-pool curve:
    //    if one session does X signs/sec, N sessions should approach N*X until SoftHSM2's
    //    own locking or the CPU saturates. Deliberately sequential -- no concurrency yet.
    let iterations: usize = env_or("SPIKE_ITERATIONS", "2000").parse().unwrap_or(2000);
    if iterations > 0 {
        // Warm up so first-call lazy initialization inside the module is not measured.
        for _ in 0..100 {
            session.sign(&Mechanism::Ecdsa, private_key, &digest)?;
        }

        let start = std::time::Instant::now();
        for _ in 0..iterations {
            session.sign(&Mechanism::Ecdsa, private_key, &digest)?;
        }
        let elapsed = start.elapsed();

        let per_op = elapsed / iterations as u32;
        let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();
        println!("\n-- single-session ECDSA P-256 sign, sequential --");
        println!("iterations  : {iterations}");
        println!("elapsed     : {elapsed:.3?}");
        println!("per op      : {per_op:.3?}");
        println!("throughput  : {ops_per_sec:.0} signs/sec (1 session, 1 thread)");
    }

    // 9. Price the *naive* access pattern against the tuned one. plan.md 4.3 claims that
    //    calling C_FindObjects on every request is "a common and expensive mistake" and
    //    that the per-worker handle cache is "a large part of the speedup". That claim is
    //    load-bearing for the whole benchmark story, so measure it rather than assert it.
    if iterations > 0 {
        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let handle = find_one(&session, ObjectClass::PRIVATE_KEY, KEY_LABEL)?
                .ok_or_else(|| anyhow!("key vanished mid-loop"))?;
            session.sign(&Mechanism::Ecdsa, handle, &digest)?;
        }
        let elapsed = start.elapsed();
        println!("\n-- naive pattern: C_FindObjects on every request --");
        println!("per op      : {:.3?}", elapsed / iterations as u32);
        println!(
            "throughput  : {:.0} signs/sec (1 session, 1 thread)",
            iterations as f64 / elapsed.as_secs_f64()
        );
    }

    // 10. RSA-2048 for contrast. plan.md 7 wants this reported even though it is much
    //     slower; the asymmetry between ECDSA and RSA is a real part of the story.
    let rsa_iterations = (iterations / 10).max(1);
    if iterations > 0 {
        let (rsa_private, _rsa_public) = match find_key_pair(&session, RSA_KEY_LABEL)? {
            Some(pair) => pair,
            None => generate_rsa_key_pair(&session, RSA_KEY_LABEL)?,
        };
        let message = b"gRPC-low-latency M0 spike";
        for _ in 0..10 {
            session.sign(&Mechanism::Sha256RsaPkcs, rsa_private, message)?;
        }
        let start = std::time::Instant::now();
        for _ in 0..rsa_iterations {
            session.sign(&Mechanism::Sha256RsaPkcs, rsa_private, message)?;
        }
        let elapsed = start.elapsed();
        println!("\n-- RSA-2048 sign (SHA256-RSA-PKCS), handle cached --");
        println!("per op      : {:.3?}", elapsed / rsa_iterations as u32);
        println!(
            "throughput  : {:.0} signs/sec (1 session, 1 thread)",
            rsa_iterations as f64 / elapsed.as_secs_f64()
        );
    }

    // 11. Clean teardown, the same sequence the proxy will run on shutdown.
    session.logout().context("C_Logout failed")?;
    drop(session);

    println!("\nM0 exit criterion met: ECDSA P-256 signature produced and verified.");
    Ok(())
}

/// Look for an existing (private, public) pair sharing `label`.
fn find_key_pair(session: &Session, label: &str) -> Result<Option<(ObjectHandle, ObjectHandle)>> {
    let private = find_one(session, ObjectClass::PRIVATE_KEY, label)?;
    let public = find_one(session, ObjectClass::PUBLIC_KEY, label)?;
    match (private, public) {
        (Some(p), Some(q)) => Ok(Some((p, q))),
        _ => Ok(None),
    }
}

fn find_one(session: &Session, class: ObjectClass, label: &str) -> Result<Option<ObjectHandle>> {
    let template = [
        Attribute::Class(class),
        Attribute::Label(label.as_bytes().to_vec()),
    ];
    Ok(session
        .find_objects(&template)
        .context("C_FindObjects failed")?
        .into_iter()
        .next())
}

/// Generate a token-resident, non-extractable ECDSA P-256 key pair.
fn generate_ec_key_pair(session: &Session, label: &str) -> Result<(ObjectHandle, ObjectHandle)> {
    let public_template = [
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::KeyType(KeyType::EC),
        Attribute::Verify(true),
        Attribute::EcParams(SECP256R1_OID_DER.to_vec()),
        Attribute::Label(label.as_bytes().to_vec()),
    ];
    // Sensitive + !Extractable is the point of an HSM: the private key never leaves the token.
    let private_template = [
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Sign(true),
        Attribute::Label(label.as_bytes().to_vec()),
    ];

    let (public_key, private_key) = session
        .generate_key_pair(
            &Mechanism::EccKeyPairGen,
            &public_template,
            &private_template,
        )
        .context("C_GenerateKeyPair(CKM_EC_KEY_PAIR_GEN) failed")?;

    Ok((private_key, public_key))
}

/// Generate a token-resident RSA-2048 key pair.
fn generate_rsa_key_pair(session: &Session, label: &str) -> Result<(ObjectHandle, ObjectHandle)> {
    let public_template = [
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::KeyType(KeyType::RSA),
        Attribute::Verify(true),
        Attribute::Encrypt(true),
        Attribute::ModulusBits(2048.into()),
        Attribute::PublicExponent(vec![0x01, 0x00, 0x01]),
        Attribute::Label(label.as_bytes().to_vec()),
    ];
    let private_template = [
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Sign(true),
        Attribute::Decrypt(true),
        Attribute::Label(label.as_bytes().to_vec()),
    ];

    let (public_key, private_key) = session
        .generate_key_pair(
            &Mechanism::RsaPkcsKeyPairGen,
            &public_template,
            &private_template,
        )
        .context("C_GenerateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN) failed")?;

    Ok((private_key, public_key))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
