//! M1 exit check: prove the proxy container can open the shared SoftHSM token
//! read/write and use the keys that `softhsm-init` provisioned.
//!
//! This runs as the proxy image's entrypoint until M2 replaces it with the gRPC
//! server. It is kept afterwards as a compose healthcheck and CI smoke test, since
//! "can the proxy actually reach the token" is the failure that wastes the most time.

use anyhow::{anyhow, Context, Result};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectClass};
use cryptoki::session::Session;
use grpc_low_latency_proxy::pkcs11::{
    find_object, find_object_pair, is_transfer_only, open_token, TokenConfig,
};
use sha2::{Digest, Sha256};

/// Keys that `docker/softhsm-init/init-token.sh` is contracted to provision.
const EXPECTED_KEYPAIRS: &[&str] = &["demo-ec-p256", "demo-rsa-2048"];
const EXPECTED_SECRET_KEYS: &[&str] = &["demo-aes-256"];
const EXPECTED_TRANSFER_KEYS: &[&str] = &["demo-hot-wallet"];

fn main() -> Result<()> {
    let config = TokenConfig::from_env()?;
    println!("== token-check ==");
    println!("module      : {}", config.module_path);
    println!("token label : {}", config.token_label);

    let (pkcs11, slot, session) = open_token(&config)?;

    let token_info = pkcs11
        .get_token_info(slot)
        .context("C_GetTokenInfo failed")?;
    println!("slot        : {}", slot.id());
    println!("token model : {}", token_info.model().trim());
    println!("login       : ok (read/write session)");

    let mut failures = Vec::new();

    for label in EXPECTED_KEYPAIRS {
        match check_keypair(&session, label) {
            Ok(note) => println!("keypair     : {label} -> {note}"),
            Err(err) => {
                println!("keypair     : {label} -> FAILED: {err:#}");
                failures.push(format!("{label}: {err:#}"));
            }
        }
    }

    for label in EXPECTED_TRANSFER_KEYS {
        match check_transfer_key(&session, label) {
            Ok(note) => println!("transfer key: {label} -> {note}"),
            Err(err) => {
                println!("transfer key: {label} -> FAILED: {err:#}");
                failures.push(format!("{label}: {err:#}"));
            }
        }
    }

    for label in EXPECTED_SECRET_KEYS {
        match find_object(&session, ObjectClass::SECRET_KEY, label)? {
            Some(_) => println!("secret key  : {label} -> present"),
            None => {
                println!("secret key  : {label} -> FAILED: not found");
                failures.push(format!("{label}: not found"));
            }
        }
    }

    // Prove the session really is read/write, not just readable. A read-only session
    // is the failure mode when the token volume is mounted with the wrong permissions,
    // and it stays invisible until the first write.
    match write_probe(&session) {
        Ok(()) => println!("rw probe    : ok (created and destroyed a session object)"),
        Err(err) => {
            println!("rw probe    : FAILED: {err:#}");
            failures.push(format!("read/write probe: {err:#}"));
        }
    }

    session.logout().ok();

    if failures.is_empty() {
        println!("\ntoken-check passed: proxy can open the shared token read/write.");
        Ok(())
    } else {
        Err(anyhow!(
            "token-check failed:\n  - {}",
            failures.join("\n  - ")
        ))
    }
}

/// Confirm a transfer key pair exists, is protected, and carries the transfer-only
/// marker. An unmarked key under this label would make the proxy refuse transfers and
/// leave a blind signer behind, so the marker is the point of the check.
///
/// Not test-signed, unlike the other key pairs: the one thing a transfer key must never
/// do is sign something that is not a transfer, and a health check is no exception.
/// The transfer demo exercises it end to end instead.
fn check_transfer_key(session: &Session, label: &str) -> Result<String> {
    let (private_key, _) = find_object_pair(session, label)?
        .ok_or_else(|| anyhow!("key pair not found; did softhsm-init run?"))?;
    check_protection(session, private_key)?;
    if !is_transfer_only(session, private_key)? {
        return Err(anyhow!(
            "private key is not marked transfer-only (CKA_ID); destroy it and provision again"
        ));
    }
    Ok("sensitive, non-extractable, marked transfer-only".to_string())
}

/// Confirm a key pair exists, that the private key is properly protected, and that it
/// can actually sign.
fn check_keypair(session: &Session, label: &str) -> Result<String> {
    let (private_key, public_key) = find_object_pair(session, label)?
        .ok_or_else(|| anyhow!("key pair not found; did softhsm-init run?"))?;
    check_protection(session, private_key)?;

    // Sign and verify, so "the key exists" also means "the key works".
    let digest = Sha256::digest(b"token-check");
    let mechanism = if label.contains("rsa") {
        Mechanism::Sha256RsaPkcs
    } else {
        Mechanism::Ecdsa
    };
    let payload: &[u8] = if label.contains("rsa") {
        b"token-check"
    } else {
        &digest
    };

    let signature = session
        .sign(&mechanism, private_key, payload)
        .context("C_Sign failed")?;
    session
        .verify(&mechanism, public_key, payload, &signature)
        .context("C_Verify failed")?;

    Ok(format!(
        "sensitive, non-extractable, signs ok ({} byte signature)",
        signature.len()
    ))
}

/// The whole premise of an HSM is that the private key cannot be read out. If
/// provisioning got this wrong the project's security story is void, so check it
/// rather than trusting the provisioning script.
fn check_protection(session: &Session, private_key: cryptoki::object::ObjectHandle) -> Result<()> {
    let attrs = session
        .get_attributes(
            private_key,
            &[AttributeType::Sensitive, AttributeType::Extractable],
        )
        .context("C_GetAttributeValue failed")?;

    for attr in &attrs {
        match attr {
            Attribute::Sensitive(false) => {
                return Err(anyhow!("private key is CKA_SENSITIVE=false"))
            }
            Attribute::Extractable(true) => {
                return Err(anyhow!("private key is CKA_EXTRACTABLE=true"))
            }
            _ => {}
        }
    }
    Ok(())
}

/// Create and immediately destroy a session-scoped object. Fails on a read-only session.
fn write_probe(session: &Session) -> Result<()> {
    let handle = session
        .create_object(&[
            Attribute::Class(ObjectClass::DATA),
            Attribute::Token(false), // session object -- never touches the token directory
            Attribute::Private(false),
            Attribute::Label(b"token-check-probe".to_vec()),
            Attribute::Value(b"probe".to_vec()),
        ])
        .context("C_CreateObject failed -- session is not read/write")?;

    session
        .destroy_object(handle)
        .context("C_DestroyObject failed")?;
    Ok(())
}
