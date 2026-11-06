//! Transfer keys against a real SoftHSM token (M10).
//!
//! The policy and the guard are unit-tested without a token. What only a token can
//! show is the part they rely on: that the marker survives provisioning, that the
//! workers refuse to blind-sign with a marked key whatever the caller sends, and that a
//! transfer signature is an ordinary ECDSA signature over the canonical bytes, which
//! anyone holding the public key can check without trusting the proxy.

mod common;

use std::time::Duration;

use cryptoki::object::{Attribute, ObjectClass};
use grpc_low_latency_proxy::crypto::SignAlgorithm;
use grpc_low_latency_proxy::pkcs11::provision::{
    ensure_ec_key, ensure_transfer_key, Provisioned, DEMO_EC_KEY, DEMO_TRANSFER_KEY,
};
use grpc_low_latency_proxy::pkcs11::{
    find_object, is_transfer_only, open_token, JobRequest, JobResponse, Pool, PoolConfig, PoolError,
};
use grpc_low_latency_proxy::transfer::Transfer;
use p256::pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256};

fn config() -> PoolConfig {
    PoolConfig {
        workers: 2,
        queue_depth: 8,
        job_timeout: Duration::from_secs(5),
    }
}

fn transfer() -> Transfer {
    Transfer::new(
        DEMO_TRANSFER_KEY,
        "devnet",
        "ETH",
        18,
        "0xc01dc01dc01dc01dc01dc01dc01dc01dc01dc01d",
        1_500_000_000_000_000_000,
        1,
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn provisioned_transfer_key_is_marked() {
    let _serial = common::serial_guard().await;
    let token = require_token!();
    let pool = Pool::start(token.config.clone(), config()).expect("pool starts");

    for (label, expected) in [(DEMO_TRANSFER_KEY, true), (DEMO_EC_KEY, false)] {
        let described = pool
            .submit(JobRequest::DescribeKey {
                key_label: label.to_string(),
            })
            .await
            .expect("describe succeeds");
        assert!(
            matches!(described, JobResponse::KeyDescription { transfer_only } if transfer_only == expected),
            "{label}: {described:?}"
        );
    }

    pool.shutdown();
}

/// The heart of it: a transfer key will not sign a digest it was handed, whatever the
/// digest is. This is the request a compromised caller would send.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transfer_key_refuses_to_sign_a_digest() {
    let _serial = common::serial_guard().await;
    let token = require_token!();
    let pool = Pool::start(token.config.clone(), config()).expect("pool starts");

    // Including the digest of a perfectly valid transfer: the refusal is about the path
    // the bytes took, not about what they hash to.
    for payload in [
        Sha256::digest(b"anything at all").to_vec(),
        transfer().digest().to_vec(),
    ] {
        let refused = pool
            .submit(JobRequest::Sign {
                key_label: DEMO_TRANSFER_KEY.to_string(),
                algorithm: SignAlgorithm::Ecdsa,
                payload,
            })
            .await;
        assert!(
            matches!(refused, Err(PoolError::TransferOnly(ref label)) if label == DEMO_TRANSFER_KEY),
            "{refused:?}"
        );
    }

    // And the refusal holds on a worker whose handle cache is already warm.
    pool.submit(JobRequest::SignTransfer {
        key_label: DEMO_TRANSFER_KEY.to_string(),
        digest: transfer().digest(),
    })
    .await
    .expect("transfer signs");
    let refused = pool
        .submit(JobRequest::Sign {
            key_label: DEMO_TRANSFER_KEY.to_string(),
            algorithm: SignAlgorithm::Ecdsa,
            payload: Sha256::digest(b"after warm-up").to_vec(),
        })
        .await;
    assert!(
        matches!(refused, Err(PoolError::TransferOnly(_))),
        "{refused:?}"
    );

    pool.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ordinary_keys_do_not_sign_transfers() {
    let _serial = common::serial_guard().await;
    let token = require_token!();
    let pool = Pool::start(token.config.clone(), config()).expect("pool starts");

    let refused = pool
        .submit(JobRequest::SignTransfer {
            key_label: DEMO_EC_KEY.to_string(),
            digest: transfer().digest(),
        })
        .await;
    assert!(
        matches!(refused, Err(PoolError::NotTransferKey(_))),
        "{refused:?}"
    );

    pool.shutdown();
}

/// A transfer signature is plain ECDSA P-256 over SHA-256 of the canonical bytes, so a
/// verifier needs the public key and the bytes -- nothing from the proxy's own code.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transfer_signature_verifies_over_the_canonical_bytes() {
    let _serial = common::serial_guard().await;
    let token = require_token!();
    let pool = Pool::start(token.config.clone(), config()).expect("pool starts");

    let transfer = transfer();
    let signature = match pool
        .submit(JobRequest::SignTransfer {
            key_label: DEMO_TRANSFER_KEY.to_string(),
            digest: transfer.digest(),
        })
        .await
        .expect("transfer signs")
    {
        JobResponse::Signature(signature) => signature,
        other => panic!("expected a signature, got {other:?}"),
    };

    let spki = match pool
        .submit(JobRequest::GetPublicKey {
            key_label: DEMO_TRANSFER_KEY.to_string(),
        })
        .await
        .expect("public key")
    {
        JobResponse::PublicKey { spki_der, .. } => spki_der,
        other => panic!("expected a public key, got {other:?}"),
    };
    let key = p256::PublicKey::from_public_key_der(&spki).expect("P-256 SPKI");
    let point = p256::EncodedPoint::from(key);
    let verifier = ring::signature::UnparsedPublicKey::new(
        &ring::signature::ECDSA_P256_SHA256_FIXED,
        point.as_bytes(),
    );

    verifier
        .verify(&transfer.encode(), &signature)
        .expect("signature verifies over the canonical bytes");

    // Any change to the transfer -- here the destination -- breaks it.
    let redirected = Transfer::new(
        DEMO_TRANSFER_KEY,
        "devnet",
        "ETH",
        18,
        "0xbadbadbadbadbadbadbadbadbadbadbadbadbad0",
        transfer.amount(),
        transfer.nonce(),
    )
    .unwrap();
    assert!(verifier.verify(&redirected.encode(), &signature).is_err());

    pool.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn provisioning_is_idempotent_and_refuses_an_unmarked_key() {
    let _serial = common::serial_guard().await;
    let token = require_token!();
    let (_ctx, _slot, session) = open_token(&token.config).expect("token opens");

    assert_eq!(
        ensure_transfer_key(&session, DEMO_TRANSFER_KEY).unwrap(),
        Provisioned::AlreadyPresent
    );

    // An ordinary key under the label a transfer key should have. Reporting it as
    // present would leave a blind signer where the policy expects a transfer key.
    ensure_ec_key(&session, "unmarked-transfer-key").unwrap();
    let error = ensure_transfer_key(&session, "unmarked-transfer-key").unwrap_err();
    assert!(
        format!("{error:#}").contains("not marked transfer-only"),
        "{error:#}"
    );

    let _ = session.logout();
}

/// The marker is only as good as its permanence. `CKA_MODIFIABLE=false` should make the
/// token refuse to clear it; if a token ever accepted the change, the worker would still
/// see the result, so check both that the change is refused and that the key reads as
/// marked afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_marker_cannot_be_cleared() {
    let _serial = common::serial_guard().await;
    let token = require_token!();
    let (_ctx, _slot, session) = open_token(&token.config).expect("token opens");

    // The control: the same change on an ordinary key goes through, so a refusal below
    // is CKA_MODIFIABLE at work rather than the token refusing CKA_ID changes in general.
    ensure_ec_key(&session, "control-key").unwrap();
    let control = find_object(&session, ObjectClass::PRIVATE_KEY, "control-key")
        .unwrap()
        .expect("control key present");
    session
        .update_attributes(control, &[Attribute::Id(b"anything".to_vec())])
        .expect("an ordinary key's CKA_ID can be changed");

    let key = find_object(&session, ObjectClass::PRIVATE_KEY, DEMO_TRANSFER_KEY)
        .unwrap()
        .expect("transfer key present");
    let cleared = session.update_attributes(key, &[Attribute::Id(b"ordinary".to_vec())]);
    assert!(cleared.is_err(), "the token let the marker be rewritten");
    assert!(is_transfer_only(&session, key).unwrap());

    let _ = session.logout();
}

/// Nor shed by copying. Without `CKA_COPYABLE=false`, anyone with the PIN could copy the
/// key under a new label and a new `CKA_ID`, and the proxy would serve the copy through
/// the generic `Sign` like any other key.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_key_cannot_be_copied_without_its_marker() {
    let _serial = common::serial_guard().await;
    let token = require_token!();
    let (_ctx, _slot, session) = open_token(&token.config).expect("token opens");

    let twin = |label: &str| {
        vec![
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Id(b"ordinary".to_vec()),
        ]
    };

    ensure_ec_key(&session, "copy-control").unwrap();
    let control = find_object(&session, ObjectClass::PRIVATE_KEY, "copy-control")
        .unwrap()
        .expect("control key present");
    let copied = session
        .copy_object(control, &twin("copy-control-twin"))
        .expect("an ordinary key can be copied");
    session.destroy_object(copied).unwrap();

    let key = find_object(&session, ObjectClass::PRIVATE_KEY, DEMO_TRANSFER_KEY)
        .unwrap()
        .expect("transfer key present");
    assert!(
        session.copy_object(key, &twin("unmarked-twin")).is_err(),
        "the token copied a transfer key"
    );
    assert!(
        find_object(&session, ObjectClass::PRIVATE_KEY, "unmarked-twin")
            .unwrap()
            .is_none()
    );

    let _ = session.logout();
}
