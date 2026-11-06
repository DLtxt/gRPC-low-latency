//! Transfer keys (M10) and release keys (M11) against a real SoftHSM token.
//!
//! The policies and the guards are unit-tested without a token. What only a token can
//! show is the part they rely on: that the marker survives provisioning, that the
//! workers refuse to blind-sign with a marked key whatever the caller sends, that a key
//! marked for one purpose will not sign the other's statements, and that a signature is
//! an ordinary ECDSA signature over the canonical bytes, which anyone holding the public
//! key can check without trusting the proxy.

mod common;

use std::time::Duration;

use cryptoki::object::{Attribute, ObjectClass};
use grpc_low_latency_proxy::crypto::SignAlgorithm;
use grpc_low_latency_proxy::pkcs11::provision::{
    ensure_ec_key, ensure_purpose_key, Provisioned, DEMO_EC_KEY, DEMO_RELEASE_KEY,
    DEMO_TRANSFER_KEY,
};
use grpc_low_latency_proxy::pkcs11::{
    find_object, open_token, purpose_of, JobRequest, JobResponse, Pool, PoolConfig, PoolError,
    Purpose,
};
use grpc_low_latency_proxy::release::Release;
use grpc_low_latency_proxy::transfer::Transfer;
use p256::pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256};

/// Each purpose-bound demo key, with its purpose.
const PURPOSE_KEYS: [(&str, Purpose); 2] = [
    (DEMO_TRANSFER_KEY, Purpose::Transfer),
    (DEMO_RELEASE_KEY, Purpose::Release),
];

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

fn release() -> Release {
    Release::new(
        DEMO_RELEASE_KEY,
        "gll-proxy",
        "1.4.0",
        "stable",
        Sha256::digest(b"gll-proxy 1.4.0 linux-amd64").into(),
    )
    .unwrap()
}

/// The digest of a valid statement for `purpose`, signed by its demo key.
fn statement_digest(purpose: Purpose) -> [u8; 32] {
    match purpose {
        Purpose::Transfer => transfer().digest(),
        Purpose::Release => release().digest(),
    }
}

fn sign_statement(purpose: Purpose, key_label: &str, digest: [u8; 32]) -> JobRequest {
    JobRequest::SignStatement {
        purpose,
        key_label: key_label.to_string(),
        digest,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn provisioned_keys_are_marked_for_their_purpose() {
    let _serial = common::serial_guard().await;
    let token = require_token!();
    let pool = Pool::start(token.config.clone(), config()).expect("pool starts");

    for (label, expected) in [
        (DEMO_TRANSFER_KEY, Some(Purpose::Transfer)),
        (DEMO_RELEASE_KEY, Some(Purpose::Release)),
        (DEMO_EC_KEY, None),
    ] {
        let described = pool
            .submit(JobRequest::DescribeKey {
                key_label: label.to_string(),
            })
            .await
            .expect("describe succeeds");
        assert!(
            matches!(described, JobResponse::KeyDescription { purpose } if purpose == expected),
            "{label}: {described:?}"
        );
    }

    pool.shutdown();
}

/// The heart of it: a purpose-bound key will not sign a digest it was handed, whatever
/// the digest is. This is the request a compromised caller would send.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn purpose_keys_refuse_to_sign_a_digest() {
    let _serial = common::serial_guard().await;
    let token = require_token!();
    let pool = Pool::start(token.config.clone(), config()).expect("pool starts");

    for (label, purpose) in PURPOSE_KEYS {
        // Including the digest of a perfectly valid statement: the refusal is about the
        // path the bytes took, not about what they hash to.
        for payload in [
            Sha256::digest(b"anything at all").to_vec(),
            statement_digest(purpose).to_vec(),
        ] {
            let refused = pool
                .submit(JobRequest::Sign {
                    key_label: label.to_string(),
                    algorithm: SignAlgorithm::Ecdsa,
                    payload,
                })
                .await;
            assert!(
                matches!(
                    refused,
                    Err(PoolError::PurposeBound { ref key_label, purpose: refused_for })
                        if key_label == label && refused_for == purpose
                ),
                "{label}: {refused:?}"
            );
        }

        // And the refusal holds on a worker whose handle cache is already warm.
        pool.submit(sign_statement(purpose, label, statement_digest(purpose)))
            .await
            .expect("its own statements sign");
        let refused = pool
            .submit(JobRequest::Sign {
                key_label: label.to_string(),
                algorithm: SignAlgorithm::Ecdsa,
                payload: Sha256::digest(b"after warm-up").to_vec(),
            })
            .await;
        assert!(
            matches!(refused, Err(PoolError::PurposeBound { .. })),
            "{label}: {refused:?}"
        );
    }

    pool.shutdown();
}

/// Marked for one purpose is marked for that purpose only: a release key does not sign
/// transfers, a transfer key does not sign releases, and an ordinary key signs neither.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keys_sign_only_their_own_purpose() {
    let _serial = common::serial_guard().await;
    let token = require_token!();
    let pool = Pool::start(token.config.clone(), config()).expect("pool starts");

    for (label, asked) in [
        (DEMO_RELEASE_KEY, Purpose::Transfer),
        (DEMO_TRANSFER_KEY, Purpose::Release),
        (DEMO_EC_KEY, Purpose::Transfer),
        (DEMO_EC_KEY, Purpose::Release),
    ] {
        let refused = pool
            .submit(sign_statement(asked, label, statement_digest(asked)))
            .await;
        assert!(
            matches!(
                refused,
                Err(PoolError::WrongPurpose { ref key_label, expected })
                    if key_label == label && expected == asked
            ),
            "{label} asked to sign a {}: {refused:?}",
            asked.as_str()
        );
    }

    pool.shutdown();
}

/// A transfer or release signature is plain ECDSA P-256 over SHA-256 of the canonical
/// bytes, so a verifier needs the public key and the bytes -- nothing from the proxy's
/// own code -- and any change to the statement breaks it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signatures_verify_over_the_canonical_bytes() {
    let _serial = common::serial_guard().await;
    let token = require_token!();
    let pool = Pool::start(token.config.clone(), config()).expect("pool starts");

    let transfer = transfer();
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

    let release = release();
    let swapped = Release::new(
        DEMO_RELEASE_KEY,
        release.artifact(),
        release.version(),
        release.channel(),
        Sha256::digest(b"something else entirely").into(),
    )
    .unwrap();
    let relabelled = Release::new(
        DEMO_RELEASE_KEY,
        release.artifact(),
        release.version(),
        "beta",
        release.sha256(),
    )
    .unwrap();

    let cases = [
        (
            DEMO_TRANSFER_KEY,
            Purpose::Transfer,
            transfer.digest(),
            transfer.encode(),
            vec![redirected.encode()],
        ),
        (
            DEMO_RELEASE_KEY,
            Purpose::Release,
            release.digest(),
            release.encode(),
            vec![swapped.encode(), relabelled.encode()],
        ),
    ];

    for (label, purpose, digest, canonical, altered) in cases {
        let signature = match pool
            .submit(sign_statement(purpose, label, digest))
            .await
            .expect("statement signs")
        {
            JobResponse::Signature(signature) => signature,
            other => panic!("expected a signature, got {other:?}"),
        };

        let spki = match pool
            .submit(JobRequest::GetPublicKey {
                key_label: label.to_string(),
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
            .verify(&canonical, &signature)
            .unwrap_or_else(|_| panic!("{label}: signature verifies over the canonical bytes"));
        // A different destination; a different file; the same file on another channel.
        for other in altered {
            assert!(verifier.verify(&other, &signature).is_err(), "{label}");
        }
    }

    pool.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn provisioning_is_idempotent_and_refuses_a_mismarked_key() {
    let _serial = common::serial_guard().await;
    let token = require_token!();
    let (_ctx, _slot, session) = open_token(&token.config).expect("token opens");

    for (label, purpose) in PURPOSE_KEYS {
        assert_eq!(
            ensure_purpose_key(&session, label, purpose).unwrap(),
            Provisioned::AlreadyPresent
        );
    }

    // An ordinary key under the label a purpose-bound key should have. Reporting it as
    // present would leave a blind signer where the policy expects a transfer key.
    ensure_ec_key(&session, "unmarked-transfer-key").unwrap();
    let error =
        ensure_purpose_key(&session, "unmarked-transfer-key", Purpose::Transfer).unwrap_err();
    assert!(
        format!("{error:#}").contains("not marked transfer-only"),
        "{error:#}"
    );

    // Nor is a key marked for the other purpose good enough.
    let error = ensure_purpose_key(&session, DEMO_TRANSFER_KEY, Purpose::Release).unwrap_err();
    assert!(
        format!("{error:#}").contains("not marked release-only"),
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

    for (label, purpose) in PURPOSE_KEYS {
        let key = find_object(&session, ObjectClass::PRIVATE_KEY, label)
            .unwrap()
            .expect("purpose key present");
        // Clearing it, or swapping it for the other purpose's marker.
        for id in [
            b"ordinary".to_vec(),
            purpose_swap(purpose).marker().to_vec(),
        ] {
            let rewritten = session.update_attributes(key, &[Attribute::Id(id)]);
            assert!(
                rewritten.is_err(),
                "the token let {label}'s marker be rewritten"
            );
        }
        assert_eq!(purpose_of(&session, key).unwrap(), Some(purpose));
    }

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

    for (label, _) in PURPOSE_KEYS {
        let key = find_object(&session, ObjectClass::PRIVATE_KEY, label)
            .unwrap()
            .expect("purpose key present");
        let twin_label = format!("unmarked-twin-of-{label}");
        assert!(
            session.copy_object(key, &twin(&twin_label)).is_err(),
            "the token copied {label}"
        );
        assert!(find_object(&session, ObjectClass::PRIVATE_KEY, &twin_label)
            .unwrap()
            .is_none());
    }

    let _ = session.logout();
}

fn purpose_swap(purpose: Purpose) -> Purpose {
    match purpose {
        Purpose::Transfer => Purpose::Release,
        Purpose::Release => Purpose::Transfer,
    }
}
