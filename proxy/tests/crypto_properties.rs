//! Property tests for the signing and verification paths (plan.md §8).
//!
//! The crypto layer has more branches than it looks like. A caller may send a message or
//! a pre-computed digest; ECDSA wants a bare digest while `CKM_SHA256_RSA_PKCS` wants the
//! message; a pre-hashed RSA request has to be wrapped in a DER `DigestInfo` by hand; and
//! verification runs through `ring` for message input but RustCrypto's `p256` for digest
//! input, because `ring` exposes no prehash entry point.
//!
//! That is six sign paths and several verify paths, and the invariant across all of them
//! is the same: **whatever the token signed, in-process verification must accept — and
//! the two input forms must agree with each other.** Example-based tests check a handful
//! of payloads; these check hundreds, including the empty message and sizes that straddle
//! block boundaries.

mod common;

use grpc_low_latency_proxy::crypto::{
    prepare, public_key_to_spki_der, verify_public, SigningInput,
};
use grpc_low_latency_proxy::pkcs11::{find_object_pair, open_token};
use proptest::prelude::*;
use sha2::{Digest, Sha256};

/// Mechanism numbers from `hsm.v1.SignatureMechanism`.
const ECDSA_SHA256: i32 = 1;
const RSA_PKCS_SHA256: i32 = 2;
const RSA_PSS_SHA256: i32 = 3;

struct Fixture {
    _token: common::TestToken,
    _pkcs11: cryptoki::context::Pkcs11,
    /// Behind a mutex because a PKCS#11 session permits **one active operation at a
    /// time**, and the test harness runs these properties on parallel threads. Sharing
    /// the session unguarded produces `CKR_OPERATION_ACTIVE` as one thread's `C_SignInit`
    /// lands inside another's operation.
    ///
    /// `cryptoki::Session` is `Send` but deliberately not `Sync`, which is the API saying
    /// exactly this. `Mutex<Session>` is the sound way to share it; an `unsafe impl Sync`
    /// would compile and then fail at runtime, which is how this was first written.
    session: std::sync::Mutex<cryptoki::session::Session>,
}

impl Fixture {
    fn new() -> Option<Self> {
        let token = common::TestToken::new()?;
        let (pkcs11, _slot, session) = open_token(&token.config).ok()?;
        Some(Self {
            _token: token,
            _pkcs11: pkcs11,
            session: std::sync::Mutex::new(session),
        })
    }

    /// Sign through the token exactly as the proxy would, then verify in-process.
    ///
    /// Returns `None` when the key is missing, so a fixture problem is distinguishable
    /// from a property failure.
    fn round_trip(&self, key_label: &str, mechanism: i32, input: SigningInput) -> Option<bool> {
        let session = self.lock();
        let (private, public) = find_object_pair(&session, key_label).ok()??;

        // `prepare` decides the mechanism and shapes the payload; the same call the
        // handler makes, so the test exercises the real decision rather than a copy.
        let prepared = prepare(mechanism, clone_input(&input)).ok()?;
        let signature = session
            .sign(&prepared.algorithm.mechanism(), private, &prepared.payload)
            .ok()?;

        let (spki, _kind) = public_key_to_spki_der(&session, public).ok()?;
        verify_public(&spki, mechanism, &input, &signature).ok()
    }
}

impl Fixture {
    /// Exclusive access to the session for the duration of one operation.
    fn lock(&self) -> std::sync::MutexGuard<'_, cryptoki::session::Session> {
        self.session.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn clone_input(input: &SigningInput) -> SigningInput {
    match input {
        SigningInput::Message(m) => SigningInput::Message(m.clone()),
        SigningInput::Digest(d) => SigningInput::Digest(d.clone()),
    }
}

/// One shared fixture: `C_Initialize` is process-global, so a fixture per generated case
/// would both crash and take far longer than the property run itself.
fn fixture() -> Option<&'static Fixture> {
    use std::sync::OnceLock;
    static FIXTURE: OnceLock<Option<Fixture>> = OnceLock::new();
    FIXTURE.get_or_init(Fixture::new).as_ref()
}

macro_rules! skip_without_token {
    () => {
        match fixture() {
            Some(f) => f,
            None => {
                eprintln!("SKIPPED: SoftHSM2 not available");
                return Ok(());
            }
        }
    };
}

proptest! {
    // Each case is a real token signature, so keep the count modest enough to stay fast.
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// ECDSA: whatever the token signs over a message, in-process verification accepts.
    #[test]
    fn ecdsa_message_round_trips(payload in prop::collection::vec(any::<u8>(), 0..4096)) {
        let f = skip_without_token!();
        let ok = f.round_trip("demo-ec-p256", ECDSA_SHA256, SigningInput::Message(payload.clone()));
        prop_assert_eq!(ok, Some(true), "ECDSA message round-trip failed for {} bytes", payload.len());
    }

    /// ECDSA with a pre-computed digest. This is the path that falls back to `p256`,
    /// because `ring` has no prehash entry point -- a different implementation verifying
    /// the same signature.
    #[test]
    fn ecdsa_digest_round_trips(payload in prop::collection::vec(any::<u8>(), 0..4096)) {
        let f = skip_without_token!();
        let digest = Sha256::digest(&payload).to_vec();
        let ok = f.round_trip("demo-ec-p256", ECDSA_SHA256, SigningInput::Digest(digest));
        prop_assert_eq!(ok, Some(true), "ECDSA digest round-trip failed for {} bytes", payload.len());
    }

    /// The two ECDSA input forms must agree. A signature produced from the message form
    /// must verify when the caller supplies only the digest, and vice versa -- otherwise
    /// pre-hashing silently changes the meaning of a request.
    #[test]
    fn ecdsa_input_forms_agree(payload in prop::collection::vec(any::<u8>(), 0..2048)) {
        let f = skip_without_token!();
        let digest = Sha256::digest(&payload).to_vec();

        let session = f.lock();
        let (private, public) = match find_object_pair(&session, "demo-ec-p256") {
            Ok(Some(pair)) => pair,
            _ => return Ok(()),
        };
        let prepared = prepare(ECDSA_SHA256, SigningInput::Message(payload.clone())).unwrap();
        let signature = session
            .sign(&prepared.algorithm.mechanism(), private, &prepared.payload)
            .unwrap();
        let (spki, _) = public_key_to_spki_der(&session, public).unwrap();

        let via_message = verify_public(&spki, ECDSA_SHA256, &SigningInput::Message(payload), &signature).unwrap();
        let via_digest  = verify_public(&spki, ECDSA_SHA256, &SigningInput::Digest(digest), &signature).unwrap();
        prop_assert!(via_message, "message-form verification rejected a valid signature");
        prop_assert!(via_digest, "digest-form verification rejected the same signature");
    }

    /// RSA PKCS#1 v1.5 over a message: the token hashes.
    #[test]
    fn rsa_pkcs1_message_round_trips(payload in prop::collection::vec(any::<u8>(), 0..2048)) {
        let f = skip_without_token!();
        let ok = f.round_trip("demo-rsa-2048", RSA_PKCS_SHA256, SigningInput::Message(payload.clone()));
        prop_assert_eq!(ok, Some(true), "RSA PKCS1 message round-trip failed for {} bytes", payload.len());
    }

    /// RSA PKCS#1 v1.5 over a digest: this is the hand-rolled `DigestInfo` path, where a
    /// wrong prefix byte would produce a signature that verifies nowhere.
    #[test]
    fn rsa_pkcs1_digest_round_trips(payload in prop::collection::vec(any::<u8>(), 0..2048)) {
        let f = skip_without_token!();
        let digest = Sha256::digest(&payload).to_vec();
        let ok = f.round_trip("demo-rsa-2048", RSA_PKCS_SHA256, SigningInput::Digest(digest));
        prop_assert_eq!(ok, Some(true), "RSA PKCS1 digest round-trip failed for {} bytes", payload.len());
    }

    /// PKCS#1 v1.5 is deterministic, so a signature over the message and one over the
    /// digest must be *byte-identical*. That is a far stronger check than both verifying:
    /// it proves the DigestInfo we build is exactly what the token builds internally.
    #[test]
    fn rsa_pkcs1_both_forms_produce_identical_signatures(
        payload in prop::collection::vec(any::<u8>(), 0..1024)
    ) {
        let f = skip_without_token!();
        let session = f.lock();
        let (private, _public) = match find_object_pair(&session, "demo-rsa-2048") {
            Ok(Some(pair)) => pair,
            _ => return Ok(()),
        };

        let from_message = {
            let p = prepare(RSA_PKCS_SHA256, SigningInput::Message(payload.clone())).unwrap();
            session.sign(&p.algorithm.mechanism(), private, &p.payload).unwrap()
        };
        let from_digest = {
            let digest = Sha256::digest(&payload).to_vec();
            let p = prepare(RSA_PKCS_SHA256, SigningInput::Digest(digest)).unwrap();
            session.sign(&p.algorithm.mechanism(), private, &p.payload).unwrap()
        };

        prop_assert_eq!(from_message, from_digest,
            "PKCS#1 v1.5 is deterministic: the DigestInfo path must match the token's own");
    }

    /// RSA-PSS over a message. PSS is randomised, so only verification can check it.
    #[test]
    fn rsa_pss_message_round_trips(payload in prop::collection::vec(any::<u8>(), 0..2048)) {
        let f = skip_without_token!();
        let ok = f.round_trip("demo-rsa-2048", RSA_PSS_SHA256, SigningInput::Message(payload.clone()));
        prop_assert_eq!(ok, Some(true), "RSA-PSS message round-trip failed for {} bytes", payload.len());
    }

    /// A signature must not verify against different data. Without this the round-trip
    /// tests would all pass against a verifier that returned `true` unconditionally.
    #[test]
    fn signatures_do_not_verify_against_other_data(
        a in prop::collection::vec(any::<u8>(), 1..512),
        b in prop::collection::vec(any::<u8>(), 1..512),
    ) {
        prop_assume!(a != b);
        let f = skip_without_token!();

        let session = f.lock();
        let (private, public) = match find_object_pair(&session, "demo-ec-p256") {
            Ok(Some(pair)) => pair,
            _ => return Ok(()),
        };
        let p = prepare(ECDSA_SHA256, SigningInput::Message(a)).unwrap();
        let signature = session.sign(&p.algorithm.mechanism(), private, &p.payload).unwrap();
        let (spki, _) = public_key_to_spki_der(&session, public).unwrap();

        let accepted = verify_public(&spki, ECDSA_SHA256, &SigningInput::Message(b), &signature).unwrap();
        prop_assert!(!accepted, "a signature verified against data it was not made over");
    }
}
