//! M2 service implementation: one PKCS#11 session behind a mutex.
//!
//! This is deliberately the slow, naive design. Every request serializes on a single
//! session, and each blocking `C_Sign` is executed while holding the lock on a Tokio
//! worker thread, which stalls that thread for the duration. Both of those are exactly
//! what `plan.md` M3 replaces with the dedicated worker pool.
//!
//! It exists to produce an honest "single session" datapoint measured through the real
//! gRPC stack, so the M3 improvement is compared against something real rather than
//! against a number nobody ran.

use anyhow::Result;
use cryptoki::context::Pkcs11;
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{ObjectClass, ObjectHandle};
use cryptoki::session::Session;
use rand::RngCore;
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};

use crate::crypto::{self, SigningInput};
use crate::pkcs11::{find_object, open_token, TokenConfig};
use crate::proto::v1::{
    hsm_service_server::HsmService, signing_input, CipherMechanism, DecryptRequest,
    DecryptResponse, EncryptRequest, EncryptResponse, GetPublicKeyRequest, GetPublicKeyResponse,
    SignRequest, SignResponse, VerifyRequest, VerifyResponse,
};

/// AES-GCM parameters. 96-bit IVs are the standard choice and the fast path in most
/// implementations; 128-bit tags are the maximum GCM offers.
const GCM_IV_LEN: usize = 12;
const GCM_TAG_BITS: u64 = 128;

pub struct SingleSessionService {
    /// Kept alive for the lifetime of the service: dropping the context finalizes the
    /// PKCS#11 library and invalidates every session derived from it.
    _pkcs11: Pkcs11,
    session: Mutex<Session>,
}

impl SingleSessionService {
    pub fn connect(config: &TokenConfig) -> Result<Self> {
        let (pkcs11, _slot, session) = open_token(config)?;
        Ok(Self {
            _pkcs11: pkcs11,
            session: Mutex::new(session),
        })
    }
}

// --- error mapping ------------------------------------------------------------------
//
// Callers need to tell "you sent me nonsense" apart from "the token broke", because the
// first is their bug and the second is ours. Anything unexpected becomes `internal`
// rather than leaking PKCS#11 return codes into the API surface.

fn invalid_argument(err: impl std::fmt::Display) -> Status {
    Status::invalid_argument(err.to_string())
}

fn key_not_found(label: &str) -> Status {
    Status::not_found(format!("no key labelled '{label}' on the token"))
}

fn hsm_failure(operation: &str, err: impl std::fmt::Display) -> Status {
    // Logged in full; the client gets the operation but not the module internals.
    tracing::error!(operation, error = %err, "HSM operation failed");
    Status::internal(format!("{operation} failed"))
}

/// Unpack the `oneof` into the internal representation, rejecting an empty request.
fn extract_input(input: Option<crate::proto::v1::SigningInput>) -> Result<SigningInput, Status> {
    let input = input
        .and_then(|i| i.input)
        .ok_or_else(|| Status::invalid_argument("input must be set to either message or digest"))?;

    Ok(match input {
        signing_input::Input::Message(message) => SigningInput::Message(message),
        signing_input::Input::Digest(digest) => SigningInput::Digest(digest),
    })
}

fn require_object(
    session: &Session,
    class: ObjectClass,
    label: &str,
) -> Result<ObjectHandle, Status> {
    find_object(session, class, label)
        .map_err(|e| hsm_failure("C_FindObjects", e))?
        .ok_or_else(|| key_not_found(label))
}

fn require_aes_gcm(mechanism: i32) -> Result<(), Status> {
    match CipherMechanism::try_from(mechanism) {
        Ok(CipherMechanism::AesGcm) => Ok(()),
        _ => Err(Status::invalid_argument(
            "only CIPHER_MECHANISM_AES_GCM is supported",
        )),
    }
}

#[tonic::async_trait]
impl HsmService for SingleSessionService {
    async fn sign(&self, request: Request<SignRequest>) -> Result<Response<SignResponse>, Status> {
        let request = request.into_inner();
        let input = extract_input(request.input)?;
        let prepared = crypto::prepare(request.mechanism, input).map_err(invalid_argument)?;

        // Blocking call under an async lock: the M2 datapoint, replaced in M3.
        let session = self.session.lock().await;
        let private_key = require_object(&session, ObjectClass::PRIVATE_KEY, &request.key_label)?;

        let signature = session
            .sign(
                &prepared.algorithm.mechanism(),
                private_key,
                &prepared.payload,
            )
            .map_err(|e| hsm_failure("C_Sign", e))?;

        Ok(Response::new(SignResponse {
            signature,
            key_label: request.key_label,
        }))
    }

    async fn verify(
        &self,
        request: Request<VerifyRequest>,
    ) -> Result<Response<VerifyResponse>, Status> {
        let request = request.into_inner();
        let input = extract_input(request.input)?;
        let prepared = crypto::prepare(request.mechanism, input).map_err(invalid_argument)?;

        let session = self.session.lock().await;
        let public_key = require_object(&session, ObjectClass::PUBLIC_KEY, &request.key_label)?;

        // A bad signature is a legitimate answer, not an error: the client asked a
        // yes/no question and deserves a yes/no reply. Only a broken token is a Status.
        let valid = match session.verify(
            &prepared.algorithm.mechanism(),
            public_key,
            &prepared.payload,
            &request.signature,
        ) {
            Ok(()) => true,
            Err(cryptoki::error::Error::Pkcs11(
                cryptoki::error::RvError::SignatureInvalid
                | cryptoki::error::RvError::SignatureLenRange,
                _,
            )) => false,
            Err(e) => return Err(hsm_failure("C_Verify", e)),
        };

        Ok(Response::new(VerifyResponse {
            valid,
            // M5 adds the public key cache; until then every verify hits the token.
            served_from_cache: false,
        }))
    }

    async fn encrypt(
        &self,
        request: Request<EncryptRequest>,
    ) -> Result<Response<EncryptResponse>, Status> {
        let request = request.into_inner();
        require_aes_gcm(request.mechanism)?;

        // A reused GCM IV is catastrophic -- it leaks the keystream and forges the MAC --
        // so the proxy generates one per request rather than trusting the caller.
        let mut iv = vec![0u8; GCM_IV_LEN];
        rand::thread_rng().fill_bytes(&mut iv);

        let session = self.session.lock().await;
        let key = require_object(&session, ObjectClass::SECRET_KEY, &request.key_label)?;

        let mut iv_for_params = iv.clone();
        let params = cryptoki::mechanism::aead::GcmParams::new(
            &mut iv_for_params,
            &request.associated_data,
            GCM_TAG_BITS.into(),
        )
        .map_err(invalid_argument)?;

        let ciphertext = session
            .encrypt(&Mechanism::AesGcm(params), key, &request.plaintext)
            .map_err(|e| hsm_failure("C_Encrypt", e))?;

        Ok(Response::new(EncryptResponse { ciphertext, iv }))
    }

    async fn decrypt(
        &self,
        request: Request<DecryptRequest>,
    ) -> Result<Response<DecryptResponse>, Status> {
        let request = request.into_inner();
        require_aes_gcm(request.mechanism)?;

        if request.iv.len() != GCM_IV_LEN {
            return Err(Status::invalid_argument(format!(
                "iv must be {GCM_IV_LEN} bytes, got {}",
                request.iv.len()
            )));
        }

        let session = self.session.lock().await;
        let key = require_object(&session, ObjectClass::SECRET_KEY, &request.key_label)?;

        let mut iv = request.iv.clone();
        let params = cryptoki::mechanism::aead::GcmParams::new(
            &mut iv,
            &request.associated_data,
            GCM_TAG_BITS.into(),
        )
        .map_err(invalid_argument)?;

        let plaintext = session
            .decrypt(&Mechanism::AesGcm(params), key, &request.ciphertext)
            .map_err(|e| {
                // Authentication failure is the client's problem, not a server fault.
                match e {
                    cryptoki::error::Error::Pkcs11(
                        cryptoki::error::RvError::EncryptedDataInvalid
                        | cryptoki::error::RvError::EncryptedDataLenRange,
                        _,
                    ) => Status::invalid_argument("ciphertext failed authentication"),
                    other => hsm_failure("C_Decrypt", other),
                }
            })?;

        Ok(Response::new(DecryptResponse { plaintext }))
    }

    async fn get_public_key(
        &self,
        request: Request<GetPublicKeyRequest>,
    ) -> Result<Response<GetPublicKeyResponse>, Status> {
        let request = request.into_inner();

        let session = self.session.lock().await;
        let public_key = require_object(&session, ObjectClass::PUBLIC_KEY, &request.key_label)?;

        let (spki_der, key_type) = crypto::public_key_to_spki_der(&session, public_key)
            .map_err(|e| hsm_failure("public key encoding", e))?;

        Ok(Response::new(GetPublicKeyResponse {
            spki_der,
            key_type,
            served_from_cache: false,
        }))
    }
}
