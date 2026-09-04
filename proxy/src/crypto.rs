//! Translating the wire protocol's mechanisms and key material into PKCS#11 terms.

use anyhow::{anyhow, bail, Context, Result};
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsPssParams};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, ObjectHandle};
use cryptoki::session::Session;
use sha2::{Digest, Sha256};

/// Length of a SHA-256 digest.
pub const SHA256_LEN: usize = 32;

/// DER `DigestInfo` prefix for SHA-256, per RFC 8017 section 9.2.
///
/// PKCS#11's `CKM_SHA256_RSA_PKCS` hashes the message itself, so it cannot accept a
/// digest a caller already computed. To honour a pre-hashed request we wrap the digest
/// in `DigestInfo` ourselves and use plain `CKM_RSA_PKCS`, which is what the combined
/// mechanism does internally anyway.
const SHA256_DIGEST_INFO_PREFIX: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// What the caller supplied to sign or verify.
pub enum SigningInput {
    /// The raw message; the proxy or the token hashes it.
    Message(Vec<u8>),
    /// A digest the caller computed. Keeps large payloads off the wire.
    Digest(Vec<u8>),
}

/// Which PKCS#11 mechanism to invoke.
///
/// This is a plain enum rather than a `cryptoki::Mechanism` on purpose. `Mechanism`
/// carries raw pointers for its parameterized variants, so it is `!Send` and cannot be
/// held across an `.await` or sent down the M3 worker channel. Deciding *which*
/// mechanism is Send-safe; building it is not, so construction is deferred to the
/// thread that will actually call into the module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignAlgorithm {
    /// CKM_ECDSA over a bare digest.
    Ecdsa,
    /// CKM_RSA_PKCS over a caller-supplied DigestInfo.
    RsaPkcs,
    /// CKM_SHA256_RSA_PKCS: the token hashes.
    Sha256RsaPkcs,
    /// CKM_RSA_PKCS_PSS over a bare digest.
    RsaPkcsPss,
    /// CKM_SHA256_RSA_PKCS_PSS: the token hashes.
    Sha256RsaPkcsPss,
}

impl SignAlgorithm {
    /// Build the `cryptoki` mechanism. Call this on the thread that owns the session.
    pub fn mechanism(self) -> Mechanism<'static> {
        match self {
            SignAlgorithm::Ecdsa => Mechanism::Ecdsa,
            SignAlgorithm::RsaPkcs => Mechanism::RsaPkcs,
            SignAlgorithm::Sha256RsaPkcs => Mechanism::Sha256RsaPkcs,
            SignAlgorithm::RsaPkcsPss => Mechanism::RsaPkcsPss(pss_params()),
            SignAlgorithm::Sha256RsaPkcsPss => Mechanism::Sha256RsaPkcsPss(pss_params()),
        }
    }
}

/// An algorithm paired with the exact bytes to hand `C_Sign`.
///
/// The two travel together because they are not independent: whether the payload is a
/// message, a bare digest, or a `DigestInfo` wrapper depends on which mechanism the
/// pre-hashing forced us into.
pub struct PreparedOperation {
    pub algorithm: SignAlgorithm,
    pub payload: Vec<u8>,
}

fn pss_params() -> PkcsPssParams {
    PkcsPssParams {
        hash_alg: MechanismType::SHA256,
        mgf: PkcsMgfType::MGF1_SHA256,
        // Salt length equal to the hash length is the standard choice.
        s_len: (SHA256_LEN as u64).into(),
    }
}

/// Resolve a wire mechanism plus input into something PKCS#11 can execute.
pub fn prepare(mechanism: i32, input: SigningInput) -> Result<PreparedOperation> {
    use crate::proto::v1::SignatureMechanism;

    let mechanism = SignatureMechanism::try_from(mechanism)
        .map_err(|_| anyhow!("unknown signature mechanism {mechanism}"))?;

    Ok(match (mechanism, input) {
        (SignatureMechanism::Unspecified, _) => {
            bail!("signature mechanism must be specified")
        }

        // ECDSA: CKM_ECDSA always signs a bare digest, so hash here if needed.
        (SignatureMechanism::EcdsaSha256, SigningInput::Message(message)) => PreparedOperation {
            algorithm: SignAlgorithm::Ecdsa,
            payload: Sha256::digest(&message).to_vec(),
        },
        (SignatureMechanism::EcdsaSha256, SigningInput::Digest(digest)) => {
            check_digest_len(&digest)?;
            PreparedOperation {
                algorithm: SignAlgorithm::Ecdsa,
                payload: digest,
            }
        }

        // RSA PKCS#1 v1.5: let the token hash when we have the message, otherwise
        // wrap the caller's digest in DigestInfo and use the raw mechanism.
        (SignatureMechanism::RsaPkcsSha256, SigningInput::Message(message)) => PreparedOperation {
            algorithm: SignAlgorithm::Sha256RsaPkcs,
            payload: message,
        },
        (SignatureMechanism::RsaPkcsSha256, SigningInput::Digest(digest)) => {
            check_digest_len(&digest)?;
            let mut payload = SHA256_DIGEST_INFO_PREFIX.to_vec();
            payload.extend_from_slice(&digest);
            PreparedOperation {
                algorithm: SignAlgorithm::RsaPkcs,
                payload,
            }
        }

        // PSS encodes the digest itself, so the bare digest goes to CKM_RSA_PKCS_PSS.
        (SignatureMechanism::RsaPssSha256, SigningInput::Message(message)) => PreparedOperation {
            algorithm: SignAlgorithm::Sha256RsaPkcsPss,
            payload: message,
        },
        (SignatureMechanism::RsaPssSha256, SigningInput::Digest(digest)) => {
            check_digest_len(&digest)?;
            PreparedOperation {
                algorithm: SignAlgorithm::RsaPkcsPss,
                payload: digest,
            }
        }
    })
}

fn check_digest_len(digest: &[u8]) -> Result<()> {
    if digest.len() != SHA256_LEN {
        bail!(
            "expected a {SHA256_LEN}-byte SHA-256 digest, got {} bytes",
            digest.len()
        );
    }
    Ok(())
}

/// Read a public key off the token and re-encode it as DER `SubjectPublicKeyInfo`.
///
/// PKCS#11 exposes public keys as raw components -- an EC point, or an RSA modulus and
/// exponent -- but callers want something they can feed to a standard library, and the
/// M5 cache stores SPKI so `Verify` can run in-process.
///
/// Returns the DER bytes and the key type ("EC" or "RSA").
pub fn public_key_to_spki_der(
    session: &Session,
    public_key: ObjectHandle,
) -> Result<(Vec<u8>, String)> {
    let key_type = session
        .get_attributes(public_key, &[AttributeType::KeyType])
        .context("C_GetAttributeValue(CKA_KEY_TYPE) failed")?;

    match key_type.first() {
        Some(Attribute::KeyType(t)) if *t == cryptoki::object::KeyType::EC => {
            ec_spki(session, public_key).map(|der| (der, "EC".to_string()))
        }
        Some(Attribute::KeyType(t)) if *t == cryptoki::object::KeyType::RSA => {
            rsa_spki(session, public_key).map(|der| (der, "RSA".to_string()))
        }
        other => bail!("unsupported public key type: {other:?}"),
    }
}

/// Pull the uncompressed SEC1 point out of a DER SubjectPublicKeyInfo.
///
/// `ring` takes a raw point rather than SPKI, so the cached DER has to be unwrapped.
pub fn sec1_point_from_spki(spki_der: &[u8]) -> Result<Vec<u8>> {
    use p256::pkcs8::DecodePublicKey;
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let key = p256::PublicKey::from_public_key_der(spki_der)
        .context("not a valid P-256 SPKI")?;
    Ok(key.to_encoded_point(false).as_bytes().to_vec())
}

fn ec_spki(session: &Session, public_key: ObjectHandle) -> Result<Vec<u8>> {
    use p256::pkcs8::EncodePublicKey;

    let attrs = session
        .get_attributes(public_key, &[AttributeType::EcPoint])
        .context("C_GetAttributeValue(CKA_EC_POINT) failed")?;

    let ec_point = attrs
        .into_iter()
        .find_map(|attr| match attr {
            Attribute::EcPoint(point) => Some(point),
            _ => None,
        })
        .ok_or_else(|| anyhow!("public key has no CKA_EC_POINT"))?;

    let sec1 = unwrap_der_octet_string(&ec_point)?;

    let key = p256::PublicKey::from_sec1_bytes(sec1)
        .map_err(|e| anyhow!("CKA_EC_POINT is not a valid P-256 point: {e}"))?;

    Ok(key
        .to_public_key_der()
        .context("failed to DER-encode the EC public key")?
        .as_bytes()
        .to_vec())
}

fn rsa_spki(session: &Session, public_key: ObjectHandle) -> Result<Vec<u8>> {
    use rsa::pkcs8::EncodePublicKey;
    use rsa::BigUint;

    let attrs = session
        .get_attributes(
            public_key,
            &[AttributeType::Modulus, AttributeType::PublicExponent],
        )
        .context("C_GetAttributeValue(CKA_MODULUS/CKA_PUBLIC_EXPONENT) failed")?;

    let mut modulus = None;
    let mut exponent = None;
    for attr in attrs {
        match attr {
            Attribute::Modulus(m) => modulus = Some(m),
            Attribute::PublicExponent(e) => exponent = Some(e),
            _ => {}
        }
    }

    let key = rsa::RsaPublicKey::new(
        BigUint::from_bytes_be(&modulus.ok_or_else(|| anyhow!("public key has no modulus"))?),
        BigUint::from_bytes_be(&exponent.ok_or_else(|| anyhow!("public key has no exponent"))?),
    )
    .context("token returned an invalid RSA public key")?;

    Ok(key
        .to_public_key_der()
        .context("failed to DER-encode the RSA public key")?
        .as_bytes()
        .to_vec())
}

/// `CKA_EC_POINT` is defined as a DER `OCTET STRING` wrapping the SEC1 point, but some
/// modules return the bare point. Accept both rather than depending on the module.
fn unwrap_der_octet_string(bytes: &[u8]) -> Result<&[u8]> {
    // A bare uncompressed SEC1 P-256 point is exactly 65 bytes starting with 0x04,
    // which collides with the OCTET STRING tag -- disambiguate on total length.
    if bytes.len() == 65 && bytes[0] == 0x04 {
        return Ok(bytes);
    }

    if bytes.first() != Some(&0x04) {
        bail!("CKA_EC_POINT is neither a DER OCTET STRING nor a SEC1 point");
    }

    // Short form: one length byte. Long form 0x81: one following length byte.
    let (len, offset) = match bytes.get(1) {
        Some(&n) if n < 0x80 => (n as usize, 2),
        Some(&0x81) => (
            *bytes.get(2).ok_or_else(|| anyhow!("truncated EC point"))? as usize,
            3,
        ),
        _ => bail!("unsupported CKA_EC_POINT length encoding"),
    };

    bytes
        .get(offset..offset + len)
        .ok_or_else(|| anyhow!("CKA_EC_POINT declares {len} bytes but the value is truncated"))
}

// --- in-process verification --------------------------------------------------------
//
// Verification needs only the public key, so once that key is cached there is no reason
// to cross into the token at all. This is the M5 win: not the HSM going faster, but the
// HSM leaving the path (plan.md 2).

impl PreparedOperation {
    /// The bare SHA-256 digest this operation is over.
    ///
    /// `prepare` shapes the payload for whichever PKCS#11 mechanism it selected -- a raw
    /// digest, a full message, or a DigestInfo wrapper -- so recovering the digest means
    /// undoing exactly that choice.
    pub fn verification_digest(&self) -> Result<Vec<u8>> {
        Ok(match self.algorithm {
            // Already a digest.
            SignAlgorithm::Ecdsa | SignAlgorithm::RsaPkcsPss => self.payload.clone(),

            // The token was going to hash it; do that here instead.
            SignAlgorithm::Sha256RsaPkcs | SignAlgorithm::Sha256RsaPkcsPss => {
                Sha256::digest(&self.payload).to_vec()
            }

            // A DigestInfo wrapper we built ourselves; strip it back off.
            SignAlgorithm::RsaPkcs => {
                let prefix = SHA256_DIGEST_INFO_PREFIX;
                if self.payload.len() != prefix.len() + SHA256_LEN
                    || !self.payload.starts_with(prefix)
                {
                    bail!("payload is not a SHA-256 DigestInfo");
                }
                self.payload[prefix.len()..].to_vec()
            }
        })
    }
}

/// Verify a signature in this process against a DER SubjectPublicKeyInfo.
///
/// Returns `Ok(false)` for a signature that simply does not check out, and `Err` only
/// when the request itself is malformed -- a caller must be able to tell "your signature
/// is wrong" from "your request is wrong".
///
/// ECDSA goes through `ring`, which carries P-256 assembly. Measured single-threaded on
/// an Apple M2: ring 80 us, the token's OpenSSL 142 us, RustCrypto's portable `p256`
/// 327 us. Choosing the portable implementation here made `Verify` slower than leaving
/// the work on the HSM, which defeated the entire point of caching the key.
pub fn verify_public(
    spki_der: &[u8],
    mechanism: i32,
    input: &SigningInput,
    signature: &[u8],
) -> Result<bool> {
    use crate::proto::v1::SignatureMechanism;

    let mechanism = SignatureMechanism::try_from(mechanism)
        .map_err(|_| anyhow!("unknown signature mechanism"))?;

    match (mechanism, input) {
        (SignatureMechanism::Unspecified, _) => bail!("signature mechanism must be specified"),

        // ring hashes the message itself, which is the fast path.
        (SignatureMechanism::EcdsaSha256, SigningInput::Message(message)) => {
            verify_ecdsa_ring(spki_der, message, signature)
        }

        // ring exposes no prehash entry point for ECDSA, so a caller that pre-hashed
        // pays for the portable implementation. Sending the message is faster here;
        // pre-hashing is the right trade only when the payload is large enough that
        // keeping it off the wire outweighs the slower verification.
        (SignatureMechanism::EcdsaSha256, SigningInput::Digest(digest)) => {
            check_digest_len(digest)?;
            verify_ecdsa_prehash(spki_der, digest, signature)
        }

        // RSA verification is a public-exponent operation and already cheap.
        (SignatureMechanism::RsaPkcsSha256, input) => {
            verify_rsa(spki_der, &digest_of(input)?, signature, false)
        }
        (SignatureMechanism::RsaPssSha256, input) => {
            verify_rsa(spki_der, &digest_of(input)?, signature, true)
        }
    }
}

fn digest_of(input: &SigningInput) -> Result<Vec<u8>> {
    Ok(match input {
        SigningInput::Message(message) => Sha256::digest(message).to_vec(),
        SigningInput::Digest(digest) => {
            check_digest_len(digest)?;
            digest.clone()
        }
    })
}

fn verify_ecdsa_ring(spki_der: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
    let point = sec1_point_from_spki(spki_der)?;
    let key =
        ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_FIXED, &point);
    Ok(key.verify(message, signature).is_ok())
}

fn verify_ecdsa_prehash(spki_der: &[u8], digest: &[u8], signature: &[u8]) -> Result<bool> {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use p256::pkcs8::DecodePublicKey;

    let key = p256::ecdsa::VerifyingKey::from_public_key_der(spki_der)
        .context("cached public key is not a valid P-256 SPKI")?;

    // PKCS#11 emits raw r||s, not the DER encoding many libraries default to.
    let Ok(signature) = p256::ecdsa::Signature::from_slice(signature) else {
        return Ok(false);
    };

    Ok(key.verify_prehash(digest, &signature).is_ok())
}

fn verify_rsa(spki_der: &[u8], digest: &[u8], signature: &[u8], pss: bool) -> Result<bool> {
    use rsa::pkcs8::DecodePublicKey;

    let key = rsa::RsaPublicKey::from_public_key_der(spki_der)
        .context("cached public key is not a valid RSA SPKI")?;

    let outcome = if pss {
        // Salt length must match what the token used when signing; `prepare` requests a
        // salt equal to the hash length, and `Pss::new` defaults to the same.
        key.verify(rsa::pss::Pss::new::<Sha256>(), digest, signature)
    } else {
        key.verify(rsa::Pkcs1v15Sign::new::<Sha256>(), digest, signature)
    };

    Ok(outcome.is_ok())
}
