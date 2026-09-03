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
