//! Creating the demo keys on a token.
//!
//! Provisioning lives in Rust rather than only in `pkcs11-tool` so the native
//! development token and the container token are created by the same code with the
//! same attributes. Two provisioning implementations would drift, and the attributes
//! that matter here -- `CKA_SENSITIVE` and `CKA_EXTRACTABLE` -- are exactly the ones
//! a project about key protection cannot afford to get subtly wrong in one path.

use anyhow::{Context, Result};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::Session;

use super::find_object;

/// DER encoding of the secp256r1 / prime256v1 named-curve OID (1.2.840.10045.3.1.7).
const SECP256R1_OID_DER: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

/// The demo keys every environment is expected to have.
pub const DEMO_EC_KEY: &str = "demo-ec-p256";
pub const DEMO_RSA_KEY: &str = "demo-rsa-2048";
pub const DEMO_AES_KEY: &str = "demo-aes-256";

/// Whether a key had to be created or was already there.
#[derive(Debug, PartialEq, Eq)]
pub enum Provisioned {
    Created,
    AlreadyPresent,
}

/// Attributes shared by every private key: the token must never hand the key back.
fn private_key_base(label: &str) -> Vec<Attribute> {
    vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Sign(true),
        Attribute::Label(label.as_bytes().to_vec()),
    ]
}

fn public_key_base(label: &str) -> Vec<Attribute> {
    vec![
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::Verify(true),
        Attribute::Label(label.as_bytes().to_vec()),
    ]
}

/// Create the ECDSA P-256 demo key pair if it is not already present.
pub fn ensure_ec_key(session: &Session, label: &str) -> Result<Provisioned> {
    if find_object(session, ObjectClass::PRIVATE_KEY, label)?.is_some() {
        return Ok(Provisioned::AlreadyPresent);
    }

    let mut public_template = public_key_base(label);
    public_template.push(Attribute::KeyType(KeyType::EC));
    public_template.push(Attribute::EcParams(SECP256R1_OID_DER.to_vec()));

    session
        .generate_key_pair(
            &Mechanism::EccKeyPairGen,
            &public_template,
            &private_key_base(label),
        )
        .context("C_GenerateKeyPair(CKM_EC_KEY_PAIR_GEN) failed")?;

    Ok(Provisioned::Created)
}

/// Create the RSA-2048 demo key pair if it is not already present.
pub fn ensure_rsa_key(session: &Session, label: &str) -> Result<Provisioned> {
    if find_object(session, ObjectClass::PRIVATE_KEY, label)?.is_some() {
        return Ok(Provisioned::AlreadyPresent);
    }

    let mut public_template = public_key_base(label);
    public_template.push(Attribute::KeyType(KeyType::RSA));
    public_template.push(Attribute::ModulusBits(2048.into()));
    public_template.push(Attribute::PublicExponent(vec![0x01, 0x00, 0x01]));
    public_template.push(Attribute::Encrypt(true));

    let mut private_template = private_key_base(label);
    private_template.push(Attribute::Decrypt(true));

    session
        .generate_key_pair(
            &Mechanism::RsaPkcsKeyPairGen,
            &public_template,
            &private_template,
        )
        .context("C_GenerateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN) failed")?;

    Ok(Provisioned::Created)
}

/// Create the AES-256 demo secret key if it is not already present.
pub fn ensure_aes_key(session: &Session, label: &str) -> Result<Provisioned> {
    if find_object(session, ObjectClass::SECRET_KEY, label)?.is_some() {
        return Ok(Provisioned::AlreadyPresent);
    }

    let template = [
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
        Attribute::KeyType(KeyType::AES),
        Attribute::ValueLen(32.into()),
        Attribute::Label(label.as_bytes().to_vec()),
    ];

    let _handle: ObjectHandle = session
        .generate_key(&Mechanism::AesKeyGen, &template)
        .context("C_GenerateKey(CKM_AES_KEY_GEN) failed")?;

    Ok(Provisioned::Created)
}

/// Provision every demo key. Idempotent.
pub fn ensure_demo_keys(session: &Session) -> Result<Vec<(&'static str, Provisioned)>> {
    Ok(vec![
        (DEMO_EC_KEY, ensure_ec_key(session, DEMO_EC_KEY)?),
        (DEMO_RSA_KEY, ensure_rsa_key(session, DEMO_RSA_KEY)?),
        (DEMO_AES_KEY, ensure_aes_key(session, DEMO_AES_KEY)?),
    ])
}
