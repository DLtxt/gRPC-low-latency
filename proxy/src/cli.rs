//! Shared by the `transfer` and `release` command-line tools: connecting over mTLS,
//! argument parsing, and the approver's side of an approval, which is the same for every
//! purpose-bound key.
//!
//! The approval side is the part that matters. It does not take the proxy's word for
//! what is being approved. It fetches the held request's canonical bytes and checks they
//! hash to the digest the approver was asked about. The tool that knows the format then
//! decodes and shows them, and only those exact bytes are signed, with the approver's own
//! key. A proxy that showed one request and held another would get an approval that
//! verifies for neither.
//!
//! That is the Bybit lesson in miniature: the approvers there signed what a compromised
//! interface showed them. Here the decoding happens on the approver's side, and the
//! approval covers the full request rather than a hash, so a hardware signer with a
//! screen could display it field by field. These tools stand in for that device; in the
//! demos they run on the same machine as everything else, which a deployment would not.

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::process::ExitCode;

use anyhow::{anyhow, bail, ensure, Context, Result};
use p256::ecdsa::signature::Signer;
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey};
use sha2::{Digest, Sha256};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

use crate::approval::{approval_message, HOLD_ID_LEN};
use crate::encoding::{from_hex, to_hex};
use crate::proto::v1::{
    hsm_service_client::HsmServiceClient, signing_input, ApproveRequest, GetPendingApprovalRequest,
    GetPublicKeyRequest, SignRequest, SignatureMechanism, SigningInput,
};

pub type Client = HsmServiceClient<Channel>;

/// Held for approval: not a failure, but not a signature either, and a script needs to
/// tell the three apart.
pub const EXIT_HELD: u8 = 2;

/// `<command>` plus `--name value` options and `--flag` switches. Hand-rolled: a handful
/// of commands do not justify an argument-parsing dependency in a security-sensitive
/// crate, and every option is a plain string.
pub struct Args {
    pub command: String,
    options: HashMap<String, String>,
    flags: Vec<String>,
    usage: &'static str,
}

impl Args {
    pub fn parse(
        mut raw: impl Iterator<Item = String>,
        usage: &'static str,
        known_flags: &[&str],
    ) -> Result<Self> {
        let mut command = None;
        let mut options = HashMap::new();
        let mut flags = Vec::new();
        while let Some(arg) = raw.next() {
            if arg == "-h" || arg == "--help" {
                println!("{usage}");
                std::process::exit(0);
            }
            if let Some(name) = arg.strip_prefix("--") {
                if known_flags.contains(&name) {
                    flags.push(name.to_string());
                    continue;
                }
                let value = raw
                    .next()
                    .ok_or_else(|| anyhow!("--{name} needs a value"))?;
                if options.insert(name.to_string(), value).is_some() {
                    bail!("--{name} given twice");
                }
            } else if command.is_none() {
                command = Some(arg);
            } else {
                bail!("unexpected argument '{arg}'\n\n{usage}");
            }
        }
        Ok(Self {
            command: command.ok_or_else(|| anyhow!("{usage}"))?,
            options,
            flags,
            usage,
        })
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.options.get(name).map(String::as_str)
    }

    pub fn required(&self, name: &str) -> Result<&str> {
        self.get(name)
            .ok_or_else(|| anyhow!("{} needs --{name}\n\n{}", self.command, self.usage))
    }

    pub fn flag(&self, name: &str) -> bool {
        self.flags.iter().any(|flag| flag == name)
    }

    /// A 32-byte value given as 64 hex characters.
    pub fn hex32(&self, name: &str) -> Result<[u8; 32]> {
        let hex = self.required(name)?;
        from_hex(hex)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| anyhow!("--{name} must be 64 hex characters"))
    }
}

/// Connect over mTLS as `--as WORKLOAD`: `$CERT_DIR/<WORKLOAD>.crt` and `.key`.
pub async fn connect(args: &Args, default_workload: &str) -> Result<Client> {
    let cert_dir = std::env::var("CERT_DIR").unwrap_or_else(|_| "certs".to_string());
    let workload = args.get("as").unwrap_or(default_workload);
    let read = |name: String| {
        std::fs::read(&name).with_context(|| format!("failed to read {name}; run make certs"))
    };
    let ca = Certificate::from_pem(read(format!("{cert_dir}/ca.crt"))?);
    let identity = Identity::from_pem(
        read(format!("{cert_dir}/{workload}.crt"))?,
        read(format!("{cert_dir}/{workload}.key"))?,
    );

    let addr = args
        .get("addr")
        .map(str::to_string)
        .or_else(|| std::env::var("PROXY_ADDR").ok())
        .unwrap_or_else(|| "https://localhost:50051".to_string());
    let tls = ClientTlsConfig::new()
        .ca_certificate(ca)
        .identity(identity)
        .domain_name(args.get("domain").unwrap_or("localhost"));

    let channel = Channel::from_shared(addr.clone())
        .with_context(|| format!("bad address {addr}"))?
        .tls_config(tls)
        .context("bad TLS configuration")?
        .connect()
        .await
        .with_context(|| format!("could not connect to {addr}"))?;
    Ok(HsmServiceClient::new(channel))
}

/// Report a refusal from the proxy. A refusal is an answer, not a crash.
pub fn refused(status: &tonic::Status) -> ExitCode {
    println!("refused    {:?}: {}", status.code(), status.message());
    ExitCode::FAILURE
}

/// A held request, fetched and checked against the digest the approver was asked about.
pub struct Held {
    pub canonical: Vec<u8>,
    pub hold_id: [u8; HOLD_ID_LEN],
    pub reason: String,
    pub required: u32,
    pub approved_by: Vec<String>,
    pub expires_in_seconds: u64,
}

/// Fetch a held request and check its bytes are the ones asked about. The outer error is
/// a failure; the inner one is the proxy's refusal, already reported.
pub async fn fetch_held(
    client: &mut Client,
    key: &str,
    digest: &[u8; 32],
) -> Result<std::result::Result<Held, ExitCode>> {
    let pending = match client
        .get_pending_approval(GetPendingApprovalRequest {
            key_label: key.to_string(),
            digest: digest.to_vec(),
        })
        .await
    {
        Ok(response) => response.into_inner(),
        Err(status) => return Ok(Err(refused(&status))),
    };

    // The digest is what the approver was asked about, out of band. Bytes that hash to
    // anything else are not that request, whatever the proxy's summary says.
    let actual: [u8; 32] = Sha256::digest(&pending.canonical).into();
    ensure!(
        &actual == digest,
        "the proxy returned a request that does not match digest {}; refusing to show it",
        to_hex(digest)
    );
    let hold_id = pending
        .hold_id
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("the proxy returned a malformed hold identifier"))?;

    Ok(Ok(Held {
        canonical: pending.canonical,
        hold_id,
        reason: pending.hold_reason,
        required: pending.approvals_required,
        approved_by: pending.approved_by,
        expires_in_seconds: pending.expires_in_seconds,
    }))
}

/// The hold's own lines, after the decoded request.
pub fn print_hold(held: &Held, digest: &[u8; 32]) {
    println!("digest     {}", to_hex(digest));
    println!("hold       {}", to_hex(&held.hold_id));
    println!("held       {}", held.reason);
    println!(
        "approvals  {} of {}{}",
        held.approved_by.len(),
        held.required,
        if held.approved_by.is_empty() {
            String::new()
        } else {
            format!(" ({})", held.approved_by.join(", "))
        }
    );
    println!("expires    in {}s", held.expires_in_seconds);
}

/// The approver's private key: `--approver-key PATH`, or `$APPROVER_KEY_DIR/<name>.key`.
pub fn load_approver_key(args: &Args, approver: &str) -> Result<p256::ecdsa::SigningKey> {
    let path = match args.get("approver-key") {
        Some(path) => path.to_string(),
        None => {
            let dir = std::env::var("APPROVER_KEY_DIR")
                .unwrap_or_else(|_| ".local/approvers".to_string());
            format!("{dir}/{approver}.key")
        }
    };
    let pem = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {approver}'s approval key {path}"))?;
    p256::ecdsa::SigningKey::from_pkcs8_pem(&pem)
        .map_err(|e| anyhow!("{path} is not a P-256 private key in PKCS#8 PEM: {e}"))
}

/// Ask on the terminal; only the word itself counts as yes.
pub fn confirm(question: &str) -> Result<bool> {
    print!("{question}? type 'approve' to sign: ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim() == "approve")
}

/// Sign the held bytes as `approver` -- the bytes that were decoded and shown, and
/// nothing else, for this hold only -- and submit the approval.
pub async fn submit_approval(
    client: &mut Client,
    key: &str,
    digest: &[u8; 32],
    approver: &str,
    signing_key: &p256::ecdsa::SigningKey,
    held: &Held,
) -> Result<ExitCode> {
    let signature: p256::ecdsa::Signature =
        signing_key.sign(&approval_message(&held.hold_id, &held.canonical));
    let response = match client
        .approve(ApproveRequest {
            key_label: key.to_string(),
            digest: digest.to_vec(),
            approver: approver.to_string(),
            signature: signature.to_bytes().to_vec(),
            hold_id: held.hold_id.to_vec(),
        })
        .await
    {
        Ok(response) => response.into_inner(),
        Err(status) => return Ok(refused(&status)),
    };

    println!(
        "approved   as {approver}: {} of {}{}",
        response.approvals_received,
        response.approvals_required,
        if response.approved {
            "; quorum reached, the requester can now collect it"
        } else {
            ""
        }
    );
    Ok(ExitCode::SUCCESS)
}

/// The request a compromised caller would send: sign this digest, no questions asked.
/// Kept so the demos can show a purpose-bound key refusing it.
pub async fn raw_sign(client: &mut Client, key: &str, digest: &[u8; 32]) -> Result<ExitCode> {
    match client
        .sign(SignRequest {
            key_label: key.to_string(),
            mechanism: SignatureMechanism::EcdsaSha256 as i32,
            input: Some(SigningInput {
                input: Some(signing_input::Input::Digest(digest.to_vec())),
            }),
        })
        .await
    {
        Ok(response) => {
            println!("status     SIGNED (blind)");
            println!("signature  {}", to_hex(&response.into_inner().signature));
            Ok(ExitCode::SUCCESS)
        }
        Err(status) => Ok(refused(&status)),
    }
}

/// A key's public half, as DER SubjectPublicKeyInfo.
pub async fn public_key(client: &mut Client, key: &str) -> Result<Vec<u8>> {
    Ok(client
        .get_public_key(GetPublicKeyRequest {
            key_label: key.to_string(),
        })
        .await
        .map_err(|status| anyhow!("could not fetch the public key: {status}"))?
        .into_inner()
        .spki_der)
}

/// Verify an ECDSA P-256 signature with nothing but the public key and the bytes.
pub fn verify_p256(spki_der: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    let key = p256::PublicKey::from_public_key_der(spki_der)
        .map_err(|e| anyhow!("the key's public half is not P-256: {e}"))?;
    let point = p256::EncodedPoint::from(key);
    ring::signature::UnparsedPublicKey::new(
        &ring::signature::ECDSA_P256_SHA256_FIXED,
        point.as_bytes(),
    )
    .verify(message, signature)
    .map_err(|_| anyhow!("the signature does NOT verify"))
}
