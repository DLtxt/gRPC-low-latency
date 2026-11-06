//! Request, review, and approve transfers from a transfer key (M10).
//!
//! The approval side is the part that matters. `approve` does not take the proxy's word
//! for what it is approving: it fetches the held transfer's canonical bytes, decodes them
//! itself, checks they hash to the digest it was asked about, shows the decoded fields,
//! and signs those exact bytes with the approver's own key. A proxy that showed one
//! transfer and held another would get an approval that verifies for neither.
//!
//! That is the Bybit lesson in miniature: the approvers there signed what a compromised
//! interface showed them. Here the decoding happens on the approver's side, and the
//! approval covers the full transfer rather than a hash, so a hardware signer with a
//! screen could display it field by field. This CLI stands in for that device; in the
//! demo it runs on the same machine as everything else, which a deployment would not.
//!
//! ```text
//! transfer [--as WORKLOAD] [--addr URL] [--domain NAME] <command> [options]
//!
//!   sign      --key LABEL --chain CHAIN --asset ASSET --to DESTINATION --amount AMOUNT --nonce N
//!   show      --key LABEL --digest HEX
//!   approve   --key LABEL --digest HEX --approver NAME [--approver-key PATH] [--yes]
//!   raw-sign  --key LABEL --digest HEX     the blind-signing request a transfer key refuses
//! ```
//!
//! Exit status: 0 on success, 2 when `sign` was held for approval, 1 on any refusal.

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::process::ExitCode;

use anyhow::{anyhow, bail, ensure, Context, Result};
use grpc_low_latency_proxy::proto::v1::{
    hsm_service_client::HsmServiceClient, signing_input, ApproveTransferRequest,
    GetPendingTransferRequest, GetPublicKeyRequest, SignRequest, SignTransferRequest,
    SignatureMechanism, SigningInput, Transfer as WireTransfer, TransferStatus,
};
use grpc_low_latency_proxy::transfer::canonical::{
    approval_message, from_hex, parse_amount, to_hex, HOLD_ID_LEN,
};
use grpc_low_latency_proxy::transfer::Transfer;
use p256::ecdsa::signature::Signer;
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey};
use sha2::{Digest, Sha256};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

type Client = HsmServiceClient<Channel>;

const USAGE: &str = "\
usage: transfer [--as WORKLOAD] [--addr URL] [--domain NAME] <command> [options]

commands:
  sign      --key LABEL --chain CHAIN --asset ASSET --to DESTINATION --amount AMOUNT --nonce N
  show      --key LABEL --digest HEX
  approve   --key LABEL --digest HEX --approver NAME [--approver-key PATH] [--yes]
  raw-sign  --key LABEL --digest HEX

--as names the client certificate: $CERT_DIR/<WORKLOAD>.crt and .key (default payments).
Environment: CERT_DIR (certs), PROXY_ADDR (https://localhost:50051),
APPROVER_KEY_DIR (.local/approvers).";

/// Held for approval: not a failure, but not a signature either, and a script needs to
/// tell the three apart.
const EXIT_HELD: u8 = 2;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    // Same reason as the server: two rustls providers are reachable from this crate.
    let _ = rustls::crypto::ring::default_provider().install_default();

    match run().await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<ExitCode> {
    let args = Args::parse(std::env::args().skip(1))?;
    let mut client = connect(&args).await?;

    match args.command.as_str() {
        "sign" => sign(&mut client, &args).await,
        "show" => show(&mut client, &args).await,
        "approve" => approve(&mut client, &args).await,
        "raw-sign" => raw_sign(&mut client, &args).await,
        other => bail!("unknown command '{other}'\n\n{USAGE}"),
    }
}

/// Request a transfer. If it is signed, check the signature locally against the key's
/// public half -- over bytes this CLI decoded and compared with what it asked for --
/// rather than trusting that the proxy signed what it says it signed.
async fn sign(client: &mut Client, args: &Args) -> Result<ExitCode> {
    let key = args.required("key")?;
    let nonce: u64 = args
        .required("nonce")?
        .parse()
        .context("--nonce must be a non-negative integer")?;
    let wire = WireTransfer {
        chain: args.required("chain")?.to_string(),
        asset: args.required("asset")?.to_string(),
        destination: args.required("to")?.to_string(),
        amount: args.required("amount")?.to_string(),
        nonce,
    };

    let response = match client
        .sign_transfer(SignTransferRequest {
            key_label: key.to_string(),
            transfer: Some(wire.clone()),
        })
        .await
    {
        Ok(response) => response.into_inner(),
        Err(status) => return Ok(refused(&status)),
    };

    let transfer = Transfer::decode(&response.canonical_transfer)
        .map_err(|e| anyhow!("the proxy returned a malformed transfer: {e}"))?;
    ensure_matches(&transfer, key, &wire)?;
    let digest: [u8; 32] = Sha256::digest(&response.canonical_transfer).into();
    ensure!(
        response.digest == digest,
        "the proxy's digest does not match the transfer it returned"
    );

    match TransferStatus::try_from(response.status) {
        Ok(TransferStatus::Signed) => {
            let spki = client
                .get_public_key(GetPublicKeyRequest {
                    key_label: key.to_string(),
                })
                .await
                .map_err(|status| anyhow!("could not fetch the public key: {status}"))?
                .into_inner()
                .spki_der;
            verify(&spki, &response.canonical_transfer, &response.signature)?;

            println!("status     SIGNED");
            println!("transfer   {}", transfer.summary());
            println!("digest     {}", to_hex(&digest));
            println!("signature  {}", to_hex(&response.signature));
            if response.approvals_received > 0 {
                println!(
                    "approvals  {} of {} required",
                    response.approvals_received, response.approvals_required
                );
            }
            println!("verified   locally, over the decoded transfer, against {key}'s public key");
            Ok(ExitCode::SUCCESS)
        }
        Ok(TransferStatus::PendingApproval) => {
            println!("status     PENDING_APPROVAL");
            println!("transfer   {}", transfer.summary());
            println!("digest     {}", to_hex(&digest));
            println!("reason     {}", response.hold_reason);
            println!(
                "approvals  {} of {}",
                response.approvals_received, response.approvals_required
            );
            println!("next       approvers run `transfer approve`; then resubmit this transfer, same nonce");
            Ok(ExitCode::from(EXIT_HELD))
        }
        _ => bail!("the proxy returned an unknown status {}", response.status),
    }
}

/// Show a held transfer, decoded here rather than as the proxy summarises it.
async fn show(client: &mut Client, args: &Args) -> Result<ExitCode> {
    let key = args.required("key")?;
    let digest = args.digest()?;
    let held = match fetch_held(client, key, &digest).await? {
        Ok(held) => held,
        Err(code) => return Ok(code),
    };
    print_held(&held);
    Ok(ExitCode::SUCCESS)
}

/// Approve a held transfer: decode it, show it, and sign exactly those bytes.
async fn approve(client: &mut Client, args: &Args) -> Result<ExitCode> {
    let key = args.required("key")?;
    let digest = args.digest()?;
    let approver = args.required("approver")?;
    let key_path = match args.get("approver-key") {
        Some(path) => path.to_string(),
        None => {
            let dir = std::env::var("APPROVER_KEY_DIR")
                .unwrap_or_else(|_| ".local/approvers".to_string());
            format!("{dir}/{approver}.key")
        }
    };
    let pem = std::fs::read_to_string(&key_path)
        .with_context(|| format!("failed to read {approver}'s approval key {key_path}"))?;
    let signing_key = p256::ecdsa::SigningKey::from_pkcs8_pem(&pem)
        .map_err(|e| anyhow!("{key_path} is not a P-256 private key in PKCS#8 PEM: {e}"))?;

    let held = match fetch_held(client, key, &digest).await? {
        Ok(held) => held,
        Err(code) => return Ok(code),
    };
    print_held(&held);

    if !args.flag("yes") && !confirm(approver, &held.transfer)? {
        println!("not approved");
        return Ok(ExitCode::FAILURE);
    }

    // The bytes that were decoded and displayed, and nothing else, for this hold only.
    let signature: p256::ecdsa::Signature =
        signing_key.sign(&approval_message(&held.hold_id, &held.canonical));
    let response = match client
        .approve_transfer(ApproveTransferRequest {
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
/// Kept so the demo can show a transfer key refusing it.
async fn raw_sign(client: &mut Client, args: &Args) -> Result<ExitCode> {
    let key = args.required("key")?;
    let digest = args.digest()?;
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

struct Held {
    canonical: Vec<u8>,
    hold_id: [u8; HOLD_ID_LEN],
    transfer: Transfer,
    reason: String,
    required: u32,
    approved_by: Vec<String>,
    expires_in_seconds: u64,
}

/// Fetch a held transfer and check it is the one asked about. The outer error is a
/// failure; the inner one is the proxy's refusal, already reported.
async fn fetch_held(
    client: &mut Client,
    key: &str,
    digest: &[u8; 32],
) -> Result<std::result::Result<Held, ExitCode>> {
    let pending = match client
        .get_pending_transfer(GetPendingTransferRequest {
            key_label: key.to_string(),
            digest: digest.to_vec(),
        })
        .await
    {
        Ok(response) => response.into_inner(),
        Err(status) => return Ok(Err(refused(&status))),
    };

    // The digest is what the approver was asked about, out of band. Bytes that hash to
    // anything else are not that transfer, whatever the proxy's summary says.
    let actual: [u8; 32] = Sha256::digest(&pending.canonical_transfer).into();
    ensure!(
        &actual == digest,
        "the proxy returned a transfer that does not match digest {}; refusing to show it",
        to_hex(digest)
    );
    let transfer = Transfer::decode(&pending.canonical_transfer)
        .map_err(|e| anyhow!("the proxy returned a malformed transfer: {e}"))?;
    ensure!(
        transfer.key_label() == key,
        "the held transfer is from key '{}', not '{key}'",
        transfer.key_label()
    );

    let hold_id = pending
        .hold_id
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("the proxy returned a malformed hold identifier"))?;

    Ok(Ok(Held {
        canonical: pending.canonical_transfer,
        hold_id,
        transfer,
        reason: pending.hold_reason,
        required: pending.approvals_required,
        approved_by: pending.approved_by,
        expires_in_seconds: pending.expires_in_seconds,
    }))
}

fn print_held(held: &Held) {
    let t = &held.transfer;
    println!("decoded from the transfer's own bytes:");
    println!("  from         {}", t.key_label());
    println!("  chain        {}", t.chain());
    println!("  asset        {}", t.asset());
    println!("  amount       {} {}", t.amount_display(), t.asset());
    println!("  destination  {}", t.destination());
    println!("  nonce        {}", t.nonce());
    println!("digest     {}", to_hex(&t.digest()));
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

fn confirm(approver: &str, transfer: &Transfer) -> Result<bool> {
    print!(
        "approve {} {} to {} as {approver}? type 'approve' to sign: ",
        transfer.amount_display(),
        transfer.asset(),
        transfer.destination()
    );
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim() == "approve")
}

/// The decoded transfer must be the one requested, field for field. Otherwise the
/// signature, however valid, is over something the caller did not ask for.
fn ensure_matches(transfer: &Transfer, key: &str, asked: &WireTransfer) -> Result<()> {
    let amount = parse_amount(&asked.amount, transfer.decimals())
        .map_err(|e| anyhow!("the requested amount does not parse: {e}"))?;
    let matches = transfer.key_label() == key
        && transfer.chain() == asked.chain
        && transfer.asset() == asked.asset
        && transfer.destination() == asked.destination
        && transfer.amount() == amount
        && transfer.nonce() == asked.nonce;
    ensure!(
        matches,
        "the proxy returned a different transfer from the one requested: {}",
        transfer.summary()
    );
    Ok(())
}

/// Verify a transfer signature with nothing but the public key and the bytes.
fn verify(spki_der: &[u8], canonical: &[u8], signature: &[u8]) -> Result<()> {
    let key = p256::PublicKey::from_public_key_der(spki_der)
        .map_err(|e| anyhow!("the transfer key's public key is not P-256: {e}"))?;
    let point = p256::EncodedPoint::from(key);
    ring::signature::UnparsedPublicKey::new(
        &ring::signature::ECDSA_P256_SHA256_FIXED,
        point.as_bytes(),
    )
    .verify(canonical, signature)
    .map_err(|_| anyhow!("the signature does NOT verify over the returned transfer"))
}

fn refused(status: &tonic::Status) -> ExitCode {
    println!("refused    {:?}: {}", status.code(), status.message());
    ExitCode::FAILURE
}

async fn connect(args: &Args) -> Result<Client> {
    let cert_dir = std::env::var("CERT_DIR").unwrap_or_else(|_| "certs".to_string());
    let workload = args.get("as").unwrap_or("payments");
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

/// `<command>` plus `--name value` options and `--flag` switches. Hand-rolled: four
/// commands do not justify an argument-parsing dependency in a security-sensitive
/// crate, and every option is a plain string.
struct Args {
    command: String,
    options: HashMap<String, String>,
    flags: Vec<String>,
}

impl Args {
    const FLAGS: &'static [&'static str] = &["yes"];

    fn parse(mut raw: impl Iterator<Item = String>) -> Result<Self> {
        let mut command = None;
        let mut options = HashMap::new();
        let mut flags = Vec::new();
        while let Some(arg) = raw.next() {
            if arg == "-h" || arg == "--help" {
                println!("{USAGE}");
                std::process::exit(0);
            }
            if let Some(name) = arg.strip_prefix("--") {
                if Self::FLAGS.contains(&name) {
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
                bail!("unexpected argument '{arg}'\n\n{USAGE}");
            }
        }
        Ok(Self {
            command: command.ok_or_else(|| anyhow!("{USAGE}"))?,
            options,
            flags,
        })
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.options.get(name).map(String::as_str)
    }

    fn required(&self, name: &str) -> Result<&str> {
        self.get(name)
            .ok_or_else(|| anyhow!("{} needs --{name}\n\n{USAGE}", self.command))
    }

    fn flag(&self, name: &str) -> bool {
        self.flags.iter().any(|flag| flag == name)
    }

    fn digest(&self) -> Result<[u8; 32]> {
        let hex = self.required("digest")?;
        from_hex(hex)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| anyhow!("--digest must be 64 hex characters"))
    }
}
