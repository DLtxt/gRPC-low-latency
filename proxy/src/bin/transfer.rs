//! Request, review, and approve transfers from a transfer key (M10).
//!
//! The approval side is the part that matters. `approve` does not take the proxy's word
//! for what it is approving: it fetches the held transfer's canonical bytes, checks they
//! hash to the digest it was asked about, decodes them itself, shows the decoded fields,
//! and signs those exact bytes with the approver's own key. A proxy that showed one
//! transfer and held another would get an approval that verifies for neither. The
//! mechanics are shared with the `release` tool, in `grpc_low_latency_proxy::cli`.
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

use std::process::ExitCode;

use anyhow::{anyhow, bail, ensure, Context, Result};
use grpc_low_latency_proxy::cli::{self, Args, Client, Held, EXIT_HELD};
use grpc_low_latency_proxy::encoding::to_hex;
use grpc_low_latency_proxy::proto::v1::{
    SignTransferRequest, SigningStatus, Transfer as WireTransfer,
};
use grpc_low_latency_proxy::transfer::canonical::parse_amount;
use grpc_low_latency_proxy::transfer::Transfer;
use sha2::{Digest, Sha256};

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
    let args = Args::parse(std::env::args().skip(1), USAGE, &["yes"])?;
    let mut client = cli::connect(&args, "payments").await?;

    match args.command.as_str() {
        "sign" => sign(&mut client, &args).await,
        "show" => show(&mut client, &args).await,
        "approve" => approve(&mut client, &args).await,
        "raw-sign" => {
            let key = args.required("key")?;
            cli::raw_sign(&mut client, key, &args.hex32("digest")?).await
        }
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
        Err(status) => return Ok(cli::refused(&status)),
    };

    let transfer = Transfer::decode(&response.canonical_transfer)
        .map_err(|e| anyhow!("the proxy returned a malformed transfer: {e}"))?;
    ensure_matches(&transfer, key, &wire)?;
    let digest: [u8; 32] = Sha256::digest(&response.canonical_transfer).into();
    ensure!(
        response.digest == digest,
        "the proxy's digest does not match the transfer it returned"
    );

    match SigningStatus::try_from(response.status) {
        Ok(SigningStatus::Signed) => {
            let spki = cli::public_key(client, key).await?;
            cli::verify_p256(&spki, &response.canonical_transfer, &response.signature)
                .context("over the returned transfer")?;

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
        Ok(SigningStatus::PendingApproval) => {
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
    let digest = args.hex32("digest")?;
    let held = match cli::fetch_held(client, key, &digest).await? {
        Ok(held) => held,
        Err(code) => return Ok(code),
    };
    print_held(&decode_held(&held, key)?, &held, &digest);
    Ok(ExitCode::SUCCESS)
}

/// Approve a held transfer: decode it, show it, and sign exactly those bytes.
async fn approve(client: &mut Client, args: &Args) -> Result<ExitCode> {
    let key = args.required("key")?;
    let digest = args.hex32("digest")?;
    let approver = args.required("approver")?;
    let signing_key = cli::load_approver_key(args, approver)?;

    let held = match cli::fetch_held(client, key, &digest).await? {
        Ok(held) => held,
        Err(code) => return Ok(code),
    };
    let transfer = decode_held(&held, key)?;
    print_held(&transfer, &held, &digest);

    let question = format!(
        "approve {} {} to {} as {approver}",
        transfer.amount_display(),
        transfer.asset(),
        transfer.destination()
    );
    if !args.flag("yes") && !cli::confirm(&question)? {
        println!("not approved");
        return Ok(ExitCode::FAILURE);
    }
    cli::submit_approval(client, key, &digest, approver, &signing_key, &held).await
}

/// Decode a held request as a transfer from `key`, or refuse to go further.
fn decode_held(held: &Held, key: &str) -> Result<Transfer> {
    let transfer = Transfer::decode(&held.canonical)
        .map_err(|e| anyhow!("the held request is not a well-formed transfer: {e}"))?;
    ensure!(
        transfer.key_label() == key,
        "the held transfer is from key '{}', not '{key}'",
        transfer.key_label()
    );
    Ok(transfer)
}

fn print_held(t: &Transfer, held: &Held, digest: &[u8; 32]) {
    println!("decoded from the transfer's own bytes:");
    println!("  from         {}", t.key_label());
    println!("  chain        {}", t.chain());
    println!("  asset        {}", t.asset());
    println!("  amount       {} {}", t.amount_display(), t.asset());
    println!("  destination  {}", t.destination());
    println!("  nonce        {}", t.nonce());
    cli::print_hold(held, digest);
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
