//! Request, review, approve and verify software releases from a release key (M11).
//!
//! A build system asks with `sign`, naming the file it built; the tool hashes the file and
//! sends the hash with the artifact, version and channel. The proxy builds the release
//! statement it signs from those fields. Nothing else is ever signed by a release key.
//!
//! An approver checks more than the proxy can. `approve` needs the approver's own copy
//! of the build -- fetched or rebuilt independently -- and refuses to sign unless it
//! hashes to the file the held statement names. A build system that swapped the file
//! would have to get past every approver's copy as well as the proxy. The approval
//! mechanics are shared with the `transfer` tool, in `grpc_low_latency_proxy::cli`.
//!
//! `verify` is what an updater does before installing: rebuild the statement from the
//! file it downloaded and the fields it expects, and check the signature with nothing
//! but the key's public half.
//!
//! ```text
//! release [--as WORKLOAD] [--addr URL] [--domain NAME] <command> [options]
//!
//!   sign      --key LABEL --artifact NAME --version V --channel C --file PATH
//!   show      --key LABEL --digest HEX
//!   approve   --key LABEL --digest HEX --approver NAME --file PATH [--approver-key PATH] [--yes]
//!   verify    --key LABEL --artifact NAME --version V --channel C --file PATH --signature HEX
//!   raw-sign  --key LABEL --digest HEX     the blind-signing request a release key refuses
//! ```
//!
//! Exit status: 0 on success, 2 when `sign` was held for approval, 1 on any refusal or a
//! signature that does not verify.

use std::process::ExitCode;

use anyhow::{anyhow, bail, ensure, Context, Result};
use grpc_low_latency_proxy::cli::{self, Args, Client, Held, EXIT_HELD};
use grpc_low_latency_proxy::encoding::{from_hex, to_hex};
use grpc_low_latency_proxy::proto::v1::{
    Release as WireRelease, SignReleaseRequest, SigningStatus,
};
use grpc_low_latency_proxy::release::Release;
use sha2::{Digest, Sha256};

const USAGE: &str = "\
usage: release [--as WORKLOAD] [--addr URL] [--domain NAME] <command> [options]

commands:
  sign      --key LABEL --artifact NAME --version V --channel C --file PATH
  show      --key LABEL --digest HEX
  approve   --key LABEL --digest HEX --approver NAME --file PATH [--approver-key PATH] [--yes]
  verify    --key LABEL --artifact NAME --version V --channel C --file PATH --signature HEX
  raw-sign  --key LABEL --digest HEX

--as names the client certificate: $CERT_DIR/<WORKLOAD>.crt and .key (default ci).
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
    let mut client = cli::connect(&args, "ci").await?;

    match args.command.as_str() {
        "sign" => sign(&mut client, &args).await,
        "show" => show(&mut client, &args).await,
        "approve" => approve(&mut client, &args).await,
        "verify" => verify(&mut client, &args).await,
        "raw-sign" => {
            let key = args.required("key")?;
            cli::raw_sign(&mut client, key, &args.hex32("digest")?).await
        }
        other => bail!("unknown command '{other}'\n\n{USAGE}"),
    }
}

/// SHA-256 of the file at `--file`.
fn hash_file(args: &Args) -> Result<[u8; 32]> {
    let path = args.required("file")?;
    let contents = std::fs::read(path).with_context(|| format!("failed to read {path}"))?;
    Ok(Sha256::digest(&contents).into())
}

/// Request a release signature. If it is signed, check the signature locally, over the
/// statement this tool decoded and compared with what it asked for.
async fn sign(client: &mut Client, args: &Args) -> Result<ExitCode> {
    let key = args.required("key")?;
    let wire = WireRelease {
        artifact: args.required("artifact")?.to_string(),
        version: args.required("version")?.to_string(),
        channel: args.required("channel")?.to_string(),
        sha256: hash_file(args)?.to_vec(),
    };

    let response = match client
        .sign_release(SignReleaseRequest {
            key_label: key.to_string(),
            release: Some(wire.clone()),
        })
        .await
    {
        Ok(response) => response.into_inner(),
        Err(status) => return Ok(cli::refused(&status)),
    };

    let release = Release::decode(&response.canonical_release)
        .map_err(|e| anyhow!("the proxy returned a malformed release: {e}"))?;
    let matches = release.key_label() == key
        && release.artifact() == wire.artifact
        && release.version() == wire.version
        && release.channel() == wire.channel
        && release.sha256().as_slice() == wire.sha256;
    ensure!(
        matches,
        "the proxy returned a different release from the one requested: {}",
        release.summary()
    );
    let digest: [u8; 32] = Sha256::digest(&response.canonical_release).into();
    ensure!(
        response.digest == digest,
        "the proxy's digest does not match the release it returned"
    );

    match SigningStatus::try_from(response.status) {
        Ok(SigningStatus::Signed) => {
            let spki = cli::public_key(client, key).await?;
            cli::verify_p256(&spki, &response.canonical_release, &response.signature)
                .context("over the returned release")?;

            println!("status     SIGNED");
            println!("release    {}", release.summary());
            println!("digest     {}", to_hex(&digest));
            println!("signature  {}", to_hex(&response.signature));
            if response.approvals_received > 0 {
                println!(
                    "approvals  {} of {} required",
                    response.approvals_received, response.approvals_required
                );
            }
            println!("verified   locally, over the decoded release, against {key}'s public key");
            Ok(ExitCode::SUCCESS)
        }
        Ok(SigningStatus::PendingApproval) => {
            println!("status     PENDING_APPROVAL");
            println!("release    {}", release.summary());
            println!("digest     {}", to_hex(&digest));
            println!("reason     {}", response.hold_reason);
            println!(
                "approvals  {} of {}",
                response.approvals_received, response.approvals_required
            );
            println!("next       approvers run `release approve` with their own copy of the file; then resubmit");
            Ok(ExitCode::from(EXIT_HELD))
        }
        _ => bail!("the proxy returned an unknown status {}", response.status),
    }
}

/// Show a held release, decoded here rather than as the proxy summarises it.
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

/// Approve a held release: decode it, check it names the approver's own copy of the
/// file, show it, and sign exactly those bytes.
async fn approve(client: &mut Client, args: &Args) -> Result<ExitCode> {
    let key = args.required("key")?;
    let digest = args.hex32("digest")?;
    let approver = args.required("approver")?;
    let own_copy = hash_file(args)?;
    let signing_key = cli::load_approver_key(args, approver)?;

    let held = match cli::fetch_held(client, key, &digest).await? {
        Ok(held) => held,
        Err(code) => return Ok(code),
    };
    let release = decode_held(&held, key)?;
    print_held(&release, &held, &digest);

    // The check the proxy cannot make: is this the build the approver expects to ship?
    if release.sha256() != own_copy {
        println!(
            "mismatch   your copy of the file is sha256 {}; the held release names {}",
            to_hex(&own_copy),
            to_hex(&release.sha256())
        );
        println!("not approved");
        return Ok(ExitCode::FAILURE);
    }
    println!("file       matches your copy");

    let question = format!(
        "approve {} {} on {} as {approver}",
        release.artifact(),
        release.version(),
        release.channel()
    );
    if !args.flag("yes") && !cli::confirm(&question)? {
        println!("not approved");
        return Ok(ExitCode::FAILURE);
    }
    cli::submit_approval(client, key, &digest, approver, &signing_key, &held).await
}

/// Check a release signature the way an updater would: from the downloaded file and the
/// fields it expects, with nothing but the key's public half.
async fn verify(client: &mut Client, args: &Args) -> Result<ExitCode> {
    let key = args.required("key")?;
    let expected = Release::new(
        key,
        args.required("artifact")?,
        args.required("version")?,
        args.required("channel")?,
        hash_file(args)?,
    )
    .map_err(|e| anyhow!("{e}"))?;
    let signature =
        from_hex(args.required("signature")?).ok_or_else(|| anyhow!("--signature must be hex"))?;

    let spki = cli::public_key(client, key).await?;
    match cli::verify_p256(&spki, &expected.encode(), &signature) {
        Ok(()) => {
            println!("valid      {}", expected.summary());
            Ok(ExitCode::SUCCESS)
        }
        Err(_) => {
            println!(
                "invalid    the signature does not cover this file as {} {} on {}",
                expected.artifact(),
                expected.version(),
                expected.channel()
            );
            Ok(ExitCode::FAILURE)
        }
    }
}

/// Decode a held request as a release from `key`, or refuse to go further.
fn decode_held(held: &Held, key: &str) -> Result<Release> {
    let release = Release::decode(&held.canonical)
        .map_err(|e| anyhow!("the held request is not a well-formed release: {e}"))?;
    ensure!(
        release.key_label() == key,
        "the held release is from key '{}', not '{key}'",
        release.key_label()
    );
    Ok(release)
}

fn print_held(r: &Release, held: &Held, digest: &[u8; 32]) {
    println!("decoded from the release's own bytes:");
    println!("  from         {}", r.key_label());
    println!("  artifact     {}", r.artifact());
    println!("  version      {}", r.version());
    println!("  channel      {}", r.channel());
    println!("  file sha256  {}", to_hex(&r.sha256()));
    cli::print_hold(held, digest);
}
