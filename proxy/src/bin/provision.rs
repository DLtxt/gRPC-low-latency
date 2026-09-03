//! Provision the demo keys on a token.
//!
//! Used for the native development and benchmark token, where OpenSC's `pkcs11-tool`
//! is not necessarily installed. Idempotent, so it is safe to run before every session.

use anyhow::Result;
use grpc_low_latency_proxy::pkcs11::provision::ensure_demo_keys;
use grpc_low_latency_proxy::pkcs11::{open_token, TokenConfig};

fn main() -> Result<()> {
    let config = TokenConfig::from_env()?;
    println!("provisioning token '{}'", config.token_label);

    let (_pkcs11, _slot, session) = open_token(&config)?;

    for (label, outcome) in ensure_demo_keys(&session)? {
        println!("  {label}: {outcome:?}");
    }

    session.logout().ok();
    println!("provisioning complete");
    Ok(())
}
