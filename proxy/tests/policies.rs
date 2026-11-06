//! The policies the repository ships must load, and must agree with each other.
//! Otherwise the first anyone hears of a mismatch is the proxy refusing to start.

use std::path::{Path, PathBuf};

use grpc_low_latency_proxy::approval::{check_grants, purpose_map};
use grpc_low_latency_proxy::authz::Policy as AuthzPolicy;
use grpc_low_latency_proxy::pkcs11::Purpose;
use grpc_low_latency_proxy::release::ReleasePolicy;
use grpc_low_latency_proxy::transfer::TransferPolicy;

fn shipped(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../policy")
        .join(name)
}

#[test]
fn shipped_policies_load_and_agree() {
    let authz = AuthzPolicy::load(shipped("authz.toml")).unwrap();
    let transfers = TransferPolicy::load(shipped("transfers.toml")).unwrap();
    let releases = ReleasePolicy::load(shipped("releases.toml")).unwrap();

    assert!(transfers.is_transfer_key("demo-transfer-key"));
    assert!(releases.is_release_key("demo-release-key"));

    let keys = purpose_map(
        transfers
            .key_labels()
            .map(|label| (label.to_string(), Purpose::Transfer))
            .chain(
                releases
                    .key_labels()
                    .map(|label| (label.to_string(), Purpose::Release)),
            ),
    )
    .unwrap();
    check_grants(&authz, &keys).unwrap();
}
