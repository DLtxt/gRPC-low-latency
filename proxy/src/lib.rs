//! gRPC-low-latency proxy: a gRPC cryptographic proxy in front of a PKCS#11 token.
//!
//! PKCS#11 is an in-process C API, so everything here ultimately runs inside this
//! process's address space via `cryptoki`. See `plan.md` 4.1 for why that rules out
//! the obvious "connect to the HSM container" design.
//!
//! Stateless except for purpose-bound keys -- transfer keys (`transfer`) and release keys
//! (`release`) -- whose limits, records and held approvals live in memory. See
//! docs/m10-transfer-keys.md and docs/m11-release-keys.md for what that costs.

pub mod approval;
pub mod authz;
pub mod cache;
pub mod cli;
pub mod crypto;
pub mod encoding;
pub mod grpc;
pub mod pkcs11;
pub mod proto;
pub mod release;
pub mod resilience;
pub mod telemetry;
pub mod transfer;
pub mod velocity;
