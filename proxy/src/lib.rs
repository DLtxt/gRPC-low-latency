//! gRPC-low-latency proxy: a gRPC cryptographic proxy in front of a PKCS#11 token.
//!
//! PKCS#11 is an in-process C API, so everything here ultimately runs inside this
//! process's address space via `cryptoki`. See `plan.md` 4.1 for why that rules out
//! the obvious "connect to the HSM container" design.
//!
//! Stateless except for transfer keys (`transfer`), whose limits and held approvals live
//! in memory -- see docs/m10-transfer-keys.md for what that costs.

pub mod authz;
pub mod cache;
pub mod crypto;
pub mod grpc;
pub mod pkcs11;
pub mod proto;
pub mod resilience;
pub mod telemetry;
pub mod transfer;
