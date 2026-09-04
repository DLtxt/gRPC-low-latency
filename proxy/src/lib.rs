//! gRPC-low-latency proxy: a stateless gRPC cryptographic proxy in front of a
//! PKCS#11 token.
//!
//! PKCS#11 is an in-process C API, so everything here ultimately runs inside this
//! process's address space via `cryptoki`. See `plan.md` 4.1 for why that rules out
//! the obvious "connect to the HSM container" design.

pub mod authz;
pub mod cache;
pub mod crypto;
pub mod grpc;
pub mod pkcs11;
pub mod proto;
