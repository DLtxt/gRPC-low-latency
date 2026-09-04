//! Who is calling, and what are they allowed to do.
//!
//! Authentication happens at the TLS layer: the server requires a client certificate
//! signed by the configured CA, so an unauthenticated connection is refused before any
//! handler runs. This module covers what comes after -- turning that certificate into a
//! workload identity, and checking that identity against the policy.
//!
//! Authorization is enforced inside the handlers rather than as a tower layer, because
//! the thing being authorized is the *key label*, which lives in the decoded protobuf
//! body. A layer sees bytes, not key labels.

pub mod authorizer;
pub mod identity;
pub mod policy;

pub use authorizer::{Authorizer, AuthzMetrics};
pub use identity::IdentityExtractor;
pub use policy::{Operation, Policy};
