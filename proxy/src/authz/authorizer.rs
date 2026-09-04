//! Binding identity extraction and policy evaluation into one check.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tonic::{Request, Status};

use super::identity::IdentityExtractor;
use super::policy::{Operation, Policy};

#[derive(Default, Debug)]
pub struct AuthzMetrics {
    pub allowed_total: AtomicU64,
    pub denied_total: AtomicU64,
    pub unauthenticated_total: AtomicU64,
}

pub struct Authorizer {
    extractor: IdentityExtractor,
    policy: Policy,
    metrics: AuthzMetrics,
}

impl Authorizer {
    pub fn new(policy: Policy) -> Self {
        Self {
            extractor: IdentityExtractor::new(),
            policy,
            metrics: AuthzMetrics::default(),
        }
    }

    pub fn metrics(&self) -> &AuthzMetrics {
        &self.metrics
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Establish the caller's identity and check it against the policy.
    ///
    /// The denial message names the identity, key, and operation. That is deliberate:
    /// this is not a secret being protected from the caller -- they already know which
    /// key they asked for -- and a vague "permission denied" turns a one-line policy fix
    /// into a debugging session.
    pub fn authorize<T>(
        &self,
        request: &Request<T>,
        key_label: &str,
        operation: Operation,
    ) -> Result<Arc<str>, Status> {
        let identity = self.extractor.identify(request).inspect_err(|_| {
            self.metrics
                .unauthenticated_total
                .fetch_add(1, Ordering::Relaxed);
        })?;

        if self
            .policy
            .is_allowed(&identity, key_label, operation)
        {
            self.metrics.allowed_total.fetch_add(1, Ordering::Relaxed);
            return Ok(identity);
        }

        self.metrics.denied_total.fetch_add(1, Ordering::Relaxed);

        // The structured fields are what plan.md 4.5 wants exported as
        // hsm_authz_denied_total{identity, key_label, op}; M7 wires them to Prometheus.
        tracing::warn!(
            identity = %identity,
            key_label,
            op = operation.as_str(),
            "authorization denied"
        );

        Err(Status::permission_denied(format!(
            "identity '{identity}' is not permitted to {} key '{key_label}'",
            operation.as_str()
        )))
    }
}
