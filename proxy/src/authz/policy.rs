//! The authorization policy: identity x key x operation.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

/// The operations a policy can grant. These mirror the RPCs rather than the underlying
/// PKCS#11 calls, because the policy is about what a *caller* may ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Sign,
    Verify,
    Encrypt,
    Decrypt,
    GetPublicKey,
}

impl Operation {
    pub fn as_str(self) -> &'static str {
        match self {
            Operation::Sign => "sign",
            Operation::Verify => "verify",
            Operation::Encrypt => "encrypt",
            Operation::Decrypt => "decrypt",
            Operation::GetPublicKey => "get_public_key",
        }
    }
}

#[derive(Debug, Deserialize)]
struct PolicyFile {
    #[serde(default)]
    workloads: Vec<WorkloadEntry>,
}

#[derive(Debug, Deserialize)]
struct WorkloadEntry {
    identity: String,
    #[serde(default)]
    #[allow(dead_code)]
    description: Option<String>,
    #[serde(default)]
    grants: Vec<GrantEntry>,
}

#[derive(Debug, Deserialize)]
struct GrantEntry {
    key_label: String,
    operations: Vec<Operation>,
}

/// A compiled policy. Lookups are two hash probes and a set membership test, because
/// this runs on every request inside a 2 ms latency budget.
#[derive(Debug, Default)]
pub struct Policy {
    grants: HashMap<String, HashMap<String, HashSet<Operation>>>,
}

impl Policy {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read policy file {}", path.display()))?;
        Self::parse(&text)
            .with_context(|| format!("failed to parse policy file {}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Self> {
        let file: PolicyFile = toml::from_str(text).context("invalid TOML")?;

        let mut grants: HashMap<String, HashMap<String, HashSet<Operation>>> = HashMap::new();
        for workload in file.workloads {
            let per_key = grants.entry(workload.identity).or_default();
            for grant in workload.grants {
                per_key
                    .entry(grant.key_label)
                    .or_default()
                    .extend(grant.operations);
            }
        }

        Ok(Self { grants })
    }

    /// Is `identity` permitted to perform `operation` on `key_label`?
    ///
    /// Absence is denial at every level: unknown identity, unknown key for a known
    /// identity, or a known key without this operation all return false.
    pub fn is_allowed(&self, identity: &str, key_label: &str, operation: Operation) -> bool {
        self.grants
            .get(identity)
            .and_then(|keys| keys.get(key_label))
            .is_some_and(|ops| ops.contains(&operation))
    }

    pub fn identity_count(&self) -> usize {
        self.grants.len()
    }

    pub fn grant_count(&self) -> usize {
        self.grants
            .values()
            .flat_map(|keys| keys.values())
            .map(HashSet::len)
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[[workloads]]
identity = "spiffe://local/ns/default/sa/payments"
grants = [
    { key_label = "demo-ec-p256", operations = ["sign", "verify"] },
]

[[workloads]]
identity = "spiffe://local/ns/default/sa/batch"
grants = [
    { key_label = "demo-ec-p256", operations = ["sign"] },
]
"#;

    #[test]
    fn grants_what_is_listed() {
        let policy = Policy::parse(SAMPLE).unwrap();
        assert!(policy.is_allowed(
            "spiffe://local/ns/default/sa/payments",
            "demo-ec-p256",
            Operation::Sign
        ));
    }

    #[test]
    fn denies_operation_not_granted() {
        let policy = Policy::parse(SAMPLE).unwrap();
        assert!(!policy.is_allowed(
            "spiffe://local/ns/default/sa/batch",
            "demo-ec-p256",
            Operation::Verify
        ));
    }

    #[test]
    fn denies_key_not_granted() {
        let policy = Policy::parse(SAMPLE).unwrap();
        assert!(!policy.is_allowed(
            "spiffe://local/ns/default/sa/batch",
            "demo-rsa-2048",
            Operation::Sign
        ));
    }

    #[test]
    fn denies_unknown_identity() {
        let policy = Policy::parse(SAMPLE).unwrap();
        assert!(!policy.is_allowed("spiffe://local/ns/default/sa/nobody", "demo-ec-p256", Operation::Sign));
    }

    /// An empty policy must deny everything rather than fail open.
    #[test]
    fn empty_policy_denies_everything() {
        let policy = Policy::parse("").unwrap();
        assert!(!policy.is_allowed("anyone", "any-key", Operation::Sign));
    }

    /// A typo in an operation name must be a load-time error, not a silently dropped
    /// grant that looks like it was applied.
    #[test]
    fn unknown_operation_is_rejected() {
        let bad = r#"
[[workloads]]
identity = "x"
grants = [{ key_label = "k", operations = ["singn"] }]
"#;
        assert!(Policy::parse(bad).is_err());
    }
}
