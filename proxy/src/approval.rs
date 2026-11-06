//! Approvals: how a request held for people becomes one the key will sign.
//!
//! Shared by every purpose-bound key. Transfer keys (M10) and release keys (M11) check
//! different things before deciding to hold a request, but they hold it and approve it
//! in exactly the same way, and this module is that way:
//!
//! * A held request is kept, with a fresh random identifier, until a quorum of approvers
//!   has signed off or it lapses. It belongs to the identity that asked for it; once it
//!   is approved, that identity collects the signature by asking again.
//! * An approval is a signature by the approver's own P-256 key over the approval
//!   message: a tag, the hold's identifier, then the request's full canonical bytes. The
//!   proxy holds only the public halves, so it cannot approve anything by itself, and an
//!   approval counts for one hold of one request.
//!
//! The approval message is the same for every kind of request. An approval of a transfer
//! cannot count as an approval of a release because the canonical bytes it covers begin
//! with their own format's domain tag.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Context, Result};
use rand::RngCore;
use serde::Deserialize;

use crate::authz::{Operation, Policy as AuthzPolicy};
use crate::encoding::{Field, FormatError};
use crate::pkcs11::Purpose;

/// Domain tag for approvals. Distinct from every request format's tag, so an approver's
/// signature over a request can never be replayed as a signature *of* that request.
pub const APPROVAL_TAG: &[u8; 16] = b"gll-approval-v1\0";

/// Length of the random identifier the proxy gives each hold.
pub const HOLD_ID_LEN: usize = 16;

/// The bytes an approver signs: the approval tag, the hold's identifier, then the whole
/// canonical request.
///
/// The whole request rather than its digest, so that a hardware signer can decode and
/// show what it is approving. A device asked to sign a bare digest has nothing to
/// display, which is exactly the blind signing the approval step exists to prevent.
///
/// The hold identifier is random and fresh for every hold, so an approval counts once,
/// for one hold. Without it, an approval would cover the request's bytes for good: once
/// a request had been approved and signed, anyone who had relayed the approvals could
/// replay them onto a later request for the identical thing.
pub fn approval_message(hold_id: &[u8; HOLD_ID_LEN], canonical: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(APPROVAL_TAG.len() + HOLD_ID_LEN + canonical.len());
    message.extend_from_slice(APPROVAL_TAG);
    message.extend_from_slice(hold_id);
    message.extend_from_slice(canonical);
    message
}

/// Approver names: short, lowercase, unambiguous.
const APPROVER: Field = Field {
    name: "approver",
    max_len: 32,
    allowed: |b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-',
    description: "lowercase letters, digits and '-'",
};

pub fn check_approver(value: &str) -> Result<(), FormatError> {
    APPROVER.check(value)
}

/// Something a purpose-bound key signs: a transfer, or a release.
pub trait Statement: Clone + std::fmt::Debug {
    /// The exact bytes the key signs. Built by the proxy from fields it checked, never
    /// supplied by a caller.
    fn encode(&self) -> Vec<u8>;

    /// SHA-256 of `encode()`: what approvers and logs call the request.
    fn digest(&self) -> [u8; 32];

    /// One line, for logs.
    fn summary(&self) -> String;
}

/// Why a hold, or an approval of one, was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApprovalRefusal {
    #[error("'{0}' is not a key that holds requests for approval")]
    NotApprovable(String),

    #[error("{0}")]
    Invalid(String),

    #[error("{limit} requests are already held for approval on this key")]
    TooManyHolds { limit: usize },

    #[error("this request is held for a different requester")]
    HeldForAnotherRequester,

    #[error("nothing is held with that digest; it may have expired or been collected")]
    NoSuchHold,

    /// The approval names a hold that has since been collected, expired, or replaced by
    /// a new request for the same thing. The new hold needs approving afresh.
    #[error("that hold has been collected or replaced; review the request again")]
    StaleHold,

    #[error("'{approver}' is not an approver for '{key_label}'")]
    NotAnApprover { approver: String, key_label: String },

    #[error("no public key is loaded for approver '{0}'")]
    ApproverKeyMissing(String),

    #[error("the approval signature does not verify for approver '{0}'")]
    BadApprovalSignature(String),

    #[error("approval state is unavailable after an internal error")]
    Internal,
}

impl ApprovalRefusal {
    /// A fixed label for metrics. Never derived from the request, which is
    /// caller-controlled and would make the label set unbounded.
    pub fn reason(&self) -> &'static str {
        match self {
            ApprovalRefusal::NotApprovable(_) => "not_approvable",
            ApprovalRefusal::Invalid(_) => "invalid",
            ApprovalRefusal::TooManyHolds { .. } => "holds_full",
            ApprovalRefusal::HeldForAnotherRequester => "other_requester",
            ApprovalRefusal::NoSuchHold => "no_hold",
            ApprovalRefusal::StaleHold => "stale_hold",
            ApprovalRefusal::NotAnApprover { .. } => "not_approver",
            ApprovalRefusal::ApproverKeyMissing(_) => "approver_key_missing",
            ApprovalRefusal::BadApprovalSignature(_) => "bad_signature",
            ApprovalRefusal::Internal => "internal",
        }
    }
}

/// How a key holds requests: who may approve, how many must, how long a hold lasts, and
/// how many may wait at once.
#[derive(Debug, Clone)]
pub struct HoldRules {
    pub approvers: BTreeSet<String>,
    pub quorum: usize,
    pub hold_ttl: Duration,
    pub max_pending: usize,
}

impl HoldRules {
    /// Compile a key's approval settings from a policy file, checking them against the
    /// approvers the file registers.
    pub fn compile(
        key_label: &str,
        approvers: Vec<String>,
        quorum: usize,
        hold_ttl_secs: u64,
        max_pending: usize,
        registered: &BTreeSet<String>,
    ) -> Result<Self> {
        ensure!(!approvers.is_empty(), "approvers must not be empty");
        let mut names = BTreeSet::new();
        for name in approvers {
            ensure!(
                registered.contains(&name),
                "approver '{name}' is not registered under [[approvers]]"
            );
            ensure!(
                names.insert(name.clone()),
                "approver '{name}' is listed twice"
            );
        }
        ensure!(
            (1..=names.len()).contains(&quorum),
            "quorum must be between 1 and the number of approvers ({}), got {quorum}",
            names.len()
        );
        if quorum == 1 {
            tracing::warn!(
                key = %key_label,
                "quorum 1: a single approver can release anything this key holds"
            );
        }
        ensure!(
            (1..=86_400).contains(&hold_ttl_secs),
            "hold_ttl_secs must be between 1 and 86400"
        );
        ensure!(max_pending >= 1, "max_pending must be at least 1");

        Ok(Self {
            approvers: names,
            quorum,
            hold_ttl: Duration::from_secs(hold_ttl_secs),
            max_pending,
        })
    }
}

/// An `[[approvers]]` entry in a policy file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproverEntry {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// The approvers a policy file registers: valid names, each once.
pub fn register_approvers(entries: Vec<ApproverEntry>) -> Result<BTreeSet<String>> {
    let mut approvers = BTreeSet::new();
    for entry in entries {
        check_approver(&entry.name)?;
        ensure!(
            approvers.insert(entry.name.clone()),
            "approver '{}' is registered twice",
            entry.name
        );
    }
    Ok(approvers)
}

/// A held request, as reported to requesters and approvers.
#[derive(Debug, Clone)]
pub struct HoldStatus<S> {
    pub statement: S,
    /// Fresh for every hold, and part of what approvers sign.
    pub hold_id: [u8; HOLD_ID_LEN],
    /// Why it was held, as a fixed label for metrics.
    pub kind: &'static str,
    /// Why it was held, for people.
    pub reason: String,
    pub required: usize,
    pub approved_by: Vec<String>,
    pub expires_in: Duration,
}

impl<S> HoldStatus<S> {
    pub fn received(&self) -> usize {
        self.approved_by.len()
    }

    pub fn approved(&self) -> bool {
        self.received() >= self.required
    }
}

#[derive(Debug)]
pub struct Hold<S> {
    statement: S,
    id: [u8; HOLD_ID_LEN],
    requester: Arc<str>,
    kind: &'static str,
    reason: String,
    expires: Instant,
    /// Approver name to signature. The signatures are kept, not just counted: they are
    /// the evidence of who agreed to what.
    approvals: BTreeMap<String, Vec<u8>>,
}

impl<S: Statement> Hold<S> {
    pub fn statement(&self) -> &S {
        &self.statement
    }

    pub fn requester(&self) -> &str {
        &self.requester
    }

    pub fn approval_count(&self) -> usize {
        self.approvals.len()
    }

    /// Who approved, for the audit log.
    pub fn approvers(&self) -> Vec<String> {
        self.approvals.keys().cloned().collect()
    }

    pub fn status(&self, required: usize, now: Instant) -> HoldStatus<S> {
        HoldStatus {
            statement: self.statement.clone(),
            hold_id: self.id,
            kind: self.kind,
            reason: self.reason.clone(),
            required,
            approved_by: self.approvers(),
            expires_in: self.expires.saturating_duration_since(now),
        }
    }
}

/// One key's held requests, by digest.
#[derive(Debug)]
pub struct Holds<S> {
    held: HashMap<[u8; 32], Hold<S>>,
}

impl<S> Default for Holds<S> {
    fn default() -> Self {
        Self {
            held: HashMap::new(),
        }
    }
}

impl<S: Statement> Holds<S> {
    pub fn expire(&mut self, now: Instant) {
        self.held.retain(|_, hold| hold.expires > now);
    }

    pub fn len(&self) -> usize {
        self.held.len()
    }

    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    pub fn get(&self, digest: &[u8; 32]) -> Option<&Hold<S>> {
        self.held.get(digest)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Hold<S>> {
        self.held.values()
    }

    /// Hold `statement` for `requester` until enough approvers sign off or the hold
    /// lapses.
    pub fn open(
        &mut self,
        statement: S,
        requester: &Arc<str>,
        kind: &'static str,
        reason: String,
        rules: &HoldRules,
        now: Instant,
    ) -> Result<HoldStatus<S>, ApprovalRefusal> {
        if self.held.len() >= rules.max_pending {
            return Err(ApprovalRefusal::TooManyHolds {
                limit: rules.max_pending,
            });
        }
        let mut id = [0u8; HOLD_ID_LEN];
        rand::rngs::OsRng.fill_bytes(&mut id);
        let digest = statement.digest();
        let hold = Hold {
            statement,
            id,
            requester: Arc::clone(requester),
            kind,
            reason,
            expires: now + rules.hold_ttl,
            approvals: BTreeMap::new(),
        };
        let status = hold.status(rules.quorum, now);
        self.held.insert(digest, hold);
        Ok(status)
    }

    /// Remove a hold in order to sign what it held.
    pub fn take(&mut self, digest: &[u8; 32]) -> Option<Hold<S>> {
        self.held.remove(digest)
    }

    /// Put back a hold whose signature never happened, so a transient HSM error does not
    /// cost the approvers their work.
    pub fn restore(&mut self, hold: Hold<S>) {
        self.held.insert(hold.statement.digest(), hold);
    }

    fn live(&mut self, digest: &[u8; 32], now: Instant) -> Result<&mut Hold<S>, ApprovalRefusal> {
        self.expire(now);
        self.held.get_mut(digest).ok_or(ApprovalRefusal::NoSuchHold)
    }
}

/// Access to a guard's holds under its lock, so that `pending` and `approve` run the
/// same protocol against every kind of purpose-bound key.
pub trait HoldStore<S> {
    /// Run `f` on `key_label`'s holds with the guard's state locked. A key that has never
    /// held anything has no holds to find.
    fn with_holds<R>(
        &self,
        key_label: &str,
        f: impl FnOnce(&mut Holds<S>) -> Result<R, ApprovalRefusal>,
    ) -> Result<R, ApprovalRefusal>;
}

/// A held request, for an approver to review.
pub fn pending<S: Statement>(
    store: &impl HoldStore<S>,
    key_label: &str,
    rules: &HoldRules,
    digest: &[u8; 32],
    now: Instant,
) -> Result<HoldStatus<S>, ApprovalRefusal> {
    store.with_holds(key_label, |holds| {
        Ok(holds.live(digest, now)?.status(rules.quorum, now))
    })
}

/// Record one approver's signature on a held request.
///
/// The signature must verify over the approval message for *this* hold of *this*
/// request, under the key registered for *this* approver. A signature made for another
/// request, for an earlier hold of the same one, by another approver's key, or over
/// anything but the full request, does not count.
#[allow(clippy::too_many_arguments)]
pub fn approve<S: Statement>(
    store: &impl HoldStore<S>,
    keys: &ApproverKeys,
    key_label: &str,
    rules: &HoldRules,
    digest: &[u8; 32],
    hold_id: &[u8],
    approver: &str,
    signature: &[u8],
    now: Instant,
) -> Result<HoldStatus<S>, ApprovalRefusal> {
    check_approver(approver).map_err(|e| ApprovalRefusal::Invalid(e.to_string()))?;
    if !rules.approvers.contains(approver) {
        return Err(ApprovalRefusal::NotAnApprover {
            approver: approver.to_string(),
            key_label: key_label.to_string(),
        });
    }
    let point = keys
        .point(approver)
        .ok_or_else(|| ApprovalRefusal::ApproverKeyMissing(approver.to_string()))?;

    // The bytes under the lock, the signature check outside it, so a stream of bogus
    // approvals cannot hold up signing behind ECDSA verification.
    let (id, canonical) = store.with_holds(key_label, |holds| {
        let hold = holds.live(digest, now)?;
        Ok((hold.id, hold.statement.encode()))
    })?;
    if hold_id != id.as_slice() {
        return Err(ApprovalRefusal::StaleHold);
    }

    let message = approval_message(&id, &canonical);
    let key =
        ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_FIXED, point);
    if key.verify(&message, signature).is_err() {
        return Err(ApprovalRefusal::BadApprovalSignature(approver.to_string()));
    }

    // Looked up again: meanwhile the hold may have lapsed, or been collected and
    // requested anew. A new hold has a new identifier, which this signature does not
    // cover.
    store.with_holds(key_label, |holds| {
        let hold = holds.live(digest, now)?;
        if hold.id != id {
            return Err(ApprovalRefusal::StaleHold);
        }
        hold.approvals
            .insert(approver.to_string(), signature.to_vec());
        Ok(hold.status(rules.quorum, now))
    })
}

/// Approver public keys, as uncompressed SEC1 points ready for `ring`.
///
/// The proxy holds only the public halves. An approval is unforgeable by anything
/// without the approver's private key -- including this process, and including the
/// workload that made the request.
#[derive(Debug, Default)]
pub struct ApproverKeys {
    points: HashMap<String, Vec<u8>>,
}

impl ApproverKeys {
    pub fn none() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, name: &str, key: &p256::PublicKey) {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        self.points.insert(
            name.to_string(),
            key.to_encoded_point(false).as_bytes().to_vec(),
        );
    }

    /// Read `<dir>/<name>.pub` -- a PEM SubjectPublicKeyInfo for a P-256 key -- for each
    /// name, returning the keys that loaded and a description of each that did not.
    ///
    /// Missing keys are reported rather than fatal. Without an approver's key that
    /// approver's signatures cannot verify, so held requests fail closed; the proxy can
    /// still serve everything else, including requests that need no approval.
    pub fn load<'a>(dir: &Path, names: impl IntoIterator<Item = &'a str>) -> (Self, Vec<String>) {
        use p256::pkcs8::DecodePublicKey;

        let mut keys = Self::none();
        let mut problems = Vec::new();
        for name in names {
            let path = dir.join(format!("{name}.pub"));
            let loaded = std::fs::read_to_string(&path)
                .with_context(|| format!("cannot read {}", path.display()))
                .and_then(|pem| {
                    p256::PublicKey::from_public_key_pem(&pem).map_err(|e| {
                        anyhow::anyhow!("{} is not a P-256 public key: {e}", path.display())
                    })
                });
            match loaded {
                Ok(key) => keys.insert(name, &key),
                Err(e) => problems.push(format!("approver '{name}': {e:#}")),
            }
        }
        (keys, problems)
    }

    pub fn len(&self) -> usize {
        self.points.len()
    }

    pub fn is_empty(&self) -> bool {
        self.points.is_empty()
    }

    fn point(&self, name: &str) -> Option<&[u8]> {
        self.points.get(name).map(Vec::as_slice)
    }
}

/// The authorization grant that requests signatures from a key of this purpose.
pub fn sign_operation(purpose: Purpose) -> Operation {
    match purpose {
        Purpose::Transfer => Operation::SignTransfer,
        Purpose::Release => Operation::SignRelease,
    }
}

/// Every purpose-bound key the policies name, by label. A label that two policies both
/// claim is an error: a key has one purpose, and the token marks which.
pub fn purpose_map(
    claims: impl IntoIterator<Item = (String, Purpose)>,
) -> Result<HashMap<String, Purpose>> {
    let mut keys = HashMap::new();
    for (label, purpose) in claims {
        if let Some(other) = keys.insert(label.clone(), purpose) {
            bail!(
                "'{label}' is configured as both a {} key and a {} key",
                other.as_str(),
                purpose.as_str()
            );
        }
    }
    Ok(keys)
}

/// Check the authorization policy against the purpose-bound keys, refusing grants that
/// would undo them.
///
/// * `sign` on a purpose-bound key is the blind-signing path these keys exist to close,
///   so granting it is a configuration error, not a policy choice.
/// * The workload that requests signatures from a key must not be one that relays its
///   approvals. Approvals are authenticated by the approver's own signature, so this is
///   not what makes them unforgeable -- it keeps the two roles from collapsing into one
///   compromised service holding both.
/// * A purpose's grant on a key of another purpose, or on an ordinary key, would
///   silently do nothing.
pub fn check_grants(authz: &AuthzPolicy, keys: &HashMap<String, Purpose>) -> Result<()> {
    for (label, &purpose) in keys {
        let request = sign_operation(purpose);
        let raw = authz.identities_granted(label, Operation::Sign);
        ensure!(
            raw.is_empty(),
            "{} granted 'sign' on {} key '{label}'; {} keys sign only through '{}'",
            raw.join(", "),
            purpose.as_str(),
            purpose.as_str(),
            request.as_str()
        );

        let requesters: HashSet<_> = authz
            .identities_granted(label, request)
            .into_iter()
            .collect();
        for identity in authz.identities_granted(label, Operation::Approve) {
            ensure!(
                !requesters.contains(identity),
                "{identity} is granted both '{}' and 'approve' on '{label}'; the workload \
                 that requests signatures must not also submit their approvals",
                request.as_str()
            );
        }
    }

    for purpose in Purpose::ALL {
        let operation = sign_operation(purpose);
        for label in authz.keys_with(operation) {
            if keys.get(label) != Some(&purpose) {
                bail!(
                    "'{}' is granted on '{label}', which is not a {} key",
                    operation.as_str(),
                    purpose.as_str()
                );
            }
        }
    }
    for label in authz.keys_with(Operation::Approve) {
        ensure!(
            keys.contains_key(label),
            "'approve' is granted on '{label}', which is neither a transfer key nor a \
             release key, so it holds nothing to approve"
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_message_is_tag_then_hold_then_request() {
        let canonical = b"gll-release-v1\0 and the rest".to_vec();
        let hold = [7u8; HOLD_ID_LEN];
        let message = approval_message(&hold, &canonical);
        assert_eq!(&message[..16], APPROVAL_TAG);
        assert_eq!(&message[16..32], &hold);
        assert_eq!(&message[32..], canonical.as_slice());
    }

    fn keys() -> HashMap<String, Purpose> {
        purpose_map([
            ("transfer-key".to_string(), Purpose::Transfer),
            ("release-key".to_string(), Purpose::Release),
        ])
        .unwrap()
    }

    const AUTHZ: &str = r#"
[[workloads]]
identity = "payments"
grants = [{ key_label = "transfer-key", operations = ["sign_transfer", "verify"] }]

[[workloads]]
identity = "treasury"
grants = [{ key_label = "transfer-key", operations = ["approve"] }]

[[workloads]]
identity = "ci"
grants = [{ key_label = "release-key", operations = ["sign_release", "get_public_key"] }]

[[workloads]]
identity = "release-review"
grants = [{ key_label = "release-key", operations = ["approve"] }]
"#;

    fn check(authz: &str) -> String {
        match check_grants(&AuthzPolicy::parse(authz).unwrap(), &keys()) {
            Ok(()) => "ok".to_string(),
            Err(e) => format!("{e:#}"),
        }
    }

    #[test]
    fn accepts_separate_requesters_and_approvers() {
        assert_eq!(check(AUTHZ), "ok");
    }

    /// The blind-signing path must not be grantable on a purpose-bound key at all.
    #[test]
    fn rejects_raw_sign_grant_on_either_kind_of_key() {
        let transfer = AUTHZ.replace(r#"["sign_transfer", "verify"]"#, r#"["sign", "verify"]"#);
        assert!(check(&transfer).contains("granted 'sign' on transfer key"));
        let release = AUTHZ.replace(
            r#"["sign_release", "get_public_key"]"#,
            r#"["sign", "get_public_key"]"#,
        );
        assert!(check(&release).contains("granted 'sign' on release key"));
    }

    #[test]
    fn rejects_requester_that_also_approves() {
        let authz = AUTHZ.replace(
            r#"["sign_release", "get_public_key"]"#,
            r#"["sign_release", "approve"]"#,
        );
        assert!(check(&authz).contains("both 'sign_release' and 'approve'"));
    }

    #[test]
    fn rejects_a_purpose_grant_on_the_wrong_key() {
        let ordinary = format!(
            "{AUTHZ}\n[[workloads]]\nidentity = \"batch\"\ngrants = [{{ key_label = \
             \"demo-ec-p256\", operations = [\"sign_transfer\"] }}]\n"
        );
        assert!(check(&ordinary).contains("not a transfer key"));
        let crossed = AUTHZ.replace(
            r#"key_label = "release-key", operations = ["sign_release""#,
            r#"key_label = "transfer-key", operations = ["sign_release""#,
        );
        assert!(check(&crossed).contains("not a release key"));
    }

    #[test]
    fn rejects_approve_on_an_ordinary_key() {
        let authz = AUTHZ.replace(
            r#"{ key_label = "release-key", operations = ["approve"] }"#,
            r#"{ key_label = "demo-ec-p256", operations = ["approve"] }"#,
        );
        assert!(check(&authz).contains("holds nothing to approve"));
    }

    #[test]
    fn a_key_has_one_purpose() {
        let doubled = purpose_map([
            ("key".to_string(), Purpose::Transfer),
            ("key".to_string(), Purpose::Release),
        ]);
        assert!(format!("{:#}", doubled.unwrap_err()).contains("both a transfer key"));
    }
}
