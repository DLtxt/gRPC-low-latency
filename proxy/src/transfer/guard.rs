//! The transfer guard: for each requested transfer, sign it now, hold it for approval,
//! or refuse it -- and keep the state those decisions depend on.
//!
//! The order of the checks is the design:
//!
//! 1. **Hard limits** -- configured asset, allowlisted destination, per-transfer cap.
//!    Refused whatever anyone approves. Approval is for transfers that are unusual, not
//!    for transfers the policy forbids.
//! 2. **Holds** -- above the approval threshold, or past the hourly auto-sign budget.
//!    Not refused: held until a quorum of approvers signs off. A drain stalls at the
//!    budget, but legitimate work can still get through with people in the loop.
//! 3. **Rate** -- signatures per minute, approved or not. A burst like the fifty
//!    delegations signed in one go against Binance is refused outright.
//!
//! The budget and rate checks and the reservation that records a signature against
//! them happen under one lock, so two concurrent requests cannot both see the last of
//! the budget and both be signed. The signature itself happens outside the lock; if it
//! fails, `release` hands the reservation back.
//!
//! Holding and approving work as they do for every purpose-bound key, in
//! `crate::approval`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use super::canonical::{parse_amount, Transfer};
use super::policy::{KeyRules, TransferPolicy};
use crate::approval::{self, ApprovalRefusal, ApproverKeys, Hold, HoldStatus, HoldStore, Holds};
use crate::velocity::{Mark, Window};

/// A transfer as the caller described it, before any of it has been checked.
pub struct TransferRequest<'a> {
    pub chain: &'a str,
    pub asset: &'a str,
    pub destination: &'a str,
    pub amount: &'a str,
    pub nonce: u64,
}

/// Why a transfer was refused.
///
/// Messages name what was wrong. As with authorization denials, none of this is secret
/// from the caller -- they know what they asked for -- and a vague refusal turns a
/// one-line fix into an investigation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("'{0}' is not a transfer key")]
    NotATransferKey(String),

    #[error("{0}")]
    Invalid(String),

    #[error("{asset:?} on {chain:?} is not configured for this key")]
    AssetNotAllowed { chain: String, asset: String },

    #[error("destination {destination} is not on the allowlist for {asset} on {chain}")]
    DestinationNotAllowed {
        destination: String,
        chain: String,
        asset: String,
    },

    #[error(
        "{amount} {asset} is above the {max} {asset} per-transfer cap; approval cannot lift it"
    )]
    OverMaxPerTransfer {
        amount: String,
        max: String,
        asset: String,
    },

    #[error("this key has signed {limit} transfers in the last minute, its limit")]
    RateLimited { limit: u32 },

    /// A refusal from holding or collecting it: too many held, or held for someone else.
    #[error(transparent)]
    Approval(#[from] ApprovalRefusal),

    #[error("transfer state is unavailable after an internal error")]
    Internal,
}

impl Refusal {
    /// A fixed label for metrics. Never derived from the request, which is
    /// caller-controlled and would make the label set unbounded.
    pub fn reason(&self) -> &'static str {
        match self {
            Refusal::NotATransferKey(_) => "not_transfer_key",
            Refusal::Invalid(_) => "invalid",
            Refusal::AssetNotAllowed { .. } => "asset",
            Refusal::DestinationNotAllowed { .. } => "destination",
            Refusal::OverMaxPerTransfer { .. } => "over_cap",
            Refusal::RateLimited { .. } => "rate",
            Refusal::Approval(refusal) => refusal.reason(),
            Refusal::Internal => "internal",
        }
    }
}

/// What to do with a transfer.
#[derive(Debug)]
pub enum Outcome {
    /// Sign `transfer` now. If the signature fails, hand `reservation` back with
    /// `TransferGuard::release`.
    Sign {
        transfer: Transfer,
        reservation: Reservation,
    },
    /// Held until enough approvers sign off.
    Held(HoldStatus<Transfer>),
}

/// Why a transfer was held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldKind {
    /// Above the asset's approval threshold.
    Threshold,
    /// Would pass the hourly auto-sign budget.
    Budget,
}

impl HoldKind {
    /// A stable, low-cardinality label for metrics.
    pub fn as_str(self) -> &'static str {
        match self {
            HoldKind::Threshold => "threshold",
            HoldKind::Budget => "budget",
        }
    }
}

/// A signature counted against the rate and the budget before it was made.
#[derive(Debug)]
#[must_use = "a reservation must be released if the signature fails"]
pub struct Reservation {
    key_label: String,
    chain: String,
    asset: String,
    minute: Mark,
    hour: Mark,
    /// The hold this signature releases. Put back if signing fails, so a transient
    /// HSM error does not cost the approvers their work. Boxed because it is rare: only
    /// approved transfers carry one, and every other signature should not pay for it.
    released: Option<Box<Hold<Transfer>>>,
}

impl Reservation {
    /// Who approved the released transfer, for the audit log.
    pub fn approvers(&self) -> Vec<String> {
        self.released
            .as_ref()
            .map(|hold| hold.approvers())
            .unwrap_or_default()
    }
}

#[derive(Debug)]
struct KeyState {
    origin: Instant,
    per_minute: Window,
    hourly: HashMap<(String, String), Window>,
    holds: Holds<Transfer>,
}

impl KeyState {
    fn new(origin: Instant) -> Self {
        Self {
            origin,
            per_minute: Window::per_minute(origin),
            hourly: HashMap::new(),
            holds: Holds::default(),
        }
    }

    fn expire(&mut self, now: Instant) {
        self.holds.expire(now);
    }

    fn hourly(&mut self, chain: &str, asset: &str) -> &mut Window {
        let origin = self.origin;
        self.hourly
            .entry((chain.to_string(), asset.to_string()))
            .or_insert_with(|| Window::per_hour(origin))
    }

    fn check_rate(&self, rules: &KeyRules, now: Instant) -> Result<(), Refusal> {
        if self.per_minute.total(now) >= u128::from(rules.max_transfers_per_minute) {
            return Err(Refusal::RateLimited {
                limit: rules.max_transfers_per_minute,
            });
        }
        Ok(())
    }

    fn reserve(
        &mut self,
        transfer: &Transfer,
        now: Instant,
        released: Option<Box<Hold<Transfer>>>,
    ) -> Reservation {
        let minute = self.per_minute.add(now, 1);
        let hour = self
            .hourly(transfer.chain(), transfer.asset())
            .add(now, transfer.amount());
        Reservation {
            key_label: transfer.key_label().to_string(),
            chain: transfer.chain().to_string(),
            asset: transfer.asset().to_string(),
            minute,
            hour,
            released,
        }
    }
}

pub struct TransferGuard {
    policy: TransferPolicy,
    approver_keys: ApproverKeys,
    /// Common origin for every window, so their buckets line up.
    origin: Instant,
    /// One lock for all keys. Transfers are bounded by `max_transfers_per_minute`, so
    /// this is never the hot path, and one lock makes every check-and-reserve atomic
    /// without having to reason about lock ordering.
    state: Mutex<HashMap<String, KeyState>>,
}

impl TransferGuard {
    pub fn new(policy: TransferPolicy, approver_keys: ApproverKeys) -> Self {
        Self {
            policy,
            approver_keys,
            origin: Instant::now(),
            state: Mutex::new(HashMap::new()),
        }
    }

    pub fn policy(&self) -> &TransferPolicy {
        &self.policy
    }

    pub fn is_transfer_key(&self, key_label: &str) -> bool {
        self.policy.is_transfer_key(key_label)
    }

    /// A poisoned lock means a panic mid-update, so the state may be half-written.
    /// For limits on money the safe response is to stop signing, not to guess.
    fn lock(&self) -> Result<MutexGuard<'_, HashMap<String, KeyState>>, Refusal> {
        self.state.lock().map_err(|_| Refusal::Internal)
    }

    /// Decide what to do with a requested transfer.
    pub fn submit(
        &self,
        requester: &Arc<str>,
        key_label: &str,
        request: &TransferRequest<'_>,
        now: Instant,
    ) -> Result<Outcome, Refusal> {
        let rules = self
            .policy
            .key(key_label)
            .ok_or_else(|| Refusal::NotATransferKey(key_label.to_string()))?;
        let asset =
            rules
                .asset(request.chain, request.asset)
                .ok_or_else(|| Refusal::AssetNotAllowed {
                    chain: request.chain.to_string(),
                    asset: request.asset.to_string(),
                })?;

        let amount = parse_amount(request.amount, asset.decimals)
            .map_err(|e| Refusal::Invalid(e.to_string()))?;
        let transfer = Transfer::new(
            key_label,
            request.chain,
            request.asset,
            asset.decimals,
            request.destination,
            amount,
            request.nonce,
        )
        .map_err(|e| Refusal::Invalid(e.to_string()))?;

        // 1. Hard limits.
        if !asset.allows_destination(transfer.destination()) {
            return Err(Refusal::DestinationNotAllowed {
                destination: transfer.destination().to_string(),
                chain: transfer.chain().to_string(),
                asset: transfer.asset().to_string(),
            });
        }
        if amount > asset.max_per_transfer {
            return Err(Refusal::OverMaxPerTransfer {
                amount: transfer.amount_display(),
                max: asset.display(asset.max_per_transfer),
                asset: transfer.asset().to_string(),
            });
        }

        let digest = transfer.digest();
        let mut state = self.lock()?;
        let key_state = state
            .entry(key_label.to_string())
            .or_insert_with(|| KeyState::new(self.origin));
        key_state.expire(now);

        // Already held: report on it, or release it once approved.
        if let Some(hold) = key_state.holds.get(&digest) {
            if hold.requester() != requester.as_ref() {
                return Err(ApprovalRefusal::HeldForAnotherRequester.into());
            }
            if hold.approval_count() < rules.holds.quorum {
                return Ok(Outcome::Held(hold.status(rules.holds.quorum, now)));
            }
            // Approval lifts the hold, not the rate: an approved transfer is still a
            // signature, and still counts against the minute.
            key_state.check_rate(rules, now)?;
            let hold = key_state.holds.take(&digest).ok_or(Refusal::Internal)?;
            let reservation = key_state.reserve(&transfer, now, Some(Box::new(hold)));
            return Ok(Outcome::Sign {
                transfer,
                reservation,
            });
        }

        // 2. Does this need a human?
        let signed_last_hour = key_state
            .hourly(transfer.chain(), transfer.asset())
            .total(now);
        let hold_reason = if amount > asset.approval_above {
            Some((
                HoldKind::Threshold,
                format!(
                    "{} {} is above the {} {} approval threshold",
                    transfer.amount_display(),
                    transfer.asset(),
                    asset.display(asset.approval_above),
                    transfer.asset()
                ),
            ))
        } else if signed_last_hour.saturating_add(amount) > asset.auto_sign_per_hour {
            Some((
                HoldKind::Budget,
                format!(
                    "{} {} has been signed in the last hour; this would pass the {} {} \
                 auto-sign budget",
                    asset.display(signed_last_hour),
                    transfer.asset(),
                    asset.display(asset.auto_sign_per_hour),
                    transfer.asset()
                ),
            ))
        } else {
            None
        };

        if let Some((kind, reason)) = hold_reason {
            let status = key_state.holds.open(
                transfer,
                requester,
                kind.as_str(),
                reason,
                &rules.holds,
                now,
            )?;
            return Ok(Outcome::Held(status));
        }

        // 3. Rate, then record the signature before it is made.
        key_state.check_rate(rules, now)?;
        let reservation = key_state.reserve(&transfer, now, None);
        Ok(Outcome::Sign {
            transfer,
            reservation,
        })
    }

    /// Give back a reservation whose signature never happened.
    pub fn release(&self, reservation: Reservation) {
        let Ok(mut state) = self.lock() else {
            return;
        };
        let Some(key_state) = state.get_mut(&reservation.key_label) else {
            return;
        };
        key_state.per_minute.remove(reservation.minute);
        key_state
            .hourly(&reservation.chain, &reservation.asset)
            .remove(reservation.hour);
        if let Some(hold) = reservation.released {
            key_state.holds.restore(*hold);
        }
    }

    fn approval_rules(&self, key_label: &str) -> Result<&KeyRules, ApprovalRefusal> {
        self.policy
            .key(key_label)
            .ok_or_else(|| ApprovalRefusal::NotApprovable(key_label.to_string()))
    }

    /// A held transfer, for an approver to review.
    pub fn pending(
        &self,
        key_label: &str,
        digest: &[u8; 32],
        now: Instant,
    ) -> Result<HoldStatus<Transfer>, ApprovalRefusal> {
        let rules = self.approval_rules(key_label)?;
        approval::pending(self, key_label, &rules.holds, digest, now)
    }

    /// Record one approver's signature on a held transfer; see `approval::approve`.
    pub fn approve(
        &self,
        key_label: &str,
        digest: &[u8; 32],
        hold_id: &[u8],
        approver: &str,
        signature: &[u8],
        now: Instant,
    ) -> Result<HoldStatus<Transfer>, ApprovalRefusal> {
        let rules = self.approval_rules(key_label)?;
        approval::approve(
            self,
            &self.approver_keys,
            key_label,
            &rules.holds,
            digest,
            hold_id,
            approver,
            signature,
            now,
        )
    }

    /// Each configured asset's signed outflow over the last hour, against its budget.
    pub fn outflow_last_hour(&self, now: Instant) -> Vec<Outflow> {
        let Ok(state) = self.lock() else {
            return Vec::new();
        };
        let mut flows = Vec::new();
        for label in self.policy.key_labels() {
            let Some(rules) = self.policy.key(label) else {
                continue;
            };
            for (chain, asset, asset_rules) in rules.assets() {
                let signed = state
                    .get(label)
                    .and_then(|key_state| {
                        key_state
                            .hourly
                            .get(&(chain.to_string(), asset.to_string()))
                    })
                    .map_or(0, |window| window.total(now));
                flows.push(Outflow {
                    key_label: label.to_string(),
                    chain: chain.to_string(),
                    asset: asset.to_string(),
                    signed: whole_units(signed, asset_rules.decimals),
                    budget: whole_units(asset_rules.auto_sign_per_hour, asset_rules.decimals),
                });
            }
        }
        flows
    }

    /// Held transfers across all keys, for the dashboard.
    pub fn pending_count(&self, now: Instant) -> usize {
        let Ok(mut state) = self.lock() else {
            return 0;
        };
        state
            .values_mut()
            .map(|key_state| {
                key_state.expire(now);
                key_state.holds.len()
            })
            .sum()
    }
}

/// One asset's outflow over the last hour, for the dashboard.
#[derive(Debug, Clone)]
pub struct Outflow {
    pub key_label: String,
    pub chain: String,
    pub asset: String,
    /// Whole units. An `f64` is lossy at 18 decimals, which is fine for a graph and is
    /// why nothing that enforces a limit reads it.
    pub signed: f64,
    pub budget: f64,
}

fn whole_units(amount: u128, decimals: u8) -> f64 {
    amount as f64 / 10f64.powi(i32::from(decimals))
}

impl HoldStore<Transfer> for TransferGuard {
    fn with_holds<R>(
        &self,
        key_label: &str,
        f: impl FnOnce(&mut Holds<Transfer>) -> Result<R, ApprovalRefusal>,
    ) -> Result<R, ApprovalRefusal> {
        let mut state = self.state.lock().map_err(|_| ApprovalRefusal::Internal)?;
        let key_state = state
            .get_mut(key_label)
            .ok_or(ApprovalRefusal::NoSuchHold)?;
        f(&mut key_state.holds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::approval_message;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};
    use std::time::Duration;

    const POLICY: &str = r#"
[[approvers]]
name = "alice"
[[approvers]]
name = "bob"
[[approvers]]
name = "carol"
[[approvers]]
name = "dave"

[[keys]]
key_label = "transfer-key"
approvers = ["alice", "bob", "carol"]
quorum = 2
hold_ttl_secs = 600
max_pending = 3
max_transfers_per_minute = 5

[[keys.assets]]
chain = "devnet"
asset = "ETH"
decimals = 18
max_per_transfer = "100"
approval_above = "10"
auto_sign_per_hour = "20"
destinations = ["0xc01d", "0x5e77"]
"#;

    struct Fixture {
        guard: TransferGuard,
        signers: HashMap<&'static str, SigningKey>,
        payments: Arc<str>,
        start: Instant,
    }

    impl Fixture {
        fn new() -> Self {
            let mut keys = ApproverKeys::none();
            let mut signers = HashMap::new();
            for name in ["alice", "bob", "carol", "dave"] {
                let signer = SigningKey::random(&mut rand::rngs::OsRng);
                keys.insert(name, &p256::PublicKey::from(signer.verifying_key()));
                signers.insert(name, signer);
            }
            Self {
                guard: TransferGuard::new(TransferPolicy::parse(POLICY).unwrap(), keys),
                signers,
                payments: Arc::from("payments"),
                start: Instant::now(),
            }
        }

        fn at(&self, secs: u64) -> Instant {
            self.start + Duration::from_secs(secs)
        }

        fn submit(
            &self,
            to: &str,
            amount: &str,
            nonce: u64,
            secs: u64,
        ) -> Result<Outcome, Refusal> {
            self.submit_as(&self.payments, to, amount, nonce, secs)
        }

        fn submit_as(
            &self,
            requester: &Arc<str>,
            to: &str,
            amount: &str,
            nonce: u64,
            secs: u64,
        ) -> Result<Outcome, Refusal> {
            let request = TransferRequest {
                chain: "devnet",
                asset: "ETH",
                destination: to,
                amount,
                nonce,
            };
            self.guard
                .submit(requester, "transfer-key", &request, self.at(secs))
        }

        fn held(&self, amount: &str, nonce: u64) -> HoldStatus<Transfer> {
            match self.submit("0xc01d", amount, nonce, 0).unwrap() {
                Outcome::Held(status) => status,
                Outcome::Sign { .. } => panic!("expected a hold"),
            }
        }

        /// Approve as `approver`, signing with `signer`'s key.
        fn approve(
            &self,
            status: &HoldStatus<Transfer>,
            approver: &str,
            signer: &str,
        ) -> Result<HoldStatus<Transfer>, ApprovalRefusal> {
            let message = approval_message(&status.hold_id, &status.statement.encode());
            let signature: Signature = self.signers[signer].sign(&message);
            self.guard.approve(
                "transfer-key",
                &status.statement.digest(),
                &status.hold_id,
                approver,
                &signature.to_bytes(),
                self.at(1),
            )
        }
    }

    fn signs(outcome: Result<Outcome, Refusal>) -> Reservation {
        match outcome {
            Ok(Outcome::Sign { reservation, .. }) => reservation,
            other => panic!("expected a signature, got {other:?}"),
        }
    }

    fn holds(outcome: Result<Outcome, Refusal>) -> HoldStatus<Transfer> {
        match outcome {
            Ok(Outcome::Held(status)) => status,
            other => panic!("expected a hold, got {other:?}"),
        }
    }

    #[test]
    fn signs_a_small_transfer_to_an_allowlisted_destination() {
        let f = Fixture::new();
        let _ = signs(f.submit("0xc01d", "1.5", 1, 0));
    }

    #[test]
    fn refuses_keys_the_policy_does_not_list() {
        let f = Fixture::new();
        let request = TransferRequest {
            chain: "devnet",
            asset: "ETH",
            destination: "0xc01d",
            amount: "1",
            nonce: 1,
        };
        assert!(matches!(
            f.guard
                .submit(&f.payments, "demo-ec-p256", &request, f.at(0)),
            Err(Refusal::NotATransferKey(_))
        ));
    }

    #[test]
    fn refuses_unlisted_destinations() {
        let f = Fixture::new();
        assert!(matches!(
            f.submit("0xbad", "1", 1, 0),
            Err(Refusal::DestinationNotAllowed { .. })
        ));
    }

    #[test]
    fn refuses_unconfigured_assets() {
        let f = Fixture::new();
        let request = TransferRequest {
            chain: "devnet",
            asset: "BTC",
            destination: "0xc01d",
            amount: "1",
            nonce: 1,
        };
        assert!(matches!(
            f.guard
                .submit(&f.payments, "transfer-key", &request, f.at(0)),
            Err(Refusal::AssetNotAllowed { .. })
        ));
    }

    /// The cap is a hard limit: no hold is created, so there is nothing to approve.
    #[test]
    fn refuses_above_the_cap_instead_of_holding() {
        let f = Fixture::new();
        assert!(matches!(
            f.submit("0xc01d", "100.000000000000000001", 1, 0),
            Err(Refusal::OverMaxPerTransfer { .. })
        ));
        assert_eq!(f.guard.pending_count(f.at(0)), 0);
    }

    #[test]
    fn holds_above_the_approval_threshold() {
        let f = Fixture::new();
        let status = f.held("25", 1);
        assert_eq!((status.received(), status.required), (0, 2));
        assert!(status.reason.contains("approval threshold"));
    }

    #[test]
    fn asking_again_reports_the_same_hold() {
        let f = Fixture::new();
        f.held("25", 1);
        f.held("25", 1);
        assert_eq!(f.guard.pending_count(f.at(0)), 1);
    }

    #[test]
    fn quorum_releases_a_held_transfer_exactly_once() {
        let f = Fixture::new();
        let status = f.held("25", 1);

        assert_eq!(f.approve(&status, "alice", "alice").unwrap().received(), 1);
        let _ = holds(f.submit("0xc01d", "25", 1, 2));

        assert!(f.approve(&status, "bob", "bob").unwrap().approved());
        let reservation = signs(f.submit("0xc01d", "25", 1, 3));
        assert_eq!(reservation.approvers(), ["alice", "bob"]);

        // Collected: the same transfer again is a new request needing new approvals.
        assert_eq!(holds(f.submit("0xc01d", "25", 1, 4)).received(), 0);
    }

    /// Whoever relayed the approvals for a collected hold still has the signatures. They
    /// must not be able to replay them onto a new hold of the identical transfer, which
    /// would approve it with no approver involved.
    #[test]
    fn approvals_cannot_be_replayed_onto_a_new_hold_of_the_same_transfer() {
        let f = Fixture::new();
        let first = f.held("25", 1);
        let message = approval_message(&first.hold_id, &first.statement.encode());
        let spent: Vec<(&str, Signature)> = ["alice", "bob"]
            .into_iter()
            .map(|name| (name, f.signers[name].sign(&message)))
            .collect();
        for (name, signature) in &spent {
            f.guard
                .approve(
                    "transfer-key",
                    &first.statement.digest(),
                    &first.hold_id,
                    name,
                    &signature.to_bytes(),
                    f.at(1),
                )
                .unwrap();
        }
        let _ = signs(f.submit("0xc01d", "25", 1, 2));

        let second = holds(f.submit("0xc01d", "25", 1, 3));
        assert_eq!(second.statement.digest(), first.statement.digest());
        assert_ne!(second.hold_id, first.hold_id);

        for (name, signature) in &spent {
            let digest = second.statement.digest();
            // Naming the old hold: it is gone.
            assert_eq!(
                f.guard
                    .approve(
                        "transfer-key",
                        &digest,
                        &first.hold_id,
                        name,
                        &signature.to_bytes(),
                        f.at(4)
                    )
                    .unwrap_err(),
                ApprovalRefusal::StaleHold
            );
            // Naming the new one: the signature does not cover it.
            assert_eq!(
                f.guard
                    .approve(
                        "transfer-key",
                        &digest,
                        &second.hold_id,
                        name,
                        &signature.to_bytes(),
                        f.at(4)
                    )
                    .unwrap_err(),
                ApprovalRefusal::BadApprovalSignature(name.to_string())
            );
        }
        assert_eq!(holds(f.submit("0xc01d", "25", 1, 5)).received(), 0);
    }

    #[test]
    fn the_same_approver_counts_once() {
        let f = Fixture::new();
        let status = f.held("25", 1);
        f.approve(&status, "alice", "alice").unwrap();
        assert_eq!(f.approve(&status, "alice", "alice").unwrap().received(), 1);
    }

    /// An approver cannot vouch for a colleague with their own key.
    #[test]
    fn rejects_an_approval_signed_with_someone_elses_key() {
        let f = Fixture::new();
        let status = f.held("25", 1);
        assert_eq!(
            f.approve(&status, "carol", "alice").unwrap_err(),
            ApprovalRefusal::BadApprovalSignature("carol".to_string())
        );
    }

    #[test]
    fn rejects_an_approval_made_for_a_different_transfer() {
        let f = Fixture::new();
        let target = f.held("25", 1);
        let other = f.held("25", 2);

        let message = approval_message(&target.hold_id, &other.statement.encode());
        let signature: Signature = f.signers["alice"].sign(&message);
        assert!(matches!(
            f.guard.approve(
                "transfer-key",
                &target.statement.digest(),
                &target.hold_id,
                "alice",
                &signature.to_bytes(),
                f.at(1)
            ),
            Err(ApprovalRefusal::BadApprovalSignature(_))
        ));
    }

    /// A signature over the bare transfer, without the approval tag, is not an approval.
    #[test]
    fn rejects_a_signature_without_the_approval_tag() {
        let f = Fixture::new();
        let status = f.held("25", 1);
        let signature: Signature = f.signers["alice"].sign(&status.statement.encode());
        assert!(matches!(
            f.guard.approve(
                "transfer-key",
                &status.statement.digest(),
                &status.hold_id,
                "alice",
                &signature.to_bytes(),
                f.at(1)
            ),
            Err(ApprovalRefusal::BadApprovalSignature(_))
        ));
    }

    #[test]
    fn rejects_an_approver_not_listed_for_the_key() {
        let f = Fixture::new();
        let status = f.held("25", 1);
        assert!(matches!(
            f.approve(&status, "dave", "dave"),
            Err(ApprovalRefusal::NotAnApprover { .. })
        ));
    }

    #[test]
    fn only_the_requester_can_collect() {
        let f = Fixture::new();
        f.held("25", 1);
        let batch: Arc<str> = Arc::from("batch");
        assert_eq!(
            f.submit_as(&batch, "0xc01d", "25", 1, 1).unwrap_err(),
            Refusal::Approval(ApprovalRefusal::HeldForAnotherRequester)
        );
    }

    #[test]
    fn holds_lapse_after_their_ttl() {
        let f = Fixture::new();
        let status = f.held("25", 1);
        assert!(f
            .guard
            .pending("transfer-key", &status.statement.digest(), f.at(599))
            .is_ok());
        assert_eq!(
            f.guard
                .pending("transfer-key", &status.statement.digest(), f.at(600))
                .unwrap_err(),
            ApprovalRefusal::NoSuchHold
        );
    }

    #[test]
    fn caps_the_number_of_holds() {
        let f = Fixture::new();
        for nonce in 0..3 {
            f.held("25", nonce);
        }
        assert!(matches!(
            f.submit("0xc01d", "25", 3, 0),
            Err(Refusal::Approval(ApprovalRefusal::TooManyHolds {
                limit: 3
            }))
        ));
    }

    /// The October 2026 pattern: many transfers in quick succession, each small enough
    /// to pass on its own. The budget turns the tail of the drain into holds.
    #[test]
    fn holds_once_the_hourly_budget_is_spent() {
        let f = Fixture::new();
        for nonce in 0..2 {
            let _ = signs(f.submit("0xc01d", "10", nonce, nonce * 61));
        }
        let status = holds(f.submit("0xc01d", "0.5", 9, 200));
        assert!(status.reason.contains("auto-sign budget"));

        // An hour on, the budget is back.
        let _ = signs(f.submit("0xc01d", "0.5", 10, 3_700));
    }

    #[test]
    fn refuses_a_burst_past_the_per_minute_rate() {
        let f = Fixture::new();
        for nonce in 0..5 {
            let _ = signs(f.submit("0x5e77", "0.01", nonce, 10));
        }
        assert_eq!(
            f.submit("0x5e77", "0.01", 5, 10).unwrap_err(),
            Refusal::RateLimited { limit: 5 }
        );
        let _ = signs(f.submit("0x5e77", "0.01", 6, 70));
    }

    #[test]
    fn approval_does_not_lift_the_rate() {
        let f = Fixture::new();
        let status = f.held("25", 100);
        f.approve(&status, "alice", "alice").unwrap();
        f.approve(&status, "bob", "bob").unwrap();
        for nonce in 0..5 {
            let _ = signs(f.submit("0x5e77", "0.01", nonce, 3));
        }
        assert!(matches!(
            f.submit("0xc01d", "25", 100, 3),
            Err(Refusal::RateLimited { .. })
        ));
        // Still held and still approved, so it can be collected once the minute passes.
        let _ = signs(f.submit("0xc01d", "25", 100, 64));
    }

    #[test]
    fn release_returns_budget_rate_and_hold() {
        let f = Fixture::new();
        let reservation = signs(f.submit("0xc01d", "10", 1, 0));
        f.guard.release(reservation);
        // Had the release not returned the 10, this would pass the 20 budget and hold.
        let _ = signs(f.submit("0xc01d", "10", 2, 0));
        let _ = signs(f.submit("0xc01d", "10", 3, 0));

        let status = f.held("25", 4);
        f.approve(&status, "alice", "alice").unwrap();
        f.approve(&status, "bob", "bob").unwrap();
        let reservation = signs(f.submit("0xc01d", "25", 4, 2));
        f.guard.release(reservation);
        assert!(f
            .guard
            .pending("transfer-key", &status.statement.digest(), f.at(2))
            .unwrap()
            .approved());
    }
}
