//! The release guard: for each requested release, sign it now, hold it for approval, or
//! refuse it -- and keep the state those decisions depend on.
//!
//! In order:
//!
//! 1. **Hard limits** -- an artifact this key releases, a channel it publishes to, and a
//!    version that names one file. Refused whatever anyone approves.
//! 2. **Holds** -- every release to an approval channel, such as `stable`, waits for a
//!    quorum of approvers. There is no stable release small enough to wave through.
//! 3. **Rate** -- signatures per rolling hour, approved or not, so a compromised build
//!    system cannot mint a stream of auto-signed releases under fresh version numbers.
//!
//! One file per version is the check that only makes sense for releases. Once a version
//! of an artifact has been signed, or held, for one file, the key refuses that version
//! for any other file. A build system compromised after 1.4.0 shipped cannot re-sign
//! 1.4.0 as something else, and approvers are never shown two different files under one
//! version number. Promoting a build from `beta` to `stable` is the same file, so it is
//! allowed. Like the transfer limits, the record lives in memory, so a restart forgets
//! it; docs/m11-release-keys.md says what that costs.
//!
//! Holding and approving work as they do for every purpose-bound key, in
//! `crate::approval`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use super::policy::{ChannelRule, KeyRules, ReleasePolicy};
use super::statement::Release;
use crate::approval::{self, ApprovalRefusal, ApproverKeys, Hold, HoldStatus, HoldStore, Holds};
use crate::velocity::{Mark, Window};

/// A release as the caller described it, before any of it has been checked.
pub struct ReleaseRequest<'a> {
    pub artifact: &'a str,
    pub version: &'a str,
    pub channel: &'a str,
    pub sha256: &'a [u8],
}

/// Why a release was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("'{0}' is not a release key")]
    NotAReleaseKey(String),

    #[error("{0}")]
    Invalid(String),

    #[error("artifact {artifact:?} is not one this key releases")]
    ArtifactNotAllowed { artifact: String },

    #[error("channel {channel:?} is not one this key publishes to")]
    ChannelNotAllowed { channel: String },

    #[error(
        "{artifact} {version} is already signed for a different file; a version names one file"
    )]
    VersionTaken { artifact: String, version: String },

    #[error("{artifact} {version} is already held for approval as a different file")]
    VersionHeld { artifact: String, version: String },

    #[error("this key has signed {limit} releases in the last hour, its limit")]
    RateLimited { limit: u32 },

    /// A refusal from holding or collecting it: too many held, or held for someone else.
    #[error(transparent)]
    Approval(#[from] ApprovalRefusal),

    #[error("release state is unavailable after an internal error")]
    Internal,
}

impl Refusal {
    /// A fixed label for metrics. Never derived from the request.
    pub fn reason(&self) -> &'static str {
        match self {
            Refusal::NotAReleaseKey(_) => "not_release_key",
            Refusal::Invalid(_) => "invalid",
            Refusal::ArtifactNotAllowed { .. } => "artifact",
            Refusal::ChannelNotAllowed { .. } => "channel",
            Refusal::VersionTaken { .. } => "version_taken",
            Refusal::VersionHeld { .. } => "version_held",
            Refusal::RateLimited { .. } => "rate",
            Refusal::Approval(refusal) => refusal.reason(),
            Refusal::Internal => "internal",
        }
    }
}

/// What to do with a release.
#[derive(Debug)]
pub enum Outcome {
    /// Sign `release` now. If the signature fails, hand `reservation` back with
    /// `ReleaseGuard::release`.
    Sign {
        release: Release,
        reservation: Reservation,
    },
    /// Held until enough approvers sign off.
    Held(HoldStatus<Release>),
}

/// A signature counted against the hourly cap, and its version recorded, before it was
/// made.
#[derive(Debug)]
#[must_use = "a reservation must be released if the signature fails"]
pub struct Reservation {
    key_label: String,
    hour: Mark,
    /// The hold this signature releases, put back if signing fails.
    released: Option<Box<Hold<Release>>>,
}

impl Reservation {
    /// Who approved the released release, for the audit log.
    pub fn approvers(&self) -> Vec<String> {
        self.released
            .as_ref()
            .map(|hold| hold.approvers())
            .unwrap_or_default()
    }
}

#[derive(Debug)]
struct KeyState {
    hourly: Window,
    /// Which file each signed version is: (artifact, version) to the file's SHA-256.
    signed: HashMap<(String, String), [u8; 32]>,
    holds: Holds<Release>,
}

impl KeyState {
    fn new(origin: Instant) -> Self {
        Self {
            hourly: Window::per_hour(origin),
            signed: HashMap::new(),
            holds: Holds::default(),
        }
    }

    fn check_rate(&self, rules: &KeyRules, now: Instant) -> Result<(), Refusal> {
        if self.hourly.total(now) >= u128::from(rules.max_releases_per_hour) {
            return Err(Refusal::RateLimited {
                limit: rules.max_releases_per_hour,
            });
        }
        Ok(())
    }

    /// Refuse a version that already names a different file, signed or held.
    fn check_version(&self, release: &Release) -> Result<(), Refusal> {
        let version = (
            release.artifact().to_string(),
            release.version().to_string(),
        );
        if self
            .signed
            .get(&version)
            .is_some_and(|signed| *signed != release.sha256())
        {
            return Err(Refusal::VersionTaken {
                artifact: version.0,
                version: version.1,
            });
        }
        let held_as_another_file = self.holds.iter().any(|hold| {
            let held = hold.statement();
            held.artifact() == release.artifact()
                && held.version() == release.version()
                && held.sha256() != release.sha256()
        });
        if held_as_another_file {
            return Err(Refusal::VersionHeld {
                artifact: version.0,
                version: version.1,
            });
        }
        Ok(())
    }

    fn reserve(
        &mut self,
        release: &Release,
        now: Instant,
        released: Option<Box<Hold<Release>>>,
    ) -> Reservation {
        let hour = self.hourly.add(now, 1);
        // Recorded under the same lock as the check, so two concurrent requests for one
        // version with different files cannot both pass it.
        self.signed
            .entry((
                release.artifact().to_string(),
                release.version().to_string(),
            ))
            .or_insert(release.sha256());
        Reservation {
            key_label: release.key_label().to_string(),
            hour,
            released,
        }
    }
}

pub struct ReleaseGuard {
    policy: ReleasePolicy,
    approver_keys: ApproverKeys,
    /// Common origin for every window, so their buckets line up.
    origin: Instant,
    /// One lock for all keys: releases are rare, and one lock makes every
    /// check-and-reserve atomic.
    state: Mutex<HashMap<String, KeyState>>,
}

impl ReleaseGuard {
    pub fn new(policy: ReleasePolicy, approver_keys: ApproverKeys) -> Self {
        Self {
            policy,
            approver_keys,
            origin: Instant::now(),
            state: Mutex::new(HashMap::new()),
        }
    }

    pub fn policy(&self) -> &ReleasePolicy {
        &self.policy
    }

    pub fn is_release_key(&self, key_label: &str) -> bool {
        self.policy.is_release_key(key_label)
    }

    /// A poisoned lock means a panic mid-update, so the state may be half-written. The
    /// safe response is to stop signing, not to guess.
    fn lock(&self) -> Result<MutexGuard<'_, HashMap<String, KeyState>>, Refusal> {
        self.state.lock().map_err(|_| Refusal::Internal)
    }

    /// Decide what to do with a requested release.
    pub fn submit(
        &self,
        requester: &Arc<str>,
        key_label: &str,
        request: &ReleaseRequest<'_>,
        now: Instant,
    ) -> Result<Outcome, Refusal> {
        let rules = self
            .policy
            .key(key_label)
            .ok_or_else(|| Refusal::NotAReleaseKey(key_label.to_string()))?;
        let sha256: [u8; 32] = request.sha256.try_into().map_err(|_| {
            Refusal::Invalid("sha256 must be the 32-byte SHA-256 of the released file".to_string())
        })?;
        let release = Release::new(
            key_label,
            request.artifact,
            request.version,
            request.channel,
            sha256,
        )
        .map_err(|e| Refusal::Invalid(e.to_string()))?;

        // 1. Hard limits.
        if !rules.allows_artifact(release.artifact()) {
            return Err(Refusal::ArtifactNotAllowed {
                artifact: release.artifact().to_string(),
            });
        }
        let channel =
            rules
                .channel(release.channel())
                .ok_or_else(|| Refusal::ChannelNotAllowed {
                    channel: release.channel().to_string(),
                })?;

        let digest = release.digest();
        let mut state = self.lock()?;
        let key_state = state
            .entry(key_label.to_string())
            .or_insert_with(|| KeyState::new(self.origin));
        key_state.holds.expire(now);
        key_state.check_version(&release)?;

        // Already held: report on it, or release it once approved.
        if let Some(hold) = key_state.holds.get(&digest) {
            if hold.requester() != requester.as_ref() {
                return Err(ApprovalRefusal::HeldForAnotherRequester.into());
            }
            if hold.approval_count() < rules.holds.quorum {
                return Ok(Outcome::Held(hold.status(rules.holds.quorum, now)));
            }
            // Approval lifts the hold, not the rate: an approved release is still a
            // signature, and still counts against the hour.
            key_state.check_rate(rules, now)?;
            let hold = key_state.holds.take(&digest).ok_or(Refusal::Internal)?;
            let reservation = key_state.reserve(&release, now, Some(Box::new(hold)));
            return Ok(Outcome::Sign {
                release,
                reservation,
            });
        }

        // 2. Does this need people?
        if channel == ChannelRule::Approval {
            let reason = format!(
                "{} releases need {} of {} approvers",
                release.channel(),
                rules.holds.quorum,
                rules.holds.approvers.len()
            );
            let status =
                key_state
                    .holds
                    .open(release, requester, "channel", reason, &rules.holds, now)?;
            return Ok(Outcome::Held(status));
        }

        // 3. Rate, then record the signature before it is made.
        key_state.check_rate(rules, now)?;
        let reservation = key_state.reserve(&release, now, None);
        Ok(Outcome::Sign {
            release,
            reservation,
        })
    }

    /// Give back a reservation whose signature never happened: its share of the hour, and
    /// the approvals it was collecting.
    ///
    /// Not the version's record. A concurrent request for the same release may have been
    /// signed, and the record is what stops that version being signed again for another
    /// file, so it fails closed: the version stays bound to this file, and retrying with
    /// the same file still works.
    pub fn release(&self, reservation: Reservation) {
        let Ok(mut state) = self.lock() else {
            return;
        };
        let Some(key_state) = state.get_mut(&reservation.key_label) else {
            return;
        };
        key_state.hourly.remove(reservation.hour);
        if let Some(hold) = reservation.released {
            key_state.holds.restore(*hold);
        }
    }

    fn approval_rules(&self, key_label: &str) -> Result<&KeyRules, ApprovalRefusal> {
        self.policy
            .key(key_label)
            .ok_or_else(|| ApprovalRefusal::NotApprovable(key_label.to_string()))
    }

    /// A held release, for an approver to review.
    pub fn pending(
        &self,
        key_label: &str,
        digest: &[u8; 32],
        now: Instant,
    ) -> Result<HoldStatus<Release>, ApprovalRefusal> {
        let rules = self.approval_rules(key_label)?;
        approval::pending(self, key_label, &rules.holds, digest, now)
    }

    /// Record one approver's signature on a held release; see `approval::approve`.
    pub fn approve(
        &self,
        key_label: &str,
        digest: &[u8; 32],
        hold_id: &[u8],
        approver: &str,
        signature: &[u8],
        now: Instant,
    ) -> Result<HoldStatus<Release>, ApprovalRefusal> {
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

    /// Held releases across all keys, for the dashboard.
    pub fn pending_count(&self, now: Instant) -> usize {
        let Ok(mut state) = self.lock() else {
            return 0;
        };
        state
            .values_mut()
            .map(|key_state| {
                key_state.holds.expire(now);
                key_state.holds.len()
            })
            .sum()
    }
}

impl HoldStore<Release> for ReleaseGuard {
    fn with_holds<R>(
        &self,
        key_label: &str,
        f: impl FnOnce(&mut Holds<Release>) -> Result<R, ApprovalRefusal>,
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
    use sha2::{Digest, Sha256};
    use std::time::Duration;

    const POLICY: &str = r#"
[[approvers]]
name = "alice"
[[approvers]]
name = "bob"
[[approvers]]
name = "carol"

[[keys]]
key_label = "release-key"
approvers = ["alice", "bob", "carol"]
quorum = 2
hold_ttl_secs = 600
max_pending = 2
max_releases_per_hour = 4
artifacts = ["gll-proxy"]
auto_sign_channels = ["beta"]
approval_channels = ["stable"]
"#;

    struct Fixture {
        guard: ReleaseGuard,
        signers: HashMap<&'static str, SigningKey>,
        ci: Arc<str>,
        start: Instant,
    }

    fn file(contents: &str) -> [u8; 32] {
        Sha256::digest(contents.as_bytes()).into()
    }

    impl Fixture {
        fn new() -> Self {
            let mut keys = ApproverKeys::none();
            let mut signers = HashMap::new();
            for name in ["alice", "bob", "carol"] {
                let signer = SigningKey::random(&mut rand::rngs::OsRng);
                keys.insert(name, &p256::PublicKey::from(signer.verifying_key()));
                signers.insert(name, signer);
            }
            Self {
                guard: ReleaseGuard::new(ReleasePolicy::parse(POLICY).unwrap(), keys),
                signers,
                ci: Arc::from("ci"),
                start: Instant::now(),
            }
        }

        fn at(&self, secs: u64) -> Instant {
            self.start + Duration::from_secs(secs)
        }

        fn submit_as(
            &self,
            requester: &Arc<str>,
            version: &str,
            channel: &str,
            contents: &str,
            secs: u64,
        ) -> Result<Outcome, Refusal> {
            let sha256 = file(contents);
            let request = ReleaseRequest {
                artifact: "gll-proxy",
                version,
                channel,
                sha256: &sha256,
            };
            self.guard
                .submit(requester, "release-key", &request, self.at(secs))
        }

        fn submit(&self, version: &str, channel: &str, contents: &str) -> Result<Outcome, Refusal> {
            self.submit_as(&self.ci, version, channel, contents, 0)
        }

        fn approve(
            &self,
            status: &HoldStatus<Release>,
            approver: &str,
        ) -> Result<HoldStatus<Release>, ApprovalRefusal> {
            let message = approval_message(&status.hold_id, &status.statement.encode());
            let signature: Signature = self.signers[approver].sign(&message);
            self.guard.approve(
                "release-key",
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

    fn holds(outcome: Result<Outcome, Refusal>) -> HoldStatus<Release> {
        match outcome {
            Ok(Outcome::Held(status)) => status,
            other => panic!("expected a hold, got {other:?}"),
        }
    }

    #[test]
    fn signs_a_beta_release_at_once() {
        let f = Fixture::new();
        let reservation = signs(f.submit("1.4.0-rc.1", "beta", "build 1"));
        assert!(reservation.approvers().is_empty());
    }

    #[test]
    fn refuses_what_the_key_does_not_release() {
        let f = Fixture::new();
        let sha256 = file("build");
        let request = |artifact, channel| ReleaseRequest {
            artifact,
            version: "1.4.0",
            channel,
            sha256: &sha256,
        };
        assert!(matches!(
            f.guard
                .submit(&f.ci, "release-key", &request("evil-tool", "beta"), f.at(0)),
            Err(Refusal::ArtifactNotAllowed { .. })
        ));
        assert!(matches!(
            f.guard.submit(
                &f.ci,
                "release-key",
                &request("gll-proxy", "hotfix"),
                f.at(0)
            ),
            Err(Refusal::ChannelNotAllowed { .. })
        ));
        assert!(matches!(
            f.guard.submit(
                &f.ci,
                "demo-ec-p256",
                &request("gll-proxy", "beta"),
                f.at(0)
            ),
            Err(Refusal::NotAReleaseKey(_))
        ));
    }

    #[test]
    fn refuses_a_malformed_version_or_digest() {
        let f = Fixture::new();
        assert!(matches!(
            f.submit("1.4.0+build.5", "beta", "build"),
            Err(Refusal::Invalid(_))
        ));
        let short = [0u8; 31];
        let request = ReleaseRequest {
            artifact: "gll-proxy",
            version: "1.4.0",
            channel: "beta",
            sha256: &short,
        };
        assert!(matches!(
            f.guard.submit(&f.ci, "release-key", &request, f.at(0)),
            Err(Refusal::Invalid(_))
        ));
    }

    /// The release-specific rule: once 1.4.0 is one file, it is never another.
    #[test]
    fn a_signed_version_names_one_file() {
        let f = Fixture::new();
        let _ = signs(f.submit("1.4.0", "beta", "build 1"));
        assert_eq!(
            f.submit("1.4.0", "beta", "build 2").unwrap_err(),
            Refusal::VersionTaken {
                artifact: "gll-proxy".to_string(),
                version: "1.4.0".to_string()
            }
        );
        // Promotion is the same file on another channel: allowed, and held as stable is.
        holds(f.submit("1.4.0", "stable", "build 1"));
        // Re-signing the identical statement is harmless.
        let _ = signs(f.submit("1.4.0", "beta", "build 1"));
    }

    #[test]
    fn a_held_version_names_one_file() {
        let f = Fixture::new();
        holds(f.submit("2.0.0", "stable", "build 1"));
        for channel in ["stable", "beta"] {
            assert!(matches!(
                f.submit("2.0.0", channel, "build 2"),
                Err(Refusal::VersionHeld { .. })
            ));
        }
    }

    #[test]
    fn stable_waits_for_a_quorum_and_the_requester_collects() {
        let f = Fixture::new();
        let status = holds(f.submit("2.0.0", "stable", "build"));
        assert_eq!(status.kind, "channel");
        assert_eq!(status.required, 2);

        assert_eq!(f.approve(&status, "alice").unwrap().received(), 1);
        assert_eq!(holds(f.submit("2.0.0", "stable", "build")).received(), 1);
        assert!(f.approve(&status, "bob").unwrap().approved());

        let reservation = signs(f.submit("2.0.0", "stable", "build"));
        assert_eq!(reservation.approvers(), ["alice", "bob"]);

        // Spent: asking again starts a fresh hold that nobody has approved.
        assert_eq!(holds(f.submit("2.0.0", "stable", "build")).received(), 0);
    }

    #[test]
    fn a_hold_belongs_to_whoever_asked() {
        let f = Fixture::new();
        let status = holds(f.submit("2.0.0", "stable", "build"));
        f.approve(&status, "alice").unwrap();
        f.approve(&status, "bob").unwrap();
        let other: Arc<str> = Arc::from("batch");
        assert_eq!(
            f.submit_as(&other, "2.0.0", "stable", "build", 0)
                .unwrap_err(),
            Refusal::Approval(ApprovalRefusal::HeldForAnotherRequester)
        );
    }

    #[test]
    fn an_approval_by_the_wrong_key_does_not_count() {
        let f = Fixture::new();
        let status = holds(f.submit("2.0.0", "stable", "build"));
        let message = approval_message(&status.hold_id, &status.statement.encode());
        let forged: Signature = f.signers["carol"].sign(&message);
        assert_eq!(
            f.guard
                .approve(
                    "release-key",
                    &status.statement.digest(),
                    &status.hold_id,
                    "alice",
                    &forged.to_bytes(),
                    f.at(1),
                )
                .unwrap_err(),
            ApprovalRefusal::BadApprovalSignature("alice".to_string())
        );
    }

    #[test]
    fn caps_signatures_per_hour_approved_or_not() {
        let f = Fixture::new();
        for n in 0..4 {
            let _ = signs(f.submit(&format!("1.{n}.0"), "beta", &format!("build {n}")));
        }
        assert_eq!(
            f.submit("1.9.0", "beta", "build 9").unwrap_err(),
            Refusal::RateLimited { limit: 4 }
        );
        // An hour on, the cap is back.
        let _ = signs(f.submit_as(&f.ci, "1.9.0", "beta", "build 9", 3_601));
    }

    #[test]
    fn holds_are_capped() {
        let f = Fixture::new();
        holds(f.submit("3.0.0", "stable", "a"));
        holds(f.submit("3.1.0", "stable", "b"));
        assert_eq!(
            f.submit("3.2.0", "stable", "c").unwrap_err(),
            Refusal::Approval(ApprovalRefusal::TooManyHolds { limit: 2 })
        );
    }

    /// A signature that failed in the HSM must not use up the hour or cost the approvers
    /// their work.
    #[test]
    fn release_returns_the_rate_and_the_hold() {
        let f = Fixture::new();
        for n in 0..8 {
            let reservation = signs(f.submit(&format!("1.{n}.0"), "beta", "build"));
            f.guard.release(reservation);
        }
        // Eight failures, and the cap of four is untouched.
        for n in 0..4 {
            let _ = signs(f.submit(&format!("1.{n}.0"), "beta", "build"));
        }

        let f = Fixture::new();
        let status = holds(f.submit("2.0.0", "stable", "build"));
        f.approve(&status, "alice").unwrap();
        f.approve(&status, "carol").unwrap();
        let reservation = signs(f.submit("2.0.0", "stable", "build"));
        f.guard.release(reservation);
        assert_eq!(f.guard.pending_count(f.at(2)), 1);
        let collected = signs(f.submit("2.0.0", "stable", "build"));
        assert_eq!(collected.approvers(), ["alice", "carol"]);
    }

    /// But it keeps the version bound to its file. Two identical requests can be in
    /// flight at once; if one fails, the other may have been signed, and forgetting the
    /// version would let it be signed again for a different file.
    #[test]
    fn a_failed_signature_keeps_the_version_bound_to_its_file() {
        let f = Fixture::new();
        let first = signs(f.submit("1.0.0", "beta", "build 1"));
        let concurrent = signs(f.submit("1.0.0", "beta", "build 1"));
        f.guard.release(first);
        drop(concurrent); // signed

        assert!(matches!(
            f.submit("1.0.0", "beta", "build 2"),
            Err(Refusal::VersionTaken { .. })
        ));
        // Retrying with the same file still works.
        let _ = signs(f.submit("1.0.0", "beta", "build 1"));
    }
}
