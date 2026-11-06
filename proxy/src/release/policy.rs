//! The release policy: what each release key signs on its own, and what has to wait for
//! people.
//!
//! Kept in its own file, like the transfer policy and for the same reasons. It applies
//! whether or not mTLS is on, because it is what makes a release key refuse the generic
//! `Sign`. And it has a different owner: whoever decides what ships, rather than whoever
//! decides which workloads may call what.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use anyhow::{ensure, Context, Result};
use serde::Deserialize;

use super::statement::{check_artifact, check_channel};
use crate::approval::{register_approvers, ApproverEntry, HoldRules};
use crate::encoding::check_key_label;

/// Default lifetime of a held release. Long enough for an approver to fetch the build
/// and check it for themselves; short enough that a request nobody acted on does not
/// linger for an attacker to wait out.
const DEFAULT_HOLD_TTL_SECS: u64 = 3600;

/// Default cap on held releases per key. Releases are rare, so a queue of them is a sign
/// of trouble rather than of load.
const DEFAULT_MAX_PENDING: usize = 16;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    #[serde(default)]
    approvers: Vec<ApproverEntry>,
    #[serde(default)]
    keys: Vec<KeyEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyEntry {
    key_label: String,
    #[serde(default)]
    #[allow(dead_code)]
    description: Option<String>,
    approvers: Vec<String>,
    quorum: usize,
    #[serde(default = "default_hold_ttl")]
    hold_ttl_secs: u64,
    #[serde(default = "default_max_pending")]
    max_pending: usize,
    max_releases_per_hour: u32,
    artifacts: Vec<String>,
    #[serde(default)]
    auto_sign_channels: Vec<String>,
    #[serde(default)]
    approval_channels: Vec<String>,
}

fn default_hold_ttl() -> u64 {
    DEFAULT_HOLD_TTL_SECS
}

fn default_max_pending() -> usize {
    DEFAULT_MAX_PENDING
}

/// How releases to a channel are signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelRule {
    /// Signed at once, within the hourly cap.
    Auto,
    /// Held until a quorum of approvers signs off.
    Approval,
}

/// Rules for one release key.
#[derive(Debug)]
pub struct KeyRules {
    /// Who approves held releases, and how many must.
    pub holds: HoldRules,
    /// Signatures per rolling hour, whether or not a release was approved first.
    pub max_releases_per_hour: u32,
    artifacts: BTreeSet<String>,
    channels: BTreeMap<String, ChannelRule>,
}

impl KeyRules {
    pub fn allows_artifact(&self, artifact: &str) -> bool {
        self.artifacts.contains(artifact)
    }

    /// How releases to `channel` are signed, or `None` if this key does not publish to it.
    pub fn channel(&self, channel: &str) -> Option<ChannelRule> {
        self.channels.get(channel).copied()
    }
}

/// A compiled release policy, validated in full at load.
#[derive(Debug, Default)]
pub struct ReleasePolicy {
    keys: HashMap<String, KeyRules>,
    approvers: BTreeSet<String>,
}

impl ReleasePolicy {
    /// No release keys at all.
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read release policy {}", path.display()))?;
        Self::parse(&text)
            .with_context(|| format!("failed to parse release policy {}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Self> {
        let file: PolicyFile = toml::from_str(text).context("invalid TOML")?;
        let approvers = register_approvers(file.approvers)?;

        let mut keys = HashMap::new();
        for entry in file.keys {
            let label = entry.key_label.clone();
            let rules = compile_key(entry, &approvers).with_context(|| format!("key '{label}'"))?;
            ensure!(
                keys.insert(label.clone(), rules).is_none(),
                "key '{label}' is configured twice"
            );
        }

        Ok(Self { keys, approvers })
    }

    pub fn is_release_key(&self, key_label: &str) -> bool {
        self.keys.contains_key(key_label)
    }

    pub fn key(&self, key_label: &str) -> Option<&KeyRules> {
        self.keys.get(key_label)
    }

    pub fn key_labels(&self) -> impl Iterator<Item = &str> {
        self.keys.keys().map(String::as_str)
    }

    pub fn approver_names(&self) -> impl Iterator<Item = &str> {
        self.approvers.iter().map(String::as_str)
    }

    pub fn key_count(&self) -> usize {
        self.keys.len()
    }
}

fn compile_key(entry: KeyEntry, registered: &BTreeSet<String>) -> Result<KeyRules> {
    check_key_label(&entry.key_label)?;
    let holds = HoldRules::compile(
        &entry.key_label,
        entry.approvers,
        entry.quorum,
        entry.hold_ttl_secs,
        entry.max_pending,
        registered,
    )?;
    ensure!(
        entry.max_releases_per_hour >= 1,
        "max_releases_per_hour must be at least 1"
    );

    // A key that releases nothing is a typo, not a policy.
    ensure!(!entry.artifacts.is_empty(), "artifacts must not be empty");
    let mut artifacts = BTreeSet::new();
    for artifact in entry.artifacts {
        check_artifact(&artifact)?;
        ensure!(
            artifacts.insert(artifact.clone()),
            "artifact '{artifact}' is listed twice"
        );
    }

    let mut channels = BTreeMap::new();
    let rules = [
        (entry.auto_sign_channels, ChannelRule::Auto),
        (entry.approval_channels, ChannelRule::Approval),
    ];
    for (names, rule) in rules {
        for channel in names {
            check_channel(&channel)?;
            // In both lists, a channel would be signed automatically or held depending on
            // which entry won -- exactly the ambiguity a policy must not have.
            ensure!(
                channels.insert(channel.clone(), rule).is_none(),
                "channel '{channel}' is listed twice"
            );
        }
    }
    ensure!(
        !channels.is_empty(),
        "auto_sign_channels and approval_channels must not both be empty"
    );

    Ok(KeyRules {
        holds,
        max_releases_per_hour: entry.max_releases_per_hour,
        artifacts,
        channels,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[[approvers]]
name = "alice"
[[approvers]]
name = "bob"

[[keys]]
key_label = "release-key"
approvers = ["alice", "bob"]
quorum = 2
max_releases_per_hour = 10
artifacts = ["gll-proxy", "gll-transfer"]
auto_sign_channels = ["nightly", "beta"]
approval_channels = ["stable"]
"#;

    fn with(replace: &str, by: &str) -> String {
        assert!(
            SAMPLE.contains(replace),
            "sample does not contain {replace:?}"
        );
        SAMPLE.replace(replace, by)
    }

    fn error(text: &str) -> String {
        format!("{:#}", ReleasePolicy::parse(text).unwrap_err())
    }

    #[test]
    fn compiles_artifacts_and_channels() {
        let policy = ReleasePolicy::parse(SAMPLE).unwrap();
        let rules = policy.key("release-key").unwrap();
        assert!(rules.allows_artifact("gll-proxy"));
        assert!(!rules.allows_artifact("gll-proxy-debug"));
        assert_eq!(rules.channel("beta"), Some(ChannelRule::Auto));
        assert_eq!(rules.channel("stable"), Some(ChannelRule::Approval));
        assert_eq!(rules.channel("Stable"), None);
        assert_eq!(rules.holds.hold_ttl.as_secs(), DEFAULT_HOLD_TTL_SECS);
    }

    #[test]
    fn unlisted_keys_are_not_release_keys() {
        let policy = ReleasePolicy::parse(SAMPLE).unwrap();
        assert!(policy.is_release_key("release-key"));
        assert!(!policy.is_release_key("demo-ec-p256"));
        assert_eq!(ReleasePolicy::parse("").unwrap().key_count(), 0);
    }

    /// A misspelt field must fail the load rather than leave a rule silently unset.
    #[test]
    fn rejects_unknown_fields() {
        assert!(error(&with("approval_channels", "approval_channel")).contains("unknown field"));
    }

    #[test]
    fn rejects_a_channel_in_both_lists() {
        assert!(error(&with(r#"["stable"]"#, r#"["stable", "beta"]"#)).contains("listed twice"));
    }

    #[test]
    fn rejects_a_key_with_no_channels_or_artifacts() {
        let no_channels = with(r#"["nightly", "beta"]"#, "[]").replace(r#"["stable"]"#, "[]");
        assert!(error(&no_channels).contains("must not both be empty"));
        assert!(
            error(&with(r#"["gll-proxy", "gll-transfer"]"#, "[]")).contains("artifacts must not")
        );
    }

    #[test]
    fn rejects_artifact_with_lookalike_characters() {
        assert!(error(&with("gll-transfer", "gll-trаnsfer")).contains("may contain only"));
    }

    #[test]
    fn rejects_quorum_out_of_range() {
        assert!(error(&with("quorum = 2", "quorum = 3")).contains("quorum"));
    }

    #[test]
    fn rejects_unregistered_approver() {
        assert!(
            error(&with(r#"["alice", "bob"]"#, r#"["alice", "mallory"]"#))
                .contains("not registered")
        );
    }
}
