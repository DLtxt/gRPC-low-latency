//! The transfer policy: what each transfer key may sign on its own, and who has to agree
//! to the rest.
//!
//! Kept in its own file rather than in `authz.toml` for two reasons. It applies whether
//! or not mTLS is on, because it is what makes a transfer key refuse the generic `Sign`
//! RPC, and that refusal must not depend on how the transport is configured. And it is
//! a different owner's document: the authorization policy says which workloads may call
//! what, while this one is a treasury decision about how much may leave, and how fast.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;

use anyhow::{ensure, Context, Result};
use serde::Deserialize;

use super::canonical::{self, format_amount, parse_amount};
use crate::approval::{register_approvers, ApproverEntry, HoldRules};
use crate::encoding::check_key_label;

/// Default lifetime of a held transfer. Long enough for two people to look at it, short
/// enough that an approval cannot surface days later for a transfer nobody remembers.
const DEFAULT_HOLD_TTL_SECS: u64 = 900;

/// Default cap on held transfers per key. Holds are memory, and a caller that can create
/// them must not be able to create them without bound.
const DEFAULT_MAX_PENDING: usize = 256;

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
    max_transfers_per_minute: u32,
    assets: Vec<AssetEntry>,
}

/// Amounts are strings in whole units of the asset -- `"12.5"` -- so the file reads the
/// way a person thinks about money, and so 18-decimal assets are not squeezed through a
/// TOML integer.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AssetEntry {
    chain: String,
    asset: String,
    decimals: u8,
    max_per_transfer: String,
    approval_above: String,
    auto_sign_per_hour: String,
    destinations: Vec<String>,
}

fn default_hold_ttl() -> u64 {
    DEFAULT_HOLD_TTL_SECS
}

fn default_max_pending() -> usize {
    DEFAULT_MAX_PENDING
}

/// Rules for one transfer key.
#[derive(Debug)]
pub struct KeyRules {
    /// Who approves held transfers, and how many must.
    pub holds: HoldRules,
    /// Signatures per rolling minute, whether or not a transfer was approved first.
    pub max_transfers_per_minute: u32,
    assets: HashMap<(String, String), AssetRules>,
}

impl KeyRules {
    pub fn asset(&self, chain: &str, asset: &str) -> Option<&AssetRules> {
        self.assets.get(&(chain.to_string(), asset.to_string()))
    }

    pub fn assets(&self) -> impl Iterator<Item = (&str, &str, &AssetRules)> {
        self.assets
            .iter()
            .map(|((chain, asset), rules)| (chain.as_str(), asset.as_str(), rules))
    }
}

/// Rules for one asset on one chain, with amounts in the asset's smallest unit.
#[derive(Debug)]
pub struct AssetRules {
    pub decimals: u8,
    /// Refused above this, approved or not.
    pub max_per_transfer: u128,
    /// Held for approval above this.
    pub approval_above: u128,
    /// Signed without approval until this much has left in the last hour; after that,
    /// every transfer is held.
    pub auto_sign_per_hour: u128,
    destinations: HashSet<String>,
}

impl AssetRules {
    pub fn allows_destination(&self, destination: &str) -> bool {
        self.destinations.contains(destination)
    }

    pub fn display(&self, amount: u128) -> String {
        format_amount(amount, self.decimals)
    }
}

/// A compiled transfer policy. Validated in full at load: a mistake here is a mistake
/// about how much money can leave, and finding it at startup is the only acceptable time.
#[derive(Debug, Default)]
pub struct TransferPolicy {
    keys: HashMap<String, KeyRules>,
    approvers: BTreeSet<String>,
}

impl TransferPolicy {
    /// No transfer keys at all.
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read transfer policy {}", path.display()))?;
        Self::parse(&text)
            .with_context(|| format!("failed to parse transfer policy {}", path.display()))
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

    pub fn is_transfer_key(&self, key_label: &str) -> bool {
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
        entry.max_transfers_per_minute >= 1,
        "max_transfers_per_minute must be at least 1"
    );

    ensure!(!entry.assets.is_empty(), "assets must not be empty");
    let mut assets = HashMap::new();
    for asset in entry.assets {
        let id = (asset.chain.clone(), asset.asset.clone());
        let rules = compile_asset(asset).with_context(|| format!("asset {} on {}", id.1, id.0))?;
        ensure!(
            assets.insert(id.clone(), rules).is_none(),
            "asset {} on {} is configured twice",
            id.1,
            id.0
        );
    }

    Ok(KeyRules {
        holds,
        max_transfers_per_minute: entry.max_transfers_per_minute,
        assets,
    })
}

fn compile_asset(entry: AssetEntry) -> Result<AssetRules> {
    canonical::check_chain(&entry.chain)?;
    canonical::check_asset(&entry.asset)?;
    ensure!(
        entry.decimals <= canonical::MAX_DECIMALS,
        "decimals must be at most {}",
        canonical::MAX_DECIMALS
    );

    let amount = |name: &str, text: &str| {
        parse_amount(text, entry.decimals).with_context(|| format!("{name} = {text:?}"))
    };
    let max_per_transfer = amount("max_per_transfer", &entry.max_per_transfer)?;
    let approval_above = amount("approval_above", &entry.approval_above)?;
    let auto_sign_per_hour = amount("auto_sign_per_hour", &entry.auto_sign_per_hour)?;

    ensure!(max_per_transfer > 0, "max_per_transfer must be above zero");
    ensure!(
        approval_above <= max_per_transfer,
        "approval_above ({}) exceeds max_per_transfer ({}), so it could never apply",
        entry.approval_above,
        entry.max_per_transfer
    );

    // An asset nothing can be sent to is a typo, not a policy.
    ensure!(
        !entry.destinations.is_empty(),
        "destinations must not be empty"
    );
    let mut destinations = HashSet::new();
    for destination in entry.destinations {
        canonical::check_destination(&destination)?;
        ensure!(
            destinations.insert(destination.clone()),
            "destination {destination} is listed twice"
        );
    }

    Ok(AssetRules {
        decimals: entry.decimals,
        max_per_transfer,
        approval_above,
        auto_sign_per_hour,
        destinations,
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
[[approvers]]
name = "carol"

[[keys]]
key_label = "transfer-key"
approvers = ["alice", "bob", "carol"]
quorum = 2
max_transfers_per_minute = 30

[[keys.assets]]
chain = "devnet"
asset = "ETH"
decimals = 18
max_per_transfer = "100"
approval_above = "10"
auto_sign_per_hour = "50"
destinations = ["0xc01d", "0x5e77"]
"#;

    fn with(replace: &str, by: &str) -> String {
        assert!(
            SAMPLE.contains(replace),
            "sample does not contain {replace:?}"
        );
        SAMPLE.replace(replace, by)
    }

    fn error(text: &str) -> String {
        format!("{:#}", TransferPolicy::parse(text).unwrap_err())
    }

    #[test]
    fn compiles_amounts_into_smallest_units() {
        let policy = TransferPolicy::parse(SAMPLE).unwrap();
        let eth = policy
            .key("transfer-key")
            .unwrap()
            .asset("devnet", "ETH")
            .unwrap();
        assert_eq!(eth.max_per_transfer, 100 * 10u128.pow(18));
        assert_eq!(eth.approval_above, 10 * 10u128.pow(18));
        assert!(eth.allows_destination("0xc01d"));
        assert!(!eth.allows_destination("0xC01D"));
    }

    #[test]
    fn unlisted_keys_are_not_transfer_keys() {
        let policy = TransferPolicy::parse(SAMPLE).unwrap();
        assert!(policy.is_transfer_key("transfer-key"));
        assert!(!policy.is_transfer_key("demo-ec-p256"));
    }

    #[test]
    fn empty_file_has_no_transfer_keys() {
        assert_eq!(TransferPolicy::parse("").unwrap().key_count(), 0);
    }

    /// A misspelt field must fail the load rather than leave a limit silently unset.
    #[test]
    fn rejects_unknown_fields() {
        assert!(error(&with("max_per_transfer", "max_per_transfr")).contains("unknown field"));
    }

    #[test]
    fn rejects_unregistered_approver() {
        assert!(error(&with(r#""carol"]"#, r#""mallory"]"#)).contains("not registered"));
    }

    #[test]
    fn rejects_quorum_out_of_range() {
        assert!(error(&with("quorum = 2", "quorum = 4")).contains("quorum"));
        assert!(error(&with("quorum = 2", "quorum = 0")).contains("quorum"));
    }

    #[test]
    fn rejects_threshold_above_cap() {
        assert!(error(&with(
            r#"approval_above = "10""#,
            r#"approval_above = "101""#
        ))
        .contains("exceeds max_per_transfer"));
    }

    #[test]
    fn rejects_amount_finer_than_the_asset() {
        let text = with("decimals = 18", "decimals = 0")
            .replace(r#"approval_above = "10""#, r#"approval_above = "10.5""#);
        assert!(error(&text).contains("decimal places"));
    }

    #[test]
    fn rejects_empty_destinations() {
        assert!(error(&with(r#"["0xc01d", "0x5e77"]"#, "[]")).contains("destinations must not"));
    }

    #[test]
    fn rejects_destination_with_lookalike_characters() {
        assert!(error(&with("0x5e77", "0x5е77")).contains("may contain only"));
    }

    #[test]
    fn rejects_duplicate_keys() {
        let doubled = format!("{SAMPLE}\n{}", &SAMPLE[SAMPLE.find("[[keys]]").unwrap()..]);
        assert!(error(&doubled).contains("configured twice"));
    }
}
