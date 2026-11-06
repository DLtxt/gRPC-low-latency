//! The release format: the exact bytes a release key signs.
//!
//! A release statement says that the file with this SHA-256 is this version of this
//! artifact, published on this channel, by this key. Checking a download needs the file,
//! the fields the client expects, the signature and the key's public half -- nothing
//! from the proxy.
//!
//! ```text
//! "gll-release-v1\0"   15 bytes   domain tag and version
//! kind                  1 byte    0x01 = release; nothing else exists
//! key_label             u8 length, then ASCII
//! artifact              u8 length, then ASCII
//! version               u8 length, then ASCII
//! channel               u8 length, then ASCII
//! sha256               32 bytes   the released file's SHA-256
//! ```
//!
//! The channel is signed, not just the file: a build signed for `beta` cannot be
//! presented as a `stable` release, because that is a different statement with a
//! different signature. The rules shared with the transfer format -- length prefixes, a
//! plain-ASCII alphabet per field, strict decoding -- live in `crate::encoding`.
//!
//! Versions are strict semantic versions: `MAJOR.MINOR.PATCH`, with an optional
//! `-prerelease`, and nothing else. Build metadata (`+build.5`) and leading zeros are
//! refused, because each would give one version two spellings: semantic versioning
//! ignores build metadata when comparing versions, and `1.04.0` is `1.4.0`. The guard's
//! rule that a version names one file is only as good as there being one way to write
//! the version.

use sha2::{Digest, Sha256};

use crate::approval::Statement;
use crate::encoding::{check_key_label, invalid, put_str, to_hex, Field, FormatError, Reader};

/// Domain tag for releases. Also the format version: a v2 would get a new tag.
pub const RELEASE_TAG: &[u8; 15] = b"gll-release-v1\0";

/// The only kind of thing a release key can sign. Enumerated for the same reason as the
/// transfer format's kind: a second one would be a deliberate format change.
const KIND_RELEASE: u8 = 0x01;

const ARTIFACT: Field = Field {
    name: "artifact",
    max_len: 64,
    allowed: |b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-',
    description: "lowercase letters, digits and '-'",
};

const CHANNEL: Field = Field {
    name: "channel",
    max_len: 32,
    allowed: |b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-',
    description: "lowercase letters, digits and '-'",
};

const MAX_VERSION_LEN: usize = 64;

pub fn check_artifact(value: &str) -> Result<(), FormatError> {
    ARTIFACT.check(value)
}

pub fn check_channel(value: &str) -> Result<(), FormatError> {
    CHANNEL.check(value)
}

/// A strict semantic version: `1.4.0` or `1.4.0-rc.1`, one spelling per version.
pub fn check_version(value: &str) -> Result<(), FormatError> {
    if value.is_empty() || value.len() > MAX_VERSION_LEN {
        return Err(invalid(format!(
            "version must be 1 to {MAX_VERSION_LEN} characters"
        )));
    }
    let not_semver = || {
        invalid(format!(
            "version {value:?} is not a semantic version such as \"1.4.0\" or \
             \"1.4.0-rc.1\" (no build metadata, no leading zeros)"
        ))
    };
    let number = |part: &str| {
        !part.is_empty()
            && part.bytes().all(|b| b.is_ascii_digit())
            && !(part.len() > 1 && part.starts_with('0'))
    };

    let (core, prerelease) = match value.split_once('-') {
        Some((core, prerelease)) => (core, Some(prerelease)),
        None => (value, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() != 3 || !parts.iter().all(|part| number(part)) {
        return Err(not_semver());
    }
    if let Some(prerelease) = prerelease {
        for identifier in prerelease.split('.') {
            let alphanumeric = !identifier.is_empty()
                && identifier
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-');
            let numeric = identifier.bytes().all(|b| b.is_ascii_digit());
            if !alphanumeric || (numeric && !number(identifier)) {
                return Err(not_semver());
            }
        }
    }
    Ok(())
}

/// A release that satisfies the format. Fields are private so that every `Release` in
/// existence has been validated, and `encode` never has to consider one that was not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    key_label: String,
    artifact: String,
    version: String,
    channel: String,
    sha256: [u8; 32],
}

impl Release {
    pub fn new(
        key_label: &str,
        artifact: &str,
        version: &str,
        channel: &str,
        sha256: [u8; 32],
    ) -> Result<Self, FormatError> {
        check_key_label(key_label)?;
        check_artifact(artifact)?;
        check_version(version)?;
        check_channel(channel)?;
        Ok(Self {
            key_label: key_label.to_string(),
            artifact: artifact.to_string(),
            version: version.to_string(),
            channel: channel.to_string(),
            sha256,
        })
    }

    pub fn key_label(&self) -> &str {
        &self.key_label
    }

    pub fn artifact(&self) -> &str {
        &self.artifact
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn channel(&self) -> &str {
        &self.channel
    }

    /// The released file's SHA-256.
    pub fn sha256(&self) -> [u8; 32] {
        self.sha256
    }

    /// One line, for logs and hold reasons.
    pub fn summary(&self) -> String {
        format!(
            "{} {} on {} (file sha256 {}) from {}",
            self.artifact,
            self.version,
            self.channel,
            to_hex(&self.sha256),
            self.key_label
        )
    }

    /// The canonical encoding. The only bytes a release key ever signs.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            RELEASE_TAG.len()
                + 1
                + 4
                + self.key_label.len()
                + self.artifact.len()
                + self.version.len()
                + self.channel.len()
                + 32,
        );
        out.extend_from_slice(RELEASE_TAG);
        out.push(KIND_RELEASE);
        put_str(&mut out, &self.key_label);
        put_str(&mut out, &self.artifact);
        put_str(&mut out, &self.version);
        put_str(&mut out, &self.channel);
        out.extend_from_slice(&self.sha256);
        out
    }

    /// Parse a canonical encoding, accepting nothing else.
    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        let mut reader = Reader::new(bytes);

        if reader.take(RELEASE_TAG.len())? != RELEASE_TAG {
            return Err(invalid("not a gll-release-v1 encoding"));
        }
        match reader.byte()? {
            KIND_RELEASE => {}
            other => return Err(invalid(format!("unknown kind 0x{other:02x}"))),
        }

        let key_label = reader.string()?;
        let artifact = reader.string()?;
        let version = reader.string()?;
        let channel = reader.string()?;
        let sha256 = reader.array()?;
        reader.finish("sha256")?;

        Self::new(key_label, artifact, version, channel, sha256)
    }

    /// SHA-256 of the canonical encoding: what approvers and logs call the release.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.encode()).into()
    }
}

impl Statement for Release {
    fn encode(&self) -> Vec<u8> {
        Release::encode(self)
    }

    fn digest(&self) -> [u8; 32] {
        Release::digest(self)
    }

    fn summary(&self) -> String {
        Release::summary(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::APPROVAL_TAG;
    use crate::transfer::canonical::TRANSFER_TAG;

    fn file() -> [u8; 32] {
        Sha256::digest(b"gll-proxy 1.4.0 linux-amd64").into()
    }

    fn sample() -> Release {
        Release::new("demo-release-key", "gll-proxy", "1.4.0", "stable", file()).unwrap()
    }

    #[test]
    fn round_trips() {
        let release = sample();
        assert_eq!(Release::decode(&release.encode()).unwrap(), release);
    }

    /// A change here changes every release signature, so it has to be deliberate. The
    /// expected digest was computed by an independent Python implementation of the
    /// layout in the module documentation, not by this code.
    #[test]
    fn encoding_is_stable() {
        assert_eq!(sample().encode().len(), 88);
        assert_eq!(
            to_hex(&sample().digest()),
            "ec73339d2fa290715221ac426437fd7c91484a1b25cf560998255ff5fd7c8a66"
        );
    }

    #[test]
    fn the_channel_is_part_of_what_is_signed() {
        let beta = Release::new("demo-release-key", "gll-proxy", "1.4.0", "beta", file()).unwrap();
        assert_ne!(beta.digest(), sample().digest());
    }

    #[test]
    fn rejects_trailing_bytes_and_truncation() {
        let mut bytes = sample().encode();
        for len in 0..bytes.len() {
            assert!(
                Release::decode(&bytes[..len]).is_err(),
                "accepted {len} bytes"
            );
        }
        bytes.push(0);
        assert!(Release::decode(&bytes).is_err());
    }

    /// Neither a transfer nor an approval can be read as a release.
    #[test]
    fn rejects_other_kinds_and_tags() {
        let mut bytes = sample().encode();
        bytes[RELEASE_TAG.len()] = 0x02;
        assert!(Release::decode(&bytes).is_err());

        for tag in [&TRANSFER_TAG[..15], &APPROVAL_TAG[..15]] {
            let mut bytes = sample().encode();
            bytes[..15].copy_from_slice(tag);
            assert!(Release::decode(&bytes).is_err());
        }
    }

    #[test]
    fn accepts_semantic_versions() {
        for version in [
            "0.1.0",
            "1.4.0",
            "10.20.30",
            "1.4.0-rc.1",
            "1.0.0-alpha-1",
            "2.0.0-0.3.7",
        ] {
            check_version(version).unwrap_or_else(|e| panic!("{version}: {e}"));
        }
    }

    /// Every version has one spelling, or "one file per version" means nothing.
    #[test]
    fn rejects_versions_that_are_not_one_spelling() {
        for version in [
            "1.4",
            "1.4.0.1",
            "01.4.0",
            "1.04.0",
            "1.4.0+build.5",
            "1.4.0-",
            "1.4.0-rc..1",
            "1.4.0-01",
            "v1.4.0",
            " 1.4.0",
            "1.4.0 ",
            "1.4.0-rc\u{200b}",
        ] {
            assert!(check_version(version).is_err(), "accepted {version:?}");
        }
    }

    #[test]
    fn rejects_lookalike_and_invisible_characters() {
        for artifact in ["gll-prоxy", "GLL-proxy", "gll proxy", "gll-proxy\u{200b}"] {
            assert!(
                Release::new("demo-release-key", artifact, "1.4.0", "stable", file()).is_err(),
                "accepted {artifact:?}"
            );
        }
    }
}
