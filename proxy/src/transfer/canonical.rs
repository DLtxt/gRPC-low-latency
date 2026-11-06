//! The transfer format: the exact bytes a transfer key signs.
//!
//! The caller never supplies these bytes. It describes a transfer in fields, the proxy
//! checks the fields, and only then builds the encoding below -- so what the policy
//! checked and what the token signs cannot diverge, and there is no hash for a
//! compromised caller to smuggle through.
//!
//! ```text
//! "gll-transfer-v1\0"  16 bytes   domain tag and version
//! kind                  1 byte    0x01 = transfer; nothing else exists
//! key_label             u8 length, then ASCII
//! chain                 u8 length, then ASCII
//! asset                 u8 length, then ASCII
//! decimals              1 byte
//! destination           u8 length, then ASCII
//! amount               16 bytes   big-endian u128, in the asset's smallest unit
//! nonce                 8 bytes   big-endian u64
//! ```
//!
//! The tag is a domain separator: a signature over a transfer cannot be passed off as a
//! signature over anything else, and approvals and releases carry different tags, so
//! neither can double as a transfer signature. The other rules -- length-prefixed strings,
//! a plain-ASCII alphabet per field, strict decoding -- are shared with the release format
//! and live in `crate::encoding`.
//!
//! This is the project's own format, not a real chain's transaction encoding. A
//! deployment signing Ethereum or Bitcoin transactions would replace `encode` with that
//! chain's encoder and keep everything around it; the property that matters -- the
//! signer builds the bytes from fields it checked -- does not depend on the format.

use sha2::{Digest, Sha256};

use crate::approval::Statement;
use crate::encoding::{check_key_label, invalid, put_str, Field, FormatError, Reader};

/// Domain tag for transfers. Also the format version: a v2 would get a new tag.
pub const TRANSFER_TAG: &[u8; 16] = b"gll-transfer-v1\0";

/// The only kind of thing a transfer key can sign.
///
/// An enumerated kind rather than an implied one, so that adding a second -- say, a
/// delegation -- is a deliberate format change that existing verifiers reject, not a new
/// interpretation of bytes they already accept.
const KIND_TRANSFER: u8 = 0x01;

/// More decimal places than any real asset uses, and few enough that one whole unit
/// still leaves headroom inside a u128.
pub const MAX_DECIMALS: u8 = 30;

/// Longest decimal amount string accepted. A u128 has 39 digits; this leaves room for a
/// decimal point and fraction without letting a caller hand the parser a megabyte.
const MAX_AMOUNT_LEN: usize = 80;

const CHAIN: Field = Field {
    name: "chain",
    max_len: 32,
    allowed: |b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-',
    description: "lowercase letters, digits and '-'",
};

const ASSET: Field = Field {
    name: "asset",
    max_len: 16,
    allowed: |b| b.is_ascii_uppercase() || b.is_ascii_digit(),
    description: "uppercase letters and digits",
};

const DESTINATION: Field = Field {
    name: "destination",
    max_len: 128,
    allowed: |b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'.' | b'_' | b'-'),
    description: "letters, digits, ':', '.', '_' and '-'",
};

pub fn check_chain(value: &str) -> Result<(), FormatError> {
    CHAIN.check(value)
}

pub fn check_asset(value: &str) -> Result<(), FormatError> {
    ASSET.check(value)
}

pub fn check_destination(value: &str) -> Result<(), FormatError> {
    DESTINATION.check(value)
}

/// A transfer that satisfies the format. Fields are private so that every `Transfer`
/// in existence has been validated, and `encode` never has to consider one that was not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transfer {
    key_label: String,
    chain: String,
    asset: String,
    decimals: u8,
    destination: String,
    amount: u128,
    nonce: u64,
}

impl Transfer {
    pub fn new(
        key_label: &str,
        chain: &str,
        asset: &str,
        decimals: u8,
        destination: &str,
        amount: u128,
        nonce: u64,
    ) -> Result<Self, FormatError> {
        check_key_label(key_label)?;
        check_chain(chain)?;
        check_asset(asset)?;
        check_destination(destination)?;
        if decimals > MAX_DECIMALS {
            return Err(invalid(format!("decimals must be at most {MAX_DECIMALS}")));
        }
        if amount == 0 {
            return Err(invalid("amount must be greater than zero"));
        }
        Ok(Self {
            key_label: key_label.to_string(),
            chain: chain.to_string(),
            asset: asset.to_string(),
            decimals,
            destination: destination.to_string(),
            amount,
            nonce,
        })
    }

    pub fn key_label(&self) -> &str {
        &self.key_label
    }

    pub fn chain(&self) -> &str {
        &self.chain
    }

    pub fn asset(&self) -> &str {
        &self.asset
    }

    pub fn decimals(&self) -> u8 {
        self.decimals
    }

    pub fn destination(&self) -> &str {
        &self.destination
    }

    /// In the asset's smallest unit.
    pub fn amount(&self) -> u128 {
        self.amount
    }

    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    /// The amount in whole units, as a person would read it: `12.5`, not
    /// `12500000000000000000`.
    pub fn amount_display(&self) -> String {
        format_amount(self.amount, self.decimals)
    }

    /// One line, for logs and hold reasons.
    pub fn summary(&self) -> String {
        format!(
            "{} {} on {} to {} from {} (nonce {})",
            self.amount_display(),
            self.asset,
            self.chain,
            self.destination,
            self.key_label,
            self.nonce
        )
    }

    /// The canonical encoding. The only bytes a transfer key ever signs.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            TRANSFER_TAG.len()
                + 1
                + 4
                + self.key_label.len()
                + self.chain.len()
                + self.asset.len()
                + 1
                + self.destination.len()
                + 16
                + 8,
        );
        out.extend_from_slice(TRANSFER_TAG);
        out.push(KIND_TRANSFER);
        put_str(&mut out, &self.key_label);
        put_str(&mut out, &self.chain);
        put_str(&mut out, &self.asset);
        out.push(self.decimals);
        put_str(&mut out, &self.destination);
        out.extend_from_slice(&self.amount.to_be_bytes());
        out.extend_from_slice(&self.nonce.to_be_bytes());
        out
    }

    /// Parse a canonical encoding, accepting nothing else.
    ///
    /// Strict in both directions: anything `decode` accepts re-encodes to exactly the
    /// same bytes, so there is never a second spelling of a transfer that a verifier
    /// and the signer could read differently.
    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        let mut reader = Reader::new(bytes);

        if reader.take(TRANSFER_TAG.len())? != TRANSFER_TAG {
            return Err(invalid("not a gll-transfer-v1 encoding"));
        }
        match reader.byte()? {
            KIND_TRANSFER => {}
            other => return Err(invalid(format!("unknown kind 0x{other:02x}"))),
        }

        let key_label = reader.string()?;
        let chain = reader.string()?;
        let asset = reader.string()?;
        let decimals = reader.byte()?;
        let destination = reader.string()?;
        let amount = u128::from_be_bytes(reader.array()?);
        let nonce = u64::from_be_bytes(reader.array()?);
        reader.finish("nonce")?;

        Self::new(
            key_label,
            chain,
            asset,
            decimals,
            destination,
            amount,
            nonce,
        )
    }

    /// SHA-256 of the canonical encoding: what approvers and logs call the transfer.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.encode()).into()
    }
}

impl Statement for Transfer {
    fn encode(&self) -> Vec<u8> {
        Transfer::encode(self)
    }

    fn digest(&self) -> [u8; 32] {
        Transfer::digest(self)
    }

    fn summary(&self) -> String {
        Transfer::summary(self)
    }
}

/// Parse a decimal amount in whole units into the asset's smallest unit.
///
/// Exact integer arithmetic throughout. `"12.5"` with 18 decimals is
/// `12_500_000_000_000_000_000`; more fractional digits than the asset has is an error
/// rather than a rounding, because a silently rounded amount is a different transfer.
/// Accepts `0` -- the policy uses it to mean "never" -- so a transfer's own non-zero
/// rule lives in `Transfer::new`.
pub fn parse_amount(text: &str, decimals: u8) -> Result<u128, FormatError> {
    let not_a_number = || {
        invalid(format!(
            "amount {text:?} is not a plain decimal number such as \"12.5\""
        ))
    };

    if text.is_empty() || text.len() > MAX_AMOUNT_LEN {
        return Err(not_a_number());
    }
    if decimals > MAX_DECIMALS {
        return Err(invalid(format!("decimals must be at most {MAX_DECIMALS}")));
    }

    let (whole, fraction) = match text.split_once('.') {
        Some((whole, fraction)) => (whole, fraction),
        None => (text, ""),
    };
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());

    if !digits(whole) || (text.contains('.') && !digits(fraction)) {
        return Err(not_a_number());
    }
    // Some systems read a leading zero as octal, so "010" could mean 8 to the caller and
    // 10 to the signer. Refusing it is cheaper than finding out which.
    if whole.len() > 1 && whole.starts_with('0') {
        return Err(not_a_number());
    }
    if fraction.len() > decimals as usize {
        return Err(invalid(format!(
            "amount {text:?} has more than {decimals} decimal places"
        )));
    }

    let too_large = || invalid(format!("amount {text:?} is too large"));
    let scale = 10u128.pow(decimals as u32);
    let whole_units: u128 = whole.parse().map_err(|_| too_large())?;
    let fraction_units: u128 = if fraction.is_empty() {
        0
    } else {
        let padding = 10u128.pow((decimals as usize - fraction.len()) as u32);
        // At most MAX_DECIMALS digits, so this parse cannot overflow.
        fraction.parse::<u128>().map_err(|_| not_a_number())? * padding
    };

    whole_units
        .checked_mul(scale)
        .and_then(|units| units.checked_add(fraction_units))
        .ok_or_else(too_large)
}

/// Render an amount in the asset's smallest unit as whole units, without trailing zeros.
pub fn format_amount(amount: u128, decimals: u8) -> String {
    // Clamped once so the scale and the padding agree. Nothing valid exceeds it.
    let decimals = decimals.min(MAX_DECIMALS);
    let scale = 10u128.pow(decimals as u32);
    let whole = amount / scale;
    let fraction = amount % scale;
    if fraction == 0 {
        return whole.to_string();
    }
    let fraction = format!("{fraction:0width$}", width = decimals as usize);
    format!("{whole}.{}", fraction.trim_end_matches('0'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::APPROVAL_TAG;
    use crate::encoding::to_hex;

    const WEI: u128 = 1_000_000_000_000_000_000;

    fn sample() -> Transfer {
        Transfer::new(
            "demo-transfer-key",
            "devnet",
            "ETH",
            18,
            "0xc01dc01dc01dc01dc01dc01dc01dc01dc01dc01d",
            12 * WEI + WEI / 2,
            7,
        )
        .unwrap()
    }

    #[test]
    fn round_trips() {
        let transfer = sample();
        assert_eq!(Transfer::decode(&transfer.encode()).unwrap(), transfer);
    }

    /// Pinned so that an accidental change to the encoding -- which would invalidate
    /// every signature and approval ever made -- fails a test instead of shipping. The
    /// value was cross-checked against a separate implementation of the layout in the
    /// module docs, not just copied from this encoder's output.
    #[test]
    fn encoding_is_stable() {
        assert_eq!(
            to_hex(&sample().digest()),
            "1b5892b46531a51ac1f41e03425afd0237dfb4e12b535c7377a90fec82c68c58"
        );
    }

    #[test]
    fn fields_are_length_prefixed() {
        // Moving a character between adjacent fields must change the encoding.
        let a = Transfer::new("k", "ab", "C", 0, "d", 1, 0).unwrap();
        let b = Transfer::new("k", "a", "BC", 0, "d", 1, 0).unwrap();
        assert_ne!(a.encode(), b.encode());
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut bytes = sample().encode();
        bytes.push(0);
        assert!(Transfer::decode(&bytes).is_err());
    }

    #[test]
    fn rejects_truncation_at_every_length() {
        let bytes = sample().encode();
        for len in 0..bytes.len() {
            assert!(
                Transfer::decode(&bytes[..len]).is_err(),
                "accepted {len} bytes"
            );
        }
    }

    #[test]
    fn rejects_other_kinds_and_tags() {
        let mut bytes = sample().encode();
        bytes[TRANSFER_TAG.len()] = 0x02;
        assert!(Transfer::decode(&bytes).is_err());

        let mut bytes = sample().encode();
        bytes[..16].copy_from_slice(APPROVAL_TAG);
        assert!(Transfer::decode(&bytes).is_err());
    }

    #[test]
    fn rejects_lookalike_and_invisible_characters() {
        // Cyrillic 'а' in place of Latin 'a', a right-to-left override, a zero-width
        // space, and a space: each would display as something other than it is.
        for destination in ["0xаbc", "0x\u{202e}cba", "0x\u{200b}abc", "0x abc"] {
            assert!(
                Transfer::new("k", "devnet", "ETH", 18, destination, 1, 0).is_err(),
                "accepted {destination:?}"
            );
        }
    }

    #[test]
    fn rejects_zero_amount() {
        assert!(Transfer::new("k", "devnet", "ETH", 18, "0xabc", 0, 0).is_err());
    }

    #[test]
    fn parses_amounts_exactly() {
        assert_eq!(parse_amount("12.5", 18).unwrap(), 12 * WEI + WEI / 2);
        assert_eq!(parse_amount("1", 18).unwrap(), WEI);
        assert_eq!(parse_amount("0.000000000000000001", 18).unwrap(), 1);
        assert_eq!(parse_amount("1.50", 2).unwrap(), 150);
        assert_eq!(parse_amount("0", 6).unwrap(), 0);
        assert_eq!(parse_amount("42", 0).unwrap(), 42);
    }

    #[test]
    fn rejects_amounts_that_are_not_one_plain_spelling() {
        for text in [
            "", ".5", "1.", "+1", "-1", "1e3", " 1", "1 ", "1,000", "1_000", "007", "0x10", "1.2.3",
        ] {
            assert!(parse_amount(text, 18).is_err(), "accepted {text:?}");
        }
    }

    #[test]
    fn rejects_excess_precision_instead_of_rounding() {
        assert!(parse_amount("1.001", 2).is_err());
        assert!(parse_amount("1.5", 0).is_err());
    }

    #[test]
    fn rejects_overflow() {
        assert!(parse_amount(&"9".repeat(40), 0).is_err());
        assert!(parse_amount("340282366920938463464", 18).is_err());
    }

    #[test]
    fn formats_without_trailing_zeros() {
        assert_eq!(format_amount(12 * WEI + WEI / 2, 18), "12.5");
        assert_eq!(format_amount(WEI, 18), "1");
        assert_eq!(format_amount(1, 18), "0.000000000000000001");
        assert_eq!(format_amount(150, 2), "1.5");
        assert_eq!(format_amount(42, 0), "42");
    }
}
