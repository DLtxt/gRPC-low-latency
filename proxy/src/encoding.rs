//! Building blocks for the formats purpose-bound keys sign: transfers
//! (`transfer::canonical`) and releases (`release::statement`).
//!
//! Each format is a domain tag followed by fields, and they all follow the same rules,
//! which is why the rules live here once:
//!
//! * Every string is length-prefixed, because a bare concatenation would let `"ab" + "c"`
//!   and `"a" + "bc"` encode identically.
//! * Strings are plain ASCII, from an alphabet chosen per field. An approver is shown
//!   what these bytes say, and a Cyrillic lookalike, a right-to-left override or a
//!   zero-width space would display as something it is not.
//! * Decoding is strict: anything a decoder accepts re-encodes to exactly the same bytes,
//!   so there is never a second spelling of a request that a verifier and the signer
//!   could read differently.

/// A value that does not satisfy a format.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct FormatError(pub String);

pub fn invalid(message: impl Into<String>) -> FormatError {
    FormatError(message.into())
}

/// Field rules: maximum length and the characters allowed.
pub struct Field {
    pub name: &'static str,
    pub max_len: usize,
    pub allowed: fn(u8) -> bool,
    pub description: &'static str,
}

impl Field {
    pub fn check(&self, value: &str) -> Result<(), FormatError> {
        if value.is_empty() || value.len() > self.max_len {
            return Err(invalid(format!(
                "{} must be 1 to {} characters",
                self.name, self.max_len
            )));
        }
        if !value.bytes().all(self.allowed) {
            // Debug formatting escapes whatever made the value invalid, so the message
            // cannot itself carry the control characters it is complaining about.
            return Err(invalid(format!(
                "{} {value:?} may contain only {}",
                self.name, self.description
            )));
        }
        Ok(())
    }
}

/// Every format names the key it is for, so a signature cannot be presented as coming
/// from a different key.
const KEY_LABEL: Field = Field {
    name: "key_label",
    max_len: 64,
    allowed: |b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'),
    description: "letters, digits, '.', '_' and '-'",
};

pub fn check_key_label(value: &str) -> Result<(), FormatError> {
    KEY_LABEL.check(value)
}

/// Append a length-prefixed string.
pub fn put_str(out: &mut Vec<u8>, value: &str) {
    // Every string field is validated to at most 128 bytes, so this cannot truncate.
    debug_assert!(value.len() <= u8::MAX as usize);
    out.push(value.len() as u8);
    out.extend_from_slice(value.as_bytes());
}

/// Reads an encoding front to back.
pub struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], FormatError> {
        if self.bytes.len() < n {
            return Err(invalid("truncated encoding"));
        }
        let (head, tail) = self.bytes.split_at(n);
        self.bytes = tail;
        Ok(head)
    }

    pub fn byte(&mut self) -> Result<u8, FormatError> {
        Ok(self.take(1)?[0])
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], FormatError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    pub fn string(&mut self) -> Result<&'a str, FormatError> {
        let len = self.byte()? as usize;
        std::str::from_utf8(self.take(len)?).map_err(|_| invalid("string field is not UTF-8"))
    }

    /// Refuse anything after the last field: trailing bytes would be a second spelling.
    pub fn finish(self, last_field: &str) -> Result<(), FormatError> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(invalid(format!(
                "{} trailing bytes after the {last_field}",
                self.bytes.len()
            )))
        }
    }
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn from_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let bytes = [0x00, 0x7f, 0xff, 0x10];
        assert_eq!(from_hex(&to_hex(&bytes)).unwrap(), bytes);
        assert!(from_hex("abc").is_none());
        assert!(from_hex("zz").is_none());
    }

    #[test]
    fn reader_refuses_trailing_bytes() {
        let mut reader = Reader::new(&[1, 2, 3]);
        assert_eq!(reader.byte().unwrap(), 1);
        assert!(reader
            .finish("first byte")
            .unwrap_err()
            .0
            .contains("2 trailing"));
    }
}
