//! Canonical binary encoding for values stored in the state trie.
//!
//! # Why not JSON
//!
//! State values are hashed into the trie, and the trie root is what Aptos L1
//! adjudicates disputes against. During one-step verification the `sena::osp`
//! Move contract must decode the slot a step touches, apply the step, and
//! re-encode it — so whatever encoding the Rust node uses, a Move contract has
//! to reproduce byte for byte.
//!
//! JSON cannot meet that bar. Reimplementing a JSON parser in Move that agrees
//! with `serde_json` on every edge — number formatting, escaping, field order,
//! whitespace — would be both large and a permanent source of consensus risk.
//!
//! This encoding is designed to be trivial to reimplement:
//!
//! - integers are fixed-width big-endian, so there is one representation per value;
//! - byte strings carry a 4-byte big-endian length;
//! - sequences carry a 4-byte count, then their elements;
//! - enums carry a single-byte discriminant;
//! - there is no whitespace, no optional field, and no alternative spelling of
//!   any value.
//!
//! Every encoding is therefore canonical: two encoders that agree on the field
//! order produce identical bytes, and a decoder that accepts trailing input is
//! a bug rather than a tolerance.

use crate::hash::Hash256;

/// Why decoding failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum DecodeError {
    /// The input ended before the value did.
    #[error("input ended unexpectedly")]
    Truncated,
    /// A discriminant did not name a known variant.
    #[error("unknown variant discriminant {0}")]
    UnknownVariant(u8),
    /// Bytes remained after the value was decoded.
    ///
    /// Rejected rather than ignored: trailing bytes would give one value two
    /// valid encodings, and the trie commits to bytes.
    #[error("{0} trailing bytes after the value")]
    TrailingBytes(usize),
    /// A length field exceeded what the remaining input can hold.
    #[error("declared length exceeds the remaining input")]
    LengthOverflow,
}

/// Appends values to a byte buffer.
#[derive(Debug, Default, Clone)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// Creates an empty writer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a `u8`.
    pub fn u8(&mut self, value: u8) -> &mut Self {
        self.buf.push(value);
        self
    }

    /// Appends a big-endian `u32`.
    pub fn u32(&mut self, value: u32) -> &mut Self {
        self.buf.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// Appends a big-endian `u64`.
    pub fn u64(&mut self, value: u64) -> &mut Self {
        self.buf.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// Appends a big-endian `u128`.
    pub fn u128(&mut self, value: u128) -> &mut Self {
        self.buf.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// Appends a boolean as one byte.
    pub fn bool(&mut self, value: bool) -> &mut Self {
        self.u8(u8::from(value))
    }

    /// Appends a 32-byte value with no length prefix.
    pub fn hash(&mut self, value: &Hash256) -> &mut Self {
        self.buf.extend_from_slice(value.as_bytes());
        self
    }

    /// Appends a fixed 32-byte array with no length prefix.
    pub fn bytes32(&mut self, value: &[u8; 32]) -> &mut Self {
        self.buf.extend_from_slice(value);
        self
    }

    /// Appends a length-prefixed byte string.
    ///
    /// # Panics
    ///
    /// Panics if the string is longer than `u32::MAX`, which no state value
    /// approaches.
    pub fn bytes(&mut self, value: &[u8]) -> &mut Self {
        let len = u32::try_from(value.len()).expect("value exceeds u32::MAX bytes");
        self.u32(len);
        self.buf.extend_from_slice(value);
        self
    }

    /// Appends a length-prefixed UTF-8 string.
    pub fn string(&mut self, value: &str) -> &mut Self {
        self.bytes(value.as_bytes())
    }

    /// Returns the encoded bytes.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// Reads values from a byte slice.
#[derive(Debug)]
pub struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    /// Creates a reader over `input`.
    #[must_use]
    pub const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    /// Reads a `u8`.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Truncated`] if the input is exhausted.
    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        let byte = *self.input.get(self.offset).ok_or(DecodeError::Truncated)?;
        self.offset += 1;
        Ok(byte)
    }

    /// Reads a big-endian `u32`.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Truncated`] if fewer than four bytes remain.
    ///
    /// # Panics
    ///
    /// Does not panic: the slice is taken at a fixed width before conversion.
    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("slice is four bytes"),
        ))
    }

    /// Reads a big-endian `u64`.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Truncated`] if fewer than eight bytes remain.
    ///
    /// # Panics
    ///
    /// Does not panic: the slice is taken at a fixed width before conversion.
    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("slice is eight bytes"),
        ))
    }

    /// Reads a big-endian `u128`.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Truncated`] if fewer than sixteen bytes remain.
    ///
    /// # Panics
    ///
    /// Does not panic: the slice is taken at a fixed width before conversion.
    pub fn u128(&mut self) -> Result<u128, DecodeError> {
        Ok(u128::from_be_bytes(
            self.take(16)?.try_into().expect("slice is sixteen bytes"),
        ))
    }

    /// Reads a boolean.
    ///
    /// Any non-zero byte other than one is rejected, so a boolean has exactly
    /// two valid encodings.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] if the input is exhausted or the byte is not 0 or 1.
    pub fn bool(&mut self) -> Result<bool, DecodeError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(DecodeError::UnknownVariant(other)),
        }
    }

    /// Reads a fixed 32-byte array.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Truncated`] if fewer than 32 bytes remain.
    ///
    /// # Panics
    ///
    /// Does not panic: the slice is taken at a fixed width before conversion.
    pub fn bytes32(&mut self) -> Result<[u8; 32], DecodeError> {
        Ok(self.take(32)?.try_into().expect("slice is 32 bytes"))
    }

    /// Reads a 32-byte hash.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Truncated`] if fewer than 32 bytes remain.
    pub fn hash(&mut self) -> Result<Hash256, DecodeError> {
        Ok(Hash256(self.bytes32()?))
    }

    /// Reads a length-prefixed byte string.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] if the input is truncated or the declared length
    /// exceeds what remains.
    pub fn bytes(&mut self) -> Result<Vec<u8>, DecodeError> {
        let len = self.u32()? as usize;
        if len > self.input.len().saturating_sub(self.offset) {
            return Err(DecodeError::LengthOverflow);
        }
        Ok(self.take(len)?.to_vec())
    }

    /// Reads a length-prefixed UTF-8 string.
    ///
    /// Invalid UTF-8 is replaced rather than rejected, because the bytes are
    /// what the trie committed to: refusing to decode a slot the chain has
    /// already accepted would make a step unverifiable.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] if the input is truncated.
    pub fn string(&mut self) -> Result<String, DecodeError> {
        Ok(String::from_utf8_lossy(&self.bytes()?).into_owned())
    }

    /// Finishes decoding, rejecting any trailing input.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::TrailingBytes`] if bytes remain.
    pub fn finish(self) -> Result<(), DecodeError> {
        let remaining = self.input.len() - self.offset;
        if remaining == 0 {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes(remaining))
        }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self
            .offset
            .checked_add(n)
            .ok_or(DecodeError::LengthOverflow)?;
        let slice = self
            .input
            .get(self.offset..end)
            .ok_or(DecodeError::Truncated)?;
        self.offset = end;
        Ok(slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_round_trip() {
        let mut w = Writer::new();
        w.u8(7)
            .u32(1 << 20)
            .u64(u64::MAX)
            .u128(12_345_678_901_234_567_890);
        let bytes = w.finish();

        let mut r = Reader::new(&bytes);
        assert_eq!(r.u8().unwrap(), 7);
        assert_eq!(r.u32().unwrap(), 1 << 20);
        assert_eq!(r.u64().unwrap(), u64::MAX);
        assert_eq!(r.u128().unwrap(), 12_345_678_901_234_567_890);
        r.finish().unwrap();
    }

    #[test]
    fn integers_are_big_endian() {
        // Fixed byte order is what lets a Move implementation agree without
        // knowing the host's architecture.
        let mut w = Writer::new();
        w.u32(1);
        assert_eq!(w.finish(), vec![0, 0, 0, 1]);
    }

    #[test]
    fn strings_round_trip() {
        let mut w = Writer::new();
        w.string("USDC").string("");
        let bytes = w.finish();

        let mut r = Reader::new(&bytes);
        assert_eq!(r.string().unwrap(), "USDC");
        assert_eq!(r.string().unwrap(), "");
        r.finish().unwrap();
    }

    #[test]
    fn framing_disambiguates_adjacent_strings() {
        let mut a = Writer::new();
        a.string("ab").string("c");
        let mut b = Writer::new();
        b.string("a").string("bc");
        assert_ne!(a.finish(), b.finish());
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        // Two encodings of one value would mean two trie leaves for one state.
        let mut w = Writer::new();
        w.u64(1);
        let mut bytes = w.finish();
        bytes.push(0);

        let mut r = Reader::new(&bytes);
        r.u64().unwrap();
        assert_eq!(r.finish().unwrap_err(), DecodeError::TrailingBytes(1));
    }

    #[test]
    fn truncated_input_is_rejected() {
        let bytes = [0u8; 3];
        assert_eq!(
            Reader::new(&bytes).u32().unwrap_err(),
            DecodeError::Truncated
        );
    }

    #[test]
    fn an_overlong_length_is_rejected_rather_than_panicking() {
        // A hostile or corrupt slot must not be able to crash a verifier.
        let bytes = [0xFF, 0xFF, 0xFF, 0xFF, 0x00];
        assert_eq!(
            Reader::new(&bytes).bytes().unwrap_err(),
            DecodeError::LengthOverflow
        );
    }

    #[test]
    fn booleans_have_exactly_two_encodings() {
        assert!(!Reader::new(&[0]).bool().unwrap());
        assert!(Reader::new(&[1]).bool().unwrap());
        assert_eq!(
            Reader::new(&[2]).bool().unwrap_err(),
            DecodeError::UnknownVariant(2)
        );
    }

    #[test]
    fn determinism_encoding_is_reproducible() {
        let encode = || {
            let mut w = Writer::new();
            w.u64(42).string("stable").u128(7);
            w.finish()
        };
        let bytes = encode();
        println!("root={}", hex::encode(Hash256::digest(&bytes).0));
        assert_eq!(bytes, encode());
    }
}
