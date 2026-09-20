//! Hex serialisation for fixed-size byte arrays.
//!
//! `serde` cannot derive these for arrays larger than 32 elements, and hex keeps
//! the JSON wire format readable while it is the protocol's transport.

/// Serialises a `[u8; 32]` as a hex string.
pub mod bytes_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    /// Writes the array as lowercase hex.
    ///
    /// # Errors
    ///
    /// Propagates the serializer's error.
    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    /// Reads a 64-character hex string.
    ///
    /// # Errors
    ///
    /// Returns an error if the string is not hex or is not 32 bytes.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

/// Serialises a `[u8; 64]` as a hex string.
pub mod bytes_64 {
    use serde::{Deserialize, Deserializer, Serializer};

    /// Writes the array as lowercase hex.
    ///
    /// # Errors
    ///
    /// Propagates the serializer's error.
    pub fn serialize<S: Serializer>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    /// Reads a 128-character hex string.
    ///
    /// # Errors
    ///
    /// Returns an error if the string is not hex or is not 64 bytes.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes"))
    }
}
