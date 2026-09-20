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

/// Serialises a `u128` as a decimal string.
///
/// JSON numbers are IEEE-754 doubles in most clients, JavaScript included, so a
/// `u128` balance sent as a JSON number is silently rounded above 2^53 — an
/// integrator would read a wrong balance with no error raised anywhere.
/// `serde_json` refuses to encode `u128` at all, for related reasons.
///
/// Amounts therefore travel as decimal strings on the wire. This affects only
/// the JSON representation: consensus hashing uses the canonical binary codec,
/// where a `u128` is sixteen big-endian bytes.
pub mod u128_string {
    use serde::{Deserialize, Deserializer, Serializer};

    /// Writes the value as a decimal string.
    ///
    /// # Errors
    ///
    /// Propagates the serializer's error.
    pub fn serialize<S: Serializer>(value: &u128, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&value.to_string())
    }

    /// Reads a decimal string.
    ///
    /// # Errors
    ///
    /// Returns an error if the string is not a decimal `u128`.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u128, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Serialises `Vec<(u32, u128)>` with the amounts as decimal strings.
pub mod balances {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    struct Entry {
        asset: u32,
        amount: String,
    }

    /// Writes balances with string amounts.
    ///
    /// # Errors
    ///
    /// Propagates the serializer's error.
    pub fn serialize<S: Serializer>(value: &[(u32, u128)], s: S) -> Result<S::Ok, S::Error> {
        let entries: Vec<Entry> = value
            .iter()
            .map(|(asset, amount)| Entry {
                asset: *asset,
                amount: amount.to_string(),
            })
            .collect();
        entries.serialize(s)
    }

    /// Reads balances with string amounts.
    ///
    /// # Errors
    ///
    /// Returns an error if an amount is not a decimal `u128`.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<(u32, u128)>, D::Error> {
        let entries = Vec::<Entry>::deserialize(d)?;
        entries
            .into_iter()
            .map(|e| {
                e.amount
                    .parse()
                    .map(|amount| (e.asset, amount))
                    .map_err(serde::de::Error::custom)
            })
            .collect()
    }
}
