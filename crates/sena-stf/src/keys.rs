//! Derivation of trie keys for each kind of state.
//!
//! All L2 state shares one trie, so the key space has to be partitioned such
//! that no entry of one kind can ever be mistaken for, or collide with, an entry
//! of another. A collision between an account slot and a governance parameter
//! would let a crafted address overwrite a network setting.
//!
//! Each key is therefore a digest over a distinct domain tag plus the entry's
//! identifying fields, using the same length-prefixed encoding as every other
//! commitment in the protocol.

use sena_primitives::{CanonicalEncoder, Hash256, HashedIdentifier, L2Address};

/// Domain tags for the regions of the state trie.
mod region {
    pub const ACCOUNT: &[u8] = b"SENA:v1:state:account";
    pub const SOCIAL_BY_IDENTIFIER: &[u8] = b"SENA:v1:state:social-by-identifier";
    pub const SOCIAL_BY_ADDRESS: &[u8] = b"SENA:v1:state:social-by-address";
    pub const ASSET: &[u8] = b"SENA:v1:state:asset";
    pub const PARAMETER: &[u8] = b"SENA:v1:state:parameter";
}

/// Key of an account's state.
#[must_use]
pub fn account(address: &L2Address) -> Hash256 {
    Hash256::commit(CanonicalEncoder::new(region::ACCOUNT).field(address.as_bytes()))
}

/// Key of the address a hashed identifier resolves to (REQ-SOCIAL-004).
#[must_use]
pub fn social_by_identifier(identifier: &HashedIdentifier) -> Hash256 {
    Hash256::commit(
        CanonicalEncoder::new(region::SOCIAL_BY_IDENTIFIER).field(identifier.as_hash().as_bytes()),
    )
}

/// Key of the set of identifiers bound to an address (REQ-SOCIAL-005).
#[must_use]
pub fn social_by_address(address: &L2Address) -> Hash256 {
    Hash256::commit(CanonicalEncoder::new(region::SOCIAL_BY_ADDRESS).field(address.as_bytes()))
}

/// Key of a whitelisted gas asset's record (REQ-GAS-003).
#[must_use]
pub fn asset(asset_id: u32) -> Hash256 {
    Hash256::commit(CanonicalEncoder::new(region::ASSET).u64(u64::from(asset_id)))
}

/// Key of a governance parameter (REQ-GOV-005).
#[must_use]
pub fn parameter(name: &str) -> Hash256 {
    Hash256::commit(CanonicalEncoder::new(region::PARAMETER).field(name.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sena_primitives::{Channel, NetworkSalt};

    #[test]
    fn regions_do_not_collide() {
        // The same 32 bytes interpreted as an address and as an identifier must
        // land in different slots.
        let raw = [7u8; 32];
        let address = L2Address::from_bytes(raw);
        let identifier = HashedIdentifier(Hash256(raw));

        let keys = [
            account(&address),
            social_by_identifier(&identifier),
            social_by_address(&address),
        ];
        for (i, a) in keys.iter().enumerate() {
            for b in &keys[i + 1..] {
                assert_ne!(a, b, "state regions must be disjoint");
            }
        }
    }

    #[test]
    fn distinct_inputs_give_distinct_keys() {
        assert_ne!(
            account(&L2Address::from_bytes([1; 32])),
            account(&L2Address::from_bytes([2; 32]))
        );
        assert_ne!(asset(1), asset(2));
        assert_ne!(parameter("a"), parameter("b"));
    }

    #[test]
    fn parameter_names_are_unambiguous() {
        assert_ne!(parameter("ab"), parameter("a"));
    }

    #[test]
    fn keys_are_deterministic() {
        let salt = NetworkSalt::new(*b"salt");
        let id = HashedIdentifier::new(Channel::Handle, "alice", &salt);
        println!("root={}", social_by_identifier(&id));
        assert_eq!(social_by_identifier(&id), social_by_identifier(&id));
    }
}
