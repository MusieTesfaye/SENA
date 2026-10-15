//! Keyless accounts through the node: genesis, admission, block production and
//! independent verification, driven by Aptos's real circuit proof.

use ed25519_dalek::{Signer, SigningKey};
use sena_primitives::{AssetId, L2Address};
use sena_stf::keyless::{aptos_sample, KeylessConfig};
use sena_stf::{Authenticator, Payload, Transaction};

use sena_fraudproof::{AssertionChain, PartyId};
use sena_node::genesis::{Allocation, GenesisConfig, GenesisError, JwkConfig, KeylessGenesis};
use sena_node::{Outcome, RejectReason, Sequencer, VerifierNode};

const USDC: AssetId = AssetId(1);
const RECIPIENT: L2Address = L2Address::from_bytes([9; 32]);

/// Inside the sample ephemeral key's lifetime.
fn early() -> u64 {
    1_700_000_000
}

/// After the sample ephemeral key has expired.
fn late() -> u64 {
    aptos_sample::EXP_DATE_SECS
}

fn config(jwks: Vec<JwkConfig>) -> GenesisConfig {
    let mut config = GenesisConfig::dev(vec![Allocation {
        address: aptos_sample::signature().address(),
        asset: 1,
        amount: 1_000_000,
    }]);
    config.keyless = Some(KeylessGenesis {
        setup: KeylessConfig::aptos_devnet_insecure().name.to_owned(),
        allow_insecure_test_setup: true,
        jwks,
    });
    config
}

fn sample_jwk() -> JwkConfig {
    JwkConfig {
        iss: aptos_sample::ISS.to_owned(),
        kid: "test-rsa".to_owned(),
        n: aptos_sample::JWK_N.to_owned(),
    }
}

fn sequencer(config: &GenesisConfig, clock: fn() -> u64) -> Sequencer {
    let state = config.build_state().unwrap();
    let chain = AssertionChain::new(
        state.root(),
        config.challenge_window_secs,
        config.minimum_bond,
    );
    Sequencer::new(state, chain, PartyId(1), config.minimum_bond)
        .with_keyless(config.keyless_config().unwrap())
        .with_clock(clock)
}

fn keyless_transfer(amount: u128) -> Transaction {
    let mut tx = Transaction {
        sender: aptos_sample::signature().address(),
        nonce: 0,
        fee_asset: USDC,
        fee_rate: 0,
        fee_intrinsic_gas: 0,
        gas_limit: 0,
        max_fee_per_gas: 0,
        max_priority_fee_per_gas: 0,
        payload: Payload::Transfer {
            to: RECIPIENT,
            asset: USDC,
            amount,
        },
        authenticator: Authenticator::Keyless(Box::new(aptos_sample::signature())),
    };
    sena_stf::gas::fill_default_fees(&mut tx);
    let esk = SigningKey::from_bytes(&aptos_sample::ephemeral_secret_key());
    let signature = esk.sign(tx.signing_digest().as_bytes()).to_bytes();
    if let Authenticator::Keyless(sig) = &mut tx.authenticator {
        sig.ephemeral_signature = signature;
    }
    tx
}

#[test]
fn the_insecure_test_setup_must_be_acknowledged() {
    let mut config = config(vec![]);
    config.keyless.as_mut().unwrap().allow_insecure_test_setup = false;
    assert!(matches!(
        config.validate(),
        Err(GenesisError::InsecureKeylessSetup(_))
    ));
}

#[test]
fn an_unknown_setup_is_refused() {
    let mut config = config(vec![]);
    config.keyless.as_mut().unwrap().setup = "my-own-ceremony".to_owned();
    assert!(matches!(
        config.validate(),
        Err(GenesisError::UnknownKeylessSetup(_))
    ));
}

#[test]
fn the_mainnet_setup_needs_no_acknowledgement() {
    let mut config = config(vec![]);
    let k = config.keyless.as_mut().unwrap();
    k.setup = KeylessConfig::aptos_mainnet().name.to_owned();
    k.allow_insecure_test_setup = false;
    assert!(config.validate().is_ok());
}

#[test]
fn genesis_jwks_change_the_genesis_root() {
    assert_ne!(
        config(vec![]).state_root().unwrap(),
        config(vec![sample_jwk()]).state_root().unwrap()
    );
}

#[test]
fn a_keyless_transfer_is_sealed_and_independently_verified() {
    let config = config(vec![sample_jwk()]);
    let mut seq = sequencer(&config, early);
    seq.submit(keyless_transfer(1_234)).expect("admitted");
    let (block, id) = seq.produce(10).unwrap().expect("a block");
    assert_eq!(block.timestamp, early());

    let assertion = seq.chain.get(&id).unwrap().assertion.clone();
    let mut verifier = VerifierNode::new(
        config.build_state().unwrap(),
        PartyId(2),
        config.keyless_config().unwrap(),
    );
    assert_eq!(verifier.follow(&block, &assertion), Outcome::Accepted);
}

#[test]
fn a_verifier_without_the_keyless_config_cannot_follow() {
    // Documents why VerifierNode::new takes the config explicitly: without it
    // an honest keyless block looks unexecutable.
    let config = config(vec![sample_jwk()]);
    let mut seq = sequencer(&config, early);
    seq.submit(keyless_transfer(1)).unwrap();
    let (block, id) = seq.produce(10).unwrap().unwrap();
    let assertion = seq.chain.get(&id).unwrap().assertion.clone();
    let mut verifier = VerifierNode::new(config.build_state().unwrap(), PartyId(2), None);
    assert!(matches!(
        verifier.follow(&block, &assertion),
        Outcome::Unexecutable { .. }
    ));
}

#[test]
fn without_a_genesis_jwk_the_transfer_is_refused_at_admission() {
    let config = config(vec![]);
    let mut seq = sequencer(&config, early);
    assert!(matches!(
        seq.submit(keyless_transfer(1)),
        Err(RejectReason::WouldNotExecute { .. })
    ));
}

#[test]
fn an_expired_ephemeral_key_is_refused_at_admission() {
    let config = config(vec![sample_jwk()]);
    let mut seq = sequencer(&config, late);
    assert!(matches!(
        seq.submit(keyless_transfer(1)),
        Err(RejectReason::WouldNotExecute { .. })
    ));
}
