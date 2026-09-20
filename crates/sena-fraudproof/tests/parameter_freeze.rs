//! Binds the implementation's constants to the frozen beta parameter set.
//!
//! `BETA_BUILD_PLAN.md` W-01 requires beta parameters to be frozen and
//! versioned. Freezing them in a document achieves nothing on its own — the
//! failure mode is a value that reads one way in the SRS, another in a Move
//! constant and a third in the code, and a chain that then finalizes on a
//! schedule nobody chose.
//!
//! These tests make that drift a build failure. If someone changes a constant
//! in the implementation without changing `sena-params`, or the reverse, the
//! suite fails and names the parameter.

use sena_params::{clock_budget_secs, validate, BETA};

#[test]
fn the_frozen_parameters_are_internally_consistent() {
    validate(&BETA).expect("the frozen set must be consistent");
}

#[test]
fn the_challenge_window_matches_the_frozen_set() {
    assert_eq!(
        sena_fraudproof::DEFAULT_CHALLENGE_WINDOW,
        BETA.challenge_window_secs,
        "default challenge window drifted from sena-params"
    );
    assert_eq!(
        sena_fraudproof::CHALLENGE_WINDOW_FLOOR,
        BETA.challenge_window_floor_secs,
        "challenge window floor drifted from sena-params"
    );
}

#[test]
fn the_dispute_timings_match_the_frozen_set() {
    assert_eq!(
        sena_fraudproof::MOVE_TIMEOUT,
        BETA.move_timeout_secs,
        "move timeout drifted from sena-params"
    );
    assert_eq!(
        sena_fraudproof::CLOCK_BUDGET_DIVISOR,
        BETA.clock_budget_divisor,
        "clock budget divisor drifted from sena-params"
    );
    assert_eq!(
        sena_fraudproof::DEFAULT_ARITY,
        BETA.bisection_arity,
        "bisection arity drifted from sena-params"
    );
}

#[test]
fn the_implementation_computes_the_same_clock_budget() {
    for window in [
        BETA.challenge_window_floor_secs,
        BETA.challenge_window_secs,
        30 * 24 * 60 * 60,
    ] {
        assert_eq!(
            sena_fraudproof::clock_budget(window),
            clock_budget_secs(&BETA, window),
            "clock budget diverged at a {window}s window"
        );
    }
}

#[test]
fn the_gas_parameters_match_the_frozen_set() {
    assert_eq!(
        sena_stf::RATE_SCALE,
        BETA.gas_rate_scale,
        "gas rate scale drifted from sena-params"
    );
    assert_eq!(
        sena_stf::BASE_GAS_NATIVE,
        BETA.base_gas_native,
        "base gas drifted from sena-params"
    );
}
