//! The frozen beta protocol parameter set.
//!
//! Every parameter the protocol depends on lives here, once. The Rust node, the
//! Move contracts, the specifications and the release notes all derive from this
//! module rather than each carrying their own copy.
//!
//! # Why a crate and not a constant in each module
//!
//! `BETA_BUILD_PLAN.md` W-01 requires the beta parameters to be frozen and
//! versioned, and the reason is drift. A challenge window that reads 7 days in
//! the SRS, 24 hours in a Move constant and 48 hours in a test is not a
//! documentation problem — it is a chain that finalizes on a schedule nobody
//! intended. Putting them in one crate makes a mismatch a compile error or a
//! failing test rather than something a reader has to notice.
//!
//! # The relationships that must hold
//!
//! Some of these values are not independent. A dispute must conclude while the
//! challenge window is still open, or fraud could finalize while a challenge was
//! still in progress. A single move must not be able to consume a party's whole
//! budget. [`validate`] checks every such relationship, and a test runs it
//! against the frozen set and against the window floor.
//!
//! ```
//! use sena_params::{BETA, validate};
//!
//! // The frozen set is internally consistent, including at the window floor.
//! validate(&BETA).expect("the frozen beta parameters must be consistent");
//! ```

#![doc(html_root_url = "https://docs.rs/sena-params")]
#![warn(missing_docs, clippy::pedantic)]

use serde::{Deserialize, Serialize};

/// Identifies this parameter set. Bumped whenever any value changes.
pub const PARAM_SET_VERSION: &str = "sena-beta-params-1";

/// The protocol version these parameters describe.
pub const PROTOCOL_VERSION: &str = "0.3.0-beta";

/// One second, for readability below.
const SECOND: u64 = 1;
/// One minute in seconds.
const MINUTE: u64 = 60 * SECOND;
/// One hour in seconds.
const HOUR: u64 = 60 * MINUTE;
/// One day in seconds.
const DAY: u64 = 24 * HOUR;

/// The complete parameter set.
///
/// Every field carries a unit in its name or its documentation. Unitless
/// durations are how a timeout ends up a thousand times too short.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Params {
    /// Identifier of this set.
    pub version: &'static str,

    // --- Dispute lifecycle ---
    /// How long an assertion stays challengeable, in seconds (REQ-FRAUD-004).
    pub challenge_window_secs: u64,
    /// The hard floor on the challenge window, in seconds.
    ///
    /// Enforced in code, not policy: `AssertionChain::new` clamps to it and
    /// governance has no path to lower it (REQ-GOV-007).
    pub challenge_window_floor_secs: u64,
    /// How long a party has to make one bisection move, in seconds (REQ-FRAUD-014).
    pub move_timeout_secs: u64,
    /// Divisor giving each party's total dispute budget from the window.
    ///
    /// Four, so both parties together can consume at most half the window.
    /// Derived rather than fixed because a constant budget generous enough to be
    /// fair under L1 congestion can exceed a window set near its floor
    /// (REQ-FRAUD-015).
    pub clock_budget_divisor: u64,
    /// Segments each bisection round divides the disputed interval into.
    ///
    /// Higher arity means fewer rounds and less total L1 gas, at the cost of
    /// larger individual moves.
    pub bisection_arity: u64,

    // --- Data availability ---
    /// How long a proposer has to publish challenged batch data, in seconds
    /// (REQ-FRAUD-009).
    pub da_response_timeout_secs: u64,

    // --- Liveness ---
    /// How long the sequencer has to include a forced transaction, in seconds
    /// (REQ-FRAUD-029).
    pub forced_inclusion_timeout_secs: u64,
    /// How long the sequencer may go without proposing before anyone may, in
    /// seconds (REQ-FRAUD-030).
    pub proposer_liveness_timeout_secs: u64,

    // --- Bonds ---
    /// Minimum bond an assertion must carry (REQ-FRAUD-003).
    pub sequencer_bond_min: u128,
    /// Bond a challenger must post (REQ-FRAUD-011).
    pub challenger_bond: u128,
    /// Percentage of a slashed bond paid to the winner, 0–100.
    ///
    /// Deliberately below 100: a challenger who receives everything the proposer
    /// loses has an incentive to collude with — or simply be — the proposer,
    /// posting invalid assertions to harvest bonds in a wash (REQ-FRAUD-020).
    pub slash_reward_percent: u8,

    // --- Execution ---
    /// Base cost of a transaction, in native units.
    pub base_gas_native: u128,
    /// Fixed-point scale for gas asset exchange rates.
    pub gas_rate_scale: u128,
    /// Maximum transactions a block may contain.
    pub max_block_transactions: u32,

    // --- Node operation ---
    /// Target seconds between blocks.
    pub block_interval_secs: u64,
    /// Seconds between state persists.
    pub persist_interval_secs: u64,
}

/// The frozen beta parameter set.
///
/// Changing any value here requires bumping [`PARAM_SET_VERSION`] and recording
/// the change in `docs/beta/DECISION_LOG.md`.
pub const BETA: Params = Params {
    version: PARAM_SET_VERSION,

    challenge_window_secs: 7 * DAY,
    challenge_window_floor_secs: DAY,
    move_timeout_secs: 6 * HOUR,
    clock_budget_divisor: 4,
    bisection_arity: 8,

    da_response_timeout_secs: 12 * HOUR,

    forced_inclusion_timeout_secs: DAY,
    proposer_liveness_timeout_secs: DAY,

    sequencer_bond_min: 1_000_000,
    challenger_bond: 100_000,
    slash_reward_percent: 50,

    base_gas_native: 1_000,
    gas_rate_scale: 1_000_000,
    max_block_transactions: 512,

    block_interval_secs: 2,
    persist_interval_secs: 10,
};

/// Returns each party's total dispute budget for a given window, in seconds.
#[must_use]
pub const fn clock_budget_secs(params: &Params, challenge_window_secs: u64) -> u64 {
    challenge_window_secs / params.clock_budget_divisor
}

/// A relationship between parameters that does not hold.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum ParamError {
    /// The challenge window is below its floor.
    #[error("challenge window {window}s is below the floor of {floor}s")]
    WindowBelowFloor {
        /// The configured window.
        window: u64,
        /// The floor.
        floor: u64,
    },
    /// Both parties' budgets together could outlast the window.
    ///
    /// The consequence is not a slow dispute: it is fraud finalizing while a
    /// challenge against it is still being played (NFR-PERF-006).
    #[error(
        "both parties' dispute budgets total {total}s, which does not fit inside a {window}s \
         challenge window: a dispute could outlive the window it exists to resolve within"
    )]
    DisputeCanOutlastWindow {
        /// Combined budget.
        total: u64,
        /// The window it must fit inside.
        window: u64,
    },
    /// One move could consume a party's whole budget.
    #[error("a single move may take {move_timeout}s, exhausting a {budget}s budget outright")]
    MoveExceedsBudget {
        /// The per-move allowance.
        move_timeout: u64,
        /// The total budget.
        budget: u64,
    },
    /// The bisection arity is degenerate.
    #[error("bisection arity must be at least 2, got {0}")]
    ArityTooSmall(u64),
    /// A timeout is zero.
    #[error("{name} must be greater than zero")]
    ZeroTimeout {
        /// Which parameter.
        name: &'static str,
    },
    /// The slash reward is out of range or would enable wash-challenging.
    #[error("slash reward must be between 1 and 99 percent, got {0}")]
    SlashRewardOutOfRange(u8),
    /// The gas rate scale is not usable.
    #[error("gas rate scale must be greater than zero")]
    ZeroRateScale,
}

/// Checks every relationship that must hold between parameters.
///
/// Called with the frozen set, and separately with the window floor, because a
/// set that is consistent at a seven-day window can be inconsistent at the
/// shortest window governance may set.
///
/// # Errors
///
/// Returns [`ParamError`] naming the relationship that fails.
pub fn validate(params: &Params) -> Result<(), ParamError> {
    validate_at_window(params, params.challenge_window_secs)?;
    // The floor is the adversarial case: governance may raise the window but
    // never lower it past here, so every relationship must hold there too.
    validate_at_window(params, params.challenge_window_floor_secs)
}

/// Checks the window-dependent relationships at a specific window length.
///
/// # Errors
///
/// Returns [`ParamError`] naming the relationship that fails.
pub fn validate_at_window(params: &Params, challenge_window_secs: u64) -> Result<(), ParamError> {
    if challenge_window_secs < params.challenge_window_floor_secs {
        return Err(ParamError::WindowBelowFloor {
            window: challenge_window_secs,
            floor: params.challenge_window_floor_secs,
        });
    }
    if params.bisection_arity < 2 {
        return Err(ParamError::ArityTooSmall(params.bisection_arity));
    }
    if params.clock_budget_divisor < 2 {
        return Err(ParamError::ZeroTimeout {
            name: "clock_budget_divisor",
        });
    }
    for (name, value) in [
        ("move_timeout_secs", params.move_timeout_secs),
        ("da_response_timeout_secs", params.da_response_timeout_secs),
        (
            "forced_inclusion_timeout_secs",
            params.forced_inclusion_timeout_secs,
        ),
        (
            "proposer_liveness_timeout_secs",
            params.proposer_liveness_timeout_secs,
        ),
        ("block_interval_secs", params.block_interval_secs),
    ] {
        if value == 0 {
            return Err(ParamError::ZeroTimeout { name });
        }
    }
    if params.slash_reward_percent == 0 || params.slash_reward_percent >= 100 {
        return Err(ParamError::SlashRewardOutOfRange(
            params.slash_reward_percent,
        ));
    }
    if params.gas_rate_scale == 0 {
        return Err(ParamError::ZeroRateScale);
    }

    let budget = clock_budget_secs(params, challenge_window_secs);
    let total = budget.saturating_mul(2);
    if total >= challenge_window_secs {
        return Err(ParamError::DisputeCanOutlastWindow {
            total,
            window: challenge_window_secs,
        });
    }
    // A move allowance larger than the budget would let one stall end a dispute.
    // The node clamps the allowance to the budget; this check records that the
    // clamp is load-bearing at short windows rather than cosmetic.
    if params.move_timeout_secs > budget {
        return Err(ParamError::MoveExceedsBudget {
            move_timeout: params.move_timeout_secs,
            budget,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_frozen_set_is_consistent() {
        validate(&BETA).expect("the frozen beta parameters must be internally consistent");
    }

    #[test]
    fn the_frozen_set_is_consistent_at_the_window_floor() {
        // The adversarial case: governance raises the window freely but can
        // never go below the floor, so the floor is where relationships are
        // tightest.
        validate_at_window(&BETA, BETA.challenge_window_floor_secs)
            .expect("parameters must hold at the shortest permitted window");
    }

    #[test]
    fn a_dispute_cannot_outlast_any_permitted_window() {
        for window in [
            BETA.challenge_window_floor_secs,
            BETA.challenge_window_secs,
            30 * DAY,
        ] {
            let total = 2 * clock_budget_secs(&BETA, window);
            assert!(
                total < window,
                "at a {window}s window both budgets total {total}s, which does not fit"
            );
        }
    }

    #[test]
    fn a_window_below_the_floor_is_rejected() {
        let mut params = BETA.clone();
        params.challenge_window_secs = HOUR;
        assert!(matches!(
            validate(&params),
            Err(ParamError::WindowBelowFloor { .. })
        ));
    }

    #[test]
    fn an_oversized_move_timeout_is_rejected() {
        // The regression this guards: a fixed move allowance that exceeds the
        // budget at short windows, letting one stall end a dispute.
        let mut params = BETA.clone();
        params.move_timeout_secs = 10 * DAY;
        assert!(matches!(
            validate(&params),
            Err(ParamError::MoveExceedsBudget { .. })
        ));
    }

    #[test]
    fn a_budget_divisor_that_lets_disputes_overrun_is_rejected() {
        let mut params = BETA.clone();
        params.clock_budget_divisor = 2; // both parties together = the whole window
        assert!(matches!(
            validate(&params),
            Err(ParamError::DisputeCanOutlastWindow { .. })
        ));
    }

    #[test]
    fn a_full_slash_reward_is_rejected() {
        // Paying the winner everything the loser forfeits makes collusive
        // self-challenging profitable.
        let mut params = BETA.clone();
        params.slash_reward_percent = 100;
        assert!(matches!(
            validate(&params),
            Err(ParamError::SlashRewardOutOfRange(100))
        ));
    }

    #[test]
    fn degenerate_arity_is_rejected() {
        let mut params = BETA.clone();
        params.bisection_arity = 1;
        assert!(matches!(
            validate(&params),
            Err(ParamError::ArityTooSmall(1))
        ));
    }

    #[test]
    fn zero_timeouts_are_rejected() {
        let mut params = BETA.clone();
        params.da_response_timeout_secs = 0;
        assert!(matches!(
            validate(&params),
            Err(ParamError::ZeroTimeout { .. })
        ));
    }

    #[test]
    fn determinism_the_set_is_stable() {
        println!("root={}", BETA.version);
        assert_eq!(BETA, BETA.clone());
    }
}
