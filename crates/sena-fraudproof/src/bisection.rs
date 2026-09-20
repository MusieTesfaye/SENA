//! The interactive bisection protocol (REQ-FRAUD-012 to REQ-FRAUD-015).
//!
//! # Why this works
//!
//! Two parties disputing a batch agree on its starting state and disagree on its
//! ending state. It follows that there is a first step at which their traces
//! diverge. Neither has to prove anything about the other steps: they only have
//! to find that one.
//!
//! Each round, the defender divides the disputed interval and publishes the
//! machine state at each division point. The challenger names the first division
//! it disagrees with, and the interval shrinks to that segment. After
//! `log_k(N)` rounds the interval is one step wide, and both parties now agree
//! on its input while disagreeing on its output — a question Aptos L1 can settle
//! by executing that single step itself.
//!
//! An honest party is never forced into a false claim at any round, because it
//! publishes commitments from a trace it actually computed. So an honest party
//! entering the game correctly cannot lose it, which is the property the whole
//! security argument rests on.

use sena_primitives::Hash256;
use serde::{Deserialize, Serialize};

use crate::assertion::{AssertionId, PartyId};

/// A role in a dispute.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Party {
    /// The proposer, defending the assertion.
    Defender,
    /// The challenger, disputing it.
    Challenger,
}

impl Party {
    /// Returns the other party.
    #[must_use]
    pub const fn opponent(self) -> Self {
        match self {
            Self::Defender => Self::Challenger,
            Self::Challenger => Self::Defender,
        }
    }
}

/// How far the dispute has progressed.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Stage {
    /// Narrowing the interval. Holds the defender's latest unanswered division.
    Bisecting {
        /// Interior commitments the defender published, awaiting a selection.
        offered: Option<Vec<Hash256>>,
    },
    /// The interval is one step wide; awaiting a One-Step Proof.
    OneStep,
    /// Concluded.
    Resolved {
        /// Who won.
        winner: Party,
        /// Why.
        reason: Resolution,
    },
}

/// How a dispute ended.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Resolution {
    /// A party failed to move before its deadline (REQ-FRAUD-014).
    Timeout,
    /// A party exhausted its total time budget (REQ-FRAUD-015).
    ClockExhausted,
    /// Aptos L1 executed the disputed step and compared the result.
    OneStepAdjudicated,
}

/// Why a move was refused.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum MoveError {
    /// The dispute is already over.
    #[error("dispute is already resolved")]
    AlreadyResolved,
    /// It is not this party's turn.
    #[error("it is {expected:?}'s turn, not {actual:?}'s")]
    WrongTurn {
        /// Whose turn it is.
        expected: Party,
        /// Who tried to move.
        actual: Party,
    },
    /// The move does not fit the current stage.
    #[error("that move is not available at this stage")]
    WrongStage,
    /// The defender published the wrong number of commitments.
    #[error("expected {expected} interior commitments, got {got}")]
    WrongDissectionLength {
        /// How many the interval requires.
        expected: usize,
        /// How many were supplied.
        got: usize,
    },
    /// The challenger selected a segment that does not exist.
    #[error("segment {index} is out of range; the interval has {segments} segments")]
    SegmentOutOfRange {
        /// The index selected.
        index: usize,
        /// How many segments exist.
        segments: usize,
    },
    /// The challenger agreed with every division it was offered.
    ///
    /// Selecting nothing would mean conceding; the protocol requires the
    /// challenger to name a disagreement or lose.
    #[error("the selected segment's end commitment was not disputed")]
    NoDisagreement,
    /// Time moved backwards.
    #[error("time moved backwards")]
    TimeWentBackwards,
}

/// The terms a dispute opens on.
///
/// Grouped rather than passed as loose arguments because several are commitments
/// of the same type, and transposing two of them would open a dispute that looks
/// well-formed and is not.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Opening {
    /// The assertion under challenge.
    pub assertion: AssertionId,
    /// The proposer defending it.
    pub defender: PartyId,
    /// The party challenging it.
    pub challenger: PartyId,
    /// Number of steps in the disputed trace.
    pub trace_length: u64,
    /// The agreed commitment at step zero.
    pub lo_commitment: Hash256,
    /// The defender's commitment at the final step.
    pub hi_commitment: Hash256,
    /// The chain's challenge window, from which the time budgets derive.
    pub challenge_window: u64,
}

/// An interactive dispute over one assertion.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Dispute {
    /// The assertion under challenge.
    pub assertion: AssertionId,
    /// The proposer defending it.
    pub defender: PartyId,
    /// The party challenging it.
    pub challenger: PartyId,
    /// Start of the disputed interval. Both parties agree on the state here.
    pub lo: u64,
    /// End of the disputed interval. The parties disagree on the state here.
    pub hi: u64,
    /// The agreed commitment at `lo`.
    pub lo_commitment: Hash256,
    /// The defender's commitment at `hi`, which the challenger disputes.
    pub hi_commitment: Hash256,
    /// Current stage.
    pub stage: Stage,
    /// Whose move it is.
    pub turn: Party,
    /// Absolute time by which the current party must move.
    pub deadline: u64,
    /// Each party's total budget, retained so later moves reuse it.
    pub clock_budget: u64,
    /// Remaining total budget for the defender, in seconds.
    pub defender_clock: u64,
    /// Remaining total budget for the challenger, in seconds.
    pub challenger_clock: u64,
    /// Time of the last move, for charging the clock.
    pub last_move_at: u64,
    /// How many segments each round divides the interval into.
    pub arity: u64,
}

/// How long a party has to make any single move, in seconds.
pub const MOVE_TIMEOUT: u64 = 6 * 60 * 60;

/// The share of the challenge window each party may consume, as a divisor.
///
/// Four, so the two parties together can use at most half the window and a
/// dispute always concludes with the window still open.
pub const CLOCK_BUDGET_DIVISOR: u64 = 4;

/// Each party's total time budget for a dispute, in seconds.
///
/// Derived from the challenge window rather than fixed, and that matters: a
/// constant budget generous enough to be fair under L1 congestion can exceed a
/// window that governance has set near its floor, and a dispute that outlives
/// its window lets fraud finalize while still under challenge (REQ-FRAUD-015,
/// NFR-PERF-006). Tying the two together makes the relationship hold at every
/// window the chain will accept.
///
/// ```
/// use sena_fraudproof::bisection::clock_budget;
/// use sena_fraudproof::CHALLENGE_WINDOW_FLOOR;
///
/// // Even at the shortest permitted window, both parties together use only
/// // half of it.
/// assert!(2 * clock_budget(CHALLENGE_WINDOW_FLOOR) < CHALLENGE_WINDOW_FLOOR);
/// ```
#[must_use]
pub const fn clock_budget(challenge_window: u64) -> u64 {
    challenge_window / CLOCK_BUDGET_DIVISOR
}

/// Segments per bisection round.
///
/// Higher arity means fewer rounds — less wall-clock time and less total L1 gas
/// — at the cost of larger individual moves. Tuned against L1 transaction size
/// limits.
pub const DEFAULT_ARITY: u64 = 8;

impl Dispute {
    /// Opens a dispute over the whole trace.
    ///
    /// The caller is responsible for having established that the challenger
    /// genuinely disagrees; a challenger who agrees with `hi_commitment` has
    /// nothing to win and will forfeit at the first round.
    #[must_use]
    pub fn open(opening: &Opening, now: u64) -> Self {
        let budget = clock_budget(opening.challenge_window);
        let mut dispute = Self {
            assertion: opening.assertion,
            defender: opening.defender,
            challenger: opening.challenger,
            lo: 0,
            hi: opening.trace_length,
            lo_commitment: opening.lo_commitment,
            hi_commitment: opening.hi_commitment,
            stage: Stage::Bisecting { offered: None },
            turn: Party::Defender,
            clock_budget: budget,
            // A single move may never be given longer than the whole budget,
            // or one stall would exhaust it outright.
            deadline: now.saturating_add(MOVE_TIMEOUT.min(budget)),
            defender_clock: budget,
            challenger_clock: budget,
            last_move_at: now,
            arity: DEFAULT_ARITY,
        };
        dispute.enter_one_step_if_narrow();
        dispute
    }

    /// Returns the winner, if the dispute has concluded.
    #[must_use]
    pub const fn winner(&self) -> Option<Party> {
        match self.stage {
            Stage::Resolved { winner, .. } => Some(winner),
            _ => None,
        }
    }

    /// Returns the step index under dispute, once the interval is one wide.
    #[must_use]
    pub const fn disputed_step(&self) -> Option<u64> {
        if matches!(self.stage, Stage::OneStep) {
            Some(self.lo)
        } else {
            None
        }
    }

    /// Returns the boundaries of the current interval's segments.
    ///
    /// Boundaries are computed by integer arithmetic from `lo`, `hi` and the
    /// arity, so both parties and the L1 contract derive the same division
    /// without it having to be transmitted.
    #[must_use]
    pub fn boundaries(&self) -> Vec<u64> {
        let span = self.hi - self.lo;
        let segments = self.arity.min(span).max(1);
        (0..=segments)
            .map(|i| self.lo + (span * i) / segments)
            .collect()
    }

    /// Returns how many interior commitments the defender must publish.
    #[must_use]
    pub fn dissection_len(&self) -> usize {
        self.boundaries().len().saturating_sub(2)
    }

    /// The defender divides the interval and publishes the interior states.
    ///
    /// # Errors
    ///
    /// Returns [`MoveError`] if it is not the defender's turn, the stage is
    /// wrong, or the wrong number of commitments was supplied.
    pub fn dissect(&mut self, now: u64, commitments: Vec<Hash256>) -> Result<(), MoveError> {
        self.begin_move(now, Party::Defender)?;
        if !matches!(self.stage, Stage::Bisecting { .. }) {
            return Err(MoveError::WrongStage);
        }
        let expected = self.boundaries().len() - 2;
        if commitments.len() != expected {
            return Err(MoveError::WrongDissectionLength {
                expected,
                got: commitments.len(),
            });
        }
        self.stage = Stage::Bisecting {
            offered: Some(commitments),
        };
        self.pass_turn(now);
        Ok(())
    }

    /// The challenger names the first segment whose end it disputes.
    ///
    /// # Errors
    ///
    /// Returns [`MoveError`] if it is not the challenger's turn, no dissection
    /// is pending, the index is out of range, or the selected segment's end was
    /// one the challenger had already implicitly agreed with.
    pub fn select(&mut self, now: u64, index: usize) -> Result<(), MoveError> {
        self.begin_move(now, Party::Challenger)?;
        let Stage::Bisecting { offered } = &self.stage else {
            return Err(MoveError::WrongStage);
        };
        let offered = offered.clone().ok_or(MoveError::WrongStage)?;

        let boundaries = self.boundaries();
        let segments = boundaries.len() - 1;
        if index >= segments {
            return Err(MoveError::SegmentOutOfRange { index, segments });
        }

        // Commitments at every boundary: lo (agreed), the offered interior
        // points, and hi (the defender's disputed claim).
        let mut all = Vec::with_capacity(boundaries.len());
        all.push(self.lo_commitment);
        all.extend(offered);
        all.push(self.hi_commitment);

        self.lo = boundaries[index];
        self.hi = boundaries[index + 1];
        self.lo_commitment = all[index];
        self.hi_commitment = all[index + 1];

        self.stage = Stage::Bisecting { offered: None };
        self.pass_turn(now);
        self.enter_one_step_if_narrow();
        Ok(())
    }

    /// Concludes the dispute after L1 has adjudicated the final step.
    pub fn resolve_by_one_step(&mut self, winner: Party) {
        self.stage = Stage::Resolved {
            winner,
            reason: Resolution::OneStepAdjudicated,
        };
    }

    /// Applies a timeout, if one is due (REQ-FRAUD-014).
    ///
    /// The party whose turn it is forfeits. Returns the winner if the dispute
    /// ended here.
    pub fn check_timeout(&mut self, now: u64) -> Option<Party> {
        if matches!(self.stage, Stage::Resolved { .. }) || now <= self.deadline {
            return None;
        }
        let winner = self.turn.opponent();
        self.stage = Stage::Resolved {
            winner,
            reason: Resolution::Timeout,
        };
        Some(winner)
    }

    /// Charges the mover's clock and checks it is their turn.
    fn begin_move(&mut self, now: u64, party: Party) -> Result<(), MoveError> {
        if matches!(self.stage, Stage::Resolved { .. }) {
            return Err(MoveError::AlreadyResolved);
        }
        if now < self.last_move_at {
            return Err(MoveError::TimeWentBackwards);
        }
        if self.turn != party {
            return Err(MoveError::WrongTurn {
                expected: self.turn,
                actual: party,
            });
        }
        if now > self.deadline {
            let winner = party.opponent();
            self.stage = Stage::Resolved {
                winner,
                reason: Resolution::Timeout,
            };
            return Err(MoveError::AlreadyResolved);
        }

        // A per-move deadline alone would let an adversary stretch a dispute by
        // always answering at the last permitted moment. The total budget is
        // what bounds the dispute below the challenge window.
        let elapsed = now - self.last_move_at;
        let clock = match party {
            Party::Defender => &mut self.defender_clock,
            Party::Challenger => &mut self.challenger_clock,
        };
        if elapsed > *clock {
            let winner = party.opponent();
            self.stage = Stage::Resolved {
                winner,
                reason: Resolution::ClockExhausted,
            };
            return Err(MoveError::AlreadyResolved);
        }
        *clock -= elapsed;
        Ok(())
    }

    fn pass_turn(&mut self, now: u64) {
        self.turn = self.turn.opponent();
        self.last_move_at = now;
        self.deadline = now.saturating_add(MOVE_TIMEOUT.min(self.clock_budget));
    }

    fn enter_one_step_if_narrow(&mut self) {
        if self.hi.saturating_sub(self.lo) == 1 {
            self.stage = Stage::OneStep;
            // The challenger must produce the One-Step Proof, so the turn is
            // theirs regardless of who moved last.
            self.turn = Party::Challenger;
        }
    }
}
