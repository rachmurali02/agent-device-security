//! Glitch resistance: decisions are checked twice.
//!
//! Hardware attackers can disturb a chip's power or clock ("glitching") to
//! flip a single decision: "over budget" becomes "fine", "wrong PIN" becomes
//! "correct". The HSM defends against any *single* such fault: every
//! security decision that leads to a signature or a login is made once on
//! the normal path, then made again by separate code right before acting.
//! If the two disagree, the HSM records the fault and stops (fails closed).
//!
//! With the `fault-injection` feature (tests only), a chosen decision can be
//! flipped on purpose, to prove that one glitch never gets through.

/// The decisions that can be glitched in tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Point {
    /// "This key may be used for agent actions."
    KeyUsage,
    /// "The rules allow this kind of action."
    KindAllowed,
    /// "A receiver's one-time code is present if the rules need one."
    NonceRule,
    /// "This payment is under the per-payment cap."
    AmountCap,
    /// "This payment fits in the remaining budget."
    Budget,
    /// "This action does not need the user's confirmation."
    NoConfirmationNeeded,
    /// "The user's confirmation signature is valid."
    ConfirmationValid,
    /// "The PIN is correct."
    PinMatches,
    /// "Enough admins signed."
    QuorumMet,
}

impl Point {
    pub const ALL: [Point; 9] = [
        Point::KeyUsage,
        Point::KindAllowed,
        Point::NonceRule,
        Point::AmountCap,
        Point::Budget,
        Point::NoConfirmationNeeded,
        Point::ConfirmationValid,
        Point::PinMatches,
        Point::QuorumMet,
    ];
}

/// A one-shot glitch armed by a test. Compiled out of normal builds.
#[derive(Debug, Default)]
pub struct Glitch {
    #[cfg(feature = "fault-injection")]
    armed: core::cell::Cell<Option<Point>>,
}

impl Glitch {
    /// Arms a glitch that flips the next decision made at `point`.
    #[cfg(feature = "fault-injection")]
    pub fn arm(&self, point: Point) {
        self.armed.set(Some(point));
    }

    /// Passes a decision through; flips it once if a glitch is armed here.
    #[inline(always)]
    pub fn decide(&self, _point: Point, value: bool) -> bool {
        #[cfg(feature = "fault-injection")]
        if self.armed.get() == Some(_point) {
            self.armed.set(None);
            return !value;
        }
        value
    }
}
