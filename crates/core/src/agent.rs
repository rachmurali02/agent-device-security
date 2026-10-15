//! Agent actions, policies and signed statements.
//!
//! An *agent key* never signs bytes chosen by the host. The host describes
//! an action (what, to whom, how much); the HSM parses it, checks it against
//! the key's policy, and signs a statement it builds itself. Whoever receives
//! the statement sees exactly what the HSM approved.

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::wire::{PUBLIC_KEY_LEN, Reader, SERIAL_LEN, SIGNATURE_LEN, WireError, Writer};

pub const MAX_TARGET: usize = 64;
pub const MAX_DETAILS: usize = 128;
pub const CHALLENGE_LEN: usize = 32;
pub const DIGEST_LEN: usize = 32;

/// Prefix of every statement an agent key signs. Domain separation: a
/// statement can never be confused with any other signed message.
pub const STATEMENT_DOMAIN: &[u8; 12] = b"QHSM-ACTION\x01";
/// Prefix of the message a user's confirmation device signs.
pub const CONFIRM_DOMAIN: &[u8; 13] = b"QHSM-CONFIRM\x01";
const POLICY_DOMAIN: &[u8; 12] = b"QHSM-POLICY\x01";

/// Largest possible encoded statement.
pub const MAX_STATEMENT: usize =
    STATEMENT_DOMAIN.len() + SERIAL_LEN + 4 + 8 + ACTION_MAX + 1 + DIGEST_LEN;
const ACTION_MAX: usize = 1 + 8 + 2 + MAX_TARGET + 2 + MAX_DETAILS;
const CONFIRM_MAX: usize = CONFIRM_DOMAIN.len() + SERIAL_LEN + CHALLENGE_LEN + 4 + ACTION_MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ActionKind {
    SendMessage = 1,
    Payment = 2,
    InstallSoftware = 3,
    ShareData = 4,
    DeleteData = 5,
}

impl ActionKind {
    pub const ALL: [ActionKind; 5] = [
        ActionKind::SendMessage,
        ActionKind::Payment,
        ActionKind::InstallSoftware,
        ActionKind::ShareData,
        ActionKind::DeleteData,
    ];

    /// This kind's bit in a policy's kind mask.
    pub const fn bit(self) -> u16 {
        1 << self as u8
    }

    pub const fn name(self) -> &'static str {
        match self {
            ActionKind::SendMessage => "send_message",
            ActionKind::Payment => "payment",
            ActionKind::InstallSoftware => "install_software",
            ActionKind::ShareData => "share_data",
            ActionKind::DeleteData => "delete_data",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.name() == name)
    }
}

impl TryFrom<u8> for ActionKind {
    type Error = WireError;
    fn try_from(b: u8) -> Result<Self, WireError> {
        Self::ALL
            .into_iter()
            .find(|k| *k as u8 == b)
            .ok_or(WireError::UnknownTag)
    }
}

/// Mask of every defined kind; any other bit in a policy is rejected.
pub const ALL_KINDS: u16 = {
    let mut m = 0;
    let mut i = 0;
    while i < ActionKind::ALL.len() {
        m |= ActionKind::ALL[i].bit();
        i += 1;
    }
    m
};

/// What an agent wants to do.
///
/// Decoding is strict so that each action has exactly one encoding, and so
/// that what a confirmation screen shows is exactly what gets signed:
/// - `target` (1-64 bytes) and `details` (0-128 bytes) are printable ASCII,
///   so no control characters, invisible characters or look-alike letters.
/// - `amount` (in cents) is non-zero for payments and zero for everything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Action<'a> {
    pub kind: ActionKind,
    pub amount: u64,
    pub target: &'a [u8],
    pub details: &'a [u8],
}

fn printable(s: &[u8]) -> bool {
    s.iter().all(|&b| (0x20..=0x7e).contains(&b))
}

impl<'a> Action<'a> {
    pub fn validate(&self) -> Result<(), WireError> {
        let amount_ok = (self.kind == ActionKind::Payment) == (self.amount > 0);
        let target_ok = !self.target.is_empty() && self.target.len() <= MAX_TARGET;
        let details_ok = self.details.len() <= MAX_DETAILS;
        if amount_ok && target_ok && details_ok && printable(self.target) && printable(self.details)
        {
            Ok(())
        } else {
            Err(WireError::Invalid)
        }
    }

    pub fn read(r: &mut Reader<'a>) -> Result<Self, WireError> {
        let action = Action {
            kind: ActionKind::try_from(r.u8()?)?,
            amount: r.u64()?,
            target: r.bytes(MAX_TARGET)?,
            details: r.bytes(MAX_DETAILS)?,
        };
        action.validate()?;
        Ok(action)
    }

    pub fn write(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        self.validate()?;
        w.u8(self.kind as u8)?;
        w.u64(self.amount)?;
        w.bytes(self.target)?;
        w.bytes(self.details)
    }
}

/// The rules attached to an agent key when it is created.
///
/// Milestone 2: a policy is fixed for the key's lifetime, so nobody, not
/// even a logged-in user, can loosen it. Changing rules will need sign-off
/// from several people (milestone 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub struct Policy {
    /// Kinds of action this key may approve (`ActionKind::bit` mask).
    pub allowed: u16,
    /// Largest single payment, in cents.
    pub max_amount: u64,
    /// Total that may ever be spent with this key, in cents.
    pub budget: u64,
    /// Payments above this many cents need the user's confirmation.
    pub confirm_above: u64,
    /// Kinds that always need the user's confirmation.
    pub always_confirm: u16,
    /// Public key of the user's confirmation device, if any. Without one,
    /// any action that needs confirmation is refused.
    pub confirmer: Option<[u8; PUBLIC_KEY_LEN]>,
}

pub const POLICY_LEN: usize = 2 + 8 + 8 + 8 + 2 + 1 + PUBLIC_KEY_LEN;

impl Policy {
    pub fn read(r: &mut Reader<'_>) -> Result<Self, WireError> {
        let allowed = r.u16()?;
        let max_amount = r.u64()?;
        let budget = r.u64()?;
        let confirm_above = r.u64()?;
        let always_confirm = r.u16()?;
        let has_confirmer = r.u8()?;
        let key: [u8; PUBLIC_KEY_LEN] = r.array()?;
        let confirmer = match has_confirmer {
            0 if key == [0; PUBLIC_KEY_LEN] => None,
            1 => Some(key),
            _ => return Err(WireError::Invalid),
        };
        let policy = Policy {
            allowed,
            max_amount,
            budget,
            confirm_above,
            always_confirm,
            confirmer,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn write(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        self.validate()?;
        w.u16(self.allowed)?;
        w.u64(self.max_amount)?;
        w.u64(self.budget)?;
        w.u64(self.confirm_above)?;
        w.u16(self.always_confirm)?;
        w.u8(self.confirmer.is_some() as u8)?;
        w.raw(&self.confirmer.unwrap_or([0; PUBLIC_KEY_LEN]))
    }

    pub fn validate(&self) -> Result<(), WireError> {
        let kinds_ok = self.allowed != 0
            && self.allowed & !ALL_KINDS == 0
            && self.always_confirm & !ALL_KINDS == 0;
        let confirmer_ok = self
            .confirmer
            .is_none_or(|k| VerifyingKey::from_bytes(&k).is_ok());
        if kinds_ok && confirmer_ok {
            Ok(())
        } else {
            Err(WireError::Invalid)
        }
    }

    pub fn allows(&self, kind: ActionKind) -> bool {
        self.allowed & kind.bit() != 0
    }

    pub fn needs_confirmation(&self, action: &Action<'_>) -> bool {
        self.always_confirm & action.kind.bit() != 0 || action.amount > self.confirm_above
    }

    /// Fingerprint of the policy, included in every statement so a verifier
    /// knows which rules approved the action.
    pub fn digest(&self) -> [u8; DIGEST_LEN] {
        let mut buf = [0u8; POLICY_LEN];
        let mut w = Writer::new(&mut buf);
        // Policies are validated on the way in, so this cannot fail.
        let _ = self.write(&mut w);
        Sha256::new()
            .chain_update(POLICY_DOMAIN)
            .chain_update(buf)
            .finalize()
            .into()
    }
}

/// What the HSM signs when it approves an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Statement<'a> {
    /// Which HSM approved it.
    pub serial: [u8; SERIAL_LEN],
    /// Which key on that HSM.
    pub key: u32,
    /// Starts at 1 and goes up by one per approved action, so a verifier can
    /// spot replays and gaps.
    pub sequence: u64,
    pub action: Action<'a>,
    /// Whether the user confirmed this action on their confirmation device.
    pub confirmed: bool,
    pub policy_digest: [u8; DIGEST_LEN],
}

impl<'a> Statement<'a> {
    pub fn write(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        w.raw(STATEMENT_DOMAIN)?;
        w.raw(&self.serial)?;
        w.u32(self.key)?;
        w.u64(self.sequence)?;
        self.action.write(w)?;
        w.u8(self.confirmed as u8)?;
        w.raw(&self.policy_digest)
    }

    pub fn decode(bytes: &'a [u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        if r.raw(STATEMENT_DOMAIN.len())? != STATEMENT_DOMAIN {
            return Err(WireError::Invalid);
        }
        let s = Statement {
            serial: r.array()?,
            key: r.u32()?,
            sequence: r.u64()?,
            action: Action::read(&mut r)?,
            confirmed: match r.u8()? {
                0 => false,
                1 => true,
                _ => return Err(WireError::Invalid),
            },
            policy_digest: r.array()?,
        };
        r.finish()?;
        Ok(s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    BadPublicKey,
    Malformed,
    BadSignature,
}

/// Verifier side: check an HSM signature over a statement and decode it.
/// Usable by anyone holding the agent key's public key; no HSM needed.
pub fn verify_statement<'a>(
    public: &[u8; PUBLIC_KEY_LEN],
    statement: &'a [u8],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<Statement<'a>, VerifyError> {
    let vk = VerifyingKey::from_bytes(public).map_err(|_| VerifyError::BadPublicKey)?;
    vk.verify_strict(statement, &Signature::from_bytes(signature))
        .map_err(|_| VerifyError::BadSignature)?;
    Statement::decode(statement).map_err(|_| VerifyError::Malformed)
}

/// The exact bytes a user's confirmation device signs to approve `action`.
///
/// It covers the HSM's one-time challenge (so a confirmation cannot be
/// replayed), the HSM serial and key (so it cannot be used elsewhere) and the
/// full action (so the agent cannot swap in a different one).
pub fn confirmation_message(
    out: &mut [u8; CONFIRM_MAX],
    serial: &[u8; SERIAL_LEN],
    challenge: &[u8; CHALLENGE_LEN],
    key: u32,
    action: &Action<'_>,
) -> Result<usize, WireError> {
    let mut w = Writer::new(out);
    w.raw(CONFIRM_DOMAIN)?;
    w.raw(serial)?;
    w.raw(challenge)?;
    w.u32(key)?;
    action.write(&mut w)?;
    Ok(w.len())
}

pub const CONFIRM_MESSAGE_MAX: usize = CONFIRM_MAX;

/// Checks a confirmation signature against the policy's confirmer key.
pub(crate) fn confirmation_valid(
    confirmer: &[u8; PUBLIC_KEY_LEN],
    serial: &[u8; SERIAL_LEN],
    challenge: &[u8; CHALLENGE_LEN],
    key: u32,
    action: &Action<'_>,
    signature: &[u8; SIGNATURE_LEN],
) -> bool {
    let mut msg = [0u8; CONFIRM_MAX];
    let Ok(len) = confirmation_message(&mut msg, serial, challenge, key, action) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(confirmer) else {
        return false;
    };
    vk.verify_strict(&msg[..len], &Signature::from_bytes(signature))
        .is_ok()
}
