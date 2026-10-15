//! Multi-person sign-off ("quorum") for sensitive operations.
//!
//! At the factory, an HSM is given a fixed list of admin public keys and a
//! threshold, e.g. "any 2 of these 3". Creating or deleting an agent key then
//! needs that many admins to sign the exact operation. Holding the PIN is
//! not enough.
//!
//! Flow:
//! 1. An operator asks the HSM for a one-time admin challenge.
//! 2. The *proposal* (HSM serial + challenge + operation) is sent to admins.
//! 3. Each admin's tool shows the operation and, if they agree, signs the
//!    proposal bytes.
//! 4. The operator submits the operation with the signatures. The HSM
//!    rebuilds the proposal from its own serial and pending challenge, so a
//!    signature only counts for exactly that operation, on that HSM, once.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::agent::{CHALLENGE_LEN, POLICY_LEN, Policy, valid_public_key};
use crate::wire::{
    MAX_EXT_ID, MAX_LABEL, PUBLIC_KEY_LEN, Reader, SERIAL_LEN, SIGNATURE_LEN, WireError, Writer,
};

pub const MAX_ADMINS: usize = 8;
pub const ADMIN_DOMAIN: &[u8; 11] = b"QHSM-ADMIN\x01";

/// Largest possible proposal.
pub const MAX_PROPOSAL: usize = ADMIN_DOMAIN.len()
    + SERIAL_LEN
    + CHALLENGE_LEN
    + 1
    + 2
    + MAX_LABEL
    + 2
    + MAX_EXT_ID
    + POLICY_LEN;

/// The operations that need sign-off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminOp<'a> {
    CreateAgentKey {
        label: &'a [u8],
        ext_id: &'a [u8],
        policy: Policy,
    },
    DeleteAgentKey {
        key: u32,
    },
}

impl<'a> AdminOp<'a> {
    pub fn read(r: &mut Reader<'a>) -> Result<Self, WireError> {
        Ok(match r.u8()? {
            1 => AdminOp::CreateAgentKey {
                label: r.bytes(MAX_LABEL)?,
                ext_id: r.bytes(MAX_EXT_ID)?,
                policy: Policy::read(r)?,
            },
            2 => AdminOp::DeleteAgentKey { key: r.u32()? },
            _ => return Err(WireError::UnknownTag),
        })
    }

    pub fn write(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        match *self {
            AdminOp::CreateAgentKey {
                label,
                ext_id,
                policy,
            } => {
                w.u8(1)?;
                w.bytes(label)?;
                w.bytes(ext_id)?;
                policy.write(w)
            }
            AdminOp::DeleteAgentKey { key } => {
                w.u8(2)?;
                w.u32(key)
            }
        }
    }
}

/// What admins sign: domain, HSM serial, the HSM's one-time challenge and
/// the operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Proposal<'a> {
    pub serial: [u8; SERIAL_LEN],
    pub challenge: [u8; CHALLENGE_LEN],
    pub op: AdminOp<'a>,
}

impl<'a> Proposal<'a> {
    pub fn encode(&self, out: &mut [u8; MAX_PROPOSAL]) -> Result<usize, WireError> {
        let mut w = Writer::new(out);
        w.raw(ADMIN_DOMAIN)?;
        w.raw(&self.serial)?;
        w.raw(&self.challenge)?;
        self.op.write(&mut w)?;
        Ok(w.len())
    }

    pub fn decode(bytes: &'a [u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        if r.raw(ADMIN_DOMAIN.len())? != ADMIN_DOMAIN {
            return Err(WireError::Invalid);
        }
        let p = Proposal {
            serial: r.array()?,
            challenge: r.array()?,
            op: AdminOp::read(&mut r)?,
        };
        r.finish()?;
        Ok(p)
    }
}

/// Admin signatures on a proposal: `(admin index, signature)` pairs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Approvals {
    len: u8,
    entries: [(u8, [u8; SIGNATURE_LEN]); MAX_ADMINS],
}

impl Default for Approvals {
    fn default() -> Self {
        Approvals {
            len: 0,
            entries: [(0, [0; SIGNATURE_LEN]); MAX_ADMINS],
        }
    }
}

impl Approvals {
    pub fn push(&mut self, admin: u8, sig: [u8; SIGNATURE_LEN]) -> Result<(), WireError> {
        let slot = self
            .entries
            .get_mut(self.len as usize)
            .ok_or(WireError::TooLong)?;
        *slot = (admin, sig);
        self.len += 1;
        Ok(())
    }

    pub fn iter(&self) -> impl Iterator<Item = &(u8, [u8; SIGNATURE_LEN])> {
        self.entries[..self.len as usize].iter()
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn read(r: &mut Reader<'_>) -> Result<Self, WireError> {
        let n = r.u8()? as usize;
        if n > MAX_ADMINS {
            return Err(WireError::TooLong);
        }
        let mut a = Approvals::default();
        for _ in 0..n {
            a.push(r.u8()?, r.array()?)?;
        }
        Ok(a)
    }

    pub fn write(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        w.u8(self.len)?;
        for (i, sig) in self.iter() {
            w.u8(*i)?;
            w.raw(sig)?;
        }
        Ok(())
    }
}

/// The admin list and threshold, fixed at the factory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminSet {
    keys: [[u8; PUBLIC_KEY_LEN]; MAX_ADMINS],
    count: u8,
    threshold: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuorumError {
    /// No admins were set up, so these operations are disabled.
    NoAdmins,
    /// Fewer valid approvals than the threshold.
    NotEnough,
    /// A signature is wrong, from an unknown admin, or from the same admin twice.
    Invalid,
}

impl AdminSet {
    pub const NONE: AdminSet = AdminSet {
        keys: [[0; PUBLIC_KEY_LEN]; MAX_ADMINS],
        count: 0,
        threshold: 0,
    };

    /// `threshold` of `keys` must approve. Rejects duplicate or invalid keys
    /// and impossible thresholds. An empty list means "no admins".
    pub fn new(keys: &[[u8; PUBLIC_KEY_LEN]], threshold: u8) -> Result<Self, WireError> {
        if keys.is_empty() {
            return if threshold == 0 {
                Ok(Self::NONE)
            } else {
                Err(WireError::Invalid)
            };
        }
        if keys.len() > MAX_ADMINS || threshold == 0 || threshold as usize > keys.len() {
            return Err(WireError::Invalid);
        }
        let mut set = Self::NONE;
        for (i, k) in keys.iter().enumerate() {
            if !valid_public_key(k) || keys[..i].contains(k) {
                return Err(WireError::Invalid);
            }
            set.keys[i] = *k;
        }
        set.count = keys.len() as u8;
        set.threshold = threshold;
        Ok(set)
    }

    pub fn keys(&self) -> &[[u8; PUBLIC_KEY_LEN]] {
        &self.keys[..self.count as usize]
    }

    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    /// Checks that enough distinct admins signed `proposal`. Every presented
    /// signature must be valid: one bad signature rejects the whole request,
    /// so a mistake is never silently ignored. Returns a bitmask of the
    /// admins who approved.
    pub fn check(&self, proposal: &[u8], approvals: &Approvals) -> Result<u8, QuorumError> {
        if self.count == 0 {
            return Err(QuorumError::NoAdmins);
        }
        let mut approved: u8 = 0;
        for (index, sig) in approvals.iter() {
            let Some(key) = self.keys().get(*index as usize) else {
                return Err(QuorumError::Invalid);
            };
            let bit = 1u8 << index;
            if approved & bit != 0 {
                return Err(QuorumError::Invalid);
            }
            let vk = VerifyingKey::from_bytes(key).map_err(|_| QuorumError::Invalid)?;
            vk.verify_strict(proposal, &Signature::from_bytes(sig))
                .map_err(|_| QuorumError::Invalid)?;
            approved |= bit;
        }
        if approved.count_ones() < self.threshold as u32 {
            return Err(QuorumError::NotEnough);
        }
        Ok(approved)
    }

    pub fn write(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        w.u8(self.count)?;
        w.u8(self.threshold)?;
        for k in self.keys() {
            w.raw(k)?;
        }
        Ok(())
    }

    pub fn read(r: &mut Reader<'_>) -> Result<Self, WireError> {
        let count = r.u8()? as usize;
        let threshold = r.u8()?;
        if count > MAX_ADMINS {
            return Err(WireError::Invalid);
        }
        let mut keys = [[0u8; PUBLIC_KEY_LEN]; MAX_ADMINS];
        for k in keys.iter_mut().take(count) {
            *k = r.array()?;
        }
        Self::new(&keys[..count], threshold)
    }
}
