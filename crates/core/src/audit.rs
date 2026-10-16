//! Tamper-evident audit log.
//!
//! Every security-relevant event (logins, key and rule changes, every agent
//! action approved *or refused*) becomes a fixed-size entry. Entries are
//! chained: each link is a hash of the previous link and the new entry, so
//! changing, removing or reordering any entry changes every link after it.
//!
//! The HSM keeps entries in a small buffer until the computer copies them out
//! (`ReadAudit`) and confirms it has stored them (`AckAudit`). If the buffer
//! is full, the HSM refuses further audited operations rather than lose
//! evidence. On request it signs a *checkpoint* (sequence number + latest
//! link) with its identity key. Anyone holding the copied entries and a
//! checkpoint can then prove the log is complete and unaltered up to it.
//!
//! What the log cannot do: stop the computer from *deleting* its copy. It
//! makes that detectable (the chain no longer reaches a signed checkpoint).

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::agent::DIGEST_LEN;
use crate::wire::{PUBLIC_KEY_LEN, Reader, SERIAL_LEN, SIGNATURE_LEN, WireError, Writer};

pub const AUDIT_DOMAIN: &[u8; 11] = b"QHSM-AUDIT\x01";
pub const CHECKPOINT_DOMAIN: &[u8; 16] = b"QHSM-CHECKPOINT\x01";
pub const ENTRY_LEN: usize = 8 + 1 + 1 + 4 + 8 + DIGEST_LEN;
/// Entries the HSM holds before the computer must copy them out.
pub const AUDIT_CAPACITY: usize = 64;
pub const CHECKPOINT_LEN: usize = CHECKPOINT_DOMAIN.len() + SERIAL_LEN + 8 + DIGEST_LEN;
/// The link before the first entry.
pub const GENESIS: [u8; DIGEST_LEN] = [0; DIGEST_LEN];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Event {
    /// The HSM was created at the factory. Always entry #1.
    Provisioned = 1,
    LoginOk = 2,
    LoginFailed = 3,
    KeyCreated = 4,
    KeyDeleted = 5,
    AgentKeyCreated = 6,
    AgentKeyDeleted = 7,
    PolicyUpdated = 8,
    AdminsChanged = 9,
    ActionApproved = 10,
    ActionRefused = 11,
    /// An admin operation was refused (not enough or invalid approvals).
    AdminRequestRefused = 12,
    /// Two independent checks disagreed (a glitch?); the HSM stopped.
    FaultDetected = 13,
}

impl Event {
    pub const ALL: [Event; 13] = [
        Event::Provisioned,
        Event::LoginOk,
        Event::LoginFailed,
        Event::KeyCreated,
        Event::KeyDeleted,
        Event::AgentKeyCreated,
        Event::AgentKeyDeleted,
        Event::PolicyUpdated,
        Event::AdminsChanged,
        Event::ActionApproved,
        Event::ActionRefused,
        Event::AdminRequestRefused,
        Event::FaultDetected,
    ];
}

impl TryFrom<u8> for Event {
    type Error = WireError;
    fn try_from(b: u8) -> Result<Self, WireError> {
        Self::ALL
            .into_iter()
            .find(|e| *e as u8 == b)
            .ok_or(WireError::UnknownTag)
    }
}

/// One audit entry. `status` is the wire status code of the outcome
/// (0 = OK); `digest` fingerprints what the event was about (the signed
/// statement, the refused action, the new rules...).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub seq: u64,
    pub event: Event,
    pub status: u8,
    pub key: u32,
    pub amount: u64,
    pub digest: [u8; DIGEST_LEN],
}

impl Entry {
    pub fn encode(&self) -> [u8; ENTRY_LEN] {
        let mut out = [0u8; ENTRY_LEN];
        let mut w = Writer::new(&mut out);
        // Fixed size: cannot fail.
        let _ = w.u64(self.seq);
        let _ = w.u8(self.event as u8);
        let _ = w.u8(self.status);
        let _ = w.u32(self.key);
        let _ = w.u64(self.amount);
        let _ = w.raw(&self.digest);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let e = Entry {
            seq: r.u64()?,
            event: Event::try_from(r.u8()?)?,
            status: r.u8()?,
            key: r.u32()?,
            amount: r.u64()?,
            digest: r.array()?,
        };
        r.finish()?;
        Ok(e)
    }
}

/// Fingerprint used for audit digests.
pub fn digest(parts: &[&[u8]]) -> [u8; DIGEST_LEN] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// The next link in the chain.
pub fn link(prev: &[u8; DIGEST_LEN], entry: &[u8; ENTRY_LEN]) -> [u8; DIGEST_LEN] {
    Sha256::new()
        .chain_update(AUDIT_DOMAIN)
        .chain_update(prev)
        .chain_update(entry)
        .finalize()
        .into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Full;

/// The HSM's side of the log: the chain head and the entries not yet
/// copied out.
#[derive(Clone)]
pub struct AuditLog {
    buf: [[u8; ENTRY_LEN]; AUDIT_CAPACITY],
    /// Number of entries held (oldest first, starting at `first_seq`).
    len: usize,
    first_seq: u64,
    /// Link after the newest entry.
    head: [u8; DIGEST_LEN],
    /// Sequence number of the newest entry (0 before the first).
    last_seq: u64,
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditLog {
    pub const fn new() -> Self {
        AuditLog {
            buf: [[0; ENTRY_LEN]; AUDIT_CAPACITY],
            len: 0,
            first_seq: 1,
            head: GENESIS,
            last_seq: 0,
        }
    }

    pub fn is_full(&self) -> bool {
        self.len == AUDIT_CAPACITY
    }

    pub fn head(&self) -> [u8; DIGEST_LEN] {
        self.head
    }

    pub fn last_seq(&self) -> u64 {
        self.last_seq
    }

    pub fn held(&self) -> usize {
        self.len
    }

    /// Adds an entry and advances the chain. Refuses when full: the caller
    /// must then refuse the operation it was about to record.
    pub fn append(
        &mut self,
        event: Event,
        status: u8,
        key: u32,
        amount: u64,
        digest: [u8; DIGEST_LEN],
    ) -> Result<u64, Full> {
        if self.is_full() {
            return Err(Full);
        }
        let seq = self.last_seq + 1;
        let bytes = Entry {
            seq,
            event,
            status,
            key,
            amount,
            digest,
        }
        .encode();
        self.head = link(&self.head, &bytes);
        self.buf[self.len] = bytes;
        self.len += 1;
        self.last_seq = seq;
        Ok(seq)
    }

    /// Entries with `seq >= from` that are still held.
    pub fn entries_from(&self, from: u64) -> impl Iterator<Item = &[u8; ENTRY_LEN]> {
        let skip = from.saturating_sub(self.first_seq) as usize;
        self.buf[..self.len].iter().skip(skip)
    }

    /// The computer confirms it has stored everything up to `upto`; those
    /// entries are released. Returns false if `upto` is beyond the newest
    /// entry.
    pub fn ack(&mut self, upto: u64) -> bool {
        if upto > self.last_seq {
            return false;
        }
        if upto < self.first_seq {
            return true;
        }
        let drop = (upto - self.first_seq + 1) as usize;
        self.buf.copy_within(drop..self.len, 0);
        self.len -= drop;
        self.first_seq = upto + 1;
        true
    }

    pub fn write_state(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        w.u64(self.last_seq)?;
        w.raw(&self.head)?;
        w.u8(self.len as u8)?;
        for e in &self.buf[..self.len] {
            w.raw(e)?;
        }
        Ok(())
    }

    /// Restores the log and re-checks it: held entries must be numbered
    /// consecutively up to `last_seq`.
    pub fn read_state(r: &mut Reader<'_>) -> Result<Self, WireError> {
        let mut log = AuditLog::new();
        log.last_seq = r.u64()?;
        log.head = r.array()?;
        log.len = r.u8()? as usize;
        if log.len > AUDIT_CAPACITY || log.len as u64 > log.last_seq {
            return Err(WireError::Invalid);
        }
        log.first_seq = log.last_seq + 1 - log.len as u64;
        for i in 0..log.len {
            log.buf[i] = r.array()?;
            let e = Entry::decode(&log.buf[i])?;
            if e.seq != log.first_seq + i as u64 {
                return Err(WireError::Invalid);
            }
        }
        Ok(log)
    }
}

pub const AUDIT_STATE_MAX: usize = 8 + DIGEST_LEN + 1 + AUDIT_CAPACITY * ENTRY_LEN;

/// "Up to entry `seq`, the chain ends in `head`," signed by the HSM identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoint {
    pub serial: [u8; SERIAL_LEN],
    pub seq: u64,
    pub head: [u8; DIGEST_LEN],
}

impl Checkpoint {
    pub fn encode(&self) -> [u8; CHECKPOINT_LEN] {
        let mut out = [0u8; CHECKPOINT_LEN];
        let mut w = Writer::new(&mut out);
        let _ = w.raw(CHECKPOINT_DOMAIN);
        let _ = w.raw(&self.serial);
        let _ = w.u64(self.seq);
        let _ = w.raw(&self.head);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        if r.raw(CHECKPOINT_DOMAIN.len())? != CHECKPOINT_DOMAIN {
            return Err(WireError::Invalid);
        }
        let c = Checkpoint {
            serial: r.array()?,
            seq: r.u64()?,
            head: r.array()?,
        };
        r.finish()?;
        Ok(c)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogError {
    /// The checkpoint was not signed by this HSM.
    BadCheckpoint,
    /// Entry `seq` is malformed or out of order (something removed, added or
    /// reordered).
    BrokenAt(u64),
    /// The entries run out before reaching the checkpoint (entries missing
    /// at the end).
    TooShort { have: u64, need: u64 },
    /// All entries are present, but they don't hash to the signed head
    /// (something was changed).
    HeadMismatch,
}

/// Verifier side: checks a complete copy of the log (starting from entry
/// #1) against a signed checkpoint. Returns the checkpoint on success.
/// Entries after the checkpoint are allowed but not vouched for.
pub fn verify_log<'a>(
    identity: &[u8; PUBLIC_KEY_LEN],
    checkpoint: &[u8],
    signature: &[u8; SIGNATURE_LEN],
    entries: impl IntoIterator<Item = &'a [u8; ENTRY_LEN]>,
) -> Result<Checkpoint, LogError> {
    let vk = VerifyingKey::from_bytes(identity).map_err(|_| LogError::BadCheckpoint)?;
    vk.verify_strict(checkpoint, &Signature::from_bytes(signature))
        .map_err(|_| LogError::BadCheckpoint)?;
    let cp = Checkpoint::decode(checkpoint).map_err(|_| LogError::BadCheckpoint)?;

    let mut head = GENESIS;
    let mut seq = 0u64;
    for bytes in entries {
        if seq == cp.seq {
            break;
        }
        let e = Entry::decode(bytes).map_err(|_| LogError::BrokenAt(seq + 1))?;
        if e.seq != seq + 1 {
            return Err(LogError::BrokenAt(seq + 1));
        }
        head = link(&head, bytes);
        seq = e.seq;
    }
    if seq < cp.seq {
        return Err(LogError::TooShort {
            have: seq,
            need: cp.seq,
        });
    }
    if head != cp.head {
        return Err(LogError::HeadMismatch);
    }
    Ok(cp)
}
