//! Host <-> HSM wire protocol.
//!
//! Every byte that crosses the trust boundary goes through this module, so it
//! is written to be boring: fixed-width little-endian integers, `u16`
//! length-prefixed byte strings with per-field maximums, and no trailing
//! garbage allowed. Decoding never allocates and never panics.
//!
//! Request frame:  `[cmd: u8] [fields...]`
//! Response frame: `[status: u8] [fields...]` (fields only when status == Ok)

pub const MAX_FRAME: usize = 4096;
pub const MAX_PIN: usize = 32;
pub const MIN_PIN: usize = 4;
pub const MAX_LABEL: usize = 32;
pub const MAX_EXT_ID: usize = 32;
pub const MAX_MESSAGE: usize = 2048;

pub const PUBLIC_KEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;
pub const SERIAL_LEN: usize = 16;

use crate::admin::{AdminSet, Approvals};
use crate::agent::{Action, Policy};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// Input ended before a field was complete.
    Truncated,
    /// A length-prefixed field exceeded its maximum.
    TooLong,
    /// Bytes left over after the last field.
    Trailing,
    /// Output buffer too small.
    Overflow,
    /// Unknown command or status byte.
    UnknownTag,
    /// Well-formed bytes with a value the protocol does not allow.
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Cmd {
    GetInfo = 0x01,
    Login = 0x02,
    Logout = 0x03,
    GetIdentity = 0x04,
    GenerateKey = 0x10,
    ListKeys = 0x11,
    Sign = 0x12,
    DeleteKey = 0x13,
    GenerateAgentKey = 0x14,
    GetChallenge = 0x20,
    SignAction = 0x21,
    GetKeyPolicy = 0x22,
    GetKeyCert = 0x23,
    UpdatePolicy = 0x24,
    GetAdminChallenge = 0x30,
    DeleteAgentKey = 0x31,
    ChangeAdmins = 0x32,
    ReadAudit = 0x40,
    AuditCheckpoint = 0x41,
    AckAudit = 0x42,
}

impl TryFrom<u8> for Cmd {
    type Error = WireError;
    fn try_from(b: u8) -> Result<Self, WireError> {
        Ok(match b {
            0x01 => Cmd::GetInfo,
            0x02 => Cmd::Login,
            0x03 => Cmd::Logout,
            0x04 => Cmd::GetIdentity,
            0x10 => Cmd::GenerateKey,
            0x11 => Cmd::ListKeys,
            0x12 => Cmd::Sign,
            0x13 => Cmd::DeleteKey,
            0x14 => Cmd::GenerateAgentKey,
            0x20 => Cmd::GetChallenge,
            0x21 => Cmd::SignAction,
            0x22 => Cmd::GetKeyPolicy,
            0x23 => Cmd::GetKeyCert,
            0x24 => Cmd::UpdatePolicy,
            0x30 => Cmd::GetAdminChallenge,
            0x31 => Cmd::DeleteAgentKey,
            0x32 => Cmd::ChangeAdmins,
            0x40 => Cmd::ReadAudit,
            0x41 => Cmd::AuditCheckpoint,
            0x42 => Cmd::AckAudit,
            _ => return Err(WireError::UnknownTag),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    Ok = 0x00,
    BadRequest = 0x01,
    NotLoggedIn = 0x02,
    AlreadyLoggedIn = 0x03,
    PinIncorrect = 0x04,
    PinLocked = 0x05,
    KeyNotFound = 0x06,
    StoreFull = 0x07,
    ResponseTooLarge = 0x08,
    /// Persistent storage failed; the HSM refuses all commands until restart.
    Fault = 0x09,
    /// The key exists but may not be used this way (e.g. raw signing with
    /// an agent key).
    UsageNotAllowed = 0x0a,
    // Policy decisions for agent actions.
    ActionNotAllowed = 0x10,
    AmountTooHigh = 0x11,
    BudgetExceeded = 0x12,
    ConfirmationRequired = 0x13,
    ConfirmationInvalid = 0x14,
    NoChallenge = 0x15,
    /// The key's rules require a receiver's one-time code and none was given.
    NonceRequired = 0x16,
    // Multi-person sign-off.
    /// This operation needs admin sign-off (or no admins were set up).
    QuorumRequired = 0x20,
    /// An admin signature is wrong, unknown, or repeated.
    ApprovalInvalid = 0x21,
    /// No pending admin challenge (never requested, or already used).
    NoAdminChallenge = 0x22,
    /// The audit log is full: copy it out (`ReadAudit` + `AckAudit`) first.
    AuditFull = 0x30,
}

impl TryFrom<u8> for Status {
    type Error = WireError;
    fn try_from(b: u8) -> Result<Self, WireError> {
        Ok(match b {
            0x00 => Status::Ok,
            0x01 => Status::BadRequest,
            0x02 => Status::NotLoggedIn,
            0x03 => Status::AlreadyLoggedIn,
            0x04 => Status::PinIncorrect,
            0x05 => Status::PinLocked,
            0x06 => Status::KeyNotFound,
            0x07 => Status::StoreFull,
            0x08 => Status::ResponseTooLarge,
            0x09 => Status::Fault,
            0x0a => Status::UsageNotAllowed,
            0x10 => Status::ActionNotAllowed,
            0x11 => Status::AmountTooHigh,
            0x12 => Status::BudgetExceeded,
            0x13 => Status::ConfirmationRequired,
            0x14 => Status::ConfirmationInvalid,
            0x15 => Status::NoChallenge,
            0x16 => Status::NonceRequired,
            0x20 => Status::QuorumRequired,
            0x21 => Status::ApprovalInvalid,
            0x22 => Status::NoAdminChallenge,
            0x30 => Status::AuditFull,
            _ => return Err(WireError::UnknownTag),
        })
    }
}

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    pub fn raw(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(n).ok_or(WireError::Truncated)?;
        let out = self.buf.get(self.pos..end).ok_or(WireError::Truncated)?;
        self.pos = end;
        Ok(out)
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.raw(N)?);
        Ok(out)
    }

    pub fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.raw(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    pub fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub fn u64(&mut self) -> Result<u64, WireError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    /// A `u16`-length-prefixed byte string of at most `max` bytes.
    pub fn bytes(&mut self, max: usize) -> Result<&'a [u8], WireError> {
        let len = self.u16()? as usize;
        if len > max {
            return Err(WireError::TooLong);
        }
        self.raw(len)
    }

    pub fn finish(self) -> Result<(), WireError> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(WireError::Trailing)
        }
    }
}

pub struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Writer<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Writer { buf, pos: 0 }
    }

    pub fn raw(&mut self, data: &[u8]) -> Result<(), WireError> {
        let end = self
            .pos
            .checked_add(data.len())
            .ok_or(WireError::Overflow)?;
        self.buf
            .get_mut(self.pos..end)
            .ok_or(WireError::Overflow)?
            .copy_from_slice(data);
        self.pos = end;
        Ok(())
    }

    pub fn u8(&mut self, v: u8) -> Result<(), WireError> {
        self.raw(&[v])
    }

    pub fn u16(&mut self, v: u16) -> Result<(), WireError> {
        self.raw(&v.to_le_bytes())
    }

    pub fn u32(&mut self, v: u32) -> Result<(), WireError> {
        self.raw(&v.to_le_bytes())
    }

    pub fn u64(&mut self, v: u64) -> Result<(), WireError> {
        self.raw(&v.to_le_bytes())
    }

    pub fn bytes(&mut self, data: &[u8]) -> Result<(), WireError> {
        let len = u16::try_from(data.len()).map_err(|_| WireError::TooLong)?;
        self.u16(len)?;
        self.raw(data)
    }

    pub fn len(&self) -> usize {
        self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.pos == 0
    }
}

/// A decoded request. Borrowed fields point into the request frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request<'a> {
    GetInfo,
    Login {
        pin: &'a [u8],
    },
    Logout,
    /// `ext_id` is opaque caller metadata (PKCS#11 `CKA_ID`).
    GenerateKey {
        label: &'a [u8],
        ext_id: &'a [u8],
    },
    ListKeys,
    Sign {
        key: u32,
        msg: &'a [u8],
    },
    DeleteKey {
        key: u32,
    },
    /// Who this HSM is: serial, identity public key, admins.
    GetIdentity,
    /// Create a key that can only sign agent actions allowed by `policy`.
    /// Needs admin sign-off on the matching proposal.
    GenerateAgentKey {
        label: &'a [u8],
        ext_id: &'a [u8],
        policy: Policy,
        approvals: Approvals,
    },
    /// Delete an agent key. Needs admin sign-off.
    DeleteAgentKey {
        key: u32,
        approvals: Approvals,
    },
    /// Get a one-time challenge for an admin proposal.
    GetAdminChallenge,
    /// Get an agent key's birth certificate.
    GetKeyCert {
        key: u32,
    },
    /// Replace an agent key's rules. Needs admin sign-off.
    UpdatePolicy {
        key: u32,
        policy: Policy,
        approvals: Approvals,
    },
    /// Replace the admin list. Needs sign-off from the current admins.
    ChangeAdmins {
        admins: AdminSet,
        approvals: Approvals,
    },
    /// Audit entries from sequence number `from` that the HSM still holds.
    ReadAudit {
        from: u64,
    },
    /// A signed checkpoint of the audit chain.
    AuditCheckpoint,
    /// The computer has stored entries up to `upto`; the HSM may drop them.
    AckAudit {
        upto: u64,
    },
    /// Get a fresh one-time challenge for a user confirmation.
    GetChallenge,
    /// Ask the HSM to approve and sign an agent action. `confirmation` is the
    /// user's confirmation-device signature, when the policy needs one.
    SignAction {
        key: u32,
        action: Action<'a>,
        confirmation: Option<[u8; SIGNATURE_LEN]>,
    },
    GetKeyPolicy {
        key: u32,
    },
}

impl<'a> Request<'a> {
    pub fn decode(frame: &'a [u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(frame);
        let req = match Cmd::try_from(r.u8()?)? {
            Cmd::GetInfo => Request::GetInfo,
            Cmd::Login => Request::Login {
                pin: r.bytes(MAX_PIN)?,
            },
            Cmd::Logout => Request::Logout,
            Cmd::GenerateKey => Request::GenerateKey {
                label: r.bytes(MAX_LABEL)?,
                ext_id: r.bytes(MAX_EXT_ID)?,
            },
            Cmd::ListKeys => Request::ListKeys,
            Cmd::Sign => Request::Sign {
                key: r.u32()?,
                msg: r.bytes(MAX_MESSAGE)?,
            },
            Cmd::DeleteKey => Request::DeleteKey { key: r.u32()? },
            Cmd::GetIdentity => Request::GetIdentity,
            Cmd::GenerateAgentKey => Request::GenerateAgentKey {
                label: r.bytes(MAX_LABEL)?,
                ext_id: r.bytes(MAX_EXT_ID)?,
                policy: Policy::read(&mut r)?,
                approvals: Approvals::read(&mut r)?,
            },
            Cmd::DeleteAgentKey => Request::DeleteAgentKey {
                key: r.u32()?,
                approvals: Approvals::read(&mut r)?,
            },
            Cmd::GetAdminChallenge => Request::GetAdminChallenge,
            Cmd::GetKeyCert => Request::GetKeyCert { key: r.u32()? },
            Cmd::UpdatePolicy => Request::UpdatePolicy {
                key: r.u32()?,
                policy: Policy::read(&mut r)?,
                approvals: Approvals::read(&mut r)?,
            },
            Cmd::ChangeAdmins => {
                let admins = AdminSet::read(&mut r)?;
                // The HSM must always have someone who can approve changes.
                if admins.keys().is_empty() {
                    return Err(WireError::Invalid);
                }
                Request::ChangeAdmins {
                    admins,
                    approvals: Approvals::read(&mut r)?,
                }
            }
            Cmd::ReadAudit => Request::ReadAudit { from: r.u64()? },
            Cmd::AuditCheckpoint => Request::AuditCheckpoint,
            Cmd::AckAudit => Request::AckAudit { upto: r.u64()? },
            Cmd::GetChallenge => Request::GetChallenge,
            Cmd::SignAction => Request::SignAction {
                key: r.u32()?,
                action: Action::read(&mut r)?,
                confirmation: match r.u8()? {
                    0 => None,
                    1 => Some(r.array()?),
                    _ => return Err(WireError::Invalid),
                },
            },
            Cmd::GetKeyPolicy => Request::GetKeyPolicy { key: r.u32()? },
        };
        r.finish()?;
        Ok(req)
    }

    pub fn encode(&self, out: &mut [u8]) -> Result<usize, WireError> {
        let mut w = Writer::new(out);
        match *self {
            Request::GetInfo => w.u8(Cmd::GetInfo as u8)?,
            Request::Login { pin } => {
                w.u8(Cmd::Login as u8)?;
                w.bytes(pin)?;
            }
            Request::Logout => w.u8(Cmd::Logout as u8)?,
            Request::GenerateKey { label, ext_id } => {
                w.u8(Cmd::GenerateKey as u8)?;
                w.bytes(label)?;
                w.bytes(ext_id)?;
            }
            Request::ListKeys => w.u8(Cmd::ListKeys as u8)?,
            Request::Sign { key, msg } => {
                w.u8(Cmd::Sign as u8)?;
                w.u32(key)?;
                w.bytes(msg)?;
            }
            Request::DeleteKey { key } => {
                w.u8(Cmd::DeleteKey as u8)?;
                w.u32(key)?;
            }
            Request::GetIdentity => w.u8(Cmd::GetIdentity as u8)?,
            Request::GenerateAgentKey {
                label,
                ext_id,
                policy,
                approvals,
            } => {
                w.u8(Cmd::GenerateAgentKey as u8)?;
                w.bytes(label)?;
                w.bytes(ext_id)?;
                policy.write(&mut w)?;
                approvals.write(&mut w)?;
            }
            Request::DeleteAgentKey { key, approvals } => {
                w.u8(Cmd::DeleteAgentKey as u8)?;
                w.u32(key)?;
                approvals.write(&mut w)?;
            }
            Request::GetAdminChallenge => w.u8(Cmd::GetAdminChallenge as u8)?,
            Request::GetKeyCert { key } => {
                w.u8(Cmd::GetKeyCert as u8)?;
                w.u32(key)?;
            }
            Request::UpdatePolicy {
                key,
                policy,
                approvals,
            } => {
                w.u8(Cmd::UpdatePolicy as u8)?;
                w.u32(key)?;
                policy.write(&mut w)?;
                approvals.write(&mut w)?;
            }
            Request::ChangeAdmins { admins, approvals } => {
                w.u8(Cmd::ChangeAdmins as u8)?;
                admins.write(&mut w)?;
                approvals.write(&mut w)?;
            }
            Request::ReadAudit { from } => {
                w.u8(Cmd::ReadAudit as u8)?;
                w.u64(from)?;
            }
            Request::AuditCheckpoint => w.u8(Cmd::AuditCheckpoint as u8)?,
            Request::AckAudit { upto } => {
                w.u8(Cmd::AckAudit as u8)?;
                w.u64(upto)?;
            }
            Request::GetChallenge => w.u8(Cmd::GetChallenge as u8)?,
            Request::SignAction {
                key,
                action,
                confirmation,
            } => {
                w.u8(Cmd::SignAction as u8)?;
                w.u32(key)?;
                action.write(&mut w)?;
                match confirmation {
                    None => w.u8(0)?,
                    Some(sig) => {
                        w.u8(1)?;
                        w.raw(&sig)?;
                    }
                }
            }
            Request::GetKeyPolicy { key } => {
                w.u8(Cmd::GetKeyPolicy as u8)?;
                w.u32(key)?;
            }
        }
        Ok(w.len())
    }
}

/// Response payload types, with decoders for the host side.
pub mod resp {
    use super::*;

    pub const FLAG_LOGGED_IN: u8 = 1 << 0;
    pub const FLAG_PIN_LOCKED: u8 = 1 << 1;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Info {
        pub serial: [u8; SERIAL_LEN],
        pub fw_major: u8,
        pub fw_minor: u8,
        pub key_count: u8,
        pub max_keys: u8,
        pub pin_tries_left: u8,
        pub flags: u8,
    }

    impl Info {
        pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
            w.raw(&self.serial)?;
            w.u8(self.fw_major)?;
            w.u8(self.fw_minor)?;
            w.u8(self.key_count)?;
            w.u8(self.max_keys)?;
            w.u8(self.pin_tries_left)?;
            w.u8(self.flags)
        }

        pub fn decode(payload: &[u8]) -> Result<Self, WireError> {
            let mut r = Reader::new(payload);
            let info = Info {
                serial: r.array()?,
                fw_major: r.u8()?,
                fw_minor: r.u8()?,
                key_count: r.u8()?,
                max_keys: r.u8()?,
                pin_tries_left: r.u8()?,
                flags: r.u8()?,
            };
            r.finish()?;
            Ok(info)
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Generated {
        pub key: u32,
        pub public: [u8; PUBLIC_KEY_LEN],
    }

    impl Generated {
        pub fn decode(payload: &[u8]) -> Result<Self, WireError> {
            let mut r = Reader::new(payload);
            let g = Generated {
                key: r.u32()?,
                public: r.array()?,
            };
            r.finish()?;
            Ok(g)
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct KeyEntry<'a> {
        pub key: u32,
        pub label: &'a [u8],
        pub ext_id: &'a [u8],
        pub public: [u8; PUBLIC_KEY_LEN],
        pub usage: KeyUsage,
    }

    impl KeyEntry<'_> {
        pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
            w.u32(self.key)?;
            w.bytes(self.label)?;
            w.bytes(self.ext_id)?;
            w.raw(&self.public)?;
            w.u8(self.usage as u8)
        }
    }

    /// Decodes a `ListKeys` payload: `[count: u8] [KeyEntry]*`.
    /// Validates the whole payload up front so iteration cannot fail.
    pub fn decode_key_list(payload: &[u8]) -> Result<KeyList<'_>, WireError> {
        let mut r = Reader::new(payload);
        let count = r.u8()?;
        for _ in 0..count {
            read_entry(&mut r)?;
        }
        r.finish()?;
        Ok(KeyList {
            r: Reader::new(&payload[1..]),
            remaining: count,
        })
    }

    fn read_entry<'a>(r: &mut Reader<'a>) -> Result<KeyEntry<'a>, WireError> {
        Ok(KeyEntry {
            key: r.u32()?,
            label: r.bytes(MAX_LABEL)?,
            ext_id: r.bytes(MAX_EXT_ID)?,
            public: r.array()?,
            usage: KeyUsage::try_from(r.u8()?)?,
        })
    }

    pub struct KeyList<'a> {
        r: Reader<'a>,
        remaining: u8,
    }

    impl<'a> Iterator for KeyList<'a> {
        type Item = KeyEntry<'a>;
        fn next(&mut self) -> Option<KeyEntry<'a>> {
            if self.remaining == 0 {
                return None;
            }
            self.remaining -= 1;
            read_entry(&mut self.r).ok()
        }
    }

    pub fn decode_signature(payload: &[u8]) -> Result<[u8; SIGNATURE_LEN], WireError> {
        let mut r = Reader::new(payload);
        let sig = r.array()?;
        r.finish()?;
        Ok(sig)
    }

    /// Splits a response frame into its status and payload.
    pub fn split(frame: &[u8]) -> Result<(Status, &[u8]), WireError> {
        let (&status, payload) = frame.split_first().ok_or(WireError::Truncated)?;
        Ok((Status::try_from(status)?, payload))
    }

    /// `SignAction` payload: `[statement: bytes] [signature: 64]`.
    pub fn decode_signed_action(payload: &[u8]) -> Result<(&[u8], [u8; SIGNATURE_LEN]), WireError> {
        let mut r = Reader::new(payload);
        let statement = r.bytes(crate::agent::MAX_STATEMENT)?;
        let sig = r.array()?;
        r.finish()?;
        Ok((statement, sig))
    }

    /// `GetKeyPolicy` payload.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct KeyPolicy {
        pub policy: Policy,
        /// Total spent so far, in cents.
        pub spent: u64,
        /// Number of actions approved so far (the last sequence number).
        pub approved: u64,
    }

    impl KeyPolicy {
        pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
            self.policy.write(w)?;
            w.u64(self.spent)?;
            w.u64(self.approved)
        }

        pub fn decode(payload: &[u8]) -> Result<Self, WireError> {
            let mut r = Reader::new(payload);
            let kp = KeyPolicy {
                policy: Policy::read(&mut r)?,
                spent: r.u64()?,
                approved: r.u64()?,
            };
            r.finish()?;
            Ok(kp)
        }
    }

    pub fn decode_challenge(
        payload: &[u8],
    ) -> Result<[u8; crate::agent::CHALLENGE_LEN], WireError> {
        let mut r = Reader::new(payload);
        let c = r.array()?;
        r.finish()?;
        Ok(c)
    }

    /// `GetIdentity` payload.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Identity {
        pub serial: [u8; SERIAL_LEN],
        /// Signs birth certificates only.
        pub public: [u8; PUBLIC_KEY_LEN],
        pub admins: AdminSet,
    }

    impl Identity {
        pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
            w.raw(&self.serial)?;
            w.raw(&self.public)?;
            self.admins.write(w)
        }

        pub fn decode(payload: &[u8]) -> Result<Self, WireError> {
            let mut r = Reader::new(payload);
            let id = Identity {
                serial: r.array()?,
                public: r.array()?,
                admins: AdminSet::read(&mut r)?,
            };
            r.finish()?;
            Ok(id)
        }
    }

    /// A birth certificate and the HSM identity's signature on it.
    pub fn write_cert(
        w: &mut Writer<'_>,
        cert: &[u8],
        sig: &[u8; SIGNATURE_LEN],
    ) -> Result<(), WireError> {
        w.bytes(cert)?;
        w.raw(sig)
    }

    fn read_cert<'a>(r: &mut Reader<'a>) -> Result<(&'a [u8], [u8; SIGNATURE_LEN]), WireError> {
        Ok((r.bytes(crate::cert::KEYCERT_LEN)?, r.array()?))
    }

    /// `GetKeyCert` payload.
    pub fn decode_cert(payload: &[u8]) -> Result<(&[u8], [u8; SIGNATURE_LEN]), WireError> {
        let mut r = Reader::new(payload);
        let c = read_cert(&mut r)?;
        r.finish()?;
        Ok(c)
    }

    /// `GenerateAgentKey` payload: the new key and its birth certificate.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AgentKeyCreated<'a> {
        pub key: u32,
        pub public: [u8; PUBLIC_KEY_LEN],
        pub cert: &'a [u8],
        pub cert_sig: [u8; SIGNATURE_LEN],
    }

    impl<'a> AgentKeyCreated<'a> {
        pub fn decode(payload: &'a [u8]) -> Result<Self, WireError> {
            let mut r = Reader::new(payload);
            let key = r.u32()?;
            let public = r.array()?;
            let (cert, cert_sig) = read_cert(&mut r)?;
            r.finish()?;
            Ok(AgentKeyCreated {
                key,
                public,
                cert,
                cert_sig,
            })
        }
    }

    /// `ReadAudit` payload: the newest sequence number, the chain head, and
    /// the held entries from the requested point.
    pub struct AuditBatch<'a> {
        pub last_seq: u64,
        pub head: [u8; 32],
        entries: &'a [u8],
    }

    impl<'a> AuditBatch<'a> {
        pub fn decode(payload: &'a [u8]) -> Result<Self, WireError> {
            let mut r = Reader::new(payload);
            let last_seq = r.u64()?;
            let head = r.array()?;
            let n = r.u8()? as usize;
            let entries = r.raw(n * crate::audit::ENTRY_LEN)?;
            r.finish()?;
            Ok(AuditBatch {
                last_seq,
                head,
                entries,
            })
        }

        pub fn entries(&self) -> impl Iterator<Item = &'a [u8; crate::audit::ENTRY_LEN]> {
            self.entries
                .chunks_exact(crate::audit::ENTRY_LEN)
                .filter_map(|c| c.try_into().ok())
        }
    }

    /// `AuditCheckpoint` payload: checkpoint bytes and identity signature.
    pub fn decode_checkpoint(payload: &[u8]) -> Result<(&[u8], [u8; SIGNATURE_LEN]), WireError> {
        let mut r = Reader::new(payload);
        let c = r.bytes(crate::audit::CHECKPOINT_LEN)?;
        let sig = r.array()?;
        r.finish()?;
        Ok((c, sig))
    }
}

/// What a key may be used for. Fixed when the key is created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyUsage {
    /// Signs any bytes the logged-in user asks for (classic HSM behaviour).
    General = 0,
    /// Signs only agent actions that pass the key's policy.
    Agent = 1,
}

impl TryFrom<u8> for KeyUsage {
    type Error = WireError;
    fn try_from(b: u8) -> Result<Self, WireError> {
        match b {
            0 => Ok(KeyUsage::General),
            1 => Ok(KeyUsage::Agent),
            _ => Err(WireError::UnknownTag),
        }
    }
}
