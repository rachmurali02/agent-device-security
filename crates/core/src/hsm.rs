//! The HSM command processor: the code that runs inside the trust boundary.
//!
//! The host sends request frames; `Hsm::handle` decides whether to honour
//! them and writes a response frame. Every security decision (is the caller
//! logged in, is the PIN right, does the key exist, does this agent action
//! follow the key's rules) is made here, never in the host library.

use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use ed25519_dalek::{Signer, SigningKey};

use crate::admin::{AdminOp, AdminSet, Approvals, MAX_ADMINS, MAX_PROPOSAL, Proposal, QuorumError};
use crate::agent::{
    Action, CHALLENGE_LEN, MAX_STATEMENT, POLICY_LEN, Policy, Statement, confirmation_valid,
};
use crate::audit::{AUDIT_STATE_MAX, AuditLog, Checkpoint, Event, digest};
use crate::cert::{KEYCERT_LEN, KeyCert};
use crate::keystore::{KeyMeta, KeyStore, MAX_KEYS, SECRET_LEN, UseError};
use crate::wire::{
    KeyUsage, MAX_EXT_ID, MAX_LABEL, MAX_PIN, MIN_PIN, Reader, Request, SERIAL_LEN, SIGNATURE_LEN,
    Status, WireError, Writer, resp,
};

pub const FW_VERSION: (u8, u8) = (0, 4);
pub const MAX_PIN_TRIES: u8 = 5;

const STATE_MAGIC: &[u8; 4] = b"QHSM";
const STATE_VERSION: u8 = 4;
/// Worst case per key: an agent key, which also stores its policy and counters.
const SLOT_STATE_LEN: usize =
    4 + 1 + MAX_LABEL + 1 + MAX_EXT_ID + SECRET_LEN + 1 + POLICY_LEN + 8 + 8 + 1 + 4;
const IDENTITY_SECRET_LEN: usize = 32;
const ADMINS_STATE_LEN: usize = 2 + MAX_ADMINS * 32;
/// Upper bound on the serialized state size.
pub const STATE_MAX: usize = 4
    + 1
    + SERIAL_LEN
    + 1
    + MAX_PIN
    + 1
    + IDENTITY_SECRET_LEN
    + ADMINS_STATE_LEN
    + AUDIT_STATE_MAX
    + 4
    + 1
    + MAX_KEYS * SLOT_STATE_LEN;

/// Persistent storage for HSM state (flash on a device, a file in the emulator).
///
/// `commit` must be atomic: after it returns, either the new state or the old
/// state is durable, never a mix. The HSM calls it *before* acting on any
/// change that must survive power loss.
pub trait Storage {
    fn commit(&mut self, state: &[u8]) -> Result<(), StorageError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateError {
    BadMagic,
    UnsupportedVersion,
    Malformed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitError {
    BadPinLength,
    /// Duplicate or invalid admin keys, or an impossible threshold.
    BadAdmins,
    Storage,
}

/// Everything the factory decides when it creates an HSM.
pub struct Provisioning<'a> {
    pub serial: [u8; SERIAL_LEN],
    pub pin: &'a [u8],
    /// Admins whose sign-off is needed to create or delete agent keys.
    /// Empty means agent keys can never be created on this HSM.
    pub admins: &'a [[u8; 32]],
    /// How many admins must sign off.
    pub threshold: u8,
}

/// Per-connection state. On real hardware this lives in the HSM's RAM, keyed
/// by the host session; it is never trusted from the host.
#[derive(Debug, Default)]
pub struct Session {
    logged_in: bool,
    /// One-time challenge for the next user confirmation. Consumed by the
    /// first `SignAction` that presents a confirmation, valid or not.
    challenge: Option<[u8; CHALLENGE_LEN]>,
}

impl Session {
    pub fn is_logged_in(&self) -> bool {
        self.logged_in
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Hsm {
    serial: [u8; SERIAL_LEN],
    pin: [u8; MAX_PIN],
    pin_len: u8,
    pin_tries_left: u8,
    store: KeyStore,
    /// Signs birth certificates and audit checkpoints, each with its own
    /// domain prefix, and never anything the computer chooses. Created at
    /// the factory, never leaves the HSM.
    identity: [u8; IDENTITY_SECRET_LEN],
    #[zeroize(skip)]
    audit: AuditLog,
    #[zeroize(skip)]
    admins: AdminSet,
    /// One-time challenge for the pending admin proposal. Kept in RAM only:
    /// a restart cancels any proposal in progress.
    #[zeroize(skip)]
    admin_challenge: Option<[u8; CHALLENGE_LEN]>,
    /// Set when storage fails. A faulted HSM refuses every command (fail
    /// closed) until it restarts and reloads its last committed state.
    #[zeroize(skip)]
    faulted: bool,
}

impl Hsm {
    /// Factory provisioning: create a fresh HSM and commit its first state.
    pub fn provision(
        p: Provisioning<'_>,
        rng: &mut impl CryptoRngCore,
        storage: &mut impl Storage,
    ) -> Result<Self, InitError> {
        if !(MIN_PIN..=MAX_PIN).contains(&p.pin.len()) {
            return Err(InitError::BadPinLength);
        }
        let admins = AdminSet::new(p.admins, p.threshold).map_err(|_| InitError::BadAdmins)?;
        let mut hsm = Hsm {
            serial: p.serial,
            pin: [0; MAX_PIN],
            pin_len: p.pin.len() as u8,
            pin_tries_left: MAX_PIN_TRIES,
            store: KeyStore::new(),
            identity: [0; IDENTITY_SECRET_LEN],
            audit: AuditLog::new(),
            admins,
            admin_challenge: None,
            faulted: false,
        };
        rng.fill_bytes(&mut hsm.identity);
        hsm.pin[..p.pin.len()].copy_from_slice(p.pin);
        // Entry #1 records who the admins were at the factory.
        let admins_digest = hsm.admins_digest();
        hsm.record(Event::Provisioned, Status::Ok, 0, 0, admins_digest)
            .map_err(|_| InitError::Storage)?;
        hsm.commit(storage).map_err(|_| InitError::Storage)?;
        Ok(hsm)
    }

    pub fn serial(&self) -> &[u8; SERIAL_LEN] {
        &self.serial
    }

    /// The public half of the identity key: what receivers trust.
    pub fn identity_public(&self) -> [u8; 32] {
        SigningKey::from_bytes(&self.identity)
            .verifying_key()
            .to_bytes()
    }

    pub fn is_faulted(&self) -> bool {
        self.faulted
    }

    /// Processes one request frame and writes the response frame into
    /// `resp`, returning its length. `resp` should be `wire::MAX_FRAME` bytes.
    pub fn handle(
        &mut self,
        session: &mut Session,
        storage: &mut impl Storage,
        rng: &mut impl CryptoRngCore,
        req: &[u8],
        resp: &mut [u8],
    ) -> usize {
        let mut w = Writer::new(resp);
        // Status byte first; payload follows only on success.
        if w.u8(Status::Ok as u8).is_err() {
            return 0;
        }
        let status = match self.dispatch(session, storage, rng, req, &mut w) {
            Ok(()) => return w.len(),
            Err(status) => status,
        };
        resp[0] = status as u8;
        1
    }

    fn dispatch(
        &mut self,
        session: &mut Session,
        storage: &mut impl Storage,
        rng: &mut impl CryptoRngCore,
        req: &[u8],
        w: &mut Writer<'_>,
    ) -> Result<(), Status> {
        if self.faulted {
            return Err(Status::Fault);
        }
        let req = Request::decode(req).map_err(|_| Status::BadRequest)?;
        let overflow = |_: WireError| Status::ResponseTooLarge;

        match req {
            Request::GetInfo => {
                let mut flags = 0;
                if session.logged_in {
                    flags |= resp::FLAG_LOGGED_IN;
                }
                if self.pin_tries_left == 0 {
                    flags |= resp::FLAG_PIN_LOCKED;
                }
                resp::Info {
                    serial: self.serial,
                    fw_major: FW_VERSION.0,
                    fw_minor: FW_VERSION.1,
                    key_count: self.store.len() as u8,
                    max_keys: MAX_KEYS as u8,
                    pin_tries_left: self.pin_tries_left,
                    flags,
                }
                .encode(w)
                .map_err(overflow)
            }

            Request::Login { pin } => self.login(session, storage, pin),

            Request::Logout => {
                *session = Session::default();
                Ok(())
            }

            Request::GenerateKey { label, ext_id } => {
                require_login(session)?;
                self.audit_room()?;
                let (id, public) = self
                    .store
                    .generate(rng, KeyMeta::general(label, ext_id))
                    .map_err(|_| Status::StoreFull)?;
                self.record(Event::KeyCreated, Status::Ok, id, 0, digest(&[&public]))?;
                // The key does not exist until it is durable. If the commit
                // fails we fault rather than hand out a key that a restart
                // would silently lose.
                self.commit(storage)?;
                w.u32(id).map_err(overflow)?;
                w.raw(&public).map_err(overflow)
            }

            // Public metadata is visible without login, like PKCS#11 public
            // objects. Secrets never appear here.
            Request::ListKeys => {
                w.u8(self.store.len() as u8).map_err(overflow)?;
                for slot in self.store.slots() {
                    resp::KeyEntry {
                        key: slot.id,
                        label: slot.label(),
                        ext_id: slot.ext_id(),
                        public: slot.public,
                        usage: slot.usage,
                    }
                    .encode(w)
                    .map_err(overflow)?;
                }
                Ok(())
            }

            Request::Sign { key, msg } => {
                require_login(session)?;
                let sig = self.store.sign(key, msg).map_err(use_error)?;
                w.raw(&sig).map_err(overflow)
            }

            Request::DeleteKey { key } => {
                require_login(session)?;
                let slot = self.store.get(key).ok_or(Status::KeyNotFound)?;
                // Deleting an agent key needs admin sign-off; otherwise the
                // PIN holder could delete it and ask for a fresh budget.
                if slot.usage == KeyUsage::Agent {
                    return Err(Status::QuorumRequired);
                }
                self.audit_room()?;
                let public = slot.public;
                self.store.delete(key);
                self.record(Event::KeyDeleted, Status::Ok, key, 0, digest(&[&public]))?;
                self.commit(storage)
            }

            Request::GetIdentity => resp::Identity {
                serial: self.serial,
                public: self.identity_public(),
                admins: self.admins,
            }
            .encode(w)
            .map_err(overflow),

            Request::GetAdminChallenge => {
                require_login(session)?;
                let mut challenge = [0u8; CHALLENGE_LEN];
                rng.fill_bytes(&mut challenge);
                self.admin_challenge = Some(challenge);
                w.raw(&challenge).map_err(overflow)
            }

            Request::GenerateAgentKey {
                label,
                ext_id,
                policy,
                approvals,
            } => {
                require_login(session)?;
                let op = AdminOp::CreateAgentKey {
                    label,
                    ext_id,
                    policy,
                };
                let approvers = self.admin_op(storage, 0, &op, &approvals)?;
                let (id, public) = self
                    .store
                    .generate(rng, KeyMeta::agent(label, ext_id, policy, approvers))
                    .map_err(|_| Status::StoreFull)?;
                self.record(Event::AgentKeyCreated, Status::Ok, id, 0, policy.digest())?;
                self.commit(storage)?;
                w.u32(id).map_err(overflow)?;
                w.raw(&public).map_err(overflow)?;
                self.write_cert(id, w)
            }

            Request::DeleteAgentKey { key, approvals } => {
                require_login(session)?;
                let slot = self.store.get(key).ok_or(Status::KeyNotFound)?;
                if slot.usage != KeyUsage::Agent {
                    return Err(Status::UsageNotAllowed);
                }
                let op = AdminOp::DeleteAgentKey { key };
                self.admin_op(storage, key, &op, &approvals)?;
                let public = self.store.get(key).map(|s| s.public).unwrap_or_default();
                self.store.delete(key);
                self.record(
                    Event::AgentKeyDeleted,
                    Status::Ok,
                    key,
                    0,
                    digest(&[&public]),
                )?;
                self.commit(storage)
            }

            Request::UpdatePolicy {
                key,
                policy,
                approvals,
            } => {
                require_login(session)?;
                let slot = self.store.get(key).ok_or(Status::KeyNotFound)?;
                if slot.usage != KeyUsage::Agent {
                    return Err(Status::UsageNotAllowed);
                }
                let op = AdminOp::UpdatePolicy { key, policy };
                let approvers = self.admin_op(storage, key, &op, &approvals)?;
                self.store
                    .update_policy(key, policy, approvers)
                    .ok_or(Status::KeyNotFound)?;
                self.record(Event::PolicyUpdated, Status::Ok, key, 0, policy.digest())?;
                self.commit(storage)?;
                self.write_cert(key, w)
            }

            Request::ChangeAdmins { admins, approvals } => {
                require_login(session)?;
                // Approved by the admins in charge *now*, not the new ones.
                self.admin_op(storage, 0, &AdminOp::ChangeAdmins { admins }, &approvals)?;
                self.admins = admins;
                let admins_digest = self.admins_digest();
                self.record(Event::AdminsChanged, Status::Ok, 0, 0, admins_digest)?;
                self.commit(storage)
            }

            // The log is evidence, not a secret: anyone may read it, and
            // anyone may release entries already copied out. Releasing
            // without keeping a copy only destroys the copier's own evidence,
            // and shows up as a gap against any checkpoint.
            Request::ReadAudit { from } => {
                w.u64(self.audit.last_seq()).map_err(overflow)?;
                w.raw(&self.audit.head()).map_err(overflow)?;
                let n = self.audit.entries_from(from).count();
                w.u8(n as u8).map_err(overflow)?;
                for e in self.audit.entries_from(from) {
                    w.raw(e).map_err(overflow)?;
                }
                Ok(())
            }

            Request::AuditCheckpoint => {
                let cp = Checkpoint {
                    serial: self.serial,
                    seq: self.audit.last_seq(),
                    head: self.audit.head(),
                }
                .encode();
                let sig = SigningKey::from_bytes(&self.identity).sign(&cp).to_bytes();
                w.bytes(&cp).map_err(overflow)?;
                w.raw(&sig).map_err(overflow)
            }

            Request::AckAudit { upto } => {
                if !self.audit.ack(upto) {
                    return Err(Status::BadRequest);
                }
                self.commit(storage)
            }

            // Certificates are public: they are meant to be handed out.
            Request::GetKeyCert { key } => {
                let slot = self.store.get(key).ok_or(Status::KeyNotFound)?;
                if slot.usage != KeyUsage::Agent {
                    return Err(Status::UsageNotAllowed);
                }
                self.write_cert(key, w)
            }

            Request::GetChallenge => {
                require_login(session)?;
                let mut challenge = [0u8; CHALLENGE_LEN];
                rng.fill_bytes(&mut challenge);
                session.challenge = Some(challenge);
                w.raw(&challenge).map_err(overflow)
            }

            Request::SignAction {
                key,
                action,
                confirmation,
            } => self.sign_action(session, storage, key, &action, confirmation, w),

            // Rules are public: anyone may read them, and they are bound
            // into every statement by digest anyway.
            Request::GetKeyPolicy { key } => {
                let slot = self.store.get(key).ok_or(Status::KeyNotFound)?;
                if slot.usage != KeyUsage::Agent {
                    return Err(Status::UsageNotAllowed);
                }
                resp::KeyPolicy {
                    policy: slot.policy,
                    spent: slot.spent,
                    approved: slot.approved,
                }
                .encode(w)
                .map_err(overflow)
            }
        }
    }

    /// The policy check for agent actions. Checks run in a fixed order and
    /// the first failure wins; nothing is charged or signed unless all pass.
    fn sign_action(
        &mut self,
        session: &mut Session,
        storage: &mut impl Storage,
        key: u32,
        action: &Action<'_>,
        confirmation: Option<[u8; SIGNATURE_LEN]>,
        w: &mut Writer<'_>,
    ) -> Result<(), Status> {
        require_login(session)?;
        // No room to record the outcome: refuse before anything else, so not
        // even a refusal goes unrecorded.
        self.audit_room()?;
        match self.check_action(session, key, action, confirmation) {
            Ok(confirmed) => self.approve_action(storage, key, action, confirmed, w),
            Err(status) => {
                let mut buf = [0u8; MAX_STATEMENT];
                let mut aw = Writer::new(&mut buf);
                let _ = action.write(&mut aw);
                let n = aw.len();
                let what = digest(&[&buf[..n]]);
                self.record(Event::ActionRefused, status, key, action.amount, what)?;
                self.commit(storage)?;
                Err(status)
            }
        }
    }

    /// Every rule check, in a fixed order; the first failure wins. Returns
    /// whether the user confirmed.
    fn check_action(
        &self,
        session: &mut Session,
        key: u32,
        action: &Action<'_>,
        confirmation: Option<[u8; SIGNATURE_LEN]>,
    ) -> Result<bool, Status> {
        let slot = self.store.get(key).ok_or(Status::KeyNotFound)?;
        if slot.usage != KeyUsage::Agent {
            return Err(Status::UsageNotAllowed);
        }
        let policy: Policy = slot.policy;

        // 1. Is this kind of action allowed at all?
        if !policy.allows(action.kind) {
            return Err(Status::ActionNotAllowed);
        }
        // 1b. Do the rules demand a receiver's one-time code?
        if policy.require_nonce && action.nonce.is_empty() {
            return Err(Status::NonceRequired);
        }
        // 2. Is this single payment small enough?
        if action.amount > policy.max_amount {
            return Err(Status::AmountTooHigh);
        }
        // 3. Would it go over the total budget?
        match slot.spent.checked_add(action.amount) {
            Some(total) if total <= policy.budget => {}
            _ => return Err(Status::BudgetExceeded),
        }
        // 4. Does it need the user's confirmation, and is the one given real?
        let confirmed = match confirmation {
            Some(sig) => {
                // A presented confirmation always uses up the challenge, so
                // each one can be tried exactly once.
                let challenge = session.challenge.take().ok_or(Status::NoChallenge)?;
                let confirmer = policy.confirmer.ok_or(Status::ConfirmationInvalid)?;
                if !confirmation_valid(&confirmer, &self.serial, &challenge, key, action, &sig) {
                    return Err(Status::ConfirmationInvalid);
                }
                true
            }
            None if policy.needs_confirmation(action) => {
                return Err(Status::ConfirmationRequired);
            }
            None => false,
        };
        Ok(confirmed)
    }

    fn approve_action(
        &mut self,
        storage: &mut impl Storage,
        key: u32,
        action: &Action<'_>,
        confirmed: bool,
        w: &mut Writer<'_>,
    ) -> Result<(), Status> {
        let policy = self.store.get(key).ok_or(Status::KeyNotFound)?.policy;
        // All checks passed. Charge the action and make that durable *before*
        // signing: a crash or power cut can never yield a signature that
        // was not counted against the budget, or reuse a sequence number.
        let sequence = self
            .store
            .charge(key, action.amount)
            .ok_or(Status::BudgetExceeded)?;
        let statement = Statement {
            serial: self.serial,
            key,
            sequence,
            action: *action,
            confirmed,
            policy_digest: policy.digest(),
        };
        let mut buf = [0u8; MAX_STATEMENT];
        let mut sw = Writer::new(&mut buf);
        statement.write(&mut sw).map_err(|_| Status::Fault)?;
        let len = sw.len();
        // The approval is logged in the same save as the spending.
        let what = digest(&[&buf[..len]]);
        self.record(Event::ActionApproved, Status::Ok, key, action.amount, what)?;
        self.commit(storage)?;

        let sig = self
            .store
            .sign_statement(key, &buf[..len])
            .map_err(use_error)?;

        let overflow = |_: WireError| Status::ResponseTooLarge;
        w.bytes(&buf[..len]).map_err(overflow)?;
        w.raw(&sig).map_err(overflow)
    }

    /// Fails with `AuditFull` if the log cannot take another entry.
    fn audit_room(&self) -> Result<(), Status> {
        if self.audit.is_full() {
            Err(Status::AuditFull)
        } else {
            Ok(())
        }
    }

    fn record(
        &mut self,
        event: Event,
        status: Status,
        key: u32,
        amount: u64,
        what: [u8; 32],
    ) -> Result<(), Status> {
        self.audit
            .append(event, status as u8, key, amount, what)
            .map(drop)
            .map_err(|_| Status::AuditFull)
    }

    fn admins_digest(&self) -> [u8; 32] {
        let mut buf = [0u8; ADMINS_STATE_LEN];
        let mut w = Writer::new(&mut buf);
        let _ = self.admins.write(&mut w);
        let n = w.len();
        digest(&[&buf[..n]])
    }

    /// Checks admin sign-off for `op`, recording a refusal in the audit log.
    fn admin_op(
        &mut self,
        storage: &mut impl Storage,
        key: u32,
        op: &AdminOp<'_>,
        approvals: &Approvals,
    ) -> Result<u8, Status> {
        self.audit_room()?;
        match self.check_quorum(op, approvals) {
            Ok(approvers) => Ok(approvers),
            Err(status) => {
                let mut buf = [0u8; MAX_PROPOSAL];
                let mut w = Writer::new(&mut buf);
                let _ = op.write(&mut w);
                let n = w.len();
                self.record(
                    Event::AdminRequestRefused,
                    status,
                    key,
                    0,
                    digest(&[&buf[..n]]),
                )?;
                self.commit(storage)?;
                Err(status)
            }
        }
    }

    /// Uses up the pending admin challenge and checks the approvals against
    /// the proposal rebuilt from this HSM's serial, that challenge and `op`.
    /// Returns which admins approved.
    fn check_quorum(&mut self, op: &AdminOp<'_>, approvals: &Approvals) -> Result<u8, Status> {
        if self.admins.keys().is_empty() {
            return Err(Status::QuorumRequired);
        }
        let challenge = self
            .admin_challenge
            .take()
            .ok_or(Status::NoAdminChallenge)?;
        let mut buf = [0u8; MAX_PROPOSAL];
        let len = Proposal {
            serial: self.serial,
            challenge,
            op: *op,
        }
        .encode(&mut buf)
        .map_err(|_| Status::BadRequest)?;
        self.admins
            .check(&buf[..len], approvals)
            .map_err(|e| match e {
                QuorumError::NoAdmins | QuorumError::NotEnough => Status::QuorumRequired,
                QuorumError::Invalid => Status::ApprovalInvalid,
            })
    }

    /// Writes an agent key's birth certificate and the identity signature.
    /// Ed25519 signatures are deterministic, so this always produces the
    /// same certificate for the same key.
    fn write_cert(&self, key: u32, w: &mut Writer<'_>) -> Result<(), Status> {
        let slot = self.store.get(key).ok_or(Status::KeyNotFound)?;
        let cert = KeyCert {
            serial: self.serial,
            key,
            public: slot.public,
            policy: slot.policy,
            approvers: slot.approvers,
            version: slot.policy_version,
        };
        let mut buf = [0u8; KEYCERT_LEN];
        let len = cert.encode(&mut buf).map_err(|_| Status::Fault)?;
        let sig = SigningKey::from_bytes(&self.identity)
            .sign(&buf[..len])
            .to_bytes();
        resp::write_cert(w, &buf[..len], &sig).map_err(|_| Status::ResponseTooLarge)
    }

    fn login(
        &mut self,
        session: &mut Session,
        storage: &mut impl Storage,
        pin: &[u8],
    ) -> Result<(), Status> {
        if session.logged_in {
            return Err(Status::AlreadyLoggedIn);
        }
        if self.pin_tries_left == 0 {
            return Err(Status::PinLocked);
        }
        // The outcome must be recordable; otherwise don't even try.
        self.audit_room()?;

        // Spend the attempt and make that durable *before* comparing. If an
        // attacker cuts power the moment they detect a wrong guess (timing,
        // power trace), the attempt has already been counted. Comparing first
        // would give unlimited guesses.
        self.pin_tries_left -= 1;
        self.commit(storage)?;

        if self.pin_matches(pin) {
            self.pin_tries_left = MAX_PIN_TRIES;
            self.record(Event::LoginOk, Status::Ok, 0, 0, [0; 32])?;
            self.commit(storage)?;
            session.logged_in = true;
            Ok(())
        } else {
            let status = if self.pin_tries_left == 0 {
                Status::PinLocked
            } else {
                Status::PinIncorrect
            };
            self.record(Event::LoginFailed, status, 0, 0, [0; 32])?;
            self.commit(storage)?;
            Err(status)
        }
    }

    /// Constant-time PIN check: compares the full fixed-size buffers and the
    /// lengths, so timing does not reveal how many leading bytes matched.
    fn pin_matches(&self, candidate: &[u8]) -> bool {
        if candidate.len() > MAX_PIN {
            return false;
        }
        let mut padded = [0u8; MAX_PIN];
        padded[..candidate.len()].copy_from_slice(candidate);
        let same_bytes = self.pin.ct_eq(&padded);
        let same_len = self.pin_len.ct_eq(&(candidate.len() as u8));
        padded.zeroize();
        bool::from(same_bytes & same_len)
    }

    fn commit(&mut self, storage: &mut impl Storage) -> Result<(), Status> {
        let mut buf = [0u8; STATE_MAX];
        let result = match self.save(&mut buf) {
            Ok(len) => storage.commit(&buf[..len]).map_err(|_| Status::Fault),
            Err(_) => Err(Status::Fault),
        };
        buf.zeroize();
        if result.is_err() {
            self.faulted = true;
        }
        result
    }

    /// Serializes the full state, including secrets, for persistent storage.
    ///
    /// Milestone 1 stores this in plaintext. Sealing it (encrypting and
    /// authenticating under a device-unique key) is tracked in the roadmap.
    pub fn save(&self, out: &mut [u8]) -> Result<usize, WireError> {
        let mut w = Writer::new(out);
        w.raw(STATE_MAGIC)?;
        w.u8(STATE_VERSION)?;
        w.raw(&self.serial)?;
        w.u8(self.pin_len)?;
        w.raw(&self.pin)?;
        w.u8(self.pin_tries_left)?;
        w.raw(&self.identity)?;
        self.admins.write(&mut w)?;
        self.audit.write_state(&mut w)?;
        w.u32(self.store.next_id())?;
        w.u8(self.store.len() as u8)?;
        for slot in self.store.slots() {
            w.u32(slot.id)?;
            w.u8(slot.label_len)?;
            w.raw(&slot.label)?;
            w.u8(slot.ext_id_len)?;
            w.raw(&slot.ext_id)?;
            w.raw(&slot.secret)?;
            w.u8(slot.usage as u8)?;
            if slot.usage == KeyUsage::Agent {
                slot.policy.write(&mut w)?;
                w.u64(slot.spent)?;
                w.u64(slot.approved)?;
                w.u8(slot.approvers)?;
                w.u32(slot.policy_version)?;
            }
        }
        Ok(w.len())
    }

    /// Restores state written by `save`. Rejects anything inconsistent
    /// rather than guessing.
    pub fn load(state: &[u8]) -> Result<Self, StateError> {
        let mut r = Reader::new(state);
        let bad = |_: WireError| StateError::Malformed;
        if r.raw(4).map_err(bad)? != STATE_MAGIC {
            return Err(StateError::BadMagic);
        }
        if r.u8().map_err(bad)? != STATE_VERSION {
            return Err(StateError::UnsupportedVersion);
        }
        let mut hsm = Hsm {
            serial: r.array().map_err(bad)?,
            pin_len: r.u8().map_err(bad)?,
            pin: r.array().map_err(bad)?,
            pin_tries_left: r.u8().map_err(bad)?,
            store: KeyStore::new(),
            identity: r.array().map_err(bad)?,
            admins: AdminSet::read(&mut r).map_err(bad)?,
            audit: AuditLog::read_state(&mut r).map_err(bad)?,
            admin_challenge: None,
            faulted: false,
        };
        let pin_len = hsm.pin_len as usize;
        if !(MIN_PIN..=MAX_PIN).contains(&pin_len)
            || hsm.pin[pin_len..].iter().any(|&b| b != 0)
            || hsm.pin_tries_left > MAX_PIN_TRIES
        {
            return Err(StateError::Malformed);
        }

        let next_id = r.u32().map_err(bad)?;
        let count = r.u8().map_err(bad)? as usize;
        if count > MAX_KEYS {
            return Err(StateError::Malformed);
        }
        for _ in 0..count {
            let id = r.u32().map_err(bad)?;
            let label_len = r.u8().map_err(bad)? as usize;
            let label: [u8; MAX_LABEL] = r.array().map_err(bad)?;
            let ext_len = r.u8().map_err(bad)? as usize;
            let ext_id: [u8; MAX_EXT_ID] = r.array().map_err(bad)?;
            let mut secret: [u8; SECRET_LEN] = r.array().map_err(bad)?;
            let meta = read_key_meta(&mut r, &label, label_len, &ext_id, ext_len);
            let valid = id != 0
                && id < next_id
                && label_len <= MAX_LABEL
                && ext_len <= MAX_EXT_ID
                && hsm.store.public_key(id).is_none();
            let inserted = match meta {
                Ok(meta) if valid => hsm.store.insert_with_id(id, &secret, meta).is_ok(),
                _ => false,
            };
            secret.zeroize();
            if !inserted {
                return Err(StateError::Malformed);
            }
        }
        r.finish().map_err(bad)?;
        hsm.store.set_next_id(next_id);
        Ok(hsm)
    }
}

/// Reads a key's usage and, for agent keys, its policy and counters.
fn read_key_meta<'a>(
    r: &mut Reader<'_>,
    label: &'a [u8; MAX_LABEL],
    label_len: usize,
    ext_id: &'a [u8; MAX_EXT_ID],
    ext_len: usize,
) -> Result<KeyMeta<'a>, StateError> {
    let bad = |_: WireError| StateError::Malformed;
    let label = label.get(..label_len).ok_or(StateError::Malformed)?;
    let ext_id = ext_id.get(..ext_len).ok_or(StateError::Malformed)?;
    match KeyUsage::try_from(r.u8().map_err(bad)?).map_err(bad)? {
        KeyUsage::General => Ok(KeyMeta::general(label, ext_id)),
        KeyUsage::Agent => {
            let policy = Policy::read(r).map_err(bad)?;
            let spent = r.u64().map_err(bad)?;
            let approved = r.u64().map_err(bad)?;
            let approvers = r.u8().map_err(bad)?;
            let policy_version = r.u32().map_err(bad)?;
            // Note: `spent` may exceed the budget after admins lower it.
            if policy_version == 0 {
                return Err(StateError::Malformed);
            }
            Ok(KeyMeta {
                spent,
                approved,
                policy_version,
                ..KeyMeta::agent(label, ext_id, policy, approvers)
            })
        }
    }
}

fn use_error(e: UseError) -> Status {
    match e {
        UseError::NotFound => Status::KeyNotFound,
        UseError::WrongUsage => Status::UsageNotAllowed,
    }
}

fn require_login(session: &Session) -> Result<(), Status> {
    if session.logged_in {
        Ok(())
    } else {
        Err(Status::NotLoggedIn)
    }
}
