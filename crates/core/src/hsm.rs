//! The HSM command processor: the code that runs inside the trust boundary.
//!
//! The host sends request frames; `Hsm::handle` decides whether to honour
//! them and writes a response frame. Every security decision (is the caller
//! logged in, is the PIN right, does the key exist) is made here, never in
//! the host library.

use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::keystore::{KeyStore, MAX_KEYS, SECRET_LEN};
use crate::wire::{
    MAX_EXT_ID, MAX_LABEL, MAX_PIN, MIN_PIN, Reader, Request, SERIAL_LEN, Status, WireError,
    Writer, resp,
};

pub const FW_VERSION: (u8, u8) = (0, 1);
pub const MAX_PIN_TRIES: u8 = 5;

const STATE_MAGIC: &[u8; 4] = b"QHSM";
const STATE_VERSION: u8 = 1;
const SLOT_STATE_LEN: usize = 4 + 1 + MAX_LABEL + 1 + MAX_EXT_ID + SECRET_LEN;
/// Upper bound on the serialized state size.
pub const STATE_MAX: usize =
    4 + 1 + SERIAL_LEN + 1 + MAX_PIN + 1 + 4 + 1 + MAX_KEYS * SLOT_STATE_LEN;

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
    Storage,
}

/// Per-connection state. On real hardware this lives in the HSM's RAM, keyed
/// by the host session; it is never trusted from the host.
#[derive(Debug, Default)]
pub struct Session {
    logged_in: bool,
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
    /// Set when storage fails. A faulted HSM refuses every command (fail
    /// closed) until it restarts and reloads its last committed state.
    #[zeroize(skip)]
    faulted: bool,
}

impl Hsm {
    /// Factory provisioning: create a fresh HSM and commit its first state.
    pub fn provision(
        serial: [u8; SERIAL_LEN],
        pin: &[u8],
        storage: &mut impl Storage,
    ) -> Result<Self, InitError> {
        if !(MIN_PIN..=MAX_PIN).contains(&pin.len()) {
            return Err(InitError::BadPinLength);
        }
        let mut hsm = Hsm {
            serial,
            pin: [0; MAX_PIN],
            pin_len: pin.len() as u8,
            pin_tries_left: MAX_PIN_TRIES,
            store: KeyStore::new(),
            faulted: false,
        };
        hsm.pin[..pin.len()].copy_from_slice(pin);
        hsm.commit(storage).map_err(|_| InitError::Storage)?;
        Ok(hsm)
    }

    pub fn serial(&self) -> &[u8; SERIAL_LEN] {
        &self.serial
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
                session.logged_in = false;
                Ok(())
            }

            Request::GenerateKey { label, ext_id } => {
                require_login(session)?;
                let (id, public) = self
                    .store
                    .generate(rng, label, ext_id)
                    .map_err(|_| Status::StoreFull)?;
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
                    }
                    .encode(w)
                    .map_err(overflow)?;
                }
                Ok(())
            }

            Request::Sign { key, msg } => {
                require_login(session)?;
                let sig = self.store.sign(key, msg).ok_or(Status::KeyNotFound)?;
                w.raw(&sig).map_err(overflow)
            }

            Request::DeleteKey { key } => {
                require_login(session)?;
                if !self.store.delete(key) {
                    return Err(Status::KeyNotFound);
                }
                self.commit(storage)
            }
        }
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

        // Spend the attempt and make that durable *before* comparing. If an
        // attacker cuts power the moment they detect a wrong guess (timing,
        // power trace), the attempt has already been counted. Comparing first
        // would give unlimited guesses.
        self.pin_tries_left -= 1;
        self.commit(storage)?;

        if self.pin_matches(pin) {
            self.pin_tries_left = MAX_PIN_TRIES;
            self.commit(storage)?;
            session.logged_in = true;
            Ok(())
        } else if self.pin_tries_left == 0 {
            Err(Status::PinLocked)
        } else {
            Err(Status::PinIncorrect)
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
        w.u32(self.store.next_id())?;
        w.u8(self.store.len() as u8)?;
        for slot in self.store.slots() {
            w.u32(slot.id)?;
            w.u8(slot.label_len)?;
            w.raw(&slot.label)?;
            w.u8(slot.ext_id_len)?;
            w.raw(&slot.ext_id)?;
            w.raw(&slot.secret)?;
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
            let valid = id != 0
                && id < next_id
                && label_len <= MAX_LABEL
                && ext_len <= MAX_EXT_ID
                && hsm.store.public_key(id).is_none();
            let inserted = valid
                && hsm
                    .store
                    .insert_with_id(id, &secret, &label[..label_len], &ext_id[..ext_len])
                    .is_ok();
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

fn require_login(session: &Session) -> Result<(), Status> {
    if session.logged_in {
        Ok(())
    } else {
        Err(Status::NotLoggedIn)
    }
}
