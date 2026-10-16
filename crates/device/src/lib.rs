//! `quorum-device`: what the HSM firmware does, independent of any one chip.
//!
//! The chip-specific firmware (`firmware/rp2350`) only moves bytes: USB in,
//! USB out, flash reads and writes, random numbers. Everything else lives
//! here, so it can be tested on an ordinary computer with a simulated flash
//! chip ([`mock::MockFlash`]), including power cuts at every possible moment.
//!
//! A device starts **blank**. The first `Provision` command sets its PIN and
//! admins; the device then picks its own serial number and identity key and
//! saves its first state. From then on it is an ordinary quorum HSM, and
//! `Provision` is refused for good.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod flash;
pub mod framer;
pub mod mock;

use quorum_core::wire::{MAX_FRAME, Request, SERIAL_LEN, Status, Writer, resp};
use quorum_core::{Hsm, Provisioning, Session};
use rand_core::CryptoRngCore;

use flash::{Flash, FlashSlots, Found};

/// What the device is currently able to do.
// No heap on the chip, so the HSM is stored inline; there is only one `Mode`.
#[allow(clippy::large_enum_variant)]
enum Mode {
    /// Waiting for `Provision`.
    Blank,
    Ready(Hsm),
    /// Flash is damaged, unreadable, or the saved state did not load. Every
    /// command is refused until the device is repaired (re-flashed with a
    /// debug tool, which also wipes the keys).
    Broken,
}

/// The firmware's whole state: flash storage, the HSM, and the one host
/// session (one USB connection at a time).
pub struct Firmware<F: Flash> {
    slots: FlashSlots<F>,
    mode: Mode,
    session: Session,
}

impl<F: Flash> Firmware<F> {
    /// Boots from flash: loads the latest saved state, or starts blank on a
    /// brand-new chip.
    pub fn boot(flash: F, state_base: u32) -> Self {
        let (slots, found) = FlashSlots::open(flash, state_base);
        let mode = match found {
            Found::Blank => Mode::Blank,
            Found::State(_) => match Hsm::load(slots.state()) {
                Ok(hsm) => Mode::Ready(hsm),
                Err(_) => Mode::Broken,
            },
            Found::Damaged => Mode::Broken,
        };
        Firmware {
            slots,
            mode,
            session: Session::default(),
        }
    }

    /// `"blank"`, `"ready"` or `"broken"` (for the status LED and tests).
    pub fn mode(&self) -> &'static str {
        match self.mode {
            Mode::Blank => "blank",
            Mode::Ready(_) => "ready",
            Mode::Broken => "broken",
        }
    }

    /// The host disconnected: forget the login and pending challenges.
    pub fn end_session(&mut self) {
        self.session = Session::default();
    }

    /// Handles one request frame; writes the response into `out` (at least
    /// `MAX_FRAME` bytes) and returns its length.
    pub fn handle(&mut self, rng: &mut impl CryptoRngCore, req: &[u8], out: &mut [u8]) -> usize {
        match &mut self.mode {
            Mode::Ready(hsm) => hsm.handle(&mut self.session, &mut self.slots, rng, req, out),
            Mode::Broken => status_only(out, Status::Fault),
            Mode::Blank => match Request::decode(req) {
                Ok(Request::Provision { pin, admins }) => self.provision(rng, pin, admins, out),
                Ok(_) => status_only(out, Status::NotProvisioned),
                Err(_) => status_only(out, Status::BadRequest),
            },
        }
    }

    fn provision(
        &mut self,
        rng: &mut impl CryptoRngCore,
        pin: &[u8],
        admins: quorum_core::admin::AdminSet,
        out: &mut [u8],
    ) -> usize {
        let serial = random_serial(rng);
        let p = Provisioning {
            serial,
            pin,
            admins: admins.keys(),
            threshold: admins.threshold(),
        };
        let hsm = match Hsm::provision(p, rng, &mut self.slots) {
            Ok(hsm) => hsm,
            Err(quorum_core::hsm::InitError::Storage) => {
                // The first save failed part-way. Refuse everything rather
                // than guess (see `Found::Damaged`).
                self.mode = Mode::Broken;
                return status_only(out, Status::Fault);
            }
            Err(_) => return status_only(out, Status::BadRequest),
        };
        let reply = resp::Provisioned {
            serial,
            public: hsm.identity_public(),
        };
        self.mode = Mode::Ready(hsm);
        let mut w = Writer::new(out);
        match w.u8(Status::Ok as u8).and_then(|_| reply.encode(&mut w)) {
            Ok(()) => w.len(),
            Err(_) => status_only(out, Status::ResponseTooLarge),
        }
    }

    /// Gives the flash back (tests use this to simulate a restart).
    pub fn into_flash(self) -> F {
        self.slots.into_flash()
    }
}

fn status_only(out: &mut [u8], status: Status) -> usize {
    match out.first_mut() {
        Some(b) => {
            *b = status as u8;
            1
        }
        None => 0,
    }
}

/// 16 upper-case hex characters from the random number generator.
fn random_serial(rng: &mut impl CryptoRngCore) -> [u8; SERIAL_LEN] {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut raw = [0u8; SERIAL_LEN / 2];
    rng.fill_bytes(&mut raw);
    let mut serial = [0u8; SERIAL_LEN];
    for (i, b) in raw.iter().enumerate() {
        serial[2 * i] = HEX[(b >> 4) as usize];
        serial[2 * i + 1] = HEX[(b & 0xF) as usize];
    }
    serial
}

/// The response buffer size the firmware needs.
pub const RESPONSE_MAX: usize = MAX_FRAME;

#[cfg(test)]
mod tests;
