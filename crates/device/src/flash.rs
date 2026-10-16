//! The HSM's state on real flash memory, in two slots (A and B).
//!
//! Flash memory (NOR flash, as on the RP2350's Pico 2 board) has two rules
//! that a file does not: you must *erase* a whole sector (setting every bit
//! to 1) before writing, and writing can only turn 1s into 0s. Saving the
//! state is therefore: erase the slot not holding the latest state, write
//! the new record into it, then read it back to check. A power cut at any
//! point leaves the other slot untouched, and the half-done slot fails its
//! hash check on the next boot (see [`quorum_core::slots`]).

use quorum_core::slots::{self, HEADER_LEN, SLOT_LEN, parse_slot_at, slot_for};
use quorum_core::{Storage, StorageError};

/// Writes are padded to this size. Flash chips program 256-byte pages; the
/// padding is 0xFF, which leaves erased flash unchanged.
pub const PAGE: usize = 256;
/// The record buffer: a whole slot, rounded up to whole pages.
const BUF_LEN: usize = SLOT_LEN.div_ceil(PAGE) * PAGE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlashError {
    /// The chip reported a failure, or (in tests) the power was cut.
    Failed,
    /// What was read back is not what was written.
    VerifyFailed,
    /// The state does not fit in a slot.
    TooLarge,
}

/// The few flash operations the HSM needs. Offsets are from the start of
/// the flash chip.
pub trait Flash {
    /// Erase granularity in bytes (4096 on the RP2350's flash).
    const SECTOR: u32;
    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), FlashError>;
    /// Erases `[from, to)`; both must be sector-aligned.
    fn erase(&mut self, from: u32, to: u32) -> Result<(), FlashError>;
    /// Programs `data` at `offset` (already erased). Page-aligned.
    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), FlashError>;
}

/// The bytes one slot occupies on flash: the slot rounded up to sectors.
pub const fn slot_span(sector: u32) -> u32 {
    (SLOT_LEN as u32).div_ceil(sector) * sector
}

/// The bytes the two slots occupy together.
pub const fn region_len(sector: u32) -> u32 {
    2 * slot_span(sector)
}

/// What was found in the state area at boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Found {
    /// Both slots are erased: a brand-new device, ready to be provisioned.
    Blank,
    /// A valid saved state of this many bytes (see [`FlashSlots::state`]).
    State(usize),
    /// Something is there but neither slot is valid. The device refuses to
    /// work and refuses to be provisioned again: damage must never be a way
    /// to reset the HSM (and its keys, PIN tries and counters).
    Damaged,
}

/// Two-slot storage on flash, starting at `base`.
pub struct FlashSlots<F: Flash> {
    flash: F,
    base: u32,
    /// Sequence number of the latest valid save (0: none yet).
    seq: u64,
    /// One slot's worth of bytes: what was loaded at boot, then scratch
    /// space for each save.
    buf: [u8; BUF_LEN],
    loaded: usize,
}

impl<F: Flash> FlashSlots<F> {
    /// Reads both slots and keeps the latest valid one. Unreadable flash
    /// counts as damaged.
    pub fn open(flash: F, base: u32) -> (Self, Found) {
        let mut s = FlashSlots {
            flash,
            base,
            seq: 0,
            buf: [0xFF; BUF_LEN],
            loaded: 0,
        };
        let found = s.scan().unwrap_or(Found::Damaged);
        if found == Found::Damaged {
            s.seq = 0;
            s.loaded = 0;
        }
        (s, found)
    }

    fn scan(&mut self) -> Result<Found, FlashError> {
        let s = self;
        let mut best: Option<(usize, u64)> = None;
        let mut erased = true;
        for index in 0..2 {
            s.read_slot(index)?;
            erased &= s.buf.iter().all(|&b| b == 0xFF);
            if let Some((seq, _)) = parse_slot_at(index, &s.buf)
                && best.is_none_or(|(_, b)| seq > b)
            {
                best = Some((index, seq));
            }
        }
        let found = match best {
            Some((index, seq)) => {
                s.read_slot(index)?;
                let (_, state) = parse_slot_at(index, &s.buf).ok_or(FlashError::VerifyFailed)?;
                s.loaded = state.len();
                s.seq = seq;
                Found::State(s.loaded)
            }
            None if erased => Found::Blank,
            None => Found::Damaged,
        };
        Ok(found)
    }

    /// The state found by [`open`](Self::open), before any new save.
    pub fn state(&self) -> &[u8] {
        &self.buf[HEADER_LEN..HEADER_LEN + self.loaded]
    }

    /// Sequence number of the latest save.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Gives the flash back (used by tests to "reboot").
    pub fn into_flash(self) -> F {
        self.flash
    }

    fn slot_offset(&self, index: usize) -> u32 {
        self.base + index as u32 * slot_span(F::SECTOR)
    }

    fn read_slot(&mut self, index: usize) -> Result<(), FlashError> {
        let offset = self.slot_offset(index);
        self.flash.read(offset, &mut self.buf)
    }

    /// Saves `state` as the next save: erase, write, read back and check.
    pub fn save(&mut self, state: &[u8]) -> Result<(), FlashError> {
        let seq = self.seq + 1;
        let header = slots::header(seq, state).ok_or(FlashError::TooLarge)?;
        let index = slot_for(seq);
        let offset = self.slot_offset(index);
        let len = (HEADER_LEN + state.len()).div_ceil(PAGE) * PAGE;

        self.loaded = 0;
        self.buf.fill(0xFF);
        self.buf[..HEADER_LEN].copy_from_slice(&header);
        self.buf[HEADER_LEN..HEADER_LEN + state.len()].copy_from_slice(state);

        self.flash.erase(offset, offset + slot_span(F::SECTOR))?;
        self.flash.write(offset, &self.buf[..len])?;

        // Read back: a weak or worn-out flash cell must not go unnoticed.
        self.buf.fill(0);
        self.flash.read(offset, &mut self.buf[..len])?;
        match parse_slot_at(index, &self.buf[..len]) {
            Some((s, saved)) if s == seq && saved == state => {
                self.seq = seq;
                Ok(())
            }
            _ => Err(FlashError::VerifyFailed),
        }
    }
}

impl<F: Flash> Storage for FlashSlots<F> {
    fn commit(&mut self, state: &[u8]) -> Result<(), StorageError> {
        self.save(state).map_err(|_| StorageError)
    }
}
