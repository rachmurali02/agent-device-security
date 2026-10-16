//! The format of a saved state on "flash": two slots, A and B.
//!
//! Each save goes to the slot that does *not* hold the latest state, stamped
//! with the next sequence number and a hash. If power is lost mid-save, the
//! half-written slot fails its hash check and the other slot (the previous
//! state) is used. The emulator (a file) and the firmware (real flash) both
//! use this module, so they share one tested format.
//!
//! Slot layout: `magic (4) | sequence (8) | state length (4) | SHA-256 (32) |
//! state`. The hash covers everything before it plus the state.

use crate::audit::digest;
use crate::hsm::STATE_MAX;

pub const SLOT_MAGIC: &[u8; 4] = b"QSLT";
/// magic, sequence number, length, SHA-256 of (magic, sequence, length, state)
pub const HEADER_LEN: usize = 4 + 8 + 4 + 32;
/// Every slot has room for the largest possible state.
pub const SLOT_LEN: usize = HEADER_LEN + STATE_MAX;

/// The header for saving `state` as save number `seq`. `None` if the state
/// is too large for a slot.
pub fn header(seq: u64, state: &[u8]) -> Option<[u8; HEADER_LEN]> {
    if state.len() > STATE_MAX || seq == 0 {
        return None;
    }
    let len = (state.len() as u32).to_le_bytes();
    let seq_bytes = seq.to_le_bytes();
    let hash = digest(&[SLOT_MAGIC, &seq_bytes, &len, state]);
    let mut out = [0u8; HEADER_LEN];
    out[..4].copy_from_slice(SLOT_MAGIC);
    out[4..12].copy_from_slice(&seq_bytes);
    out[12..16].copy_from_slice(&len);
    out[16..].copy_from_slice(&hash);
    Some(out)
}

/// Which slot (0 or 1) save number `seq` belongs in. Saves alternate, so
/// the next save never overwrites the latest one.
pub fn slot_for(seq: u64) -> usize {
    (seq % 2) as usize
}

/// Parses one slot (which may be longer than the record, e.g. a whole flash
/// sector). `None` if it is empty, torn or corrupted.
pub fn parse_slot(slot: &[u8]) -> Option<(u64, &[u8])> {
    if slot.get(..4)? != SLOT_MAGIC {
        return None;
    }
    let seq = u64::from_le_bytes(slot.get(4..12)?.try_into().ok()?);
    let len_bytes: [u8; 4] = slot.get(12..16)?.try_into().ok()?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len > STATE_MAX || seq == 0 {
        return None;
    }
    let hash = slot.get(16..HEADER_LEN)?;
    let state = slot.get(HEADER_LEN..HEADER_LEN + len)?;
    let expected = digest(&[SLOT_MAGIC, &seq.to_le_bytes(), &len_bytes, state]);
    (hash == expected).then_some((seq, state))
}

/// Parses slot number `index`, which must hold a save that belongs there.
/// A save found in the wrong slot is not trusted: writing the next save
/// would then overwrite it.
pub fn parse_slot_at(index: usize, slot: &[u8]) -> Option<(u64, &[u8])> {
    parse_slot(slot).filter(|(seq, _)| slot_for(*seq) == index)
}

/// The valid slot with the highest sequence number, from a file image of
/// two `SLOT_LEN` slots.
pub fn latest_slot(image: &[u8]) -> Option<(u64, &[u8])> {
    image
        .chunks(SLOT_LEN)
        .take(2)
        .enumerate()
        .filter_map(|(i, s)| parse_slot_at(i, s))
        .max_by_key(|(seq, _)| *seq)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(saves: &[(usize, u64, &[u8])]) -> [u8; 2 * SLOT_LEN] {
        let mut img = [0xFF; 2 * SLOT_LEN];
        for &(index, seq, state) in saves {
            let at = index * SLOT_LEN;
            img[at..at + HEADER_LEN].copy_from_slice(&header(seq, state).unwrap());
            img[at + HEADER_LEN..at + HEADER_LEN + state.len()].copy_from_slice(state);
        }
        img
    }

    #[test]
    fn the_newest_save_in_its_own_slot_wins() {
        let img = image(&[(1, 3, b"three"), (0, 4, b"four")]);
        assert_eq!(latest_slot(&img), Some((4, &b"four"[..])));
    }

    #[test]
    fn a_save_in_the_wrong_slot_is_not_trusted() {
        // Save 4 belongs in slot 0. Found in slot 1, the next save (5) would
        // overwrite it, so it must not be used.
        let img = image(&[(1, 4, b"four")]);
        assert_eq!(latest_slot(&img), None);
        let img = image(&[(0, 2, b"two"), (1, 4, b"four")]);
        assert_eq!(latest_slot(&img), Some((2, &b"two"[..])));
    }

    #[test]
    fn save_number_zero_and_oversized_states_are_refused() {
        assert!(header(0, b"x").is_none());
        assert!(header(1, &[0; STATE_MAX + 1]).is_none());
    }
}
