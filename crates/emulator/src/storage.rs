//! Where the HSM's state lives between restarts (the emulator's "flash").
//!
//! Two implementations, both all-or-nothing (after a crash you get either the
//! old state or the new one, never a mix):
//!
//! - [`SlotStorage`] (default): two fixed-size slots in one file, written
//!   alternately in place. One wait for the disk per save.
//! - [`RenameStorage`] (previous design, kept for comparison): rewrite the
//!   whole state to a temporary file and rename it over the old one. Two
//!   waits for the disk per save (the file, then the folder).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use quorum_core::audit::digest;
use quorum_core::hsm::STATE_MAX;
use quorum_core::{Storage, StorageError};

const SLOT_MAGIC: &[u8; 4] = b"QSLT";
/// magic, sequence number, length, SHA-256 of (magic, sequence, length, state)
const HEADER_LEN: usize = 4 + 8 + 4 + 32;
/// Every slot has room for the largest possible state.
pub const SLOT_LEN: usize = HEADER_LEN + STATE_MAX;
/// The whole file: two slots. Its size never changes after creation.
pub const SLOT_FILE_LEN: u64 = 2 * SLOT_LEN as u64;

/// Two-slot ("A/B") storage, the way secure-chip firmware commonly keeps
/// state in flash.
///
/// Each save goes to the slot *not* holding the latest state, stamped with
/// the next sequence number and a hash, and then waits for the disk once.
/// Because the file is preallocated and never changes size, that wait does
/// not have to flush any file-system bookkeeping either. If power is lost
/// mid-save, the half-written slot fails its hash check on restart and the
/// other slot, the previous state, is used.
pub struct SlotStorage {
    file: File,
    /// Sequence number of the latest valid save.
    seq: u64,
    /// Wait for the disk to confirm every write. Turning this off is only
    /// for measuring what durability costs: a power cut could then lose a
    /// counter update, which is exactly what the HSM must never allow.
    pub sync: bool,
}

impl SlotStorage {
    /// Creates a fresh slot file (at the factory), replacing any old one.
    /// Both slots are written out in full now so that later saves only ever
    /// overwrite existing blocks.
    pub fn create(path: &Path) -> io::Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(&vec![0u8; SLOT_FILE_LEN as usize])?;
        file.sync_all()?;
        sync_dir(path)?;
        Ok(SlotStorage {
            file,
            seq: 0,
            sync: true,
        })
    }

    /// Opens a slot file and returns the latest valid state in it.
    pub fn open(path: &Path) -> io::Result<(Self, Vec<u8>)> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let mut data = vec![0u8; SLOT_FILE_LEN as usize];
        let len = file.metadata()?.len();
        if len != SLOT_FILE_LEN {
            return Err(invalid(format!(
                "{} is not an HSM slot file ({len} bytes, expected {SLOT_FILE_LEN})",
                path.display()
            )));
        }
        file.read_exact_at(&mut data, 0)?;
        let (seq, state) = latest_slot(&data)
            .ok_or_else(|| invalid(format!("{}: no valid saved state", path.display())))?;
        let state = state.to_vec();
        Ok((
            SlotStorage {
                file,
                seq,
                sync: true,
            },
            state,
        ))
    }

    /// The bytes one save writes: header plus state.
    fn record(seq: u64, state: &[u8]) -> Vec<u8> {
        let len = (state.len() as u32).to_le_bytes();
        let seq_bytes = seq.to_le_bytes();
        let hash = digest(&[SLOT_MAGIC, &seq_bytes, &len, state]);
        let mut out = Vec::with_capacity(HEADER_LEN + state.len());
        out.extend_from_slice(SLOT_MAGIC);
        out.extend_from_slice(&seq_bytes);
        out.extend_from_slice(&len);
        out.extend_from_slice(&hash);
        out.extend_from_slice(state);
        out
    }

    fn write_slot(&mut self, state: &[u8]) -> io::Result<()> {
        if state.len() > STATE_MAX {
            return Err(invalid("state larger than a slot".into()));
        }
        let seq = self.seq + 1;
        let offset = (seq % 2) * SLOT_LEN as u64;
        self.file.write_all_at(&Self::record(seq, state), offset)?;
        if self.sync {
            // Data only: the file's size and blocks never change.
            self.file.sync_data()?;
        }
        self.seq = seq;
        Ok(())
    }
}

impl Storage for SlotStorage {
    fn commit(&mut self, state: &[u8]) -> Result<(), StorageError> {
        self.write_slot(state).map_err(|e| {
            eprintln!("storage: commit failed: {e}");
            StorageError
        })
    }
}

/// Parses one slot; `None` if it is empty, torn or corrupted.
fn parse_slot(slot: &[u8]) -> Option<(u64, &[u8])> {
    if slot.get(..4)? != SLOT_MAGIC {
        return None;
    }
    let seq = u64::from_le_bytes(slot.get(4..12)?.try_into().ok()?);
    let len_bytes: [u8; 4] = slot.get(12..16)?.try_into().ok()?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    let hash = slot.get(16..HEADER_LEN)?;
    let state = slot.get(HEADER_LEN..HEADER_LEN.checked_add(len)?)?;
    if len > STATE_MAX || seq == 0 {
        return None;
    }
    let expected = digest(&[SLOT_MAGIC, &seq.to_le_bytes(), &len_bytes, state]);
    (hash == expected).then_some((seq, state))
}

/// The valid slot with the highest sequence number.
fn latest_slot(file: &[u8]) -> Option<(u64, &[u8])> {
    file.chunks(SLOT_LEN)
        .filter_map(parse_slot)
        .max_by_key(|(seq, _)| *seq)
}

fn invalid(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn sync_dir(path: &Path) -> io::Result<()> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    File::open(dir.unwrap_or(Path::new(".")))?.sync_all()
}

/// The previous design, kept so the benchmark can compare: write the whole
/// state to a temporary file, wait for the disk, rename it over the old
/// file, then wait for the disk again so the rename itself is saved.
pub struct RenameStorage {
    pub path: PathBuf,
    /// See [`SlotStorage::sync`].
    pub sync: bool,
}

impl RenameStorage {
    pub fn new(path: PathBuf) -> Self {
        RenameStorage { path, sync: true }
    }

    fn write_atomic(&self, state: &[u8]) -> io::Result<()> {
        let tmp = self.path.with_extension("tmp");
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(state)?;
        if self.sync {
            f.sync_all()?;
        }
        fs::rename(&tmp, &self.path)?;
        if self.sync {
            sync_dir(&self.path)?;
        }
        Ok(())
    }
}

impl Storage for RenameStorage {
    fn commit(&mut self, state: &[u8]) -> Result<(), StorageError> {
        self.write_atomic(state).map_err(|e| {
            eprintln!("storage: commit failed: {e}");
            StorageError
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("quorum-slots-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir.join("hsm.state")
    }

    #[test]
    fn the_latest_save_wins_and_the_file_never_changes_size() {
        let path = temp("latest");
        let mut s = SlotStorage::create(&path).unwrap();
        for i in 1..=5u8 {
            s.commit(&vec![i; 100 + i as usize]).unwrap();
            assert_eq!(fs::metadata(&path).unwrap().len(), SLOT_FILE_LEN);
        }
        let (s2, state) = SlotStorage::open(&path).unwrap();
        assert_eq!(state, vec![5u8; 105]);
        assert_eq!(s2.seq, 5);
    }

    #[test]
    fn a_fresh_file_has_no_state_yet() {
        let path = temp("fresh");
        SlotStorage::create(&path).unwrap();
        assert!(SlotStorage::open(&path).is_err());
    }

    #[test]
    fn a_save_cut_off_at_any_byte_leaves_the_previous_state() {
        // Simulate power loss partway through writing the newest slot: for
        // every possible cut-off point, restarting must give the old state
        // or (only if the write completed) the new one, never anything else.
        let path = temp("torn");
        let old = vec![0xAA; 300];
        let new = vec![0xBB; 280];
        let mut s = SlotStorage::create(&path).unwrap();
        s.commit(b"first").unwrap();
        s.commit(&old).unwrap();
        let clean = fs::read(&path).unwrap();
        let record = SlotStorage::record(3, &new);
        // Save #3 goes to slot 3 % 2 = 1.
        let offset = SLOT_LEN;
        for cut in 0..=record.len() {
            let mut image = clean.clone();
            image[offset..offset + cut].copy_from_slice(&record[..cut]);
            let (_, state) = latest_slot(&image).expect("some state must survive");
            if cut == record.len() {
                assert_eq!(state, &new[..]);
            } else {
                assert_eq!(state, &old[..], "cut at byte {cut}");
            }
        }
    }

    #[test]
    fn flipped_bits_in_the_newest_slot_fall_back_to_the_other_one() {
        let path = temp("bitflip");
        let mut s = SlotStorage::create(&path).unwrap();
        s.commit(b"older").unwrap();
        s.commit(b"newer").unwrap();
        let mut image = fs::read(&path).unwrap();
        // The newest save (sequence 2) lives in slot 0.
        image[HEADER_LEN + 2] ^= 0x01;
        assert_eq!(latest_slot(&image).unwrap().1, b"older");
        // Damage both and nothing is trusted.
        image[SLOT_LEN + HEADER_LEN] ^= 0x01;
        assert!(latest_slot(&image).is_none());
    }

    #[test]
    fn oversized_states_are_refused() {
        let path = temp("big");
        let mut s = SlotStorage::create(&path).unwrap();
        assert!(s.commit(&vec![0; STATE_MAX + 1]).is_err());
    }
}
