//! Any bytes as the emulator's two-slot state file (e.g. after a crash or
//! disk corruption): finding the latest valid slot must never panic, and
//! whatever it returns must fit in a slot.
#![no_main]

use libfuzzer_sys::fuzz_target;
use quorum_core::hsm::STATE_MAX;

fuzz_target!(|data: &[u8]| {
    if let Some((seq, state)) = quorum_emulator::latest_slot(data) {
        assert!(seq > 0);
        assert!(state.len() <= STATE_MAX);
    }
});
