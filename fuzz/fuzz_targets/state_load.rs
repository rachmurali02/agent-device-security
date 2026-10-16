//! Any bytes as saved HSM state: loading must never panic, and any state it
//! accepts must save back to exactly the same bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use quorum_core::Hsm;
use quorum_core::hsm::STATE_MAX;

fuzz_target!(|data: &[u8]| {
    if let Ok(hsm) = Hsm::load(data) {
        let mut out = vec![0u8; STATE_MAX];
        let n = hsm.save(&mut out).expect("a loaded state must save");
        assert_eq!(&out[..n], data, "state did not round-trip");
    }
});
