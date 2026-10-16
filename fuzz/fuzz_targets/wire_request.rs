//! Any bytes into the request parser: it must never panic, and every request
//! it accepts must have exactly one encoding (decode, then encode, gives back
//! the same bytes). One encoding per meaning is what makes "what was checked
//! is what gets signed" hold.
#![no_main]

use libfuzzer_sys::fuzz_target;
use quorum_core::wire::{MAX_FRAME, Request};

fuzz_target!(|data: &[u8]| {
    if let Ok(req) = Request::decode(data) {
        let mut out = [0u8; MAX_FRAME];
        let n = req
            .encode(&mut out)
            .expect("an accepted request must re-encode");
        assert_eq!(&out[..n], data, "two encodings for one request: {req:?}");
    }
});
