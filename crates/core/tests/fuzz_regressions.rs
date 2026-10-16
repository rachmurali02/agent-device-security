//! Inputs the fuzzer once found problems with, kept so they stay fixed.
//! Each file in `tests/fuzz-regressions/` is named `<target>-<what>.bin`.

use quorum_core::Hsm;
use quorum_core::hsm::STATE_MAX;
use quorum_core::wire::{MAX_FRAME, Request};

fn regressions(target: &str) -> Vec<(String, Vec<u8>)> {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fuzz-regressions");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if name.starts_with(&format!("{target}-")) {
            out.push((name, std::fs::read(&path).unwrap()));
        }
    }
    out
}

/// Loaded states must save back to the same bytes (no hidden junk).
#[test]
fn state_load() {
    let cases = regressions("state_load");
    assert!(!cases.is_empty());
    for (name, data) in cases {
        if let Ok(hsm) = Hsm::load(&data) {
            let mut out = vec![0u8; STATE_MAX];
            let n = hsm.save(&mut out).unwrap();
            assert_eq!(&out[..n], &data[..], "{name}");
        }
    }
}

/// Accepted requests must re-encode to the same bytes.
#[test]
fn wire_request() {
    for (name, data) in regressions("wire_request") {
        if let Ok(req) = Request::decode(&data) {
            let mut out = [0u8; MAX_FRAME];
            let n = req.encode(&mut out).unwrap();
            assert_eq!(&out[..n], &data[..], "{name}");
        }
    }
}
