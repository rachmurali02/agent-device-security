//! Any bytes into everything a receiver, admin or auditor parses: signed
//! statements, birth certificates, proposals, audit entries and checkpoints,
//! and the HSM's replies. Nothing may panic, and whatever parses must
//! re-encode to the same bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use quorum_core::admin::{MAX_PROPOSAL, Proposal};
use quorum_core::agent::{MAX_STATEMENT, Statement, verify_statement};
use quorum_core::audit::{Checkpoint, ENTRY_LEN, Entry, verify_log};
use quorum_core::cert::{KEYCERT_LEN, KeyCert, verify_action, verify_key_cert};
use quorum_core::wire::{Writer, resp};

fuzz_target!(|data: &[u8]| {
    let key = [0x42; 32];
    let sig = [0u8; 64];

    if let Ok(s) = Statement::decode(data) {
        let mut out = [0u8; MAX_STATEMENT];
        let mut w = Writer::new(&mut out);
        s.write(&mut w).expect("re-encode statement");
        let n = w.len();
        assert_eq!(&out[..n], data);
    }
    if let Ok(c) = KeyCert::decode(data) {
        let mut out = [0u8; KEYCERT_LEN];
        let n = c.encode(&mut out).expect("re-encode certificate");
        assert_eq!(&out[..n], data);
    }
    if let Ok(p) = Proposal::decode(data) {
        let mut out = [0u8; MAX_PROPOSAL];
        let n = p.encode(&mut out).expect("re-encode proposal");
        assert_eq!(&out[..n], data);
    }
    if let Ok(e) = Entry::decode(data) {
        assert_eq!(&e.encode()[..], data);
    }
    if let Ok(c) = Checkpoint::decode(data) {
        assert_eq!(&c.encode()[..], data);
    }

    // Signature checks on garbage must fail cleanly, never panic.
    let _ = verify_statement(&key, data, &sig);
    let _ = verify_key_cert(&key, data, &sig);
    let half = data.len() / 2;
    let _ = verify_action(&key, &data[..half], &sig, &data[half..], &sig);
    let entries: Vec<[u8; ENTRY_LEN]> = data.as_chunks::<ENTRY_LEN>().0.to_vec();
    let _ = verify_log(&key, data, &sig, &entries);

    // Replies from a possibly malicious HSM or socket.
    let _ = resp::split(data);
    let _ = resp::Info::decode(data);
    let _ = resp::Generated::decode(data);
    if let Ok(list) = resp::decode_key_list(data) {
        for _ in list {}
    }
    let _ = resp::decode_signature(data);
    let _ = resp::decode_signed_action(data);
    let _ = resp::KeyPolicy::decode(data);
    let _ = resp::decode_challenge(data);
    let _ = resp::Identity::decode(data);
    let _ = resp::decode_cert(data);
    let _ = resp::AgentKeyCreated::decode(data);
    if let Ok(b) = resp::AuditBatch::decode(data) {
        for _ in b.entries() {}
    }
    let _ = resp::decode_checkpoint(data);
});
