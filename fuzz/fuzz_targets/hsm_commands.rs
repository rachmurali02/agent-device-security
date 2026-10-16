//! Drives the whole HSM with fuzzer-chosen sequences of commands: valid
//! ones, nearly valid ones (wrong PIN, missing or forged approvals, tampered
//! confirmations) and raw garbage. After every step it checks rules that
//! must always hold:
//!
//! - the HSM never panics and every reply is well-formed;
//! - every approved agent action obeys the key's rules as read just before
//!   (kind, cap, budget, receiver's code, user confirmation), carries a valid
//!   signature and the next sequence number;
//! - the saved state always reloads, and saves back to the same bytes;
//! - the audit log, copied out as it goes, always verifies against a fresh
//!   HSM-signed checkpoint.
#![no_main]

use std::collections::HashMap;

use ed25519_dalek::{Signer, SigningKey};
use libfuzzer_sys::fuzz_target;
use quorum_core::admin::{AdminOp, AdminSet, Approvals, MAX_PROPOSAL, Proposal};
use quorum_core::agent::{
    Action, ActionKind, CONFIRM_MESSAGE_MAX, Policy, Statement, confirmation_message,
    verify_statement,
};
use quorum_core::audit::{ENTRY_LEN, verify_log};
use quorum_core::hsm::STATE_MAX;
use quorum_core::wire::{KeyUsage, MAX_FRAME, Request, Status, resp};
use quorum_core::{Hsm, Provisioning, Session, Storage, StorageError};
use rand_core::{CryptoRng, RngCore};

const PIN: &[u8] = b"123456";

/// Deterministic randomness so every input replays exactly. Fuzzing only.
struct Rng(u64);
impl RngCore for Rng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl CryptoRng for Rng {}

#[derive(Default)]
struct Mem(Vec<u8>);
impl Storage for Mem {
    fn commit(&mut self, state: &[u8]) -> Result<(), StorageError> {
        self.0 = state.to_vec();
        Ok(())
    }
}

/// Everyone who could ever be an admin, by fuzzer index.
fn pool() -> [SigningKey; 4] {
    [101, 102, 103, 104].map(|b| SigningKey::from_bytes(&[b; 32]))
}

fn phone() -> SigningKey {
    SigningKey::from_bytes(&[105; 32])
}

/// Reads fuzzer bytes as choices; returns zeros once exhausted.
struct Input<'a> {
    d: &'a [u8],
    i: usize,
}

impl<'a> Input<'a> {
    fn done(&self) -> bool {
        self.i >= self.d.len()
    }
    fn u8(&mut self) -> u8 {
        let b = self.d.get(self.i).copied().unwrap_or(0);
        self.i += 1;
        b
    }
    fn u16(&mut self) -> u16 {
        u16::from_le_bytes([self.u8(), self.u8()])
    }
    fn bytes(&mut self, max: usize) -> &'a [u8] {
        let n = (self.u8() as usize).min(max);
        let start = self.i.min(self.d.len());
        let end = (start + n).min(self.d.len());
        self.i = start + n;
        &self.d[start..end]
    }
}

struct World {
    hsm: Hsm,
    sess: Session,
    mem: Mem,
    rng: Rng,
    serial: [u8; 16],
    identity: [u8; 32],
    /// Indices into `pool()` of the current admins, in order.
    admins: Vec<usize>,
    /// Agent key id -> public key.
    agents: HashMap<u32, [u8; 32]>,
    general: Vec<u32>,
    /// The complete audit log, copied out as we go.
    log: Vec<[u8; ENTRY_LEN]>,
}

impl World {
    fn new() -> Self {
        let mut mem = Mem::default();
        let mut rng = Rng(1);
        let keys: Vec<[u8; 32]> = pool()[..3]
            .iter()
            .map(|k| k.verifying_key().to_bytes())
            .collect();
        let hsm = Hsm::provision(
            Provisioning {
                serial: *b"FUZZ000000000001",
                pin: PIN,
                admins: &keys,
                threshold: 2,
            },
            &mut rng,
            &mut mem,
        )
        .unwrap();
        let identity = hsm.identity_public();
        World {
            hsm,
            sess: Session::default(),
            mem,
            rng,
            serial: *b"FUZZ000000000001",
            identity,
            admins: vec![0, 1, 2],
            agents: HashMap::new(),
            general: Vec::new(),
            log: Vec::new(),
        }
    }

    /// Sends one frame and checks the always-true rules.
    fn raw(&mut self, frame: &[u8]) -> (Status, Vec<u8>) {
        let mut out = [0u8; MAX_FRAME];
        let n = self.hsm.handle(
            &mut self.sess,
            &mut self.mem,
            &mut self.rng,
            frame,
            &mut out,
        );
        let (status, payload) = resp::split(&out[..n]).expect("malformed reply");
        assert!(
            !self.hsm.is_faulted(),
            "faulted without any storage failure"
        );
        // Saved state always reloads and re-saves identically.
        let reloaded = Hsm::load(&self.mem.0).expect("saved state doesn't reload");
        let mut again = vec![0u8; STATE_MAX];
        let m = reloaded.save(&mut again).unwrap();
        assert_eq!(&again[..m], &self.mem.0[..], "state isn't canonical");
        (status, payload.to_vec())
    }

    fn call(&mut self, req: Request<'_>) -> Option<(Status, Vec<u8>)> {
        let mut frame = [0u8; MAX_FRAME];
        // Requests the client-side encoder refuses (invalid rules) are skipped.
        let n = req.encode(&mut frame).ok()?;
        Some(self.raw(&frame[..n]))
    }

    /// Copies out every new audit entry (before anything can release it).
    fn collect(&mut self) {
        let from = self.log.len() as u64 + 1;
        let (st, p) = self.call(Request::ReadAudit { from }).unwrap();
        assert_eq!(st, Status::Ok);
        let batch = resp::AuditBatch::decode(&p).expect("bad audit batch");
        let before = self.log.len();
        self.log.extend(batch.entries().copied());
        assert_eq!(
            self.log.len() as u64,
            batch.last_seq,
            "audit entries went missing"
        );
        if self.log.len() > before {
            let (st, _) = self
                .call(Request::AckAudit {
                    upto: batch.last_seq,
                })
                .unwrap();
            assert_eq!(st, Status::Ok);
        }
    }

    fn verify_log_now(&mut self) {
        self.collect();
        let (st, p) = self.call(Request::AuditCheckpoint).unwrap();
        assert_eq!(st, Status::Ok);
        let (cp, sig) = resp::decode_checkpoint(&p).unwrap();
        let checked = verify_log(&self.identity, cp, &sig, &self.log).expect("audit log broken");
        assert_eq!(checked.seq, self.log.len() as u64);
    }

    fn pick(&self, keys: &[u32], b: u8) -> u32 {
        if keys.is_empty() || b == 255 {
            // Sometimes a key that doesn't exist.
            return b as u32;
        }
        keys[b as usize % keys.len()]
    }

    fn agent_ids(&self) -> Vec<u32> {
        let mut v: Vec<u32> = self.agents.keys().copied().collect();
        v.sort();
        v
    }

    /// Admin approvals chosen by the fuzzer: which current admins sign,
    /// and whether one signature is tampered with or covers another op.
    fn approvals(&mut self, inp: &mut Input<'_>, op: &AdminOp<'_>) -> Option<Approvals> {
        let (st, p) = self.call(Request::GetAdminChallenge)?;
        if st != Status::Ok {
            return Some(Approvals::default());
        }
        let challenge = resp::decode_challenge(&p).unwrap();
        let mask = inp.u8();
        let tamper = inp.u8();
        let mut buf = [0u8; MAX_PROPOSAL];
        let n = Proposal {
            serial: self.serial,
            challenge,
            op: *op,
        }
        .encode(&mut buf)
        .ok()?;
        if tamper % 8 == 1 {
            buf[n - 1] ^= 1; // signs a slightly different operation
        }
        let pool = pool();
        let mut a = Approvals::default();
        for (i, &who) in self.admins.iter().enumerate() {
            if mask & (1 << i) != 0 {
                let mut sig = pool[who].sign(&buf[..n]).to_bytes();
                if tamper % 8 == 2 && i == 0 {
                    sig[5] ^= 0x80;
                }
                a.push(i as u8, sig).ok()?;
            }
        }
        if tamper % 8 == 3 {
            // An outsider claims a slot.
            let _ = a.push(3, pool[3].sign(&buf[..n]).to_bytes());
        }
        Some(a)
    }

    fn policy(inp: &mut Input<'_>) -> Policy {
        Policy {
            allowed: (inp.u8() as u16 & 0x3f) << 1 | ActionKind::Payment.bit(),
            max_amount: inp.u16() as u64,
            budget: inp.u16() as u64 * 4,
            confirm_above: inp.u16() as u64,
            always_confirm: (inp.u8() as u16 & 0x3f) << 1 & !ActionKind::Payment.bit(),
            confirmer: (inp.u8() & 1 == 0).then(|| phone().verifying_key().to_bytes()),
            require_nonce: inp.u8() & 1 == 1,
        }
    }

    fn step(&mut self, inp: &mut Input<'_>) {
        match inp.u8() % 20 {
            0 => {
                self.call(Request::GetInfo);
            }
            1 => {
                self.call(Request::Login { pin: PIN });
            }
            2 => {
                let pin = inp.bytes(40);
                self.call(Request::Login { pin });
            }
            3 => {
                self.call(Request::Logout);
            }
            4 => {
                let label = inp.bytes(40);
                if let Some((Status::Ok, p)) =
                    self.call(Request::GenerateKey { label, ext_id: b"" })
                {
                    self.general.push(resp::Generated::decode(&p).unwrap().key);
                }
            }
            5 => {
                if let Some((Status::Ok, p)) = self.call(Request::ListKeys) {
                    for e in resp::decode_key_list(&p).unwrap() {
                        if e.usage == KeyUsage::Agent {
                            assert_eq!(self.agents.get(&e.key), Some(&e.public));
                        }
                    }
                }
            }
            6 => {
                let mut all = self.general.clone();
                all.extend(self.agent_ids());
                let key = self.pick(&all, inp.u8());
                let msg = inp.bytes(64);
                if let Some((Status::Ok, _)) = self.call(Request::Sign { key, msg }) {
                    assert!(
                        !self.agents.contains_key(&key),
                        "agent key signed raw bytes"
                    );
                }
            }
            7 => {
                let key = self.pick(&self.general.clone(), inp.u8());
                if let Some((Status::Ok, _)) = self.call(Request::DeleteKey { key }) {
                    assert!(
                        !self.agents.contains_key(&key),
                        "agent key deleted without admins"
                    );
                    self.general.retain(|&k| k != key);
                }
            }
            8 => {
                self.call(Request::GetChallenge);
            }
            9 | 10 | 11 => self.agent_action(inp),
            12 => {
                let policy = Self::policy(inp);
                let op = AdminOp::CreateAgentKey {
                    label: b"agent",
                    ext_id: b"",
                    policy,
                };
                let Some(approvals) = self.approvals(inp, &op) else {
                    return;
                };
                let req = Request::GenerateAgentKey {
                    label: b"agent",
                    ext_id: b"",
                    policy,
                    approvals,
                };
                if let Some((Status::Ok, p)) = self.call(req) {
                    let c = resp::AgentKeyCreated::decode(&p).unwrap();
                    let cert =
                        quorum_core::cert::verify_key_cert(&self.identity, c.cert, &c.cert_sig)
                            .expect("bad birth certificate");
                    assert_eq!((cert.public, cert.policy), (c.public, policy));
                    assert!(cert.approvers.count_ones() as usize >= 1);
                    self.agents.insert(c.key, c.public);
                }
            }
            13 => {
                let key = self.pick(&self.agent_ids(), inp.u8());
                let op = AdminOp::DeleteAgentKey { key };
                let Some(approvals) = self.approvals(inp, &op) else {
                    return;
                };
                if let Some((Status::Ok, _)) = self.call(Request::DeleteAgentKey { key, approvals })
                {
                    self.agents.remove(&key);
                }
            }
            14 => {
                let key = self.pick(&self.agent_ids(), inp.u8());
                let policy = Self::policy(inp);
                let op = AdminOp::UpdatePolicy { key, policy };
                let Some(approvals) = self.approvals(inp, &op) else {
                    return;
                };
                if let Some((Status::Ok, p)) = self.call(Request::UpdatePolicy {
                    key,
                    policy,
                    approvals,
                }) {
                    let (cert, sig) = resp::decode_cert(&p).unwrap();
                    let c = quorum_core::cert::verify_key_cert(&self.identity, cert, &sig).unwrap();
                    assert_eq!(c.policy, policy);
                    assert!(c.version >= 2);
                }
            }
            15 => {
                // Hand over to a fuzzer-chosen subset of the pool.
                let mask = (inp.u8() & 0x0f).max(1);
                let new: Vec<usize> = (0..4).filter(|i| mask & (1 << i) != 0).collect();
                let threshold = (inp.u8() as usize % new.len()) as u8 + 1;
                let keys: Vec<[u8; 32]> = new
                    .iter()
                    .map(|&i| pool()[i].verifying_key().to_bytes())
                    .collect();
                let admins = AdminSet::new(&keys, threshold).unwrap();
                let op = AdminOp::ChangeAdmins { admins };
                let Some(approvals) = self.approvals(inp, &op) else {
                    return;
                };
                if let Some((Status::Ok, _)) =
                    self.call(Request::ChangeAdmins { admins, approvals })
                {
                    self.admins = new;
                }
            }
            16 => self.collect(),
            17 => {
                self.collect();
                let upto = inp.u16() as u64;
                self.call(Request::AckAudit { upto });
            }
            18 => self.verify_log_now(),
            _ => {
                // Raw garbage (after saving the log, so an "ack" inside it
                // can only release entries we already have).
                self.collect();
                let frame = inp.bytes(255).to_vec();
                if let (Status::Ok, _) = self.raw(&frame) {
                    // Whatever got through must also be a valid request.
                    assert!(Request::decode(&frame).is_ok());
                }
            }
        }
        // Keep the HSM's audit buffer from filling up.
        if self.log.len() % 8 == 0 {
            self.collect();
        }
    }

    /// An agent action with fuzzer-chosen details, checked against the
    /// rules as the HSM reported them just before.
    fn agent_action(&mut self, inp: &mut Input<'_>) {
        let key = self.pick(&self.agent_ids(), inp.u8());
        let kind = ActionKind::ALL[inp.u8() as usize % ActionKind::ALL.len()];
        let raw_amount = inp.u16() as u64;
        let amount = if kind == ActionKind::Payment {
            raw_amount.max(1)
        } else {
            0
        };
        let nonce: &[u8] = if inp.u8() & 1 == 0 { &[] } else { &[9; 16] };
        let action = Action {
            kind,
            amount,
            target: b"shop.example",
            details: b"",
            nonce,
            expires: 0,
        };
        let mode = inp.u8() % 4;

        let before = match self.call(Request::GetKeyPolicy { key }) {
            Some((Status::Ok, p)) => Some(resp::KeyPolicy::decode(&p).unwrap()),
            _ => None,
        };
        let confirmation = match mode {
            0 => None,
            _ => {
                let Some((Status::Ok, p)) = self.call(Request::GetChallenge) else {
                    return;
                };
                let challenge = resp::decode_challenge(&p).unwrap();
                let signed = if mode == 3 {
                    Action {
                        amount: amount + 1,
                        ..action
                    } // approves something else
                } else {
                    action
                };
                let mut msg = [0u8; CONFIRM_MESSAGE_MAX];
                let Ok(n) = confirmation_message(&mut msg, &self.serial, &challenge, key, &signed)
                else {
                    return;
                };
                let signer = if mode == 2 {
                    SigningKey::from_bytes(&[7; 32])
                } else {
                    phone()
                };
                Some(signer.sign(&msg[..n]).to_bytes())
            }
        };
        let Some((status, p)) = self.call(Request::SignAction {
            key,
            action,
            confirmation,
        }) else {
            return;
        };
        if status != Status::Ok {
            return;
        }
        // Approved: it must have obeyed every rule.
        let kp = before.expect("approved an action for a key with no rules");
        let rules = kp.policy;
        assert!(rules.allows(kind), "approved a forbidden kind");
        assert!(amount <= rules.max_amount, "approved over the cap");
        assert!(
            kp.spent + amount <= rules.budget,
            "approved over the budget"
        );
        assert!(
            !rules.require_nonce || !nonce.is_empty(),
            "approved without required code"
        );
        assert!(
            !rules.needs_confirmation(&action) || mode == 1,
            "approved without a valid confirmation"
        );
        assert!(mode != 2 && mode != 3, "accepted a bad confirmation");
        let (stmt, sig) = resp::decode_signed_action(&p).unwrap();
        let public = self.agents[&key];
        let s: Statement<'_> = verify_statement(&public, stmt, &sig).expect("bad signature");
        assert_eq!(
            s.sequence,
            kp.approved + 1,
            "sequence number skipped or reused"
        );
        assert_eq!(s.action, action);
        assert_eq!(s.confirmed, confirmation.is_some());
        assert_eq!(s.policy_digest, rules.digest());
    }
}

fuzz_target!(|data: &[u8]| {
    let mut w = World::new();
    // Start logged in with one agent key, so deep states are reachable.
    w.call(Request::Login { pin: PIN });
    let mut seed = Input {
        d: &[
            0x3f, 0x10, 0x27, 0x40, 0x9c, 0xe8, 0x03, 0x00, 0, 0, 0b011, 0,
        ],
        i: 0,
    };
    let policy = World::policy(&mut seed);
    let op = AdminOp::CreateAgentKey {
        label: b"agent",
        ext_id: b"",
        policy,
    };
    if let Some(approvals) = w.approvals(&mut seed, &op) {
        if let Some((Status::Ok, p)) = w.call(Request::GenerateAgentKey {
            label: b"agent",
            ext_id: b"",
            policy,
            approvals,
        }) {
            let c = resp::AgentKeyCreated::decode(&p).unwrap();
            w.agents.insert(c.key, c.public);
        }
    }

    let mut inp = Input { d: data, i: 0 };
    let mut steps = 0;
    while !inp.done() && steps < 200 {
        w.step(&mut inp);
        steps += 1;
    }
    w.verify_log_now();
});
