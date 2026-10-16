//! More attack vectors, each one actually carried out.
//!
//! Every attack has an *expected* outcome written down before it runs:
//! - **Blocked**: the HSM refuses.
//! - **Detected**: it happens, but leaves evidence that can't be hidden.
//! - **Stopped by the receiver**: the HSM signs, by design, and the
//!   receiver's checks reject it.
//! - **Works**: a known gap (or a new finding), reported honestly.
//!
//! The run fails if any attack ends differently from what is expected, so
//! a regression (or an attack that suddenly works) can't go unnoticed.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;

use ed25519_dalek::SigningKey;
use quorum_core::admin::{AdminOp, Approvals};
use quorum_core::agent::{Action, ActionKind, Policy};
use quorum_core::cert::verify_action;
use quorum_core::wire::{Cmd, MAX_FRAME, Request, Status, Writer, resp};
use quorum_core::{Hsm as Core, Session};
use rand_core::{OsRng, RngCore};

use crate::common::*;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    Blocked,
    Detected,
    ReceiverStops,
    Works,
}

impl Outcome {
    fn label(self) -> &'static str {
        match self {
            Outcome::Blocked => "✅ blocked",
            Outcome::Detected => "🔎 detected (not prevented)",
            Outcome::ReceiverStops => "✅ stopped by the receiver",
            Outcome::Works => "❌ attack works",
        }
    }
}

struct Result {
    group: &'static str,
    name: &'static str,
    expected: Outcome,
    got: Outcome,
    detail: String,
}

/// Rules for the attack HSM: payments and messages, $100 each at most, $50
/// in total, the user's OK above $20 (and for every message).
fn attack_policy() -> Policy {
    Policy {
        allowed: ActionKind::Payment.bit() | ActionKind::SendMessage.bit(),
        max_amount: 10_000,
        budget: 5_000,
        confirm_above: 2_000,
        always_confirm: ActionKind::SendMessage.bit(),
        confirmer: Some(phone().verifying_key().to_bytes()),
        require_nonce: false,
    }
}

fn blocked_if(refused: bool) -> Outcome {
    if refused {
        Outcome::Blocked
    } else {
        Outcome::Works
    }
}

pub fn run(dir: &Path, out: &mut String, data: &mut String) -> bool {
    let mut results: Vec<Result> = Vec::new();
    let mut add = |group, name, expected, got, detail: String| {
        eprintln!("  attack: {name}: {got:?}");
        results.push(Result {
            group,
            name,
            expected,
            got,
            detail,
        })
    };

    let hsm = start_hsm(dir, "attacks");
    let mut c = Conn::login(&hsm.socket).expect("connect");
    let k = c
        .create_agent_key(b"agent", attack_policy())
        .expect("agent key");
    let key = k.key;
    let flight = pay(2_500, b"airline.example");

    // ---- the user's approval ------------------------------------------------
    {
        let conf = c.confirm(key, &flight, &phone());
        let first = c.sign(key, flight, Some(conf)).0;
        let again = c.sign(key, flight, Some(conf)).0;
        add(
            "User approval",
            "Replay the user's approval for a second, identical payment",
            Outcome::Blocked,
            blocked_if(first == Status::Ok && again != Status::Ok),
            format!("first use: {first:?}; second use: {again:?}"),
        );
    }
    {
        let conf = c.confirm(key, &flight, &phone());
        let moved = pay(2_500, b"attacker.example");
        let r = c.sign(key, moved, Some(conf)).0;
        add(
            "User approval",
            "Move an approval to a different recipient (same amount)",
            Outcome::Blocked,
            blocked_if(r != Status::Ok),
            format!("{r:?}"),
        );
    }
    {
        let conf = c.confirm(key, &pay(2_100, b"airline.example"), &phone());
        let r = c.sign(key, pay(4_900, b"airline.example"), Some(conf)).0;
        add(
            "User approval",
            "Use an approval for $21 on a $49 payment",
            Outcome::Blocked,
            blocked_if(r != Status::Ok),
            format!("{r:?}"),
        );
    }
    {
        let attacker = SigningKey::from_bytes(&[99; 32]);
        let conf = c.confirm(key, &flight, &attacker);
        let r = c.sign(key, flight, Some(conf)).0;
        add(
            "User approval",
            "Approve with the attacker's own \"phone\" key",
            Outcome::Blocked,
            blocked_if(r != Status::Ok),
            format!("{r:?}"),
        );
    }
    {
        // Session A asks for the challenge and gets it approved; session B uses it.
        let conf = c.confirm(key, &flight, &phone());
        let mut b = Conn::login(&hsm.socket).expect("b");
        let r = b.sign(key, flight, Some(conf)).0;
        add(
            "User approval",
            "Use an approval from one connection on another",
            Outcome::Blocked,
            blocked_if(r != Status::Ok),
            format!("{r:?}"),
        );
    }

    // ---- what the user is shown ----------------------------------------------
    {
        let tricks: [(&str, &[u8]); 5] = [
            (
                "Cyrillic look-alike letter",
                "shop.exampl\u{0435}".as_bytes(),
            ),
            ("right-to-left override", "\u{202e}elpmaxe.pohs".as_bytes()),
            ("terminal escape code", b"shop.example\x1b[2K"),
            ("hidden NUL byte", b"shop\0.example"),
            ("line break", b"shop.example\nattacker.example"),
        ];
        let mut raw = Raw::open(&hsm.socket).expect("raw");
        raw.request(Request::Login {
            pin: PIN.as_bytes(),
        })
        .expect("login");
        let mut refused = Vec::new();
        for (name, target) in tricks {
            let frame = sign_action_frame(key, 100, target);
            let r = raw.frame(&frame).expect("reply");
            let st = resp::split(&r).expect("resp").0;
            refused.push((name, st));
        }
        let all = refused.iter().all(|(_, s)| *s == Status::BadRequest);
        add(
            "What the user is shown",
            "Recipients that look like one thing but are another",
            Outcome::Blocked,
            blocked_if(all),
            refused
                .iter()
                .map(|(n, s)| format!("{n}: {s:?}"))
                .collect::<Vec<_>>()
                .join("; "),
        );
    }

    // ---- money -------------------------------------------------------------
    {
        // Rules allowing anything up to the largest number, to reach the overflow.
        let wide = Policy {
            allowed: ActionKind::Payment.bit(),
            max_amount: u64::MAX,
            budget: u64::MAX,
            confirm_above: u64::MAX,
            always_confirm: 0,
            confirmer: None,
            require_nonce: false,
        };
        let w = c.create_agent_key(b"wide", wide).expect("wide key").key;
        let a = c.sign(w, pay(1, b"shop.example"), None).0;
        let b = c.sign(w, pay(u64::MAX, b"shop.example"), None).0;
        add(
            "Money",
            "Make the spending counter wrap around (1 cent, then the largest possible amount)",
            Outcome::Blocked,
            blocked_if(a == Status::Ok && b != Status::Ok),
            format!("1 cent: {a:?}; 2^64-1 cents: {b:?}"),
        );
    }
    {
        // $10 budget, 20 connections each try five $1 payments at the same instant.
        let tight = Policy {
            budget: 1_000,
            max_amount: 100,
            ..attack_policy()
        };
        let t = c.create_agent_key(b"tight", tight).expect("tight").key;
        let _ = collect(&mut c.c);
        let barrier = Arc::new(Barrier::new(20));
        let handles: Vec<_> = (0..20)
            .map(|_| {
                let (socket, barrier) = (hsm.socket.clone(), barrier.clone());
                thread::spawn(move || {
                    let mut c = Conn::login(&socket).expect("c");
                    barrier.wait();
                    (0..5)
                        .filter(|_| {
                            loop {
                                match c.sign(t, pay(100, b"shop.example"), None).0 {
                                    Status::Ok => break true,
                                    Status::AuditFull => {
                                        let _ = collect(&mut c.c);
                                    }
                                    _ => break false,
                                }
                            }
                        })
                        .count()
                })
            })
            .collect();
        let approved: usize = handles.into_iter().map(|h| h.join().expect("t")).sum();
        add(
            "Money",
            "Race: 20 connections spend the last of a $10 budget at the same instant (100 tries of $1)",
            Outcome::Blocked,
            blocked_if(approved == 10),
            format!("{approved} of 100 approved (exactly 10 fit the budget)"),
        );
    }
    let _ = collect(&mut c.c);

    // ---- admin sign-off ----------------------------------------------------
    let policy2 = Policy {
        budget: 9_000,
        ..attack_policy()
    };
    {
        let op = AdminOp::UpdatePolicy {
            key,
            policy: policy2,
        };
        let approvals = c.approvals(op, &[0, 1]);
        let first = c
            .call(Request::UpdatePolicy {
                key,
                policy: policy2,
                approvals,
            })
            .0;
        let _ = c.call(Request::GetAdminChallenge); // a new proposal is started
        let again = c
            .call(Request::UpdatePolicy {
                key,
                policy: policy2,
                approvals,
            })
            .0;
        add(
            "Admin sign-off",
            "Reuse admins' approvals from an earlier change",
            Outcome::Blocked,
            blocked_if(first == Status::Ok && again != Status::Ok),
            format!("first: {first:?}; reused: {again:?}"),
        );
    }
    {
        let other = start_hsm(dir, "attacks-other");
        let mut o = Conn::login(&other.socket).expect("other");
        let ok = o
            .create_agent_key(b"agent", attack_policy())
            .expect("key")
            .key;
        // Approvals made for the first HSM...
        let op = AdminOp::UpdatePolicy {
            key: ok,
            policy: policy2,
        };
        let approvals = c.approvals(op, &[0, 1]);
        // ...presented to the second, which has a challenge pending too.
        let _ = o.call(Request::GetAdminChallenge);
        let r = o
            .call(Request::UpdatePolicy {
                key: ok,
                policy: policy2,
                approvals,
            })
            .0;
        add(
            "Admin sign-off",
            "Take approvals made for one HSM to another HSM with the same admins",
            Outcome::Blocked,
            blocked_if(r != Status::Ok),
            format!("{r:?}"),
        );
    }
    {
        let op = AdminOp::UpdatePolicy {
            key,
            policy: attack_policy(),
        };
        let one = c.approvals(op, &[0]);
        let (_, sig) = *one.iter().next().expect("sig");
        let mut twice = Approvals::default();
        twice.push(0, sig).expect("push");
        twice.push(0, sig).expect("push");
        let r1 = c
            .call(Request::UpdatePolicy {
                key,
                policy: attack_policy(),
                approvals: twice,
            })
            .0;
        let one = c.approvals(op, &[0]);
        let (_, sig) = *one.iter().next().expect("sig");
        let mut relabelled = Approvals::default();
        relabelled.push(0, sig).expect("push");
        relabelled.push(1, sig).expect("push");
        let r2 = c
            .call(Request::UpdatePolicy {
                key,
                policy: attack_policy(),
                approvals: relabelled,
            })
            .0;
        add(
            "Admin sign-off",
            "One admin counted twice (same signature twice, or relabelled as another admin)",
            Outcome::Blocked,
            blocked_if(r1 != Status::Ok && r2 != Status::Ok),
            format!("twice: {r1:?}; relabelled: {r2:?}"),
        );
    }

    // ---- the audit log -----------------------------------------------------
    {
        let h = start_hsm(dir, "attacks-audit");
        let mut pin_holder = Conn::login(&h.socket).expect("c");
        let ak = pin_holder
            .create_agent_key(b"agent", attack_policy())
            .expect("k")
            .key;
        // The collector copies everything so far.
        let mut collector_log = 0u64;
        let (_, p) = pin_holder.call(Request::ReadAudit { from: 1 });
        let batch = resp::AuditBatch::decode(&p).expect("batch");
        collector_log += batch.entries().count() as u64;
        pin_holder.call(Request::AckAudit {
            upto: batch.last_seq,
        });
        // The attacker tries something forbidden...
        let refused = pin_holder
            .sign(ak, pay(9_999_999, b"attacker.example"), None)
            .0;
        // ...then, from a connection without the PIN, releases the evidence
        // before the collector's next visit.
        let mut sneaky = Conn::open(&h.socket).expect("sneaky");
        let (_, p) = sneaky.call(Request::ReadAudit { from: 0 });
        let last = resp::AuditBatch::decode(&p).expect("batch").last_seq;
        let acked = sneaky.call(Request::AckAudit { upto: last }).0;
        // The collector comes back.
        let (_, p) = pin_holder.call(Request::ReadAudit {
            from: collector_log + 1,
        });
        let batch = resp::AuditBatch::decode(&p).expect("batch");
        let gap = batch.entries().next().is_none() && batch.last_seq > collector_log;
        add(
            "Audit log",
            "Release (delete) log entries from the HSM before the collector copies them, without the PIN",
            Outcome::Detected,
            if refused != Status::Ok && acked == Status::Ok && gap {
                Outcome::Detected
            } else if acked != Status::Ok {
                Outcome::Blocked
            } else {
                Outcome::Works
            },
            format!(
                "release accepted: {acked:?}; the collector then sees entries {} to {} missing, and the checkpoint check fails",
                collector_log + 1,
                batch.last_seq
            ),
        );
    }

    // ---- the PIN -----------------------------------------------------------
    {
        let (answered, locked_after, correct) = pin_guessing_with_power_cuts(dir);
        add(
            "PIN",
            "Guess the PIN, cutting the power right after every attempt to stop it being counted",
            Outcome::Blocked,
            blocked_if(answered <= 5 && correct == Status::PinLocked),
            format!(
                "{answered} wrong guesses answered over {locked_after} restarts; then the correct PIN: {correct:?}"
            ),
        );
    }
    {
        let (spread, noise, table) = pin_timing();
        data.push_str(&table);
        add(
            "PIN",
            "Learn the PIN from timing (how long a wrong PIN takes, by number of correct leading digits)",
            Outcome::Blocked,
            blocked_if(spread <= 3.0 * noise.max(1.0)),
            format!(
                "median times differ by at most {spread:.0} ns across 0-5 correct digits; run-to-run noise {noise:.0} ns"
            ),
        );
    }
    {
        let mut b = Conn::open(&hsm.socket).expect("b");
        let r = b.call(Request::Sign { key, msg: b"x" }).0;
        let g = b
            .call(Request::GenerateKey {
                label: b"x",
                ext_id: b"",
            })
            .0;
        add(
            "PIN",
            "Use another connection's login (sessions are per connection)",
            Outcome::Blocked,
            blocked_if(r == Status::NotLoggedIn && g == Status::NotLoggedIn),
            format!("sign: {r:?}; create key: {g:?}"),
        );
    }

    // ---- the receiver ------------------------------------------------------
    {
        let other = c
            .create_agent_key(b"other", attack_policy())
            .expect("other");
        let (_, p) = c.sign(key, pay(100, b"shop.example"), None);
        let (st, sig) = resp::decode_signed_action(&p).expect("signed");
        // The key's rules were changed above (attack 9), so ask for its
        // current certificate; the factory one is out of date.
        let (_, cp) = c.call(Request::GetKeyCert { key });
        let (cert, cert_sig) = resp::decode_cert(&cp).expect("cert");
        let ok_own = verify_action(&c.identity, cert, &cert_sig, st, &sig).is_ok();
        let stale = verify_action(&c.identity, &k.cert, &k.cert_sig, st, &sig).is_err();
        let swapped = verify_action(&c.identity, &other.cert, &other.cert_sig, st, &sig);
        add(
            "Receiver",
            "Present a payment with the wrong birth certificate (another key's, or one with old rules)",
            Outcome::ReceiverStops,
            if ok_own && stale && swapped.is_err() {
                Outcome::ReceiverStops
            } else {
                Outcome::Works
            },
            format!(
                "with its current certificate: valid {ok_own}; with its out-of-date one (old rules): rejected {stale}; with the other key's: {:?}",
                swapped.err()
            ),
        );
    }
    {
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        let a = Action {
            nonce: &nonce,
            expires: 1_900_000_000,
            ..pay(100, b"shop.example")
        };
        let mut seen = HashSet::new();
        let mut accepted = 0;
        let mut signed = 0;
        for _ in 0..2 {
            let (s, p) = c.sign(key, a, None);
            if s == Status::Ok {
                signed += 1;
                let (st, _) = resp::decode_signed_action(&p).expect("signed");
                let n = quorum_core::agent::Statement::decode(st)
                    .expect("st")
                    .action
                    .nonce
                    .to_vec();
                if seen.insert(n) {
                    accepted += 1;
                }
            }
        }
        add(
            "Receiver",
            "Get two payments signed for the same one-time shop request",
            Outcome::ReceiverStops,
            if signed == 2 && accepted == 1 {
                Outcome::ReceiverStops
            } else if signed < 2 {
                Outcome::Blocked
            } else {
                Outcome::Works
            },
            format!(
                "the HSM signed {signed} (it keeps no list of requests, by design); the shop accepted {accepted}"
            ),
        );
    }

    // ---- the connection ----------------------------------------------------
    {
        let mut r = Raw::open(&hsm.socket).expect("raw");
        let mut junk = [0u8; 200];
        let mut bad = 0;
        for _ in 0..200 {
            OsRng.fill_bytes(&mut junk);
            let n = 1 + (OsRng.next_u32() as usize % junk.len());
            if let Ok(resp) = r.frame(&junk[..n])
                && resp == [Status::BadRequest as u8]
            {
                bad += 1;
            }
        }
        let mut login_frame = [0u8; MAX_FRAME];
        let n = Request::Login {
            pin: PIN.as_bytes(),
        }
        .encode(&mut login_frame)
        .expect("enc");
        login_frame[n] = 0;
        let trailing = r
            .frame(&login_frame[..n + 1])
            .is_ok_and(|v| v == [Status::BadRequest as u8]);
        let mut huge = Raw::open(&hsm.socket).expect("raw");
        let _ = huge.send_len(u32::MAX);
        let closed = huge.read().is_err();
        let still = Conn::open(&hsm.socket).map(|mut x| x.call(Request::GetInfo).0);
        add(
            "Connection",
            "Random garbage, a valid request with an extra byte, and a 4 GB length prefix",
            Outcome::Blocked,
            blocked_if(bad >= 190 && trailing && closed && matches!(still, Ok(Status::Ok))),
            format!(
                "{bad}/200 garbage frames refused; extra byte refused: {}; 4 GB frame: connection closed {closed}; HSM still answering: {}",
                trailing,
                matches!(still, Ok(Status::Ok))
            ),
        );
    }

    // ---- resources ---------------------------------------------------------
    {
        let h = start_hsm(dir, "attacks-full");
        let mut pin_holder = Conn::login(&h.socket).expect("c");
        let mut made = 0;
        loop {
            match pin_holder
                .call(Request::GenerateKey {
                    label: b"junk",
                    ext_id: b"",
                })
                .0
            {
                Status::Ok => made += 1,
                Status::AuditFull => {
                    let _ = collect(&mut pin_holder.c);
                }
                _ => break,
            }
        }
        let r = pin_holder.create_agent_key(b"agent", attack_policy());
        let status = r.as_ref().err().copied();
        add(
            "Resources",
            "Fill the key store with ordinary keys (PIN only) so admins can't create agent keys",
            Outcome::Works,
            if r.is_ok() {
                Outcome::Blocked
            } else {
                Outcome::Works
            },
            format!(
                "{made} junk keys created; then the admins' agent key: {status:?}. Existing agent keys keep working"
            ),
        );
    }

    // ---- stored state ------------------------------------------------------
    {
        let (before, after) = rollback(dir);
        add(
            "Stored state",
            "Roll back: copy the state file, spend the budget, put the old copy back",
            Outcome::Works,
            if after == Status::Ok {
                Outcome::Works
            } else {
                Outcome::Blocked
            },
            format!(
                "after spending $50 of $50: {before:?}; after restoring the old file: {after:?}"
            ),
        );
    }

    // ---- report ------------------------------------------------------------
    writeln!(
        out,
        "| # | Area | Attack | Expected | Result | What happened |"
    )
    .unwrap();
    writeln!(out, "|---:|---|---|---|---|---|").unwrap();
    let mut all_as_expected = true;
    for (i, r) in results.iter().enumerate() {
        let as_expected = r.got == r.expected;
        all_as_expected &= as_expected;
        writeln!(
            out,
            "| {} | {} | {} | {} | {}{} | {} |",
            i + 1,
            r.group,
            r.name,
            r.expected.label(),
            r.got.label(),
            if as_expected { "" } else { " **UNEXPECTED**" },
            r.detail.replace('|', "/")
        )
        .unwrap();
        writeln!(data, "attack\t{}\t{:?}\t{:?}", r.name, r.expected, r.got).unwrap();
    }
    let count = |o| results.iter().filter(|r| r.got == o).count();
    writeln!(
        out,
        "\n**{} attacks:** {} blocked, {} stopped by the receiver, {} detected, {} work ({} as expected).\n",
        results.len(),
        count(Outcome::Blocked),
        count(Outcome::ReceiverStops),
        count(Outcome::Detected),
        count(Outcome::Works),
        if all_as_expected { "all" } else { "NOT all" }
    )
    .unwrap();
    all_as_expected
}

/// A SignAction frame built by hand, so the recipient can contain bytes the
/// normal client refuses to encode.
fn sign_action_frame(key: u32, cents: u64, target: &[u8]) -> Vec<u8> {
    let mut buf = [0u8; MAX_FRAME];
    let mut w = Writer::new(&mut buf);
    w.u8(Cmd::SignAction as u8).expect("w");
    w.u32(key).expect("w");
    w.u8(ActionKind::Payment as u8).expect("w");
    w.u64(cents).expect("w");
    w.bytes(target).expect("w");
    w.bytes(b"").expect("w");
    w.bytes(b"").expect("w");
    w.u64(0).expect("w");
    w.u8(0).expect("w");
    let n = w.len();
    buf[..n].to_vec()
}

/// Wrong PIN, then `kill -9` the HSM the instant the answer arrives (and
/// sometimes before), over and over. Returns (wrong guesses answered,
/// restarts, the correct PIN's result at the end).
fn pin_guessing_with_power_cuts(dir: &Path) -> (u32, u32, Status) {
    let mut p = Proc::init(dir, "pin");
    let mut answered = 0;
    let mut restarts = 0;
    for _ in 0..12 {
        p.start();
        restarts += 1;
        if let Ok(mut r) = Raw::open(&p.socket)
            && let Ok(st) = r.request(Request::Login { pin: b"000000" })
            && st == Status::PinIncorrect
        {
            answered += 1;
        }
        p.kill();
    }
    p.start();
    let mut r = Raw::open(&p.socket).expect("raw");
    let correct = r
        .request(Request::Login {
            pin: PIN.as_bytes(),
        })
        .expect("login");
    (answered, restarts, correct)
}

/// Times wrong-PIN logins on the core itself (no disk, no socket), grouped
/// by how many leading digits are right. Returns (largest difference
/// between groups' medians, run-to-run noise, raw rows), in nanoseconds.
fn pin_timing() -> (f64, f64, String) {
    let mut storage = MemStorage;
    let mut hsm = Core::provision(provisioning(), &mut OsRng, &mut storage).expect("core");
    let guesses: [&[u8]; 6] = [
        b"000000", b"100000", b"120000", b"123000", b"123400", b"123450",
    ];
    let mut out = [0u8; MAX_FRAME];
    let mut call = |hsm: &mut Core, s: &mut Session, req: Request<'_>| {
        let mut f = [0u8; MAX_FRAME];
        let n = req.encode(&mut f).expect("enc");
        let m = hsm.handle(s, &mut MemStorage, &mut OsRng, &f[..n], &mut out);
        out[0]
            .try_into()
            .map(|s: Status| (s, out[1..m].to_vec()))
            .expect("status")
    };
    const ROUNDS: usize = 4000;
    let mut samples = vec![Vec::with_capacity(ROUNDS); guesses.len()];
    let mut session = Session::default();
    // Guesses are tried in a fresh random order every round, so that "where
    // in the round" can't masquerade as "how many digits were right".
    let mut order: Vec<usize> = (0..guesses.len()).collect();
    for _ in 0..ROUNDS {
        for i in (1..order.len()).rev() {
            order.swap(i, OsRng.next_u32() as usize % (i + 1));
        }
        for &g in &order {
            let guess = guesses[g];
            let t = Instant::now();
            let (st, _) = call(&mut hsm, &mut session, Request::Login { pin: guess });
            let ns = t.elapsed().as_nanos() as u64;
            assert_eq!(st, Status::PinIncorrect);
            samples[g].push(ns);
            // The right PIN resets the tries; then log out again.
            let (st, _) = call(
                &mut hsm,
                &mut session,
                Request::Login {
                    pin: PIN.as_bytes(),
                },
            );
            assert_eq!(st, Status::Ok);
            call(&mut hsm, &mut session, Request::Logout);
        }
        {
            let (_, p) = call(&mut hsm, &mut session, Request::ReadAudit { from: 0 });
            let last = resp::AuditBatch::decode(&p).expect("batch").last_seq;
            call(&mut hsm, &mut session, Request::AckAudit { upto: last });
        }
    }
    let median = |v: &[u64]| {
        let mut v = v.to_vec();
        v.sort_unstable();
        v[v.len() / 2] as f64
    };
    let medians: Vec<f64> = samples.iter().map(|s| median(s)).collect();
    let spread = medians.iter().cloned().fold(f64::MIN, f64::max)
        - medians.iter().cloned().fold(f64::MAX, f64::min);
    // Noise: the same group measured in two halves.
    let noise = samples
        .iter()
        .map(|s| (median(&s[..s.len() / 2]) - median(&s[s.len() / 2..])).abs())
        .fold(0.0, f64::max);
    let mut table = String::new();
    for (g, m) in medians.iter().enumerate() {
        writeln!(table, "pin_timing\t{g}\t{m:.0}").unwrap();
    }
    (spread, noise, table)
}

/// Spends a $50 budget, then puts back a copy of the state file made
/// before the spending. Returns (a payment after spending it all, a payment
/// after restoring the old copy).
fn rollback(dir: &Path) -> (Status, Status) {
    let mut p = Proc::init(dir, "rollback");
    p.start();
    let rules = Policy {
        confirm_above: 10_000,
        ..attack_policy()
    };
    let key = Conn::login(&p.socket)
        .expect("c")
        .create_agent_key(b"agent", rules)
        .expect("k")
        .key;
    p.kill();
    let copy = dir.join("rollback.copy");
    fs::copy(&p.state, &copy).expect("copy");
    p.start();
    let mut c = Conn::login(&p.socket).expect("c");
    for _ in 0..5 {
        assert_eq!(c.sign(key, pay(1_000, b"shop.example"), None).0, Status::Ok);
    }
    let before = c.sign(key, pay(1_000, b"shop.example"), None).0;
    drop(c);
    p.kill();
    fs::copy(&copy, &p.state).expect("restore");
    p.start();
    let mut c = Conn::login(&p.socket).expect("c");
    let after = c.sign(key, pay(1_000, b"shop.example"), None).0;
    (before, after)
}
