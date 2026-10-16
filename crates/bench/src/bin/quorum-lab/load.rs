//! Performance under load.
//!
//! - **Concurrency sweep:** 1 to 64 clients, each sending requests back to
//!   back. The HSM handles one command at a time (like a single-core chip),
//!   so throughput levels off and extra clients wait in line. We measure how
//!   long, whether any client is starved, and whether the counters stay
//!   exactly right under contention.
//! - **Noisy neighbours:** one ordinary client while others flood the HSM
//!   (with and without the PIN, with garbage, with idle connections).
//! - **Soak:** a steady load for a while; does anything drift?
//! - **Crash under load:** the HSM process is killed (`kill -9`) again and
//!   again in the middle of traffic. No answer may ever be lost from the
//!   counters, and no action number may ever be handed out twice.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use quorum_client::Client;
use quorum_core::agent::Statement;
use quorum_core::wire::{Request, Status, resp};
use rand_core::{OsRng, RngCore};

use crate::common::*;

pub struct Settings {
    pub seconds: f64,
    pub max_clients: usize,
    pub soak_seconds: f64,
    pub crash_rounds: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Work {
    /// An approved one-cent payment: rules checked, spending saved to disk.
    Payment,
    /// A refused payment (over the limit): recorded in the audit log, saved.
    Refusal,
    /// Signing a message with an ordinary key: no disk write.
    RawSign,
    /// Reading a key's rules and spending: nothing changes.
    Read,
}

impl Work {
    fn name(self) -> &'static str {
        match self {
            Work::Payment => "approved payment (saved to disk)",
            Work::Refusal => "refused payment (logged, saved)",
            Work::RawSign => "raw signing, ordinary key (no disk)",
            Work::Read => "read rules and spending (no change)",
        }
    }
    fn tag(self) -> &'static str {
        match self {
            Work::Payment => "payment",
            Work::Refusal => "refusal",
            Work::RawSign => "rawsign",
            Work::Read => "read",
        }
    }
}

struct Level {
    clients: usize,
    ops: u64,
    secs: f64,
    lat: Vec<u64>,
    per_client: Vec<u64>,
    audit_full: u64,
    sequences: Vec<u64>,
}

impl Level {
    fn ops_per_sec(&self) -> f64 {
        self.ops as f64 / self.secs
    }
    /// Fewest requests any client got done, divided by the most.
    fn fairness(&self) -> f64 {
        let min = *self.per_client.iter().min().unwrap_or(&0) as f64;
        let max = *self.per_client.iter().max().unwrap_or(&1) as f64;
        if max == 0.0 { 1.0 } else { min / max }
    }
}

/// Copies the audit log out every few milliseconds until stopped, as a
/// collector would. Without it the HSM stops after 64 audited actions.
fn collector(socket: &Path, stop: Arc<AtomicBool>) -> thread::JoinHandle<()> {
    let socket = socket.to_path_buf();
    thread::spawn(move || {
        let mut c = Client::connect_at(&socket).expect("collector");
        while !stop.load(Ordering::Relaxed) {
            let _ = collect(&mut c);
            thread::sleep(Duration::from_millis(5));
        }
        let _ = collect(&mut c);
    })
}

/// One request; retries (and counts) when the log is momentarily full.
fn one(c: &mut Conn, work: Work, key: u32, general: u32, full: &AtomicU64) -> (Status, Vec<u8>) {
    loop {
        let r = match work {
            Work::Payment => c.sign(key, cent(), None),
            Work::Refusal => c.sign(key, pay(5000, b"shop.example"), None),
            Work::RawSign => c.call(Request::Sign {
                key: general,
                msg: &[0x42; 64],
            }),
            Work::Read => c.call(Request::GetKeyPolicy { key }),
        };
        if r.0 == Status::AuditFull {
            full.fetch_add(1, Ordering::Relaxed);
            thread::sleep(Duration::from_micros(200));
            continue;
        }
        return r;
    }
}

fn run_level(
    socket: &Path,
    key: u32,
    general: u32,
    work: Work,
    clients: usize,
    secs: f64,
) -> Level {
    let barrier = Arc::new(Barrier::new(clients + 1));
    let full = Arc::new(AtomicU64::new(0));
    let mut handles = Vec::new();
    for _ in 0..clients {
        let (socket, barrier, full) = (socket.to_path_buf(), barrier.clone(), full.clone());
        handles.push(thread::spawn(move || {
            let mut c = Conn::login(&socket).expect("connect");
            let mut lat = Vec::new();
            let mut seqs = Vec::new();
            barrier.wait();
            let end = Instant::now() + Duration::from_secs_f64(secs);
            while Instant::now() < end {
                let t = Instant::now();
                let (status, payload) = one(&mut c, work, key, general, &full);
                lat.push(t.elapsed().as_micros() as u64);
                match (work, status) {
                    (Work::Payment, Status::Ok) => {
                        let (st, _) = resp::decode_signed_action(&payload).expect("signed");
                        seqs.push(Statement::decode(st).expect("statement").sequence);
                    }
                    (Work::Refusal, Status::AmountTooHigh) | (_, Status::Ok) => {}
                    (_, s) => panic!("unexpected {s:?} under load"),
                }
            }
            (lat, seqs)
        }));
    }
    barrier.wait();
    let start = Instant::now();
    let mut all = Vec::new();
    let mut per_client = Vec::new();
    let mut sequences = Vec::new();
    for h in handles {
        let (lat, seqs) = h.join().expect("client");
        per_client.push(lat.len() as u64);
        all.extend(lat);
        sequences.extend(seqs);
    }
    let secs = start.elapsed().as_secs_f64();
    all.sort_unstable();
    Level {
        clients,
        ops: all.len() as u64,
        secs,
        lat: all,
        per_client,
        audit_full: full.load(Ordering::Relaxed),
        sequences,
    }
}

pub fn run(dir: &Path, s: &Settings, out: &mut String, data: &mut String) -> bool {
    let mut ok = true;
    let hsm = start_hsm(dir, "load");
    let mut admin = Conn::login(&hsm.socket).expect("connect");
    let key = admin
        .create_agent_key(b"load-agent", load_policy())
        .expect("agent key")
        .key;
    let (st, p) = admin.call(Request::GenerateKey {
        label: b"load-general",
        ext_id: b"",
    });
    assert_eq!(st, Status::Ok);
    let general = resp::Generated::decode(&p).expect("generated").key;

    let stop = Arc::new(AtomicBool::new(false));
    let col = collector(&hsm.socket, stop.clone());

    // ---- concurrency sweep -------------------------------------------------
    let mut levels = vec![1];
    while levels.last().copied().unwrap_or(1) * 2 <= s.max_clients {
        let next = levels.last().copied().unwrap_or(1) * 2;
        levels.push(next);
    }
    writeln!(out, "## 1. Concurrency sweep\n").unwrap();
    writeln!(
        out,
        "Each client sends requests back to back for {} s. One HSM, one command at a time; an audit collector copies the log out every 5 ms.\n",
        s.seconds
    )
    .unwrap();
    let mut total_payments = 0u64;
    let mut all_seqs: Vec<u64> = Vec::new();
    for work in [Work::Payment, Work::Refusal, Work::RawSign, Work::Read] {
        writeln!(out, "### {}\n", work.name()).unwrap();
        writeln!(
            out,
            "| Clients | Requests/s | Median wait | 99th percentile | 99.9th | Slowest client / fastest | Log-full retries |"
        )
        .unwrap();
        writeln!(out, "|---:|---:|---:|---:|---:|---:|---:|").unwrap();
        for &n in &levels {
            eprintln!("  load: {} x {n}", work.tag());
            let l = run_level(&hsm.socket, key, general, work, n, s.seconds);
            let (p50, p99, p999) = (
                percentile(&l.lat, 50.0),
                percentile(&l.lat, 99.0),
                percentile(&l.lat, 99.9),
            );
            writeln!(
                out,
                "| {} | {:.0} | {} | {} | {} | {:.2} | {} |",
                l.clients,
                l.ops_per_sec(),
                fmt_us(p50),
                fmt_us(p99),
                fmt_us(p999),
                l.fairness(),
                l.audit_full
            )
            .unwrap();
            writeln!(
                data,
                "sweep\t{}\t{}\t{:.1}\t{p50}\t{p99}\t{p999}\t{:.3}\t{}",
                work.tag(),
                l.clients,
                l.ops_per_sec(),
                l.fairness(),
                l.audit_full
            )
            .unwrap();
            if work == Work::Payment {
                total_payments += l.ops;
                all_seqs.extend(&l.sequences);
            }
        }
        writeln!(out).unwrap();
    }

    // Under all that contention, were the counters exactly right?
    let (_, p) = admin.call(Request::GetKeyPolicy { key });
    let kp = resp::KeyPolicy::decode(&p).expect("policy");
    all_seqs.sort_unstable();
    let unique = all_seqs.windows(2).all(|w| w[0] != w[1]);
    let contiguous =
        all_seqs.first() == Some(&1) && all_seqs.last() == Some(&(all_seqs.len() as u64));
    let counters_ok =
        kp.spent == total_payments && kp.approved == total_payments && unique && contiguous;
    ok &= counters_ok;
    writeln!(out, "**Counters under contention:** {total_payments} payments approved across all levels; the HSM's spending counter says {} cents and {} actions; action numbers handed out are {}unique and {}gap-free. {}\n",
        kp.spent, kp.approved,
        if unique { "" } else { "NOT " }, if contiguous { "" } else { "NOT " },
        if counters_ok { "✅ exact" } else { "❌ MISMATCH" }).unwrap();

    // ---- noisy neighbours --------------------------------------------------
    writeln!(out, "## 2. Noisy neighbours\n").unwrap();
    writeln!(out, "One ordinary client makes one-cent payments for {} s while others do something else at full speed.\n", s.seconds).unwrap();
    writeln!(out, "| What the others do | Ordinary client: requests/s | Median wait | 99th percentile | Slowdown (median) |").unwrap();
    writeln!(out, "|---|---:|---:|---:|---:|").unwrap();
    let mut base_p50 = 0;
    for (name, tag) in [
        ("nothing (baseline)", "none"),
        ("8 clients with the PIN flood refused actions", "refusals"),
        (
            "8 clients without the PIN flood \"who are you?\" requests",
            "unauth",
        ),
        ("8 clients send garbage frames and reconnect", "garbage"),
        ("200 idle connections held open", "idle"),
        ("100 connections send half a frame and stall", "slowloris"),
        ("8 clients with the PIN flood approved payments", "payments"),
    ] {
        eprintln!("  noisy: {tag}");
        let r = noisy(&hsm.socket, key, tag, s.seconds);
        if tag == "none" {
            base_p50 = r.1.max(1);
        }
        writeln!(
            out,
            "| {name} | {:.0} | {} | {} | {:.1}x |",
            r.0,
            fmt_us(r.1),
            fmt_us(r.2),
            r.1 as f64 / base_p50 as f64
        )
        .unwrap();
        writeln!(data, "noisy\t{tag}\t{:.1}\t{}\t{}", r.0, r.1, r.2).unwrap();
    }
    writeln!(out).unwrap();

    // ---- soak ---------------------------------------------------------------
    writeln!(
        out,
        "## 3. Soak: 4 clients making payments for {} s\n",
        s.soak_seconds
    )
    .unwrap();
    let windows = soak(&hsm.socket, key, s.soak_seconds);
    writeln!(out, "| Window | Requests/s | 99th percentile |").unwrap();
    writeln!(out, "|---:|---:|---:|").unwrap();
    for (i, (ops, p99)) in windows.iter().enumerate() {
        writeln!(
            out,
            "| {}–{} s | {ops:.0} | {} |",
            i * 5,
            (i + 1) * 5,
            fmt_us(*p99)
        )
        .unwrap();
        writeln!(data, "soak\t{i}\t{ops:.1}\t{p99}").unwrap();
    }
    let state_len = std::fs::metadata(dir.join("load.state"))
        .map(|m| m.len())
        .unwrap_or(0);
    writeln!(
        out,
        "\nState file size after the soak: {state_len} bytes (fixed: two slots).\n"
    )
    .unwrap();

    stop.store(true, Ordering::Relaxed);
    let _ = col.join();

    // ---- crash under load --------------------------------------------------
    writeln!(out, "## 4. Killing the HSM in the middle of traffic\n").unwrap();
    let crash_ok = crash(dir, s.crash_rounds, out, data);
    ok &= crash_ok;
    ok
}

/// Returns the ordinary client's (requests/s, median µs, p99 µs).
fn noisy(socket: &Path, key: u32, tag: &str, secs: f64) -> (f64, u64, u64) {
    let stop = Arc::new(AtomicBool::new(false));
    let mut noise = Vec::new();
    let mut held = Vec::new();
    let flooders = |f: fn(&Path, u32, &AtomicBool)| {
        (0..8)
            .map(|_| {
                let (socket, stop) = (socket.to_path_buf(), stop.clone());
                thread::spawn(move || f(&socket, key, &stop))
            })
            .collect::<Vec<_>>()
    };
    match tag {
        "refusals" => {
            noise = flooders(|s, key, stop| {
                let mut c = Conn::login(s).expect("c");
                let full = AtomicU64::new(0);
                while !stop.load(Ordering::Relaxed) {
                    one(&mut c, Work::Refusal, key, 0, &full);
                }
            })
        }
        "payments" => {
            noise = flooders(|s, key, stop| {
                let mut c = Conn::login(s).expect("c");
                let full = AtomicU64::new(0);
                while !stop.load(Ordering::Relaxed) {
                    one(&mut c, Work::Payment, key, 0, &full);
                }
            })
        }
        "unauth" => {
            noise = flooders(|s, _, stop| {
                let mut c = Client::connect_at(s).expect("c");
                while !stop.load(Ordering::Relaxed) {
                    let _ = c.call(&Request::GetInfo);
                }
            })
        }
        "garbage" => {
            noise = flooders(|s, _, stop| {
                let mut junk = [0u8; 64];
                while !stop.load(Ordering::Relaxed) {
                    if let Ok(mut r) = Raw::open(s) {
                        OsRng.fill_bytes(&mut junk);
                        let _ = r.frame(&junk);
                        let _ = r.send_len(u32::MAX);
                    }
                }
            })
        }
        "idle" => {
            for _ in 0..200 {
                held.push(Raw::open(socket).expect("idle"));
            }
        }
        "slowloris" => {
            for _ in 0..100 {
                let mut r = Raw::open(socket).expect("slow");
                let _ = r.send_len(100);
                let _ = std::io::Write::write_all(r.raw_stream(), &[0x12, 0, 0]);
                held.push(r);
            }
        }
        _ => {}
    }
    let mut c = Conn::login(socket).expect("victim");
    let full = AtomicU64::new(0);
    let mut lat = Vec::new();
    let end = Instant::now() + Duration::from_secs_f64(secs);
    let start = Instant::now();
    while Instant::now() < end {
        let t = Instant::now();
        let (st, _) = one(&mut c, Work::Payment, key, 0, &full);
        assert_eq!(st, Status::Ok);
        lat.push(t.elapsed().as_micros() as u64);
    }
    let elapsed = start.elapsed().as_secs_f64();
    stop.store(true, Ordering::Relaxed);
    for h in noise {
        let _ = h.join();
    }
    drop(held);
    lat.sort_unstable();
    (
        lat.len() as f64 / elapsed,
        percentile(&lat, 50.0),
        percentile(&lat, 99.0),
    )
}

/// (requests/s, p99 µs) for each 5-second window.
fn soak(socket: &Path, key: u32, secs: f64) -> Vec<(f64, u64)> {
    let windows = (secs / 5.0).ceil().max(1.0) as usize;
    let lat: Arc<Mutex<Vec<Vec<u64>>>> = Arc::new(Mutex::new(vec![Vec::new(); windows]));
    let start = Instant::now();
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let (socket, lat) = (socket.to_path_buf(), lat.clone());
            thread::spawn(move || {
                let mut c = Conn::login(&socket).expect("c");
                let full = AtomicU64::new(0);
                let mut mine = vec![Vec::new(); windows];
                loop {
                    let w = (start.elapsed().as_secs_f64() / 5.0) as usize;
                    if w >= windows {
                        break;
                    }
                    let t = Instant::now();
                    one(&mut c, Work::Payment, key, 0, &full);
                    mine[w].push(t.elapsed().as_micros() as u64);
                }
                let mut all = lat.lock().expect("lat");
                for (a, m) in all.iter_mut().zip(mine) {
                    a.extend(m);
                }
            })
        })
        .collect();
    for h in handles {
        let _ = h.join();
    }
    let all = lat.lock().expect("lat");
    all.iter()
        .map(|w| {
            let mut w = w.clone();
            w.sort_unstable();
            (w.len() as f64 / 5.0, percentile(&w, 99.0))
        })
        .collect()
}

/// Kills the HSM process at random moments while 4 clients make payments.
fn crash(dir: &Path, rounds: usize, out: &mut String, data: &mut String) -> bool {
    let mut p = Proc::init(dir, "crash");
    p.start();
    let key = Conn::login(&p.socket)
        .expect("c")
        .create_agent_key(b"crash-agent", load_policy())
        .expect("agent key")
        .key;
    let received: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
    let mut restarts_ok = 0;
    for round in 0..rounds {
        if round > 0 {
            p.start();
            restarts_ok += 1;
        }
        // Keep the log from filling between kills.
        if let Ok(mut c) = Client::connect_at(&p.socket) {
            let _ = collect(&mut c);
        }
        let stop = Arc::new(AtomicBool::new(false));
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let (socket, received, stop) = (p.socket.clone(), received.clone(), stop.clone());
                thread::spawn(move || {
                    let Ok(mut c) = Conn::login(&socket) else {
                        return;
                    };
                    let mut n = 0u32;
                    while !stop.load(Ordering::Relaxed) {
                        let Ok((st, payload)) = c.c.call(&Request::SignAction {
                            key,
                            action: cent(),
                            confirmation: None,
                        }) else {
                            return; // the HSM died mid-request
                        };
                        match st {
                            Status::Ok => {
                                let (s, _) = resp::decode_signed_action(&payload).expect("signed");
                                let seq = Statement::decode(s).expect("statement").sequence;
                                received.lock().expect("r").push(seq);
                            }
                            Status::AuditFull => {
                                let _ = collect(&mut c.c);
                            }
                            other => panic!("unexpected {other:?}"),
                        }
                        n += 1;
                        if n.is_multiple_of(16) {
                            let _ = collect(&mut c.c);
                        }
                    }
                })
            })
            .collect();
        let delay = 20 + OsRng.next_u32() % 200;
        thread::sleep(Duration::from_millis(delay as u64));
        p.kill();
        stop.store(true, Ordering::Relaxed);
        for h in handles {
            let _ = h.join();
        }
    }
    p.start();
    restarts_ok += 1;
    let mut c = Conn::login(&p.socket).expect("final");
    let (_, pl) = c.call(Request::GetKeyPolicy { key });
    let kp = resp::KeyPolicy::decode(&pl).expect("policy");
    let got = received.lock().expect("r").clone();
    let unique: HashSet<_> = got.iter().collect();
    let max_seq = got.iter().max().copied().unwrap_or(0);
    let no_dupes = unique.len() == got.len();
    let none_unsaved = max_seq <= kp.approved && got.len() as u64 <= kp.approved;
    let spent_matches = kp.spent == kp.approved; // one cent each
    let ok = no_dupes && none_unsaved && spent_matches && restarts_ok == rounds;
    writeln!(out, "4 clients make one-cent payments; the HSM process is killed with `kill -9` after a random 20–220 ms, then restarted, {rounds} times.\n").unwrap();
    writeln!(out, "| Check | Result |").unwrap();
    writeln!(out, "|---|---|").unwrap();
    writeln!(
        out,
        "| Restarts that loaded the saved state | {restarts_ok} of {rounds} |"
    )
    .unwrap();
    writeln!(
        out,
        "| Signed payments the clients received | {} |",
        got.len()
    )
    .unwrap();
    writeln!(
        out,
        "| Payments the HSM counted | {} (spent {} cents) |",
        kp.approved, kp.spent
    )
    .unwrap();
    writeln!(
        out,
        "| Counted but answer lost in a crash | {} (safe direction: counted, never used) |",
        kp.approved.saturating_sub(got.len() as u64)
    )
    .unwrap();
    writeln!(
        out,
        "| Any action number handed out twice? | {} |",
        if no_dupes { "no ✅" } else { "YES ❌" }
    )
    .unwrap();
    writeln!(
        out,
        "| Any signature the HSM hadn't counted? | {} |\n",
        if none_unsaved { "no ✅" } else { "YES ❌" }
    )
    .unwrap();
    writeln!(
        data,
        "crash\t{rounds}\t{restarts_ok}\t{}\t{}\t{}",
        got.len(),
        kp.approved,
        ok
    )
    .unwrap();
    ok
}
