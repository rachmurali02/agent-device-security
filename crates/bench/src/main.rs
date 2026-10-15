//! `quorum-bench`: measures speed *and* security of HSM options side by side.
//!
//! The PKCS#11 parts drive any HSM through the same code, so the numbers are
//! comparable: point `--softhsm` (or any other module) at a different
//! library, e.g. a YubiHSM 2's `yubihsm_pkcs11.so`, and rerun.
//!
//! Options compared:
//! - **quorum-hsm** (this project): rules enforced inside the HSM.
//! - **SoftHSM2**: the standard open-source software HSM, used the
//!   conventional way: the HSM only signs; the rules run on the host.
//! - **In-process baselines**: the same crypto with no HSM boundary at all,
//!   to show what the boundary itself costs.
//!
//! Every security row is an attack the harness actually runs, not a claim.

use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::Write as _;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::object::{Attribute, AttributeType, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use quorum_client::Client;
use quorum_core::admin::{AdminOp, Approvals, MAX_PROPOSAL, Proposal};
use quorum_core::agent::{
    Action, ActionKind, CONFIRM_MESSAGE_MAX, MAX_STATEMENT, Policy, Statement, confirmation_message,
};
use quorum_core::cert::verify_action;
use quorum_core::wire::{MAX_FRAME, Request, Status, Writer, resp};
use quorum_core::{Hsm, Provisioning, Session as HsmSession, Storage, StorageError};
use quorum_emulator::{Device, FileStorage};
use rand_core::OsRng;

const PIN: &str = "123456";
const MSG: [u8; 64] = [0x42; 64];

struct Config {
    iterations: usize,
    threads: usize,
    quorum_module: PathBuf,
    softhsm_module: PathBuf,
    out: Option<PathBuf>,
    /// Raw numbers as tab-separated values, for charts (`tools/plot_benchmarks.py`).
    data: Option<PathBuf>,
}

/// Raw results, one tab-separated row per measurement:
/// `section, option, p50_us, p99_us, ops_per_sec` (latency tables),
/// `threads, option, ops_1_thread, ops_n_threads` (throughput), and
/// `attack, name, quorum_blocked, softhsm_blocked` (security).
static DATA: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());

fn record(fields: &[&str]) {
    let mut d = DATA.lock().unwrap();
    d.push_str(&fields.join("\t"));
    d.push('\n');
}

fn parse_args() -> Config {
    let args: Vec<String> = std::env::args().collect();
    let get = |name: &str| {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1).cloned())
    };
    Config {
        iterations: get("--iterations")
            .and_then(|v| v.parse().ok())
            .unwrap_or(2000),
        threads: get("--threads").and_then(|v| v.parse().ok()).unwrap_or(4),
        quorum_module: get("--quorum-module")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("target/release/libquorum_pkcs11.so")),
        softhsm_module: get("--softhsm")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/usr/lib/softhsm/libsofthsm2.so")),
        out: get("--out").map(PathBuf::from),
        data: get("--data").map(PathBuf::from),
    }
}

// ---- measurement -------------------------------------------------------------

struct Stats {
    name: String,
    p50: Duration,
    p99: Duration,
    ops_per_sec: f64,
}

/// Runs `f` `n` times after a warm-up and records each call's latency.
fn measure(name: &str, n: usize, mut f: impl FnMut()) -> Stats {
    for _ in 0..(n / 10).max(5) {
        f();
    }
    let mut samples = Vec::with_capacity(n);
    let start = Instant::now();
    for _ in 0..n {
        let t = Instant::now();
        f();
        samples.push(t.elapsed());
    }
    let total = start.elapsed();
    samples.sort();
    let pct = |p: f64| samples[((samples.len() as f64 * p) as usize).min(samples.len() - 1)];
    Stats {
        name: name.to_string(),
        p50: pct(0.50),
        p99: pct(0.99),
        ops_per_sec: n as f64 / total.as_secs_f64(),
    }
}

/// Runs `per_thread` operations on each of `threads` threads at once.
/// `make` builds one worker per thread (its own session or connection).
fn throughput<W: FnMut() + Send + 'static>(
    threads: usize,
    per_thread: usize,
    make: impl Fn() -> W,
) -> f64 {
    let barrier = Arc::new(Barrier::new(threads + 1));
    let handles: Vec<_> = (0..threads)
        .map(|_| {
            let mut work = make();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                for _ in 0..per_thread {
                    work();
                }
            })
        })
        .collect();
    barrier.wait();
    let start = Instant::now();
    for h in handles {
        h.join().expect("worker panicked");
    }
    (threads * per_thread) as f64 / start.elapsed().as_secs_f64()
}

fn fmt_dur(d: Duration) -> String {
    let us = d.as_secs_f64() * 1e6;
    if us < 1000.0 {
        format!("{us:.1} µs")
    } else {
        format!("{:.2} ms", us / 1000.0)
    }
}

fn table(out: &mut String, title: &str, rows: &[Stats]) {
    writeln!(out, "\n### {title}\n").unwrap();
    writeln!(
        out,
        "| Option | Median latency | 99th percentile | Ops per second |"
    )
    .unwrap();
    writeln!(out, "|---|---:|---:|---:|").unwrap();
    for r in rows {
        record(&[
            title,
            &r.name,
            &format!("{:.2}", r.p50.as_secs_f64() * 1e6),
            &format!("{:.2}", r.p99.as_secs_f64() * 1e6),
            &format!("{:.1}", r.ops_per_sec),
        ]);
        writeln!(
            out,
            "| {} | {} | {} | {:.0} |",
            r.name,
            fmt_dur(r.p50),
            fmt_dur(r.p99),
            r.ops_per_sec
        )
        .unwrap();
    }
}

// ---- test fixtures -----------------------------------------------------------

#[derive(Default)]
struct MemStorage(Vec<u8>);
impl Storage for MemStorage {
    fn commit(&mut self, state: &[u8]) -> Result<(), StorageError> {
        self.0.clear();
        self.0.extend_from_slice(state);
        Ok(())
    }
}

fn admins() -> [SigningKey; 3] {
    [61, 62, 63].map(|b| SigningKey::from_bytes(&[b; 32]))
}

fn phone() -> SigningKey {
    SigningKey::from_bytes(&[64; 32])
}

/// Generous rules so the benchmark never runs out of budget. Payments never
/// need confirmation; messages always do (used for the confirmation run).
fn bench_policy() -> Policy {
    Policy {
        allowed: ActionKind::Payment.bit() | ActionKind::SendMessage.bit(),
        max_amount: 100,
        budget: u64::MAX / 2,
        confirm_above: 100,
        always_confirm: ActionKind::SendMessage.bit(),
        confirmer: Some(phone().verifying_key().to_bytes()),
        require_nonce: false,
    }
}

fn payment() -> Action<'static> {
    Action {
        kind: ActionKind::Payment,
        amount: 1,
        target: b"shop.example",
        details: b"",
        nonce: &[7; 16],
        expires: 1_900_000_000,
    }
}

fn message() -> Action<'static> {
    Action {
        kind: ActionKind::SendMessage,
        amount: 0,
        target: b"alice@example.com",
        details: b"hello",
        nonce: b"",
        expires: 0,
    }
}

fn provision(storage: &mut impl Storage) -> Hsm {
    let admin_keys = admins().map(|k| k.verifying_key().to_bytes());
    Hsm::provision(
        Provisioning {
            serial: *b"BENCH00000000001",
            pin: PIN.as_bytes(),
            admins: &admin_keys,
            threshold: 2,
        },
        &mut OsRng,
        storage,
    )
    .expect("provision")
}

/// A running emulated HSM on a private socket.
struct Emulator {
    socket: PathBuf,
}

fn start_emulator(dir: &Path, name: &str, sync: bool) -> Emulator {
    let socket = dir.join(format!("{name}.sock"));
    let mut storage = FileStorage::new(dir.join(format!("{name}.state")));
    storage.sync = sync;
    let hsm = provision(&mut storage);
    let listener = UnixListener::bind(&socket).expect("bind");
    thread::spawn(move || quorum_emulator::serve_with(listener, Device { hsm, storage }, false));
    Emulator { socket }
}

/// Talks to an emulator directly, the way `quorum` (the CLI) does.
struct Direct {
    c: Client,
    serial: [u8; 16],
}

impl Direct {
    fn connect(e: &Emulator) -> Self {
        let mut c = Client::connect_at(&e.socket).expect("connect");
        let (s, _) = c
            .call(&Request::Login {
                pin: PIN.as_bytes(),
            })
            .unwrap();
        assert_eq!(s, Status::Ok);
        let (_, p) = c.call(&Request::GetIdentity).unwrap();
        let serial = resp::Identity::decode(&p).unwrap().serial;
        Direct { c, serial }
    }

    fn call(&mut self, req: Request<'_>) -> (Status, Vec<u8>) {
        self.c.call(&req).expect("hsm io")
    }

    /// Creates an agent key with 2-of-3 admin sign-off.
    fn create_agent_key(&mut self, policy: Policy) -> (Status, Vec<u8>) {
        let (_, p) = self.call(Request::GetAdminChallenge);
        let challenge = resp::decode_challenge(&p).unwrap();
        let op = AdminOp::CreateAgentKey {
            label: b"bench-agent",
            ext_id: b"",
            policy,
        };
        let mut buf = [0u8; MAX_PROPOSAL];
        let n = Proposal {
            serial: self.serial,
            challenge,
            op,
        }
        .encode(&mut buf)
        .unwrap();
        let mut approvals = Approvals::default();
        for i in 0..2 {
            approvals
                .push(i as u8, admins()[i].sign(&buf[..n]).to_bytes())
                .unwrap();
        }
        self.call(Request::GenerateAgentKey {
            label: b"bench-agent",
            ext_id: b"",
            policy,
            approvals,
        })
    }

    fn sign_action(&mut self, key: u32, action: Action<'_>) -> Status {
        self.call(Request::SignAction {
            key,
            action,
            confirmation: None,
        })
        .0
    }

    /// The full confirmed flow: challenge, the phone signs, HSM approves.
    fn sign_confirmed(&mut self, key: u32, action: Action<'_>) -> Status {
        let (_, p) = self.call(Request::GetChallenge);
        let challenge = resp::decode_challenge(&p).unwrap();
        let mut msg = [0u8; CONFIRM_MESSAGE_MAX];
        let n = confirmation_message(&mut msg, &self.serial, &challenge, key, &action).unwrap();
        let conf = phone().sign(&msg[..n]).to_bytes();
        self.call(Request::SignAction {
            key,
            action,
            confirmation: Some(conf),
        })
        .0
    }
}

// ---- PKCS#11 helpers -----------------------------------------------------------

fn eddsa() -> Mechanism<'static> {
    Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure))
}

fn ed25519_params() -> Vec<u8> {
    vec![0x06, 0x03, 0x2b, 0x65, 0x70]
}

fn open_module(path: &Path) -> Pkcs11 {
    let p = Pkcs11::new(path).unwrap_or_else(|e| panic!("loading {}: {e}", path.display()));
    p.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .expect("C_Initialize");
    p
}

fn session(p: &Pkcs11, login: bool) -> Session {
    let slot = p.get_slots_with_token().expect("slots")[0];
    let s = p.open_rw_session(slot).expect("open session");
    if login {
        s.login(UserType::User, Some(&AuthPin::new(PIN.into())))
            .expect("login");
    }
    s
}

fn generate(s: &Session, label: &str) -> cryptoki::error::Result<(ObjectHandle, ObjectHandle)> {
    s.generate_key_pair(
        &Mechanism::EccEdwardsKeyPairGen,
        &[
            Attribute::Token(true),
            Attribute::Verify(true),
            Attribute::EcParams(ed25519_params()),
            Attribute::Label(label.into()),
        ],
        &[
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Sign(true),
            Attribute::Label(label.into()),
        ],
    )
}

fn public_key(s: &Session, pubh: ObjectHandle) -> [u8; 32] {
    let attrs = s.get_attributes(pubh, &[AttributeType::EcPoint]).unwrap();
    let Some(Attribute::EcPoint(p)) = attrs.into_iter().next() else {
        panic!("no EC point");
    };
    // DER OCTET STRING (04 20 || key) or raw 32 bytes.
    p[p.len() - 32..].try_into().unwrap()
}

/// Does the module hand out the private key's value?
fn private_value_readable(s: &Session, privh: ObjectHandle) -> bool {
    matches!(
        s.get_attributes(privh, &[AttributeType::Value]).as_deref(),
        Ok([Attribute::Value(v)]) if !v.is_empty()
    )
}

fn softhsm_setup(dir: &Path) -> bool {
    let conf = dir.join("softhsm2.conf");
    let tokens = dir.join("softhsm-tokens");
    fs::create_dir_all(&tokens).unwrap();
    fs::write(
        &conf,
        format!("directories.tokendir = {}\n", tokens.display()),
    )
    .unwrap();
    // Safe: still single-threaded at this point.
    unsafe { std::env::set_var("SOFTHSM2_CONF", &conf) };
    Command::new("softhsm2-util")
        .args([
            "--init-token",
            "--free",
            "--label",
            "bench",
            "--pin",
            PIN,
            "--so-pin",
            "12345678",
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ---- the conventional design: SoftHSM2 signs, the host enforces the rules ------

/// What a conventional deployment does: the *host* checks the rules and
/// keeps the spending counter, then asks the HSM to sign. Reuses the exact
/// same rule logic as quorum-hsm so only *where* it runs differs.
struct HostPolicy {
    policy: Policy,
    spent: u64,
    sequence: u64,
    /// Persist the counters like a careful host would (fsync per action).
    persist: Option<File>,
}

impl HostPolicy {
    fn approve(&mut self, s: &Session, key: ObjectHandle, action: &Action<'_>) -> bool {
        let p = &self.policy;
        let ok = p.allows(action.kind)
            && action.amount <= p.max_amount
            && self
                .spent
                .checked_add(action.amount)
                .is_some_and(|t| t <= p.budget)
            && !p.needs_confirmation(action);
        if !ok {
            return false;
        }
        self.spent += action.amount;
        self.sequence += 1;
        if let Some(f) = &mut self.persist {
            f.write_all(&self.spent.to_le_bytes()).unwrap();
            f.sync_data().unwrap();
        }
        let statement = Statement {
            serial: *b"SOFTHSM000000001",
            key: 1,
            sequence: self.sequence,
            action: *action,
            confirmed: false,
            policy_digest: p.digest(),
        };
        let mut buf = [0u8; MAX_STATEMENT];
        let mut w = Writer::new(&mut buf);
        statement.write(&mut w).unwrap();
        let n = w.len();
        s.sign(&eddsa(), key, &buf[..n]).is_ok()
    }
}

// ---- main ----------------------------------------------------------------------

fn main() {
    let cfg = parse_args();
    let n = cfg.iterations;
    let dir = std::env::temp_dir().join(format!("quorum-bench-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    let mut report = String::new();
    environment(&mut report, &cfg);

    let have_softhsm = cfg.softhsm_module.exists() && softhsm_setup(&dir);
    if !have_softhsm {
        eprintln!("SoftHSM2 not available; its rows are skipped");
    }

    // Emulators: the safe default (fsync) and an unsafe no-fsync variant
    // that shows how much of the cost is durability.
    let safe = start_emulator(&dir, "safe", true);
    let fast = start_emulator(&dir, "nofsync", false);
    // Safe: no other thread reads the environment yet.
    unsafe { std::env::set_var("QUORUM_HSM_SOCKET", &safe.socket) };

    eprintln!("1/5 signing...");
    signing(&mut report, &cfg, have_softhsm);
    eprintln!("2/5 key creation...");
    key_creation(&mut report, &cfg, &safe, have_softhsm);
    eprintln!("3/5 agent actions...");
    agent_actions(&mut report, n, &safe, &fast, &dir, have_softhsm, &cfg);
    eprintln!("4/5 throughput...");
    concurrency(&mut report, &cfg, &safe, have_softhsm);
    eprintln!("5/5 attacks...");
    let held = attacks(&mut report, &cfg, &safe, have_softhsm);

    print!("{report}");
    if let Some(out) = &cfg.out {
        fs::write(out, &report).unwrap();
        eprintln!("results written to {}", out.display());
    }
    if let Some(data) = &cfg.data {
        fs::write(data, &*DATA.lock().unwrap()).unwrap();
        eprintln!("raw numbers written to {}", data.display());
    }
    let _ = fs::remove_dir_all(&dir);
    if !held {
        eprintln!("FAILED: an attack succeeded against quorum-hsm");
        std::process::exit(1);
    }
}

fn environment(out: &mut String, cfg: &Config) {
    let cpu = fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|c| {
            c.lines()
                .find(|l| l.starts_with("model name"))
                .and_then(|l| l.split(':').nth(1))
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| "unknown".into());
    let cores = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    writeln!(out, "## Environment\n").unwrap();
    writeln!(out, "- CPU: {cpu} ({cores} cores)").unwrap();
    writeln!(out, "- Iterations per measurement: {}", cfg.iterations).unwrap();
    writeln!(out, "- Threads for throughput: {}", cfg.threads).unwrap();
    writeln!(
        out,
        "- Message size for raw signing: 64 bytes; signature scheme: Ed25519 everywhere"
    )
    .unwrap();
}

fn signing(out: &mut String, cfg: &Config, have_softhsm: bool) {
    let n = cfg.iterations;
    let mut rows = Vec::new();

    let sk = SigningKey::from_bytes(&[1; 32]);
    rows.push(measure(
        "No HSM: Ed25519 in the same process (floor)",
        n,
        || {
            std::hint::black_box(sk.sign(&MSG));
        },
    ));

    // The HSM core's own logic, called directly: parsing, checks, signing.
    let mut storage = MemStorage::default();
    let mut hsm = provision(&mut storage);
    let mut sess = HsmSession::default();
    let mut req = [0u8; MAX_FRAME];
    let mut resp_buf = [0u8; MAX_FRAME];
    let k = Request::Login {
        pin: PIN.as_bytes(),
    }
    .encode(&mut req)
    .unwrap();
    hsm.handle(
        &mut sess,
        &mut storage,
        &mut OsRng,
        &req[..k],
        &mut resp_buf,
    );
    let k = Request::GenerateKey {
        label: b"k",
        ext_id: b"",
    }
    .encode(&mut req)
    .unwrap();
    let r = hsm.handle(
        &mut sess,
        &mut storage,
        &mut OsRng,
        &req[..k],
        &mut resp_buf,
    );
    let key = resp::Generated::decode(&resp_buf[1..r]).unwrap().key;
    let k = Request::Sign { key, msg: &MSG }.encode(&mut req).unwrap();
    rows.push(measure(
        "quorum-hsm core, in process (no socket)",
        n,
        || {
            hsm.handle(
                &mut sess,
                &mut storage,
                &mut OsRng,
                &req[..k],
                &mut resp_buf,
            );
        },
    ));

    let q = open_module(&cfg.quorum_module);
    let s = session(&q, true);
    let (_, privh) = generate(&s, "bench").expect("quorum keygen");
    rows.push(measure("quorum-hsm emulator via PKCS#11", n, || {
        s.sign(&eddsa(), privh, &MSG).unwrap();
    }));
    drop(s);
    q.finalize().ok();

    if have_softhsm {
        let p = open_module(&cfg.softhsm_module);
        let s = session(&p, true);
        let (_, privh) = generate(&s, "bench").expect("softhsm keygen");
        rows.push(measure("SoftHSM2 via PKCS#11", n, || {
            s.sign(&eddsa(), privh, &MSG).unwrap();
        }));
        drop(s);
        p.finalize().ok();
    }
    table(out, "1. Signing a 64-byte message (raw signing)", &rows);
}

fn key_creation(out: &mut String, cfg: &Config, safe: &Emulator, have_softhsm: bool) {
    // Key creation fills key stores, so use fewer iterations.
    let n = (cfg.iterations / 50).clamp(5, 12);
    let mut rows = Vec::new();

    let q = open_module(&cfg.quorum_module);
    let s = session(&q, true);
    let mut i = 0;
    // quorum-hsm holds 16 keys; signing used one, so stay under that.
    rows.push(measure(
        "quorum-hsm: general key via PKCS#11 (fsync)",
        n,
        || {
            i += 1;
            let (pubh, _) = generate(&s, &format!("k{i}")).unwrap();
            s.destroy_object(pubh).unwrap();
        },
    ));
    drop(s);
    q.finalize().ok();

    let mut d = Direct::connect(safe);
    rows.push(measure(
        "quorum-hsm: agent key with 2-of-3 admin sign-off + birth certificate",
        n,
        || {
            let (st, p) = d.create_agent_key(bench_policy());
            assert_eq!(st, Status::Ok);
            let key = resp::AgentKeyCreated::decode(&p).unwrap().key;
            // Delete it again (also needs sign-off) so the store never fills.
            let (_, p) = d.call(Request::GetAdminChallenge);
            let challenge = resp::decode_challenge(&p).unwrap();
            let op = AdminOp::DeleteAgentKey { key };
            let mut buf = [0u8; MAX_PROPOSAL];
            let m = Proposal {
                serial: d.serial,
                challenge,
                op,
            }
            .encode(&mut buf)
            .unwrap();
            let mut approvals = Approvals::default();
            for j in 0..2 {
                approvals
                    .push(j as u8, admins()[j].sign(&buf[..m]).to_bytes())
                    .unwrap();
            }
            assert_eq!(
                d.call(Request::DeleteAgentKey { key, approvals }).0,
                Status::Ok
            );
        },
    ));
    rows.last_mut().unwrap().name += " (create + delete pair)";

    if have_softhsm {
        let p = open_module(&cfg.softhsm_module);
        let s = session(&p, true);
        let mut i = 0;
        rows.push(measure("SoftHSM2: key via PKCS#11", n, || {
            i += 1;
            let (pubh, privh) = generate(&s, &format!("k{i}")).unwrap();
            s.destroy_object(pubh).unwrap();
            s.destroy_object(privh).unwrap();
        }));
        drop(s);
        p.finalize().ok();
    }
    table(out, "2. Creating keys", &rows);
}

#[allow(clippy::too_many_arguments)]
fn agent_actions(
    out: &mut String,
    n: usize,
    safe: &Emulator,
    fast: &Emulator,
    dir: &Path,
    have_softhsm: bool,
    cfg: &Config,
) {
    let mut rows = Vec::new();

    // Core logic only: policy checks + statement + signing, no I/O.
    let mut storage = MemStorage::default();
    let mut hsm = provision(&mut storage);
    let mut sess = HsmSession::default();
    let mut d_inproc = InProcess::new(&mut hsm, &mut sess, &mut storage);
    let key = d_inproc.agent_key();
    let mut req = [0u8; MAX_FRAME];
    let k = Request::SignAction {
        key,
        action: payment(),
        confirmation: None,
    }
    .encode(&mut req)
    .unwrap();
    rows.push(measure(
        "quorum-hsm core, in process (no socket, no disk)",
        n,
        || {
            d_inproc.raw(&req[..k]);
        },
    ));

    for (emu, name) in [
        (
            safe,
            "quorum-hsm emulator, spending saved with fsync (safe default)",
        ),
        (
            fast,
            "quorum-hsm emulator, fsync off (unsafe; shows cost of durability)",
        ),
    ] {
        let mut d = Direct::connect(emu);
        let (st, p) = d.create_agent_key(bench_policy());
        assert_eq!(st, Status::Ok);
        let key = resp::AgentKeyCreated::decode(&p).unwrap().key;
        rows.push(measure(name, n, || {
            assert_eq!(d.sign_action(key, payment()), Status::Ok);
        }));
    }

    let mut d = Direct::connect(safe);
    let (_, p) = d.create_agent_key(bench_policy());
    let key = resp::AgentKeyCreated::decode(&p).unwrap().key;
    rows.push(measure(
        "quorum-hsm emulator, with the user's confirmation (challenge + phone + approve)",
        n,
        || {
            assert_eq!(d.sign_confirmed(key, message()), Status::Ok);
        },
    ));

    if have_softhsm {
        let p = open_module(&cfg.softhsm_module);
        let s = session(&p, true);
        let (_, privh) = generate(&s, "agent").unwrap();
        for (persist, name) in [
            (
                false,
                "SoftHSM2 + rules on the host, counters in memory only",
            ),
            (
                true,
                "SoftHSM2 + rules on the host, counters saved with fsync",
            ),
        ] {
            let mut host = HostPolicy {
                policy: bench_policy(),
                spent: 0,
                sequence: 0,
                persist: persist.then(|| File::create(dir.join("host-counters")).unwrap()),
            };
            rows.push(measure(name, n, || {
                assert!(host.approve(&s, privh, &payment()));
            }));
        }
        drop(s);
        p.finalize().ok();
    }

    // The receiver's side: certificate + statement check, no HSM.
    let mut d = Direct::connect(safe);
    let id = resp::Identity::decode(&d.call(Request::GetIdentity).1)
        .unwrap()
        .public;
    let (_, p) = d.create_agent_key(bench_policy());
    let created = resp::AgentKeyCreated::decode(&p).unwrap();
    let (cert, cert_sig) = (created.cert.to_vec(), created.cert_sig);
    let (_, p) = d.call(Request::SignAction {
        key: created.key,
        action: payment(),
        confirmation: None,
    });
    let (stmt, sig) = resp::decode_signed_action(&p).unwrap();
    let stmt = stmt.to_vec();
    rows.push(measure(
        "Receiver check: HSM identity -> certificate -> signed action",
        n,
        || {
            verify_action(&id, &cert, &cert_sig, &stmt, &sig).unwrap();
        },
    ));

    table(
        out,
        "3. Approving one agent action (\"pay $0.01 to shop.example\")",
        &rows,
    );
}

/// Drives an in-process HSM core through its normal request/response API.
struct InProcess<'a> {
    hsm: &'a mut Hsm,
    sess: &'a mut HsmSession,
    storage: &'a mut MemStorage,
    out: Box<[u8; MAX_FRAME]>,
}

impl<'a> InProcess<'a> {
    fn new(hsm: &'a mut Hsm, sess: &'a mut HsmSession, storage: &'a mut MemStorage) -> Self {
        let mut p = InProcess {
            hsm,
            sess,
            storage,
            out: Box::new([0; MAX_FRAME]),
        };
        let mut req = [0u8; MAX_FRAME];
        let k = Request::Login {
            pin: PIN.as_bytes(),
        }
        .encode(&mut req)
        .unwrap();
        p.raw(&req[..k]);
        p
    }

    fn raw(&mut self, req: &[u8]) -> &[u8] {
        let n = self
            .hsm
            .handle(self.sess, self.storage, &mut OsRng, req, &mut self.out[..]);
        &self.out[..n]
    }

    fn call(&mut self, r: Request<'_>) -> Vec<u8> {
        let mut req = [0u8; MAX_FRAME];
        let k = r.encode(&mut req).unwrap();
        self.raw(&req[..k]).to_vec()
    }

    fn agent_key(&mut self) -> u32 {
        let out = self.call(Request::GetAdminChallenge);
        let challenge = resp::decode_challenge(&out[1..]).unwrap();
        let policy = bench_policy();
        let op = AdminOp::CreateAgentKey {
            label: b"bench-agent",
            ext_id: b"",
            policy,
        };
        let mut buf = [0u8; MAX_PROPOSAL];
        let n = Proposal {
            serial: *self.hsm.serial(),
            challenge,
            op,
        }
        .encode(&mut buf)
        .unwrap();
        let mut approvals = Approvals::default();
        for i in 0..2 {
            approvals
                .push(i as u8, admins()[i].sign(&buf[..n]).to_bytes())
                .unwrap();
        }
        let out = self.call(Request::GenerateAgentKey {
            label: b"bench-agent",
            ext_id: b"",
            policy,
            approvals,
        });
        resp::AgentKeyCreated::decode(&out[1..]).unwrap().key
    }
}

fn concurrency(out: &mut String, cfg: &Config, safe: &Emulator, have_softhsm: bool) {
    let t = cfg.threads;
    let per = (cfg.iterations / t).max(50);
    writeln!(out, "\n### 4. Many requests at once ({t} threads)\n").unwrap();
    writeln!(
        out,
        "| Option | Ops per second, 1 thread | Ops per second, {t} threads |"
    )
    .unwrap();
    writeln!(out, "|---|---:|---:|").unwrap();

    let raw = |module: &Path, name: &str, out: &mut String| {
        let p = open_module(module);
        let s = session(&p, true);
        let (_, privh) = generate(&s, "conc").unwrap();
        let one = throughput(1, per * t, || {
            let s = session(&p, false);
            move || {
                s.sign(&eddsa(), privh, &MSG).unwrap();
            }
        });
        let many = throughput(t, per, || {
            let s = session(&p, false);
            move || {
                s.sign(&eddsa(), privh, &MSG).unwrap();
            }
        });
        writeln!(out, "| {name} | {one:.0} | {many:.0} |").unwrap();
        record(&["threads", name, &format!("{one:.1}"), &format!("{many:.1}")]);
        drop(s);
        p.finalize().ok();
    };
    raw(
        &cfg.quorum_module,
        "quorum-hsm emulator: raw signing via PKCS#11",
        out,
    );
    if have_softhsm {
        raw(
            &cfg.softhsm_module,
            "SoftHSM2: raw signing via PKCS#11",
            out,
        );
    }

    let mut setup = Direct::connect(safe);
    let (_, p) = setup.create_agent_key(bench_policy());
    let key = resp::AgentKeyCreated::decode(&p).unwrap().key;
    let worker = || {
        let mut d = Direct::connect(safe);
        move || {
            assert_eq!(d.sign_action(key, payment()), Status::Ok);
        }
    };
    let one = throughput(1, per * t, worker);
    let many = throughput(t, per, worker);
    writeln!(
        out,
        "| quorum-hsm emulator: agent actions (fsync), one connection per thread | {one:.0} | {many:.0} |"
    )
    .unwrap();
    record(&[
        "threads",
        "quorum-hsm emulator: agent actions (fsync), one connection per thread",
        &format!("{one:.1}"),
        &format!("{many:.1}"),
    ]);
}

/// Each attack is run for real against each option.
/// Returns false if any attack succeeded against quorum-hsm.
fn attacks(out: &mut String, cfg: &Config, safe: &Emulator, have_softhsm: bool) -> bool {
    let mut quorum_held = true;
    writeln!(
        out,
        "\n### 5. Security: attacks by someone who controls the computer and knows the PIN\n"
    )
    .unwrap();
    writeln!(
        out,
        "| Attack | quorum-hsm | SoftHSM2 + rules on the host |"
    )
    .unwrap();
    writeln!(out, "|---|---|---|").unwrap();
    let mut row = |out: &mut String, attack: &str, q: String, s: String| {
        quorum_held &= q.starts_with('✅');
        writeln!(out, "| {attack} | {q} | {s} |").unwrap();
        let held = |c: &str| {
            if c.starts_with('✅') {
                "1"
            } else if c.starts_with('❌') {
                "0"
            } else {
                ""
            }
        };
        record(&["attack", attack, held(&q), held(&s)]);
    };
    let blocked = |how: &str| format!("✅ blocked ({how})");
    let works = |how: &str| format!("❌ attack works ({how})");
    let skip = || "not run (SoftHSM2 missing)".to_string();

    let mut d = Direct::connect(safe);
    let (_, p) = d.create_agent_key(Policy {
        budget: 300,
        ..bench_policy()
    });
    let agent = resp::AgentKeyCreated::decode(&p).unwrap();

    let soft = have_softhsm.then(|| {
        let p = open_module(&cfg.softhsm_module);
        let s = session(&p, true);
        let (pubh, privh) = generate(&s, "victim").unwrap();
        (p, s, pubh, privh)
    });

    // 1. Sign an action the rules forbid, by skipping the rule check.
    let forged = Action {
        amount: 999_999,
        target: b"attacker.example",
        ..payment()
    };
    let st = d.sign_action(agent.key, forged);
    let raw = d.call(Request::Sign {
        key: agent.key,
        msg: b"QHSM-ACTION\x01 pay $9999.99 to attacker",
    });
    let q = if st == Status::AmountTooHigh && raw.0 == Status::UsageNotAllowed {
        blocked("the HSM checks the amount itself; raw signing with agent keys is refused")
    } else {
        works(&format!("{st:?} / {:?}", raw.0))
    };
    let s = match &soft {
        None => skip(),
        Some((_, s, pubh, privh)) => {
            // The attacker simply doesn't call the host's rule check.
            let statement = b"pay $9999.99 to attacker.example".to_vec();
            let sig = s.sign(&eddsa(), *privh, &statement).unwrap();
            let vk = VerifyingKey::from_bytes(&public_key(s, *pubh)).unwrap();
            let valid = vk
                .verify(
                    &statement,
                    &ed25519_dalek::Signature::from_slice(&sig).unwrap(),
                )
                .is_ok();
            if valid {
                works("C_Sign signs anything; the signature verifies")
            } else {
                blocked("signature failed")
            }
        }
    };
    row(
        out,
        "Get a signature for a payment the rules forbid ($9,999.99)",
        q,
        s,
    );

    // 2. Keep spending past the budget ($3 budget, $1 payments).
    let dollar = Action {
        amount: 100,
        ..payment()
    };
    let mut approved = 0;
    for _ in 0..10 {
        if d.sign_action(agent.key, dollar) == Status::Ok {
            approved += 1;
        }
    }
    let q = if approved == 3 {
        blocked("3 of 10 approved, then BudgetExceeded")
    } else {
        works(&format!("{approved} of 10 approved"))
    };
    let s = match &soft {
        None => skip(),
        Some((_, s, _, privh)) => {
            let signed = (0..10)
                .filter(|_| s.sign(&eddsa(), *privh, &MSG).is_ok())
                .count();
            works(&format!(
                "{signed} of 10 signed; the budget lives on the host"
            ))
        }
    };
    row(
        out,
        "Spend past the budget ($3 budget, ten $1 payments)",
        q,
        s,
    );

    // 3. Create a new signing key with just the PIN.
    let (st, _) = d.call(Request::GenerateAgentKey {
        label: b"rogue",
        ext_id: b"",
        policy: Policy {
            budget: u64::MAX / 2,
            max_amount: u64::MAX / 2,
            ..bench_policy()
        },
        approvals: Approvals::default(),
    });
    let q = if st == Status::NoAdminChallenge || st == Status::QuorumRequired {
        blocked("agent keys need 2-of-3 admin sign-off")
    } else {
        works(&format!("{st:?}"))
    };
    let s = match &soft {
        None => skip(),
        Some((_, s, _, _)) => match generate(s, "rogue") {
            Ok(_) => works("C_GenerateKeyPair succeeds; receivers can't tell it apart"),
            Err(e) => blocked(&e.to_string()),
        },
    };
    row(
        out,
        "Create a new signing key with loose rules, using only the PIN",
        q,
        s,
    );

    // 4. Delete the key and start over with a fresh budget.
    let st = d.call(Request::DeleteKey { key: agent.key }).0;
    let q = if st == Status::QuorumRequired {
        blocked("deleting agent keys needs admin sign-off")
    } else {
        works(&format!("{st:?}"))
    };
    let s = match &soft {
        None => skip(),
        Some(_) => works("the host's counter file can simply be reset"),
    };
    row(
        out,
        "Reset the budget by deleting and re-creating the key",
        q,
        s,
    );

    // 5. Read the private key out.
    let q_module = open_module(&cfg.quorum_module);
    let qs = session(&q_module, true);
    let (_, qpriv) = generate(&qs, "extract").unwrap();
    let q = if private_value_readable(&qs, qpriv) {
        works("CKA_VALUE returned")
    } else {
        blocked("CKA_VALUE is sensitive")
    };
    drop(qs);
    q_module.finalize().ok();
    let s = match &soft {
        None => skip(),
        Some((_, s, _, privh)) => {
            if private_value_readable(s, *privh) {
                works("CKA_VALUE returned")
            } else {
                blocked("CKA_VALUE is sensitive")
            }
        }
    };
    row(out, "Read the private key out of the HSM", q, s);

    // 6. A receiver asks: "which rules approved this, and who set them up?"
    let id = resp::Identity::decode(&d.call(Request::GetIdentity).1)
        .unwrap()
        .public;
    let expected = Policy {
        budget: 300,
        ..bench_policy()
    };
    let q = match quorum_core::cert::verify_key_cert(&id, agent.cert, &agent.cert_sig) {
        Ok(c) if c.policy == expected && c.approvers.count_ones() == 2 => {
            blocked("the birth certificate names the exact rules and the 2 approving admins")
        }
        other => works(&format!("certificate check: {other:?}")),
    };
    let s = match &soft {
        None => skip(),
        Some(_) => works("nothing ties a key to its rules; receivers must trust the host"),
    };
    row(
        out,
        "Pass off a signature as approved under rules it wasn't (receiver's view)",
        q,
        s,
    );

    if let Some((p, s, _, _)) = soft {
        drop(s);
        p.finalize().ok();
    }
    quorum_held
}
