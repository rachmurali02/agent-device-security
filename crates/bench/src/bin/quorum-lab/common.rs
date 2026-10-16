//! Shared pieces: emulated HSMs (in this process or as a separate process
//! that can be killed), logged-in connections, admin sign-off, statistics.

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use quorum_client::Client;
use quorum_core::admin::{AdminOp, Approvals, MAX_PROPOSAL, Proposal};
use quorum_core::agent::{Action, ActionKind, CONFIRM_MESSAGE_MAX, Policy, confirmation_message};
use quorum_core::wire::{MAX_FRAME, Request, Status, resp};
use quorum_core::{Hsm as Core, Provisioning, Storage, StorageError};
use quorum_emulator::{Device, SlotStorage};
use rand_core::OsRng;

pub const PIN: &str = "123456";

pub fn admins() -> [SigningKey; 3] {
    [71, 72, 73].map(|b| SigningKey::from_bytes(&[b; 32]))
}

/// The user's confirmation device.
pub fn phone() -> SigningKey {
    SigningKey::from_bytes(&[74; 32])
}

pub fn admin_keys() -> [[u8; 32]; 3] {
    admins().map(|k| k.verifying_key().to_bytes())
}

/// Rules for load tests: payments of up to $1 never need the user; messages
/// always do; the budget never runs out.
pub fn load_policy() -> Policy {
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

/// A one-cent payment.
pub fn cent() -> Action<'static> {
    pay(1, b"shop.example")
}

pub fn pay(cents: u64, to: &'static [u8]) -> Action<'static> {
    Action {
        kind: ActionKind::Payment,
        amount: cents,
        target: to,
        details: b"",
        nonce: b"",
        expires: 0,
    }
}

/// Keeps state in memory (for timing the core without a disk).
pub struct MemStorage;

impl Storage for MemStorage {
    fn commit(&mut self, state: &[u8]) -> Result<(), StorageError> {
        std::hint::black_box(state);
        Ok(())
    }
}

pub fn provisioning() -> Provisioning<'static> {
    static KEYS: std::sync::OnceLock<[[u8; 32]; 3]> = std::sync::OnceLock::new();
    Provisioning {
        serial: *b"LAB0000000000001",
        pin: PIN.as_bytes(),
        admins: KEYS.get_or_init(admin_keys),
        threshold: 2,
    }
}

/// An emulated HSM served from this process (one thread per connection,
/// one command at a time, every save waits for the disk).
pub struct Hsm {
    pub socket: PathBuf,
}

pub fn start_hsm(dir: &Path, name: &str) -> Hsm {
    let socket = dir.join(format!("{name}.sock"));
    let _ = fs::remove_file(&socket);
    let mut storage = SlotStorage::create(&dir.join(format!("{name}.state"))).expect("state");
    let hsm = Core::provision(provisioning(), &mut OsRng, &mut storage).expect("provision");
    let listener = UnixListener::bind(&socket).expect("bind");
    thread::spawn(move || quorum_emulator::serve_with(listener, Device { hsm, storage }, false));
    Hsm { socket }
}

/// An agent key just created, with its birth certificate.
pub struct AgentKey {
    pub key: u32,
    pub cert: Vec<u8>,
    pub cert_sig: [u8; 64],
}

pub struct Conn {
    pub c: Client,
    pub serial: [u8; 16],
    pub identity: [u8; 32],
}

impl Conn {
    pub fn open(socket: &Path) -> io::Result<Conn> {
        let mut c = Client::connect_at(socket)?;
        let (_, p) = c.call(&Request::GetIdentity)?;
        let id = resp::Identity::decode(&p).expect("identity");
        Ok(Conn {
            c,
            serial: id.serial,
            identity: id.public,
        })
    }

    pub fn login(socket: &Path) -> io::Result<Conn> {
        let mut c = Conn::open(socket)?;
        let (s, _) = c.c.call(&Request::Login {
            pin: PIN.as_bytes(),
        })?;
        assert_eq!(s, Status::Ok, "login");
        Ok(c)
    }

    pub fn call(&mut self, req: Request<'_>) -> (Status, Vec<u8>) {
        self.c.call(&req).expect("hsm connection")
    }

    /// Admin sign-off on `op` by the admins numbered in `signers`.
    pub fn approvals(&mut self, op: AdminOp<'_>, signers: &[usize]) -> Approvals {
        let (_, p) = self.call(Request::GetAdminChallenge);
        let challenge = resp::decode_challenge(&p).expect("challenge");
        let mut buf = [0u8; MAX_PROPOSAL];
        let n = Proposal {
            serial: self.serial,
            challenge,
            op,
        }
        .encode(&mut buf)
        .expect("proposal");
        let mut a = Approvals::default();
        for &i in signers {
            a.push(i as u8, admins()[i].sign(&buf[..n]).to_bytes())
                .expect("approval");
        }
        a
    }

    pub fn create_agent_key(&mut self, label: &[u8], policy: Policy) -> Result<AgentKey, Status> {
        let op = AdminOp::CreateAgentKey {
            label,
            ext_id: b"",
            policy,
        };
        let approvals = self.approvals(op, &[0, 1]);
        match self.call(Request::GenerateAgentKey {
            label,
            ext_id: b"",
            policy,
            approvals,
        }) {
            (Status::Ok, p) => {
                let k = resp::AgentKeyCreated::decode(&p).expect("created");
                Ok(AgentKey {
                    key: k.key,
                    cert: k.cert.to_vec(),
                    cert_sig: k.cert_sig,
                })
            }
            (s, _) => Err(s),
        }
    }

    /// The user's confirmation for `action`, over a fresh challenge.
    pub fn confirm(&mut self, key: u32, action: &Action<'_>, device: &SigningKey) -> [u8; 64] {
        let (_, p) = self.call(Request::GetChallenge);
        let challenge = resp::decode_challenge(&p).expect("challenge");
        sign_confirmation(&self.serial, &challenge, key, action, device)
    }

    pub fn sign(
        &mut self,
        key: u32,
        action: Action<'_>,
        confirmation: Option<[u8; 64]>,
    ) -> (Status, Vec<u8>) {
        self.call(Request::SignAction {
            key,
            action,
            confirmation,
        })
    }
}

pub fn sign_confirmation(
    serial: &[u8; 16],
    challenge: &[u8; 32],
    key: u32,
    action: &Action<'_>,
    device: &SigningKey,
) -> [u8; 64] {
    let mut msg = [0u8; CONFIRM_MESSAGE_MAX];
    let n = confirmation_message(&mut msg, serial, challenge, key, action).expect("message");
    device.sign(&msg[..n]).to_bytes()
}

/// Copies the audit log out and releases it, like an audit collector.
pub fn collect(c: &mut Client) -> io::Result<()> {
    let (_, p) = c.call(&Request::ReadAudit { from: 0 })?;
    let batch = resp::AuditBatch::decode(&p).expect("audit batch");
    c.call(&Request::AckAudit {
        upto: batch.last_seq,
    })?;
    Ok(())
}

/// A connection that sends hand-made frames, bytes the normal client
/// refuses to produce.
pub struct Raw(UnixStream);

impl Raw {
    pub fn open(socket: &Path) -> io::Result<Raw> {
        let s = UnixStream::connect(socket)?;
        s.set_read_timeout(Some(Duration::from_secs(5)))?;
        Ok(Raw(s))
    }

    pub fn send_len(&mut self, len: u32) -> io::Result<()> {
        self.0.write_all(&len.to_le_bytes())
    }

    pub fn frame(&mut self, frame: &[u8]) -> io::Result<Vec<u8>> {
        self.0.write_all(&(frame.len() as u32).to_le_bytes())?;
        self.0.write_all(frame)?;
        self.read()
    }

    pub fn read(&mut self) -> io::Result<Vec<u8>> {
        let mut len = [0u8; 4];
        self.0.read_exact(&mut len)?;
        let len = u32::from_le_bytes(len) as usize;
        let mut out = vec![0u8; len.min(MAX_FRAME)];
        self.0.read_exact(&mut out)?;
        Ok(out)
    }

    pub fn request(&mut self, req: Request<'_>) -> io::Result<Status> {
        let mut buf = [0u8; MAX_FRAME];
        let n = req.encode(&mut buf).expect("encode");
        let r = self.frame(&buf[..n])?;
        Ok(resp::split(&r).expect("response").0)
    }

    pub fn raw_stream(&mut self) -> &mut UnixStream {
        &mut self.0
    }
}

/// The emulator as a separate process, so it can be killed at any moment
/// (`kill -9`: no chance to finish writing, like a power cut).
pub struct Proc {
    pub socket: PathBuf,
    pub state: PathBuf,
    child: Option<Child>,
}

fn emulator_bin() -> PathBuf {
    std::env::var_os("QUORUM_EMULATOR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::current_exe()
                .expect("exe")
                .with_file_name("quorum-emulator")
        })
}

impl Proc {
    /// Factory-provisions a state file with the lab's admins (2 of 3).
    pub fn init(dir: &Path, name: &str) -> Proc {
        let state = dir.join(format!("{name}.state"));
        let mut args = vec![
            "init".to_string(),
            "--state".into(),
            state.display().to_string(),
            "--pin".into(),
            PIN.into(),
            "--threshold".into(),
            "2".into(),
            "--force".into(),
        ];
        for (i, k) in admin_keys().iter().enumerate() {
            let f = dir.join(format!("{name}-admin{i}.pub"));
            fs::write(&f, hex(k)).expect("admin file");
            args.extend(["--admin".into(), f.display().to_string()]);
        }
        let ok = Command::new(emulator_bin())
            .args(&args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("run quorum-emulator (build it with: cargo build --release)")
            .success();
        assert!(ok, "quorum-emulator init failed");
        Proc {
            socket: dir.join(format!("{name}.sock")),
            state,
            child: None,
        }
    }

    pub fn start(&mut self) {
        let _ = fs::remove_file(&self.socket);
        let child = Command::new(emulator_bin())
            .arg("serve")
            .arg("--state")
            .arg(&self.state)
            .arg("--socket")
            .arg(&self.socket)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start emulator");
        self.child = Some(child);
        for _ in 0..500 {
            if UnixStream::connect(&self.socket).is_ok() {
                return;
            }
            thread::sleep(Duration::from_millis(2));
        }
        panic!("emulator did not start (state file rejected?)");
    }

    /// Kills the process without warning.
    pub fn kill(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        self.kill();
    }
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `p` in 0..=100 of sorted values.
pub fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let i = ((sorted.len() - 1) as f64 * p / 100.0).round() as usize;
    sorted[i]
}

/// Microseconds, human-readable.
pub fn fmt_us(us: u64) -> String {
    if us >= 10_000 {
        format!("{:.1} ms", us as f64 / 1000.0)
    } else if us >= 1000 {
        format!("{:.2} ms", us as f64 / 1000.0)
    } else {
        format!("{us} µs")
    }
}
