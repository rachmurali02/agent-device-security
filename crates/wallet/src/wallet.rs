//! The wallet itself: one connection to the HSM, the list of actions agents
//! asked for, and the user's approvals.
//!
//! The HSM makes every decision. The wallet only asks, waits for the user
//! when the HSM says "this needs the user's OK", and keeps a copy of the
//! audit log so the HSM's log never fills up.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use quorum_client::Client;
use quorum_core::agent::{
    Action, ActionKind, CONFIRM_MESSAGE_MAX, Policy, Statement, confirmation_message,
};
use quorum_core::audit::{ENTRY_LEN, Entry, Event, verify_log};
use quorum_core::wire::{KeyUsage, Request, SERIAL_LEN, Status, resp};
use serde_json::{Value, json};

/// How long an approval request waits for the user before it lapses.
pub const APPROVAL_TIMEOUT: Duration = Duration::from_secs(10 * 60);

pub type Result<T> = std::result::Result<T, String>;

/// Where the HSM is: the emulator's socket or a board's serial port.
#[derive(Debug, Clone)]
pub enum Target {
    Socket(PathBuf),
    Serial(String),
}

impl Target {
    /// `QUORUM_HSM_SERIAL` if set (a real board), else the emulator socket.
    pub fn from_env() -> Self {
        match std::env::var(quorum_client::SERIAL_ENV) {
            Ok(dev) => Target::Serial(dev),
            Err(_) => Target::Socket(quorum_client::socket_path()),
        }
    }

    fn connect(&self) -> std::io::Result<Client> {
        match self {
            Target::Socket(p) => Client::connect_at(p),
            Target::Serial(d) => Client::connect_serial(d),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Target::Socket(p) => format!("emulator at {}", p.display()),
            Target::Serial(d) => format!("board on {d}"),
        }
    }
}

/// One logged-in session with the HSM. Reconnects (and logs in again) after
/// the board is unplugged, but never resends a request that may have
/// reached it: a lost answer to "sign this" must not become two signatures.
struct Hsm {
    target: Target,
    pin: String,
    client: Option<Client>,
}

impl Hsm {
    fn call(&mut self, req: Request<'_>) -> Result<(Status, Vec<u8>)> {
        if self.client.is_none() {
            let mut c = self
                .target
                .connect()
                .map_err(|e| format!("cannot reach the HSM ({}): {e}", self.target.describe()))?;
            let (status, _) = c
                .call(&Request::Login {
                    pin: self.pin.as_bytes(),
                })
                .map_err(|e| format!("HSM connection failed: {e}"))?;
            if status != Status::Ok && status != Status::AlreadyLoggedIn {
                return Err(format!("login failed: {}", quorum_client::explain(status)));
            }
            self.client = Some(c);
        }
        let client = self.client.as_mut().ok_or("not connected")?;
        match client.call(&req) {
            Ok(r) => Ok(r),
            Err(e) => {
                self.client = None;
                Err(format!("HSM connection lost: {e}"))
            }
        }
    }

    /// A call that must succeed.
    fn ok(&mut self, req: Request<'_>) -> Result<Vec<u8>> {
        match self.call(req)? {
            (Status::Ok, payload) => Ok(payload),
            (s, _) => Err(format!("HSM refused: {}", quorum_client::explain(s))),
        }
    }
}

/// What an agent asks for.
#[derive(Debug, Clone)]
pub struct ActionRequest {
    pub key: u32,
    pub kind: ActionKind,
    /// Cents; 0 unless it's a payment.
    pub amount: u64,
    pub to: String,
    pub details: String,
    /// The receiver's one-time code and expiry, if it gave one.
    pub nonce: Vec<u8>,
    pub expires: u64,
    /// The agent's own explanation, shown to the user. Not signed, and not
    /// trusted: the user's approval covers the action itself.
    pub reason: String,
}

impl ActionRequest {
    fn action(&self) -> Action<'_> {
        Action {
            kind: self.kind,
            amount: self.amount,
            target: self.to.as_bytes(),
            details: self.details.as_bytes(),
            nonce: &self.nonce,
            expires: self.expires,
        }
    }

    pub fn describe(&self) -> String {
        describe(&self.action())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// Waiting for the user.
    Pending,
    Signed,
    /// The HSM said no (its rules).
    Refused,
    /// The user said no.
    Denied,
    /// Nobody answered in time.
    Expired,
    /// Something went wrong talking to the HSM.
    Failed,
}

impl Stage {
    fn name(self) -> &'static str {
        match self {
            Stage::Pending => "waiting_for_user",
            Stage::Signed => "signed",
            Stage::Refused => "refused_by_hsm",
            Stage::Denied => "denied_by_user",
            Stage::Expired => "expired",
            Stage::Failed => "failed",
        }
    }
}

struct Item {
    id: u64,
    created: u64,
    started: Instant,
    request: ActionRequest,
    stage: Stage,
    /// Why it was refused or failed, in plain English.
    why: Option<String>,
    /// The signed proof, once signed.
    proof: Option<Value>,
}

impl Item {
    fn json(&self) -> Value {
        let mut v = json!({
            "id": self.id,
            "created": self.created,
            "status": self.stage.name(),
            "key": self.request.key,
            "kind": self.request.kind.name(),
            "to": self.request.to,
            "amount": dollars(self.request.amount),
            "amount_cents": self.request.amount,
            "details": self.request.details,
            "description": self.request.describe(),
            "agent_reason": self.request.reason,
        });
        if let Some(why) = &self.why {
            v["why"] = json!(why);
        }
        if let Some(proof) = &self.proof {
            v["proof"] = proof.clone();
        }
        v
    }
}

#[derive(Default)]
struct State {
    next_id: u64,
    items: Vec<Item>,
}

pub struct Wallet {
    hsm: Mutex<Hsm>,
    /// The key that says "yes, the user approved". See the README: in this
    /// version it lives with the wallet, not on a separate phone.
    approver: SigningKey,
    dir: PathBuf,
    serial: [u8; SERIAL_LEN],
    identity: [u8; 32],
    state: Mutex<State>,
    changed: Condvar,
}

impl Wallet {
    /// Connects, logs in, and reads who the HSM is.
    pub fn open(target: Target, pin: String, approver: SigningKey, dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir.join("proofs")).map_err(|e| format!("{}: {e}", dir.display()))?;
        let mut hsm = Hsm {
            target,
            pin,
            client: None,
        };
        let id = resp::Identity::decode(&hsm.ok(Request::GetIdentity)?)
            .map_err(|e| format!("bad reply: {e:?}"))?;
        fs::write(dir.join("hsm.id"), hex(&id.public)).map_err(|e| e.to_string())?;
        let w = Wallet {
            hsm: Mutex::new(hsm),
            approver,
            dir: dir.to_path_buf(),
            serial: id.serial,
            identity: id.public,
            state: Mutex::new(State {
                next_id: 1,
                items: Vec::new(),
            }),
            changed: Condvar::new(),
        };
        w.sync_audit()?;
        Ok(w)
    }

    fn hsm(&self) -> MutexGuard<'_, Hsm> {
        self.hsm.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn state(&self) -> MutexGuard<'_, State> {
        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        // Lapse approvals nobody answered.
        for it in s.items.iter_mut() {
            if it.stage == Stage::Pending && it.started.elapsed() > APPROVAL_TIMEOUT {
                it.stage = Stage::Expired;
                it.why = Some("nobody approved it in time".into());
            }
        }
        s
    }

    /// The board, its agent keys and what each may still do.
    pub fn status(&self) -> Result<Value> {
        let mut hsm = self.hsm();
        let info = resp::Info::decode(&hsm.ok(Request::GetInfo)?).map_err(bad)?;
        let list = hsm.ok(Request::ListKeys)?;
        let mut keys = Vec::new();
        for e in resp::decode_key_list(&list).map_err(bad)? {
            if e.usage != KeyUsage::Agent {
                continue;
            }
            let kp = resp::KeyPolicy::decode(&hsm.ok(Request::GetKeyPolicy { key: e.key })?)
                .map_err(bad)?;
            keys.push(policy_json(e.key, &String::from_utf8_lossy(e.label), &kp));
        }
        Ok(json!({
            "hsm": {
                "serial": String::from_utf8_lossy(&info.serial),
                "identity": hex(&self.identity),
                "connection": hsm.target.describe(),
                "pin_tries_left": info.pin_tries_left,
            },
            "agent_keys": keys,
        }))
    }

    /// An agent asks for an action. Returns at once: signed, refused, or
    /// waiting for the user.
    pub fn request(&self, req: ActionRequest) -> Result<Value> {
        req.action().validate().map_err(|_| {
            "invalid action: use plain printable text, a recipient of 1-64 characters, \
             details up to 128, and an amount only for payments"
                .to_string()
        })?;
        let (stage, why, proof) = self.sign(&req, false);
        let mut s = self.state();
        let id = s.next_id;
        s.next_id += 1;
        let item = Item {
            id,
            created: now(),
            started: Instant::now(),
            request: req,
            stage,
            why,
            proof,
        };
        let v = item.json();
        if stage != Stage::Pending {
            self.record(&item);
        }
        s.items.push(item);
        drop(s);
        self.changed.notify_all();
        Ok(v)
    }

    /// The user approved request `id`: sign the confirmation and ask again.
    pub fn approve(&self, id: u64) -> Result<Value> {
        let req = {
            let s = self.state();
            let it = s
                .items
                .iter()
                .find(|i| i.id == id)
                .ok_or("no such request")?;
            if it.stage != Stage::Pending {
                return Err(format!("request {id} is already {}", it.stage.name()));
            }
            it.request.clone()
        };
        let (stage, why, proof) = self.sign(&req, true);
        self.finish(id, stage, why, proof)
    }

    /// The user said no.
    pub fn deny(&self, id: u64) -> Result<Value> {
        self.finish(id, Stage::Denied, Some("you declined".into()), None)
    }

    fn finish(
        &self,
        id: u64,
        stage: Stage,
        why: Option<String>,
        proof: Option<Value>,
    ) -> Result<Value> {
        let mut s = self.state();
        let it = s
            .items
            .iter_mut()
            .find(|i| i.id == id)
            .ok_or("no such request")?;
        if it.stage != Stage::Pending {
            return Err(format!("request {id} is already {}", it.stage.name()));
        }
        it.stage = stage;
        it.why = why;
        it.proof = proof;
        let v = it.json();
        let snapshot = Item {
            id: it.id,
            created: it.created,
            started: it.started,
            request: it.request.clone(),
            stage: it.stage,
            why: it.why.clone(),
            proof: it.proof.clone(),
        };
        drop(s);
        self.record(&snapshot);
        self.changed.notify_all();
        Ok(v)
    }

    /// Waits until request `id` is no longer waiting for the user, or until
    /// `timeout`.
    pub fn wait(&self, id: u64, timeout: Duration) -> Result<Value> {
        let deadline = Instant::now() + timeout;
        let mut s = self.state();
        loop {
            let it = s
                .items
                .iter()
                .find(|i| i.id == id)
                .ok_or("no such request")?;
            let left = deadline.saturating_duration_since(Instant::now());
            if it.stage != Stage::Pending || left.is_zero() {
                return Ok(it.json());
            }
            s = self
                .changed
                .wait_timeout(s, left)
                .unwrap_or_else(|p| p.into_inner())
                .0;
        }
    }

    pub fn get(&self, id: u64) -> Result<Value> {
        let s = self.state();
        s.items
            .iter()
            .find(|i| i.id == id)
            .map(Item::json)
            .ok_or_else(|| "no such request".into())
    }

    /// Every request this session, newest first.
    pub fn requests(&self) -> Value {
        let s = self.state();
        Value::Array(s.items.iter().rev().map(Item::json).collect())
    }

    /// Asks the HSM to sign, with the user's confirmation if `confirmed`.
    fn sign(&self, req: &ActionRequest, confirmed: bool) -> (Stage, Option<String>, Option<Value>) {
        let result = (|| {
            let mut hsm = self.hsm();
            let action = req.action();
            let confirmation = if confirmed {
                let challenge =
                    resp::decode_challenge(&hsm.ok(Request::GetChallenge)?).map_err(bad)?;
                let mut msg = [0u8; CONFIRM_MESSAGE_MAX];
                let n = confirmation_message(&mut msg, &self.serial, &challenge, req.key, &action)
                    .map_err(bad)?;
                Some(self.approver.sign(&msg[..n]).to_bytes())
            } else {
                None
            };
            let (status, payload) = hsm.call(Request::SignAction {
                key: req.key,
                action,
                confirmation,
            })?;
            let outcome = match status {
                Status::Ok => {
                    let proof = self.proof(&mut hsm, req.key, &payload)?;
                    (Stage::Signed, None, Some(proof))
                }
                Status::ConfirmationRequired if !confirmed => (Stage::Pending, None, None),
                s => (
                    Stage::Refused,
                    Some(quorum_client::explain(s).to_string()),
                    None,
                ),
            };
            Ok::<_, String>(outcome)
        })();
        // Copy the log out after every action so the HSM never fills up.
        let _ = self.sync_audit();
        result.unwrap_or_else(|e| (Stage::Failed, Some(e), None))
    }

    /// Everything a receiver needs to check the action without trusting
    /// this computer: the statement, its signature, and the key's birth
    /// certificate. Also saved as files `quorum verify` understands.
    fn proof(&self, hsm: &mut Hsm, key: u32, payload: &[u8]) -> Result<Value> {
        let (statement, sig) = resp::decode_signed_action(payload).map_err(bad)?;
        let s = Statement::decode(statement).map_err(bad)?;
        let cert_payload = hsm.ok(Request::GetKeyCert { key })?;
        let (cert, cert_sig) = resp::decode_cert(&cert_payload).map_err(bad)?;

        let base = self
            .dir
            .join("proofs")
            .join(format!("key{key}-{}", s.sequence));
        let cert_base = self.dir.join("proofs").join(format!("key{key}"));
        for (path, bytes) in [
            (ext(&base, ".statement"), statement),
            (ext(&base, ".sig"), &sig[..]),
            (ext(&cert_base, ".cert"), cert),
            (ext(&cert_base, ".cert.sig"), &cert_sig[..]),
        ] {
            fs::write(&path, bytes).map_err(|e| format!("{}: {e}", path.display()))?;
        }
        Ok(json!({
            "hsm_serial": String::from_utf8_lossy(&s.serial),
            "hsm_identity": hex(&self.identity),
            "key": key,
            "sequence": s.sequence,
            "confirmed_by_user": s.confirmed,
            "approved": describe(&s.action),
            "statement": hex(statement),
            "signature": hex(&sig),
            "certificate": hex(cert),
            "certificate_signature": hex(&cert_sig),
            "files": {
                "statement": ext(&base, ".statement"),
                "signature": ext(&base, ".sig"),
                "certificate": ext(&cert_base, ".cert"),
            },
            "check_with": format!(
                "quorum verify --hsm-identity {} --cert {} --signed {}",
                self.dir.join("hsm.id").display(),
                cert_base.display(),
                base.display()
            ),
        }))
    }

    /// Appends one finished request to `history.jsonl`.
    fn record(&self, item: &Item) {
        let path = self.dir.join("history.jsonl");
        let line = format!("{}\n", item.json());
        let _ = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
            .and_then(|mut f| f.write_all(line.as_bytes()));
    }

    fn audit_path(&self) -> PathBuf {
        self.dir.join("audit.log")
    }

    /// Copies new audit entries to `audit.log` (saved to disk first, then
    /// released on the HSM), exactly like `quorum audit pull`.
    pub fn sync_audit(&self) -> Result<u64> {
        let path = self.audit_path();
        let have = read_log(&path)?.len() as u64;
        let mut hsm = self.hsm();
        let payload = hsm.ok(Request::ReadAudit { from: have + 1 })?;
        let batch = resp::AuditBatch::decode(&payload).map_err(bad)?;
        let new: Vec<_> = batch.entries().collect();
        if let Some(first) = new.first() {
            let seq = Entry::decode(&first[..]).map_err(bad)?.seq;
            if seq != have + 1 {
                return Err(format!(
                    "audit entries {} to {} are missing",
                    have + 1,
                    seq - 1
                ));
            }
        } else if batch.last_seq > have {
            return Err(format!(
                "audit entries {} to {} are missing",
                have + 1,
                batch.last_seq
            ));
        }
        if !new.is_empty() {
            let mut f = OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(&path)
                .map_err(|e| e.to_string())?;
            for e in &new {
                f.write_all(&e[..]).map_err(|e| e.to_string())?;
            }
            f.sync_all().map_err(|e| e.to_string())?;
            hsm.ok(Request::AckAudit {
                upto: batch.last_seq,
            })?;
        }
        Ok(have + new.len() as u64)
    }

    /// The audit log, checked against a fresh HSM-signed checkpoint.
    pub fn audit(&self) -> Result<Value> {
        self.sync_audit()?;
        let payload = self.hsm().ok(Request::AuditCheckpoint)?;
        let (cp, sig) = resp::decode_checkpoint(&payload).map_err(bad)?;
        let entries = read_log(&self.audit_path())?;
        let verdict = match verify_log(&self.identity, cp, &sig, entries.iter()) {
            Ok(c) => json!({ "valid": true, "entries": c.seq }),
            Err(e) => json!({ "valid": false, "problem": format!("{e:?}") }),
        };
        let recent: Vec<Value> = entries
            .iter()
            .rev()
            .take(50)
            .filter_map(|b| Entry::decode(&b[..]).ok())
            .map(|e| json!({ "seq": e.seq, "what": describe_entry(&e) }))
            .collect();
        Ok(json!({ "verdict": verdict, "recent": recent }))
    }
}

fn bad<E: std::fmt::Debug>(e: E) -> String {
    format!("unexpected reply from HSM: {e:?}")
}

fn read_log(path: &Path) -> Result<Vec<[u8; ENTRY_LEN]>> {
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    if !data.len().is_multiple_of(ENTRY_LEN) {
        return Err(format!("{}: not an audit log file", path.display()));
    }
    Ok(data.as_chunks::<ENTRY_LEN>().0.to_vec())
}

fn ext(path: &Path, ext: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(ext);
    PathBuf::from(s)
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

pub fn dollars(cents: u64) -> String {
    format!("${}.{:02}", cents / 100, cents % 100)
}

pub fn describe(a: &Action<'_>) -> String {
    let to = String::from_utf8_lossy(a.target);
    let mut s = match a.kind {
        ActionKind::Payment => format!("pay {} to {to}", dollars(a.amount)),
        ActionKind::SendMessage => format!("send a message to {to}"),
        ActionKind::InstallSoftware => format!("install {to}"),
        ActionKind::ShareData => format!("share data with {to}"),
        ActionKind::DeleteData => format!("delete {to}"),
    };
    if !a.details.is_empty() {
        s += &format!(" ({})", String::from_utf8_lossy(a.details));
    }
    s
}

fn kinds(mask: u16) -> Vec<&'static str> {
    ActionKind::ALL
        .iter()
        .filter(|k| mask & k.bit() != 0)
        .map(|k| k.name())
        .collect()
}

fn policy_json(key: u32, label: &str, kp: &resp::KeyPolicy) -> Value {
    let p: &Policy = &kp.policy;
    json!({
        "key": key,
        "label": label,
        "allowed": kinds(p.allowed),
        "max_per_payment": dollars(p.max_amount),
        "budget": dollars(p.budget),
        "spent": dollars(kp.spent),
        "left": dollars(p.budget.saturating_sub(kp.spent)),
        "budget_cents": p.budget,
        "spent_cents": kp.spent,
        "user_ok_above": dollars(p.confirm_above),
        "user_ok_always_for": kinds(p.always_confirm),
        "needs_receiver_request": p.require_nonce,
        "actions_approved": kp.approved,
    })
}

fn describe_entry(e: &Entry) -> String {
    let why = |s: u8| {
        Status::try_from(s)
            .map(quorum_client::explain)
            .unwrap_or("unknown reason")
    };
    match e.event {
        Event::Provisioned => "HSM created".into(),
        Event::LoginOk => "logged in".into(),
        Event::LoginFailed => "wrong PIN".into(),
        Event::KeyCreated => format!("key {} created", e.key),
        Event::KeyDeleted => format!("key {} deleted", e.key),
        Event::AgentKeyCreated => format!("agent key {} created (admins approved)", e.key),
        Event::AgentKeyDeleted => format!("agent key {} deleted (admins approved)", e.key),
        Event::PolicyUpdated => format!("agent key {} rules changed (admins approved)", e.key),
        Event::AdminsChanged => "admins replaced".into(),
        Event::ActionApproved => format!("key {}: approved {}", e.key, dollars(e.amount)),
        Event::ActionRefused => format!(
            "key {}: REFUSED {}: {}",
            e.key,
            dollars(e.amount),
            why(e.status)
        ),
        Event::AdminRequestRefused => format!("admin request REFUSED: {}", why(e.status)),
        Event::FaultDetected => "FAULT DETECTED: the HSM stopped".into(),
    }
}
