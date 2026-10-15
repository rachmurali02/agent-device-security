//! `quorum`: command-line tool for agent keys.
//!
//! It plays every role so the whole story can run on one machine:
//! - **admins**, who must sign off before an agent key is created or deleted
//!   (`admin new / propose-* / approve / submit`)
//! - the **agent**, asking the HSM to approve an action (`act`)
//! - the **user's confirmation device**, a phone with a trusted screen and an
//!   "Approve" button (`confirmer new`, and `act --confirm-with`)
//! - the **receiver** (a shop): it issues a one-time payment request
//!   (`shop request`) and checks the signed action it gets back (`verify`)
//!
//! None of these roles can make the HSM break its rules: every decision is
//! made inside the HSM.

use std::fs;
use std::io::{self, BufRead, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use quorum_client::Client;
use quorum_core::admin::{AdminOp, Approvals, MAX_PROPOSAL, Proposal};
use quorum_core::agent::{
    Action, ActionKind, CONFIRM_MESSAGE_MAX, Policy, VerifyError, confirmation_message,
};
use quorum_core::cert::{ActionError, CertError, KeyCert, verify_action};
use quorum_core::wire::{KeyUsage, Request, Status, resp};
use rand_core::{OsRng, RngCore};

#[derive(Parser)]
#[command(name = "quorum", about = "Agent keys for the quorum HSM", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show who this HSM is: serial, identity key, admins.
    Identity {
        /// Also save the identity public key here (to give to receivers).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// List the keys on the HSM.
    Keys,
    /// Admin sign-off for creating and deleting agent keys.
    #[command(subcommand)]
    Admin(AdminCmd),
    /// Inspect agent keys.
    #[command(subcommand)]
    AgentKey(AgentKeyCmd),
    /// Simulated user confirmation device (the user's phone).
    #[command(subcommand)]
    Confirmer(KeyFileCmd),
    /// Simulated receiver (a shop) issuing one-time payment requests.
    #[command(subcommand)]
    Shop(ShopCmd),
    /// Ask the HSM to approve and sign an agent action.
    Act(ActArgs),
    /// Check a signed action, as the receiver, with no HSM involved.
    Verify(VerifyArgs),
}

#[derive(Args)]
struct Login {
    /// User PIN.
    #[arg(long, env = "QUORUM_PIN", hide_env_values = true)]
    pin: String,
}

#[derive(Subcommand)]
enum KeyFileCmd {
    /// Create a new key pair. Writes the secret to <out> and the public key
    /// to <out>.pub.
    New {
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
enum AdminCmd {
    /// Create a new admin key pair (secret in <out>, public in <out>.pub).
    New {
        #[arg(long)]
        out: PathBuf,
    },
    /// Start a proposal to create an agent key with these rules.
    ProposeCreate(ProposeCreateArgs),
    /// Start a proposal to delete an agent key.
    ProposeDelete {
        #[command(flatten)]
        login: Login,
        #[arg(long)]
        key: u32,
        /// Where to write the proposal for admins to review.
        #[arg(long)]
        out: PathBuf,
    },
    /// Review a proposal as an admin and sign it if you agree.
    Approve {
        #[arg(long)]
        proposal: PathBuf,
        /// Your admin secret key file.
        #[arg(long = "as")]
        admin: PathBuf,
        /// Agree without asking (for scripts).
        #[arg(long)]
        yes: bool,
        /// Where to write your approval.
        #[arg(long)]
        out: PathBuf,
    },
    /// Send a proposal with enough approvals to the HSM.
    Submit {
        #[command(flatten)]
        login: Login,
        #[arg(long)]
        proposal: PathBuf,
        #[arg(long = "approval", required = true)]
        approvals: Vec<PathBuf>,
        /// For a new key: where to save its birth certificate.
        #[arg(long)]
        cert_out: Option<PathBuf>,
    },
}

#[derive(Args)]
struct ProposeCreateArgs {
    #[command(flatten)]
    login: Login,
    #[arg(long)]
    label: String,
    /// Allowed action kinds, comma-separated:
    /// send_message, payment, install_software, share_data, delete_data.
    #[arg(long, value_delimiter = ',', required = true)]
    allow: Vec<String>,
    /// Largest single payment, in dollars (e.g. 50 or 49.99).
    #[arg(long, default_value = "0")]
    max_amount: String,
    /// Total that may ever be spent, in dollars.
    #[arg(long, default_value = "0")]
    budget: String,
    /// Payments above this many dollars need the user's confirmation.
    #[arg(long, default_value = "0")]
    confirm_above: String,
    /// Kinds that always need the user's confirmation.
    #[arg(long, value_delimiter = ',')]
    always_confirm: Vec<String>,
    /// The user's confirmation device (a public key file from `confirmer new`).
    #[arg(long)]
    confirmer: Option<PathBuf>,
    /// Refuse actions that don't carry a receiver's one-time code.
    #[arg(long)]
    require_request: bool,
    /// Where to write the proposal for admins to review.
    #[arg(long)]
    out: PathBuf,
}

#[derive(Subcommand)]
enum AgentKeyCmd {
    /// Show a key's rules and how much of its budget is used.
    Show {
        #[arg(long)]
        key: u32,
    },
    /// Save a key's birth certificate (to give to receivers).
    Cert {
        #[arg(long)]
        key: u32,
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
enum ShopCmd {
    /// Create a one-time payment request: a random code plus "valid until".
    Request {
        /// How long the request is valid, in seconds.
        #[arg(long, default_value = "300")]
        valid_for: u64,
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Args)]
struct ActArgs {
    #[command(flatten)]
    login: Login,
    #[arg(long)]
    key: u32,
    /// send_message, payment, install_software, share_data or delete_data.
    #[arg(long)]
    kind: String,
    /// Who or what the action is for (recipient, app, file...).
    #[arg(long)]
    to: String,
    /// Payment amount in dollars.
    #[arg(long, default_value = "0")]
    amount: String,
    #[arg(long, default_value = "")]
    details: String,
    /// The receiver's one-time payment request (from `shop request`).
    #[arg(long)]
    request: Option<PathBuf>,
    /// Ask the user's confirmation device (secret file from `confirmer new`).
    #[arg(long)]
    confirm_with: Option<PathBuf>,
    /// Answer "yes" on the confirmation device without asking (for scripts).
    #[arg(long)]
    yes: bool,
    /// Write the signed action to <out>.statement and <out>.sig.
    #[arg(long)]
    out: PathBuf,
}

#[derive(Args)]
struct VerifyArgs {
    /// The HSM's identity public key file (from `identity --out`).
    #[arg(long)]
    hsm_identity: PathBuf,
    /// The agent key's birth certificate (prefix from `agent-key cert`).
    #[arg(long)]
    cert: PathBuf,
    /// The signed action (prefix used with `act --out`).
    #[arg(long)]
    signed: PathBuf,
    /// The payment request this action must answer. Each request is
    /// accepted once; it also must not have expired.
    #[arg(long)]
    request: Option<PathBuf>,
}

fn main() -> ExitCode {
    match run(Cli::parse().command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

type Result<T> = std::result::Result<T, String>;

fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::Identity { out } => identity(out.as_deref()),
        Command::Keys => list_keys(),
        Command::Admin(AdminCmd::New { out }) => new_key_file(&out, "admin"),
        Command::Admin(AdminCmd::ProposeCreate(args)) => propose_create(args),
        Command::Admin(AdminCmd::ProposeDelete { login, key, out }) => {
            propose(&login, AdminOp::DeleteAgentKey { key }, &out)
        }
        Command::Admin(AdminCmd::Approve {
            proposal,
            admin,
            yes,
            out,
        }) => approve(&proposal, &admin, yes, &out),
        Command::Admin(AdminCmd::Submit {
            login,
            proposal,
            approvals,
            cert_out,
        }) => submit(&login, &proposal, &approvals, cert_out.as_deref()),
        Command::AgentKey(AgentKeyCmd::Show { key }) => show_agent_key(key),
        Command::AgentKey(AgentKeyCmd::Cert { key, out }) => save_cert(key, &out),
        Command::Confirmer(KeyFileCmd::New { out }) => new_key_file(&out, "confirmation device"),
        Command::Shop(ShopCmd::Request { valid_for, out }) => shop_request(valid_for, &out),
        Command::Act(args) => act(args),
        Command::Verify(args) => verify(args),
    }
}

// ---- talking to the HSM ----------------------------------------------------

struct Hsm(Client);

impl Hsm {
    fn connect() -> Result<Self> {
        Client::connect().map(Hsm).map_err(|e| {
            format!(
                "Cannot reach the HSM at {} ({e}). Is quorum-emulator running?",
                quorum_client::socket_path().display()
            )
        })
    }

    fn call(&mut self, req: Request<'_>) -> Result<Vec<u8>> {
        let (status, payload) = self.0.call(&req).map_err(|e| format!("HSM error: {e}"))?;
        match status {
            Status::Ok => Ok(payload),
            s => Err(explain(s)),
        }
    }

    fn login(&mut self, login: &Login) -> Result<()> {
        self.call(Request::Login {
            pin: login.pin.as_bytes(),
        })
        .map(drop)
    }

    fn identity(&mut self) -> Result<resp::Identity> {
        resp::Identity::decode(&self.call(Request::GetIdentity)?).map_err(bad_reply)
    }
}

fn bad_reply<E: std::fmt::Debug>(e: E) -> String {
    format!("unexpected reply from HSM: {e:?}")
}

/// Plain-English reasons for every HSM refusal.
fn explain(s: Status) -> String {
    let why = match s {
        Status::Ok => "OK",
        Status::BadRequest => "the HSM rejected the request as malformed",
        Status::NotLoggedIn => "you need to log in with the PIN first",
        Status::AlreadyLoggedIn => "already logged in",
        Status::PinIncorrect => "wrong PIN (the attempt was counted)",
        Status::PinLocked => "the HSM is locked after too many wrong PINs",
        Status::KeyNotFound => "there is no key with that number",
        Status::StoreFull => "the HSM has no room for more keys",
        Status::ResponseTooLarge => "the reply would be too large",
        Status::Fault => "the HSM hit a storage fault and has stopped (restart it)",
        Status::UsageNotAllowed => "that key cannot be used this way (is it an agent key?)",
        Status::ActionNotAllowed => "this key's rules do not allow that kind of action",
        Status::AmountTooHigh => "the amount is over this key's limit for a single payment",
        Status::BudgetExceeded => "this would go over the key's total spending budget",
        Status::ConfirmationRequired => {
            "this action needs the user's confirmation (use --confirm-with <device>)"
        }
        Status::ConfirmationInvalid => {
            "the confirmation is not valid for this exact action from this user's device"
        }
        Status::NoChallenge => "the confirmation has expired or was already used",
        Status::NonceRequired => {
            "this key only acts on a receiver's payment request (use --request <file>)"
        }
        Status::QuorumRequired => {
            "this needs sign-off from enough admins (see `quorum admin --help`)"
        }
        Status::ApprovalInvalid => {
            "an approval is not valid for this exact proposal, or is from an unknown or repeated admin"
        }
        Status::NoAdminChallenge => {
            "the proposal has expired or was already used (start a new one)"
        }
    };
    format!("DENIED by HSM: {why}")
}

// ---- formatting helpers ----------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex<const N: usize>(s: &str) -> Result<[u8; N]> {
    let s = s.trim();
    if s.len() != 2 * N || !s.is_ascii() {
        return Err(format!("expected {} hex characters", 2 * N));
    }
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

fn read_hex_file<const N: usize>(path: &Path) -> Result<[u8; N]> {
    let text = fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    unhex(&text).map_err(|e| format!("{}: {e}", path.display()))
}

fn read_file(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))
}

fn write_file(path: &Path, data: &[u8]) -> Result<()> {
    fs::write(path, data).map_err(|e| format!("writing {}: {e}", path.display()))
}

/// "49.99" -> 4999 cents. Rejects anything ambiguous.
fn parse_dollars(s: &str) -> Result<u64> {
    let bad = || format!("not a dollar amount: {s:?} (use e.g. 20 or 19.99)");
    let (whole, cents) = match s.split_once('.') {
        None => (s, "00"),
        Some((w, c)) if c.len() == 2 => (w, c),
        Some(_) => return Err(bad()),
    };
    if whole.is_empty() || !whole.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    let whole: u64 = whole.parse().map_err(|_| bad())?;
    let cents: u64 = cents.parse().map_err(|_| bad())?;
    whole
        .checked_mul(100)
        .and_then(|w| w.checked_add(cents))
        .ok_or_else(bad)
}

fn dollars(cents: u64) -> String {
    format!("${}.{:02}", cents / 100, cents % 100)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn kind(name: &str) -> Result<ActionKind> {
    ActionKind::from_name(name.trim()).ok_or_else(|| {
        let all: Vec<_> = ActionKind::ALL.iter().map(|k| k.name()).collect();
        format!(
            "unknown action kind {name:?}; use one of: {}",
            all.join(", ")
        )
    })
}

fn kinds_mask(names: &[String]) -> Result<u16> {
    names.iter().try_fold(0, |m, n| Ok(m | kind(n)?.bit()))
}

fn kinds_list(mask: u16) -> String {
    let names: Vec<_> = ActionKind::ALL
        .iter()
        .filter(|k| mask & k.bit() != 0)
        .map(|k| k.name())
        .collect();
    if names.is_empty() {
        "none".into()
    } else {
        names.join(", ")
    }
}

/// One-line plain-English description, as a confirmation screen shows it.
fn describe(a: &Action<'_>) -> String {
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
    if !a.nonce.is_empty() {
        s += &format!(", for request {}", hex(a.nonce));
    }
    s
}

fn describe_policy(p: &Policy) -> Vec<String> {
    let mut lines = vec![format!("allowed actions:   {}", kinds_list(p.allowed))];
    if p.allows(ActionKind::Payment) {
        lines.push(format!("max per payment:   {}", dollars(p.max_amount)));
        lines.push(format!("total budget:      {}", dollars(p.budget)));
        lines.push(format!(
            "needs user OK:     payments over {}",
            dollars(p.confirm_above)
        ));
    }
    if p.always_confirm != 0 {
        lines.push(format!(
            "always needs OK:   {}",
            kinds_list(p.always_confirm)
        ));
    }
    lines.push(format!(
        "user's device:     {}",
        p.confirmer
            .map(|k| hex(&k))
            .unwrap_or_else(|| "none (actions needing OK are impossible)".into())
    ));
    lines.push(format!(
        "receiver's code:   {}",
        if p.require_nonce {
            "required on every action"
        } else {
            "optional"
        }
    ));
    lines
}

fn describe_op(serial: &[u8; 16], op: &AdminOp<'_>) -> Vec<String> {
    let hsm = String::from_utf8_lossy(serial);
    match op {
        AdminOp::CreateAgentKey { label, policy, .. } => {
            let mut lines = vec![format!(
                "Create agent key \"{}\" on HSM {hsm} with these rules:",
                String::from_utf8_lossy(label)
            )];
            lines.extend(
                describe_policy(policy)
                    .into_iter()
                    .map(|l| format!("  {l}")),
            );
            lines
        }
        AdminOp::DeleteAgentKey { key } => vec![format!("Delete agent key {key} on HSM {hsm}")],
    }
}

fn ask_yes(prompt: &str, auto_yes: bool) -> bool {
    print!("  {prompt} [y/N] ");
    if auto_yes {
        println!("y (auto)");
        return true;
    }
    io::stdout().flush().ok();
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line).ok();
    matches!(line.trim(), "y" | "Y" | "yes")
}

fn with_ext(path: &Path, ext: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(ext);
    PathBuf::from(s)
}

// ---- commands --------------------------------------------------------------

fn identity(out: Option<&Path>) -> Result<()> {
    let id = Hsm::connect()?.identity()?;
    println!("HSM serial:      {}", String::from_utf8_lossy(&id.serial));
    println!("identity key:    {}", hex(&id.public));
    let admins = id.admins.keys();
    if admins.is_empty() {
        println!("admins:          none (agent keys cannot be created)");
    } else {
        println!(
            "sign-off needed: {} of {} admins",
            id.admins.threshold(),
            admins.len()
        );
        for (i, k) in admins.iter().enumerate() {
            println!("  admin #{i}:      {}", hex(k));
        }
    }
    if let Some(out) = out {
        write_file(out, hex(&id.public).as_bytes())?;
        println!("saved identity key to {}", out.display());
    }
    Ok(())
}

fn list_keys() -> Result<()> {
    let mut hsm = Hsm::connect()?;
    let payload = hsm.call(Request::ListKeys)?;
    let list = resp::decode_key_list(&payload).map_err(bad_reply)?;
    println!("{:>4}  {:<8}  {:<20}  public key", "key", "type", "label");
    for e in list {
        let usage = match e.usage {
            KeyUsage::General => "general",
            KeyUsage::Agent => "agent",
        };
        println!(
            "{:>4}  {:<8}  {:<20}  {}",
            e.key,
            usage,
            String::from_utf8_lossy(e.label),
            hex(&e.public)
        );
    }
    Ok(())
}

fn new_key_file(out: &Path, what: &str) -> Result<()> {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let key = SigningKey::from_bytes(&secret);
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(out)
        .and_then(|mut f| f.write_all(hex(&secret).as_bytes()))
        .map_err(|e| format!("writing {}: {e}", out.display()))?;
    let public = with_ext(out, ".pub");
    write_file(&public, hex(&key.verifying_key().to_bytes()).as_bytes())?;
    println!("Created {what} key.");
    println!("  secret (keep it private): {}", out.display());
    println!("  public (share it):        {}", public.display());
    Ok(())
}

fn propose_create(args: ProposeCreateArgs) -> Result<()> {
    let confirmer = args
        .confirmer
        .as_deref()
        .map(read_hex_file::<32>)
        .transpose()?;
    let policy = Policy {
        allowed: kinds_mask(&args.allow)?,
        max_amount: parse_dollars(&args.max_amount)?,
        budget: parse_dollars(&args.budget)?,
        confirm_above: parse_dollars(&args.confirm_above)?,
        always_confirm: kinds_mask(&args.always_confirm)?,
        confirmer,
        require_nonce: args.require_request,
    };
    policy
        .validate()
        .map_err(|_| "those rules are not valid".to_string())?;
    let op = AdminOp::CreateAgentKey {
        label: args.label.as_bytes(),
        ext_id: b"",
        policy,
    };
    propose(&args.login, op, &args.out)
}

/// Gets a one-time admin challenge and writes the proposal file: exactly the
/// bytes each admin will sign.
fn propose(login: &Login, op: AdminOp<'_>, out: &Path) -> Result<()> {
    let mut hsm = Hsm::connect()?;
    hsm.login(login)?;
    let id = hsm.identity()?;
    let challenge =
        resp::decode_challenge(&hsm.call(Request::GetAdminChallenge)?).map_err(bad_reply)?;
    let proposal = Proposal {
        serial: id.serial,
        challenge,
        op,
    };
    let mut buf = [0u8; MAX_PROPOSAL];
    let n = proposal.encode(&mut buf).map_err(|e| format!("{e:?}"))?;
    write_file(out, &buf[..n])?;
    for line in describe_op(&id.serial, &op) {
        println!("{line}");
    }
    println!(
        "Proposal written to {}. It needs {} admin approvals and is cancelled \
         if the HSM restarts or another proposal is started.",
        out.display(),
        id.admins.threshold()
    );
    Ok(())
}

/// The admin's own tool: works offline, shows exactly what is being
/// approved, and signs only on "yes". The approval file holds the admin's
/// public key and signature.
fn approve(proposal: &Path, admin: &Path, auto_yes: bool, out: &Path) -> Result<()> {
    let bytes = read_file(proposal)?;
    let p = Proposal::decode(&bytes).map_err(|_| "not a valid proposal file".to_string())?;
    let signer = SigningKey::from_bytes(&read_hex_file::<32>(admin)?);

    println!("+-------------------- admin review --------------------+");
    for line in describe_op(&p.serial, &p.op) {
        println!("  {line}");
    }
    let yes = ask_yes("Approve?", auto_yes);
    println!("+------------------------------------------------------+");
    if !yes {
        return Err("You declined. Nothing was signed.".into());
    }
    let mut approval = signer.verifying_key().to_bytes().to_vec();
    approval.extend_from_slice(&signer.sign(&bytes).to_bytes());
    write_file(out, &approval)?;
    println!("Approval written to {}", out.display());
    Ok(())
}

fn submit(
    login: &Login,
    proposal: &Path,
    approval_files: &[PathBuf],
    cert_out: Option<&Path>,
) -> Result<()> {
    let bytes = read_file(proposal)?;
    let p = Proposal::decode(&bytes).map_err(|_| "not a valid proposal file".to_string())?;
    let mut hsm = Hsm::connect()?;
    hsm.login(login)?;
    let id = hsm.identity()?;

    // Match each approval to its admin number on this HSM.
    let mut approvals = Approvals::default();
    for file in approval_files {
        let data = read_file(file)?;
        if data.len() != 96 {
            return Err(format!("{}: not an approval file", file.display()));
        }
        let index = id
            .admins
            .keys()
            .iter()
            .position(|k| k[..] == data[..32])
            .ok_or_else(|| format!("{}: signed by someone who is not an admin", file.display()))?;
        let sig: [u8; 64] = data[32..].try_into().map_err(|_| "bad approval")?;
        approvals
            .push(index as u8, sig)
            .map_err(|_| "too many approvals")?;
    }

    match p.op {
        AdminOp::CreateAgentKey {
            label,
            ext_id,
            policy,
        } => {
            let payload = hsm.call(Request::GenerateAgentKey {
                label,
                ext_id,
                policy,
                approvals,
            })?;
            let c = resp::AgentKeyCreated::decode(&payload).map_err(bad_reply)?;
            println!(
                "Created agent key {} ({})",
                c.key,
                String::from_utf8_lossy(label)
            );
            println!("public key:        {}", hex(&c.public));
            if let Some(out) = cert_out {
                write_cert(out, c.cert, &c.cert_sig)?;
            }
        }
        AdminOp::DeleteAgentKey { key } => {
            hsm.call(Request::DeleteAgentKey { key, approvals })?;
            println!("Deleted agent key {key}");
        }
    }
    Ok(())
}

fn write_cert(out: &Path, cert: &[u8], sig: &[u8; 64]) -> Result<()> {
    write_file(&with_ext(out, ".cert"), cert)?;
    write_file(&with_ext(out, ".cert.sig"), sig)?;
    let c = KeyCert::decode(cert).map_err(bad_reply)?;
    println!(
        "Birth certificate saved to {}.cert (approved by admins {})",
        out.display(),
        approvers(c.approvers)
    );
    Ok(())
}

fn approvers(mask: u8) -> String {
    let who: Vec<_> = (0..8)
        .filter(|i| mask & (1 << i) != 0)
        .map(|i| format!("#{i}"))
        .collect();
    who.join(" and ")
}

fn save_cert(key: u32, out: &Path) -> Result<()> {
    let payload = Hsm::connect()?.call(Request::GetKeyCert { key })?;
    let (cert, sig) = resp::decode_cert(&payload).map_err(bad_reply)?;
    write_cert(out, cert, &sig)
}

fn show_agent_key(key: u32) -> Result<()> {
    let mut hsm = Hsm::connect()?;
    let kp =
        resp::KeyPolicy::decode(&hsm.call(Request::GetKeyPolicy { key })?).map_err(bad_reply)?;
    println!("Agent key {key}");
    for line in describe_policy(&kp.policy) {
        println!("{line}");
    }
    println!("spent so far:      {}", dollars(kp.spent));
    println!(
        "budget left:       {}",
        dollars(kp.policy.budget - kp.spent)
    );
    println!("actions approved:  {}", kp.approved);
    Ok(())
}

/// A shop's payment request: a random one-time code and an expiry time,
/// stored as `nonce=<hex>` and `expires=<unix seconds>` lines.
fn shop_request(valid_for: u64, out: &Path) -> Result<()> {
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    let expires = now() + valid_for;
    write_file(
        out,
        format!("nonce={}\nexpires={expires}\n", hex(&nonce)).as_bytes(),
    )?;
    println!(
        "Payment request {} written to {} (valid for {valid_for} seconds)",
        hex(&nonce),
        out.display()
    );
    Ok(())
}

struct PaymentRequest {
    nonce: [u8; 16],
    expires: u64,
}

fn read_request(path: &Path) -> Result<PaymentRequest> {
    let text = fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let field = |name: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(name)?.strip_prefix('='))
            .ok_or_else(|| format!("{}: missing {name}", path.display()))
    };
    Ok(PaymentRequest {
        nonce: unhex(field("nonce")?)?,
        expires: field("expires")?
            .trim()
            .parse()
            .map_err(|_| format!("{}: bad expires", path.display()))?,
    })
}

fn act(args: ActArgs) -> Result<()> {
    let kind = kind(&args.kind)?;
    let request = args.request.as_deref().map(read_request).transpose()?;
    let action = Action {
        kind,
        amount: if kind == ActionKind::Payment {
            parse_dollars(&args.amount)?
        } else {
            0
        },
        target: args.to.as_bytes(),
        details: args.details.as_bytes(),
        nonce: request.as_ref().map(|r| &r.nonce[..]).unwrap_or(&[]),
        expires: request.as_ref().map(|r| r.expires).unwrap_or(0),
    };
    action.validate().map_err(|_| {
        "invalid action: use plain printable text (no special characters), \
         a recipient of 1-64 characters, details up to 128, and an amount only for payments"
            .to_string()
    })?;

    let mut hsm = Hsm::connect()?;
    hsm.login(&args.login)?;
    println!("Agent asks the HSM to: {}", describe(&action));

    let confirmation = match &args.confirm_with {
        None => None,
        Some(device) => Some(ask_user(&mut hsm, device, args.key, &action, args.yes)?),
    };

    let payload = hsm.call(Request::SignAction {
        key: args.key,
        action,
        confirmation,
    })?;
    let (statement, sig) = resp::decode_signed_action(&payload).map_err(bad_reply)?;
    let s = quorum_core::agent::Statement::decode(statement).map_err(bad_reply)?;

    write_file(&with_ext(&args.out, ".statement"), statement)?;
    write_file(&with_ext(&args.out, ".sig"), &sig)?;
    println!(
        "APPROVED by HSM: action #{} signed{}",
        s.sequence,
        if s.confirmed {
            " (confirmed by the user)"
        } else {
            ""
        }
    );
    println!(
        "wrote {}.statement and {}.sig",
        args.out.display(),
        args.out.display()
    );
    Ok(())
}

/// Plays the user's confirmation device: shows exactly what will be
/// approved and signs it only if the user says yes.
fn ask_user(
    hsm: &mut Hsm,
    device: &Path,
    key: u32,
    action: &Action<'_>,
    auto_yes: bool,
) -> Result<[u8; 64]> {
    let signer = SigningKey::from_bytes(&read_hex_file::<32>(device)?);
    let serial = hsm.identity()?.serial;
    let challenge = resp::decode_challenge(&hsm.call(Request::GetChallenge)?).map_err(bad_reply)?;

    println!("+--------------------- your phone ---------------------+");
    println!("  Your agent wants to: {}", describe(action));
    let yes = ask_yes("Approve?", auto_yes);
    println!("+------------------------------------------------------+");
    if !yes {
        return Err("You declined. Nothing was signed.".into());
    }

    let mut msg = [0u8; CONFIRM_MESSAGE_MAX];
    let n = confirmation_message(&mut msg, &serial, &challenge, key, action)
        .map_err(|e| format!("{e:?}"))?;
    Ok(signer.sign(&msg[..n]).to_bytes())
}

/// The receiver's check. Starts from the one thing it trusts, the HSM's
/// identity key, and needs no access to the HSM.
fn verify(args: VerifyArgs) -> Result<()> {
    let identity = read_hex_file::<32>(&args.hsm_identity)?;
    VerifyingKey::from_bytes(&identity).map_err(|_| "not a valid HSM identity key")?;
    let cert = read_file(&with_ext(&args.cert, ".cert"))?;
    let cert_sig = sig64(&read_file(&with_ext(&args.cert, ".cert.sig"))?)?;
    let statement = read_file(&with_ext(&args.signed, ".statement"))?;
    let sig = sig64(&read_file(&with_ext(&args.signed, ".sig"))?)?;

    let (c, s) = verify_action(&identity, &cert, &cert_sig, &statement, &sig).map_err(|e| {
        match e {
            ActionError::Cert(CertError::BadSignature) => {
                "INVALID: the key's birth certificate was not issued by this HSM"
            }
            ActionError::Cert(_) => "INVALID: not a well-formed birth certificate",
            ActionError::Statement(VerifyError::BadSignature) => {
                "INVALID: the action's signature does not match (it was changed, or signed by another key)"
            }
            ActionError::Statement(_) => "INVALID: not a well-formed signed action",
            ActionError::Mismatch => {
                "INVALID: the action does not belong with this certificate (different HSM, key or rules)"
            }
        }
        .to_string()
    })?;

    // The receiver's own checks: its one-time code, its clock, no reuse.
    if let Some(path) = &args.request {
        let req = read_request(path)?;
        if s.action.nonce != req.nonce {
            return Err("INVALID: this action answers a different payment request".into());
        }
        if s.action.expires != req.expires {
            return Err("INVALID: the expiry was changed from the one the shop set".into());
        }
        if now() > req.expires {
            return Err("INVALID: the payment request has expired".into());
        }
        let used = with_ext(path, ".used");
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&used)
            .map_err(|_| "INVALID: this payment request was already paid (replay)".to_string())?;
    }

    println!(
        "VALID: approved by HSM {}",
        String::from_utf8_lossy(&s.serial)
    );
    println!(
        "  agent key:   {} (created with sign-off from admins {})",
        c.key,
        approvers(c.approvers)
    );
    println!("  action #:    {}", s.sequence);
    println!("  approved:    {}", describe(&s.action));
    println!(
        "  user OK:     {}",
        if s.confirmed {
            "yes, confirmed on the user's device"
        } else {
            "not needed"
        }
    );
    if args.request.is_some() {
        println!("  request:     matches, not expired, first use");
    }
    Ok(())
}

fn sig64(bytes: &[u8]) -> Result<[u8; 64]> {
    bytes
        .try_into()
        .map_err(|_| "a signature must be 64 bytes".to_string())
}
