//! `quorum`: command-line tool for agent keys.
//!
//! It plays three roles so the whole story can run on one machine:
//! - the **agent**, asking the HSM to approve an action (`act`)
//! - the **user's confirmation device**, a phone with a trusted screen and an
//!   "Approve" button (`confirmer new`, and `act --confirm-with`)
//! - whoever **receives** the signed action and checks it (`verify`)
//!
//! None of these roles can make the HSM break its rules: every decision is
//! made inside the HSM.

use std::fs;
use std::io::{self, BufRead, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};
use quorum_client::Client;
use quorum_core::agent::{
    Action, ActionKind, CONFIRM_MESSAGE_MAX, Policy, Statement, VerifyError, confirmation_message,
    verify_statement,
};
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
    /// List the keys on the HSM.
    Keys,
    /// Create or inspect agent keys.
    #[command(subcommand)]
    AgentKey(AgentKeyCmd),
    /// Simulated user confirmation device (the user's phone).
    #[command(subcommand)]
    Confirmer(ConfirmerCmd),
    /// Ask the HSM to approve and sign an agent action.
    Act(ActArgs),
    /// Check a signed action, with no HSM involved.
    Verify(VerifyArgs),
}

#[derive(Args)]
struct Login {
    /// User PIN.
    #[arg(long, env = "QUORUM_PIN", hide_env_values = true)]
    pin: String,
}

#[derive(Subcommand)]
enum AgentKeyCmd {
    /// Create an agent key with fixed rules.
    Create(CreateArgs),
    /// Show a key's rules and how much of its budget is used.
    Show {
        #[arg(long)]
        key: u32,
    },
}

#[derive(Args)]
struct CreateArgs {
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
}

#[derive(Subcommand)]
enum ConfirmerCmd {
    /// Create a new confirmation device. Writes the secret to <out> and the
    /// public key to <out>.pub.
    New {
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
    /// The agent key's public key, as hex (shown by `agent-key create`).
    #[arg(long)]
    public_key: String,
    /// Prefix used with `act --out`.
    #[arg(long)]
    signed: PathBuf,
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
        Command::Keys => list_keys(),
        Command::AgentKey(AgentKeyCmd::Create(args)) => create_agent_key(args),
        Command::AgentKey(AgentKeyCmd::Show { key }) => show_agent_key(key),
        Command::Confirmer(ConfirmerCmd::New { out }) => new_confirmer(&out),
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

    fn serial(&mut self) -> Result<[u8; 16]> {
        let info = resp::Info::decode(&self.call(Request::GetInfo)?).map_err(bad_reply)?;
        Ok(info.serial)
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
    lines
}

fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut f| f.write_all(contents))
        .map_err(|e| format!("writing {}: {e}", path.display()))
}

fn with_ext(path: &Path, ext: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(ext);
    PathBuf::from(s)
}

// ---- commands --------------------------------------------------------------

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

fn create_agent_key(args: CreateArgs) -> Result<()> {
    let confirmer = match &args.confirmer {
        None => None,
        Some(path) => {
            let text =
                fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
            Some(unhex::<32>(&text)?)
        }
    };
    let policy = Policy {
        allowed: kinds_mask(&args.allow)?,
        max_amount: parse_dollars(&args.max_amount)?,
        budget: parse_dollars(&args.budget)?,
        confirm_above: parse_dollars(&args.confirm_above)?,
        always_confirm: kinds_mask(&args.always_confirm)?,
        confirmer,
    };
    policy
        .validate()
        .map_err(|_| "those rules are not valid".to_string())?;

    let mut hsm = Hsm::connect()?;
    hsm.login(&args.login)?;
    let payload = hsm.call(Request::GenerateAgentKey {
        label: args.label.as_bytes(),
        ext_id: b"",
        policy,
    })?;
    let g = resp::Generated::decode(&payload).map_err(bad_reply)?;
    println!("Created agent key {} ({})", g.key, args.label);
    println!("public key:        {}", hex(&g.public));
    for line in describe_policy(&policy) {
        println!("{line}");
    }
    println!("These rules are fixed for the life of the key.");
    Ok(())
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

fn new_confirmer(out: &Path) -> Result<()> {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let key = SigningKey::from_bytes(&secret);
    write_private(out, hex(&secret).as_bytes())?;
    let public = with_ext(out, ".pub");
    fs::write(&public, hex(&key.verifying_key().to_bytes()))
        .map_err(|e| format!("writing {}: {e}", public.display()))?;
    println!("Created confirmation device.");
    println!("secret (keep on the device): {}", out.display());
    println!("public (give to the HSM):    {}", public.display());
    Ok(())
}

fn act(args: ActArgs) -> Result<()> {
    let kind = kind(&args.kind)?;
    let action = Action {
        kind,
        amount: if kind == ActionKind::Payment {
            parse_dollars(&args.amount)?
        } else {
            0
        },
        target: args.to.as_bytes(),
        details: args.details.as_bytes(),
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
    let s = Statement::decode(statement).map_err(bad_reply)?;

    fs::write(with_ext(&args.out, ".statement"), statement).map_err(|e| e.to_string())?;
    fs::write(with_ext(&args.out, ".sig"), sig).map_err(|e| e.to_string())?;
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
    let text =
        fs::read_to_string(device).map_err(|e| format!("reading {}: {e}", device.display()))?;
    let signer = SigningKey::from_bytes(&unhex::<32>(&text)?);

    let serial = hsm.serial()?;
    let challenge = resp::decode_challenge(&hsm.call(Request::GetChallenge)?).map_err(bad_reply)?;

    println!("+--------------------- your phone ---------------------+");
    println!("  Your agent wants to: {}", describe(action));
    print!("  Approve? [y/N] ");
    let approved = if auto_yes {
        println!("y (auto)");
        true
    } else {
        io::stdout().flush().ok();
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line).ok();
        matches!(line.trim(), "y" | "Y" | "yes")
    };
    println!("+------------------------------------------------------+");
    if !approved {
        return Err("You declined. Nothing was signed.".into());
    }

    let mut msg = [0u8; CONFIRM_MESSAGE_MAX];
    let n = confirmation_message(&mut msg, &serial, &challenge, key, action)
        .map_err(|e| format!("{e:?}"))?;
    Ok(signer.sign(&msg[..n]).to_bytes())
}

fn verify(args: VerifyArgs) -> Result<()> {
    let public = unhex::<32>(&args.public_key)?;
    let read = |ext: &str| {
        let p = with_ext(&args.signed, ext);
        fs::read(&p).map_err(|e| format!("reading {}: {e}", p.display()))
    };
    let statement = read(".statement")?;
    let sig: [u8; 64] = read(".sig")?
        .try_into()
        .map_err(|_| "signature must be 64 bytes".to_string())?;

    let s = verify_statement(&public, &statement, &sig).map_err(|e| match e {
        VerifyError::BadSignature => {
            "INVALID: the signature does not match (changed, or signed by a different key)"
        }
        VerifyError::Malformed => "INVALID: not a well-formed statement",
        VerifyError::BadPublicKey => "INVALID: that is not a valid public key",
    })?;
    println!("VALID: signed by the HSM");
    println!("  HSM serial:  {}", String::from_utf8_lossy(&s.serial));
    println!("  key:         {}", s.key);
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
    println!("  rules:       {}", hex(&s.policy_digest));
    Ok(())
}
