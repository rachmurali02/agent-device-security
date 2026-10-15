//! `quorum-emulator`: command-line entry point for the HSM emulator.
//!
//! Usage:
//!   quorum-emulator init  --state <file> --pin <pin>
//!                         [--admin <pubkey file>]... [--threshold <n>] [--force]
//!   quorum-emulator serve --state <file> --socket <path> [--no-fsync]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::ExitCode;

use quorum_core::wire::SERIAL_LEN;
use quorum_core::{Hsm, Provisioning};
use quorum_emulator::{Device, FileStorage};
use rand_core::{OsRng, RngCore};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("init") => init(&args[1..]),
        Some("serve") => serve(&args[1..]),
        _ => Err(USAGE.to_string()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

const USAGE: &str = "usage:
  quorum-emulator init  --state <file> --pin <pin>
                        [--admin <pubkey file>]... [--threshold <n>] [--force]
  quorum-emulator serve --state <file> --socket <path> [--no-fsync]";

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

/// Every value given for a repeatable flag.
fn flags(args: &[String], name: &str) -> Vec<String> {
    args.windows(2)
        .filter(|w| w[0] == name)
        .map(|w| w[1].clone())
        .collect()
}

/// Reads a 32-byte public key stored as 64 hex characters.
fn read_public_key(path: &str) -> Result<[u8; 32], String> {
    let text = fs::read_to_string(path).map_err(|e| format!("reading {path}: {e}"))?;
    let text = text.trim();
    let mut key = [0u8; 32];
    if text.len() != 64 || !text.is_ascii() {
        return Err(format!("{path}: expected 64 hex characters"));
    }
    for (i, b) in key.iter_mut().enumerate() {
        *b = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).map_err(|e| format!("{path}: {e}"))?;
    }
    Ok(key)
}

fn required(args: &[String], name: &str) -> Result<String, String> {
    flag(args, name).ok_or_else(|| format!("missing {name}\n{USAGE}"))
}

/// Factory provisioning: create a brand-new HSM with a random serial number.
fn init(args: &[String]) -> Result<(), String> {
    let path = PathBuf::from(required(args, "--state")?);
    let pin = required(args, "--pin")?;
    if path.exists() && !args.iter().any(|a| a == "--force") {
        return Err(format!(
            "{} exists; pass --force to wipe it",
            path.display()
        ));
    }

    let mut raw = [0u8; SERIAL_LEN / 2];
    OsRng.fill_bytes(&mut raw);
    let mut serial = [0u8; SERIAL_LEN];
    for (i, b) in raw.iter().enumerate() {
        serial[2 * i..2 * i + 2].copy_from_slice(format!("{b:02X}").as_bytes());
    }

    let admins = flags(args, "--admin")
        .iter()
        .map(|p| read_public_key(p))
        .collect::<Result<Vec<_>, _>>()?;
    let threshold: u8 = match flag(args, "--threshold") {
        Some(t) => t.parse().map_err(|_| format!("bad --threshold {t:?}"))?,
        None if admins.is_empty() => 0,
        None => return Err("--threshold is required with --admin".into()),
    };

    let mut storage = FileStorage::new(path.clone());
    let hsm = Hsm::provision(
        Provisioning {
            serial,
            pin: pin.as_bytes(),
            admins: &admins,
            threshold,
        },
        &mut OsRng,
        &mut storage,
    )
    .map_err(|e| format!("provisioning failed: {e:?}"))?;
    println!(
        "provisioned HSM {} at {}",
        String::from_utf8_lossy(&serial),
        path.display()
    );
    if admins.is_empty() {
        println!("no admins: agent keys cannot be created on this HSM");
    } else {
        println!(
            "agent keys need sign-off from {threshold} of {} admins",
            admins.len()
        );
    }
    let identity: String = hsm
        .identity_public()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    println!("HSM identity (give this to receivers): {identity}");
    Ok(())
}

fn serve(args: &[String]) -> Result<(), String> {
    let path = PathBuf::from(required(args, "--state")?);
    let socket = PathBuf::from(required(args, "--socket")?);

    let state = fs::read(&path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let hsm = Hsm::load(&state).map_err(|e| format!("loading state: {e:?}"))?;
    let serial = String::from_utf8_lossy(hsm.serial()).into_owned();

    if socket.exists() {
        fs::remove_file(&socket).map_err(|e| format!("removing stale socket: {e}"))?;
    }
    let listener = UnixListener::bind(&socket).map_err(|e| format!("bind: {e}"))?;
    // Only the owning user may talk to the HSM.
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("chmod socket: {e}"))?;
    eprintln!("HSM {serial} listening on {}", socket.display());

    let mut storage = FileStorage::new(path);
    // Benchmarking only: see FileStorage::sync.
    storage.sync = !args.iter().any(|a| a == "--no-fsync");
    if !storage.sync {
        eprintln!(
            "WARNING: --no-fsync: state changes may be lost on power loss (benchmarking only)"
        );
    }
    quorum_emulator::serve(listener, Device { hsm, storage });
    Ok(())
}
