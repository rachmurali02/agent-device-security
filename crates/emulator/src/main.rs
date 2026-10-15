//! `quorum-emulator`: command-line entry point for the HSM emulator.
//!
//! Usage:
//!   quorum-emulator init  --state <file> --pin <pin> [--force]
//!   quorum-emulator serve --state <file> --socket <path>

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::ExitCode;

use quorum_core::Hsm;
use quorum_core::wire::SERIAL_LEN;
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
  quorum-emulator init  --state <file> --pin <pin> [--force]
  quorum-emulator serve --state <file> --socket <path>";

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
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

    let mut storage = FileStorage { path: path.clone() };
    Hsm::provision(serial, pin.as_bytes(), &mut storage)
        .map_err(|e| format!("provisioning failed: {e:?}"))?;
    println!(
        "provisioned HSM {} at {}",
        String::from_utf8_lossy(&serial),
        path.display()
    );
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

    quorum_emulator::serve(
        listener,
        Device {
            hsm,
            storage: FileStorage { path },
        },
    );
    Ok(())
}
