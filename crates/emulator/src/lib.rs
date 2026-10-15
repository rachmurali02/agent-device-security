//! The HSM emulator: runs `quorum-core` behind a Unix socket.
//!
//! Everything in this process stands in for HSM hardware. The socket is the
//! host interface (on a real device, USB or SPI) and the state file stands in
//! for the HSM's internal flash.

use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};
use std::thread;

use quorum_core::wire::{MAX_FRAME, Request, resp};
use quorum_core::{Hsm, Session, Storage};
use rand_core::OsRng;

mod storage;
pub use storage::{RenameStorage, SLOT_FILE_LEN, SlotStorage};

pub struct Device<S: Storage> {
    pub hsm: Hsm,
    pub storage: S,
}

/// Accepts connections forever, one thread and one HSM session each.
pub fn serve<S: Storage + Send + 'static>(listener: UnixListener, device: Device<S>) {
    serve_with(listener, device, true)
}

/// Like `serve`, but `log: false` turns off the per-command log line (used
/// by the benchmarks, where writing to the terminal would skew timings).
pub fn serve_with<S: Storage + Send + 'static>(
    listener: UnixListener,
    device: Device<S>,
    log: bool,
) {
    let device = Arc::new(Mutex::new(device));
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let device = Arc::clone(&device);
                thread::spawn(move || {
                    if let Err(e) = handle_connection(stream, &device, log)
                        && e.kind() != io::ErrorKind::UnexpectedEof
                    {
                        eprintln!("connection error: {e}");
                    }
                });
            }
            Err(e) => eprintln!("accept: {e}"),
        }
    }
}

/// One connection = one HSM session. Frames are `[len: u32 LE][frame]`.
fn handle_connection<S: Storage>(
    mut stream: UnixStream,
    device: &Mutex<Device<S>>,
    log_commands: bool,
) -> io::Result<()> {
    let mut session = Session::default();
    let mut req = vec![0u8; MAX_FRAME];
    let mut out = vec![0u8; MAX_FRAME];
    loop {
        let mut len = [0u8; 4];
        stream.read_exact(&mut len)?;
        let len = u32::from_le_bytes(len) as usize;
        if len > MAX_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame too large",
            ));
        }
        stream.read_exact(&mut req[..len])?;

        // The HSM handles one command at a time, like a single-core device.
        let n = {
            let mut guard = device.lock().unwrap_or_else(|p| p.into_inner());
            let Device { hsm, storage } = &mut *guard;
            hsm.handle(&mut session, storage, &mut OsRng, &req[..len], &mut out)
        };
        if log_commands {
            log(&req[..len], &out[..n]);
        }

        stream.write_all(&(n as u32).to_le_bytes())?;
        stream.write_all(&out[..n])?;
    }
}

/// Logs the command name and status only, never PINs, messages or keys.
fn log(req: &[u8], out: &[u8]) {
    let cmd = match Request::decode(req) {
        Ok(Request::GetInfo) => "GetInfo",
        Ok(Request::Login { .. }) => "Login",
        Ok(Request::Logout) => "Logout",
        Ok(Request::GenerateKey { .. }) => "GenerateKey",
        Ok(Request::ListKeys) => "ListKeys",
        Ok(Request::Sign { .. }) => "Sign",
        Ok(Request::DeleteKey { .. }) => "DeleteKey",
        Ok(Request::GenerateAgentKey { .. }) => "GenAgentKey",
        Ok(Request::GetChallenge) => "Challenge",
        Ok(Request::SignAction { .. }) => "SignAction",
        Ok(Request::GetKeyPolicy { .. }) => "GetPolicy",
        Ok(Request::GetIdentity) => "GetIdentity",
        Ok(Request::GetAdminChallenge) => "AdminChallenge",
        Ok(Request::DeleteAgentKey { .. }) => "DelAgentKey",
        Ok(Request::GetKeyCert { .. }) => "GetKeyCert",
        Ok(Request::UpdatePolicy { .. }) => "UpdatePolicy",
        Ok(Request::ChangeAdmins { .. }) => "ChangeAdmins",
        Ok(Request::ReadAudit { .. }) => "ReadAudit",
        Ok(Request::AuditCheckpoint) => "Checkpoint",
        Ok(Request::AckAudit { .. }) => "AckAudit",
        Err(_) => "<malformed>",
    };
    match resp::split(out) {
        Ok((status, _)) => eprintln!("{cmd:<12} -> {status:?}"),
        Err(_) => eprintln!("{cmd:<12} -> <no response>"),
    }
}
