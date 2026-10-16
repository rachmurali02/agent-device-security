//! Host-side connection to the HSM: the emulator's Unix socket, or a real
//! device's USB serial port. Both carry the same frames.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use quorum_core::wire::{MAX_FRAME, Request, Status, resp};

pub const SOCKET_ENV: &str = "QUORUM_HSM_SOCKET";
pub const DEFAULT_SOCKET: &str = "/tmp/quorum-hsm.sock";
/// Set this to a serial device (e.g. `/dev/ttyACM0`) to use a real HSM
/// board instead of the emulator.
pub const SERIAL_ENV: &str = "QUORUM_HSM_SERIAL";

pub fn socket_path() -> PathBuf {
    std::env::var_os(SOCKET_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET))
}

trait Transport: Read + Write + Send {}
impl<T: Read + Write + Send> Transport for T {}

pub struct Client {
    stream: Box<dyn Transport>,
    /// Log out when done (serial only; see `connect_serial`).
    logout_on_drop: bool,
}

impl Client {
    /// Connects to the board named by `QUORUM_HSM_SERIAL` if set, otherwise
    /// to the emulator's socket.
    pub fn connect() -> io::Result<Self> {
        match std::env::var_os(SERIAL_ENV) {
            Some(dev) => Self::connect_serial(&dev.to_string_lossy()),
            None => Self::connect_at(&socket_path()),
        }
    }

    pub fn connect_at(path: &std::path::Path) -> io::Result<Self> {
        Ok(Client {
            stream: Box::new(UnixStream::connect(path)?),
            logout_on_drop: false,
        })
    }

    /// Opens a real HSM board's USB serial port. The board ends the session
    /// when the port is closed; to be safe (some systems keep the line up),
    /// the client also logs out itself when it is done.
    pub fn connect_serial(device: &str) -> io::Result<Self> {
        // USB serial ignores the baud rate; the timeout covers the slowest
        // command (a save erases and rewrites two flash sectors).
        let port = serialport::new(device, 115_200)
            .timeout(Duration::from_secs(10))
            .open_native()
            .map_err(|e| io::Error::other(format!("{device}: {e}")))?;
        serialport::SerialPort::clear(&port, serialport::ClearBuffer::All)
            .map_err(|e| io::Error::other(format!("{device}: {e}")))?;
        Ok(Client {
            stream: Box::new(port),
            logout_on_drop: true,
        })
    }

    /// Sends one request and returns the status and payload.
    pub fn call(&mut self, req: &Request<'_>) -> io::Result<(Status, Vec<u8>)> {
        let mut frame = [0u8; MAX_FRAME];
        let n = req
            .encode(&mut frame)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{e:?}")))?;
        self.stream.write_all(&(n as u32).to_le_bytes())?;
        self.stream.write_all(&frame[..n])?;

        let mut len = [0u8; 4];
        self.stream.read_exact(&mut len)?;
        let len = u32::from_le_bytes(len) as usize;
        if len > MAX_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "response too large",
            ));
        }
        let mut out = vec![0u8; len];
        self.stream.read_exact(&mut out)?;
        let (status, payload) = resp::split(&out)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}")))?;
        Ok((status, payload.to_vec()))
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if self.logout_on_drop {
            let _ = self.call(&Request::Logout);
        }
    }
}

/// Plain-English reason for each HSM answer, for people reading refusals.
pub fn explain(s: Status) -> &'static str {
    match s {
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
        Status::AuditFull => {
            "the audit log is full; copy it out first with `quorum audit pull --log <file>`"
        }
        Status::NotProvisioned => "this device is blank; set it up first with `quorum provision`",
        Status::AlreadyProvisioned => "this device was already set up (that only happens once)",
    }
}
