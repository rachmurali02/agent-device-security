//! Host-side connection to the HSM over a Unix socket.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use quorum_core::wire::{MAX_FRAME, Request, Status, resp};

pub const SOCKET_ENV: &str = "QUORUM_HSM_SOCKET";
pub const DEFAULT_SOCKET: &str = "/tmp/quorum-hsm.sock";

pub fn socket_path() -> PathBuf {
    std::env::var_os(SOCKET_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET))
}

pub struct Client {
    stream: UnixStream,
}

impl Client {
    pub fn connect() -> io::Result<Self> {
        Self::connect_at(&socket_path())
    }

    pub fn connect_at(path: &std::path::Path) -> io::Result<Self> {
        Ok(Client {
            stream: UnixStream::connect(path)?,
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
