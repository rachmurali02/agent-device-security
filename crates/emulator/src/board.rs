//! Emulates a whole HSM *board*: the real firmware logic (`quorum-device`)
//! running on a simulated flash chip kept in a file.
//!
//! Unlike `serve`, which starts from an already-provisioned state file, a
//! board starts blank and must be set up with `quorum provision`, exactly
//! like a new Pico 2. It can be reached over a Unix socket or over a pseudo
//! serial port, so the same commands that drive the real board over USB can
//! be tested without one.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::time::Duration;

use quorum_core::wire::{MAX_FRAME, resp};
use quorum_device::Firmware;
use quorum_device::flash::{Flash, FlashError, region_len};
use quorum_device::framer::Framer;
use rand_core::OsRng;

/// The simulated chip's sector size: the same as the RP2350's flash.
const SECTOR: u32 = 4096;
/// The file holds just the state area.
pub const BOARD_FLASH_LEN: u64 = region_len(SECTOR) as u64;

/// NOR flash rules on top of a file: erase sets bytes to 0xFF, writing can
/// only clear bits. Every operation waits for the disk, like real flash.
pub struct FileFlash {
    file: File,
}

impl FileFlash {
    /// Opens the board's flash file, creating an erased one if needed.
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)?;
        let len = file.metadata()?.len();
        if len == 0 {
            file.write_all_at(&vec![0xFF; BOARD_FLASH_LEN as usize], 0)?;
            file.sync_all()?;
        } else if len != BOARD_FLASH_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: not a board flash file", path.display()),
            ));
        }
        Ok(FileFlash { file })
    }

    fn io<T>(r: io::Result<T>) -> Result<T, FlashError> {
        r.map_err(|e| {
            eprintln!("flash: {e}");
            FlashError::Failed
        })
    }
}

impl Flash for FileFlash {
    const SECTOR: u32 = SECTOR;

    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), FlashError> {
        Self::io(self.file.read_exact_at(buf, offset as u64))
    }

    fn erase(&mut self, from: u32, to: u32) -> Result<(), FlashError> {
        if !from.is_multiple_of(SECTOR) || !to.is_multiple_of(SECTOR) || to < from {
            return Err(FlashError::Failed);
        }
        Self::io(
            self.file
                .write_all_at(&vec![0xFF; (to - from) as usize], from as u64)
                .and_then(|_| self.file.sync_data()),
        )
    }

    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), FlashError> {
        let mut cur = vec![0u8; data.len()];
        self.read(offset, &mut cur)?;
        for (c, d) in cur.iter_mut().zip(data) {
            *c &= *d;
        }
        Self::io(
            self.file
                .write_all_at(&cur, offset as u64)
                .and_then(|_| self.file.sync_data()),
        )
    }
}

pub type Board = Firmware<FileFlash>;

pub fn boot(path: &Path) -> io::Result<Box<Board>> {
    Ok(Box::new(Firmware::boot(FileFlash::open(path)?, 0)))
}

/// Serves one connection at a time, like a USB device with one host. Each
/// connection is one session; disconnecting logs out.
pub fn serve_socket(listener: UnixListener, board: &mut Board) {
    for conn in listener.incoming() {
        match conn {
            Ok(mut stream) => {
                let e = run(&mut stream, board);
                if e.kind() != io::ErrorKind::UnexpectedEof {
                    eprintln!("connection error: {e}");
                }
                board.end_session();
            }
            Err(e) => eprintln!("accept: {e}"),
        }
    }
}

/// Serves on a pseudo serial port (the "USB cable"). Prints the port name
/// for `QUORUM_HSM_SERIAL`. A pseudo port has no "cable unplugged" signal,
/// so unlike the real board a login lasts until the emulator stops.
pub fn serve_pty(board: &mut Board, announce: impl FnOnce(&str)) -> io::Result<()> {
    use serialport::SerialPort;
    let (mut master, slave) = serialport::TTYPort::pair().map_err(io::Error::other)?;
    let name = slave
        .name()
        .ok_or_else(|| io::Error::other("pseudo port has no name"))?;
    master
        .set_timeout(Duration::from_secs(3600))
        .map_err(io::Error::other)?;
    announce(&name);
    // Keep our end of the slave open so the port stays up between clients.
    let _slave = slave;
    loop {
        let e = run(&mut master, board);
        if e.kind() != io::ErrorKind::TimedOut {
            return Err(e);
        }
    }
}

/// Reads bytes as they come (like USB packets) and answers each whole
/// frame, until the connection fails or closes.
fn run(stream: &mut (impl Read + Write), board: &mut Board) -> io::Error {
    match serve_frames(stream, board) {
        Ok(never) => match never {},
        Err(e) => e,
    }
}

fn serve_frames(
    stream: &mut (impl Read + Write),
    board: &mut Board,
) -> io::Result<std::convert::Infallible> {
    let mut framer = Framer::default();
    let mut packet = [0u8; 64];
    let mut out = vec![0u8; MAX_FRAME];
    loop {
        let n = stream.read(&mut packet)?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let mut input = &packet[..n];
        while !input.is_empty() {
            let (used, ready) = framer
                .push(input)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}")))?;
            input = &input[used..];
            if ready {
                let m = board.handle(&mut OsRng, framer.frame(), &mut out);
                framer.reset();
                if let Ok((status, _)) = resp::split(&out[..m]) {
                    eprintln!("board [{}] -> {status:?}", board.mode());
                }
                stream.write_all(&(m as u32).to_le_bytes())?;
                stream.write_all(&out[..m])?;
                stream.flush()?;
            }
        }
    }
}
