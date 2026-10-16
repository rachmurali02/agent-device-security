//! Cuts the incoming byte stream (USB serial) into request frames.
//!
//! The format is the same as on the emulator's socket: `[length: u32 LE]
//! [frame]`. USB delivers data in small packets (64 bytes), so a frame
//! arrives in pieces, and one packet may hold the end of one frame and the
//! start of the next.

use quorum_core::wire::MAX_FRAME;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// The length prefix is larger than any valid frame.
    TooLarge,
}

pub struct Framer {
    buf: [u8; 4 + MAX_FRAME],
    have: usize,
}

impl Default for Framer {
    fn default() -> Self {
        Framer {
            buf: [0; 4 + MAX_FRAME],
            have: 0,
        }
    }
}

impl Framer {
    /// Takes bytes from `input` until a whole frame is in. Returns how many
    /// bytes were used, and whether a frame is now ready ([`frame`](Self::frame)).
    /// Unused bytes belong to the next frame: call again after [`reset`](Self::reset).
    pub fn push(&mut self, input: &[u8]) -> Result<(usize, bool), FrameError> {
        let mut used = 0;
        loop {
            let need = self.needed()?;
            if self.have == need {
                return Ok((used, true));
            }
            if used == input.len() {
                return Ok((used, false));
            }
            let take = (need - self.have).min(input.len() - used);
            self.buf[self.have..self.have + take].copy_from_slice(&input[used..used + take]);
            self.have += take;
            used += take;
        }
    }

    /// The complete frame (valid when `push` returned `true`).
    pub fn frame(&self) -> &[u8] {
        &self.buf[4..self.have]
    }

    /// Starts on the next frame.
    pub fn reset(&mut self) {
        self.have = 0;
    }

    /// Total bytes (prefix + frame) needed for the current frame.
    fn needed(&self) -> Result<usize, FrameError> {
        if self.have < 4 {
            return Ok(4);
        }
        let len = u32::from_le_bytes(self.buf[..4].try_into().unwrap_or([0xFF; 4])) as usize;
        if len > MAX_FRAME {
            return Err(FrameError::TooLarge);
        }
        Ok(4 + len)
    }
}
