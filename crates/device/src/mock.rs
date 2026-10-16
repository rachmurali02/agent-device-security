//! A simulated NOR flash chip for tests on the computer.
//!
//! It follows real flash rules (erase sets bytes to 0xFF, writing can only
//! clear bits) and can "cut the power" after a chosen number of byte
//! operations, leaving an erase or a write half-done exactly as a real
//! power cut would.

use crate::flash::{Flash, FlashError};

pub const MOCK_SECTOR: u32 = 4096;

pub struct MockFlash<const N: usize> {
    pub mem: [u8; N],
    /// Byte operations left before the power is cut (`None`: never).
    pub power_left: Option<usize>,
    /// Byte operations done so far (to find every possible cut point).
    pub ops: usize,
}

impl<const N: usize> MockFlash<N> {
    /// A factory-fresh chip: everything erased.
    pub fn new() -> Self {
        MockFlash {
            mem: [0xFF; N],
            power_left: None,
            ops: 0,
        }
    }

    /// The same chip contents after a restart (power back on).
    pub fn reboot(&self) -> Self {
        MockFlash {
            mem: self.mem,
            power_left: None,
            ops: 0,
        }
    }

    fn tick(&mut self) -> Result<(), FlashError> {
        if let Some(left) = &mut self.power_left {
            if *left == 0 {
                return Err(FlashError::Failed);
            }
            *left -= 1;
        }
        self.ops += 1;
        Ok(())
    }

    fn range(offset: u32, len: usize) -> Result<core::ops::Range<usize>, FlashError> {
        let start = offset as usize;
        let end = start.checked_add(len).ok_or(FlashError::Failed)?;
        if end > N {
            return Err(FlashError::Failed);
        }
        Ok(start..end)
    }
}

impl<const N: usize> Default for MockFlash<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Flash for MockFlash<N> {
    const SECTOR: u32 = MOCK_SECTOR;

    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), FlashError> {
        if self.power_left == Some(0) {
            return Err(FlashError::Failed);
        }
        let r = Self::range(offset, buf.len())?;
        buf.copy_from_slice(&self.mem[r]);
        Ok(())
    }

    fn erase(&mut self, from: u32, to: u32) -> Result<(), FlashError> {
        if !from.is_multiple_of(MOCK_SECTOR) || !to.is_multiple_of(MOCK_SECTOR) || to < from {
            return Err(FlashError::Failed);
        }
        for i in Self::range(from, (to - from) as usize)? {
            self.tick()?;
            self.mem[i] = 0xFF;
        }
        Ok(())
    }

    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), FlashError> {
        for (i, b) in Self::range(offset, data.len())?.zip(data) {
            self.tick()?;
            // Programming can only clear bits.
            self.mem[i] &= *b;
        }
        Ok(())
    }
}
