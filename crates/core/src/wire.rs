//! Host <-> HSM wire protocol.
//!
//! Every byte that crosses the trust boundary goes through this module, so it
//! is written to be boring: fixed-width little-endian integers, `u16`
//! length-prefixed byte strings with per-field maximums, and no trailing
//! garbage allowed. Decoding never allocates and never panics.
//!
//! Request frame:  `[cmd: u8] [fields...]`
//! Response frame: `[status: u8] [fields...]` (fields only when status == Ok)

pub const MAX_FRAME: usize = 4096;
pub const MAX_PIN: usize = 32;
pub const MIN_PIN: usize = 4;
pub const MAX_LABEL: usize = 32;
pub const MAX_EXT_ID: usize = 32;
pub const MAX_MESSAGE: usize = 2048;

pub const PUBLIC_KEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;
pub const SERIAL_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// Input ended before a field was complete.
    Truncated,
    /// A length-prefixed field exceeded its maximum.
    TooLong,
    /// Bytes left over after the last field.
    Trailing,
    /// Output buffer too small.
    Overflow,
    /// Unknown command or status byte.
    UnknownTag,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Cmd {
    GetInfo = 0x01,
    Login = 0x02,
    Logout = 0x03,
    GenerateKey = 0x10,
    ListKeys = 0x11,
    Sign = 0x12,
    DeleteKey = 0x13,
}

impl TryFrom<u8> for Cmd {
    type Error = WireError;
    fn try_from(b: u8) -> Result<Self, WireError> {
        Ok(match b {
            0x01 => Cmd::GetInfo,
            0x02 => Cmd::Login,
            0x03 => Cmd::Logout,
            0x10 => Cmd::GenerateKey,
            0x11 => Cmd::ListKeys,
            0x12 => Cmd::Sign,
            0x13 => Cmd::DeleteKey,
            _ => return Err(WireError::UnknownTag),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    Ok = 0x00,
    BadRequest = 0x01,
    NotLoggedIn = 0x02,
    AlreadyLoggedIn = 0x03,
    PinIncorrect = 0x04,
    PinLocked = 0x05,
    KeyNotFound = 0x06,
    StoreFull = 0x07,
    ResponseTooLarge = 0x08,
    /// Persistent storage failed; the HSM refuses all commands until restart.
    Fault = 0x09,
}

impl TryFrom<u8> for Status {
    type Error = WireError;
    fn try_from(b: u8) -> Result<Self, WireError> {
        Ok(match b {
            0x00 => Status::Ok,
            0x01 => Status::BadRequest,
            0x02 => Status::NotLoggedIn,
            0x03 => Status::AlreadyLoggedIn,
            0x04 => Status::PinIncorrect,
            0x05 => Status::PinLocked,
            0x06 => Status::KeyNotFound,
            0x07 => Status::StoreFull,
            0x08 => Status::ResponseTooLarge,
            0x09 => Status::Fault,
            _ => return Err(WireError::UnknownTag),
        })
    }
}

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    pub fn raw(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(n).ok_or(WireError::Truncated)?;
        let out = self.buf.get(self.pos..end).ok_or(WireError::Truncated)?;
        self.pos = end;
        Ok(out)
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.raw(N)?);
        Ok(out)
    }

    pub fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.raw(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    pub fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    /// A `u16`-length-prefixed byte string of at most `max` bytes.
    pub fn bytes(&mut self, max: usize) -> Result<&'a [u8], WireError> {
        let len = self.u16()? as usize;
        if len > max {
            return Err(WireError::TooLong);
        }
        self.raw(len)
    }

    pub fn finish(self) -> Result<(), WireError> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(WireError::Trailing)
        }
    }
}

pub struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Writer<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Writer { buf, pos: 0 }
    }

    pub fn raw(&mut self, data: &[u8]) -> Result<(), WireError> {
        let end = self
            .pos
            .checked_add(data.len())
            .ok_or(WireError::Overflow)?;
        self.buf
            .get_mut(self.pos..end)
            .ok_or(WireError::Overflow)?
            .copy_from_slice(data);
        self.pos = end;
        Ok(())
    }

    pub fn u8(&mut self, v: u8) -> Result<(), WireError> {
        self.raw(&[v])
    }

    pub fn u16(&mut self, v: u16) -> Result<(), WireError> {
        self.raw(&v.to_le_bytes())
    }

    pub fn u32(&mut self, v: u32) -> Result<(), WireError> {
        self.raw(&v.to_le_bytes())
    }

    pub fn bytes(&mut self, data: &[u8]) -> Result<(), WireError> {
        let len = u16::try_from(data.len()).map_err(|_| WireError::TooLong)?;
        self.u16(len)?;
        self.raw(data)
    }

    pub fn len(&self) -> usize {
        self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.pos == 0
    }
}

/// A decoded request. Borrowed fields point into the request frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request<'a> {
    GetInfo,
    Login {
        pin: &'a [u8],
    },
    Logout,
    /// `ext_id` is opaque caller metadata (PKCS#11 `CKA_ID`).
    GenerateKey {
        label: &'a [u8],
        ext_id: &'a [u8],
    },
    ListKeys,
    Sign {
        key: u32,
        msg: &'a [u8],
    },
    DeleteKey {
        key: u32,
    },
}

impl<'a> Request<'a> {
    pub fn decode(frame: &'a [u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(frame);
        let req = match Cmd::try_from(r.u8()?)? {
            Cmd::GetInfo => Request::GetInfo,
            Cmd::Login => Request::Login {
                pin: r.bytes(MAX_PIN)?,
            },
            Cmd::Logout => Request::Logout,
            Cmd::GenerateKey => Request::GenerateKey {
                label: r.bytes(MAX_LABEL)?,
                ext_id: r.bytes(MAX_EXT_ID)?,
            },
            Cmd::ListKeys => Request::ListKeys,
            Cmd::Sign => Request::Sign {
                key: r.u32()?,
                msg: r.bytes(MAX_MESSAGE)?,
            },
            Cmd::DeleteKey => Request::DeleteKey { key: r.u32()? },
        };
        r.finish()?;
        Ok(req)
    }

    pub fn encode(&self, out: &mut [u8]) -> Result<usize, WireError> {
        let mut w = Writer::new(out);
        match *self {
            Request::GetInfo => w.u8(Cmd::GetInfo as u8)?,
            Request::Login { pin } => {
                w.u8(Cmd::Login as u8)?;
                w.bytes(pin)?;
            }
            Request::Logout => w.u8(Cmd::Logout as u8)?,
            Request::GenerateKey { label, ext_id } => {
                w.u8(Cmd::GenerateKey as u8)?;
                w.bytes(label)?;
                w.bytes(ext_id)?;
            }
            Request::ListKeys => w.u8(Cmd::ListKeys as u8)?,
            Request::Sign { key, msg } => {
                w.u8(Cmd::Sign as u8)?;
                w.u32(key)?;
                w.bytes(msg)?;
            }
            Request::DeleteKey { key } => {
                w.u8(Cmd::DeleteKey as u8)?;
                w.u32(key)?;
            }
        }
        Ok(w.len())
    }
}

/// Response payload types, with decoders for the host side.
pub mod resp {
    use super::*;

    pub const FLAG_LOGGED_IN: u8 = 1 << 0;
    pub const FLAG_PIN_LOCKED: u8 = 1 << 1;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Info {
        pub serial: [u8; SERIAL_LEN],
        pub fw_major: u8,
        pub fw_minor: u8,
        pub key_count: u8,
        pub max_keys: u8,
        pub pin_tries_left: u8,
        pub flags: u8,
    }

    impl Info {
        pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
            w.raw(&self.serial)?;
            w.u8(self.fw_major)?;
            w.u8(self.fw_minor)?;
            w.u8(self.key_count)?;
            w.u8(self.max_keys)?;
            w.u8(self.pin_tries_left)?;
            w.u8(self.flags)
        }

        pub fn decode(payload: &[u8]) -> Result<Self, WireError> {
            let mut r = Reader::new(payload);
            let info = Info {
                serial: r.array()?,
                fw_major: r.u8()?,
                fw_minor: r.u8()?,
                key_count: r.u8()?,
                max_keys: r.u8()?,
                pin_tries_left: r.u8()?,
                flags: r.u8()?,
            };
            r.finish()?;
            Ok(info)
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Generated {
        pub key: u32,
        pub public: [u8; PUBLIC_KEY_LEN],
    }

    impl Generated {
        pub fn decode(payload: &[u8]) -> Result<Self, WireError> {
            let mut r = Reader::new(payload);
            let g = Generated {
                key: r.u32()?,
                public: r.array()?,
            };
            r.finish()?;
            Ok(g)
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct KeyEntry<'a> {
        pub key: u32,
        pub label: &'a [u8],
        pub ext_id: &'a [u8],
        pub public: [u8; PUBLIC_KEY_LEN],
    }

    impl KeyEntry<'_> {
        pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
            w.u32(self.key)?;
            w.bytes(self.label)?;
            w.bytes(self.ext_id)?;
            w.raw(&self.public)
        }
    }

    /// Decodes a `ListKeys` payload: `[count: u8] [KeyEntry]*`.
    /// Validates the whole payload up front so iteration cannot fail.
    pub fn decode_key_list(payload: &[u8]) -> Result<KeyList<'_>, WireError> {
        let mut r = Reader::new(payload);
        let count = r.u8()?;
        for _ in 0..count {
            read_entry(&mut r)?;
        }
        r.finish()?;
        Ok(KeyList {
            r: Reader::new(&payload[1..]),
            remaining: count,
        })
    }

    fn read_entry<'a>(r: &mut Reader<'a>) -> Result<KeyEntry<'a>, WireError> {
        Ok(KeyEntry {
            key: r.u32()?,
            label: r.bytes(MAX_LABEL)?,
            ext_id: r.bytes(MAX_EXT_ID)?,
            public: r.array()?,
        })
    }

    pub struct KeyList<'a> {
        r: Reader<'a>,
        remaining: u8,
    }

    impl<'a> Iterator for KeyList<'a> {
        type Item = KeyEntry<'a>;
        fn next(&mut self) -> Option<KeyEntry<'a>> {
            if self.remaining == 0 {
                return None;
            }
            self.remaining -= 1;
            read_entry(&mut self.r).ok()
        }
    }

    pub fn decode_signature(payload: &[u8]) -> Result<[u8; SIGNATURE_LEN], WireError> {
        let mut r = Reader::new(payload);
        let sig = r.array()?;
        r.finish()?;
        Ok(sig)
    }

    /// Splits a response frame into its status and payload.
    pub fn split(frame: &[u8]) -> Result<(Status, &[u8]), WireError> {
        let (&status, payload) = frame.split_first().ok_or(WireError::Truncated)?;
        Ok((Status::try_from(status)?, payload))
    }
}
