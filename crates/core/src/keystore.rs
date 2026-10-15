//! Fixed-capacity Ed25519 key store.
//!
//! Private keys only ever exist inside this module. Callers get public keys
//! and signatures; there is deliberately no API that returns secret bytes
//! (state export in `hsm` is the single, explicit exception).

use ed25519_dalek::{Signer, SigningKey};
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::wire::{MAX_EXT_ID, MAX_LABEL, PUBLIC_KEY_LEN, SIGNATURE_LEN};

pub const MAX_KEYS: usize = 16;
pub const SECRET_LEN: usize = 32;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct Slot {
    pub(crate) used: bool,
    pub(crate) id: u32,
    pub(crate) label: [u8; MAX_LABEL],
    pub(crate) label_len: u8,
    pub(crate) ext_id: [u8; MAX_EXT_ID],
    pub(crate) ext_id_len: u8,
    pub(crate) secret: [u8; SECRET_LEN],
    pub(crate) public: [u8; PUBLIC_KEY_LEN],
}

impl Slot {
    const EMPTY: Slot = Slot {
        used: false,
        id: 0,
        label: [0; MAX_LABEL],
        label_len: 0,
        ext_id: [0; MAX_EXT_ID],
        ext_id_len: 0,
        secret: [0; SECRET_LEN],
        public: [0; PUBLIC_KEY_LEN],
    };

    pub fn label(&self) -> &[u8] {
        &self.label[..self.label_len as usize]
    }

    pub fn ext_id(&self) -> &[u8] {
        &self.ext_id[..self.ext_id_len as usize]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    Full,
    FieldTooLong,
    /// Key IDs are never reused; the 32-bit space is exhausted.
    IdsExhausted,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyStore {
    slots: [Slot; MAX_KEYS],
    /// Next ID to hand out. IDs are monotonic and never reused, so a stale
    /// handle can never silently refer to a newer key.
    next_id: u32,
}

impl Default for KeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyStore {
    pub const fn new() -> Self {
        KeyStore {
            slots: [Slot::EMPTY; MAX_KEYS],
            next_id: 1,
        }
    }

    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.used).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn generate(
        &mut self,
        rng: &mut impl CryptoRngCore,
        label: &[u8],
        ext_id: &[u8],
    ) -> Result<(u32, [u8; PUBLIC_KEY_LEN]), StoreError> {
        let mut secret = [0u8; SECRET_LEN];
        rng.fill_bytes(&mut secret);
        let result = self.insert(&secret, label, ext_id);
        secret.zeroize();
        result
    }

    /// Inserts a key with a caller-chosen secret. Crate-private: only key
    /// generation and state import may introduce key material.
    pub(crate) fn insert(
        &mut self,
        secret: &[u8; SECRET_LEN],
        label: &[u8],
        ext_id: &[u8],
    ) -> Result<(u32, [u8; PUBLIC_KEY_LEN]), StoreError> {
        let id = self.next_id;
        let next = id.checked_add(1).ok_or(StoreError::IdsExhausted)?;
        self.insert_with_id(id, secret, label, ext_id)?;
        self.next_id = next;
        Ok((id, self.get(id).map(|s| s.public).unwrap_or_default()))
    }

    pub(crate) fn insert_with_id(
        &mut self,
        id: u32,
        secret: &[u8; SECRET_LEN],
        label: &[u8],
        ext_id: &[u8],
    ) -> Result<(), StoreError> {
        if label.len() > MAX_LABEL || ext_id.len() > MAX_EXT_ID {
            return Err(StoreError::FieldTooLong);
        }
        let slot = self
            .slots
            .iter_mut()
            .find(|s| !s.used)
            .ok_or(StoreError::Full)?;
        let signing = SigningKey::from_bytes(secret);
        slot.used = true;
        slot.id = id;
        slot.label = [0; MAX_LABEL];
        slot.label[..label.len()].copy_from_slice(label);
        slot.label_len = label.len() as u8;
        slot.ext_id = [0; MAX_EXT_ID];
        slot.ext_id[..ext_id.len()].copy_from_slice(ext_id);
        slot.ext_id_len = ext_id.len() as u8;
        slot.secret = *secret;
        slot.public = signing.verifying_key().to_bytes();
        Ok(())
    }

    pub(crate) fn get(&self, id: u32) -> Option<&Slot> {
        self.slots.iter().find(|s| s.used && s.id == id)
    }

    pub fn public_key(&self, id: u32) -> Option<[u8; PUBLIC_KEY_LEN]> {
        self.get(id).map(|s| s.public)
    }

    pub fn sign(&self, id: u32, msg: &[u8]) -> Option<[u8; SIGNATURE_LEN]> {
        let slot = self.get(id)?;
        // SigningKey zeroizes itself on drop (ed25519-dalek "zeroize" feature).
        let signing = SigningKey::from_bytes(&slot.secret);
        Some(signing.sign(msg).to_bytes())
    }

    pub fn delete(&mut self, id: u32) -> bool {
        match self.slots.iter_mut().find(|s| s.used && s.id == id) {
            Some(slot) => {
                slot.zeroize();
                true
            }
            None => false,
        }
    }

    pub(crate) fn slots(&self) -> impl Iterator<Item = &Slot> {
        self.slots.iter().filter(|s| s.used)
    }

    pub(crate) fn next_id(&self) -> u32 {
        self.next_id
    }

    pub(crate) fn set_next_id(&mut self, next: u32) {
        self.next_id = next;
    }
}
