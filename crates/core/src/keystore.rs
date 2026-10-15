//! Fixed-capacity Ed25519 key store.
//!
//! Private keys only ever exist inside this module. Callers get public keys
//! and signatures; there is deliberately no API that returns secret bytes
//! (state export in `hsm` is the single, explicit exception).

use ed25519_dalek::{Signer, SigningKey};
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::agent::Policy;
use crate::wire::{KeyUsage, MAX_EXT_ID, MAX_LABEL, PUBLIC_KEY_LEN, SIGNATURE_LEN};

pub const MAX_KEYS: usize = 16;
pub const SECRET_LEN: usize = 32;

const NO_POLICY: Policy = Policy {
    allowed: 0,
    max_amount: 0,
    budget: 0,
    confirm_above: 0,
    always_confirm: 0,
    confirmer: None,
    require_nonce: false,
};

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
    #[zeroize(skip)]
    pub(crate) usage: KeyUsage,
    /// Meaningful only for agent keys.
    pub(crate) policy: Policy,
    /// Agent keys: total spent, in cents. Only ever goes up.
    pub(crate) spent: u64,
    /// Agent keys: number of approved actions. Only ever goes up.
    pub(crate) approved: u64,
    /// Agent keys: bitmask of the admins who approved the current rules.
    pub(crate) approvers: u8,
    /// Agent keys: rules version (1 at creation, +1 per approved change).
    pub(crate) policy_version: u32,
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
        usage: KeyUsage::General,
        policy: NO_POLICY,
        spent: 0,
        approved: 0,
        approvers: 0,
        policy_version: 0,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UseError {
    NotFound,
    /// The key exists but its usage forbids this operation.
    WrongUsage,
}

/// What a key is, when it is created or restored.
#[derive(Clone, Copy)]
pub(crate) struct KeyMeta<'a> {
    pub label: &'a [u8],
    pub ext_id: &'a [u8],
    pub usage: KeyUsage,
    pub policy: Policy,
    pub spent: u64,
    pub approved: u64,
    pub approvers: u8,
    pub policy_version: u32,
}

impl<'a> KeyMeta<'a> {
    pub fn general(label: &'a [u8], ext_id: &'a [u8]) -> Self {
        KeyMeta {
            label,
            ext_id,
            usage: KeyUsage::General,
            policy: NO_POLICY,
            spent: 0,
            approved: 0,
            approvers: 0,
            policy_version: 0,
        }
    }

    pub fn agent(label: &'a [u8], ext_id: &'a [u8], policy: Policy, approvers: u8) -> Self {
        KeyMeta {
            usage: KeyUsage::Agent,
            policy,
            approvers,
            policy_version: 1,
            ..Self::general(label, ext_id)
        }
    }
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

    pub(crate) fn generate(
        &mut self,
        rng: &mut impl CryptoRngCore,
        meta: KeyMeta<'_>,
    ) -> Result<(u32, [u8; PUBLIC_KEY_LEN]), StoreError> {
        let id = self.next_id;
        let next = id.checked_add(1).ok_or(StoreError::IdsExhausted)?;
        let mut secret = [0u8; SECRET_LEN];
        rng.fill_bytes(&mut secret);
        let result = self.insert_with_id(id, &secret, meta);
        secret.zeroize();
        result?;
        self.next_id = next;
        Ok((id, self.get(id).map(|s| s.public).unwrap_or_default()))
    }

    /// Crate-private: only key generation and state import may introduce
    /// key material.
    pub(crate) fn insert_with_id(
        &mut self,
        id: u32,
        secret: &[u8; SECRET_LEN],
        meta: KeyMeta<'_>,
    ) -> Result<(), StoreError> {
        if meta.label.len() > MAX_LABEL || meta.ext_id.len() > MAX_EXT_ID {
            return Err(StoreError::FieldTooLong);
        }
        let slot = self
            .slots
            .iter_mut()
            .find(|s| !s.used)
            .ok_or(StoreError::Full)?;
        let signing = SigningKey::from_bytes(secret);
        *slot = Slot {
            used: true,
            id,
            label_len: meta.label.len() as u8,
            ext_id_len: meta.ext_id.len() as u8,
            secret: *secret,
            public: signing.verifying_key().to_bytes(),
            usage: meta.usage,
            policy: meta.policy,
            spent: meta.spent,
            approved: meta.approved,
            approvers: meta.approvers,
            policy_version: meta.policy_version,
            ..Slot::EMPTY
        };
        slot.label[..meta.label.len()].copy_from_slice(meta.label);
        slot.ext_id[..meta.ext_id.len()].copy_from_slice(meta.ext_id);
        Ok(())
    }

    pub(crate) fn get(&self, id: u32) -> Option<&Slot> {
        self.slots.iter().find(|s| s.used && s.id == id)
    }

    fn get_mut(&mut self, id: u32) -> Option<&mut Slot> {
        self.slots.iter_mut().find(|s| s.used && s.id == id)
    }

    pub fn public_key(&self, id: u32) -> Option<[u8; PUBLIC_KEY_LEN]> {
        self.get(id).map(|s| s.public)
    }

    /// Raw signing: general-purpose keys only. An agent key must never sign
    /// bytes the host chose, or its policy could be bypassed.
    pub fn sign(&self, id: u32, msg: &[u8]) -> Result<[u8; SIGNATURE_LEN], UseError> {
        self.sign_as(id, KeyUsage::General, msg)
    }

    /// Signs a statement the HSM itself built. Agent keys only.
    pub(crate) fn sign_statement(
        &self,
        id: u32,
        statement: &[u8],
    ) -> Result<[u8; SIGNATURE_LEN], UseError> {
        self.sign_as(id, KeyUsage::Agent, statement)
    }

    fn sign_as(
        &self,
        id: u32,
        usage: KeyUsage,
        msg: &[u8],
    ) -> Result<[u8; SIGNATURE_LEN], UseError> {
        let slot = self.get(id).ok_or(UseError::NotFound)?;
        if slot.usage != usage {
            return Err(UseError::WrongUsage);
        }
        // SigningKey zeroizes itself on drop (ed25519-dalek "zeroize" feature).
        let signing = SigningKey::from_bytes(&slot.secret);
        Ok(signing.sign(msg).to_bytes())
    }

    /// Charges an approved action to an agent key: adds `amount` to what it
    /// has spent and returns the action's sequence number.
    pub(crate) fn charge(&mut self, id: u32, amount: u64) -> Option<u64> {
        let slot = self.get_mut(id)?;
        let spent = slot.spent.checked_add(amount)?;
        let approved = slot.approved.checked_add(1)?;
        slot.spent = spent;
        slot.approved = approved;
        Some(approved)
    }

    /// Replaces an agent key's rules after admin approval. Spending and the
    /// action count are kept, so changing rules never resets a budget.
    pub(crate) fn update_policy(&mut self, id: u32, policy: Policy, approvers: u8) -> Option<u32> {
        let slot = self.get_mut(id)?;
        let version = slot.policy_version.checked_add(1)?;
        slot.policy = policy;
        slot.approvers = approvers;
        slot.policy_version = version;
        Some(version)
    }

    pub fn delete(&mut self, id: u32) -> bool {
        match self.get_mut(id) {
            Some(slot) => {
                slot.zeroize();
                *slot = Slot::EMPTY;
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
