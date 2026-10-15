//! Birth certificates for agent keys, and the full verifier check.
//!
//! Each HSM has an *identity key*, created at the factory, that signs nothing
//! but birth certificates. A birth certificate says: "agent key K, with this
//! public key and these exact rules, was created on HSM S with approval from
//! these admins." A receiver who trusts the HSM's identity can then trust any
//! of its agent keys, and knows the rules each one is bound by.
//!
//! On a real device, the HSM identity would itself be certified by the
//! manufacturer at the factory; here the receiver is given it directly.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::agent::{POLICY_LEN, Policy, Statement, VerifyError, verify_statement};
use crate::wire::{PUBLIC_KEY_LEN, Reader, SERIAL_LEN, SIGNATURE_LEN, WireError, Writer};

pub const KEYCERT_DOMAIN: &[u8; 13] = b"QHSM-KEYCERT\x01";
pub const KEYCERT_LEN: usize =
    KEYCERT_DOMAIN.len() + SERIAL_LEN + 4 + PUBLIC_KEY_LEN + POLICY_LEN + 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyCert {
    pub serial: [u8; SERIAL_LEN],
    pub key: u32,
    pub public: [u8; PUBLIC_KEY_LEN],
    pub policy: Policy,
    /// Bitmask of the admins (by index) who approved creating the key.
    pub approvers: u8,
}

impl KeyCert {
    pub fn encode(&self, out: &mut [u8; KEYCERT_LEN]) -> Result<usize, WireError> {
        let mut w = Writer::new(out);
        w.raw(KEYCERT_DOMAIN)?;
        w.raw(&self.serial)?;
        w.u32(self.key)?;
        w.raw(&self.public)?;
        self.policy.write(&mut w)?;
        w.u8(self.approvers)?;
        Ok(w.len())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        if r.raw(KEYCERT_DOMAIN.len())? != KEYCERT_DOMAIN {
            return Err(WireError::Invalid);
        }
        let c = KeyCert {
            serial: r.array()?,
            key: r.u32()?,
            public: r.array()?,
            policy: Policy::read(&mut r)?,
            approvers: r.u8()?,
        };
        r.finish()?;
        Ok(c)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertError {
    BadIdentityKey,
    Malformed,
    /// Not signed by this HSM's identity key.
    BadSignature,
}

/// Checks a birth certificate against the HSM's identity public key.
pub fn verify_key_cert(
    identity: &[u8; PUBLIC_KEY_LEN],
    cert: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<KeyCert, CertError> {
    let vk = VerifyingKey::from_bytes(identity).map_err(|_| CertError::BadIdentityKey)?;
    vk.verify_strict(cert, &Signature::from_bytes(signature))
        .map_err(|_| CertError::BadSignature)?;
    KeyCert::decode(cert).map_err(|_| CertError::Malformed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionError {
    Cert(CertError),
    Statement(VerifyError),
    /// The statement is validly signed but does not belong with this
    /// certificate (different HSM, key or rules).
    Mismatch,
}

/// The receiver's complete check, starting from the one thing it trusts (the
/// HSM's identity key):
/// 1. the birth certificate was signed by that HSM,
/// 2. the statement was signed by the key the certificate describes,
/// 3. the statement names the same HSM and key, and was approved under the
///    rules in the certificate.
///
/// Checking the receiver's one-time code and expiry is left to the caller,
/// since only the receiver knows which codes it issued and what time it is.
pub fn verify_action<'a>(
    identity: &[u8; PUBLIC_KEY_LEN],
    cert: &[u8],
    cert_sig: &[u8; SIGNATURE_LEN],
    statement: &'a [u8],
    statement_sig: &[u8; SIGNATURE_LEN],
) -> Result<(KeyCert, Statement<'a>), ActionError> {
    let c = verify_key_cert(identity, cert, cert_sig).map_err(ActionError::Cert)?;
    let s =
        verify_statement(&c.public, statement, statement_sig).map_err(ActionError::Statement)?;
    if s.serial != c.serial || s.key != c.key || s.policy_digest != c.policy.digest() {
        return Err(ActionError::Mismatch);
    }
    Ok((c, s))
}
