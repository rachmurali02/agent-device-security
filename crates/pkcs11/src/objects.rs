//! Maps HSM keys onto PKCS#11 objects and attributes.
//!
//! Each HSM key appears as two PKCS#11 objects: a public key and a private
//! key. Object handles encode the HSM key ID and which half it is, so the
//! library keeps no object table of its own.

use cryptoki_sys::*;
use quorum_core::wire::KeyUsage;

pub const CK_UNAVAILABLE_INFORMATION: CK_ULONG = !0;

/// DER OID 1.3.101.112 (id-Ed25519, RFC 8410).
pub const ED25519_OID: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];
/// DER PrintableString "edwards25519" (PKCS#11 3.0 curve-name form).
pub const ED25519_NAME: &[u8] = b"\x13\x0cedwards25519";
/// DER OID 1.3.6.1.4.1.11591.15.1 (older GnuPG/OpenSC form).
pub const ED25519_OID_LEGACY: &[u8] = &[
    0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01,
];

pub fn is_ed25519_params(p: &[u8]) -> bool {
    p == ED25519_OID || p == ED25519_NAME || p == ED25519_OID_LEGACY
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Half {
    Public,
    Private,
}

#[derive(Debug, Clone)]
pub struct KeyObject {
    pub key: u32,
    pub label: Vec<u8>,
    pub ext_id: Vec<u8>,
    pub public: [u8; 32],
    pub usage: KeyUsage,
}

pub fn handle(key: u32, half: Half) -> CK_OBJECT_HANDLE {
    ((key as CK_OBJECT_HANDLE) << 1) | (half == Half::Private) as CK_OBJECT_HANDLE
}

pub fn split_handle(h: CK_OBJECT_HANDLE) -> Option<(u32, Half)> {
    let key = u32::try_from(h >> 1).ok().filter(|&k| k != 0)?;
    let half = if h & 1 == 1 {
        Half::Private
    } else {
        Half::Public
    };
    Some((key, half))
}

pub enum Attr {
    Value(Vec<u8>),
    /// The attribute exists but its value may never leave the HSM.
    Sensitive,
    /// The object has no such attribute.
    Invalid,
}

fn ulong(v: CK_ULONG) -> Attr {
    Attr::Value(v.to_ne_bytes().to_vec())
}

fn bool_(v: bool) -> Attr {
    Attr::Value(vec![if v { CK_TRUE } else { CK_FALSE }])
}

impl KeyObject {
    pub fn can_sign_raw(&self) -> bool {
        self.usage == KeyUsage::General
    }

    /// `CKA_ID`: the caller-supplied ID, or the HSM key ID if none was given.
    pub fn ck_id(&self) -> Vec<u8> {
        if self.ext_id.is_empty() {
            self.key.to_be_bytes().to_vec()
        } else {
            self.ext_id.clone()
        }
    }

    pub fn attribute(&self, half: Half, ty: CK_ATTRIBUTE_TYPE) -> Attr {
        let private = half == Half::Private;
        match ty {
            CKA_CLASS => ulong(if private {
                CKO_PRIVATE_KEY
            } else {
                CKO_PUBLIC_KEY
            }),
            CKA_TOKEN => bool_(true),
            CKA_PRIVATE => bool_(private),
            CKA_MODIFIABLE | CKA_COPYABLE => bool_(false),
            CKA_DESTROYABLE => bool_(true),
            CKA_LABEL => Attr::Value(self.label.clone()),
            CKA_ID => Attr::Value(self.ck_id()),
            CKA_KEY_TYPE => ulong(CKK_EC_EDWARDS),
            CKA_LOCAL => bool_(true),
            CKA_KEY_GEN_MECHANISM => ulong(CKM_EC_EDWARDS_KEY_PAIR_GEN),
            // Agent keys sign only HSM-built statements (via quorum-cli), so
            // they offer no PKCS#11 signing mechanism at all.
            CKA_ALLOWED_MECHANISMS if self.can_sign_raw() => ulong(CKM_EDDSA),
            CKA_ALLOWED_MECHANISMS => Attr::Value(Vec::new()),
            CKA_DERIVE | CKA_ENCRYPT | CKA_DECRYPT | CKA_WRAP | CKA_UNWRAP => bool_(false),
            CKA_EC_PARAMS => Attr::Value(ED25519_OID.to_vec()),
            // Public half only.
            CKA_VERIFY if !private => bool_(true),
            CKA_VERIFY_RECOVER if !private => bool_(false),
            CKA_TRUSTED if !private => bool_(false),
            CKA_EC_POINT if !private => {
                // DER OCTET STRING wrapping the 32-byte public key.
                let mut v = vec![0x04, 0x20];
                v.extend_from_slice(&self.public);
                Attr::Value(v)
            }
            // Private half only.
            CKA_SIGN if private => bool_(self.can_sign_raw()),
            CKA_SIGN_RECOVER if private => bool_(false),
            CKA_SENSITIVE | CKA_ALWAYS_SENSITIVE | CKA_NEVER_EXTRACTABLE if private => bool_(true),
            CKA_EXTRACTABLE | CKA_ALWAYS_AUTHENTICATE | CKA_WRAP_WITH_TRUSTED if private => {
                bool_(false)
            }
            CKA_VALUE if private => Attr::Sensitive,
            _ => Attr::Invalid,
        }
    }

    /// PKCS#11 template matching: every template attribute must be present
    /// with exactly the same value.
    pub fn matches(&self, half: Half, template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)]) -> bool {
        template
            .iter()
            .all(|(ty, want)| match self.attribute(half, *ty) {
                Attr::Value(have) => &have == want,
                Attr::Sensitive | Attr::Invalid => false,
            })
    }
}
