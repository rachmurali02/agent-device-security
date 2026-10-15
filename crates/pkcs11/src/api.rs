//! The PKCS#11 functions this library implements.
//!
//! This layer only translates. It never decides whether an operation is
//! allowed; it forwards the request and reports what the HSM said. The one
//! exception is signature *verification*, which uses only public data and
//! runs locally.

#![allow(non_snake_case, clippy::missing_safety_doc)]

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use cryptoki_sys::*;
use ed25519_dalek::{Signature, VerifyingKey};
use quorum_core::wire::{
    MAX_EXT_ID, MAX_LABEL, MAX_MESSAGE, MAX_PIN, MIN_PIN, Request, SIGNATURE_LEN, Status, resp,
};

use crate::function_list::FUNCTION_LIST;
use crate::objects::{
    Attr, CK_UNAVAILABLE_INFORMATION, Half, KeyObject, handle, is_ed25519_params, split_handle,
};
use quorum_client::{self as client, Client};

const SLOT_ID: CK_SLOT_ID = 0;
const MECHANISMS: [CK_MECHANISM_TYPE; 2] = [CKM_EC_EDWARDS_KEY_PAIR_GEN, CKM_EDDSA];

#[derive(Default)]
struct SessionState {
    flags: CK_FLAGS,
    find: Option<Vec<CK_OBJECT_HANDLE>>,
    sign_key: Option<u32>,
    verify_key: Option<[u8; 32]>,
}

struct Library {
    hsm: Client,
    sessions: HashMap<CK_SESSION_HANDLE, SessionState>,
    next_session: CK_SESSION_HANDLE,
    /// Mirrors the HSM's login state for C_GetSessionInfo. The HSM enforces
    /// login itself; this copy is only for reporting.
    logged_in: bool,
}

static LIBRARY: Mutex<Option<Library>> = Mutex::new(None);

type Result<T> = std::result::Result<T, CK_RV>;

fn lock() -> MutexGuard<'static, Option<Library>> {
    LIBRARY.lock().unwrap_or_else(|p| p.into_inner())
}

/// Runs `f` with the initialized library, converting errors to a CK_RV.
fn with_lib(f: impl FnOnce(&mut Library) -> Result<()>) -> CK_RV {
    let mut guard = lock();
    match guard.as_mut() {
        None => CKR_CRYPTOKI_NOT_INITIALIZED,
        Some(lib) => f(lib).err().unwrap_or(CKR_OK),
    }
}

fn status_to_rv(s: Status) -> CK_RV {
    match s {
        Status::Ok => CKR_OK,
        Status::NotLoggedIn => CKR_USER_NOT_LOGGED_IN,
        Status::AlreadyLoggedIn => CKR_USER_ALREADY_LOGGED_IN,
        Status::PinIncorrect => CKR_PIN_INCORRECT,
        Status::PinLocked => CKR_PIN_LOCKED,
        Status::KeyNotFound => CKR_KEY_HANDLE_INVALID,
        Status::StoreFull => CKR_DEVICE_MEMORY,
        Status::BadRequest | Status::ResponseTooLarge | Status::Fault => CKR_DEVICE_ERROR,
        // Agent keys refuse raw signing; agent actions go through quorum-cli.
        Status::UsageNotAllowed => CKR_KEY_FUNCTION_NOT_PERMITTED,
        Status::ActionNotAllowed
        | Status::AmountTooHigh
        | Status::BudgetExceeded
        | Status::ConfirmationRequired
        | Status::ConfirmationInvalid
        | Status::NoChallenge => CKR_FUNCTION_REJECTED,
    }
}

impl Library {
    fn call(&mut self, req: Request<'_>) -> Result<Vec<u8>> {
        let (status, payload) = self.hsm.call(&req).map_err(|e| {
            eprintln!("quorum-pkcs11: HSM connection failed: {e}");
            CKR_DEVICE_REMOVED
        })?;
        match status {
            Status::Ok => Ok(payload),
            other => Err(status_to_rv(other)),
        }
    }

    fn info(&mut self) -> Result<resp::Info> {
        let payload = self.call(Request::GetInfo)?;
        resp::Info::decode(&payload).map_err(|_| CKR_DEVICE_ERROR)
    }

    fn keys(&mut self) -> Result<Vec<KeyObject>> {
        let payload = self.call(Request::ListKeys)?;
        let list = resp::decode_key_list(&payload).map_err(|_| CKR_DEVICE_ERROR)?;
        Ok(list
            .map(|e| KeyObject {
                key: e.key,
                label: e.label.to_vec(),
                ext_id: e.ext_id.to_vec(),
                public: e.public,
                usage: e.usage,
            })
            .collect())
    }

    /// Looks up an object the caller is allowed to see. Private objects are
    /// invisible until login, as PKCS#11 requires.
    fn object(&mut self, h: CK_OBJECT_HANDLE) -> Result<(KeyObject, Half)> {
        let (key, half) = split_handle(h).ok_or(CKR_OBJECT_HANDLE_INVALID)?;
        if half == Half::Private && !self.logged_in {
            return Err(CKR_OBJECT_HANDLE_INVALID);
        }
        let obj = self
            .keys()?
            .into_iter()
            .find(|k| k.key == key)
            .ok_or(CKR_OBJECT_HANDLE_INVALID)?;
        Ok((obj, half))
    }

    fn session(&mut self, h: CK_SESSION_HANDLE) -> Result<&mut SessionState> {
        self.sessions.get_mut(&h).ok_or(CKR_SESSION_HANDLE_INVALID)
    }

    fn require_rw(&mut self, h: CK_SESSION_HANDLE) -> Result<()> {
        if self.session(h)?.flags & CKF_RW_SESSION == 0 {
            return Err(CKR_SESSION_READ_ONLY);
        }
        Ok(())
    }
}

// ---- pointer helpers -------------------------------------------------------

unsafe fn slice<'a, T>(p: *const T, n: CK_ULONG) -> Result<&'a [T]> {
    if n == 0 {
        return Ok(&[]);
    }
    if p.is_null() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    Ok(unsafe { std::slice::from_raw_parts(p, n as usize) })
}

unsafe fn out<'a, T>(p: *mut T) -> Result<&'a mut T> {
    unsafe { p.as_mut() }.ok_or(CKR_ARGUMENTS_BAD)
}

/// Copies a template into owned (type, value) pairs.
unsafe fn read_template(
    p: *const CK_ATTRIBUTE,
    n: CK_ULONG,
) -> Result<Vec<(CK_ATTRIBUTE_TYPE, Vec<u8>)>> {
    unsafe { slice(p, n) }?
        .iter()
        .map(|a| {
            let v = unsafe { slice(a.pValue as *const u8, a.ulValueLen) }?;
            Ok((a.type_, v.to_vec()))
        })
        .collect()
}

/// Space-padded fixed-width PKCS#11 string field.
fn pad<const N: usize>(s: &[u8]) -> [u8; N] {
    let mut out = [b' '; N];
    let n = s.len().min(N);
    out[..n].copy_from_slice(&s[..n]);
    out
}

/// Implements the C_Sign/C_GetMechanismList output convention: a NULL
/// buffer is a size query, a short buffer is CKR_BUFFER_TOO_SMALL.
unsafe fn write_out<T: Copy>(data: &[T], p: *mut T, len: *mut CK_ULONG) -> Result<()> {
    let len = unsafe { out(len) }?;
    let have = *len as usize;
    *len = data.len() as CK_ULONG;
    if p.is_null() {
        return Ok(());
    }
    if have < data.len() {
        return Err(CKR_BUFFER_TOO_SMALL);
    }
    unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), p, data.len()) };
    Ok(())
}

// ---- general ---------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetFunctionList(pp: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    match unsafe { out(pp) } {
        Ok(pp) => {
            *pp = &FUNCTION_LIST as *const CK_FUNCTION_LIST as *mut CK_FUNCTION_LIST;
            CKR_OK
        }
        Err(rv) => rv,
    }
}

pub unsafe extern "C" fn C_Initialize(args: *mut std::os::raw::c_void) -> CK_RV {
    if let Some(args) = unsafe { (args as *const CK_C_INITIALIZE_ARGS).as_ref() }
        && !args.pReserved.is_null()
    {
        return CKR_ARGUMENTS_BAD;
    }
    let mut guard = lock();
    if guard.is_some() {
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }
    match Client::connect() {
        Ok(hsm) => {
            *guard = Some(Library {
                hsm,
                sessions: HashMap::new(),
                next_session: 1,
                logged_in: false,
            });
            CKR_OK
        }
        Err(e) => {
            eprintln!(
                "quorum-pkcs11: cannot reach HSM at {} ({e}). Is quorum-emulator running? \
                 Set {} to override.",
                client::socket_path().display(),
                client::SOCKET_ENV
            );
            CKR_DEVICE_ERROR
        }
    }
}

pub unsafe extern "C" fn C_Finalize(reserved: *mut std::os::raw::c_void) -> CK_RV {
    if !reserved.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    match lock().take() {
        Some(_) => CKR_OK,
        None => CKR_CRYPTOKI_NOT_INITIALIZED,
    }
}

pub unsafe extern "C" fn C_GetInfo(info: *mut CK_INFO) -> CK_RV {
    with_lib(|_| {
        *unsafe { out(info) }? = CK_INFO {
            cryptokiVersion: CK_VERSION {
                major: 2,
                minor: 40,
            },
            manufacturerID: pad(b"agent-device-security"),
            flags: 0,
            libraryDescription: pad(b"quorum-hsm PKCS#11"),
            libraryVersion: CK_VERSION { major: 0, minor: 1 },
        };
        Ok(())
    })
}

// ---- slots and tokens ------------------------------------------------------

pub unsafe extern "C" fn C_GetSlotList(
    _token_present: CK_BBOOL,
    list: *mut CK_SLOT_ID,
    count: *mut CK_ULONG,
) -> CK_RV {
    with_lib(|_| unsafe { write_out(&[SLOT_ID], list, count) })
}

fn check_slot(slot: CK_SLOT_ID) -> Result<()> {
    if slot == SLOT_ID {
        Ok(())
    } else {
        Err(CKR_SLOT_ID_INVALID)
    }
}

pub unsafe extern "C" fn C_GetSlotInfo(slot: CK_SLOT_ID, info: *mut CK_SLOT_INFO) -> CK_RV {
    with_lib(|_| {
        check_slot(slot)?;
        *unsafe { out(info) }? = CK_SLOT_INFO {
            slotDescription: pad(b"quorum-hsm emulator"),
            manufacturerID: pad(b"agent-device-security"),
            flags: CKF_TOKEN_PRESENT | CKF_HW_SLOT,
            hardwareVersion: CK_VERSION { major: 0, minor: 1 },
            firmwareVersion: CK_VERSION { major: 0, minor: 1 },
        };
        Ok(())
    })
}

pub unsafe extern "C" fn C_GetTokenInfo(slot: CK_SLOT_ID, info: *mut CK_TOKEN_INFO) -> CK_RV {
    with_lib(|lib| {
        check_slot(slot)?;
        let i = lib.info()?;
        let mut flags = CKF_TOKEN_INITIALIZED | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED;
        if i.flags & resp::FLAG_PIN_LOCKED != 0 {
            flags |= CKF_USER_PIN_LOCKED;
        } else if i.pin_tries_left == 1 {
            flags |= CKF_USER_PIN_FINAL_TRY | CKF_USER_PIN_COUNT_LOW;
        } else if i.pin_tries_left < quorum_core::hsm::MAX_PIN_TRIES {
            flags |= CKF_USER_PIN_COUNT_LOW;
        }
        let sessions = lib.sessions.len() as CK_ULONG;
        let rw = lib
            .sessions
            .values()
            .filter(|s| s.flags & CKF_RW_SESSION != 0)
            .count() as CK_ULONG;
        *unsafe { out(info) }? = CK_TOKEN_INFO {
            label: pad(b"quorum-hsm"),
            manufacturerID: pad(b"agent-device-security"),
            model: pad(b"emulator"),
            serialNumber: i.serial,
            flags,
            ulMaxSessionCount: CK_EFFECTIVELY_INFINITE,
            ulSessionCount: sessions,
            ulMaxRwSessionCount: CK_EFFECTIVELY_INFINITE,
            ulRwSessionCount: rw,
            ulMaxPinLen: MAX_PIN as CK_ULONG,
            ulMinPinLen: MIN_PIN as CK_ULONG,
            ulTotalPublicMemory: CK_UNAVAILABLE_INFORMATION,
            ulFreePublicMemory: CK_UNAVAILABLE_INFORMATION,
            ulTotalPrivateMemory: CK_UNAVAILABLE_INFORMATION,
            ulFreePrivateMemory: CK_UNAVAILABLE_INFORMATION,
            hardwareVersion: CK_VERSION { major: 0, minor: 1 },
            firmwareVersion: CK_VERSION {
                major: i.fw_major,
                minor: i.fw_minor,
            },
            utcTime: [b' '; 16],
        };
        Ok(())
    })
}

pub unsafe extern "C" fn C_GetMechanismList(
    slot: CK_SLOT_ID,
    list: *mut CK_MECHANISM_TYPE,
    count: *mut CK_ULONG,
) -> CK_RV {
    with_lib(|_| {
        check_slot(slot)?;
        unsafe { write_out(&MECHANISMS, list, count) }
    })
}

pub unsafe extern "C" fn C_GetMechanismInfo(
    slot: CK_SLOT_ID,
    mech: CK_MECHANISM_TYPE,
    info: *mut CK_MECHANISM_INFO,
) -> CK_RV {
    with_lib(|_| {
        check_slot(slot)?;
        let flags = match mech {
            CKM_EC_EDWARDS_KEY_PAIR_GEN => CKF_HW | CKF_GENERATE_KEY_PAIR,
            CKM_EDDSA => CKF_HW | CKF_SIGN | CKF_VERIFY,
            _ => return Err(CKR_MECHANISM_INVALID),
        };
        *unsafe { out(info) }? = CK_MECHANISM_INFO {
            ulMinKeySize: 255,
            ulMaxKeySize: 255,
            flags,
        };
        Ok(())
    })
}

// ---- sessions and login ----------------------------------------------------

pub unsafe extern "C" fn C_OpenSession(
    slot: CK_SLOT_ID,
    flags: CK_FLAGS,
    _app: *mut std::os::raw::c_void,
    _notify: CK_NOTIFY,
    session: *mut CK_SESSION_HANDLE,
) -> CK_RV {
    with_lib(|lib| {
        check_slot(slot)?;
        if flags & CKF_SERIAL_SESSION == 0 {
            return Err(CKR_SESSION_PARALLEL_NOT_SUPPORTED);
        }
        let out = unsafe { out(session) }?;
        let h = lib.next_session;
        lib.next_session += 1;
        lib.sessions.insert(
            h,
            SessionState {
                flags,
                ..Default::default()
            },
        );
        *out = h;
        Ok(())
    })
}

/// When the last session closes, PKCS#11 says the user is logged out.
fn logout_if_idle(lib: &mut Library) -> Result<()> {
    if lib.sessions.is_empty() && lib.logged_in {
        lib.logged_in = false;
        lib.call(Request::Logout)?;
    }
    Ok(())
}

pub unsafe extern "C" fn C_CloseSession(session: CK_SESSION_HANDLE) -> CK_RV {
    with_lib(|lib| {
        lib.sessions
            .remove(&session)
            .ok_or(CKR_SESSION_HANDLE_INVALID)?;
        logout_if_idle(lib)
    })
}

pub unsafe extern "C" fn C_CloseAllSessions(slot: CK_SLOT_ID) -> CK_RV {
    with_lib(|lib| {
        check_slot(slot)?;
        lib.sessions.clear();
        logout_if_idle(lib)
    })
}

pub unsafe extern "C" fn C_GetSessionInfo(
    session: CK_SESSION_HANDLE,
    info: *mut CK_SESSION_INFO,
) -> CK_RV {
    with_lib(|lib| {
        let logged_in = lib.logged_in;
        let flags = lib.session(session)?.flags;
        let rw = flags & CKF_RW_SESSION != 0;
        let state = match (rw, logged_in) {
            (false, false) => CKS_RO_PUBLIC_SESSION,
            (true, false) => CKS_RW_PUBLIC_SESSION,
            (false, true) => CKS_RO_USER_FUNCTIONS,
            (true, true) => CKS_RW_USER_FUNCTIONS,
        };
        *unsafe { out(info) }? = CK_SESSION_INFO {
            slotID: SLOT_ID,
            state,
            flags,
            ulDeviceError: 0,
        };
        Ok(())
    })
}

pub unsafe extern "C" fn C_Login(
    session: CK_SESSION_HANDLE,
    user: CK_USER_TYPE,
    pin: *mut CK_UTF8CHAR,
    pin_len: CK_ULONG,
) -> CK_RV {
    with_lib(|lib| {
        lib.session(session)?;
        if user != CKU_USER {
            // There is no security officer role yet; administrative actions
            // will require quorum approval instead (see roadmap).
            return Err(CKR_USER_TYPE_INVALID);
        }
        let pin = unsafe { slice(pin, pin_len) }?;
        if pin.len() > MAX_PIN {
            return Err(CKR_PIN_LEN_RANGE);
        }
        lib.call(Request::Login { pin })?;
        lib.logged_in = true;
        Ok(())
    })
}

pub unsafe extern "C" fn C_Logout(session: CK_SESSION_HANDLE) -> CK_RV {
    with_lib(|lib| {
        lib.session(session)?;
        if !lib.logged_in {
            return Err(CKR_USER_NOT_LOGGED_IN);
        }
        lib.logged_in = false;
        lib.call(Request::Logout).map(drop)
    })
}

// ---- objects ---------------------------------------------------------------

pub unsafe extern "C" fn C_GetAttributeValue(
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    template: *mut CK_ATTRIBUTE,
    count: CK_ULONG,
) -> CK_RV {
    with_lib(|lib| {
        lib.session(session)?;
        let (obj, half) = lib.object(object)?;
        if template.is_null() && count > 0 {
            return Err(CKR_ARGUMENTS_BAD);
        }
        let attrs = if count == 0 {
            &mut [][..]
        } else {
            unsafe { std::slice::from_raw_parts_mut(template, count as usize) }
        };
        // Per the spec, process every attribute and report the last error.
        let mut rv = CKR_OK;
        for a in attrs {
            let value = match obj.attribute(half, a.type_) {
                Attr::Value(v) => v,
                Attr::Sensitive => {
                    a.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    rv = CKR_ATTRIBUTE_SENSITIVE;
                    continue;
                }
                Attr::Invalid => {
                    a.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    rv = CKR_ATTRIBUTE_TYPE_INVALID;
                    continue;
                }
            };
            if a.pValue.is_null() {
                a.ulValueLen = value.len() as CK_ULONG;
            } else if (a.ulValueLen as usize) < value.len() {
                a.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                rv = CKR_BUFFER_TOO_SMALL;
            } else {
                unsafe {
                    std::ptr::copy_nonoverlapping(value.as_ptr(), a.pValue as *mut u8, value.len())
                };
                a.ulValueLen = value.len() as CK_ULONG;
            }
        }
        if rv == CKR_OK { Ok(()) } else { Err(rv) }
    })
}

pub unsafe extern "C" fn C_FindObjectsInit(
    session: CK_SESSION_HANDLE,
    template: *mut CK_ATTRIBUTE,
    count: CK_ULONG,
) -> CK_RV {
    with_lib(|lib| {
        if lib.session(session)?.find.is_some() {
            return Err(CKR_OPERATION_ACTIVE);
        }
        let template = unsafe { read_template(template, count) }?;
        let logged_in = lib.logged_in;
        let mut found = Vec::new();
        for obj in lib.keys()? {
            for half in [Half::Public, Half::Private] {
                if half == Half::Private && !logged_in {
                    continue;
                }
                if obj.matches(half, &template) {
                    found.push(handle(obj.key, half));
                }
            }
        }
        // Results are handed out from the back; reverse to keep ID order.
        found.reverse();
        lib.session(session)?.find = Some(found);
        Ok(())
    })
}

pub unsafe extern "C" fn C_FindObjects(
    session: CK_SESSION_HANDLE,
    objects: *mut CK_OBJECT_HANDLE,
    max: CK_ULONG,
    count: *mut CK_ULONG,
) -> CK_RV {
    with_lib(|lib| {
        let pending = lib
            .session(session)?
            .find
            .as_mut()
            .ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
        let count = unsafe { out(count) }?;
        if objects.is_null() && max > 0 {
            return Err(CKR_ARGUMENTS_BAD);
        }
        let mut n = 0;
        while n < max as usize {
            let Some(h) = pending.pop() else { break };
            unsafe { *objects.add(n) = h };
            n += 1;
        }
        *count = n as CK_ULONG;
        Ok(())
    })
}

pub unsafe extern "C" fn C_FindObjectsFinal(session: CK_SESSION_HANDLE) -> CK_RV {
    with_lib(|lib| {
        lib.session(session)?
            .find
            .take()
            .map(drop)
            .ok_or(CKR_OPERATION_NOT_INITIALIZED)
    })
}

pub unsafe extern "C" fn C_DestroyObject(
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
) -> CK_RV {
    with_lib(|lib| {
        lib.require_rw(session)?;
        // Destroying either half destroys the key pair: the HSM stores one key.
        let (obj, _) = lib.object(object)?;
        lib.call(Request::DeleteKey { key: obj.key }).map(drop)
    })
}

// ---- key generation --------------------------------------------------------

pub unsafe extern "C" fn C_GenerateKeyPair(
    session: CK_SESSION_HANDLE,
    mechanism: *mut CK_MECHANISM,
    pub_template: *mut CK_ATTRIBUTE,
    pub_count: CK_ULONG,
    priv_template: *mut CK_ATTRIBUTE,
    priv_count: CK_ULONG,
    pub_handle: *mut CK_OBJECT_HANDLE,
    priv_handle: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    with_lib(|lib| {
        lib.require_rw(session)?;
        if unsafe { out(mechanism) }?.mechanism != CKM_EC_EDWARDS_KEY_PAIR_GEN {
            return Err(CKR_MECHANISM_INVALID);
        }
        let pub_t = unsafe { read_template(pub_template, pub_count) }?;
        let priv_t = unsafe { read_template(priv_template, priv_count) }?;
        let pub_out = unsafe { out(pub_handle) }?;
        let priv_out = unsafe { out(priv_handle) }?;

        let mut label: &[u8] = &[];
        let mut ext_id: &[u8] = &[];
        for (ty, v) in pub_t.iter().chain(priv_t.iter()) {
            let truthy = v.first().is_some_and(|&b| b != 0);
            match *ty {
                CKA_LABEL if v.len() <= MAX_LABEL => label = v,
                CKA_ID if v.len() <= MAX_EXT_ID => ext_id = v,
                CKA_LABEL | CKA_ID => return Err(CKR_ATTRIBUTE_VALUE_INVALID),
                CKA_EC_PARAMS if !is_ed25519_params(v) => return Err(CKR_CURVE_NOT_SUPPORTED),
                // Keys never leave the HSM and only live on the token.
                CKA_EXTRACTABLE if truthy => return Err(CKR_ATTRIBUTE_VALUE_INVALID),
                CKA_SENSITIVE | CKA_TOKEN if !truthy => return Err(CKR_ATTRIBUTE_VALUE_INVALID),
                _ => {}
            }
        }

        let payload = lib.call(Request::GenerateKey { label, ext_id })?;
        let g = resp::Generated::decode(&payload).map_err(|_| CKR_DEVICE_ERROR)?;
        *pub_out = handle(g.key, Half::Public);
        *priv_out = handle(g.key, Half::Private);
        Ok(())
    })
}

// ---- signing ---------------------------------------------------------------

/// Plain Ed25519 only: no pre-hash (Ed25519ph) and no context (Ed25519ctx).
unsafe fn check_eddsa(mechanism: *mut CK_MECHANISM) -> Result<()> {
    let m = unsafe { out(mechanism) }?;
    if m.mechanism != CKM_EDDSA {
        return Err(CKR_MECHANISM_INVALID);
    }
    if !m.pParameter.is_null() {
        if (m.ulParameterLen as usize) < std::mem::size_of::<CK_EDDSA_PARAMS>() {
            return Err(CKR_MECHANISM_PARAM_INVALID);
        }
        let p = unsafe { &*(m.pParameter as *const CK_EDDSA_PARAMS) };
        if p.phFlag != 0 || p.ulContextDataLen != 0 {
            return Err(CKR_MECHANISM_PARAM_INVALID);
        }
    }
    Ok(())
}

pub unsafe extern "C" fn C_SignInit(
    session: CK_SESSION_HANDLE,
    mechanism: *mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    with_lib(|lib| {
        if lib.session(session)?.sign_key.is_some() {
            return Err(CKR_OPERATION_ACTIVE);
        }
        unsafe { check_eddsa(mechanism) }?;
        if !lib.logged_in {
            return Err(CKR_USER_NOT_LOGGED_IN);
        }
        let (obj, half) = lib.object(key).map_err(|_| CKR_KEY_HANDLE_INVALID)?;
        if half != Half::Private {
            return Err(CKR_KEY_TYPE_INCONSISTENT);
        }
        // Reported early for a clear error; the HSM enforces it regardless.
        if !obj.can_sign_raw() {
            return Err(CKR_KEY_FUNCTION_NOT_PERMITTED);
        }
        lib.session(session)?.sign_key = Some(obj.key);
        Ok(())
    })
}

pub unsafe extern "C" fn C_Sign(
    session: CK_SESSION_HANDLE,
    data: *mut CK_BYTE,
    data_len: CK_ULONG,
    signature: *mut CK_BYTE,
    sig_len: *mut CK_ULONG,
) -> CK_RV {
    with_lib(|lib| {
        let key = lib
            .session(session)?
            .sign_key
            .ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
        // Size queries and short buffers leave the operation active.
        let len = unsafe { out(sig_len) }?;
        if signature.is_null() {
            *len = SIGNATURE_LEN as CK_ULONG;
            return Ok(());
        }
        if (*len as usize) < SIGNATURE_LEN {
            *len = SIGNATURE_LEN as CK_ULONG;
            return Err(CKR_BUFFER_TOO_SMALL);
        }
        // Anything else ends the operation, success or not.
        lib.session(session)?.sign_key = None;
        let msg = unsafe { slice(data, data_len) }?;
        if msg.len() > MAX_MESSAGE {
            return Err(CKR_DATA_LEN_RANGE);
        }
        let payload = lib.call(Request::Sign { key, msg })?;
        let sig = resp::decode_signature(&payload).map_err(|_| CKR_DEVICE_ERROR)?;
        unsafe { std::ptr::copy_nonoverlapping(sig.as_ptr(), signature, SIGNATURE_LEN) };
        *len = SIGNATURE_LEN as CK_ULONG;
        Ok(())
    })
}

pub unsafe extern "C" fn C_VerifyInit(
    session: CK_SESSION_HANDLE,
    mechanism: *mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    with_lib(|lib| {
        if lib.session(session)?.verify_key.is_some() {
            return Err(CKR_OPERATION_ACTIVE);
        }
        unsafe { check_eddsa(mechanism) }?;
        let (obj, _) = lib.object(key).map_err(|_| CKR_KEY_HANDLE_INVALID)?;
        lib.session(session)?.verify_key = Some(obj.public);
        Ok(())
    })
}

pub unsafe extern "C" fn C_Verify(
    session: CK_SESSION_HANDLE,
    data: *mut CK_BYTE,
    data_len: CK_ULONG,
    signature: *mut CK_BYTE,
    sig_len: CK_ULONG,
) -> CK_RV {
    with_lib(|lib| {
        let public = lib
            .session(session)?
            .verify_key
            .take()
            .ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
        let msg = unsafe { slice(data, data_len) }?;
        let sig = unsafe { slice(signature, sig_len) }?;
        let sig: [u8; SIGNATURE_LEN] = sig.try_into().map_err(|_| CKR_SIGNATURE_LEN_RANGE)?;
        let vk = VerifyingKey::from_bytes(&public).map_err(|_| CKR_DEVICE_ERROR)?;
        vk.verify_strict(msg, &Signature::from_bytes(&sig))
            .map_err(|_| CKR_SIGNATURE_INVALID)
    })
}
