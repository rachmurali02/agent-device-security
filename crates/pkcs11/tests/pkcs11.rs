//! End-to-end tests: PKCS#11 calls -> socket -> emulated HSM.
//!
//! The library has process-global state (as every PKCS#11 module does), so
//! the tests run one at a time behind a lock.

use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::ptr;
use std::sync::Mutex;

use cryptoki_sys::*;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use quorum_core::{Hsm, Provisioning};
use quorum_emulator::{Device, FileStorage};

static SERIAL: Mutex<()> = Mutex::new(());
const PIN: &[u8] = b"123456";
const SERIAL_NO: &[u8; 16] = b"TEST000000000001";

fn admin(i: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[40 + i; 32])
}

fn functions() -> &'static CK_FUNCTION_LIST {
    let mut list: *mut CK_FUNCTION_LIST = ptr::null_mut();
    assert_eq!(
        unsafe { quorum_pkcs11::C_GetFunctionList(&mut list) },
        CKR_OK
    );
    unsafe { &*list }
}

/// A fresh HSM on its own socket, with the library initialized against it.
struct Token {
    f: &'static CK_FUNCTION_LIST,
    _dir: PathBuf,
    _guard: std::sync::MutexGuard<'static, ()>,
}

impl Token {
    fn new(name: &str) -> Self {
        let guard = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        let dir = std::env::temp_dir().join(format!("quorum-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("hsm.sock");

        let mut storage = FileStorage::new(dir.join("hsm.state"));
        let hsm = Hsm::provision(
            Provisioning {
                serial: *SERIAL_NO,
                pin: PIN,
                admins: &[
                    admin(0).verifying_key().to_bytes(),
                    admin(1).verifying_key().to_bytes(),
                ],
                threshold: 2,
            },
            &mut rand_core::OsRng,
            &mut storage,
        )
        .unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        std::thread::spawn(move || quorum_emulator::serve(listener, Device { hsm, storage }));

        // Safe: tests are serialized by SERIAL, so no other thread reads env.
        unsafe { std::env::set_var("QUORUM_HSM_SOCKET", &socket) };
        let f = functions();
        assert_eq!(unsafe { f.C_Initialize.unwrap()(ptr::null_mut()) }, CKR_OK);
        Token {
            f,
            _dir: dir,
            _guard: guard,
        }
    }

    fn open(&self, rw: bool) -> CK_SESSION_HANDLE {
        let mut flags = CKF_SERIAL_SESSION;
        if rw {
            flags |= CKF_RW_SESSION;
        }
        let mut h = 0;
        let rv = unsafe { self.f.C_OpenSession.unwrap()(0, flags, ptr::null_mut(), None, &mut h) };
        assert_eq!(rv, CKR_OK);
        h
    }

    fn login(&self, s: CK_SESSION_HANDLE, pin: &[u8]) -> CK_RV {
        unsafe {
            self.f.C_Login.unwrap()(s, CKU_USER, pin.as_ptr() as *mut _, pin.len() as CK_ULONG)
        }
    }

    fn generate(
        &self,
        s: CK_SESSION_HANDLE,
        label: &[u8],
        extra_priv: &[CK_ATTRIBUTE],
    ) -> Result<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE), CK_RV> {
        let params = [0x06u8, 0x03, 0x2b, 0x65, 0x70];
        let mut pub_t = [attr(CKA_EC_PARAMS, &params), attr(CKA_LABEL, label)];
        let mut priv_t = vec![attr(CKA_LABEL, label)];
        priv_t.extend_from_slice(extra_priv);
        let mut mech = CK_MECHANISM {
            mechanism: CKM_EC_EDWARDS_KEY_PAIR_GEN,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };
        let (mut pubh, mut privh) = (0, 0);
        let rv = unsafe {
            self.f.C_GenerateKeyPair.unwrap()(
                s,
                &mut mech,
                pub_t.as_mut_ptr(),
                pub_t.len() as CK_ULONG,
                priv_t.as_mut_ptr(),
                priv_t.len() as CK_ULONG,
                &mut pubh,
                &mut privh,
            )
        };
        if rv == CKR_OK {
            Ok((pubh, privh))
        } else {
            Err(rv)
        }
    }

    fn sign(
        &self,
        s: CK_SESSION_HANDLE,
        key: CK_OBJECT_HANDLE,
        msg: &[u8],
    ) -> Result<Vec<u8>, CK_RV> {
        let mut mech = eddsa();
        let rv = unsafe { self.f.C_SignInit.unwrap()(s, &mut mech, key) };
        if rv != CKR_OK {
            return Err(rv);
        }
        // Size query first, as most applications do.
        let mut len = 0;
        let rv = unsafe {
            self.f.C_Sign.unwrap()(
                s,
                msg.as_ptr() as *mut _,
                msg.len() as CK_ULONG,
                ptr::null_mut(),
                &mut len,
            )
        };
        assert_eq!(rv, CKR_OK);
        let mut sig = vec![0u8; len as usize];
        let rv = unsafe {
            self.f.C_Sign.unwrap()(
                s,
                msg.as_ptr() as *mut _,
                msg.len() as CK_ULONG,
                sig.as_mut_ptr(),
                &mut len,
            )
        };
        if rv == CKR_OK { Ok(sig) } else { Err(rv) }
    }

    fn get(
        &self,
        s: CK_SESSION_HANDLE,
        obj: CK_OBJECT_HANDLE,
        ty: CK_ATTRIBUTE_TYPE,
    ) -> Result<Vec<u8>, CK_RV> {
        let mut a = CK_ATTRIBUTE {
            type_: ty,
            pValue: ptr::null_mut(),
            ulValueLen: 0,
        };
        let rv = unsafe { self.f.C_GetAttributeValue.unwrap()(s, obj, &mut a, 1) };
        if rv != CKR_OK {
            return Err(rv);
        }
        let mut buf = vec![0u8; a.ulValueLen as usize];
        a.pValue = buf.as_mut_ptr() as *mut _;
        let rv = unsafe { self.f.C_GetAttributeValue.unwrap()(s, obj, &mut a, 1) };
        if rv == CKR_OK { Ok(buf) } else { Err(rv) }
    }

    fn find(&self, s: CK_SESSION_HANDLE, template: &mut [CK_ATTRIBUTE]) -> Vec<CK_OBJECT_HANDLE> {
        let f = self.f;
        assert_eq!(
            unsafe {
                f.C_FindObjectsInit.unwrap()(s, template.as_mut_ptr(), template.len() as CK_ULONG)
            },
            CKR_OK
        );
        let mut out = [0; 64];
        let mut n = 0;
        assert_eq!(
            unsafe { f.C_FindObjects.unwrap()(s, out.as_mut_ptr(), 64, &mut n) },
            CKR_OK
        );
        assert_eq!(unsafe { f.C_FindObjectsFinal.unwrap()(s) }, CKR_OK);
        out[..n as usize].to_vec()
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        unsafe { self.f.C_Finalize.unwrap()(ptr::null_mut()) };
    }
}

fn attr(ty: CK_ATTRIBUTE_TYPE, v: &[u8]) -> CK_ATTRIBUTE {
    CK_ATTRIBUTE {
        type_: ty,
        pValue: v.as_ptr() as *mut _,
        ulValueLen: v.len() as CK_ULONG,
    }
}

fn eddsa() -> CK_MECHANISM {
    CK_MECHANISM {
        mechanism: CKM_EDDSA,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    }
}

#[test]
fn generate_sign_verify() {
    let t = Token::new("gsv");
    let s = t.open(true);
    assert_eq!(t.login(s, PIN), CKR_OK);
    let (pubh, privh) = t.generate(s, b"agent-key", &[]).unwrap();

    let msg = b"agent action: send_email to=alice@example.com";
    let sig = t.sign(s, privh, msg).unwrap();
    assert_eq!(sig.len(), 64);

    // Check the signature independently of the library.
    let point = t.get(s, pubh, CKA_EC_POINT).unwrap();
    assert_eq!(&point[..2], &[0x04, 0x20]);
    let vk = VerifyingKey::from_bytes(point[2..].try_into().unwrap()).unwrap();
    vk.verify(msg, &Signature::from_slice(&sig).unwrap())
        .unwrap();

    // And through C_Verify, including a tampered message.
    let mut mech = eddsa();
    for (m, want) in [
        (&msg[..], CKR_OK),
        (&b"tampered"[..], CKR_SIGNATURE_INVALID),
    ] {
        assert_eq!(
            unsafe { t.f.C_VerifyInit.unwrap()(s, &mut mech, pubh) },
            CKR_OK
        );
        let rv = unsafe {
            t.f.C_Verify.unwrap()(
                s,
                m.as_ptr() as *mut _,
                m.len() as CK_ULONG,
                sig.as_ptr() as *mut _,
                64,
            )
        };
        assert_eq!(rv, want);
    }
}

#[test]
fn signing_is_refused_without_login() {
    let t = Token::new("nologin");
    let s = t.open(true);
    assert_eq!(t.login(s, PIN), CKR_OK);
    let (_, privh) = t.generate(s, b"k", &[]).unwrap();
    assert_eq!(unsafe { t.f.C_Logout.unwrap()(s) }, CKR_OK);
    assert_eq!(t.sign(s, privh, b"m"), Err(CKR_USER_NOT_LOGGED_IN));
}

#[test]
fn private_keys_are_hidden_until_login_and_never_readable() {
    let t = Token::new("hidden");
    let s = t.open(true);
    assert_eq!(t.login(s, PIN), CKR_OK);
    let (pubh, privh) = t.generate(s, b"k", &[]).unwrap();
    assert_eq!(t.get(s, privh, CKA_VALUE), Err(CKR_ATTRIBUTE_SENSITIVE));
    assert_eq!(t.get(s, privh, CKA_EXTRACTABLE).unwrap(), vec![CK_FALSE]);
    assert_eq!(t.find(s, &mut []).len(), 2);

    assert_eq!(unsafe { t.f.C_Logout.unwrap()(s) }, CKR_OK);
    assert_eq!(t.find(s, &mut []), vec![pubh]);
    assert_eq!(t.get(s, privh, CKA_LABEL), Err(CKR_OBJECT_HANDLE_INVALID));
}

#[test]
fn extractable_keys_cannot_be_requested() {
    let t = Token::new("extractable");
    let s = t.open(true);
    assert_eq!(t.login(s, PIN), CKR_OK);
    let yes = [CK_TRUE];
    assert_eq!(
        t.generate(s, b"k", &[attr(CKA_EXTRACTABLE, &yes)]),
        Err(CKR_ATTRIBUTE_VALUE_INVALID)
    );
}

#[test]
fn read_only_sessions_cannot_create_keys() {
    let t = Token::new("ro");
    let s = t.open(false);
    assert_eq!(t.login(s, PIN), CKR_OK);
    assert_eq!(t.generate(s, b"k", &[]), Err(CKR_SESSION_READ_ONLY));
}

#[test]
fn wrong_pin_is_rejected_and_counted() {
    let t = Token::new("pin");
    let s = t.open(false);
    assert_eq!(t.login(s, b"000000"), CKR_PIN_INCORRECT);
    let mut info: CK_TOKEN_INFO = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { t.f.C_GetTokenInfo.unwrap()(0, &mut info) }, CKR_OK);
    assert_ne!(info.flags & CKF_USER_PIN_COUNT_LOW, 0);
    assert_eq!(t.login(s, PIN), CKR_OK);
}

#[test]
fn find_by_label_and_destroy() {
    let t = Token::new("find");
    let s = t.open(true);
    assert_eq!(t.login(s, PIN), CKR_OK);
    t.generate(s, b"alpha", &[]).unwrap();
    let (_, beta) = t.generate(s, b"beta", &[]).unwrap();
    let class = CKO_PRIVATE_KEY.to_ne_bytes();
    let found = t.find(s, &mut [attr(CKA_LABEL, b"beta"), attr(CKA_CLASS, &class)]);
    assert_eq!(found, vec![beta]);

    assert_eq!(unsafe { t.f.C_DestroyObject.unwrap()(s, beta) }, CKR_OK);
    assert!(t.find(s, &mut [attr(CKA_LABEL, b"beta")]).is_empty());
    assert_eq!(t.sign(s, beta, b"m"), Err(CKR_KEY_HANDLE_INVALID));
}

#[test]
fn unsupported_functions_fail_cleanly() {
    let t = Token::new("unsupported");
    let s = t.open(false);
    let rv = unsafe { t.f.C_EncryptInit.unwrap()(s, ptr::null_mut(), 0) };
    assert_eq!(rv, CKR_FUNCTION_NOT_SUPPORTED);
}

#[test]
fn agent_keys_are_visible_but_cannot_sign_or_be_deleted_through_pkcs11() {
    use ed25519_dalek::Signer;
    use quorum_core::admin::{AdminOp, Approvals, MAX_PROPOSAL, Proposal};
    use quorum_core::agent::{ActionKind, Policy};
    use quorum_core::wire::{Request, Status, resp};

    let t = Token::new("agent");
    // Create an agent key the way quorum-cli does, straight over the socket.
    let mut c = quorum_client::Client::connect().unwrap();
    assert_eq!(c.call(&Request::Login { pin: PIN }).unwrap().0, Status::Ok);
    let policy = Policy {
        allowed: ActionKind::Payment.bit(),
        max_amount: 100,
        budget: 100,
        confirm_above: 100,
        always_confirm: 0,
        confirmer: None,
        require_nonce: false,
    };
    // Both admins sign off on creating it.
    let (_, payload) = c.call(&Request::GetAdminChallenge).unwrap();
    let challenge = resp::decode_challenge(&payload).unwrap();
    let op = AdminOp::CreateAgentKey {
        label: b"agent",
        ext_id: b"",
        policy,
    };
    let mut buf = [0u8; MAX_PROPOSAL];
    let n = Proposal {
        serial: *SERIAL_NO,
        challenge,
        op,
    }
    .encode(&mut buf)
    .unwrap();
    let mut approvals = Approvals::default();
    for i in 0..2 {
        approvals
            .push(i, admin(i).sign(&buf[..n]).to_bytes())
            .unwrap();
    }
    let (status, payload) = c
        .call(&Request::GenerateAgentKey {
            label: b"agent",
            ext_id: b"",
            policy,
            approvals,
        })
        .unwrap();
    assert_eq!(status, Status::Ok);
    let key = resp::AgentKeyCreated::decode(&payload).unwrap().key;

    let s = t.open(true);
    assert_eq!(t.login(s, PIN), CKR_OK);
    let found = t.find(s, &mut [attr(CKA_LABEL, b"agent")]);
    assert_eq!(found.len(), 2);
    let privh = (key as CK_OBJECT_HANDLE) << 1 | 1;
    assert!(found.contains(&privh));
    assert_eq!(t.get(s, privh, CKA_SIGN).unwrap(), vec![CK_FALSE]);
    assert!(t.get(s, privh, CKA_ALLOWED_MECHANISMS).unwrap().is_empty());
    assert_eq!(
        t.sign(s, privh, b"forged"),
        Err(CKR_KEY_FUNCTION_NOT_PERMITTED)
    );
    // PKCS#11 can't delete it either: that needs admin sign-off.
    assert_eq!(
        unsafe { t.f.C_DestroyObject.unwrap()(s, privh) },
        CKR_ACTION_PROHIBITED
    );
}
