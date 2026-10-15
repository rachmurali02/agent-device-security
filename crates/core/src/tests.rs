use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand_core::{CryptoRng, RngCore};

use crate::hsm::{Hsm, MAX_PIN_TRIES, STATE_MAX, Session, Storage, StorageError};
use crate::keystore::MAX_KEYS;
use crate::wire::{MAX_FRAME, Request, Status, resp};

/// Deterministic RNG for tests only. Never use outside tests.
struct TestRng(u64);
impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        // splitmix64
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl CryptoRng for TestRng {}

#[derive(Default)]
struct MemStorage {
    state: Vec<u8>,
    commits: usize,
    fail: bool,
}
impl Storage for MemStorage {
    fn commit(&mut self, state: &[u8]) -> Result<(), StorageError> {
        if self.fail {
            return Err(StorageError);
        }
        self.state = state.to_vec();
        self.commits += 1;
        Ok(())
    }
}

const PIN: &[u8] = b"123456";

struct Fixture {
    hsm: Hsm,
    session: Session,
    storage: MemStorage,
    rng: TestRng,
}

impl Fixture {
    fn new() -> Self {
        let mut storage = MemStorage::default();
        let hsm = Hsm::provision(*b"TESTSERIAL000001", PIN, &mut storage).unwrap();
        Fixture {
            hsm,
            session: Session::default(),
            storage,
            rng: TestRng(7),
        }
    }

    fn raw(&mut self, frame: &[u8]) -> Vec<u8> {
        let mut out = [0u8; MAX_FRAME];
        let n = self.hsm.handle(
            &mut self.session,
            &mut self.storage,
            &mut self.rng,
            frame,
            &mut out,
        );
        out[..n].to_vec()
    }

    fn call(&mut self, req: Request<'_>) -> (Status, Vec<u8>) {
        let mut buf = [0u8; MAX_FRAME];
        let n = req.encode(&mut buf).unwrap();
        let out = self.raw(&buf[..n]);
        let (status, payload) = resp::split(&out).unwrap();
        (status, payload.to_vec())
    }

    fn login(&mut self) {
        assert_eq!(self.call(Request::Login { pin: PIN }).0, Status::Ok);
    }

    fn generate(&mut self, label: &[u8]) -> resp::Generated {
        let (status, payload) = self.call(Request::GenerateKey {
            label,
            ext_id: b"\x01",
        });
        assert_eq!(status, Status::Ok);
        resp::Generated::decode(&payload).unwrap()
    }

    fn info(&mut self) -> resp::Info {
        let (status, payload) = self.call(Request::GetInfo);
        assert_eq!(status, Status::Ok);
        resp::Info::decode(&payload).unwrap()
    }
}

#[test]
fn sign_requires_login() {
    let mut f = Fixture::new();
    assert_eq!(
        f.call(Request::GenerateKey {
            label: b"k",
            ext_id: b""
        })
        .0,
        Status::NotLoggedIn
    );
    f.login();
    let key = f.generate(b"k").key;
    f.call(Request::Logout);
    assert_eq!(
        f.call(Request::Sign { key, msg: b"hi" }).0,
        Status::NotLoggedIn
    );
    assert_eq!(f.call(Request::DeleteKey { key }).0, Status::NotLoggedIn);
}

#[test]
fn signatures_verify_with_listed_public_key() {
    let mut f = Fixture::new();
    f.login();
    let generated = f.generate(b"device-signing");

    let (status, payload) = f.call(Request::ListKeys);
    assert_eq!(status, Status::Ok);
    let entries: Vec<_> = resp::decode_key_list(&payload).unwrap().collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].label, b"device-signing");
    assert_eq!(entries[0].ext_id, b"\x01");
    assert_eq!(entries[0].public, generated.public);

    let msg = b"firmware image v1.2.3";
    let (status, payload) = f.call(Request::Sign {
        key: generated.key,
        msg,
    });
    assert_eq!(status, Status::Ok);
    let sig = Signature::from_bytes(&resp::decode_signature(&payload).unwrap());
    let vk = VerifyingKey::from_bytes(&generated.public).unwrap();
    vk.verify(msg, &sig).unwrap();
    assert!(vk.verify(b"tampered", &sig).is_err());
}

#[test]
fn wrong_pins_lock_the_token_and_correct_pin_resets() {
    let mut f = Fixture::new();
    for _ in 0..MAX_PIN_TRIES - 1 {
        assert_eq!(
            f.call(Request::Login { pin: b"000000" }).0,
            Status::PinIncorrect
        );
    }
    assert_eq!(f.info().pin_tries_left, 1);
    f.login();
    assert_eq!(f.info().pin_tries_left, MAX_PIN_TRIES);
    f.call(Request::Logout);

    for _ in 0..MAX_PIN_TRIES - 1 {
        assert_eq!(
            f.call(Request::Login { pin: b"000000" }).0,
            Status::PinIncorrect
        );
    }
    assert_eq!(
        f.call(Request::Login { pin: b"000000" }).0,
        Status::PinLocked
    );
    // Once locked, even the right PIN is refused.
    assert_eq!(f.call(Request::Login { pin: PIN }).0, Status::PinLocked);
    assert_ne!(f.info().flags & resp::FLAG_PIN_LOCKED, 0);
}

#[test]
fn pin_attempt_is_committed_before_comparison() {
    let mut f = Fixture::new();
    // Storage dies: the attempt cannot be recorded, so the PIN must not be
    // checked at all, and the HSM must fail closed.
    f.storage.fail = true;
    assert_eq!(f.call(Request::Login { pin: PIN }).0, Status::Fault);
    assert!(!f.session.is_logged_in());
    assert!(f.hsm.is_faulted());
    f.storage.fail = false;
    assert_eq!(f.call(Request::GetInfo).0, Status::Fault);
}

#[test]
fn pin_prefix_and_extension_are_rejected() {
    let mut f = Fixture::new();
    assert_eq!(
        f.call(Request::Login { pin: b"12345" }).0,
        Status::PinIncorrect
    );
    assert_eq!(
        f.call(Request::Login { pin: b"1234567" }).0,
        Status::PinIncorrect
    );
    assert_eq!(
        f.call(Request::Login { pin: b"123456\0" }).0,
        Status::PinIncorrect
    );
}

#[test]
fn deleted_ids_are_never_reused() {
    let mut f = Fixture::new();
    f.login();
    let a = f.generate(b"a").key;
    assert_eq!(f.call(Request::DeleteKey { key: a }).0, Status::Ok);
    assert_eq!(
        f.call(Request::Sign { key: a, msg: b"x" }).0,
        Status::KeyNotFound
    );
    let b = f.generate(b"b").key;
    assert_ne!(a, b);
    assert_eq!(
        f.call(Request::Sign { key: a, msg: b"x" }).0,
        Status::KeyNotFound
    );
}

#[test]
fn store_full() {
    let mut f = Fixture::new();
    f.login();
    for i in 0..MAX_KEYS {
        f.generate(format!("k{i}").as_bytes());
    }
    assert_eq!(
        f.call(Request::GenerateKey {
            label: b"x",
            ext_id: b""
        })
        .0,
        Status::StoreFull
    );
}

#[test]
fn state_round_trips_through_storage() {
    let mut f = Fixture::new();
    f.login();
    let g = f.generate(b"persist-me");
    f.call(Request::Login { pin: b"bad" }); // AlreadyLoggedIn: no attempt spent
    f.call(Request::Logout);
    f.call(Request::Login { pin: b"wrongpin" });

    let mut reloaded = Hsm::load(&f.storage.state).unwrap();
    let mut session = Session::default();
    let mut out = [0u8; MAX_FRAME];
    let mut buf = [0u8; MAX_FRAME];

    let n = Request::GetInfo.encode(&mut buf).unwrap();
    let r = reloaded.handle(
        &mut session,
        &mut f.storage,
        &mut f.rng,
        &buf[..n],
        &mut out,
    );
    let info = resp::Info::decode(&out[1..r]).unwrap();
    assert_eq!(info.pin_tries_left, MAX_PIN_TRIES - 1);
    assert_eq!(info.key_count, 1);

    let n = Request::Login { pin: PIN }.encode(&mut buf).unwrap();
    reloaded.handle(
        &mut session,
        &mut f.storage,
        &mut f.rng,
        &buf[..n],
        &mut out,
    );
    let n = Request::Sign {
        key: g.key,
        msg: b"m",
    }
    .encode(&mut buf)
    .unwrap();
    let r = reloaded.handle(
        &mut session,
        &mut f.storage,
        &mut f.rng,
        &buf[..n],
        &mut out,
    );
    assert_eq!(out[0], Status::Ok as u8);
    let sig = Signature::from_bytes(&resp::decode_signature(&out[1..r]).unwrap());
    VerifyingKey::from_bytes(&g.public)
        .unwrap()
        .verify(b"m", &sig)
        .unwrap();

    // A new key after reload must not collide with the old ID.
    let n = Request::GenerateKey {
        label: b"n",
        ext_id: b"",
    }
    .encode(&mut buf)
    .unwrap();
    let r = reloaded.handle(
        &mut session,
        &mut f.storage,
        &mut f.rng,
        &buf[..n],
        &mut out,
    );
    assert_ne!(resp::Generated::decode(&out[1..r]).unwrap().key, g.key);
}

#[test]
fn corrupted_state_is_rejected() {
    let f = Fixture::new();
    let good = f.storage.state.clone();
    assert!(Hsm::load(&good).is_ok());
    assert!(Hsm::load(&good[..good.len() - 1]).is_err());
    let mut extra = good.clone();
    extra.push(0);
    assert!(Hsm::load(&extra).is_err());
    let mut bad_magic = good.clone();
    bad_magic[0] ^= 1;
    assert!(Hsm::load(&bad_magic).is_err());
    assert!(good.len() <= STATE_MAX);
}

#[test]
fn malformed_requests_are_rejected() {
    let mut f = Fixture::new();
    let bad = |out: Vec<u8>| assert_eq!(out, vec![Status::BadRequest as u8]);
    bad(f.raw(&[]));
    bad(f.raw(&[0xff]));
    bad(f.raw(&[0x01, 0x00])); // trailing byte
    bad(f.raw(&[0x02, 0x05])); // truncated length
    bad(f.raw(&[0x02, 0x05, 0x00, b'1'])); // length longer than data
    bad(f.raw(&[0x02, 0xff, 0xff])); // PIN longer than MAX_PIN
    bad(f.raw(&[0x12, 1, 0, 0])); // truncated key id
}

#[test]
fn storage_failure_on_generate_faults_and_reload_has_no_ghost_key() {
    let mut f = Fixture::new();
    f.login();
    f.storage.fail = true;
    assert_eq!(
        f.call(Request::GenerateKey {
            label: b"g",
            ext_id: b""
        })
        .0,
        Status::Fault
    );
    let reloaded = Hsm::load(&f.storage.state).unwrap();
    let mut buf = [0u8; STATE_MAX];
    let n = reloaded.save(&mut buf).unwrap();
    assert_eq!(&buf[..n], &f.storage.state[..]);
}
