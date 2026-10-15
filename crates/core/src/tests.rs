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

/// Three admins (Alice, Bob, Carol). The default test HSM needs any two.
fn admins() -> [ed25519_dalek::SigningKey; 3] {
    [21, 22, 23].map(|b| ed25519_dalek::SigningKey::from_bytes(&[b; 32]))
}

fn admin_publics() -> [[u8; 32]; 3] {
    admins().map(|k| k.verifying_key().to_bytes())
}

struct Fixture {
    hsm: Hsm,
    session: Session,
    storage: MemStorage,
    rng: TestRng,
}

impl Fixture {
    fn new() -> Self {
        Self::with_admins(&admin_publics(), 2)
    }

    /// A fresh HSM whose agent-key operations need `threshold` of `admins`.
    fn with_admins(admins: &[[u8; 32]], threshold: u8) -> Self {
        let mut storage = MemStorage::default();
        let mut rng = TestRng(7);
        let hsm = Hsm::provision(
            crate::Provisioning {
                serial: *b"TESTSERIAL000001",
                pin: PIN,
                admins,
                threshold,
            },
            &mut rng,
            &mut storage,
        )
        .unwrap();
        Fixture {
            hsm,
            session: Session::default(),
            storage,
            rng,
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

// ---- milestone 2: agent actions and policies --------------------------------

mod agent {
    use super::*;
    use crate::admin::{AdminOp, Approvals, MAX_PROPOSAL, Proposal};
    use crate::agent::{
        Action, ActionKind, CONFIRM_MESSAGE_MAX, Policy, Statement, VerifyError,
        confirmation_message, verify_statement,
    };
    use ed25519_dalek::{Signer, SigningKey};

    /// What each admin's tool does: sign the exact proposal.
    pub(super) fn sign_proposal(
        challenge: &[u8; 32],
        op: &AdminOp<'_>,
        who: &[usize],
    ) -> Approvals {
        let mut buf = [0u8; MAX_PROPOSAL];
        let n = Proposal {
            serial: SERIAL,
            challenge: *challenge,
            op: *op,
        }
        .encode(&mut buf)
        .unwrap();
        let mut approvals = Approvals::default();
        for &i in who {
            approvals
                .push(i as u8, admins()[i].sign(&buf[..n]).to_bytes())
                .unwrap();
        }
        approvals
    }

    const SERIAL: [u8; 16] = *b"TESTSERIAL000001";

    /// Stands in for the user's phone: a separate key behind a confirm button.
    fn confirmer() -> SigningKey {
        SigningKey::from_bytes(&[9; 32])
    }

    /// Payments and messages allowed. Payments up to $50, $200 in total,
    /// anything over $20 needs the user's OK. Installing software always does.
    fn shopping_policy() -> Policy {
        Policy {
            allowed: ActionKind::Payment.bit()
                | ActionKind::SendMessage.bit()
                | ActionKind::InstallSoftware.bit(),
            max_amount: 5_000,
            budget: 20_000,
            confirm_above: 2_000,
            always_confirm: ActionKind::InstallSoftware.bit(),
            confirmer: Some(confirmer().verifying_key().to_bytes()),
            require_nonce: false,
        }
    }

    fn pay(cents: u64, to: &[u8]) -> Action<'_> {
        Action {
            kind: ActionKind::Payment,
            amount: cents,
            target: to,
            details: b"",
            nonce: b"",
            expires: 0,
        }
    }

    impl Fixture {
        /// Creates an agent key with sign-off from Alice and Bob.
        pub(super) fn agent_key(&mut self, policy: Policy) -> resp::Generated {
            let (key, public, _, _) = self.agent_key_with_cert(policy);
            resp::Generated { key, public }
        }

        pub(super) fn agent_key_with_cert(
            &mut self,
            policy: Policy,
        ) -> (u32, [u8; 32], Vec<u8>, [u8; 64]) {
            let op = AdminOp::CreateAgentKey {
                label: b"agent",
                ext_id: b"",
                policy,
            };
            let approvals = self.approve(&op, &[0, 1]);
            let (status, payload) = self.call(Request::GenerateAgentKey {
                label: b"agent",
                ext_id: b"",
                policy,
                approvals,
            });
            assert_eq!(status, Status::Ok);
            let c = resp::AgentKeyCreated::decode(&payload).unwrap();
            (c.key, c.public, c.cert.to_vec(), c.cert_sig)
        }

        /// Gets an admin challenge and has the admins at `who` sign the proposal.
        fn approve(&mut self, op: &AdminOp<'_>, who: &[usize]) -> Approvals {
            let challenge = self.admin_challenge();
            sign_proposal(&challenge, op, who)
        }

        pub(super) fn admin_challenge(&mut self) -> [u8; 32] {
            let (status, payload) = self.call(Request::GetAdminChallenge);
            assert_eq!(status, Status::Ok);
            resp::decode_challenge(&payload).unwrap()
        }

        fn act(
            &mut self,
            key: u32,
            action: Action<'_>,
            conf: Option<[u8; 64]>,
        ) -> Result<(Vec<u8>, [u8; 64]), Status> {
            let (status, payload) = self.call(Request::SignAction {
                key,
                action,
                confirmation: conf,
            });
            if status != Status::Ok {
                return Err(status);
            }
            let (stmt, sig) = resp::decode_signed_action(&payload).unwrap();
            Ok((stmt.to_vec(), sig))
        }

        fn challenge(&mut self) -> [u8; 32] {
            let (status, payload) = self.call(Request::GetChallenge);
            assert_eq!(status, Status::Ok);
            resp::decode_challenge(&payload).unwrap()
        }

        /// What the user's device does after showing the action and the user taps "Approve".
        fn confirm(&mut self, key: u32, action: &Action<'_>, by: &SigningKey) -> [u8; 64] {
            let challenge = self.challenge();
            let mut msg = [0u8; CONFIRM_MESSAGE_MAX];
            let n = confirmation_message(&mut msg, &SERIAL, &challenge, key, action).unwrap();
            by.sign(&msg[..n]).to_bytes()
        }

        fn policy_state(&mut self, key: u32) -> resp::KeyPolicy {
            let (status, payload) = self.call(Request::GetKeyPolicy { key });
            assert_eq!(status, Status::Ok);
            resp::KeyPolicy::decode(&payload).unwrap()
        }
    }

    #[test]
    fn allowed_payment_is_signed_as_a_statement_anyone_can_check() {
        let mut f = Fixture::new();
        f.login();
        let k = f.agent_key(shopping_policy());
        let (stmt, sig) = f
            .act(k.key, pay(1_500, b"coffee-shop.example"), None)
            .unwrap();

        let s = verify_statement(&k.public, &stmt, &sig).unwrap();
        assert_eq!(s.serial, SERIAL);
        assert_eq!(s.key, k.key);
        assert_eq!(s.sequence, 1);
        assert_eq!(s.action, pay(1_500, b"coffee-shop.example"));
        assert!(!s.confirmed);
        assert_eq!(s.policy_digest, shopping_policy().digest());

        let state = f.policy_state(k.key);
        assert_eq!((state.spent, state.approved), (1_500, 1));
    }

    #[test]
    fn tampered_statements_fail_verification() {
        let mut f = Fixture::new();
        f.login();
        let k = f.agent_key(shopping_policy());
        let (mut stmt, sig) = f.act(k.key, pay(1_500, b"shop"), None).unwrap();
        let other = SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes();
        assert_eq!(
            verify_statement(&other, &stmt, &sig),
            Err(VerifyError::BadSignature)
        );
        let last = stmt.len() - 40; // inside the amount/target area
        stmt[last] ^= 1;
        assert!(verify_statement(&k.public, &stmt, &sig).is_err());
    }

    #[test]
    fn disallowed_kinds_are_refused() {
        let mut f = Fixture::new();
        f.login();
        let k = f.agent_key(shopping_policy());
        let delete = Action {
            kind: ActionKind::DeleteData,
            amount: 0,
            target: b"photos",
            details: b"",
            nonce: b"",
            expires: 0,
        };
        assert_eq!(f.act(k.key, delete, None), Err(Status::ActionNotAllowed));
    }

    #[test]
    fn single_payment_cap_is_enforced() {
        let mut f = Fixture::new();
        f.login();
        let k = f.agent_key(shopping_policy());
        let conf = f.confirm(k.key, &pay(5_001, b"tv-store"), &confirmer());
        // Even with the user's confirmation: the cap is a hard rule.
        assert_eq!(
            f.act(k.key, pay(5_001, b"tv-store"), Some(conf)),
            Err(Status::AmountTooHigh)
        );
    }

    #[test]
    fn total_budget_is_enforced_across_actions() {
        let mut f = Fixture::new();
        f.login();
        let k = f.agent_key(shopping_policy());
        for i in 1..=10 {
            let (stmt, sig) = f.act(k.key, pay(2_000, b"shop"), None).unwrap();
            assert_eq!(
                verify_statement(&k.public, &stmt, &sig).unwrap().sequence,
                i
            );
        }
        // $200 spent; one more cent is over budget.
        assert_eq!(
            f.act(k.key, pay(1, b"shop"), None),
            Err(Status::BudgetExceeded)
        );
        // Denied actions are not charged.
        assert_eq!(f.policy_state(k.key).spent, 20_000);
    }

    #[test]
    fn large_payments_need_a_real_user_confirmation() {
        let mut f = Fixture::new();
        f.login();
        let k = f.agent_key(shopping_policy());
        let big = pay(3_000, b"airline.example");
        assert_eq!(f.act(k.key, big, None), Err(Status::ConfirmationRequired));

        let conf = f.confirm(k.key, &big, &confirmer());
        let (stmt, sig) = f.act(k.key, big, Some(conf)).unwrap();
        assert!(verify_statement(&k.public, &stmt, &sig).unwrap().confirmed);
    }

    #[test]
    fn a_confirmation_cannot_be_replayed() {
        let mut f = Fixture::new();
        f.login();
        let k = f.agent_key(shopping_policy());
        let big = pay(3_000, b"airline.example");
        let conf = f.confirm(k.key, &big, &confirmer());
        f.act(k.key, big, Some(conf)).unwrap();
        // Same signature again: the challenge it covered is gone.
        assert_eq!(f.act(k.key, big, Some(conf)), Err(Status::NoChallenge));
        // Even after a fresh challenge, the old signature covers the old one.
        f.challenge();
        assert_eq!(
            f.act(k.key, big, Some(conf)),
            Err(Status::ConfirmationInvalid)
        );
    }

    #[test]
    fn a_confirmation_cannot_be_moved_to_a_different_action() {
        let mut f = Fixture::new();
        f.login();
        let k = f.agent_key(shopping_policy());
        // The user approves $30 to the airline; the agent tries to send $49 to itself.
        let conf = f.confirm(k.key, &pay(3_000, b"airline.example"), &confirmer());
        assert_eq!(
            f.act(k.key, pay(4_900, b"attacker.example"), Some(conf)),
            Err(Status::ConfirmationInvalid)
        );
        // A failed attempt still uses up the challenge.
        assert_eq!(
            f.act(k.key, pay(3_000, b"airline.example"), Some(conf)),
            Err(Status::NoChallenge)
        );
    }

    #[test]
    fn only_the_registered_confirmation_device_counts() {
        let mut f = Fixture::new();
        f.login();
        let k = f.agent_key(shopping_policy());
        let impostor = SigningKey::from_bytes(&[2; 32]);
        let big = pay(3_000, b"airline.example");
        let conf = f.confirm(k.key, &big, &impostor);
        assert_eq!(
            f.act(k.key, big, Some(conf)),
            Err(Status::ConfirmationInvalid)
        );
    }

    #[test]
    fn some_kinds_always_need_confirmation() {
        let mut f = Fixture::new();
        f.login();
        let k = f.agent_key(shopping_policy());
        let install = Action {
            kind: ActionKind::InstallSoftware,
            amount: 0,
            target: b"com.example.app",
            details: b"v2.1",
            nonce: b"",
            expires: 0,
        };
        assert_eq!(
            f.act(k.key, install, None),
            Err(Status::ConfirmationRequired)
        );
        let conf = f.confirm(k.key, &install, &confirmer());
        f.act(k.key, install, Some(conf)).unwrap();
    }

    #[test]
    fn without_a_confirmation_device_confirmable_actions_are_impossible() {
        let mut f = Fixture::new();
        f.login();
        let k = f.agent_key(Policy {
            confirmer: None,
            ..shopping_policy()
        });
        assert_eq!(
            f.act(k.key, pay(3_000, b"x"), None),
            Err(Status::ConfirmationRequired)
        );
        let conf = f.confirm(k.key, &pay(3_000, b"x"), &confirmer());
        assert_eq!(
            f.act(k.key, pay(3_000, b"x"), Some(conf)),
            Err(Status::ConfirmationInvalid)
        );
        // Small payments still work.
        f.act(k.key, pay(100, b"x"), None).unwrap();
    }

    #[test]
    fn agent_keys_never_sign_raw_bytes_and_general_keys_never_sign_actions() {
        let mut f = Fixture::new();
        f.login();
        let agent = f.agent_key(shopping_policy());
        // An attacker on the host cannot hand-craft a "statement" for the agent key.
        assert_eq!(
            f.call(Request::Sign {
                key: agent.key,
                msg: b"QHSM-ACTION\x01forged"
            })
            .0,
            Status::UsageNotAllowed
        );
        let general = f.generate(b"general").key;
        assert_eq!(
            f.act(general, pay(1, b"x"), None),
            Err(Status::UsageNotAllowed)
        );
        assert_eq!(
            f.call(Request::GetKeyPolicy { key: general }).0,
            Status::UsageNotAllowed
        );
    }

    #[test]
    fn agent_actions_require_login() {
        let mut f = Fixture::new();
        f.login();
        let k = f.agent_key(shopping_policy());
        f.call(Request::Logout);
        assert_eq!(f.act(k.key, pay(1, b"x"), None), Err(Status::NotLoggedIn));
        assert_eq!(f.call(Request::GetChallenge).0, Status::NotLoggedIn);
    }

    #[test]
    fn logout_discards_the_pending_challenge() {
        let mut f = Fixture::new();
        f.login();
        let k = f.agent_key(shopping_policy());
        let conf = f.confirm(k.key, &pay(3_000, b"x"), &confirmer());
        f.call(Request::Logout);
        f.login();
        assert_eq!(
            f.act(k.key, pay(3_000, b"x"), Some(conf)),
            Err(Status::NoChallenge)
        );
    }

    #[test]
    fn misleading_or_ambiguous_actions_are_rejected_before_any_check() {
        let mut f = Fixture::new();
        f.login();
        let k = f.agent_key(shopping_policy());
        let bad_actions = [
            pay(0, b"free?"),                  // payment with no amount
            pay(100, b""),                     // nobody to pay
            pay(100, b"shop\nAmount: $1"),     // newline could fake a confirm screen
            pay(100, "sh\u{43e}p".as_bytes()), // Cyrillic look-alike letter
            Action {
                kind: ActionKind::SendMessage,
                amount: 5,
                target: b"bob",
                details: b"",
                nonce: b"",
                expires: 0,
            }, // amount on a non-payment
        ];
        for a in bad_actions {
            let mut buf = [0u8; MAX_FRAME];
            // Hand-encode, since the client-side encoder refuses these too.
            let mut w = crate::wire::Writer::new(&mut buf);
            w.u8(0x21).unwrap();
            w.u32(k.key).unwrap();
            w.u8(a.kind as u8).unwrap();
            w.u64(a.amount).unwrap();
            w.bytes(a.target).unwrap();
            w.bytes(a.details).unwrap();
            w.bytes(a.nonce).unwrap();
            w.u64(a.expires).unwrap();
            w.u8(0).unwrap();
            let n = w.len();
            assert_eq!(f.raw(&buf[..n]), vec![Status::BadRequest as u8], "{a:?}");
        }
        assert_eq!(f.policy_state(k.key).approved, 0);
    }

    #[test]
    fn invalid_policies_are_rejected() {
        let mut f = Fixture::new();
        f.login();
        for policy in [
            Policy {
                allowed: 0,
                ..shopping_policy()
            },
            Policy {
                allowed: 1 << 15,
                ..shopping_policy()
            },
            Policy {
                always_confirm: 1 << 0,
                ..shopping_policy()
            }, // undefined kind bit
        ] {
            let mut buf = [0u8; MAX_FRAME];
            // Encode a valid request, then patch in the invalid policy bytes.
            let n = Request::GenerateAgentKey {
                label: b"a",
                ext_id: b"",
                policy: shopping_policy(),
                approvals: Approvals::default(),
            }
            .encode(&mut buf)
            .unwrap();
            // Policy sits just before the (empty, 1-byte) approvals list.
            let off = n - 1 - crate::agent::POLICY_LEN;
            buf[off..off + 2].copy_from_slice(&policy.allowed.to_le_bytes());
            let ac = off + 2 + 8 + 8 + 8;
            buf[ac..ac + 2].copy_from_slice(&policy.always_confirm.to_le_bytes());
            assert_eq!(f.raw(&buf[..n]), vec![Status::BadRequest as u8]);
        }
    }

    #[test]
    fn spending_is_saved_before_signing() {
        let mut f = Fixture::new();
        f.login();
        let k = f.agent_key(shopping_policy());
        f.storage.fail = true;
        // Cannot record the spend, so no signature may be produced.
        assert_eq!(f.act(k.key, pay(100, b"shop"), None), Err(Status::Fault));
        let reloaded = Hsm::load(&f.storage.state).unwrap();
        let mut buf = [0u8; STATE_MAX];
        let n = reloaded.save(&mut buf).unwrap();
        assert_eq!(&buf[..n], &f.storage.state[..]);
    }

    #[test]
    fn spending_and_sequence_survive_a_restart() {
        let mut f = Fixture::new();
        f.login();
        let k = f.agent_key(shopping_policy());
        f.act(k.key, pay(19_000, b"shop"), None).ok(); // over confirm threshold
        let conf = f.confirm(k.key, &pay(5_000, b"shop"), &confirmer());
        f.act(k.key, pay(5_000, b"shop"), Some(conf)).unwrap();
        f.act(k.key, pay(2_000, b"shop"), None).unwrap();

        f.hsm = Hsm::load(&f.storage.state).unwrap();
        f.session = Session::default();
        f.login();
        let state = f.policy_state(k.key);
        assert_eq!((state.spent, state.approved), (7_000, 2));
        assert_eq!(state.policy, shopping_policy());
        let (stmt, sig) = f.act(k.key, pay(100, b"shop"), None).unwrap();
        assert_eq!(
            verify_statement(&k.public, &stmt, &sig).unwrap().sequence,
            3
        );
    }

    #[test]
    fn statements_round_trip() {
        let s = Statement {
            serial: SERIAL,
            key: 7,
            sequence: 42,
            action: pay(1_234, b"shop"),
            confirmed: true,
            policy_digest: [3; 32],
        };
        let mut buf = [0u8; crate::agent::MAX_STATEMENT];
        let mut w = crate::wire::Writer::new(&mut buf);
        s.write(&mut w).unwrap();
        let n = w.len();
        assert_eq!(Statement::decode(&buf[..n]).unwrap(), s);
        assert!(Statement::decode(&buf[..n - 1]).is_err());
    }
}

// ---- multi-person sign-off and birth certificates ----------------------------

mod quorum {
    use super::agent::sign_proposal;
    use super::*;
    use crate::admin::{AdminOp, Approvals, MAX_PROPOSAL, Proposal};
    use crate::agent::{Action, ActionKind, Policy};
    use crate::cert::{ActionError, CertError, KeyCert, verify_action, verify_key_cert};
    use ed25519_dalek::{Signer, SigningKey};

    fn policy() -> Policy {
        Policy {
            allowed: ActionKind::Payment.bit(),
            max_amount: 5_000,
            budget: 10_000,
            confirm_above: 5_000,
            always_confirm: 0,
            confirmer: None,
            require_nonce: false,
        }
    }

    fn create<'a>(policy: Policy) -> AdminOp<'a> {
        AdminOp::CreateAgentKey {
            label: b"agent",
            ext_id: b"",
            policy,
        }
    }

    fn submit(f: &mut Fixture, policy: Policy, approvals: Approvals) -> Status {
        f.call(Request::GenerateAgentKey {
            label: b"agent",
            ext_id: b"",
            policy,
            approvals,
        })
        .0
    }

    fn identity(f: &mut Fixture) -> resp::Identity {
        let (status, payload) = f.call(Request::GetIdentity);
        assert_eq!(status, Status::Ok);
        resp::Identity::decode(&payload).unwrap()
    }

    #[test]
    fn the_pin_alone_cannot_create_an_agent_key() {
        let mut f = Fixture::new();
        f.login();
        assert_eq!(
            submit(&mut f, policy(), Approvals::default()),
            Status::NoAdminChallenge
        );
        f.admin_challenge();
        assert_eq!(
            submit(&mut f, policy(), Approvals::default()),
            Status::QuorumRequired
        );
    }

    #[test]
    fn one_of_two_required_admins_is_not_enough() {
        let mut f = Fixture::new();
        f.login();
        let approvals = f_approve(&mut f, &create(policy()), &[2]);
        assert_eq!(submit(&mut f, policy(), approvals), Status::QuorumRequired);
    }

    #[test]
    fn two_admins_create_a_key_and_the_certificate_says_who() {
        let mut f = Fixture::new();
        f.login();
        let approvals = f_approve(&mut f, &create(policy()), &[0, 2]);
        let (status, payload) = f.call(Request::GenerateAgentKey {
            label: b"agent",
            ext_id: b"",
            policy: policy(),
            approvals,
        });
        assert_eq!(status, Status::Ok);
        let created = resp::AgentKeyCreated::decode(&payload).unwrap();

        let id = identity(&mut f);
        assert_eq!(id.public, f.hsm.identity_public());
        assert_eq!(id.admins.keys(), &admin_publics());
        assert_eq!(id.admins.threshold(), 2);

        let cert = verify_key_cert(&id.public, created.cert, &created.cert_sig).unwrap();
        assert_eq!(
            cert,
            KeyCert {
                serial: *b"TESTSERIAL000001",
                key: created.key,
                public: created.public,
                policy: policy(),
                approvers: 0b101, // Alice and Carol
                version: 1,
            }
        );
    }

    #[test]
    fn the_same_admin_twice_does_not_count_double() {
        let mut f = Fixture::new();
        f.login();
        let approvals = f_approve(&mut f, &create(policy()), &[1, 1]);
        assert_eq!(submit(&mut f, policy(), approvals), Status::ApprovalInvalid);
    }

    #[test]
    fn outsiders_and_unknown_admin_numbers_are_rejected() {
        let mut f = Fixture::new();
        f.login();
        let challenge = f.admin_challenge();
        let mut approvals = sign_proposal(&challenge, &create(policy()), &[0]);
        // Mallory signs and claims to be admin #1.
        let mallory = SigningKey::from_bytes(&[66; 32]);
        approvals
            .push(
                1,
                mallory
                    .sign(&proposal(&challenge, &create(policy())))
                    .to_bytes(),
            )
            .unwrap();
        assert_eq!(submit(&mut f, policy(), approvals), Status::ApprovalInvalid);

        let challenge = f.admin_challenge();
        let mut approvals = sign_proposal(&challenge, &create(policy()), &[0, 1]);
        approvals.push(7, [0; 64]).unwrap(); // there is no admin #7
        assert_eq!(submit(&mut f, policy(), approvals), Status::ApprovalInvalid);
    }

    fn proposal(challenge: &[u8; 32], op: &AdminOp<'_>) -> Vec<u8> {
        let mut buf = [0u8; MAX_PROPOSAL];
        let n = Proposal {
            serial: *b"TESTSERIAL000001",
            challenge: *challenge,
            op: *op,
        }
        .encode(&mut buf)
        .unwrap();
        buf[..n].to_vec()
    }

    fn f_approve(f: &mut Fixture, op: &AdminOp<'_>, who: &[usize]) -> Approvals {
        let challenge = f.admin_challenge();
        sign_proposal(&challenge, op, who)
    }

    #[test]
    fn approvals_cover_the_exact_rules() {
        let mut f = Fixture::new();
        f.login();
        // Admins approve a $100 budget; the operator submits $1,000,000.
        let approvals = f_approve(&mut f, &create(policy()), &[0, 1]);
        let greedy = Policy {
            budget: 100_000_000,
            ..policy()
        };
        assert_eq!(submit(&mut f, greedy, approvals), Status::ApprovalInvalid);
    }

    #[test]
    fn approvals_are_single_use() {
        let mut f = Fixture::new();
        f.login();
        let approvals = f_approve(&mut f, &create(policy()), &[0, 1]);
        assert_eq!(submit(&mut f, policy(), approvals), Status::Ok);
        // Replaying the same signatures to mint a second key fails...
        assert_eq!(
            submit(&mut f, policy(), approvals),
            Status::NoAdminChallenge
        );
        // ...even after a fresh challenge, since they covered the old one.
        f.admin_challenge();
        assert_eq!(submit(&mut f, policy(), approvals), Status::ApprovalInvalid);
    }

    #[test]
    fn approvals_from_another_hsm_do_not_work_here() {
        let mut f = Fixture::new();
        f.login();
        let challenge = f.admin_challenge();
        let mut buf = [0u8; MAX_PROPOSAL];
        let n = Proposal {
            serial: *b"OTHERHSM00000002",
            challenge,
            op: create(policy()),
        }
        .encode(&mut buf)
        .unwrap();
        let mut approvals = Approvals::default();
        for i in [0, 1] {
            approvals
                .push(i as u8, admins()[i].sign(&buf[..n]).to_bytes())
                .unwrap();
        }
        assert_eq!(submit(&mut f, policy(), approvals), Status::ApprovalInvalid);
    }

    #[test]
    fn deleting_an_agent_key_needs_sign_off_too() {
        let mut f = Fixture::new();
        f.login();
        let k = f.agent_key(policy());
        // With just the PIN: refused, so a fresh budget can't be had by
        // deleting and re-creating.
        assert_eq!(
            f.call(Request::DeleteKey { key: k.key }).0,
            Status::QuorumRequired
        );
        let approvals = f_approve(&mut f, &AdminOp::DeleteAgentKey { key: k.key }, &[1, 2]);
        assert_eq!(
            f.call(Request::DeleteAgentKey {
                key: k.key,
                approvals
            })
            .0,
            Status::Ok
        );
        assert_eq!(
            f.call(Request::GetKeyCert { key: k.key }).0,
            Status::KeyNotFound
        );
    }

    #[test]
    fn delete_approvals_name_the_key() {
        let mut f = Fixture::new();
        f.login();
        let a = f.agent_key(policy()).key;
        let b = f.agent_key(policy()).key;
        let approvals = f_approve(&mut f, &AdminOp::DeleteAgentKey { key: a }, &[0, 1]);
        assert_eq!(
            f.call(Request::DeleteAgentKey { key: b, approvals }).0,
            Status::ApprovalInvalid
        );
    }

    #[test]
    fn a_restart_cancels_a_pending_proposal() {
        let mut f = Fixture::new();
        f.login();
        let approvals = f_approve(&mut f, &create(policy()), &[0, 1]);
        f.hsm = Hsm::load(&f.storage.state).unwrap();
        f.session = Session::default();
        f.login();
        assert_eq!(
            submit(&mut f, policy(), approvals),
            Status::NoAdminChallenge
        );
    }

    #[test]
    fn without_admins_agent_keys_cannot_exist() {
        let mut f = Fixture::with_admins(&[], 0);
        f.login();
        f.admin_challenge();
        assert_eq!(
            submit(&mut f, policy(), Approvals::default()),
            Status::QuorumRequired
        );
    }

    #[test]
    fn bad_admin_setups_are_refused_at_the_factory() {
        let a = admin_publics();
        let mut storage = MemStorage::default();
        for (admins, threshold) in [
            (&a[..], 0u8),          // nobody needs to approve
            (&a[..], 4),            // more approvals than admins
            (&[a[0], a[0]][..], 1), // the same admin twice
            (&[][..], 1),           // a threshold with no admins
            (&[[0xff; 32]][..], 1), // not a valid public key
        ] {
            let p = crate::Provisioning {
                serial: [0; 16],
                pin: PIN,
                admins,
                threshold,
            };
            assert!(
                Hsm::provision(p, &mut TestRng(1), &mut storage).is_err(),
                "accepted admins={admins:?} threshold={threshold}"
            );
        }
    }

    #[test]
    fn certificates_are_reissued_identically_and_survive_restarts() {
        let mut f = Fixture::new();
        f.login();
        let (key, _, cert, sig) = f.agent_key_with_cert(policy());
        let (status, payload) = f.call(Request::GetKeyCert { key });
        assert_eq!(status, Status::Ok);
        assert_eq!(resp::decode_cert(&payload).unwrap(), (&cert[..], sig));

        let identity_before = f.hsm.identity_public();
        f.hsm = Hsm::load(&f.storage.state).unwrap();
        assert_eq!(f.hsm.identity_public(), identity_before);
        let (_, payload) = f.call(Request::GetKeyCert { key });
        assert_eq!(resp::decode_cert(&payload).unwrap(), (&cert[..], sig));
    }

    #[test]
    fn edited_certificates_are_rejected() {
        let mut f = Fixture::new();
        f.login();
        let (_, _, mut cert, sig) = f.agent_key_with_cert(policy());
        let id = f.hsm.identity_public();
        let n = cert.len();
        cert[n - 20] ^= 1; // somewhere in the policy
        assert_eq!(
            verify_key_cert(&id, &cert, &sig),
            Err(CertError::BadSignature)
        );
    }

    #[test]
    fn full_receiver_check_from_hsm_identity_to_action() {
        let mut f = Fixture::new();
        f.login();
        let (key, _, cert, cert_sig) = f.agent_key_with_cert(policy());
        let (other, _, other_cert, other_sig) = f.agent_key_with_cert(policy());
        let action = Action {
            kind: ActionKind::Payment,
            amount: 1_000,
            target: b"shop",
            details: b"",
            nonce: b"",
            expires: 0,
        };
        let sign = |f: &mut Fixture, key| {
            let (status, payload) = f.call(Request::SignAction {
                key,
                action,
                confirmation: None,
            });
            assert_eq!(status, Status::Ok);
            let (stmt, sig) = resp::decode_signed_action(&payload).unwrap();
            (stmt.to_vec(), sig)
        };
        let (stmt, sig) = sign(&mut f, key);
        let id = f.hsm.identity_public();

        let (c, s) = verify_action(&id, &cert, &cert_sig, &stmt, &sig).unwrap();
        assert_eq!(c.key, key);
        assert_eq!(s.action, action);

        // A statement from a different key does not pass with this certificate.
        let (stmt2, sig2) = sign(&mut f, other);
        assert!(verify_action(&id, &cert, &cert_sig, &stmt2, &sig2).is_err());
        assert!(verify_action(&id, &other_cert, &other_sig, &stmt2, &sig2).is_ok());

        // A different HSM's identity does not vouch for this key.
        let stranger = SigningKey::from_bytes(&[77; 32]).verifying_key().to_bytes();
        assert_eq!(
            verify_action(&stranger, &cert, &cert_sig, &stmt, &sig),
            Err(ActionError::Cert(CertError::BadSignature))
        );
    }

    // ---- receiver's one-time code and expiry ----

    fn pay_with<'a>(nonce: &'a [u8], expires: u64) -> Action<'a> {
        Action {
            kind: ActionKind::Payment,
            amount: 1_000,
            target: b"shop",
            details: b"",
            nonce,
            expires,
        }
    }

    #[test]
    fn rules_can_require_a_receivers_one_time_code() {
        let mut f = Fixture::new();
        f.login();
        let k = f.agent_key(Policy {
            require_nonce: true,
            ..policy()
        });
        let req = |f: &mut Fixture, a| {
            f.call(Request::SignAction {
                key: k.key,
                action: a,
                confirmation: None,
            })
        };
        assert_eq!(req(&mut f, pay_with(b"", 0)).0, Status::NonceRequired);

        let nonce = [0x5a; 16];
        let (status, payload) = req(&mut f, pay_with(&nonce, 1_900_000_000));
        assert_eq!(status, Status::Ok);
        let (stmt, sig) = resp::decode_signed_action(&payload).unwrap();
        let s = crate::agent::verify_statement(&k.public, stmt, &sig).unwrap();
        assert_eq!(s.action.nonce, &nonce);
        assert_eq!(s.action.expires, 1_900_000_000);
    }

    #[test]
    fn short_codes_are_rejected() {
        let mut f = Fixture::new();
        f.login();
        let k = f.agent_key(policy());
        let mut buf = [0u8; MAX_FRAME];
        let mut w = crate::wire::Writer::new(&mut buf);
        w.u8(0x21).unwrap();
        w.u32(k.key).unwrap();
        w.u8(ActionKind::Payment as u8).unwrap();
        w.u64(100).unwrap();
        w.bytes(b"shop").unwrap();
        w.bytes(b"").unwrap();
        w.bytes(b"guessable").unwrap(); // 9 bytes: too short to be unguessable
        w.u64(0).unwrap();
        w.u8(0).unwrap();
        let n = w.len();
        assert_eq!(f.raw(&buf[..n]), vec![Status::BadRequest as u8]);
    }

    #[test]
    fn the_users_approval_covers_the_code_and_expiry_too() {
        let confirmer = SigningKey::from_bytes(&[9; 32]);
        let mut f = Fixture::new();
        f.login();
        let k = f.agent_key(Policy {
            confirm_above: 0,
            confirmer: Some(confirmer.verifying_key().to_bytes()),
            ..policy()
        });
        let approved = pay_with(&[1; 16], 1_900_000_000);
        let (status, payload) = f.call(Request::GetChallenge);
        assert_eq!(status, Status::Ok);
        let challenge = resp::decode_challenge(&payload).unwrap();
        let mut msg = [0u8; crate::agent::CONFIRM_MESSAGE_MAX];
        let n = crate::agent::confirmation_message(
            &mut msg,
            b"TESTSERIAL000001",
            &challenge,
            k.key,
            &approved,
        )
        .unwrap();
        let conf = confirmer.sign(&msg[..n]).to_bytes();
        // The agent stretches the expiry after the user approved.
        let stretched = pay_with(&[1; 16], u64::MAX);
        assert_eq!(
            f.call(Request::SignAction {
                key: k.key,
                action: stretched,
                confirmation: Some(conf)
            })
            .0,
            Status::ConfirmationInvalid
        );
    }
}

// ---- milestone 3: rule changes, admin changes, audit log ---------------------

mod milestone3 {
    use super::agent::sign_proposal;
    use super::*;
    use crate::admin::{AdminOp, AdminSet, Approvals};
    use crate::agent::{Action, ActionKind, Policy};
    use crate::audit::{AUDIT_CAPACITY, ENTRY_LEN, Entry, Event, LogError, verify_log};
    use crate::cert::{ActionError, verify_action, verify_key_cert};
    use ed25519_dalek::SigningKey;

    fn policy() -> Policy {
        Policy {
            allowed: ActionKind::Payment.bit(),
            max_amount: 5_000,
            budget: 10_000,
            confirm_above: 5_000,
            always_confirm: 0,
            confirmer: None,
            require_nonce: false,
        }
    }

    fn pay(cents: u64) -> Action<'static> {
        Action {
            kind: ActionKind::Payment,
            amount: cents,
            target: b"shop",
            details: b"",
            nonce: b"",
            expires: 0,
        }
    }

    fn act(f: &mut Fixture, key: u32, a: Action<'_>) -> (Status, Vec<u8>) {
        f.call(Request::SignAction {
            key,
            action: a,
            confirmation: None,
        })
    }

    /// What an audit collector does: copy out everything held, then release it.
    fn pull(f: &mut Fixture, from: u64) -> Vec<[u8; ENTRY_LEN]> {
        let (status, payload) = f.call(Request::ReadAudit { from });
        assert_eq!(status, Status::Ok);
        let batch = resp::AuditBatch::decode(&payload).unwrap();
        let entries: Vec<_> = batch.entries().copied().collect();
        assert_eq!(
            f.call(Request::AckAudit {
                upto: batch.last_seq
            })
            .0,
            Status::Ok
        );
        entries
    }

    fn checkpoint(f: &mut Fixture) -> (Vec<u8>, [u8; 64]) {
        let (status, payload) = f.call(Request::AuditCheckpoint);
        assert_eq!(status, Status::Ok);
        let (cp, sig) = resp::decode_checkpoint(&payload).unwrap();
        (cp.to_vec(), sig)
    }

    fn events(entries: &[[u8; ENTRY_LEN]]) -> Vec<(Event, u8)> {
        entries
            .iter()
            .map(|e| {
                let e = Entry::decode(e).unwrap();
                (e.event, e.status)
            })
            .collect()
    }

    // -- audit log --

    #[test]
    fn the_log_starts_at_the_factory_and_records_approvals_and_refusals() {
        let mut f = Fixture::new();
        f.call(Request::Login { pin: b"wrong!" });
        f.login();
        let k = f.agent_key(policy()).key;
        act(&mut f, k, pay(100));
        act(&mut f, k, pay(9_999)); // over the per-payment limit
        let log = pull(&mut f, 1);
        assert_eq!(
            events(&log),
            vec![
                (Event::Provisioned, 0),
                (Event::LoginFailed, Status::PinIncorrect as u8),
                (Event::LoginOk, 0),
                (Event::AgentKeyCreated, 0),
                (Event::ActionApproved, 0),
                (Event::ActionRefused, Status::AmountTooHigh as u8),
            ]
        );
        let refused = Entry::decode(&log[5]).unwrap();
        assert_eq!((refused.key, refused.amount), (k, 9_999));
    }

    #[test]
    fn people_without_the_pin_cannot_flood_the_log() {
        let mut f = Fixture::new();
        f.login();
        let k = f.agent_key(policy()).key;
        f.call(Request::Logout);
        let before = pull(&mut f, 1).len();
        for _ in 0..100 {
            assert_eq!(act(&mut f, k, pay(1)).0, Status::NotLoggedIn);
        }
        let (_, payload) = f.call(Request::ReadAudit { from: 1 });
        assert_eq!(
            resp::AuditBatch::decode(&payload)
                .unwrap()
                .entries()
                .count(),
            0
        );
        assert!(before > 0);
    }

    #[test]
    fn a_full_log_stops_the_hsm_until_it_is_copied_out() {
        let mut f = Fixture::new();
        f.login();
        let k = f.agent_key(policy()).key;
        // Fill the log with refused actions.
        let mut n = 0;
        loop {
            let (status, _) = act(&mut f, k, pay(9_999));
            if status == Status::AuditFull {
                break;
            }
            assert_eq!(status, Status::AmountTooHigh);
            n += 1;
            assert!(n <= AUDIT_CAPACITY);
        }
        // Even allowed actions are refused now: they couldn't be recorded.
        assert_eq!(act(&mut f, k, pay(1)).0, Status::AuditFull);
        f.call(Request::Logout);
        assert_eq!(f.call(Request::Login { pin: PIN }).0, Status::AuditFull);

        // An audit collector copies it out (no PIN needed); work resumes.
        let copied = pull(&mut f, 1);
        assert_eq!(copied.len(), AUDIT_CAPACITY);
        f.login();
        assert_eq!(act(&mut f, k, pay(1)).0, Status::Ok);
    }

    #[test]
    fn a_complete_copy_matches_the_signed_checkpoint() {
        let mut f = Fixture::new();
        f.login();
        let k = f.agent_key(policy()).key;
        let mut log = pull(&mut f, 1);
        for _ in 0..5 {
            act(&mut f, k, pay(100));
        }
        log.extend(pull(&mut f, log.len() as u64 + 1));
        let (cp, sig) = checkpoint(&mut f);
        let id = f.hsm.identity_public();
        let ok = verify_log(&id, &cp, &sig, &log).unwrap();
        assert_eq!(ok.seq, log.len() as u64);
    }

    #[test]
    fn editing_removing_or_reordering_entries_is_detected() {
        let mut f = Fixture::new();
        f.login();
        let k = f.agent_key(policy()).key;
        act(&mut f, k, pay(100));
        act(&mut f, k, pay(9_999));
        act(&mut f, k, pay(200));
        let log = pull(&mut f, 1);
        let (cp, sig) = checkpoint(&mut f);
        let id = f.hsm.identity_public();
        assert!(verify_log(&id, &cp, &sig, &log).is_ok());

        // Hide that the refused $99.99 attempt was ever made: change it to $1.
        let mut edited = log.clone();
        let i = log.len() - 2;
        let mut e = Entry::decode(&edited[i]).unwrap();
        e.amount = 100;
        edited[i] = e.encode();
        assert_eq!(
            verify_log(&id, &cp, &sig, &edited),
            Err(LogError::HeadMismatch)
        );

        // Delete it outright.
        let mut removed = log.clone();
        removed.remove(i);
        assert_eq!(
            verify_log(&id, &cp, &sig, &removed),
            Err(LogError::BrokenAt(i as u64 + 1))
        );

        // Swap two entries.
        let mut swapped = log.clone();
        swapped.swap(1, 2);
        assert!(matches!(
            verify_log(&id, &cp, &sig, &swapped),
            Err(LogError::BrokenAt(_))
        ));

        // Drop the most recent entries.
        assert!(matches!(
            verify_log(&id, &cp, &sig, &log[..log.len() - 2]),
            Err(LogError::TooShort { .. })
        ));

        // A checkpoint "signed" by anyone else.
        let other = SigningKey::from_bytes(&[5; 32]).verifying_key().to_bytes();
        assert_eq!(
            verify_log(&other, &cp, &sig, &log),
            Err(LogError::BadCheckpoint)
        );
    }

    #[test]
    fn the_log_survives_a_restart() {
        let mut f = Fixture::new();
        f.login();
        let k = f.agent_key(policy()).key;
        act(&mut f, k, pay(100));
        let first = pull(&mut f, 1);
        act(&mut f, k, pay(200));
        f.hsm = Hsm::load(&f.storage.state).unwrap();
        f.session = Session::default();
        f.login();
        let mut log = first.clone();
        log.extend(pull(&mut f, first.len() as u64 + 1));
        let (cp, sig) = checkpoint(&mut f);
        verify_log(&f.hsm.identity_public(), &cp, &sig, &log).unwrap();
    }

    #[test]
    fn releasing_entries_that_dont_exist_is_refused() {
        let mut f = Fixture::new();
        assert_eq!(
            f.call(Request::AckAudit { upto: 1_000 }).0,
            Status::BadRequest
        );
    }

    // -- changing an agent key's rules --

    fn update(
        f: &mut Fixture,
        key: u32,
        policy: Policy,
        approvals: Approvals,
    ) -> (Status, Vec<u8>) {
        f.call(Request::UpdatePolicy {
            key,
            policy,
            approvals,
        })
    }

    #[test]
    fn the_pin_alone_cannot_loosen_a_keys_rules() {
        let mut f = Fixture::new();
        f.login();
        let k = f.agent_key(policy()).key;
        let looser = Policy {
            budget: u64::MAX / 2,
            ..policy()
        };
        f.admin_challenge();
        assert_eq!(
            update(&mut f, k, looser, Approvals::default()).0,
            Status::QuorumRequired
        );
        let log = pull(&mut f, 1);
        assert_eq!(
            events(&log).last(),
            Some(&(Event::AdminRequestRefused, Status::QuorumRequired as u8))
        );
    }

    #[test]
    fn admins_can_change_rules_and_spending_carries_over() {
        let mut f = Fixture::new();
        f.login();
        let (k, _, old_cert, old_sig) = f.agent_key_with_cert(policy());
        assert_eq!(act(&mut f, k, pay(4_000)).0, Status::Ok);

        // Admins halve the budget to $50; $40 is already spent.
        let tighter = Policy {
            budget: 5_000,
            ..policy()
        };
        let op = AdminOp::UpdatePolicy {
            key: k,
            policy: tighter,
        };
        let challenge = f.admin_challenge();
        let approvals = sign_proposal(&challenge, &op, &[1, 2]);
        let (status, payload) = update(&mut f, k, tighter, approvals);
        assert_eq!(status, Status::Ok);
        let (cert, sig) = resp::decode_cert(&payload).unwrap();
        let id = f.hsm.identity_public();
        let c = verify_key_cert(&id, cert, &sig).unwrap();
        assert_eq!((c.version, c.policy, c.approvers), (2, tighter, 0b110));

        // The new budget applies to what's already spent.
        assert_eq!(act(&mut f, k, pay(2_000)).0, Status::BudgetExceeded);
        let (status, payload) = act(&mut f, k, pay(1_000));
        assert_eq!(status, Status::Ok);
        let (stmt, ssig) = resp::decode_signed_action(&payload).unwrap();

        // A shop with the new certificate accepts it; one holding the old
        // certificate sees the rules changed and must fetch the new one.
        assert!(verify_action(&id, cert, &sig, stmt, &ssig).is_ok());
        assert_eq!(
            verify_action(&id, &old_cert, &old_sig, stmt, &ssig),
            Err(ActionError::Mismatch)
        );
    }

    #[test]
    fn approvals_for_one_rule_change_cannot_be_used_for_another() {
        let mut f = Fixture::new();
        f.login();
        let k = f.agent_key(policy()).key;
        let modest = Policy {
            budget: 20_000,
            ..policy()
        };
        let greedy = Policy {
            budget: 2_000_000,
            ..policy()
        };
        let challenge = f.admin_challenge();
        let approvals = sign_proposal(
            &challenge,
            &AdminOp::UpdatePolicy {
                key: k,
                policy: modest,
            },
            &[0, 1],
        );
        assert_eq!(
            update(&mut f, k, greedy, approvals).0,
            Status::ApprovalInvalid
        );
    }

    #[test]
    fn a_budget_lowered_below_spending_survives_a_restart() {
        let mut f = Fixture::new();
        f.login();
        let k = f.agent_key(policy()).key;
        act(&mut f, k, pay(5_000));
        let frozen = Policy {
            budget: 100,
            ..policy()
        };
        let challenge = f.admin_challenge();
        let approvals = sign_proposal(
            &challenge,
            &AdminOp::UpdatePolicy {
                key: k,
                policy: frozen,
            },
            &[0, 1],
        );
        assert_eq!(update(&mut f, k, frozen, approvals).0, Status::Ok);
        f.hsm = Hsm::load(&f.storage.state).unwrap();
        f.session = Session::default();
        f.login();
        assert_eq!(act(&mut f, k, pay(1)).0, Status::BudgetExceeded);
    }

    // -- changing the admins --

    fn new_admins() -> [SigningKey; 2] {
        [31, 32].map(|b| SigningKey::from_bytes(&[b; 32]))
    }

    fn new_admin_set() -> AdminSet {
        AdminSet::new(&new_admins().map(|k| k.verifying_key().to_bytes()), 2).unwrap()
    }

    #[test]
    fn current_admins_hand_over_to_new_ones() {
        let mut f = Fixture::new();
        f.login();
        let admins = new_admin_set();
        let challenge = f.admin_challenge();
        let approvals = sign_proposal(&challenge, &AdminOp::ChangeAdmins { admins }, &[0, 2]);
        assert_eq!(
            f.call(Request::ChangeAdmins { admins, approvals }).0,
            Status::Ok
        );
        let (_, payload) = f.call(Request::GetIdentity);
        assert_eq!(resp::Identity::decode(&payload).unwrap().admins, admins);

        // The old admins no longer count...
        let challenge = f.admin_challenge();
        let old = sign_proposal(
            &challenge,
            &AdminOp::CreateAgentKey {
                label: b"agent",
                ext_id: b"",
                policy: policy(),
            },
            &[0, 1],
        );
        assert_eq!(
            f.call(Request::GenerateAgentKey {
                label: b"agent",
                ext_id: b"",
                policy: policy(),
                approvals: old,
            })
            .0,
            Status::ApprovalInvalid
        );
        // ...and the new ones do.
        let challenge = f.admin_challenge();
        let mut buf = [0u8; crate::admin::MAX_PROPOSAL];
        let n = crate::admin::Proposal {
            serial: *b"TESTSERIAL000001",
            challenge,
            op: AdminOp::CreateAgentKey {
                label: b"agent",
                ext_id: b"",
                policy: policy(),
            },
        }
        .encode(&mut buf)
        .unwrap();
        let mut approvals = Approvals::default();
        for (i, k) in new_admins().iter().enumerate() {
            use ed25519_dalek::Signer;
            approvals
                .push(i as u8, k.sign(&buf[..n]).to_bytes())
                .unwrap();
        }
        assert_eq!(
            f.call(Request::GenerateAgentKey {
                label: b"agent",
                ext_id: b"",
                policy: policy(),
                approvals,
            })
            .0,
            Status::Ok
        );
        assert!(events(&pull(&mut f, 1)).contains(&(Event::AdminsChanged, 0)));
    }

    #[test]
    fn would_be_admins_cannot_install_themselves() {
        let mut f = Fixture::new();
        f.login();
        let admins = new_admin_set();
        let challenge = f.admin_challenge();
        let mut buf = [0u8; crate::admin::MAX_PROPOSAL];
        let n = crate::admin::Proposal {
            serial: *b"TESTSERIAL000001",
            challenge,
            op: AdminOp::ChangeAdmins { admins },
        }
        .encode(&mut buf)
        .unwrap();
        let mut approvals = Approvals::default();
        for (i, k) in new_admins().iter().enumerate() {
            use ed25519_dalek::Signer;
            approvals
                .push(i as u8, k.sign(&buf[..n]).to_bytes())
                .unwrap();
        }
        assert_eq!(
            f.call(Request::ChangeAdmins { admins, approvals }).0,
            Status::ApprovalInvalid
        );
    }

    #[test]
    fn the_admin_list_can_never_be_emptied() {
        let mut f = Fixture::new();
        f.login();
        let mut buf = [0u8; MAX_FRAME];
        let n = Request::ChangeAdmins {
            admins: AdminSet::NONE,
            approvals: Approvals::default(),
        }
        .encode(&mut buf)
        .unwrap();
        assert_eq!(f.raw(&buf[..n]), vec![Status::BadRequest as u8]);
    }
}
