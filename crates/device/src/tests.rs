use quorum_core::admin::AdminSet;
use quorum_core::wire::{MAX_FRAME, Request, Status, resp};
use rand_core::OsRng;

use crate::Firmware;
use crate::flash::{Flash, FlashError, region_len};
use crate::framer::{FrameError, Framer};
use crate::mock::{MOCK_SECTOR, MockFlash};

const LEN: usize = region_len(MOCK_SECTOR) as usize;
type Chip = MockFlash<LEN>;

fn call<F: Flash>(fw: &mut Firmware<F>, req: Request<'_>) -> (Status, Vec<u8>) {
    let mut frame = [0u8; MAX_FRAME];
    let n = req.encode(&mut frame).unwrap();
    let mut out = [0u8; MAX_FRAME];
    let m = fw.handle(&mut OsRng, &frame[..n], &mut out);
    let (status, payload) = resp::split(&out[..m]).unwrap();
    (status, payload.to_vec())
}

fn provision(fw: &mut Firmware<impl Flash>) -> resp::Provisioned {
    let (status, payload) = call(
        fw,
        Request::Provision {
            pin: b"1234",
            admins: AdminSet::NONE,
        },
    );
    assert_eq!(status, Status::Ok);
    resp::Provisioned::decode(&payload).unwrap()
}

fn info(fw: &mut Firmware<impl Flash>) -> resp::Info {
    let (status, payload) = call(fw, Request::GetInfo);
    assert_eq!(status, Status::Ok);
    resp::Info::decode(&payload).unwrap()
}

/// Turns the device off and on again.
fn reboot(fw: Firmware<Chip>) -> Firmware<Chip> {
    Firmware::boot(fw.into_flash().reboot(), 0)
}

#[test]
fn a_new_device_is_blank_and_only_accepts_provisioning() {
    let mut fw = Firmware::boot(Chip::new(), 0);
    assert_eq!(fw.mode(), "blank");
    assert_eq!(call(&mut fw, Request::GetInfo).0, Status::NotProvisioned);
    assert_eq!(
        call(&mut fw, Request::Login { pin: b"1234" }).0,
        Status::NotProvisioned
    );
    let mut out = [0u8; MAX_FRAME];
    let n = fw.handle(&mut OsRng, &[0xEE, 1, 2], &mut out);
    assert_eq!(&out[..n], &[Status::BadRequest as u8]);
}

#[test]
fn provisioning_survives_a_restart_and_happens_only_once() {
    let mut fw = Firmware::boot(Chip::new(), 0);
    let p = provision(&mut fw);
    assert!(p.serial.iter().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(info(&mut fw).serial, p.serial);

    let mut fw = reboot(fw);
    assert_eq!(fw.mode(), "ready");
    assert_eq!(info(&mut fw).serial, p.serial);
    let (_, id) = call(&mut fw, Request::GetIdentity);
    assert_eq!(resp::Identity::decode(&id).unwrap().public, p.public);
    assert_eq!(call(&mut fw, Request::Login { pin: b"1234" }).0, Status::Ok);

    let again = Request::Provision {
        pin: b"9999",
        admins: AdminSet::NONE,
    };
    assert_eq!(call(&mut fw, again).0, Status::AlreadyProvisioned);
    let mut fw = reboot(fw);
    assert_eq!(call(&mut fw, again).0, Status::AlreadyProvisioned);
}

#[test]
fn a_bad_pin_at_provisioning_leaves_the_device_blank() {
    let mut fw = Firmware::boot(Chip::new(), 0);
    let req = Request::Provision {
        pin: b"12",
        admins: AdminSet::NONE,
    };
    assert_eq!(call(&mut fw, req).0, Status::BadRequest);
    assert_eq!(fw.mode(), "blank");
    let fw = reboot(fw);
    assert_eq!(fw.mode(), "blank");
}

#[test]
fn a_disconnect_logs_the_host_out() {
    let mut fw = Firmware::boot(Chip::new(), 0);
    provision(&mut fw);
    assert_eq!(call(&mut fw, Request::Login { pin: b"1234" }).0, Status::Ok);
    fw.end_session();
    let req = Request::GenerateKey {
        label: b"k",
        ext_id: b"",
    };
    assert_eq!(call(&mut fw, req).0, Status::NotLoggedIn);
}

#[test]
fn a_power_cut_at_any_moment_of_a_save_keeps_a_valid_state() {
    // Provision, then find out how many flash byte-operations it takes to
    // log in and create a key (two saves: the PIN attempt, then the key).
    let mut fw = Firmware::boot(Chip::new(), 0);
    provision(&mut fw);
    let before = fw.into_flash().reboot();
    let steps = |fw: &mut Firmware<Chip>| {
        let login = call(fw, Request::Login { pin: b"1234" }).0;
        let key = call(
            fw,
            Request::GenerateKey {
                label: b"k",
                ext_id: b"",
            },
        )
        .0;
        (login, key)
    };
    let mut fw = Firmware::boot(before.reboot(), 0);
    assert_eq!(steps(&mut fw), (Status::Ok, Status::Ok));
    let total = fw.into_flash().ops;
    assert!(total > 2 * MOCK_SECTOR as usize);

    // Cut the power after every possible number of operations (every byte
    // while writing, every 16th byte while erasing, to keep the test fast).
    let mut cut = 0;
    let mut checked = 0;
    while cut <= total {
        let mut chip = before.reboot();
        chip.power_left = Some(cut);
        let mut fw = Firmware::boot(chip, 0);
        let (_, key) = steps(&mut fw);

        let mut fw = reboot(fw);
        assert_eq!(fw.mode(), "ready", "cut after {cut} operations");
        let keys = info(&mut fw).key_count;
        assert!(keys <= 1);
        if key == Status::Ok {
            // The device said yes, so the key must have been saved.
            assert_eq!(keys, 1, "cut after {cut} operations");
        }
        checked += 1;
        cut += 1;
    }
    assert!(checked > 1000);
}

#[test]
fn damaged_flash_is_refused_and_never_reprovisioned() {
    let mut chip = Chip::new();
    chip.mem[..64].fill(0x5A);
    let mut fw = Firmware::boot(chip, 0);
    assert_eq!(fw.mode(), "broken");
    assert_eq!(call(&mut fw, Request::GetInfo).0, Status::Fault);
    let req = Request::Provision {
        pin: b"1234",
        admins: AdminSet::NONE,
    };
    assert_eq!(call(&mut fw, req).0, Status::Fault);
}

#[test]
fn a_flipped_bit_in_the_newest_save_falls_back_to_the_previous_one() {
    let mut fw = Firmware::boot(Chip::new(), 0);
    provision(&mut fw); // save 1, slot 1
    assert_eq!(call(&mut fw, Request::Login { pin: b"1234" }).0, Status::Ok); // save 2, slot 0
    let mut chip = fw.into_flash();
    chip.mem[100] ^= 0x04;
    let mut fw = Firmware::boot(chip.reboot(), 0);
    assert_eq!(fw.mode(), "ready");
    // Back to the state right after provisioning.
    assert_eq!(info(&mut fw).pin_tries_left, 5);
}

/// Flash that silently ignores writes, like a worn-out chip.
struct WornOut(Chip);

impl Flash for WornOut {
    const SECTOR: u32 = MOCK_SECTOR;
    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), FlashError> {
        self.0.read(offset, buf)
    }
    fn erase(&mut self, from: u32, to: u32) -> Result<(), FlashError> {
        self.0.erase(from, to)
    }
    fn write(&mut self, _offset: u32, _data: &[u8]) -> Result<(), FlashError> {
        Ok(())
    }
}

#[test]
fn a_save_that_does_not_read_back_correctly_stops_the_device() {
    let mut fw = Firmware::boot(WornOut(Chip::new()), 0);
    let req = Request::Provision {
        pin: b"1234",
        admins: AdminSet::NONE,
    };
    assert_eq!(call(&mut fw, req).0, Status::Fault);
    assert_eq!(fw.mode(), "broken");
}

#[test]
fn frames_are_reassembled_from_any_packet_sizes() {
    let frames: [&[u8]; 3] = [b"\x01", b"", &[7u8; 300]];
    let mut stream = Vec::new();
    for f in frames {
        stream.extend_from_slice(&(f.len() as u32).to_le_bytes());
        stream.extend_from_slice(f);
    }
    for packet in 1..=70 {
        let mut framer = Framer::default();
        let mut got: Vec<Vec<u8>> = Vec::new();
        for mut chunk in stream.chunks(packet) {
            while !chunk.is_empty() || framer.push(&[]).unwrap().1 {
                let (used, ready) = framer.push(chunk).unwrap();
                chunk = &chunk[used..];
                if ready {
                    got.push(framer.frame().to_vec());
                    framer.reset();
                } else {
                    break;
                }
            }
        }
        assert_eq!(got, frames.map(|f| f.to_vec()), "packet size {packet}");
    }
}

#[test]
fn oversized_frames_are_refused() {
    let mut framer = Framer::default();
    let len = (MAX_FRAME as u32 + 1).to_le_bytes();
    assert_eq!(framer.push(&len), Err(FrameError::TooLarge));
}

#[test]
fn a_power_cut_during_provisioning_never_yields_a_half_made_device() {
    let req = Request::Provision {
        pin: b"1234",
        admins: AdminSet::NONE,
    };
    let mut fw = Firmware::boot(Chip::new(), 0);
    assert_eq!(call(&mut fw, req).0, Status::Ok);
    let total = fw.into_flash().ops;
    for cut in 0..=total {
        let mut chip = Chip::new();
        chip.power_left = Some(cut);
        let mut fw = Firmware::boot(chip, 0);
        let (status, _) = call(&mut fw, req);
        let fw = reboot(fw);
        match fw.mode() {
            "ready" => {}
            // Cut before anything was written (erasing blank flash changes
            // nothing), or mid-write: never "ready" after a refusal...
            other => assert_ne!(status, Status::Ok, "cut {cut}: {other}"),
        }
        if status == Status::Ok {
            assert_eq!(fw.mode(), "ready", "cut {cut}");
        }
    }
}
