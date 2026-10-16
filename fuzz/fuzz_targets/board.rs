//! A board booting from any flash contents (damaged, tampered or torn), then
//! receiving any byte stream over USB in any packet sizes. Must never panic,
//! must never be blank unless the flash really was erased, and every reply
//! must be a well-formed response frame.
#![no_main]

use libfuzzer_sys::fuzz_target;
use quorum_core::wire::{MAX_FRAME, resp};
use quorum_device::Firmware;
use quorum_device::flash::region_len;
use quorum_device::framer::Framer;
use quorum_device::mock::{MOCK_SECTOR, MockFlash};
use rand_core::OsRng;

const LEN: usize = region_len(MOCK_SECTOR) as usize;

fuzz_target!(|data: &[u8]| {
    // First byte: how much of the input is flash; the rest is the USB stream.
    let Some((&split, rest)) = data.split_first() else {
        return;
    };
    let flash_len = (split as usize * 64).min(rest.len());
    let (image, stream) = rest.split_at(flash_len);

    let mut chip = MockFlash::<LEN>::new();
    // Repeat the given bytes over the whole chip, so short inputs can still
    // place data in both slots.
    if !image.is_empty() {
        for (i, b) in chip.mem.iter_mut().enumerate() {
            *b = image[i % image.len()];
        }
    }
    let erased = chip.mem.iter().all(|&b| b == 0xFF);
    let mut fw = Firmware::boot(chip, 0);
    assert!(fw.mode() != "blank" || erased);

    let mut framer = Framer::default();
    let mut out = vec![0u8; MAX_FRAME];
    // Packet sizes taken from the stream itself.
    let mut input = stream;
    while let Some((&size, tail)) = input.split_first() {
        let n = (size as usize % 65).min(tail.len());
        let (mut packet, next) = tail.split_at(n);
        input = next;
        while !packet.is_empty() {
            let Ok((used, ready)) = framer.push(packet) else {
                return;
            };
            packet = &packet[used..];
            if ready {
                let m = fw.handle(&mut OsRng, framer.frame(), &mut out);
                framer.reset();
                assert!(m >= 1 && m <= MAX_FRAME);
                resp::split(&out[..m]).expect("well-formed response");
            }
        }
        if n == 0 {
            break;
        }
    }
});
