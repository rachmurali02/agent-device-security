//! The quorum HSM on an RP2350 board: the Raspberry Pi Pico 2 (default) or
//! the Seeed Studio XIAO RP2350 (`--features xiao-rp2350`).
//!
//! This file only connects the chip to the HSM logic, which lives in the
//! `quorum-device` and `quorum-core` crates (tested on the computer):
//!
//! - **USB** shows up as a serial port (`/dev/ttyACM0` on Linux). Requests
//!   and responses use the same `[length][frame]` format as the emulator.
//!   Opening the port starts a session; closing it logs out.
//! - **Flash**: the last 64 KB of the 4 MB flash chip hold the HSM's state
//!   (two slots, see `quorum_device::flash`). The program cannot overlap it
//!   (memory.x.in).
//! - **Random numbers** come from the RP2350's hardware random number
//!   generator (TRNG): key generation, challenges, the serial number.
//! - **The LED** shows the device's mode: slow blink = blank (waiting for
//!   `quorum provision`), steady = ready, fast blink = broken (refusing
//!   everything).

#![no_std]
#![no_main]
// The only unsafe code is inside the chip support library (embassy-rp).
#![deny(unsafe_code)]

use core::sync::atomic::{AtomicU8, Ordering};

use embassy_executor::Spawner;
use embassy_futures::join::join3;
use embassy_futures::select::{Either, select};
use embassy_rp::flash::{Blocking, Flash};
use embassy_rp::gpio::{Level, Output};
use embassy_rp::peripherals::{FLASH, TRNG, USB};
use embassy_rp::trng::{self, Trng};
use embassy_rp::usb::{self, Driver};
use embassy_rp::{Peri, bind_interrupts};
use embassy_time::Timer;
use embassy_usb::class::cdc_acm::{CdcAcmClass, ControlChanged, Receiver, Sender, State};
use embassy_usb::driver::EndpointError;
use embassy_usb::{Builder, Config};
use panic_halt as _;
use quorum_core::wire::MAX_FRAME;
use quorum_device::Firmware;
use quorum_device::flash::{Flash as StateFlash, FlashError, region_len};
use quorum_device::framer::Framer;
use static_cell::StaticCell;

bind_interrupts!(struct Irqs {
    USBCTRL_IRQ => usb::InterruptHandler<USB>;
    TRNG_IRQ => trng::InterruptHandler<TRNG>;
});

/// The board's flash chip: 4 MB on the Pico 2, 2 MB on the XIAO RP2350.
#[cfg(not(feature = "xiao-rp2350"))]
const FLASH_SIZE: usize = 4 * 1024 * 1024;
#[cfg(feature = "xiao-rp2350")]
const FLASH_SIZE: usize = 2 * 1024 * 1024;
/// Both boards have a user LED on GPIO 25. The XIAO's lights up when the pin
/// is low.
#[cfg(not(feature = "xiao-rp2350"))]
const LED_ON: Level = Level::High;
#[cfg(not(feature = "xiao-rp2350"))]
const LED_OFF: Level = Level::Low;
#[cfg(feature = "xiao-rp2350")]
const LED_ON: Level = Level::Low;
#[cfg(feature = "xiao-rp2350")]
const LED_OFF: Level = Level::High;
/// Where the state area starts: the last 64 KB, which memory.x keeps free.
const STATE_BASE: u32 = (FLASH_SIZE - 64 * 1024) as u32;
const _: () = assert!(region_len(4096) <= 64 * 1024);

/// USB packets on a full-speed bulk endpoint.
const PACKET: usize = 64;

/// The firmware's mode, shared with the LED task.
static MODE: AtomicU8 = AtomicU8::new(0);
const BLANK: u8 = 0;
const READY: u8 = 1;
const BROKEN: u8 = 2;

/// The RP2350's flash, as the HSM sees it.
struct ChipFlash(Flash<'static, FLASH, Blocking, FLASH_SIZE>);

impl StateFlash for ChipFlash {
    const SECTOR: u32 = embassy_rp::flash::ERASE_SIZE as u32;

    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), FlashError> {
        self.0
            .blocking_read(offset, buf)
            .map_err(|_| FlashError::Failed)
    }

    fn erase(&mut self, from: u32, to: u32) -> Result<(), FlashError> {
        self.0
            .blocking_erase(from, to)
            .map_err(|_| FlashError::Failed)
    }

    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), FlashError> {
        self.0
            .blocking_write(offset, data)
            .map_err(|_| FlashError::Failed)
    }
}

type Hsm = Firmware<ChipFlash>;
type Rng = Trng<'static, TRNG>;

fn publish_mode(fw: &Hsm) {
    let mode = match fw.mode() {
        "blank" => BLANK,
        "ready" => READY,
        _ => BROKEN,
    };
    MODE.store(mode, Ordering::Relaxed);
}

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    let p = embassy_rp::init(Default::default());

    let mut rng: Rng = Trng::new(p.TRNG, Irqs, trng::Config::default());
    static FIRMWARE: StaticCell<Hsm> = StaticCell::new();
    let flash = ChipFlash(Flash::new_blocking(p.FLASH));
    let fw = FIRMWARE.init_with(|| Firmware::boot(flash, STATE_BASE));
    publish_mode(fw);

    // USB: one serial port (CDC ACM). The ID pair is pid.codes' test ID,
    // meant for devices that are not sold.
    let mut config = Config::new(0x1209, 0x0001);
    config.manufacturer = Some("quorum-hsm");
    config.product = Some("quorum HSM (RP2350)");
    config.max_power = 100;
    config.max_packet_size_0 = 64;

    static CONFIG_DESC: StaticCell<[u8; 256]> = StaticCell::new();
    static BOS_DESC: StaticCell<[u8; 256]> = StaticCell::new();
    static CONTROL_BUF: StaticCell<[u8; 64]> = StaticCell::new();
    static CDC_STATE: StaticCell<State> = StaticCell::new();
    let mut builder = Builder::new(
        Driver::new(p.USB, Irqs),
        config,
        CONFIG_DESC.init([0; 256]),
        BOS_DESC.init([0; 256]),
        &mut [],
        CONTROL_BUF.init([0; 64]),
    );
    let class = CdcAcmClass::new(&mut builder, CDC_STATE.init(State::new()), PACKET as u16);
    let (mut tx, mut rx, control) = class.split_with_control();
    let mut usb = builder.build();

    let hsm = async {
        loop {
            rx.wait_connection().await;
            // Ends when the host closes the port (or sends garbage).
            let _ = session(fw, &mut rng, &mut tx, &mut rx, &control).await;
            fw.end_session();
        }
    };
    join3(usb.run(), hsm, led(p.PIN_25)).await;
}

#[derive(Debug)]
enum Disconnected {
    Usb,
    HostClosed,
    BadFrame,
}

impl From<EndpointError> for Disconnected {
    fn from(_: EndpointError) -> Self {
        Disconnected::Usb
    }
}

/// One session: from opening the serial port to closing it.
async fn session(
    fw: &mut Hsm,
    rng: &mut Rng,
    tx: &mut Sender<'static, Driver<'static, USB>>,
    rx: &mut Receiver<'static, Driver<'static, USB>>,
    control: &ControlChanged<'static>,
) -> Result<(), Disconnected> {
    let mut framer = Framer::default();
    let mut packet = [0u8; PACKET];
    let mut out = [0u8; 4 + MAX_FRAME];
    loop {
        let n = match select(rx.read_packet(&mut packet), control.control_changed()).await {
            Either::First(n) => n?,
            Either::Second(()) if !control.dtr() => return Err(Disconnected::HostClosed),
            Either::Second(()) => continue,
        };
        let mut input = &packet[..n];
        while !input.is_empty() {
            // A bad length prefix means we can no longer tell where frames
            // start: end the session; the host reconnects.
            let (used, ready) = framer.push(input).map_err(|_| Disconnected::BadFrame)?;
            input = &input[used..];
            if ready {
                let m = fw.handle(rng, framer.frame(), &mut out[4..]);
                framer.reset();
                publish_mode(fw);
                out[..4].copy_from_slice(&(m as u32).to_le_bytes());
                write_all(tx, &out[..4 + m]).await?;
            }
        }
    }
}

async fn write_all(
    tx: &mut Sender<'static, Driver<'static, USB>>,
    data: &[u8],
) -> Result<(), EndpointError> {
    for chunk in data.chunks(PACKET) {
        tx.write_packet(chunk).await?;
    }
    // A full last packet needs an empty one after it to end the transfer.
    if data.len().is_multiple_of(PACKET) {
        tx.write_packet(&[]).await?;
    }
    Ok(())
}

/// The on-board LED (GPIO 25) shows the mode.
async fn led(pin: Peri<'static, embassy_rp::peripherals::PIN_25>) {
    let mut led = Output::new(pin, LED_OFF);
    loop {
        match MODE.load(Ordering::Relaxed) {
            READY => {
                led.set_level(LED_ON);
                Timer::after_millis(200).await;
            }
            BLANK => {
                led.toggle();
                Timer::after_millis(500).await;
            }
            _ => {
                led.toggle();
                Timer::after_millis(100).await;
            }
        }
    }
}
