//! Writes memory.x (from memory.x.in), with the board's flash size, where the linker finds it.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let flash_kb = if env::var_os("CARGO_FEATURE_XIAO_RP2350").is_some() {
        2048
    } else {
        4096
    };
    let memory = fs::read_to_string("memory.x.in")
        .unwrap()
        .replace("@FLASH_KB@", &flash_kb.to_string());
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    fs::write(out.join("memory.x"), memory).unwrap();
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=memory.x.in");
}
