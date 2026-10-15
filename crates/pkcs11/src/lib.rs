//! `quorum-pkcs11`: a PKCS#11 library for the quorum HSM.
//!
//! Load `libquorum_pkcs11.so` into any PKCS#11 application (pkcs11-tool,
//! OpenSSL's pkcs11 provider, ssh-agent...). It forwards requests to the HSM
//! over a Unix socket; set `QUORUM_HSM_SOCKET` to choose which one.

mod api;
mod client;
mod function_list;
mod objects;

pub use api::C_GetFunctionList;
