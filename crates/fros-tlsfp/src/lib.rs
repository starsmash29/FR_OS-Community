//! TLS client fingerprinting for FR_OS 2's `fr-tls-fp` daemon, held to
//! FR_OS 1.x's `frfw.tlsfp` case for case (tests/reference.rs replays
//! testdata/reference/tlsfp.jsonl).
//!
//! The bytes parsed here come from any host on the LAN: every function
//! is total over its input (no panics, no unbounded loops or buffers),
//! which tests/props.rs checks on random input.

pub mod clienthello;
pub mod fingerprint;
pub mod inventory;
mod ordered;
pub mod pyjson;
pub mod reassembly;

pub use clienthello::{
    ClientHello, MAX_HELLO_BYTES, ParseError, handshake_from_records, is_grease, parse_client_hello,
};
pub use fingerprint::{ja3, ja3_string, ja4, ja4_parts};
pub use inventory::{FingerprintInventory, LEARNING_SECONDS};
pub use reassembly::Reassembler;
