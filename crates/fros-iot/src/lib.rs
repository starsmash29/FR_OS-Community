//! IoT device discovery for FR_OS 2's `fr-iot-scan`, held to FR_OS
//! 1.x's `frfw.iot` (phase 14) case for case (tests/reference.rs
//! replays testdata/reference/iot.jsonl).
//!
//! A scan merges what the router already knows about the hosts on its
//! IoT zones (the DHCP leases the apply-helper reads from Kea, the
//! kernel's neighbour table), asks them which mDNS service types they
//! advertise, scores each one with a transparent point system, decides
//! which MACs the kernel's `iot_isolated` set should hold, and writes
//! the inventory the webUI shows.
//!
//! mDNS answers and DHCP hostnames are text any LAN host can shape, so
//! every parser here is total over its input and bounded (tests/props.rs).
//! The library does no I/O of its own beyond reading a named file:
//! the helper calls and the mDNS socket are the daemon's, through
//! [`scan::ScanIo`].

pub mod arp;
pub mod classify;
pub mod csv;
pub mod mdns;
pub mod oui;
pub mod scan;

pub use arp::{ArpEntry, parse_arp_table, read_arp_table};
pub use classify::{Classification, Observation, classify};
pub use mdns::{build_query, parse_services};
pub use oui::{
    VendorDb, is_locally_administered, load_vendor_db, normalize_mac, parse_vendor_db, vendor_for,
};
pub use scan::{ScanIo, ScanResult, View, resync_wanted, run_scan};

/// An exception 1.x does not catch, by its Python name: where 1.x's
/// scan would die, this crate reports which exception it would have
/// been and does nothing more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Crash(pub &'static str);
