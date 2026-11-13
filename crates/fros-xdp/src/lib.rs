//! The XDP SNI filter's userland. The kernel program is
//! `crates/fros-xdp-ebpf` (aya, built for the BPF target with nightly
//! Rust and bpf-linker); `tests/reference.rs` loads it and has the kernel
//! run it on every frame FR_OS 1.x's C program was run on
//! (`testdata/reference/xdp.jsonl`), as root.
//!
//! This crate also holds what runs the program on a router:
//!
//! - `pins`: loading the object and pinning its programs and maps where
//!   1.x's `bpftool prog loadall ... pinmaps` put them, the pinned
//!   program's id, the blocklist, the settings switches and the
//!   counters. The `fr-xdp` binary is these as commands, run by the Go
//!   apply-helper (as root, with fixed argv); attaching to a device stays
//!   `ip link set dev X xdpdrv|xdpgeneric pinned P`, as in 1.x.
//! - `events`: the event and hello-copy records decoded, the event
//!   logger's JSON line and its file, for the daemons that read the ring
//!   buffers.
//!
//! The blocklist keys are built by the Go apply (`apply.LPMKey`), which
//! refuses a name before anything changes; `pins::sync_blocklist` takes
//! them as bytes.

pub mod events;
pub mod pins;

/// The kernel object's programs: the filter (attached), and the two it
/// tail-calls through `split_prog` (index 0 and 1).
pub const PROGRAMS: [&str; 3] = ["xdp_sni_filter", "xdp_sni_split", "xdp_sni_filter6"];

/// The `stats` map's counters, by index (1.x's STAT_ order).
pub const STATS: [&str; 10] = [
    "pass_not_tls",
    "pass_truncated",
    "pass_no_sni",
    "pass_no_match",
    "drop_match",
    "drop_reordered",
    "drop_bad_checksum",
    "drop_unfollowed",
    "drop_fragment",
    "drop_ipv6_headers",
];

/// The longest name the program extracts, exclusive (1.x's MAX_SNI_LEN).
pub const MAX_SNI_LEN: usize = 32;

/// `struct lpm_sni_key`: prefixlen (4 bytes, little-endian) and the
/// reversed name (MAX_SNI_LEN + 1 bytes), padded to 8-byte alignment.
pub const LPM_KEY_SIZE: usize = 40;

/// The blocklist map's max_entries.
pub const BLOCKLIST_MAX_ENTRIES: usize = 4096;

/// The data bytes a hello copy carries (1.x's HELLO_SNAP).
pub const HELLO_SNAP: usize = 2048;

/// The `settings` map's switches.
pub const SETTING_REPORT_PASS: u32 = 0x1;
pub const SETTING_REPORT_HELLO: u32 = 0x2;
