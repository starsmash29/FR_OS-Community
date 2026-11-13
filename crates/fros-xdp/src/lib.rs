//! The XDP SNI filter's userland. The kernel program is
//! `crates/fros-xdp-ebpf` (aya, built for the BPF target with nightly
//! Rust and bpf-linker); `tests/reference.rs` loads it and has the kernel
//! run it on every frame FR_OS 1.x's C program was run on
//! (`testdata/reference/xdp.jsonl`), as root. The loader that pins and
//! attaches it, keeps the blocklist and reads its events comes next
//! (phase 4d-2).

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
