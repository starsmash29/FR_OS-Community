//! FR_OS's XDP TLS ClientHello SNI filter, the kernel side: FR_OS 1.x's
//! `bpf/xdp_sni_filter.c` in Rust (aya), held to it frame for frame by
//! `crates/fros-xdp/tests/reference.rs` (the kernel runs both programs on
//! the same frames, `testdata/reference/xdp.jsonl`).
//!
//! What it does, as in 1.x. Parse Ethernet (up to two 802.1Q/802.1ad
//! tags, SEC-16), IPv4 or IPv6 (FND-1d), TCP to port 443; find a TLS
//! ClientHello's server_name; look the name up in an LPM trie built from
//! reverse("." + name), so a blocked name blocks its subdomains and only
//! on a label boundary. A match is dropped and reported to the `events`
//! ring buffer; everything else passes. A hello whose name isn't in its
//! first segment is followed in its next in-order segments by a second
//! program, `xdp_sni_split` (SEC-17), which keeps only the extension
//! walk's position per flow: a segment out of order is dropped until it
//! comes in order (SEC-24), one with a bad TCP checksum is dropped before
//! the walk reads it, and the rest of a hello the walk can't follow
//! (too many segments, too slow, a jumbo segment) is dropped (SEC-28).
//! A TCP fragment, IPv6 headers the program won't walk to their end, and
//! IPv4-mapped IPv6 addresses are dropped (H2). What stays out of reach,
//! as in 1.x: a hello spread over several TLS records, and Encrypted
//! Client Hello.
//!
//! The maps are 1.x's, with the same names, types, key and value layouts
//! and stat indices, so the loader and every reader of them stay as they
//! were. How the program reads the packet differs: the fixed headers
//! (Ethernet, tags, IP, TCP) with packet pointers, everything past the
//! TCP header with `bpf_xdp_load_bytes` into per-CPU scratch space, read
//! there at masked offsets. A read past the frame's end fails either way,
//! exactly where 1.x's `p + n > data_end` would, so the answers are the
//! same; the verifier has nothing to lose track of. The two extension
//! walks run as `bpf_loop` callbacks (kernel 5.17), each verified once.
#![no_std]
#![no_main]
// The BPF target has no atomic read-modify-write types; the intrinsic
// compiles to the BPF atomic add, as 1.x's __sync_fetch_and_add.
#![allow(internal_features)]
#![feature(core_intrinsics)]

use core::ffi::c_void;
use core::intrinsics::{AtomicOrdering, atomic_xadd};

use aya_ebpf::bindings::xdp_action::{XDP_DROP, XDP_PASS};
use aya_ebpf::bindings::{BPF_ANY, BPF_RB_AVAIL_DATA};
use aya_ebpf::helpers::generated::{
    bpf_csum_diff, bpf_ktime_get_ns, bpf_loop, bpf_xdp_get_buff_len, bpf_xdp_load_bytes,
};
use aya_ebpf::macros::{map, xdp};
use aya_ebpf::maps::lpm_trie::Key;
use aya_ebpf::maps::{Array, LpmTrie, LruHashMap, PerCpuArray, ProgramArray, RingBuf};
use aya_ebpf::programs::XdpContext;

// --- tunables, as in 1.x ------------------------------------------------------

/// Longest hostname matched against the blocklist; a longer one fails
/// open, and the configuration refuses such an entry by name.
const MAX_SNI_LEN: u32 = 32;
/// Extensions one walk goes through (per segment in the follower).
const MAX_TLS_EXTENSIONS: u32 = 32;

const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 22;
const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;
const TLS_EXT_SERVER_NAME: u32 = 0;
const TLS_SNI_NAME_TYPE_HOST_NAME: u8 = 0;

// stats[] indices: 1.x's, read by the dashboard and the metrics.
const STAT_PASS_NOT_TLS: u32 = 0;
const STAT_PASS_TRUNCATED: u32 = 1;
const STAT_PASS_NO_SNI: u32 = 2;
const STAT_PASS_NO_MATCH: u32 = 3;
const STAT_DROP_MATCH: u32 = 4;
const STAT_DROP_REORDERED: u32 = 5;
const STAT_DROP_BAD_CHECKSUM: u32 = 6;
const STAT_DROP_UNFOLLOWED: u32 = 7;
const STAT_DROP_FRAGMENT: u32 = 8;
const STAT_DROP_IPV6_HEADERS: u32 = 9;
const STAT_MAX: u32 = 10;

const SETTING_REPORT_PASS: u32 = 0x1;
const SETTING_REPORT_HELLO: u32 = 0x2;

/// A pass event is queued only while the ring buffer holds less than
/// this: the upper half stays for drops.
const PASS_EVENT_MAX_BACKLOG: u64 = 128 * 1024;

/// Bytes of a segment copied to `hello_pkts` (phase 19).
const HELLO_SNAP: u32 = 2048;
/// Segments after a hello's first still copied.
const HELLO_MAX_EXTRA_SEGMENTS: u32 = 3;

// SEC-17 / SEC-28: the follower.
const SPLIT_CARRY: u32 = 48;
const SPLIT_WINDOW: u32 = 64;
const SPLIT_SEG_MAX: u32 = 2048;
const SPLIT_MAX_SEGMENTS: u32 = 16;
const SPLIT_TTL_NS: u64 = 30 * 1_000_000_000;

const SPLIT_FIRST: u32 = 1;
const SPLIT_NEXT: u32 = 2;

const PROG_SPLIT: u32 = 0;
const PROG_FILTER6: u32 = 1;

const ETH_HLEN: u32 = 14;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_P_8021Q: u16 = 0x8100;
const ETH_P_8021AD: u16 = 0x88A8;
const MAX_VLAN_TAGS: u32 = 2;
const IPPROTO_TCP: u8 = 6;
const IP4_MF: u16 = 0x2000;
const IP4_OFFSET: u16 = 0x1FFF;

const MAX_IPV6_EXT_HEADERS: u32 = 4;
const NEXTHDR_HOP: u8 = 0;
const NEXTHDR_ROUTING: u8 = 43;
const NEXTHDR_FRAGMENT: u8 = 44;
const NEXTHDR_DEST: u8 = 60;

/// The first segment's bytes past the TCP header are read from a copy
/// this long. The furthest any read of the ClientHello parse can reach is
/// under 9 KiB past the payload's start (9 bytes of headers, at most 34 +
/// 1 + 32 + 2 + 512 + 1 + 16 + 2 before the extensions, which are walked
/// to at most 4095 + 4 + 4095 bytes, then 9 + 31 for a name), so the
/// copy holds every byte the parse can look at, of any frame.
const HELLO_COPY: u32 = 16384;
/// `seg` is SPLIT_SEG_MAX bytes plus room for a window read at its end,
/// rounded up to a power of two for the masks.
const SEG_BUF: u32 = 4096;

// --- maps: 1.x's names, types and layouts ----------------------------------------

/// An LPM key: prefix length in bits, then reverse("." + name). 1.x's
/// struct is 4 + 33 bytes padded to 40; the padding is data here, never
/// compared (the prefix length is at most 32 * 8 + 8 bits).
type LpmKey = Key<[u8; 36]>;

/// A flow: addresses as 16 bytes (IPv6, or IPv4-mapped), ports in network
/// order as in the TCP header.
#[repr(C)]
#[derive(Clone, Copy)]
struct FlowKey {
    saddr: [u8; 16],
    daddr: [u8; 16],
    sport: u16,
    dport: u16,
}

#[repr(C)]
struct SniEvent {
    saddr: [u8; 16],
    daddr: [u8; 16],
    sport: u16,
    dport: u16,
    action: u8,
    pad: u8,
    sni_len: u16,
    sni: [u8; MAX_SNI_LEN as usize],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct HelloFlow {
    segments: u32,
}

#[repr(C)]
struct HelloPkt {
    saddr: [u8; 16],
    daddr: [u8; 16],
    sport: u16,
    dport: u16,
    seq: u32,
    len: u16,
    first: u8,
    pad: u8,
    data: [u8; HELLO_SNAP as usize],
}

/// What the follower keeps per flow (1.x's `struct sni_flow`).
#[repr(C)]
#[derive(Clone, Copy)]
struct SniFlow {
    born: u64,
    next_seq: u32,
    first_seq: u32,
    skip: u32,
    ext_left: u32,
    carry_len: u32,
    segments: u32,
    blocked: u32,
    carry: [u8; SPLIT_CARRY as usize],
}

/// Per-CPU working space: what the filter hands the follower, the flow
/// state being worked on, and the buffers the parse reads. A tail call
/// stays on its CPU.
#[repr(C)]
struct Job {
    mode: u32,
    payload_off: u32,
    payload_len: u32,
    pos: u32,
    ext_total: u32,
    seq: u32,
    found: i32,
    tcp_hlen: u32,
    key: FlowKey,
    st: SniFlow,
    sni: [u8; MAX_SNI_LEN as usize],
    lpm: LpmKey,
    buf: [u8; 128],
    seg: [u8; SEG_BUF as usize],
    tcph: [u8; 64],
    hello: [u8; HELLO_COPY as usize],
}

#[map(name = "sni_blocklist")]
static SNI_BLOCKLIST: LpmTrie<[u8; 36], u8> = LpmTrie::with_max_entries(4096, 0);

#[map(name = "events")]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map(name = "stats")]
static STATS: Array<u64> = Array::with_max_entries(STAT_MAX, 0);

#[map(name = "settings")]
static SETTINGS: Array<u32> = Array::with_max_entries(1, 0);

#[map(name = "hello_flows")]
static HELLO_FLOWS: LruHashMap<FlowKey, HelloFlow> = LruHashMap::with_max_entries(4096, 0);

#[map(name = "hello_pkts")]
static HELLO_PKTS: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

#[map(name = "sni_flows")]
static SNI_FLOWS: LruHashMap<FlowKey, SniFlow> = LruHashMap::with_max_entries(4096, 0);

#[map(name = "split_job")]
static SPLIT_JOB: PerCpuArray<Job> = PerCpuArray::with_max_entries(1, 0);

/// [PROG_SPLIT] = xdp_sni_split, [PROG_FILTER6] = xdp_sni_filter6; the
/// loader fills both.
#[map(name = "split_prog")]
static SPLIT_PROG: ProgramArray = ProgramArray::with_max_entries(2, 0);

// --- small helpers -------------------------------------------------------------

#[inline(always)]
fn bump(idx: u32) {
    if let Some(counter) = STATS.get_ptr_mut(idx) {
        // SAFETY: an array map's value, 8-byte aligned, shared with other
        // CPUs: an atomic add, as 1.x's __sync_fetch_and_add.
        unsafe { atomic_xadd::<u64, u64, { AtomicOrdering::Relaxed }>(counter, 1) };
    }
}

#[inline(always)]
fn setting_flags() -> u32 {
    SETTINGS.get(0).copied().unwrap_or(0)
}

#[inline(always)]
fn job() -> Option<&'static mut Job> {
    // SAFETY: this CPU's slot of a per-CPU map; a program runs to its end
    // (or tail call) on one CPU without preemption by another XDP run.
    SPLIT_JOB.get_ptr_mut(0).map(|p| unsafe { &mut *p })
}

/// `n`, known to be in [1, `max`] (a power of two), in a form the
/// verifier can bound: the mask changes no value in that range. Through
/// black_box, or LLVM proves the mask a no-op and drops it, as clang did
/// without 1.x's opaque().
#[inline(always)]
fn bounded(n: u32, max: u32) -> u32 {
    (core::hint::black_box(n).wrapping_sub(1) & (max - 1)) + 1
}

/// `n` bytes of the frame at `off` into `dst`; false when the frame ends
/// first (where 1.x's `p + n > data_end` is true).
#[inline(always)]
fn load(ctx: &XdpContext, off: u32, dst: *mut u8, n: u32) -> bool {
    // SAFETY: the helper writes at most `n` bytes to `dst`, which every
    // caller sizes; the verifier checks it again.
    unsafe { bpf_xdp_load_bytes(ctx.ctx, off, dst as *mut c_void, n) >= 0 }
}

#[inline(always)]
fn load_array<const N: usize>(ctx: &XdpContext, off: u32) -> Option<[u8; N]> {
    let mut out = [0u8; N];
    if load(ctx, off, out.as_mut_ptr(), N as u32) {
        Some(out)
    } else {
        None
    }
}

/// The frame's length. Not data_end - data: the verifier refuses
/// arithmetic on data_end. The program isn't a frags one, so the frame is
/// one linear buffer and this is that buffer's length.
#[inline(always)]
fn frame_len(ctx: &XdpContext) -> u32 {
    // SAFETY: reads the context only.
    unsafe { bpf_xdp_get_buff_len(ctx.ctx) as u32 }
}

/// A packet pointer to `N` bytes at `off`, if the frame holds them.
#[inline(always)]
fn header<const N: usize>(ctx: &XdpContext, off: usize) -> Option<&[u8; N]> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + off + N > end {
        return None;
    }
    // SAFETY: checked against data_end just above.
    Some(unsafe { &*((start + off) as *const [u8; N]) })
}

#[inline(always)]
fn be16(b: &[u8], i: usize) -> u32 {
    ((b[i] as u32) << 8) | b[i + 1] as u32
}

#[inline(always)]
fn at<const N: usize>(b: &[u8; N], i: u32) -> u8 {
    b[i as usize & (N - 1)]
}

#[inline(always)]
fn is_ipv4_mapped(addr: &[u8; 16]) -> bool {
    addr[..10].iter().all(|&b| b == 0) && addr[10] == 0xFF && addr[11] == 0xFF
}

// --- the name and its key ----------------------------------------------------------

/// The name's normalization and its LPM key, a byte per bpf_loop
/// iteration: unrolled, every byte's condition doubles the paths the
/// verifier walks (BPF has no conditional move), and the program runs
/// out of its budget. Each callback is verified once.
#[repr(C)]
struct NameLoop {
    found_len: u32,
    n: u32,
}

/// Pass 1: the length after trimming trailing dots (1.x's
/// normalize_name(), H1/B3): one past the last byte that isn't a dot.
extern "C" fn name_len_one(index: u32, ctx: *mut c_void) -> i64 {
    // SAFETY: bpf_loop passes back the caller's &mut NameLoop.
    let nl = unsafe { &mut *(ctx as *mut NameLoop) };
    let Some(job) = job() else {
        return 1;
    };
    let j = index & (MAX_SNI_LEN - 1);
    if j < nl.found_len && job.sni[j as usize] != b'.' {
        nl.n = j + 1;
    }
    0
}

/// Pass 2: A-Z folded (only: never `| 0x20`, which would turn '_' into
/// DEL), the rest zeroed, and the key: reverse("." + name), so a prefix
/// match on it is a suffix match on the name, on a label boundary.
/// Reads index n - 1 - j (< n, folded or not: folding twice is folding
/// once) while writing index j.
extern "C" fn name_key_one(index: u32, ctx: *mut c_void) -> i64 {
    // SAFETY: bpf_loop passes back the caller's &mut NameLoop.
    let nl = unsafe { &mut *(ctx as *mut NameLoop) };
    let Some(job) = job() else {
        return 1;
    };
    let j = index & (MAX_SNI_LEN - 1);
    let n = nl.n & (MAX_SNI_LEN - 1);
    let fold = |c: u8| if c.is_ascii_uppercase() { c + 32 } else { c };
    let k = if j < n {
        fold(job.sni[((n - 1 - j) & (MAX_SNI_LEN - 1)) as usize])
    } else if j == n {
        b'.'
    } else {
        0
    };
    job.lpm.data[j as usize] = k;
    let c = if j < n { fold(job.sni[j as usize]) } else { 0 };
    job.sni[j as usize] = c;
    0
}

fn emit_flow_event(key: &FlowKey, sni: &[u8; MAX_SNI_LEN as usize], name_len: u32, action: u8) {
    let Some(mut ev) = EVENTS.reserve::<SniEvent>(0) else {
        return;
    };
    ev.write(SniEvent {
        saddr: key.saddr,
        daddr: key.daddr,
        sport: u16::from_be(key.sport),
        dport: u16::from_be(key.dport),
        action,
        pad: 0,
        sni_len: name_len as u16,
        sni: *sni,
    });
    ev.submit(0);
}

/// A pass or drop of the name in job.sni (its first `found_len` bytes;
/// the rest are anything), with 1.x's stats and events. Returns whether
/// it matched; `None` when it normalized to nothing.
#[inline(always)]
fn decide(job: &mut Job, key: &FlowKey, found_len: u32) -> Option<bool> {
    let mut nl = NameLoop { found_len, n: 0 };
    let ctx = &mut nl as *mut NameLoop as *mut c_void;
    // SAFETY: the callback gets &mut nl back and nothing else.
    unsafe { bpf_loop(MAX_SNI_LEN, name_len_one as *mut c_void, ctx, 0) };
    let n = nl.n;
    if !(1..MAX_SNI_LEN).contains(&n) {
        return None;
    }
    // The key's bytes past the name's dot, and its padding, are zero.
    job.lpm.data = [0; 36];
    // SAFETY: as above.
    unsafe { bpf_loop(MAX_SNI_LEN, name_key_one as *mut c_void, ctx, 0) };
    let name_len = n & (MAX_SNI_LEN - 1);
    job.lpm.prefix_len = (name_len + 1) * 8;
    if SNI_BLOCKLIST.get(&job.lpm).is_none() {
        bump(STAT_PASS_NO_MATCH);
        if setting_flags() & SETTING_REPORT_PASS != 0
            && EVENTS.query(BPF_RB_AVAIL_DATA as u64) < PASS_EVENT_MAX_BACKLOG
        {
            emit_flow_event(key, &job.sni, name_len, 0);
        }
        return Some(false);
    }
    bump(STAT_DROP_MATCH);
    emit_flow_event(key, &job.sni, name_len, 1);
    Some(true)
}

// --- phase 19: hello copies --------------------------------------------------------

#[inline(always)]
fn emit_hello_segment(
    ctx: &XdpContext,
    key: &FlowKey,
    seq: u32,
    offset: u32,
    payload_len: u32,
    first: u8,
) {
    if payload_len < 1 {
        return;
    }
    let n = if payload_len > HELLO_SNAP {
        HELLO_SNAP
    } else {
        payload_len
    };
    let n = bounded(n, HELLO_SNAP);
    let Some(mut pkt) = HELLO_PKTS.reserve::<HelloPkt>(0) else {
        return;
    };
    let p = pkt.as_mut_ptr();
    // SAFETY: a reserved ring buffer record of HelloPkt's size; the
    // header fields are written, `data` gets `n` <= HELLO_SNAP bytes.
    let ok = unsafe {
        (*p).saddr = key.saddr;
        (*p).daddr = key.daddr;
        (*p).sport = u16::from_be(key.sport);
        (*p).dport = u16::from_be(key.dport);
        (*p).seq = seq;
        (*p).first = first;
        (*p).pad = 0;
        (*p).len = n as u16;
        load(ctx, offset, (*p).data.as_mut_ptr(), n)
    };
    if ok {
        pkt.submit(0);
    } else {
        pkt.discard(0);
    }
}

// --- the first segment's extension walk --------------------------------------------

/// The walk over a ClientHello's extensions in its first segment (1.x's
/// extract_sni() loop), as a bpf_loop callback over job.hello. Offsets
/// are from the ClientHello body (the payload's ninth byte); `end` is the
/// frame's bytes from there, `room` the datagram's from the extensions.
#[repr(C)]
struct ExtWalk {
    ext_off: u32,
    ext_total: u32,
    end: u32,
    room: u32,
    consumed: u32,
    found: u32,
    found_len: u32,
    found_off: u32,
}

/// The body byte `i` of the copied hello.
#[inline(always)]
fn body(job: &Job, i: u32) -> u8 {
    at(&job.hello, 9 + i)
}

extern "C" fn ext_walk_one(_index: u32, ctx: *mut c_void) -> i64 {
    // SAFETY: bpf_loop passes back the caller's &mut ExtWalk.
    let w = unsafe { &mut *(ctx as *mut ExtWalk) };
    let Some(job) = job() else {
        return 1;
    };
    let p = w.ext_off + (w.consumed & 16383);
    // The header must lie inside the datagram and inside the frame.
    if w.consumed + 4 > w.room || p + 4 > w.end {
        return 1;
    }
    let ext_type = ((body(job, p) as u32) << 8) | body(job, p + 1) as u32;
    let ext_len = ((body(job, p + 2) as u32) << 8) | body(job, p + 3) as u32;
    if ext_len > 4095 || w.consumed >= w.ext_total {
        return 1;
    }
    if ext_type == TLS_EXT_SERVER_NAME {
        // list length(2), name type(1), name length(2), all in the frame;
        // then the whole name inside the datagram.
        let q = p + 4;
        if q + 3 <= w.end && body(job, q + 2) == TLS_SNI_NAME_TYPE_HOST_NAME && q + 5 <= w.end {
            let nl = ((body(job, q + 3) as u32) << 8) | body(job, q + 4) as u32;
            if nl != 0 && nl < MAX_SNI_LEN && w.consumed + 9 + nl <= w.room {
                w.found = 1;
                w.found_len = nl;
                w.found_off = w.consumed + 9;
            }
        }
        return 1;
    }
    w.consumed = (w.consumed + 4 + ext_len) & 16383;
    0
}

/// Where the name is: its offset from the ClientHello body and its
/// length (1). With no name (-2, or -1 for a malformed or truncated
/// hello), `off` and `len` are the extensions block's start and declared
/// length, 0 when the walk didn't get that far (1.x's sni_ref).
struct SniRef {
    found: i32,
    off: u32,
    len: u32,
}

/// 1.x's extract_sni() over job.hello: `end` is the frame's bytes from the
/// body's start, `limit` the datagram's.
#[inline(always)]
fn extract_sni(job: &Job, end: u32, limit: u32) -> SniRef {
    let bad = SniRef {
        found: -1,
        off: 0,
        len: 0,
    };
    // client_version(2) + random(32)
    if 34 > end || 34 > limit {
        return bad;
    }
    let mut off = 34u32;
    // session_id
    if off + 1 > end || off + 1 > limit {
        return bad;
    }
    let sid = body(job, off) as u32;
    off += 1;
    if sid > 32 || off + sid > end || off + sid > limit {
        return bad;
    }
    off += sid;
    // cipher_suites
    if off + 2 > end || off + 2 > limit {
        return bad;
    }
    let cs = ((body(job, off) as u32) << 8) | body(job, off + 1) as u32;
    off += 2;
    if cs > 512 || off + cs > end || off + cs > limit {
        return bad;
    }
    off += cs;
    // compression_methods
    if off + 1 > end || off + 1 > limit {
        return bad;
    }
    let comp = body(job, off) as u32;
    off += 1;
    if comp > 16 || off + comp > end || off + comp > limit {
        return bad;
    }
    off += comp;
    // extensions: none at all is "no server_name", not truncation.
    if off + 2 > end || off + 2 > limit {
        return SniRef {
            found: -2,
            off: 0,
            len: 0,
        };
    }
    let ext_total = ((body(job, off) as u32) << 8) | body(job, off + 1) as u32;
    off += 2;
    let mut walk = ExtWalk {
        ext_off: off,
        ext_total: if ext_total > 4095 { 4095 } else { ext_total },
        end,
        room: limit - off,
        consumed: 0,
        found: 0,
        found_len: 0,
        found_off: 0,
    };
    // SAFETY: the callback gets &mut walk back and nothing else.
    unsafe {
        bpf_loop(
            MAX_TLS_EXTENSIONS,
            ext_walk_one as *mut c_void,
            &mut walk as *mut ExtWalk as *mut c_void,
            0,
        )
    };
    if walk.found != 0 {
        SniRef {
            found: 1,
            off: off + walk.found_off,
            len: walk.found_len,
        }
    } else {
        SniRef {
            found: -2,
            off,
            len: ext_total,
        }
    }
}

// --- SEC-17: handing a segment to the follower --------------------------------------

#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn prepare_job(
    mode: u32,
    key: &FlowKey,
    payload_off: u32,
    payload_len: u32,
    seq: u32,
    pos: u32,
    ext_total: u32,
    found: i32,
    tcp_hlen: u32,
) -> bool {
    let Some(job) = job() else {
        return false;
    };
    job.mode = mode;
    job.payload_off = payload_off;
    job.payload_len = payload_len;
    job.pos = pos;
    job.ext_total = ext_total;
    job.seq = seq;
    job.found = found;
    job.tcp_hlen = tcp_hlen;
    job.key = *key;
    true
}

#[inline(always)]
fn tail_call(ctx: &XdpContext, index: u32) {
    // SAFETY: returns only when the call fails; then the caller goes on.
    unsafe { SPLIT_PROG.tail_call(ctx, index) };
}

enum Follow {
    Not,
    HandOver,
    Verdict(u32),
}

/// What becomes of a segment of a flow the follower may be following
/// (1.x's follow_flow()).
#[inline(always)]
fn follow_flow(key: &FlowKey, tcp: &[u8; 20], payload_off: u32, payload_len: u32) -> Follow {
    let flags = tcp[13];
    if flags & 0x06 != 0 {
        // SYN or RST: a new connection on these addresses and ports, or
        // the end of this one.
        let _ = SNI_FLOWS.remove(key);
        return Follow::Not;
    }
    if payload_len == 0 {
        return Follow::Not;
    }
    let Some(split) = SNI_FLOWS.get_ptr_mut(key) else {
        return Follow::Not;
    };
    // SAFETY: a value of this map, valid until the program ends.
    let split = unsafe { &mut *split };
    if split.blocked != 0 {
        return Follow::Verdict(XDP_DROP);
    }
    // SAFETY: no arguments.
    if unsafe { bpf_ktime_get_ns() }.wrapping_sub(split.born) > SPLIT_TTL_NS {
        // SEC-28: a hello not finished in time is dropped from here on.
        split.blocked = 1;
        bump(STAT_DROP_UNFOLLOWED);
        return Follow::Verdict(XDP_DROP);
    }
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    if seq != split.next_seq {
        if seq == split.first_seq {
            return Follow::Not;
        }
        // SEC-24: anything past the bytes the walk has read waits until it
        // comes in order (modulo 2^32).
        if (seq.wrapping_add(payload_len).wrapping_sub(split.next_seq) as i32) > 0 {
            bump(STAT_DROP_REORDERED);
            return Follow::Verdict(XDP_DROP);
        }
        return Follow::Not;
    }
    let doff = (tcp[12] >> 4) as u32;
    if !prepare_job(
        SPLIT_NEXT,
        key,
        payload_off,
        payload_len,
        seq,
        0,
        0,
        0,
        doff * 4,
    ) {
        return Follow::Verdict(XDP_PASS);
    }
    Follow::HandOver
}

// --- the TCP and TLS part, for both families ----------------------------------------

/// 1.x's filter_tcp(): the TCP header at packet offset `l4_off`, with
/// `l4_len` bytes of the datagram from it on (SEC-7: never padding).
#[inline(always)]
fn filter_tcp(ctx: &XdpContext, l4_off: u32, l4_len: u32, key: &mut FlowKey) -> u32 {
    let Some(tcp) = header::<20>(ctx, l4_off as usize) else {
        return XDP_PASS;
    };
    let tcp = *tcp;
    if tcp[2] != 0x01 || tcp[3] != 0xBB {
        return XDP_PASS; // not port 443
    }
    let doff = (tcp[12] >> 4) as u32;
    if doff < 5 {
        return XDP_PASS;
    }
    let tcp_len = doff * 4;
    let payload_off = l4_off + tcp_len;
    let frame_len = frame_len(ctx);
    if payload_off > frame_len {
        return XDP_PASS;
    }
    let frame_avail = frame_len - payload_off;
    let payload_len = l4_len.saturating_sub(tcp_len);
    let report_hello = setting_flags() & SETTING_REPORT_HELLO != 0;
    key.sport = u16::from_ne_bytes([tcp[0], tcp[1]]);
    key.dport = u16::from_ne_bytes([tcp[2], tcp[3]]);
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);

    // Phase 19: the rest of a ClientHello that didn't fit its first segment.
    if report_hello
        && payload_len > 0
        && frame_avail >= 1
        && let Some([b0]) = load_array::<1>(ctx, payload_off)
        && b0 != TLS_CONTENT_TYPE_HANDSHAKE
        && let Some(flow) = HELLO_FLOWS.get_ptr_mut(key)
    {
        emit_hello_segment(ctx, key, seq, payload_off, payload_len, 0);
        // SAFETY: a value of this map, valid until the program ends.
        let flow = unsafe { &mut *flow };
        flow.segments += 1;
        if flow.segments >= HELLO_MAX_EXTRA_SEGMENTS {
            let _ = HELLO_FLOWS.remove(key);
        }
    }

    // SEC-17: the next segment of a hello being followed.
    match follow_flow(key, &tcp, payload_off, payload_len) {
        Follow::HandOver => {
            tail_call(ctx, PROG_SPLIT);
            return XDP_PASS; // the tail call failed: as without following
        }
        Follow::Verdict(v) => return v,
        Follow::Not => {}
    }

    // A TLS record header, then a handshake header; each checked against
    // the frame, then the datagram (SEC-7).
    let Some(rec) = load_array::<5>(ctx, payload_off) else {
        bump(STAT_PASS_NOT_TLS);
        return XDP_PASS;
    };
    if payload_len < 5 || rec[0] != TLS_CONTENT_TYPE_HANDSHAKE {
        bump(STAT_PASS_NOT_TLS);
        return XDP_PASS;
    }
    let hs = match load_array::<4>(ctx, payload_off + 5) {
        Some(hs) if payload_len >= 9 => hs,
        _ => {
            bump(STAT_PASS_TRUNCATED);
            return XDP_PASS;
        }
    };
    if hs[0] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO {
        bump(STAT_PASS_NOT_TLS);
        return XDP_PASS;
    }

    let rec_len = be16(&rec, 3);
    if report_hello {
        emit_hello_segment(ctx, key, seq, payload_off, payload_len, 1);
        if rec_len + 5 > payload_len {
            let _ = HELLO_FLOWS.insert(key, &HelloFlow { segments: 0 }, BPF_ANY as u64);
        }
    }
    // SEC-17: does the hello go on past this segment, in this one record?
    let hs_len = ((hs[1] as u32) << 16) | ((hs[2] as u32) << 8) | hs[3] as u32;
    let goes_on = rec_len + 5 > payload_len && hs_len + 4 <= rec_len;

    let Some(job) = job() else {
        bump(STAT_PASS_NO_MATCH);
        return XDP_PASS;
    };
    // The frame's bytes from the payload on, as far as the parse can read.
    let n = if frame_avail > HELLO_COPY {
        HELLO_COPY
    } else {
        frame_avail
    };
    let n = bounded(n, HELLO_COPY);
    if !load(ctx, payload_off, job.hello.as_mut_ptr(), n) {
        bump(STAT_PASS_TRUNCATED);
        return XDP_PASS;
    }
    let r = extract_sni(job, frame_avail - 9, payload_len - 9);

    if r.found != 1
        && r.off != 0
        && goes_on
        && prepare_job(
            SPLIT_FIRST,
            key,
            payload_off,
            payload_len,
            seq,
            9 + r.off,
            r.len,
            r.found,
            0,
        )
    {
        tail_call(ctx, PROG_SPLIT);
    }
    if r.found == -1 {
        bump(STAT_PASS_TRUNCATED);
        return XDP_PASS;
    }
    if r.found != 1 {
        bump(STAT_PASS_NO_SNI);
        return XDP_PASS;
    }

    // The name's exact bytes (SEC-20): a frame ending inside it is a
    // truncated hello, never a shorter name.
    let found_len = bounded(r.len, MAX_SNI_LEN);
    if 9 + r.off + found_len > frame_avail {
        bump(STAT_PASS_TRUNCATED);
        return XDP_PASS;
    }
    // All MAX_SNI_LEN bytes, unconditionally: decide() reads found_len.
    for i in 0..MAX_SNI_LEN {
        job.sni[i as usize] = body(job, r.off + i);
    }
    match decide(job, key, found_len) {
        None => {
            bump(STAT_PASS_NO_SNI);
            XDP_PASS
        }
        Some(true) => XDP_DROP,
        Some(false) => XDP_PASS,
    }
}

/// The Ethernet header and up to MAX_VLAN_TAGS tags: the EtherType they
/// lead to and its header's offset; 0 for a frame too short.
#[inline(always)]
fn l3_proto(ctx: &XdpContext) -> (u16, u32) {
    let Some(eth) = header::<14>(ctx, 0) else {
        return (0, 0);
    };
    let mut proto = u16::from_be_bytes([eth[12], eth[13]]);
    let mut off = ETH_HLEN;
    for _ in 0..MAX_VLAN_TAGS {
        if proto != ETH_P_8021Q && proto != ETH_P_8021AD {
            break;
        }
        let Some(tag) = header::<4>(ctx, off as usize) else {
            return (0, off);
        };
        proto = u16::from_be_bytes([tag[2], tag[3]]);
        off += 4;
    }
    (proto, off)
}

#[xdp]
pub fn xdp_sni_filter(ctx: XdpContext) -> u32 {
    let (proto, l3_off) = l3_proto(&ctx);
    if proto == ETH_P_IPV6 {
        // FND-1d: IPv6 goes to xdp_sni_filter6; if that fails, dropped, so
        // IPv6 never gets past the filter of a zone that has it.
        tail_call(&ctx, PROG_FILTER6);
        return XDP_DROP;
    }
    if proto != ETH_P_IP {
        return XDP_PASS;
    }
    let l3_off = l3_off & 31;
    let Some(ip) = header::<20>(&ctx, l3_off as usize) else {
        return XDP_PASS;
    };
    let ip = *ip;
    if ip[9] != IPPROTO_TCP {
        return XDP_PASS;
    }
    // H2: a TCP fragment, first or later, is dropped.
    if u16::from_be_bytes([ip[6], ip[7]]) & (IP4_MF | IP4_OFFSET) != 0 {
        bump(STAT_DROP_FRAGMENT);
        return XDP_DROP;
    }
    let ihl = (ip[0] & 0x0F) as u32;
    if ihl < 5 {
        return XDP_PASS;
    }
    let ip_hlen = ihl * 4;
    if l3_off + ip_hlen > frame_len(&ctx) {
        return XDP_PASS;
    }
    let ip_len = u16::from_be_bytes([ip[2], ip[3]]) as u32;
    let mut key = FlowKey {
        saddr: mapped([ip[12], ip[13], ip[14], ip[15]]),
        daddr: mapped([ip[16], ip[17], ip[18], ip[19]]),
        sport: 0,
        dport: 0,
    };
    let l4_len = ip_len.saturating_sub(ip_hlen);
    filter_tcp(&ctx, l3_off + ip_hlen, l4_len, &mut key)
}

#[inline(always)]
fn mapped(a: [u8; 4]) -> [u8; 16] {
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, a[0], a[1], a[2], a[3],
    ]
}

// --- FND-1d: IPv6 --------------------------------------------------------------------

#[inline(always)]
fn is_walked(nh: u8) -> bool {
    nh == NEXTHDR_HOP || nh == NEXTHDR_ROUTING || nh == NEXTHDR_DEST
}

enum L4 {
    Tcp(u32),
    NotTcp,
    Fragment,
    TooDeep,
    Unreadable,
}

/// The extension header chain from packet offset `off`, `nh` the fixed
/// header's next header (1.x's ipv6_tcp_offset()).
#[inline(always)]
fn ipv6_tcp_offset(ctx: &XdpContext, mut off: u32, mut nh: u8) -> L4 {
    for _ in 0..MAX_IPV6_EXT_HEADERS {
        if nh == IPPROTO_TCP {
            return L4::Tcp(off);
        }
        if nh == NEXTHDR_FRAGMENT {
            let Some([next]) = load_array::<1>(ctx, off) else {
                return L4::Unreadable;
            };
            return if next == IPPROTO_TCP || is_walked(next) || next == NEXTHDR_FRAGMENT {
                L4::Fragment
            } else {
                L4::NotTcp
            };
        }
        if !is_walked(nh) {
            return L4::NotTcp;
        }
        let Some(h) = load_array::<2>(ctx, off) else {
            return L4::Unreadable;
        };
        nh = h[0];
        off += (h[1] as u32 + 1) * 8;
    }
    if nh == IPPROTO_TCP {
        L4::Tcp(off)
    } else if is_walked(nh) || nh == NEXTHDR_FRAGMENT {
        L4::TooDeep
    } else {
        L4::NotTcp
    }
}

#[xdp]
pub fn xdp_sni_filter6(ctx: XdpContext) -> u32 {
    let (proto, l3_off) = l3_proto(&ctx);
    if proto != ETH_P_IPV6 {
        return XDP_PASS;
    }
    let l3_off = l3_off & 31;
    let Some(ip6) = header::<40>(&ctx, l3_off as usize) else {
        return XDP_PASS;
    };
    let ip6 = *ip6;
    let mut key = FlowKey {
        saddr: [0; 16],
        daddr: [0; 16],
        sport: 0,
        dport: 0,
    };
    key.saddr.copy_from_slice(&ip6[8..24]);
    key.daddr.copy_from_slice(&ip6[24..40]);
    // Never valid on the wire; and the flow keys tell IPv4 by that prefix.
    if is_ipv4_mapped(&key.saddr) || is_ipv4_mapped(&key.daddr) {
        bump(STAT_DROP_IPV6_HEADERS);
        return XDP_DROP;
    }
    let dgram_end = l3_off + 40 + u16::from_be_bytes([ip6[4], ip6[5]]) as u32;
    let l4 = match ipv6_tcp_offset(&ctx, l3_off + 40, ip6[6]) {
        L4::Tcp(off) => off,
        L4::Fragment => {
            bump(STAT_DROP_FRAGMENT);
            return XDP_DROP;
        }
        L4::TooDeep => {
            bump(STAT_DROP_IPV6_HEADERS);
            return XDP_DROP;
        }
        L4::NotTcp | L4::Unreadable => return XDP_PASS,
    };
    let l4_off = l4 & 16383;
    if l4_off >= dgram_end {
        return XDP_PASS;
    }
    filter_tcp(&ctx, l4_off, dgram_end - l4_off, &mut key)
}

// --- SEC-17: the follower --------------------------------------------------------------

const WALK_CONTINUE: u32 = 0;
const WALK_FOUND: u32 = 1;
const WALK_NONE: u32 = 2;

#[repr(C)]
struct WalkLoop {
    pos: u32,
    seg_len: u32,
    name_len: u32,
    result: u32,
}

/// One extension of a followed hello's walk (1.x's walk_one()): reads
/// job.seg and the flow state job.st; an extension's start, a carried
/// prefix plus up to SPLIT_WINDOW bytes of the segment, is assembled in
/// job.buf. Returns 0 to go on, 1 when `result` is set.
extern "C" fn walk_one(_index: u32, ctx: *mut c_void) -> i64 {
    // SAFETY: bpf_loop passes back the caller's &mut WalkLoop.
    let wl = unsafe { &mut *(ctx as *mut WalkLoop) };
    let Some(job) = job() else {
        wl.result = WALK_NONE;
        return 1;
    };
    let carry = job.st.carry_len;
    if job.st.ext_left < 4 || carry > SPLIT_CARRY {
        wl.result = WALK_NONE;
        return 1;
    }
    let pos = wl.pos;
    let avail = wl.seg_len.saturating_sub(pos);
    if carry == 0 && avail == 0 {
        wl.result = WALK_CONTINUE;
        return 1;
    }
    // Whole windows, not `carry` or `avail` bytes; only the first `have`
    // bytes of buf are read.
    let carried = job.st.carry;
    job.buf[..SPLIT_CARRY as usize].copy_from_slice(&carried);
    let from = (pos & (SPLIT_SEG_MAX - 1)) as usize;
    let to = (carry & 63) as usize;
    for i in 0..SPLIT_WINDOW as usize {
        job.buf[(to + i) & 127] = job.seg[(from + i) & (SEG_BUF as usize - 1)];
    }
    let have = carry
        + if avail > SPLIT_WINDOW {
            SPLIT_WINDOW
        } else {
            avail
        };

    let mut need = 4;
    let mut total = 0;
    let mut is_sni = false;
    let mut nl = 0;
    if have >= 4 {
        let ext_type = be16(&job.buf, 0);
        total = 4 + be16(&job.buf, 2);
        if total > job.st.ext_left {
            wl.result = WALK_NONE;
            return 1;
        }
        is_sni = ext_type == TLS_EXT_SERVER_NAME;
        if is_sni {
            need = 9;
            if have >= 9 {
                nl = be16(&job.buf, 7);
                if job.buf[6] != TLS_SNI_NAME_TYPE_HOST_NAME
                    || nl == 0
                    || nl >= MAX_SNI_LEN
                    || 9 + nl > total
                {
                    wl.result = WALK_NONE;
                    return 1;
                }
                need = 9 + nl;
            }
        }
    }
    if have < need {
        // The segment ends inside the extension's start: carry it over.
        if have > SPLIT_CARRY {
            wl.result = WALK_NONE;
            return 1;
        }
        let mut c = [0u8; SPLIT_CARRY as usize];
        c.copy_from_slice(&job.buf[..SPLIT_CARRY as usize]);
        job.st.carry = c;
        job.st.carry_len = have;
        wl.result = WALK_CONTINUE;
        return 1;
    }
    if is_sni {
        wl.name_len = nl;
        wl.result = WALK_FOUND;
        return 1;
    }
    // Any other extension is skipped.
    job.st.ext_left -= total;
    job.st.carry_len = 0;
    let in_seg = total - carry;
    if in_seg > avail {
        job.st.skip = in_seg - avail;
        wl.result = WALK_CONTINUE;
        return 1;
    }
    wl.pos = pos + in_seg;
    0
}

/// SEC-28: whether the TCP checksum of the segment in job.seg (seg_len
/// bytes) is right, over the pseudo-header, the TCP header read from the
/// packet and the payload padded with zeros to a multiple of 4.
#[inline(always)]
fn tcp_checksum_ok(ctx: &XdpContext, job: &mut Job, seg_len: u32) -> bool {
    let hlen = job.tcp_hlen;
    if !(20..=60).contains(&hlen)
        || hlen & 3 != 0
        || seg_len > SPLIT_SEG_MAX
        || job.payload_off < hlen
    {
        return false;
    }
    // The mask changes no value in [20, 60]; it bounds the size for the
    // verifier, which doesn't keep the range check above.
    let hlen = bounded(hlen, 64);
    if !load(ctx, job.payload_off - hlen, job.tcph.as_mut_ptr(), hlen) {
        return false;
    }
    let tcp_len = hlen + seg_len;
    let k = &job.key;
    // SAFETY: bpf_csum_diff reads `to_size` bytes of each buffer passed,
    // all sized here; `from` is empty.
    let mut sum = unsafe {
        if is_ipv4_mapped(&k.saddr) {
            let mut pseudo: [u32; 3] = [
                u32::from_ne_bytes([k.saddr[12], k.saddr[13], k.saddr[14], k.saddr[15]]),
                u32::from_ne_bytes([k.daddr[12], k.daddr[13], k.daddr[14], k.daddr[15]]),
                ((IPPROTO_TCP as u32) << 16 | tcp_len).to_be(),
            ];
            bpf_csum_diff(core::ptr::null_mut(), 0, pseudo.as_mut_ptr(), 12, 0)
        } else {
            // RFC 8200 8.1: addresses, upper-layer length, zeros, next header.
            let mut pseudo = [0u32; 10];
            for i in 0..4 {
                let j = i * 4;
                pseudo[i] = u32::from_ne_bytes([
                    k.saddr[j],
                    k.saddr[j + 1],
                    k.saddr[j + 2],
                    k.saddr[j + 3],
                ]);
                pseudo[4 + i] = u32::from_ne_bytes([
                    k.daddr[j],
                    k.daddr[j + 1],
                    k.daddr[j + 2],
                    k.daddr[j + 3],
                ]);
            }
            pseudo[8] = tcp_len.to_be();
            pseudo[9] = (IPPROTO_TCP as u32).to_be();
            bpf_csum_diff(core::ptr::null_mut(), 0, pseudo.as_mut_ptr(), 40, 0)
        }
    };
    if sum < 0 {
        return false;
    }
    // SAFETY: hlen <= 60 bytes of job.tcph.
    sum = unsafe {
        bpf_csum_diff(
            core::ptr::null_mut(),
            0,
            job.tcph.as_mut_ptr() as *mut u32,
            hlen,
            sum as u32,
        )
    };
    if sum < 0 {
        return false;
    }
    let s = (seg_len & (SPLIT_SEG_MAX * 2 - 1)) as usize;
    job.seg[s & (SEG_BUF as usize - 1)] = 0;
    job.seg[(s + 1) & (SEG_BUF as usize - 1)] = 0;
    job.seg[(s + 2) & (SEG_BUF as usize - 1)] = 0;
    let total = (seg_len + 3) & !3;
    let mut off = 0u32;
    while off < SPLIT_SEG_MAX {
        if off >= total {
            break;
        }
        let n = if total - off > 512 { 512 } else { total - off };
        // In [1, 512] already (off < total); the mask says so to the verifier.
        let n = bounded(n, 512);
        // SAFETY: off + n <= SPLIT_SEG_MAX + 4 bytes of job.seg.
        sum = unsafe {
            bpf_csum_diff(
                core::ptr::null_mut(),
                0,
                job.seg
                    .as_mut_ptr()
                    .add((off & (SPLIT_SEG_MAX - 1)) as usize) as *mut u32,
                n,
                sum as u32,
            )
        };
        if sum < 0 {
            return false;
        }
        off += 512;
    }
    let mut c = sum as u32;
    c = (c & 0xFFFF) + (c >> 16);
    c = (c & 0xFFFF) + (c >> 16);
    c == 0xFFFF
}

/// SEC-17: the follower, reached only by the filter's tail call with the
/// segment in split_job: SPLIT_FIRST for a hello's first segment with no
/// name in it, SPLIT_NEXT for a followed flow's next in-order segment.
#[xdp]
pub fn xdp_sni_split(ctx: XdpContext) -> u32 {
    let Some(job) = job() else {
        return XDP_PASS;
    };
    let key = job.key;
    let first = job.mode == SPLIT_FIRST;
    let mut stored: Option<&mut SniFlow> = None;
    if first {
        job.st = SniFlow {
            // SAFETY: no arguments.
            born: unsafe { bpf_ktime_get_ns() },
            next_seq: 0,
            first_seq: job.seq,
            skip: 0,
            ext_left: job.ext_total,
            carry_len: 0,
            segments: 0,
            blocked: 0,
            carry: [0; SPLIT_CARRY as usize],
        };
    } else {
        let Some(s) = SNI_FLOWS.get_ptr_mut(&key) else {
            return XDP_PASS;
        };
        // SAFETY: a value of this map, valid until the program ends.
        let s = unsafe { &mut *s };
        job.st = *s;
        job.st.segments += 1;
        stored = Some(s);
    }

    let seg_len = job.payload_len;
    let mut wl = WalkLoop {
        pos: 0,
        seg_len: 0,
        name_len: 0,
        result: WALK_NONE,
    };
    let walk = 'walk: {
        if !first {
            // SEC-28: a hello longer than the walk follows, or a segment
            // larger than it reads, is dropped from here on.
            if job.st.segments > SPLIT_MAX_SEGMENTS || seg_len > SPLIT_SEG_MAX {
                return give_up(stored);
            }
            if seg_len > 0 {
                let n = bounded(seg_len, SPLIT_SEG_MAX);
                if !load(&ctx, job.payload_off, job.seg.as_mut_ptr(), n) {
                    return give_up(stored);
                }
            }
            if !tcp_checksum_ok(&ctx, job, seg_len) {
                // What the server throws away the walk doesn't read.
                bump(STAT_DROP_BAD_CHECKSUM);
                return XDP_DROP;
            }
            let mut pos = 0;
            if job.st.skip != 0 {
                if job.st.skip >= seg_len {
                    job.st.skip -= seg_len;
                    break 'walk WALK_CONTINUE;
                }
                pos = job.st.skip;
                job.st.skip = 0;
            }
            wl.pos = pos;
            wl.seg_len = seg_len;
        } else {
            // The first segment, from where the filter's walk stopped.
            let pos = job.pos;
            let rest = seg_len.saturating_sub(pos);
            if rest > SPLIT_SEG_MAX {
                return give_up(stored);
            }
            if rest > 0 {
                let n = bounded(rest, SPLIT_SEG_MAX);
                if !load(&ctx, job.payload_off + pos, job.seg.as_mut_ptr(), n) {
                    return give_up(stored);
                }
            }
            wl.seg_len = rest;
        }
        // SAFETY: the callback gets &mut wl back and nothing else.
        unsafe {
            bpf_loop(
                MAX_TLS_EXTENSIONS,
                walk_one as *mut c_void,
                &mut wl as *mut WalkLoop as *mut c_void,
                0,
            )
        };
        wl.result
    };

    if walk == WALK_CONTINUE {
        job.st.next_seq = job.seq.wrapping_add(job.payload_len);
        if first {
            let _ = SNI_FLOWS.insert(&key, &job.st, BPF_ANY as u64);
            bump(STAT_PASS_TRUNCATED); // as before: no name in this packet
        } else if let Some(s) = stored {
            *s = job.st;
        }
        return XDP_PASS;
    }
    if walk != WALK_FOUND {
        if !first {
            let _ = SNI_FLOWS.remove(&key);
        }
        bump(if first && job.found == -1 {
            STAT_PASS_TRUNCATED
        } else {
            STAT_PASS_NO_SNI
        });
        return XDP_PASS;
    }

    let mut sni = [0u8; MAX_SNI_LEN as usize];
    sni.copy_from_slice(&job.buf[9..9 + MAX_SNI_LEN as usize]);
    job.sni = sni;
    let found_len = bounded(wl.name_len, MAX_SNI_LEN);
    match decide(job, &key, found_len) {
        None => {
            if !first {
                let _ = SNI_FLOWS.remove(&key);
            }
            bump(STAT_PASS_NO_SNI);
            XDP_PASS
        }
        Some(false) => {
            if !first {
                let _ = SNI_FLOWS.remove(&key);
            }
            XDP_PASS
        }
        Some(true) => {
            if let Some(s) = stored {
                s.blocked = 1; // and drop the rest of this hello
            }
            XDP_DROP
        }
    }
}

/// SEC-28: the walk can't follow this hello further, and a client chooses
/// all of what makes it so: its rest is dropped, retransmissions included.
#[inline(always)]
fn give_up(stored: Option<&mut SniFlow>) -> u32 {
    if let Some(s) = stored {
        s.blocked = 1;
    }
    bump(STAT_DROP_UNFOLLOWED);
    XDP_DROP
}

// The kernel takes GPL-only helpers (bpf_loop among them) only from a
// program that declares a GPL-compatible licence; FR_OS is AGPLv3, which
// the kernel's list doesn't name, and 1.x's C program declares "GPL" too.
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 4] = *b"GPL\0";

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
