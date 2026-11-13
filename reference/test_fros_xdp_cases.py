"""FR_OS 1.x's XDP SNI filter (bpf/xdp_sni_filter.c, phases 4, 16, 19,
ROADMAP SEC-7/16/17/20/24/28, FND-1d) fed frames of every shape,
recorded for FR_OS 2's crates/fros-xdp-ebpf (xdp.jsonl;
reference/generate-xdp.sh runs this module, as root).

The C program is compiled from the 1.x checkout with 1.x's own
scripts/build-xdp-object.sh, loaded with libbpf, and each frame is run
through the kernel with BPF_PROG_TEST_RUN, in order, against maps set
up per case: the blocklist (keys built by 1.x's frfw.xdp.build_lpm_key),
the settings switches. After each frame the case records the verdict,
which counters moved, the events and ClientHello copies the program
queued, and the flows it is following (split ClientHellos, ROADMAP
SEC-17) and copying (phase 19).

Frames: single-segment ClientHellos with names blocked and not, every
odd field the parser bounds, cut at every byte by the frame or by the
IP length; VLAN tags, IPv4 options and fragments, IPv6 extension
headers and fragments; ClientHellos split over segments at every offset
around the name, out of order, retransmitted, with bad checksums, past
the segment and time limits; and seeded random damage and segmentation.

Needs root, clang and libbpf (libbpf-dev); skipped otherwise, so the
unprivileged reference run (generate.sh) never records it.

Nothing here asserts anything about 1.x.
"""

from __future__ import annotations

import ctypes
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

import frfw
from frfw.xdp import SETTING_REPORT_HELLO, SETTING_REPORT_PASS, build_lpm_key

ROOT_1X = Path(frfw.__file__).resolve().parents[2]
SOURCE = ROOT_1X / "bpf" / "xdp_sni_filter.c"
BUILD = ROOT_1X / "scripts" / "build-xdp-object.sh"


def _libbpf():
    try:
        return ctypes.CDLL("libbpf.so.1", use_errno=True)
    except OSError:
        return None


_MISSING = os.geteuid() != 0 or shutil.which("clang") is None or _libbpf() is None or not SOURCE.exists()
if _MISSING and os.environ.get("FROS_XDP_REQUIRED"):
    # reference/generate-xdp.sh: an empty recording must fail, not skip.
    raise RuntimeError("needs root, clang, libbpf and 1.x's bpf/xdp_sni_filter.c")
pytestmark = pytest.mark.skipif(_MISSING, reason="needs root, clang, libbpf and 1.x's bpf/xdp_sni_filter.c")

BLOCKLIST = ["blocked.example", "ads.example.net", "evil.test", "a.b", "Upper.Example"]
STATS = 10


def _record(case: dict) -> None:
    capture = sys.modules.get("fros_capture")
    if capture is not None:
        capture._record("xdp", case)


# --- libbpf -----------------------------------------------------------------------------------


class _TestRunOpts(ctypes.Structure):
    _fields_ = [("sz", ctypes.c_size_t), ("data_in", ctypes.c_void_p), ("data_out", ctypes.c_void_p),
                ("data_size_in", ctypes.c_uint32), ("data_size_out", ctypes.c_uint32),
                ("ctx_in", ctypes.c_void_p), ("ctx_out", ctypes.c_void_p),
                ("ctx_size_in", ctypes.c_uint32), ("ctx_size_out", ctypes.c_uint32),
                ("retval", ctypes.c_uint32), ("repeat", ctypes.c_int), ("duration", ctypes.c_uint32),
                ("flags", ctypes.c_uint32), ("cpu", ctypes.c_uint32), ("batch_size", ctypes.c_uint32)]


_SAMPLE_FN = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t)


class Program:
    """1.x's object, loaded once; maps reset per case."""

    def __init__(self, obj_path: Path):
        lib = self.lib = _libbpf()
        lib.bpf_object__open_file.restype = ctypes.c_void_p
        lib.bpf_object__open_file.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
        lib.bpf_object__load.argtypes = [ctypes.c_void_p]
        lib.bpf_object__find_program_by_name.restype = ctypes.c_void_p
        lib.bpf_object__find_program_by_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        lib.bpf_program__fd.argtypes = [ctypes.c_void_p]
        lib.bpf_object__find_map_fd_by_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        lib.bpf_prog_test_run_opts.argtypes = [ctypes.c_int, ctypes.POINTER(_TestRunOpts)]
        for fn in ("bpf_map_update_elem",):
            getattr(lib, fn).argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64]
        lib.bpf_map_lookup_elem.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
        lib.bpf_map_delete_elem.argtypes = [ctypes.c_int, ctypes.c_void_p]
        lib.bpf_map_get_next_key.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
        lib.ring_buffer__new.restype = ctypes.c_void_p
        lib.ring_buffer__new.argtypes = [ctypes.c_int, _SAMPLE_FN, ctypes.c_void_p, ctypes.c_void_p]
        lib.ring_buffer__consume.argtypes = [ctypes.c_void_p]
        self.obj = lib.bpf_object__open_file(str(obj_path).encode(), None)
        assert self.obj, "bpf_object__open_file failed"
        assert lib.bpf_object__load(self.obj) == 0, "bpf_object__load failed"
        prog = lib.bpf_object__find_program_by_name(self.obj, b"xdp_sni_filter")
        self.fd = lib.bpf_program__fd(prog)
        self.maps = {name: lib.bpf_object__find_map_fd_by_name(self.obj, name.encode())
                     for name in ("sni_blocklist", "events", "stats", "settings", "hello_flows", "hello_pkts",
                                  "sni_flows")}
        self._events: list[bytes] = []
        self._hellos: list[bytes] = []
        # The callbacks must outlive the ring buffers.
        self._ev_cb = _SAMPLE_FN(lambda ctx, data, size: self._take(self._events, data, size))
        self._hp_cb = _SAMPLE_FN(lambda ctx, data, size: self._take(self._hellos, data, size))
        self._ev_rb = lib.ring_buffer__new(self.maps["events"], self._ev_cb, None, None)
        self._hp_rb = lib.ring_buffer__new(self.maps["hello_pkts"], self._hp_cb, None, None)

    @staticmethod
    def _take(into: list, data, size) -> int:
        into.append(ctypes.string_at(data, size))
        return 0

    def _keys(self, fd: int, key_size: int) -> list[bytes]:
        keys = []
        cur = None
        nxt = ctypes.create_string_buffer(key_size)
        while True:
            r = self.lib.bpf_map_get_next_key(fd, cur, nxt)
            if r != 0:
                return keys
            keys.append(nxt.raw)
            cur = ctypes.create_string_buffer(nxt.raw)

    def _clear(self, name: str, key_size: int) -> None:
        fd = self.maps[name]
        for k in self._keys(fd, key_size):
            self.lib.bpf_map_delete_elem(fd, ctypes.create_string_buffer(k))

    def _set_u32(self, name: str, index: int, value: int, width: int = 4) -> None:
        key = ctypes.create_string_buffer(struct.pack("<I", index))
        val = ctypes.create_string_buffer(value.to_bytes(width, "little"))
        assert self.lib.bpf_map_update_elem(self.maps[name], key, val, 0) == 0

    def stats(self) -> list[int]:
        out = []
        for i in range(STATS):
            key = ctypes.create_string_buffer(struct.pack("<I", i))
            val = ctypes.create_string_buffer(8)
            assert self.lib.bpf_map_lookup_elem(self.maps["stats"], key, val) == 0
            out.append(struct.unpack("<Q", val.raw)[0])
        return out

    def reset(self, blocklist: list[bytes], settings: int) -> None:
        self._clear("sni_blocklist", 40)
        self._clear("hello_flows", 36)
        self._clear("sni_flows", 36)
        for i in range(STATS):
            self._set_u32("stats", i, 0, 8)
        self._set_u32("settings", 0, settings)
        for key in blocklist:
            assert self.lib.bpf_map_update_elem(self.maps["sni_blocklist"], ctypes.create_string_buffer(key),
                                                ctypes.create_string_buffer(b"\x01"), 0) == 0
        self.drain()

    def drain(self) -> tuple[list[bytes], list[bytes]]:
        self._events.clear()
        self._hellos.clear()
        self.lib.ring_buffer__consume(self._ev_rb)
        self.lib.ring_buffer__consume(self._hp_rb)
        return list(self._events), list(self._hellos)

    def run(self, frame: bytes) -> int:
        buf = ctypes.create_string_buffer(frame, len(frame))
        opts = _TestRunOpts()
        opts.sz = ctypes.sizeof(_TestRunOpts)
        opts.data_in = ctypes.addressof(buf)
        opts.data_size_in = len(frame)
        opts.repeat = 1
        r = self.lib.bpf_prog_test_run_opts(self.fd, ctypes.byref(opts))
        assert r == 0, f"test run failed: {r} errno {ctypes.get_errno()}"
        return opts.retval

    def flows(self) -> list[list]:
        """sni_flows: what the follower keeps (born left out: a clock)."""
        out = []
        fd = self.maps["sni_flows"]
        for k in self._keys(fd, 36):
            val = ctypes.create_string_buffer(88)
            if self.lib.bpf_map_lookup_elem(fd, ctypes.create_string_buffer(k), val) != 0:
                continue
            next_seq, first_seq, skip, ext_left, carry_len, segments, blocked = struct.unpack_from("<7I", val.raw, 8)
            carry = val.raw[36:36 + min(carry_len, 48)]
            out.append([k.hex(), next_seq, first_seq, skip, ext_left, carry_len, segments, blocked, carry.hex()])
        return sorted(out)

    def hello_flows(self) -> list[list]:
        out = []
        fd = self.maps["hello_flows"]
        for k in self._keys(fd, 36):
            val = ctypes.create_string_buffer(4)
            if self.lib.bpf_map_lookup_elem(fd, ctypes.create_string_buffer(k), val) == 0:
                out.append([k.hex(), struct.unpack("<I", val.raw)[0]])
        return sorted(out)

    def expire(self) -> None:
        """Make every followed flow older than SPLIT_TTL_NS."""
        fd = self.maps["sni_flows"]
        for k in self._keys(fd, 36):
            kb = ctypes.create_string_buffer(k)
            val = ctypes.create_string_buffer(88)
            if self.lib.bpf_map_lookup_elem(fd, kb, val) == 0:
                raw = bytearray(val.raw)
                raw[0:8] = struct.pack("<Q", 1)
                self.lib.bpf_map_update_elem(fd, kb, ctypes.create_string_buffer(bytes(raw), 88), 0)


def _event(raw: bytes) -> list:
    saddr, daddr = raw[0:16].hex(), raw[16:32].hex()
    sport, dport = struct.unpack_from("<HH", raw, 32)
    action = raw[36]
    sni_len = struct.unpack_from("<H", raw, 38)[0]
    return [saddr, daddr, sport, dport, action, sni_len, raw[40:72].hex()]


def _hello(raw: bytes) -> list:
    saddr, daddr = raw[0:16].hex(), raw[16:32].hex()
    sport, dport, seq, length, first, pad = struct.unpack_from("<HHIHBB", raw, 32)
    return [saddr, daddr, sport, dport, seq, length, first, pad, raw[44:44 + min(length, 2048)].hex()]


@pytest.fixture(scope="module")
def prog():
    out = Path(tempfile.mkdtemp(prefix="fros-xdp-cases-")) / "xdp_sni_filter.o"
    subprocess.run(["sh", str(BUILD), str(SOURCE), str(out)], check=True)
    return Program(out)


def _case(prog: Program, name: str, steps: list, *, blocklist=BLOCKLIST, settings: int = 0) -> None:
    keys = [build_lpm_key(n) for n in blocklist]
    prog.reset(keys, settings)
    recorded, results = [], []
    for step in steps:
        if step == "expire":
            prog.expire()
            recorded.append({"expire": True})
            results.append({})
            continue
        before = prog.stats()
        verdict = prog.run(step)
        after = prog.stats()
        events, hellos = prog.drain()
        recorded.append({"frame": step.hex()})
        results.append({"verdict": verdict, "stats": [a - b for a, b in zip(after, before)],
                        "events": [_event(e) for e in events], "hellos": [_hello(h) for h in hellos],
                        "flows": prog.flows(), "hello_flows": prog.hello_flows()})
    _record({"op": "run", "name": name, "settings": settings, "blocklist": [k.hex() for k in keys],
             "steps": recorded, "results": results})


# --- frames -------------------------------------------------------------------------------------


V4_SRC, V4_DST = bytes([10, 0, 0, 5]), bytes([93, 184, 216, 34])
V6_SRC = bytes.fromhex("fd000000000000000000000000000005")
V6_DST = bytes.fromhex("20010db8000000000000000000000022")


def _csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def ext(t: int, body: bytes) -> bytes:
    return struct.pack("!HH", t, len(body)) + body


def sni_ext(name: bytes, *, name_type: int = 0, list_len: int | None = None, name_len: int | None = None) -> bytes:
    entry = bytes([name_type]) + struct.pack("!H", len(name) if name_len is None else name_len) + name
    return ext(0, struct.pack("!H", len(entry) if list_len is None else list_len) + entry)


CIPHERS = bytes.fromhex("130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035")


def hello(exts: list[bytes], *, sid: bytes = bytes(range(32)), sid_len: int | None = None,
          ciphers: bytes = CIPHERS, cs_len: int | None = None, comp: bytes = b"\x00", comp_len: int | None = None,
          ext_total: int | None = None, no_ext: bool = False, hs_len: int | None = None,
          rec_len: int | None = None, hs_type: int = 1, content_type: int = 0x16) -> bytes:
    body = b"\x03\x03" + bytes(range(100, 132))
    body += bytes([len(sid) if sid_len is None else sid_len]) + sid
    body += struct.pack("!H", len(ciphers) if cs_len is None else cs_len) + ciphers
    body += bytes([len(comp) if comp_len is None else comp_len]) + comp
    if not no_ext:
        e = b"".join(exts)
        body += struct.pack("!H", len(e) if ext_total is None else ext_total) + e
    hs = bytes([hs_type]) + (len(body) if hs_len is None else hs_len).to_bytes(3, "big") + body
    return bytes([content_type]) + b"\x03\x01" + struct.pack("!H", len(hs) if rec_len is None else rec_len) + hs


def std_exts(name: bytes, *, before: int = 1, after: int = 2) -> list[bytes]:
    pre = [ext(0x000A, bytes.fromhex("0006001d00170018")), ext(0x0017, b""), ext(0xFF01, b"\x00"),
           ext(0x000B, b"\x01\x00"), ext(0x0023, b""), ext(0x0010, b"\x00\x0c\x02h2\x08http/1.1")]
    post = [ext(0x002B, b"\x04\x03\x04\x03\x03"), ext(0x000D, bytes.fromhex("0008040304010503")),
            ext(0x002D, b"\x01\x01"), ext(0x0033, b"\x00\x26\x00\x1d\x00\x20" + bytes(range(32)))]
    return pre[:before] + [sni_ext(name)] + post[:after]


def tcp(payload: bytes, *, src: bytes, dst: bytes, sport: int = 40000, dport: int = 443, seq: int = 1000,
        flags: int = 0x18, doff: int | None = None, options: bytes = b"", good_csum: bool = True) -> bytes:
    hlen = 20 + len(options)
    doff_byte = ((hlen // 4) if doff is None else doff) << 4
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, doff_byte, flags, 64240, 0, 0) + options
    if len(src) == 4:
        pseudo = src + dst + struct.pack("!BBH", 0, 6, len(hdr) + len(payload))
    else:
        pseudo = src + dst + struct.pack("!I", len(hdr) + len(payload)) + b"\x00\x00\x00\x06"
    c = _csum(pseudo + hdr + payload)
    if not good_csum:
        c ^= 0x5A5A
    return hdr[:16] + struct.pack("!H", c) + hdr[18:] + payload


def ipv4(l4: bytes, *, src: bytes = V4_SRC, dst: bytes = V4_DST, proto: int = 6, options: bytes = b"",
         frag: int = 0x4000, tot_len: int | None = None, ihl: int | None = None) -> bytes:
    hlen = 20 + len(options)
    ver_ihl = 0x40 | ((hlen // 4) if ihl is None else ihl)
    total = hlen + len(l4) if tot_len is None else tot_len
    hdr = struct.pack("!BBHHHBBH4s4s", ver_ihl, 0, total, 0x1234, frag, 64, proto, 0, src, dst) + options
    c = _csum(hdr)
    return hdr[:10] + struct.pack("!H", c) + hdr[12:] + l4


def ipv6(l4: bytes, *, src: bytes = V6_SRC, dst: bytes = V6_DST, nh: int = 6,
         exts: list[tuple[int, bytes]] = (), plen: int | None = None) -> bytes:
    """`exts`: (this header's type, its body after the next-header byte),
    in order; the last one's next header is `nh`."""
    chain = b""
    types = [t for t, _ in exts] + [nh]
    for i, (t, body) in enumerate(exts):
        if t == 44:
            chain += bytes([types[i + 1]]) + body
        else:
            chain += bytes([types[i + 1], (len(body) + 2) // 8 - 1]) + body
    first = types[0]
    payload = chain + l4
    hdr = struct.pack("!IHBB16s16s", 0x60000000, len(payload) if plen is None else plen, first, 64, src, dst)
    return hdr + payload


def eth(l3: bytes, *, ethertype: int = 0x0800, tags: list[int] = (), pad: bytes = b"") -> bytes:
    out = bytes.fromhex("020000000001") + bytes.fromhex("020000000002")
    for tpid in tags:
        out += struct.pack("!H", tpid) + struct.pack("!H", 100)
    return out + struct.pack("!H", ethertype) + l3 + pad


def v4_frame(payload: bytes, *, tags=(), pad: bytes = b"", **tcp_kw) -> bytes:
    return eth(ipv4(tcp(payload, src=V4_SRC, dst=V4_DST, **tcp_kw)), tags=list(tags), pad=pad)


def v6_frame(payload: bytes, *, tags=(), exts=(), pad: bytes = b"", **tcp_kw) -> bytes:
    return eth(ipv6(tcp(payload, src=V6_SRC, dst=V6_DST, **tcp_kw), exts=list(exts)), ethertype=0x86DD,
               tags=list(tags), pad=pad)


def frame_for(family: str, payload: bytes, **kw) -> bytes:
    return v4_frame(payload, **kw) if family == "v4" else v6_frame(payload, **kw)


# --- single-segment ClientHellos -----------------------------------------------------------------


NAMES = [b"blocked.example", b"BLOCKED.Example", b"blocked.example.", b"blocked.example...", b"www.blocked.example",
         b"notblocked.example", b"xblocked.example", b"blocked.example.x", b"ads.example.net", b"evil.test",
         b"sub.evil.test", b"a.b", b"x.a.b", b"aa.b", b"upper.example", b"UPPER.EXAMPLE", b"...", b".", b"a",
         b"b" * 31, b"b" * 32, b"blocked_example", b"blocked@example", b"blocked\x7fexample", b"blocked\xffexample",
         b"Blocked.EXAMPLE.", b".blocked.example", b"blocked..example", b"x" * 20 + b".evil.test",
         b"y" * 21 + b".evil.test", b"blocked.example\x00", b"\x00blocked.example", b"[blocked.example]",
         b"Z", b"z.a.b.", b"evil.test" + b"." * 22]


def test_names(prog):
    for settings in (0, SETTING_REPORT_PASS, SETTING_REPORT_PASS | SETTING_REPORT_HELLO):
        for name in NAMES:
            for family in ("v4", "v6"):
                _case(prog, f"name {name!r} {family} s{settings}",
                      [frame_for(family, hello(std_exts(name)))], settings=settings)


def test_hello_fields(prog):
    blocked = b"blocked.example"
    shapes = {
        "sni first": hello([sni_ext(blocked)]),
        "sni last of 6": hello(std_exts(blocked, before=5, after=0)),
        "name type 1": hello([sni_ext(blocked, name_type=1)]),
        "name len 0": hello([sni_ext(blocked, name_len=0)]),
        "name len 32": hello([sni_ext(b"b" * 32)]),
        "name len past ext": hello([sni_ext(blocked, name_len=40)]),
        "name len short": hello([sni_ext(blocked, name_len=7)]),
        "list len odd": hello([sni_ext(blocked, list_len=0)]),
        "two names": hello([ext(0, struct.pack("!H", 2 * (3 + 9)) + b"\x00\x00\x09allowed.x" + b"\x00\x00\x09evil.test")]),
        "two sni exts": hello([sni_ext(b"allowed.example"), sni_ext(blocked)]),
        "sni ext empty": hello([ext(0, b"")]),
        "sni ext 3 bytes": hello([ext(0, b"\x00\x05\x00")]),
        "sid 32": hello(std_exts(blocked), sid=bytes(32)),
        "sid 33": hello(std_exts(blocked), sid=bytes(33)),
        "sid 0": hello(std_exts(blocked), sid=b""),
        "ciphers 512": hello(std_exts(blocked), ciphers=bytes(512)),
        "ciphers 514": hello(std_exts(blocked), ciphers=bytes(514)),
        "ciphers 511": hello(std_exts(blocked), ciphers=bytes(511)),
        "ciphers 513": hello(std_exts(blocked), ciphers=bytes(513)),
        "ext total at name": hello(std_exts(blocked), ext_total=12),
        "ext total at name - 1": hello(std_exts(blocked), ext_total=11),
        "ext total at name + 1": hello(std_exts(blocked), ext_total=13),
        "ciphers 0": hello(std_exts(blocked), ciphers=b""),
        "comp 16": hello(std_exts(blocked), comp=bytes(16)),
        "comp 17": hello(std_exts(blocked), comp=bytes(17)),
        "no extensions": hello([], no_ext=True),
        "empty extensions": hello([]),
        "ext total short": hello(std_exts(blocked, before=3), ext_total=10),
        "ext total 0": hello(std_exts(blocked), ext_total=0),
        "ext total huge": hello(std_exts(blocked), ext_total=0xFFFF),
        "ext total 4095": hello(std_exts(blocked), ext_total=4095),
        "ext total 4096": hello(std_exts(blocked), ext_total=4096),
        "ext len 4095 before": hello([ext(0x15, bytes(4095)[:900]), sni_ext(blocked)]),
        "ext len over 4095": hello([struct.pack("!HH", 0x15, 4096) + bytes(64), sni_ext(blocked)]),
        "ext header cut": hello([sni_ext(blocked), b"\x00\x2b\x00"]),
        "32 exts then sni": hello([ext(0x7000 + i, b"") for i in range(31)] + [sni_ext(blocked)]),
        "33 exts then sni": hello([ext(0x7000 + i, b"") for i in range(32)] + [sni_ext(blocked)]),
        "40 exts then sni": hello([ext(0x7000 + i, b"x") for i in range(40)] + [sni_ext(blocked)]),
        "server hello": hello(std_exts(blocked), hs_type=2),
        "alert record": hello(std_exts(blocked), content_type=0x15),
        "rec len 0": hello(std_exts(blocked), rec_len=0),
        "rec len short": hello(std_exts(blocked), rec_len=40),
        "rec len long": hello(std_exts(blocked), rec_len=5000),
        "hs len long": hello(std_exts(blocked), hs_len=9000),
        "hs len short": hello(std_exts(blocked), hs_len=10),
        "padding ext": hello([ext(0x15, bytes(300)), sni_ext(blocked)]),
        "grease": hello([ext(0x0A0A, b""), sni_ext(blocked), ext(0x1A1A, b"\x00")]),
    }
    for name, payload in shapes.items():
        for family in ("v4", "v6"):
            for settings in (0, SETTING_REPORT_PASS | SETTING_REPORT_HELLO):
                _case(prog, f"field {name} {family} s{settings}", [frame_for(family, payload)], settings=settings)


def test_cuts(prog):
    """A blocked hello cut at every byte: by the frame (the datagram ends
    there too) and by the IP length alone (the rest is Ethernet padding)."""
    payload = hello(std_exts(b"blocked.example", before=2, after=1))
    for cut in range(0, len(payload) + 1):
        part = payload[:cut]
        _case(prog, f"cut frame {cut}", [v4_frame(part)])
        if cut < len(payload):
            _case(prog, f"cut iplen {cut}", [v4_frame(part, pad=payload[cut:])])
            _case(prog, f"cut iplen v6 {cut}", [v6_frame(part, pad=payload[cut:])])


def test_layers(prog):
    payload = hello(std_exts(b"blocked.example"))
    t = lambda **kw: tcp(payload, src=V4_SRC, dst=V4_DST, **kw)
    t6 = lambda **kw: tcp(payload, src=V6_SRC, dst=V6_DST, **kw)
    frames = {
        "plain": eth(ipv4(t())),
        "one 8021q": eth(ipv4(t()), tags=[0x8100]),
        "qinq": eth(ipv4(t()), tags=[0x88A8, 0x8100]),
        "three tags": eth(ipv4(t()), tags=[0x8100, 0x8100, 0x8100]),
        "tag then cut": eth(b"", ethertype=0x8100)[:16],
        "arp": eth(bytes(28), ethertype=0x0806),
        "short eth": eth(b"")[:14],
        "udp": eth(ipv4(t(), proto=17)),
        "mf": eth(ipv4(t(), frag=0x2000)),
        "offset": eth(ipv4(t(), frag=0x0010)),
        "df": eth(ipv4(t(), frag=0x4000)),
        "no df": eth(ipv4(t(), frag=0)),
        "udp mf": eth(ipv4(t(), proto=17, frag=0x2000)),
        "ihl 4": eth(ipv4(t(), ihl=4)),
        "ihl 6 options": eth(ipv4(t(), options=b"\x01\x01\x01\x00")),
        "ihl 15": eth(ipv4(t(), ihl=15)),
        "ihl past frame": eth(ipv4(b"", ihl=15)),
        "ip short": eth(ipv4(t())[:19]),
        "tot len 0": eth(ipv4(t(), tot_len=0)),
        "tot len 20": eth(ipv4(t(), tot_len=20)),
        "tot len 40": eth(ipv4(t(), tot_len=40)),
        "tot len huge": eth(ipv4(t(), tot_len=0xFFFF)),
        "doff 4": eth(ipv4(t(doff=4))),
        "doff 15": eth(ipv4(t(doff=15))),
        "tcp options": eth(ipv4(t(options=b"\x02\x04\x05\xb4\x01\x01\x04\x02"))),
        "port 80": eth(ipv4(t(dport=80))),
        "port 8443": eth(ipv4(t(dport=8443))),
        "sport 443": eth(ipv4(t(sport=443, dport=50000))),
        "syn with hello": eth(ipv4(t(flags=0x02))),
        "rst with hello": eth(ipv4(t(flags=0x04))),
        "tcp short": eth(ipv4(t()[:19])),
        "v6 plain": eth(ipv6(t6()), ethertype=0x86DD),
        "v6 tagged": eth(ipv6(t6()), ethertype=0x86DD, tags=[0x8100]),
        "v6 qinq": eth(ipv6(t6()), ethertype=0x86DD, tags=[0x88A8, 0x8100]),
        "v6 hop": eth(ipv6(t6(), exts=[(0, bytes(6))]), ethertype=0x86DD),
        "v6 routing": eth(ipv6(t6(), exts=[(43, bytes(14))]), ethertype=0x86DD),
        "v6 dest": eth(ipv6(t6(), exts=[(60, bytes(6))]), ethertype=0x86DD),
        "v6 four": eth(ipv6(t6(), exts=[(0, bytes(6)), (60, bytes(6)), (43, bytes(6)), (60, bytes(6))]),
                       ethertype=0x86DD),
        "v6 five": eth(ipv6(t6(), exts=[(0, bytes(6)), (60, bytes(6)), (43, bytes(6)), (60, bytes(6)),
                                        (60, bytes(6))]), ethertype=0x86DD),
        "v6 frag tcp": eth(ipv6(t6(), exts=[(44, bytes(7))]), ethertype=0x86DD),
        "v6 frag udp": eth(ipv6(t6(), nh=17, exts=[(44, bytes(7))]), ethertype=0x86DD),
        "v6 dest frag": eth(ipv6(t6(), exts=[(60, bytes(6)), (44, bytes(7))]), ethertype=0x86DD),
        "v6 frag then dest": eth(ipv6(t6(), exts=[(44, bytes(7)), (60, bytes(6))]), ethertype=0x86DD),
        "v6 frag then frag": eth(ipv6(t6(), exts=[(44, bytes(7)), (44, bytes(7))]), ethertype=0x86DD),
        "v6 frag then udp": eth(ipv6(t6(), nh=17, exts=[(44, bytes(7)), (44, bytes(7))]), ethertype=0x86DD),
        "v6 udp": eth(ipv6(t6(), nh=17), ethertype=0x86DD),
        "v6 no next": eth(ipv6(b"", nh=59), ethertype=0x86DD),
        "v6 mapped src": eth(ipv6(t6(), src=bytes(10) + b"\xff\xff" + V4_SRC), ethertype=0x86DD),
        "v6 mapped dst": eth(ipv6(t6(), dst=bytes(10) + b"\xff\xff" + V4_DST), ethertype=0x86DD),
        "v6 ext past frame": eth(ipv6(b"", nh=0) + b"\x06", ethertype=0x86DD),
        "v6 big ext": eth(ipv6(t6(), exts=[(60, bytes(8 * 255 + 6))]), ethertype=0x86DD),
        "v6 plen short": eth(ipv6(t6(), plen=20), ethertype=0x86DD),
        "v6 plen 0": eth(ipv6(t6(), plen=0), ethertype=0x86DD),
        "v6 plen huge": eth(ipv6(t6(), plen=0xFFFF), ethertype=0x86DD),
        "v6 short": eth(ipv6(t6())[:39], ethertype=0x86DD),
        "v6 doff 4": eth(ipv6(t6(doff=4)), ethertype=0x86DD),
        "v6 port 80": eth(ipv6(t6(dport=80)), ethertype=0x86DD),
        "v4 in v6 ethertype": eth(ipv4(t()), ethertype=0x86DD),
        "v6 in v4 ethertype": eth(ipv6(t6())),
    }
    for name, frame in frames.items():
        if len(frame) < 14:
            continue
        for settings in (0, SETTING_REPORT_PASS | SETTING_REPORT_HELLO):
            _case(prog, f"layer {name} s{settings}", [frame], settings=settings)


# --- split ClientHellos (ROADMAP SEC-17/24/28) and their copies (phase 19) --------------------------


def big_hello(name: bytes, *, pad: int = 1200, after_pad: list[bytes] | None = None, rec_split: bool = False,
              sni: bytes | None = None, tail: bytes = b"", **kw) -> tuple[bytes, int]:
    """A ClientHello with `pad` bytes of extensions before the name;
    returns it and the offset of the server_name extension in it. `sni`
    replaces the server_name extension, `tail` follows the extensions,
    and the rest goes to hello()."""
    sni = sni_ext(name) if sni is None else sni
    exts = [ext(0x000A, bytes.fromhex("0006001d00170018")), ext(0x0033, bytes(pad))]
    if after_pad:
        exts += after_pad
    exts += [sni, ext(0x002B, b"\x04\x03\x04\x03\x03")]
    payload = hello(exts, **kw) + tail
    at = payload.index(sni)
    if rec_split:
        # The same handshake in two records: the walk can't follow it.
        hs = payload[5:]
        first, rest = hs[:600], hs[600:]
        payload = b"\x16\x03\x01" + struct.pack("!H", len(first)) + first + b"\x16\x03\x01" + struct.pack("!H", len(rest)) + rest
    return payload, at


def segments(stream: bytes, cuts: list[int]) -> list[tuple[int, bytes]]:
    edges = [0] + sorted(set(c for c in cuts if 0 < c < len(stream))) + [len(stream)]
    return [(edges[i], stream[edges[i]:edges[i + 1]]) for i in range(len(edges) - 1)]


def seg_frames(family: str, stream: bytes, cuts: list[int], *, isn: int = 7000, **kw) -> list[bytes]:
    return [frame_for(family, data, seq=(isn + off) & 0xFFFFFFFF, **kw) for off, data in segments(stream, cuts)]


def test_split_offsets(prog):
    for family in ("v4", "v6"):
        for name in (b"blocked.example", b"allowed.example"):
            stream, at = big_hello(name)
            for delta in range(-12, 30):
                cut = at + delta
                for settings in (0, SETTING_REPORT_PASS | SETTING_REPORT_HELLO):
                    _case(prog, f"split {family} {name.decode()} at sni{delta:+d} s{settings}",
                          seg_frames(family, stream, [cut]), settings=settings)


def test_split_edges(prog):
    """The follower's limits, each from just inside to just outside."""
    blocked, allowed = b"blocked.example", b"allowed.example"
    for family in ("v4", "v6"):
        # SEC-28: the name in the 14th to 18th segment after the first; the
        # walk follows SPLIT_MAX_SEGMENTS (16) of them and drops the rest.
        for name in (blocked, allowed):
            stream, at = big_hello(name, pad=1500)
            seen = set()
            for step in range(60, 200):
                k = 1 + (at - 300) // step
                if k in seen or not 14 <= k <= 18 or 1 + (at + 9 + len(name) - 300) // step != k:
                    continue
                seen.add(k)
                _case(prog, f"split segment {k} {family} {name.decode()}",
                      seg_frames(family, stream, [300] + list(range(300 + step, len(stream), step))))
        # One handshake in two records: followed only while it fits its record.
        two_rec, _ = big_hello(blocked, rec_split=True)
        for cuts in ([400], [400, 900], [604], [605], [606]):
            _case(prog, f"split records {family} {cuts}", seg_frames(family, two_rec, cuts),
                  settings=SETTING_REPORT_HELLO)
        stream, at = big_hello(blocked)
        # A segment ending exactly where a skipped extension does.
        for cuts in ([700, at], [700, at, at + 5], [700, at - 1], [700, at + 1]):
            _case(prog, f"split skip ends {family} {cuts}", seg_frames(family, stream, cuts))
        # Sequence numbers wrapping between the bytes read and the next ones.
        isn = (1 << 32) - 720
        one, two, three = seg_frames(family, stream, [700, at + 3], isn=isn)
        _case(prog, f"split wrap out of order {family}", [one, three, two, three])
        _case(prog, f"split wrap retransmit {family}", [one, two, two, three])
        _case(prog, f"split wrap first again {family}", [one, one, two, three])
    # The extensions block's declared length against what follows it.
    for d in (-12, -10, -9, -8, -2, -1, 1, 2, 3, 4, 5):
        stream, at = big_hello(blocked, ext_total=_ext_len(blocked) + d, tail=bytes(max(d, 0)))
        for cuts in ([700], [700, at + 3], [700, len(stream) - 2]):
            _case(prog, f"split ext total {d:+d} {cuts}", seg_frames("v4", stream, cuts))
    # A name length past its extension, and other bad name headers.
    for label, sni in (("long name", sni_ext(blocked, name_len=16)), ("short name", sni_ext(blocked, name_len=14)),
                       ("name over ext", ext(0, struct.pack("!H", 18) + b"\x00" + struct.pack("!H", 16) + blocked)),
                       ("name type 1", sni_ext(blocked, name_type=1)), ("name 0", sni_ext(b"", name_len=0)),
                       ("name 31", sni_ext(b"a" * 27 + b".b.c")), ("name 32", sni_ext(b"a" * 28 + b".b.c"))):
        stream, at = big_hello(blocked, sni=sni)
        for cuts in ([700, at + 3], [700, at + 8], [700, at + 12]):
            _case(prog, f"split {label} {cuts}", seg_frames("v4", stream, cuts))
    # No name, and 1 to 5 bytes the extensions length claims after the last.
    for d in range(0, 6):
        exts = [ext(0x000A, bytes.fromhex("0006001d00170018")), ext(0x0033, bytes(1200)), ext(0x002B, b"\x04\x03")]
        total = len(b"".join(exts)) + d
        stream = hello(exts, ext_total=total) + bytes(d)
        for cuts in ([700], [700, len(stream) - d], [700, len(stream) - 1]):
            _case(prog, f"split trailing {d} {cuts}", seg_frames("v4", stream, cuts))


def _ext_len(name: bytes) -> int:
    """The extensions block's length in big_hello(name)."""
    exts = [ext(0x000A, bytes.fromhex("0006001d00170018")), ext(0x0033, bytes(1200)), sni_ext(name),
            ext(0x002B, b"\x04\x03\x04\x03\x03")]
    return len(b"".join(exts))


def test_split_shapes(prog):
    blocked = b"blocked.example"
    stream, at = big_hello(blocked)
    fr = lambda cuts, **kw: seg_frames("v4", stream, cuts, **kw)
    a, b = fr([700, 1400])[0:2], fr([700, 1400])[2:]
    one, two, three = fr([700, at + 3])
    cases = {
        "two segments": fr([800]),
        "three segments": fr([500, 1000]),
        "mss 100": fr(list(range(100, len(stream), 100))),
        "mss 64": fr(list(range(64, len(stream), 64))),
        "mss 536": fr(list(range(536, len(stream), 536))),
        "out of order": [one, three, two, three],
        "retransmit first": [one, one, two, three],
        "retransmit read": [one, two, two, three],
        "duplicate then blocked retrans": [one, two, three, three, two],
        "rst clears": [one, frame_for("v4", b"", seq=7000 + 700, flags=0x04), two, three],
        "syn clears": [one, frame_for("v4", b"", seq=1, flags=0x02), two, three],
        "pure ack between": [one, frame_for("v4", b"", seq=7000 + 700, flags=0x10), two, three],
        "padded ack between": [one, frame_for("v4", b"", seq=7000 + 700, flags=0x10, pad=bytes(6)), two, three],
        "bad checksum": [one, frame_for("v4", stream[700:at + 3], seq=7000 + 700, good_csum=False), two, three],
        "bad checksum third": [one, two, frame_for("v4", stream[at + 3:], seq=7000 + at + 3, good_csum=False), three],
        "expired": [one, "expire", two, three, two],
        "expired after second": [one, two, "expire", three],
        "other port": [one, frame_for("v4", stream[700:at + 3], seq=7000 + 700, sport=40001), two, three],
        "wrapping seq": seg_frames("v4", stream, [700, at + 3], isn=0xFFFFFF00),
        "overlap": [one, frame_for("v4", stream[650:at + 3], seq=7000 + 650), three],
        "partial overlap read": [one, two, frame_for("v4", stream[at:at + 3], seq=7000 + at), three],
        "ahead then in order": [one, three, two, three],
        "first again bigger": [one, frame_for("v4", stream[:at + 3], seq=7000), three],
        "first then whole": [one, frame_for("v4", stream, seq=7000)],
        "jumbo next": [frame_for("v4", stream[:300], seq=7000), frame_for("v4", stream[300:] + bytes(800), seq=7300)],
        "a b": a + b,
    }
    for name, steps in cases.items():
        for settings in (0, SETTING_REPORT_PASS | SETTING_REPORT_HELLO):
            _case(prog, f"split {name} s{settings}", steps, settings=settings)
    # Some of the shapes over IPv6.
    v6s = seg_frames("v6", stream, [700, at + 3])
    _case(prog, "split v6 out of order", [v6s[0], v6s[2], v6s[1], v6s[2]])
    _case(prog, "split v6 bad checksum", [v6s[0], frame_for("v6", stream[700:at + 3], seq=7700, good_csum=False),
                                         v6s[1], v6s[2]])
    _case(prog, "split v6 mss 100", seg_frames("v6", stream, list(range(100, len(stream), 100))))
    _case(prog, "split v6 expired", [v6s[0], "expire", v6s[1]])
    # Two records: not followed.
    two_rec, at2 = big_hello(blocked, rec_split=True)
    _case(prog, "split across records", seg_frames("v4", two_rec, [800]), settings=SETTING_REPORT_HELLO)
    # A long skipped extension spanning segments, then the name.
    long_stream, at3 = big_hello(blocked, pad=100, after_pad=[ext(0x7777, bytes(2500))])
    for cuts in ([300], [300, 1000], [300, 1000, 1800, 2400], [300, 1500, at3 + 2], [60, 2650]):
        for family in ("v4", "v6"):
            _case(prog, f"split skip {family} {cuts}", seg_frames(family, long_stream, cuts))
    # VLAN-tagged split.
    _case(prog, "split tagged", seg_frames("v4", stream, [800], tags=[0x8100]))


def test_hello_copies(prog):
    stream, at = big_hello(b"allowed.example", pad=1600)
    cuts = list(range(600, len(stream), 600))
    for settings in (SETTING_REPORT_HELLO, SETTING_REPORT_HELLO | SETTING_REPORT_PASS):
        _case(prog, f"copies s{settings}", seg_frames("v4", stream, cuts) + [v4_frame(b"\x17\x03\x03\x00\x05hello", seq=99999)],
              settings=settings)
        _case(prog, f"copies v6 s{settings}", seg_frames("v6", stream, cuts), settings=settings)
    small = hello(std_exts(b"allowed.example"))
    _case(prog, "copies rec len longer", [v4_frame(hello(std_exts(b"allowed.example"), rec_len=3000)),
                                          v4_frame(b"\x00" * 100, seq=1000 + len(small)),
                                          v4_frame(b"\x01" * 100, seq=1100 + len(small)),
                                          v4_frame(b"\x02" * 100, seq=1200 + len(small)),
                                          v4_frame(b"\x03" * 100, seq=1300 + len(small))],
          settings=SETTING_REPORT_HELLO)
    _case(prog, "copies jumbo", [v4_frame(small + bytes(2400))], settings=SETTING_REPORT_HELLO)


# --- seeded random damage and segmentation ---------------------------------------------------------


def test_random_damage(prog):
    rng = random.Random(4)
    pool = [v4_frame(hello(std_exts(b"blocked.example"))), v6_frame(hello(std_exts(b"evil.test", before=4))),
            v4_frame(hello(std_exts(b"allowed.example")), tags=[0x8100]),
            v6_frame(hello(std_exts(b"blocked.example")), exts=[(0, bytes(6))]),
            v4_frame(hello([sni_ext(b"a.b")], sid=b""))]
    for i in range(700):
        frame = bytearray(rng.choice(pool))
        for _ in range(rng.randint(1, 4)):
            frame[rng.randrange(len(frame))] = rng.randrange(256)
        if rng.random() < 0.15:
            frame = frame[: rng.randint(14, len(frame))]
        _case(prog, f"damaged {i}", [bytes(frame)], settings=rng.choice([0, 1, 3]))


def test_random_splits(prog):
    rng = random.Random(17)
    for i in range(400):
        name = rng.choice([b"blocked.example", b"ads.example.net", b"allowed.example", b"x.evil.test"])
        stream, at = big_hello(name, pad=rng.randint(0, 1600),
                               after_pad=[ext(0x7000 + j, bytes(rng.randint(0, 300))) for j in range(rng.randint(0, 3))])
        family = rng.choice(["v4", "v6"])
        n = rng.randint(1, 5)
        cuts = sorted(rng.sample(range(1, len(stream)), n))
        if rng.random() < 0.5:
            cuts.append(at + rng.randint(-6, 24))
        frames = seg_frames(family, stream, cuts, isn=rng.randrange(1 << 32))
        steps: list = list(frames)
        if rng.random() < 0.3 and len(steps) > 2:
            j = rng.randrange(1, len(steps) - 1)
            steps[j], steps[j + 1] = steps[j + 1], steps[j]
        if rng.random() < 0.2:
            steps.insert(rng.randrange(1, len(steps) + 1), rng.choice(frames))
        if rng.random() < 0.1 and len(steps) > 1:
            steps.insert(rng.randrange(1, len(steps)), "expire")
        if rng.random() < 0.15:
            j = rng.randrange(len(steps))
            if steps[j] != "expire":
                bad = bytearray(steps[j])
                bad[-1] ^= 0xFF
                steps[j] = bytes(bad)
        _case(prog, f"random split {i}", steps, settings=rng.choice([0, 1, 2, 3]))
