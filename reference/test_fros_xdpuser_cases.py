"""FR_OS 1.x's XDP SNI filter userland (frfw.xdp) fed every shape of
input, recorded for FR_OS 2 (xdpuser.jsonl; reference/generate.sh runs
this module). The kernel program itself is recorded by
reference/test_fros_xdp_cases.py, as root.

Recorded:

- `normalize_sni` and `build_lpm_key` of every shape of name: case,
  trailing dots, every length around MAX_SNI_LEN, empty, only dots, not
  ASCII, then seeded random ones: the normalized name, and the key or
  the error (the Go apply builds the keys, and refuses the same names
  with the same message);
- `SniEvent.from_bytes` and `HelloSegment.from_bytes` of records of
  every shape (IPv4-mapped and IPv6 addresses, every action byte, name
  lengths past the buffer, bytes that aren't ASCII, short records), then
  seeded random ones: the decoded fields, or the error;
- `format_event_json` of decoded events at several clocks: the line the
  event logger writes;
- `EventFile`: lines appended to a file that starts empty, holds
  something, or gets too big: the bytes left and the file's mode.

Nothing here asserts anything about 1.x.
"""

from __future__ import annotations

import os
import random
import struct
import sys
import tempfile
from pathlib import Path
from unittest import mock

from frfw import xdp


def _record(case: dict) -> None:
    capture = sys.modules.get("fros_capture")
    if capture is not None:
        capture._record("xdpuser", case)


def _error(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"


# --- names and keys --------------------------------------------------------------

NAMES = [
    "example.com", "Example.COM", "EXAMPLE.COM.", "example.com..", "a", "A", ".", "..", "...", "a.", "a..",
    ".a", "..a", "a.b.c", "x" * 30, "x" * 31, "x" * 32, "x" * 33, "x" * 30 + ".", "x" * 31 + ".",
    "x" * 30 + "..", "X" * 31, "", "bücher.de", "日本.jp", "a_b.example", "a@b", "[]^_`{|}~",
    "Z", "z", "@", "[", "`", "{", "a\x00b", "a\tb", "a b", "-a-.example", "*.example.com", "xn--bcher-kva.de",
    "\x7f", "\x80", "exámple.com", "A" * 31 + ".", "." * 31, "." * 32,
]


def _random_names(rng: random.Random, n: int) -> list[str]:
    alphabet = "abcXYZ.-_09" + "".join(chr(c) for c in range(0x20, 0x7f))
    out = []
    for _ in range(n):
        length = rng.choice([1, 2, 5, 16, 29, 30, 31, 32, 33, rng.randrange(0, 40)])
        name = "".join(rng.choice(alphabet) for _ in range(length))
        if rng.random() < 0.1:
            name += "é"
        out.append(name)
    return out


def test_keys():
    rng = random.Random(4002)
    for name in NAMES + _random_names(rng, 400):
        case = {"kind": "key", "name": name, "normalized": xdp.normalize_sni(name)}
        try:
            case["key"] = xdp.build_lpm_key(name).hex()
        except Exception as exc:  # noqa: BLE001 -- recorded as is
            case["error"] = _error(exc)
        _record(case)


# --- events and hello copies ------------------------------------------------------

MAPPED = bytes(10) + b"\xff\xff"


def _v4(text: str) -> bytes:
    return MAPPED + bytes(int(p) for p in text.split("."))


ADDRESSES = [
    _v4("10.0.0.5"), _v4("0.0.0.0"), _v4("255.255.255.255"), bytes(16), bytes(15) + b"\x01",
    bytes.fromhex("20010db8000000000000000000000001"), bytes.fromhex("fe800000000000000202b3fffe1e8329"),
    bytes.fromhex("00000000000000000000000001020304"), bytes.fromhex("0000000000000000ffff000001020304"),
    bytes.fromhex("000000000000000000fffff001020304"), bytes.fromhex("ff020000000000000000000000000001"),
    bytes.fromhex("20010db8000000010000000000000000"), bytes.fromhex("20010000000000000000000000000000"),
    bytes.fromhex("0001000000000000000000000000000f"), bytes.fromhex("ffffffffffffffffffffffffffffffff"),
    bytes.fromhex("0000000000000000000000000000ffff"), bytes.fromhex("00000000ffff00000000000000000000"),
]


def _event(saddr: bytes, daddr: bytes, sport: int, dport: int, action: int, sni_len: int, sni: bytes,
           pad: int = 0) -> bytes:
    body = saddr + daddr + struct.pack("<HHBBH", sport, dport, action, pad, sni_len)
    return body + sni.ljust(xdp.MAX_SNI_LEN, b"\x00")[:xdp.MAX_SNI_LEN]


def _events(rng: random.Random) -> list[bytes]:
    out = []
    for i, a in enumerate(ADDRESSES):
        out.append(_event(a, ADDRESSES[(i + 3) % len(ADDRESSES)], 40000 + i, 443, 1, 11, b"example.com"))
    for action in (0, 1, 2, 255):
        out.append(_event(ADDRESSES[0], ADDRESSES[5], 1, 2, action, 3, b"abc"))
    for sni_len, sni in ((0, b""), (1, b"a"), (31, b"x" * 31), (32, b"y" * 32), (33, b"z" * 32),
                         (65535, b"w" * 32), (5, b"a\x00b\x80\xff"), (4, b"\xe9t\xe9!"), (3, b"A\nB"),
                         (6, b"\"\\/\x01\x1f\x7f"), (2, b"\xc3\xa9")):
        out.append(_event(ADDRESSES[0], ADDRESSES[5], 65535, 0, 1, sni_len, sni, pad=7))
    full = _event(ADDRESSES[5], ADDRESSES[6], 443, 443, 0, 7, b"example")
    out += [full[:n] for n in (0, 1, 39, 40, 71)] + [full + b"\x00" * 8, full + b"\xff"]
    for _ in range(200):
        out.append(bytes(rng.randrange(256) for _ in range(rng.choice([72, 72, 72, 80, rng.randrange(0, 90)]))))
    return out


def _decoded(event: xdp.SniEvent) -> dict:
    return {"saddr": event.saddr, "daddr": event.daddr, "sport": event.sport, "dport": event.dport,
            "hostname": event.hostname, "action": event.action}


#: The event logger's clocks (time.time()).
CLOCKS = [1793491200.0, 1793491200.5, 1793491200.123456, 0.0, 1e-7, 123456789.98765432, 1e16, 2 ** 53 + 1.0]


def test_events():
    rng = random.Random(4003)
    for n, raw in enumerate(_events(rng)):
        case = {"kind": "event", "raw": raw.hex()}
        try:
            event = xdp.SniEvent.from_bytes(raw)
        except Exception as exc:  # noqa: BLE001
            case["error"] = _error(exc)
        else:
            case["event"] = _decoded(event)
            clock = CLOCKS[n % len(CLOCKS)]
            with mock.patch("time.time", lambda: clock):
                case["ts"] = clock
                case["line"] = xdp.format_event_json(event)
        _record(case)


def _hello(saddr: bytes, daddr: bytes, sport: int, dport: int, seq: int, length: int, first: int,
           payload: bytes, pad: int = 0) -> bytes:
    head = struct.pack("<16s16sHHIHBB", saddr, daddr, sport, dport, seq, length, first, pad)
    return head + payload.ljust(xdp.HELLO_SNAP, b"\x00")[:xdp.HELLO_SNAP]


def test_hellos():
    rng = random.Random(4004)
    raws = []
    hello = bytes(range(256)) * 9
    for length in (0, 1, 5, 2047, 2048, 2049, 65535):
        for first in (0, 1, 2):
            raws.append(_hello(ADDRESSES[0], ADDRESSES[5], 51000, 443, 0xFFFFFFFF if first == 2 else 7, length,
                               first, hello, pad=first))
    for a in ADDRESSES:
        raws.append(_hello(a, ADDRESSES[1], 1, 2, 3, 4, 1, b"\x16\x03\x01\x00"))
    full = _hello(ADDRESSES[5], ADDRESSES[6], 443, 80, 1, 10, 1, b"0123456789")
    # The previous release's record (IPv4 addresses, 2068 bytes) and others too short.
    raws += [full[:n] for n in (0, 43, 44, 2068, 2091)] + [full + b"\x01\x02\x03"]
    for _ in range(120):
        size = rng.choice([2092, 2092, 2100, rng.randrange(2080, 2110)])
        raws.append(bytes(rng.randrange(256) for _ in range(size)))
    for raw in raws:
        case = {"kind": "hello", "raw": raw.hex()}
        try:
            seg = xdp.HelloSegment.from_bytes(raw)
        except Exception as exc:  # noqa: BLE001
            case["error"] = _error(exc)
        else:
            case["hello"] = {"saddr": seg.saddr, "daddr": seg.daddr, "sport": seg.sport, "dport": seg.dport,
                             "seq": seg.seq, "first": seg.first, "payload": seg.payload.hex()}
        _record(case)


# --- the event file -----------------------------------------------------------------

def test_event_file():
    lines = ['{"ts": 1.0, "action": "drop"}', "", "x" * 100, '{"sni": "\\u00e9"}', "é" * 10]
    shapes = [
        ("empty", None, 4 * 1024 * 1024, lines),
        ("holds something", b"old line\n", 4 * 1024 * 1024, lines),
        ("too big at once", b"y" * 50, 60, lines),
        ("fills up", None, 120, lines * 3),
        ("exactly full", None, len(lines[0]) + 1 + len(lines[2]) + 1, [lines[0], lines[2], lines[1]]),
        ("one line too big", None, 10, ["x" * 20, "ab"]),
        ("zero", None, 0, ["a", ""]),
        ("mode", None, 1000, ["a"]),
    ]
    with tempfile.TemporaryDirectory() as tmp:
        for name, initial, max_bytes, written in shapes:
            path = Path(tmp) / name
            if initial is not None:
                path.write_bytes(initial)
                os.chmod(path, 0o666 if name != "holds something" else 0o600)
            ef = xdp.EventFile(path, max_bytes=max_bytes)
            for line in written:
                ef.write_line(line)
            ef.close()
            _record({"kind": "eventfile", "name": name, "initial": None if initial is None else initial.hex(),
                     "max_bytes": max_bytes, "lines": written, "content": path.read_bytes().hex(),
                     "mode": oct(path.stat().st_mode & 0o7777)})
