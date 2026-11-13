"""FR_OS 1.x's TLS client fingerprinting library (frfw.tlsfp, phase 19)
fed every shape of input, recorded for FR_OS 2's crates/fros-tlsfp
(tlsfp.jsonl; reference/generate.sh runs this module).

The input is bytes any LAN host sends, so the cases go well past what a
well-behaved TLS library writes: every prefix of a hello, hellos with
each length field off by one, extensions with odd bodies, thousands of
seeded random mutations, record streams split and mangled every way, the
reassembler fed segments in and out of order with gaps, retransmits,
wrapped sequence numbers, expiry and eviction, and the inventory driven
through its learning period, its limits and state files both valid and
broken. Each case is what 1.x answered: the parsed fields and the
fingerprints, or the exact ParseError text; for a state file, what
json.dumps writes for the inventory restored from it, or the type of
the exception 1.x raised. Nothing here asserts anything about 1.x.

The hellos are built here from RFC 8446 structures, as 1.x's own
tests/tlsfp_samples.py does: no captured traffic from third parties.
"""

from __future__ import annotations

import json
import random
import struct
import sys
import tempfile
from pathlib import Path

from frfw.tlsfp.clienthello import ParseError, handshake_from_records, is_grease, parse_client_hello
from frfw.tlsfp.daemon import _read_json
from frfw.tlsfp.fingerprint import ja3, ja3_string, ja4, ja4_parts
from frfw.tlsfp.inventory import (
    LEARNING_SECONDS,
    MAX_CLIENTS,
    MAX_EVENTS,
    MAX_FINGERPRINTS_PER_CLIENT,
    MAX_NETWORK_FINGERPRINTS,
    FingerprintInventory,
)
from frfw.tlsfp.reassembly import MAX_FLOWS, Reassembler

T0 = 1_700_000_000.0
GREASE = 0x3A3A
CHROME_LIKE_CIPHERS = [GREASE, 0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030,
                       0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035]
SIGALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]


def _record(case: dict) -> None:
    capture = sys.modules.get("fros_capture")
    if capture is not None:
        capture._record("tlsfp", case)


# --- building hellos ------------------------------------------------------------------------------


def _u16(v: int) -> bytes:
    return struct.pack("!H", v & 0xFFFF)


def _vec16(data: bytes) -> bytes:
    return _u16(len(data)) + data


def _ext(ext_type: int, body: bytes) -> bytes:
    return _u16(ext_type) + _vec16(body)


def _sni(name: bytes, name_type: int = 0) -> bytes:
    return _ext(0x0000, _vec16(bytes([name_type]) + _vec16(name)))


def _alpn(protocols) -> bytes:
    return _ext(0x0010, _vec16(b"".join(bytes([len(p)]) + p for p in protocols)))


def _extensions(sni: bytes | None = b"example.com", alpn=(b"h2", b"http/1.1"), pq: bool = True,
                grease: bool = True) -> list[bytes]:
    exts = []
    if sni is not None:
        exts.append(_sni(sni))
    if grease:
        exts.append(_ext(GREASE, b""))
    groups = ([GREASE] if grease else []) + ([0x11EC] if pq else []) + [0x001D, 0x0017, 0x0018]
    versions = ([GREASE] if grease else []) + [0x0304, 0x0303]
    exts += [
        _ext(0x0017, b""),
        _ext(0xFF01, b"\x00"),
        _ext(0x000A, _vec16(b"".join(_u16(g) for g in groups))),
        _ext(0x000B, b"\x01\x00"),
        _ext(0x0023, b""),
        _ext(0x000D, _vec16(b"".join(_u16(s) for s in SIGALGS))),
        _ext(0x002B, bytes([2 * len(versions)]) + b"".join(_u16(v) for v in versions)),
        _ext(0x002D, b"\x01\x01"),
    ]
    if alpn:
        exts.append(_alpn(alpn))
    if pq:
        exts.append(_ext(0xFE0D, bytes(250)))
    shares = (_u16(GREASE) + _vec16(b"\x00") if grease else b"")
    if pq:
        shares += _u16(0x11EC) + _vec16(bytes(1216))
    shares += _u16(0x001D) + _vec16(bytes(32))
    exts.append(_ext(0x0033, _vec16(shares)))
    return exts


def _hello(extensions: list[bytes] | None, ciphers=CHROME_LIKE_CIPHERS, legacy_version=0x0303,
           session_id: bytes = bytes(32), compression: bytes = b"\x00") -> bytes:
    """The handshake message (type byte first); `extensions` None leaves
    the extensions block out entirely."""
    body = (
        _u16(legacy_version) + bytes(range(32)) + bytes([len(session_id)]) + session_id
        + _vec16(b"".join(_u16(c) for c in ciphers)) + bytes([len(compression)]) + compression
    )
    if extensions is not None:
        body += _vec16(b"".join(extensions))
    return b"\x01" + struct.pack("!I", len(body))[1:] + body


def _records(message: bytes, record_size: int = 16384, version: int = 0x0301) -> bytes:
    out = b""
    for i in range(0, len(message), record_size):
        chunk = message[i:i + record_size]
        out += b"\x16" + _u16(version) + _u16(len(chunk)) + chunk
    return out


# --- recording -------------------------------------------------------------------------------------


def _hello_case(message: bytes) -> None:
    case: dict = {"op": "hello", "input": message.hex()}
    try:
        hello = parse_client_hello(message)
    except ParseError as exc:
        case.update(ok=False, error=str(exc))
        _record(case)
        return
    a, b, c = ja4_parts(hello)
    case.update(
        ok=True,
        hello={
            "legacy_version": hello.legacy_version,
            "ciphers": hello.ciphers,
            "extensions": hello.extensions,
            "supported_groups": hello.supported_groups,
            "ec_point_formats": hello.ec_point_formats,
            "signature_algorithms": hello.signature_algorithms,
            "supported_versions": hello.supported_versions,
            "alpn": [p.hex() for p in hello.alpn],
            "server_name": hello.server_name,
        },
        ja3_string=ja3_string(hello),
        ja3=ja3(hello),
        ja4_parts=[a, b, c],
        ja4={t: ja4(hello, t) for t in ("t", "q", "d")},
    )
    _record(case)


def _records_case(stream: bytes) -> None:
    case: dict = {"op": "records", "input": stream.hex()}
    try:
        message = handshake_from_records(stream)
    except ParseError as exc:
        case.update(ok=False, error=str(exc))
    else:
        case.update(ok=True, message=None if message is None else message.hex())
    _record(case)


def _mutations(rng: random.Random, message: bytes, count: int):
    for i in range(count):
        data = bytearray(message)
        if i % 3 == 0:
            data = data[: rng.randrange(1, len(data))]
        for _ in range(rng.randint(1, 6)):
            if data:
                data[rng.randrange(len(data))] = rng.randrange(256)
        if i % 7 == 0 and data:
            pos = rng.randrange(len(data))
            data[pos:pos] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 8)))
        yield bytes(data)


# --- the cases -------------------------------------------------------------------------------------


def test_grease():
    _record({"op": "grease", "values": [v for v in range(0x10000) if is_grease(v)]})


def test_hellos():
    spec_ciphers = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8,
                    0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035]
    spec_exts = [0x001B, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002D, 0x000D, 0x0005,
                 0x0023, 0x0012, 0x002B, 0xFF01, 0x000B, 0x000A, 0x0015]
    bodies = {
        0x0000: b"\x00\x0e\x00\x00\x0bexample.com",
        0x0010: b"\x00\x03\x02h2",
        0x002B: b"\x02\x03\x04",
        0x000D: _vec16(b"".join(_u16(s) for s in SIGALGS)),
    }
    shuffled = list(spec_exts)
    random.Random(4).shuffle(shuffled)
    for order in (spec_exts, shuffled):
        _hello_case(_hello([_ext(t, bodies.get(t, b"")) for t in order], ciphers=spec_ciphers))
    _hello_case(_hello([_ext(0x2A2A, b"")] + [_ext(t, bodies.get(t, b"")) for t in spec_exts],
                       ciphers=[0x9A9A] + spec_ciphers))
    # JA3's published example.
    _hello_case(_hello([_ext(0x0000, b"\x00\x0e\x00\x00\x0bexample.com"),
                        _ext(0x000A, b"\x00\x06\x00\x17\x00\x18\x00\x19"), _ext(0x000B, b"\x01\x00")],
                       ciphers=[47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4], legacy_version=0x0301))

    # ALPN first/last characters, versions, SNI, GREASE on and off.
    for alpn in [(b"h2",), (b"http/1.1",), (), (b"",), (b"x",), (b"\xab",), (b"\x20",), (b"\xab\xcd",),
                 (b"\x30\xab",), (b"\x30\x31\xab\xcd",), (b"\x30\xab\xcd\x31",), (b"Az",), (b"a\x7f",),
                 (b"\x00\x00",), (b"\x80z",), (b"", b"h2"), (b"h3", b"h2"), (b"9-",), (b"_a_",), (b"\xff" * 255,)]:
        for pq in (False, True):
            _hello_case(_hello(_extensions(alpn=alpn, pq=pq)))
    for sni in [None, b"", b"a", b"example.com", b"\xc3\xa9t\xc3\xa9.example", b"\x00\x01\x7f\x80\xff",
                b"x" * 300, b"UPPER.Example.COM"]:
        _hello_case(_hello(_extensions(sni=sni, pq=False)))
    for grease in (False, True):
        _hello_case(_hello(_extensions(pq=False, grease=grease)))
    for version in (0x0300, 0x0301, 0x0302, 0x0303, 0x0304, 0x0002, 0xFEFF, 0xFEFD, 0xFEFC, 0x0305, 0x0000,
                    0xFFFF, 0x0A0A):
        _hello_case(_hello([], ciphers=[0x002F], legacy_version=version))
        _hello_case(_hello([_ext(0x002B, b"\x02" + _u16(version))], ciphers=[0x002F]))
    _hello_case(_hello([_ext(0x002B, b"\x04\x0a\x0a\x1a\x1a")], ciphers=[0x002F]))       # only GREASE
    _hello_case(_hello([_ext(0x002B, b"\x06\x03\x02\x03\x04\x03\x03")], ciphers=[0x002F]))  # max, not first
    _hello_case(_hello(None, ciphers=[0x002F]))                                             # no extensions block
    _hello_case(_hello(None, ciphers=[]))
    _hello_case(_hello([], ciphers=[]))
    _hello_case(_hello([], ciphers=[GREASE, 0x0A0A]))
    _hello_case(_hello([], ciphers=list(range(1, 200))))                                    # > 99 ciphers
    _hello_case(_hello([_ext(0x1000 + i, b"") for i in range(120)], ciphers=[0x002F]))     # > 99 extensions
    _hello_case(_hello([_ext(0x1000 + i, b"") for i in range(256)], ciphers=[0x002F]))
    _hello_case(_hello([_ext(0x1000 + i, b"") for i in range(257)], ciphers=[0x002F]))     # too many
    _hello_case(_hello([_ext(0x0000, b""), _ext(0x0000, b"")], ciphers=[0x002F]))          # duplicates
    _hello_case(_hello([_sni(b"first.example"), _sni(b"second.example")], ciphers=[0x002F]))
    _hello_case(_hello([_ext(0x0000, _vec16(b"\x01" + _vec16(b"host") + b"\x00" + _vec16(b"name")))],
                       ciphers=[0x002F]))                                                   # non-zero type first
    _hello_case(_hello([_ext(0x0000, _vec16(b"\x00" + _vec16(b"a") + b"\x00" + _vec16(b"b")))],
                       ciphers=[0x002F]))                                                   # two host names
    _hello_case(_hello([_ext(0x0000, _vec16(b"\x00" + _vec16(b"a")) + b"junk")], ciphers=[0x002F]))
    _hello_case(_hello([_ext(0x0000, _vec16(b"\x00" + _u16(10) + b"abc"))], ciphers=[0x002F]))
    _hello_case(_hello([_ext(0x0000, _sni(b"a.example")[4:] + b"x")], ciphers=[0x002F]))
    _hello_case(_hello([_ext(0x0010, b""), _ext(0x0010, _vec16(b"\x00"))], ciphers=[0x002F]))
    _hello_case(_hello([_ext(0x0010, _vec16(b"\x05ab"))], ciphers=[0x002F]))               # bad inner length
    _hello_case(_hello([_ext(0x000A, b"\x00\x03\x00\x17\x00")], ciphers=[0x002F]))         # odd group list
    _hello_case(_hello([_ext(0x000A, b"")], ciphers=[0x002F]))
    _hello_case(_hello([_ext(0x000A, b"\x00\x04\x00\x17\x00\x18trailing")], ciphers=[0x002F]))
    _hello_case(_hello([_ext(0x000D, b"\x00\x01\x04")], ciphers=[0x002F]))
    _hello_case(_hello([_ext(0x000D, b"\x00\x02\x0a\x0a"), _ext(0x0000, _sni(b"g")[4:])], ciphers=[0x002F]))
    _hello_case(_hello([_ext(0x000B, b"")], ciphers=[0x002F]))
    _hello_case(_hello([_ext(0x000B, b"\x03\x00\x01\x02")], ciphers=[0x002F]))
    _hello_case(_hello([_ext(0x000B, b"\x05\x00")], ciphers=[0x002F]))
    _hello_case(_hello([_ext(0x002B, b"\x03\x03\x04\x03")], ciphers=[0x002F]))             # odd versions
    _hello_case(_hello([_ext(0x002B, b"")], ciphers=[0x002F]))
    _hello_case(_hello([_ext(0x000A, b"\x00\x02\x00\x17"), _ext(0x000A, b"\x00\x02\x00\x18")], ciphers=[0x002F]))
    _hello_case(_hello([], ciphers=[0x002F], session_id=b""))
    _hello_case(_hello([], ciphers=[0x002F], session_id=bytes(255)))
    _hello_case(_hello([], ciphers=[0x002F], compression=b""))
    _hello_case(_hello([], ciphers=[0x002F], compression=b"\x01\x00"))

    # Broken outer structure.
    good = _hello(_extensions(pq=False))
    for message in [b"", b"\x01", b"\x02" + good[1:], b"\x01\x00\x00", b"\x01\x00\x00\x00",
                    b"\x01\x00\x00\x02\x03\x03", good[:4] + good[4:-1], good + b"\x00",
                    good[:1] + struct.pack("!I", len(good) - 3)[1:] + good[4:],
                    good[:1] + struct.pack("!I", len(good) + 5)[1:] + good[4:],
                    _hello([], ciphers=[0x002F]) + b"trailing",
                    ]:
        _hello_case(message)
    body = good[4:]
    for at in (2 + 32, 2 + 32 + 33, 2 + 32 + 33 + 2 + 2 * len(CHROME_LIKE_CIPHERS)):
        for delta in (-1, 1, 200):
            mangled = bytearray(body)
            mangled[at] = (mangled[at] + delta) % 256
            _hello_case(good[:4] + bytes(mangled))
    # The extensions block's own length, and a trailing byte after it.
    ext_at = 2 + 32 + 33 + 2 + 2 * len(CHROME_LIKE_CIPHERS) + 2
    for delta in (-1, 1):
        mangled = bytearray(body)
        n = struct.unpack("!H", mangled[ext_at:ext_at + 2])[0] + delta
        mangled[ext_at:ext_at + 2] = _u16(n)
        _hello_case(good[:4] + bytes(mangled))
    longer = body + b"\x00"
    _hello_case(b"\x01" + struct.pack("!I", len(longer))[1:] + longer)
    # Every prefix of a small hello.
    small = _hello([_sni(b"a.example"), _alpn([b"h2"]), _ext(0x002B, b"\x02\x03\x04")], ciphers=[0x1301, 0x002F])
    for n in range(len(small) + 1):
        _hello_case(small[:n])
        inner = small[:n]
        _hello_case(b"\x01" + struct.pack("!I", max(len(inner) - 4, 0))[1:] + inner[4:])

    # Seeded random damage, on a small hello and on one without PQ.
    rng = random.Random(19)
    for base in (small, _hello(_extensions(pq=False))):
        for message in _mutations(rng, base, 1500):
            _hello_case(message)
    rng = random.Random(20)
    for _ in range(300):
        _hello_case(bytes(rng.randrange(256) for _ in range(rng.randrange(0, 80))))
    for _ in range(200):
        _hello_case(b"\x01" + bytes(rng.randrange(256) for _ in range(rng.randrange(0, 120))))


def test_records():
    message = _hello(_extensions())
    for size in (16384, 1, 2, 3, 4, 5, 100, 500, 1000):
        wire = _records(message, record_size=size)
        _records_case(wire)
        if size >= 100:
            _records_case(wire[:-1])
            _records_case(wire + b"\x17\x03\x03\x00\x01x")
    for version in (0x0300, 0x0301, 0x0303, 0x03FF, 0x0200, 0x0400, 0x0000):
        _records_case(_records(message, version=version))
    small = _hello([_sni(b"a.example")], ciphers=[0x002F])
    wire = _records(small, record_size=7)
    for n in range(len(wire) + 1):
        _records_case(wire[:n])
    for stream in [b"", b"\x16", b"\x16\x03\x01\x00", b"\x16\x03\x01\x00\x00", b"\x16\x03\x01\x00\x00\x01",
                   b"\x17\x03\x03\x00\x10" + bytes(16), b"GET / HTTP/1.1\r\n", b"\x16\x03\x03\x00\x04\x02\x00\x00\x00",
                   b"\x16\x03\x03\x00\x04\x02", b"\x16\x03\x03\x00\x04\x01", b"\x16\x03\x03\x00\x01\x02",
                   b"\x16\x03\x01\x48\x01" + b"\x01", b"\x16\x03\x01\x48\x00" + b"\x01", b"\x16\x03\x01\x48\x00",
                   b"\x16\x03\x01\x47\xff" + b"\x02", b"\x16\x02\x01\x00\x04\x01\x00\x00\x00",
                   b"\x16\x03\x01\x00\x04\x01\x00\x00\x00", b"\x16\x03\x01\x00\x04\x01\x00\x40\x00",
                   b"\x16\x03\x01\x00\x04\x01\x00\x3f\xfc" + b"\x16\x03\x01\x00\x01\x00",
                   b"\x16\x03\x01\x00\x04\x01\x00\x3f\xfd",
                   b"\x16\x03\x01\x00\x02\x01\x00" + b"\x16\x03\x01\x00\x02\x00\x05" + bytes(5),
                   b"\x16\x03\x01\x00\x02\x01\x00" + b"\x17\x03\x01\x00\x02\x00\x05",
                   b"\x16\x03\x01\x00\x01\x02" + b"\x16\x03\x01\x00\x03\x00\x00\x00",
                   b"\x16\x03\x01\x00\x08\x01\x00\x00\x00\x02\x00\x00\x00",
                   ]:
        _records_case(stream)
    # A handshake message just under and just over the cap.
    for length in (16 * 1024 - 4, 16 * 1024 - 3):
        big = b"\x01" + struct.pack("!I", length)[1:] + bytes(length)
        _records_case(_records(big))
        _records_case(_records(big)[:9])
    rng = random.Random(21)
    for data in _mutations(rng, _records(small, record_size=20), 800):
        _records_case(data)


def _reassembly(name: str, steps, *, max_flows: int = MAX_FLOWS, timeout: float = 5.0) -> None:
    r = Reassembler(max_flows=max_flows, timeout=timeout)
    recorded = []
    for key, seq, payload, now, first in steps:
        step = {"key": list(key), "seq": seq, "payload": payload.hex(), "now": now, "first": first}
        try:
            result = r.add(key, seq, payload, now, first=first)
        except ParseError as exc:
            step["error"] = str(exc)
        else:
            step["result"] = None if result is None else result.hex()
        step["len"] = len(r)
        recorded.append(step)
    _record({"op": "reassembly", "name": name, "max_flows": max_flows, "timeout": timeout, "steps": recorded})


def _segments(wire: bytes, size: int, isn: int):
    return [((isn + i) & 0xFFFFFFFF, wire[i:i + size]) for i in range(0, len(wire), size)]


def test_reassembly():
    key = ("10.0.0.5", 50000, "1.2.3.4", 443)
    other = ("10.0.0.6", 50001, "1.2.3.4", 443)
    message = _hello(_extensions())
    wire = _records(message)
    for size in (700, 1460, 100):
        for isn in (0, 0xFFFFFF00, 1000):
            segs = _segments(wire, size, isn)
            first, rest = segs[0], segs[1:]
            forward = [(key, first[0], first[1], T0, True)] + [(key, s, c, T0, False) for s, c in rest]
            _reassembly(f"forward/{size}/{isn}", forward)
            backward = [(key, first[0], first[1], T0, True)] + [(key, s, c, T0, False) for s, c in reversed(rest)]
            _reassembly(f"backward/{size}/{isn}", backward)
            doubled = [(key, first[0], first[1], T0, True)]
            for s, c in rest:
                doubled += [(key, s, c, T0, False), (key, s, c, T0, False)]
            _reassembly(f"retransmit/{size}/{isn}", doubled)
    # Overlapping segments with different contents: the first one stays.
    segs = _segments(wire, 1000, 5000)
    overlap = [(key, segs[0][0], segs[0][1], T0, True),
               (key, segs[1][0] - 10, bytes(10) + segs[1][1], T0, False),
               (key, segs[1][0], b"\xff" * len(segs[1][1]), T0, False)]
    overlap += [(key, s, c, T0, False) for s, c in segs[2:]]
    _reassembly("overlap", overlap)
    # Gaps, unknown flows, a segment far ahead, expiry, a restart of the flow.
    _reassembly("gap", [(key, 100, wire[:500], T0, True), (key, 1100, wire[1000:], T0, False),
                        (key, 600, wire[500:1000], T0 + 1, False)])
    _reassembly("unknown flow", [(key, 100, b"\x00" * 10, T0, False)])
    _reassembly("far ahead", [(key, 100, wire[:500], T0, True), (key, 100 + 16 * 1024 + 19, b"x", T0, False),
                              (key, 100 + 16 * 1024 + 20, b"x", T0, False), (key, 99, b"x", T0, False),
                              (key, 600, wire[500:], T0, False)])
    _reassembly("expired", [(key, 100, wire[:500], T0, True), (key, 600, wire[500:], T0 + 10, False)])
    _reassembly("timeout edge", [(key, 100, wire[:500], T0, True), (key, 600, wire[500:], T0 + 5, False)])
    _reassembly("timeout edge+", [(key, 100, wire[:500], T0, True), (key, 600, wire[500:], T0 + 5.0001, False)])
    _reassembly("restart", [(key, 100, wire[:500], T0, True), (key, 7000, wire[:300], T0 + 1, True),
                            (key, 7300, wire[300:], T0 + 1, False)])
    _reassembly("eviction", [(("10.0.0.6", p, "1.2.3.4", 443), 1, wire[:500], T0 + p, True) for p in range(5)]
                + [(("10.0.0.6", 4, "1.2.3.4", 443), 501, wire[500:], T0 + 5, False),
                   (("10.0.0.6", 0, "1.2.3.4", 443), 501, wire[500:], T0 + 5, False)],
                max_flows=2, timeout=5)
    _reassembly("eviction ties", [(("10.0.0.6", p, "1.2.3.4", 443), 1, wire[:500], T0, True) for p in range(4)]
                + [(("10.0.0.6", p, "1.2.3.4", 443), 501, wire[500:], T0, False) for p in range(4)],
                max_flows=2, timeout=5)
    _reassembly("replace keeps place", [(key, 1, wire[:500], T0 + 3, True), (other, 1, wire[:500], T0 + 1, True),
                                        (key, 1, wire[:500], T0 + 1, True),
                                        (("10.0.0.9", 1, "1.2.3.4", 443), 1, wire[:500], T0 + 2, True),
                                        (key, 501, wire[500:], T0 + 2, False),
                                        (other, 501, wire[500:], T0 + 2, False)], max_flows=2)
    _reassembly("not tls", [(key, 1, b"GET / HTTP/1.1\r\n", T0, True), (key, 17, b"Host: x\r\n", T0, False)])
    _reassembly("not a hello", [(key, 1, b"\x16\x03\x01\x00\x04\x02\x00\x00\x00", T0, True)])
    _reassembly("bad later", [(key, 1, wire[:500], T0, True), (key, 1, wire[:500], T0, True),
                              (key, 501, b"\x17" * 10, T0, False)])
    _reassembly("small records", [(key, 1, _records(message, record_size=50)[:900], T0, True),
                                  (key, 901, _records(message, record_size=50)[900:], T0, False)])
    _reassembly("empty payloads", [(key, 1, b"", T0, True), (key, 1, wire[:10], T0, False),
                                   (key, 11, wire[10:], T0, False)])
    _reassembly("oversized payload", [(key, 1, wire + bytes(20000), T0, True)])
    big = b"\x01" + struct.pack("!I", 16 * 1024 - 4)[1:] + bytes(16 * 1024 - 4)
    big_wire = _records(big)
    _reassembly("cap", [(key, 1, big_wire[:16 * 1024], T0, True),
                        (key, 1 + 16 * 1024, big_wire[16 * 1024:], T0, False)])
    rng = random.Random(22)
    for n in range(30):
        segs = _segments(wire, rng.choice([50, 300, 700, 1460]), rng.randrange(0x100000000))
        steps = [(key, segs[0][0], segs[0][1], T0, True)]
        rest = segs[1:]
        rng.shuffle(rest)
        for s, c in rest:
            if rng.random() < 0.1:
                c = bytes(rng.randrange(256) for _ in range(len(c)))
            if rng.random() < 0.05:
                continue
            steps.append((key, s, c, T0 + rng.random(), rng.random() < 0.02))
        _reassembly(f"random/{n}", steps)


def _dump(inventory: FingerprintInventory, now: float) -> str:
    return json.dumps(inventory.snapshot(now))


def _inventory(name: str, started: float, steps) -> None:
    inv = FingerprintInventory(started=started)
    recorded = []
    for step in steps:
        kind, *args = step
        if kind == "observe":
            recorded.append({"observe": list(args), "result": inv.observe(*args)})
        elif kind == "event":
            inv.add_event(args[0])
            recorded.append({"event": args[0]})
        elif kind == "learning":
            recorded.append({"learning": args[0], "result": inv.learning(args[0])})
        else:
            recorded.append({"snapshot": args[0], "json": _dump(inv, args[0])})
    _record({"op": "inventory", "name": name, "started": started, "steps": recorded})


def test_inventory():
    later = T0 + LEARNING_SECONDS
    _inventory("learning", T0, [
        ("observe", "10.0.0.5", "t13d_a", "j1", "a.example", T0),
        ("learning", T0), ("learning", later - 0.5), ("learning", later),
        ("observe", "10.0.0.6", "t13d_a", "j1", None, later),
        ("observe", "10.0.0.6", "t13d_b", "j2", None, later - 0.001),
        ("observe", "10.0.0.6", "t13d_c", "j2", None, later),
        ("observe", "10.0.0.6", "t13d_c", "j3", "", later + 1),
        ("observe", "10.0.0.6", "t13d_c", "j2", "b.example", later + 2),
        ("snapshot", later + 3),
    ])
    steps = []
    for i in range(12):
        steps.append(("observe", "10.0.0.7", "fp", f"j{i % 10}", f"s{i % 7}.example", T0 + i))
    steps.append(("snapshot", T0 + 20))
    _inventory("remember limits", T0, steps)
    steps = [("observe", "10.0.0.7", f"fp{i}", "j", None, later + i) for i in range(MAX_FINGERPRINTS_PER_CLIENT + 3)]
    steps += [("observe", "10.0.0.7", "fp5", "j", None, later + 100),
              ("observe", "10.0.0.7", "fp-new", "j", None, later + 101), ("snapshot", later + 200)]
    _inventory("per-client limit", T0, steps)
    steps = [("observe", f"10.{i // 256}.{i % 256}.1", "fp", "j", None, T0 + (i % 50)) for i in range(MAX_CLIENTS + 5)]
    steps += [("observe", "10.250.0.1", "fp", "j", None, T0 + 1), ("snapshot", T0 + 100)]
    _inventory("client limit", T0, steps)
    steps = [("observe", "10.0.0.1", f"n{i}", "j", None, T0 + (i % 997)) for i in range(MAX_NETWORK_FINGERPRINTS + 3)]
    steps += [("observe", "10.0.0.2", "n0", "j", None, later + 1), ("observe", "10.0.0.2", "n-new", "j", None, later + 1),
              ("snapshot", later + 2)]
    _inventory("network limit", T0, steps)
    steps = [("event", {"type": "new_fingerprint", "client": "10.0.0.5", "n": i, "f": i / 3, "u": "é\u2028\U0001F600"})
             for i in range(MAX_EVENTS + 4)]
    steps += [("event", {}), ("event", {"nested": [1, 2.5, None, True, {"x": [1e16, 1e-5, -0.0, 0.0001]}]}),
              ("snapshot", T0)]
    _inventory("events", T0, steps)
    _inventory("odd values", T0, [
        ("observe", "", "", "", "", T0), ("observe", "c\u00e9\n\"\\", "ja4\x00\x7f", "ja3\t", "sni\U0001F600", T0 + 0.1),
        ("observe", "10.0.0.5", "fp", "j", None, float("inf")), ("snapshot", T0 + 1e-7), ("snapshot", 1e22),
        ("snapshot", 123456789012345678.0), ("snapshot", 0.0), ("snapshot", -1.5),
    ])
    _inventory("odd start", float("nan"), [("observe", "a", "b", "c", "d", T0), ("learning", T0), ("snapshot", T0)])
    _inventory("odd start inf", float("-inf"), [("observe", "a", "b", "c", "d", T0), ("snapshot", T0)])


def _restore(name: str, raw: bytes, now: float = T0 + 10) -> None:
    case: dict = {"op": "restore", "name": name, "file": raw.hex(), "now": now}
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "tls_fingerprints.json"
        path.write_bytes(raw)
        try:
            inventory = FingerprintInventory.restore(_read_json(path), now)
            case["json"] = _dump(inventory, now)
        except Exception as exc:  # noqa: BLE001 -- what 1.x does is the point
            case["crash"] = type(exc).__name__
    _record(case)


def test_restore():
    inv = FingerprintInventory(started=T0)
    later = T0 + LEARNING_SECONDS + 5
    for i in range(6):
        inv.observe(f"10.0.0.{i % 3}", f"t13d_{i % 4}", f"j{i}", f"s{i}.example" if i % 2 else None, later + i)
    inv.add_event({"type": "new_fingerprint", "ja4": "t13d_9", "time": later})
    good = inv.snapshot(later + 10)
    good["stats"] = {"hellos": 6}
    text = json.dumps(good)
    _restore("round trip", text.encode())
    _restore("indented", json.dumps(good, indent=2).encode())

    def variant(name, mutate):
        data = json.loads(text)
        mutate(data)
        _restore(name, json.dumps(data).encode())

    for value_name, value in [("null", None), ("true", True), ("false", False), ("zero", 0), ("int", 5),
                              ("float", 2.5), ("string", "x"), ("empty string", ""), ("list", [1]),
                              ("empty list", []), ("dict", {"a": 1}), ("empty dict", {})]:
        variant(f"started {value_name}", lambda d, v=value: d.__setitem__("started", v))
        variant(f"clients {value_name}", lambda d, v=value: d.__setitem__("clients", v))
        variant(f"network {value_name}", lambda d, v=value: d.__setitem__("network_first_seen", v))
        variant(f"events {value_name}", lambda d, v=value: d.__setitem__("events", v))
        variant(f"fps {value_name}", lambda d, v=value: d["clients"].__setitem__("10.0.0.1", v))
        variant(f"row {value_name}", lambda d, v=value: d["clients"]["10.0.0.1"].__setitem__("t13d_1", v))
        for field in ("first_seen", "last_seen", "count", "ja3", "sni"):
            variant(f"{field} {value_name}",
                    lambda d, v=value, f=field: d["clients"]["10.0.0.1"]["t13d_1"].__setitem__(f, v))
        variant(f"network ts {value_name}", lambda d, v=value: d["network_first_seen"].__setitem__("t13d_1", v))
        variant(f"event {value_name}", lambda d, v=value: d["events"].append(v))
        variant(f"ja3 item {value_name}",
                lambda d, v=value: d["clients"]["10.0.0.1"]["t13d_1"].__setitem__("ja3", ["a", v, "b"]))
    for field in ("started", "clients", "network_first_seen", "events"):
        variant(f"no {field}", lambda d, f=field: d.pop(f))
    for field in ("first_seen", "last_seen", "count", "ja3", "sni"):
        variant(f"row without {field}", lambda d, f=field: d["clients"]["10.0.0.1"]["t13d_1"].pop(f))
    for text_value in ["12", " 12 ", "1_2", "1__2", "_1", "1_", "-3", "+3", "0x10", "1.5", "1e3", " 1e3\n", "inf",
                       "-Infinity", "nan", "NaN", "1_0.5", "1._5", ".5", "5.", "", " ", "\t7\x0c", "\x1c8\x1f",
                       "\u00a09", "\u0669", "1\u00a0", "e5", "1e", "1e+", "--1", "1 2", "00", "0_0", "9" * 30,
                       "9" * 400, "1e400", "-1e400", "\u2003" + "4"]:
        variant(f"count {text_value!r}",
                lambda d, v=text_value: d["clients"]["10.0.0.1"]["t13d_1"].__setitem__("count", v))
        variant(f"first_seen {text_value!r}",
                lambda d, v=text_value: d["clients"]["10.0.0.1"]["t13d_1"].__setitem__("first_seen", v))
        variant(f"started {text_value!r}", lambda d, v=text_value: d.__setitem__("started", v))
    for number_name, raw_number in [("big int", "1" + "0" * 400), ("int 2^63", str(2 ** 63)), ("int -2^63-1", str(-2 ** 63 - 1)),
                                    ("int 2^64", str(2 ** 64)), ("max float", "1.7976931348623157e308"),
                                    ("over max", "1.7976931348623159e308"), ("NaN", "NaN"), ("Infinity", "Infinity"),
                                    ("-Infinity", "-Infinity"), ("float 1.9", "1.9"), ("float -1.9", "-1.9"),
                                    ("1e18", "1e18"), ("1E5", "1E5"), ("-0", "-0"), ("-0.0", "-0.0"),
                                    ("9.3e18", "9.3e18"), ("1e19", "1e19"),
                                    ("big float int", "1" + "0" * 308 + "1"), ("big float int2", "17976931348623159" + "0" * 292),
                                    ("4300 digits", "1" * 4300), ("4301 digits", "1" * 4301)]:
        for where in ("count", "first_seen", "last_seen", "started", "network", "event", "ja3"):
            data = text.replace('"count": 1', '"count": X', 1) if where == "count" else text
            if where == "count":
                raw = data.replace('"count": X', '"count": ' + raw_number, 1)
            elif where == "first_seen":
                raw = text.replace('"first_seen": ', '"first_seen": ' + raw_number + ', "x": ', 1)
            elif where == "last_seen":
                raw = text.replace('"last_seen": ', '"last_seen": ' + raw_number + ', "x": ', 1)
            elif where == "started":
                raw = text.replace('"started": ', '"started": ' + raw_number + ', "x": ', 1)
            elif where == "network":
                raw = text.replace('"network_first_seen": {', '"network_first_seen": {"zz": ' + raw_number + ', ', 1)
            elif where == "event":
                raw = text.replace('"events": [', '"events": [{"v": ' + raw_number + '}, ', 1)
            else:
                raw = text.replace('"ja3": [', '"ja3": [' + raw_number + ', ', 1)
            _restore(f"{where} {number_name}", raw.encode())
    # JSON text that json.loads refuses, or only Python takes.
    for name, raw in [("empty", b""), ("space", b"  "), ("bom", b"\xef\xbb\xbf" + text.encode()),
                      ("not utf-8", text.encode()[:20] + b"\xff" + text.encode()[20:]),
                      ("truncated", text.encode()[:-3]), ("trailing", text.encode() + b" x"),
                      ("trailing space", text.encode() + b" \n\t\r"), ("top list", b"[1, 2]"), ("top string", b'"x"'),
                      ("top null", b"null"), ("top number", b"12"), ("top NaN", b"NaN"),
                      ("single quotes", b"{'started': 1}"), ("trailing comma", b'{"started": 1,}'),
                      ("leading zero", b'{"started": 01}'), ("plus", b'{"started": +1}'),
                      ("hex", b'{"started": 0x1}'), ("dot", b'{"started": 1.}'), ("dot2", b'{"started": .5}'),
                      ("exp", b'{"started": 1e}'), ("minus", b'{"started": -}'), ("nan lower", b'{"started": nan}'),
                      ("infinity lower", b'{"started": infinity}'), ("-NaN", b'{"started": -NaN}'),
                      ("control char", b'{"started": 1, "x": "a\x01b"}'), ("raw tab", b'{"x": "a\tb", "started": 1}'),
                      ("raw del", b'{"x": "a\x7fb", "started": 1}'), ("bad escape", b'{"x": "\\q", "started": 1}'),
                      ("short u", b'{"x": "\\u12", "started": 1}'), ("pair", b'{"x": "\\ud83d\\ude00", "started": 1}'),
                      ("lone high", b'{"x": "\\ud83d", "started": 1}'), ("lone low", b'{"x": "\\ude00", "started": 1}'),
                      ("lone high in key", b'{"clients": {"\\ud83d": {"f": {"first_seen": 1, "last_seen": 2}}}, "started": 1}'),
                      ("dup keys", b'{"started": 1, "clients": {}, "started": 2}'),
                      ("dup clients", b'{"clients": {"a": {"f": {"first_seen": 1, "last_seen": 1}}, "b": {"f": {"first_seen": 2, "last_seen": 2}}, "a": {"g": {"first_seen": 3, "last_seen": 3}}}, "started": 1}'),
                      ("deep", b'{"x": ' + b"[" * 5000 + b"]" * 5000 + b', "started": 1}'),
                      ("deeper", b'{"x": ' + b"[" * 100000 + b"]" * 100000 + b', "started": 1}'),
                      ("deep 100", b'{"x": ' + b"[" * 100 + b"]" * 100 + b', "started": 1}'),
                      ("whitespace kinds", b'\r\n\t {"started"\t:\r1 }\n'),
                      ("form feed", b'\x0c{"started": 1}'), ("nbsp", b'\xc2\xa0{"started": 1}'),
                      ("escapes", b'{"x": "\\"\\\\\\/\\b\\f\\n\\r\\t\\u00e9\\u0000", "started": 1, "events": [{"e": "\\u2028\\/"}]}'),
                      ("utf-8 raw", '{"events": [{"e": "árvíztűrő 😀"}], "started": 1}'.encode()),
                      ("overlong utf-8", b'{"x": "\xc0\xaf", "started": 1}'),
                      ("surrogate utf-8", b'{"x": "\xed\xa0\x80", "started": 1}'),
                      ("big number key", b'{"started": 1, "network_first_seen": {"a": 1e400, "b": -1e400}}'),
                      ("bool network", b'{"started": 1, "network_first_seen": {"a": true, "b": false, "c": null}}'),
                      ("many clients", ('{"started": 1, "clients": {' + ", ".join(
                          f'"c{i}": {{"f": {{"first_seen": {i}, "last_seen": {i}}}}}' for i in range(MAX_CLIENTS + 10))
                          + "}}").encode()),
                      ("events 300", ('{"started": 1, "events": [' + ", ".join(f'{{"i": {i}}}' for i in range(300)) + "]}").encode()),
                      ("events mixed", b'{"started": 1, "events": [1, "x", {"a": 1}, [], {"b": 2}, null]}'),
                      ("ja3 long", ('{"started": 1, "clients": {"c": {"f": {"first_seen": 1, "last_seen": 1, "ja3": ['
                                    + ", ".join(f'"j{i}"' for i in range(20)) + '], "sni": "abcdefghij"}}}}').encode()),
                      ("ja3 string", b'{"started": 1, "clients": {"c": {"f": {"first_seen": 1, "last_seen": 1, "ja3": "xyz", "sni": {"k1": 1, "k2": 2}}}}}'),
                      ("ja3 numbers", b'{"started": 1, "clients": {"c": {"f": {"first_seen": 1, "last_seen": 1, "ja3": [1, 2.5, 1e16, 1e-5, 0.0001, -0.0, true, false, null, 1e400, NaN, 123456789012345678901234567890]}}}}'),
                      ("ja3 nested", b'{"started": 1, "clients": {"c": {"f": {"first_seen": 1, "last_seen": 1, "ja3": [[1, "a"], {"k": "v"}]}}}}'),
                      ("count forms", b'{"started": 1, "clients": {"c": {"a": {"first_seen": 1, "last_seen": 1, "count": true}, "b": {"first_seen": 1, "last_seen": 1, "count": 2.99}, "d": {"first_seen": 1, "last_seen": 1, "count": -2.99}, "e": {"first_seen": 1, "last_seen": 1, "count": null}}}}'),
                      ("times as strings", b'{"started": "1700000000", "clients": {"c": {"f": {"first_seen": "1.5", "last_seen": " 2 ", "count": "7"}}}}'),
                      ]:
        _restore(name, raw)
    _restore("missing file marker", b'{"started": 5}', now=0.0)
