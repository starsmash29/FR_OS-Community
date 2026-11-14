"""FR_OS 1.x's TLS fingerprinting daemon (frfw.tlsfp.daemon) run on
recorded input, for FR_OS 2 (tlsfpd.jsonl; reference/generate.sh runs
this module). The library under it (parsing, JA3/JA4, reassembly, the
inventory and its state file) is recorded by
reference/test_fros_tlsfp_cases.py; this is what the daemon adds:

- `daemon`: a `TlsFingerprintDaemon` started on a state file (none, a
  good one, a broken one) with the settings it reads from the config
  (`tls_fingerprint.enabled`, `.blocklist`, `.quarantine_on_match` and
  `ai_ids.quarantine_duration_seconds`: the sensor's view), then fed
  `hello_pkts` ring buffer records as the kernel hands them over (whole,
  split over segments, out of order, damaged, short), new settings, and
  flushes of its state file, at recorded clocks. Each quarantine goes
  through 1.x's real helper client to a fake apply-helper on a Unix
  socket that answers with recorded bytes (or isn't there): recorded
  are each request line, the daemon's stats after each record, every
  state file it writes, byte for byte, and an exception it lets through
  (it then dies; one at start is recorded, and the steps are then
  those of a daemon started without the file);
- `client`: the helper client alone (`send_command`) against the same
  fake helper: the request line, and the reply, the error text, or the
  exception it lets through.

The socket's path is recorded as @SOCK@. Nothing here asserts anything
about 1.x.
"""

from __future__ import annotations

import json
import os
import random
import socket
import struct
import sys
import tempfile
import threading
from pathlib import Path
from types import SimpleNamespace

from frfw.config.schema import TlsFingerprintConfig, TlsFingerprintEntry
from frfw.helper import client as helper_client
from frfw.tlsfp import daemon as tlsfp_daemon
from frfw.tlsfp.clienthello import parse_client_hello
from frfw.tlsfp.fingerprint import ja3, ja4
from frfw.tlsfp.inventory import LEARNING_SECONDS
from frfw import xdp

sys.path.insert(0, str(Path(__file__).parent))
from test_fros_tlsfp_cases import _extensions, _hello, _records  # noqa: E402

T0 = 1_700_000_000.0
LATER = T0 + LEARNING_SECONDS + 1
SOCK_DIR = Path(tempfile.mkdtemp(prefix="fros-tlsfpd-"))
SOCK = SOCK_DIR / "apply.sock"
HEADER = struct.Struct("<16s16sHHIHBB")


def _record(case: dict) -> None:
    capture = sys.modules.get("fros_capture")
    if capture is not None:
        capture._record("tlsfpd", case)


def _text(value: str) -> str:
    return value.replace(str(SOCK), "@SOCK@")


# --- the fake apply-helper ----------------------------------------------------------------------


class FakeHelper:
    """Answers one connection with `answer` (bytes), after reading the
    request to its end; None: no socket at all; "file": a regular file
    where the socket should be."""

    def __init__(self, answer):
        self.answer = answer
        self.request = None
        self._thread = None
        self._server = None

    def __enter__(self):
        if SOCK.exists():
            SOCK.unlink()
        if self.answer == "file":
            SOCK.write_text("")
        elif self.answer is not None:
            self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._server.bind(str(SOCK))
            self._server.listen(1)
            self._thread = threading.Thread(target=self._serve)
            self._thread.start()
        return self

    def _serve(self):
        conn, _ = self._server.accept()
        with conn:
            data = b""
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                data += chunk
            self.request = data.decode("utf-8", "surrogateescape")
            try:
                conn.sendall(self.answer)
            except OSError:
                pass

    def __exit__(self, *_exc):
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._server.close()
        if SOCK.exists():
            SOCK.unlink()


def _answer_json(answer):
    if answer is None or answer == "file":
        return answer
    return answer.hex()


# --- ring buffer records ----------------------------------------------------------------------------


def _addr(text: str) -> bytes:
    if ":" in text:
        return socket.inet_pton(socket.AF_INET6, text)
    return b"\x00" * 10 + b"\xff\xff" + socket.inet_aton(text)


def _rec(saddr, sport, seq, payload: bytes, first: bool, daddr="93.184.216.34", dport=443,
         length=None) -> bytes:
    """A hello_pkts record as the kernel hands it over (2092 bytes)."""
    n = len(payload) if length is None else length
    body = payload[:2048].ljust(2048, b"\x00")
    return HEADER.pack(_addr(saddr), _addr(daddr), sport, dport, seq & 0xFFFFFFFF, n, int(first), 0) + body


def _segments(saddr, sport, isn, wire: bytes, size: int = 2048):
    """The records of one hello's wire bytes, cut at `size`."""
    out = []
    for i in range(0, len(wire), size):
        out.append(_rec(saddr, sport, isn + i, wire[i:i + size], i == 0))
    return out


def _wire(**kw) -> bytes:
    return _records(_hello(_extensions(**kw)))


def _fps(wire: bytes) -> tuple[str, str]:
    hello = parse_client_hello(wire[5:])
    return ja4(hello), ja3(hello)


# --- recording the daemon -----------------------------------------------------------------------------


def _config(view: dict):
    return SimpleNamespace(
        tls_fingerprint=TlsFingerprintConfig(
            enabled=view["enabled"],
            blocklist=[TlsFingerprintEntry(e["fingerprint"], e["label"]) for e in view["blocklist"]],
            quarantine_on_match=view["quarantine_on_match"],
        ),
        ai_ids=SimpleNamespace(quarantine_duration_seconds=view["quarantine_duration_seconds"]),
    )


def _view(blocklist=(), quarantine=False, duration=7200, enabled=True) -> dict:
    return {"enabled": enabled, "blocklist": [{"fingerprint": f, "label": l} for f, l in blocklist],
            "quarantine_on_match": quarantine, "quarantine_duration_seconds": duration}


def _daemon(name: str, view: dict, steps, *, state: bytes | None = None, answers=()) -> None:
    answers = list(answers)
    clock = [T0]
    calls = []

    def quarantine(ip, duration):
        answer = answers.pop(0) if answers else b'{"ok": true}\n'
        with FakeHelper(answer) as fake:
            try:
                return helper_client.quarantine_ip(ip, duration, socket_path=SOCK)
            finally:
                calls.append({"answer": _answer_json(answer), "request": fake.request})

    case: dict = {"op": "daemon", "name": name, "view": view, "state": None if state is None else state.hex(),
                  "start": clock[0], "steps": []}
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "tls_fingerprints.json"
        if state is not None:
            path.write_bytes(state)
        def start():
            return tlsfp_daemon.TlsFingerprintDaemon(_config(view), state_path=path, quarantine_fn=quarantine,
                                                     clock=lambda: clock[0])

        try:
            d = start()
        except Exception as exc:  # noqa: BLE001 -- what 1.x does is the point
            # 1.x dies, and keeps dying on the same file. The steps are
            # then those of a daemon started without it (FR_OS 2 puts
            # the file aside and starts afresh: decisions.md).
            case["crash"] = type(exc).__name__
            path.unlink()
            d = start()
        for step in steps:
            kind, *args = step
            if kind == "record":
                now, raw = args
                clock[0] = now
                start = len(calls)
                out = {"record": raw.hex(), "now": now}
                try:
                    segment = xdp.HelloSegment.from_bytes(raw)
                except xdp.XdpError:
                    segment = None  # the ring buffer reader drops it
                try:
                    if segment is not None:
                        d.handle_segment(segment)
                except Exception as exc:  # noqa: BLE001
                    out["crash"] = type(exc).__name__
                    out["quarantine"] = calls[start:]
                    case["steps"].append(out)
                    break
                out["quarantine"] = calls[start:]
                out["stats"] = dict(d.stats)
                case["steps"].append(out)
            elif kind == "view":
                d.update_config(_config(args[0]))
                case["steps"].append({"view": args[0]})
            else:  # write
                clock[0] = args[0]
                d.write_state()
                case["steps"].append({"write": args[0], "file": path.read_text()})
    _record(json.loads(_text(json.dumps(case))))


A_WIRE = _wire(sni=b"a.example")
B_WIRE = _wire(sni=b"b.example", alpn=(b"http/1.1",), pq=False)
C_WIRE = _wire(sni=None, grease=False)
A_JA4, A_JA3 = _fps(A_WIRE)
B_JA4, B_JA3 = _fps(B_WIRE)
C_JA4, C_JA3 = _fps(C_WIRE)


def test_learning_and_new():
    steps = []
    for i, ip in enumerate(["10.0.0.5", "10.0.0.6", "fd00::5"]):
        steps += [("record", T0 + i, r) for r in _segments(ip, 40000 + i, 1000 * i, A_WIRE)]
    steps.append(("write", T0 + 10))
    steps += [("record", LATER, r) for r in _segments("10.0.0.5", 41000, 7, B_WIRE)]
    steps += [("record", LATER + 1, r) for r in _segments("10.0.0.7", 41001, 7, B_WIRE)]
    steps += [("record", LATER + 2, r) for r in _segments("10.0.0.7", 41002, 7, C_WIRE)]
    steps.append(("write", LATER + 3))
    _daemon("learning, then new fingerprints", _view(), steps)


def test_split_and_damage():
    steps = []
    segs = _segments("10.0.0.5", 40000, 0xFFFFFF00, A_WIRE, size=600)
    steps += [("record", T0 + 0.1 * i, r) for i, r in enumerate(segs)]
    rev = _segments("10.0.0.6", 40001, 5, A_WIRE, size=500)
    steps += [("record", T0 + 1, r) for r in [rev[0]] + rev[:0:-1]]
    steps += [("record", T0 + 2, _rec("10.0.0.8", 1, 1, b"\x16\x03\x01\x00\x05garbage", True))]
    steps += [("record", T0 + 2, _rec("10.0.0.8", 2, 1, b"GET / HTTP/1.1\r\n", True))]
    steps += [("record", T0 + 2, _rec("10.0.0.8", 3, 1, A_WIRE[:100], False))]
    steps += [("record", T0 + 3, _rec("10.0.0.9", 4, 1, A_WIRE[:2048], True, length=5000))]
    steps += [("record", T0 + 3, _rec("10.0.0.9", 4, 2049, A_WIRE[2048:], False, length=0))]
    steps += [("record", T0 + 4, _rec("10.0.0.9", 5, 1, A_WIRE, True)[:2091])]
    steps += [("record", T0 + 4, _rec("10.0.0.9", 6, 1, A_WIRE, True) + b"extra")]
    steps += [("record", T0 + 4, b"")]
    steps.append(("write", T0 + 5))
    _daemon("split, out of order and damaged", _view(), steps)
    rng = random.Random(4242)
    for n in range(12):
        steps = []
        for i in range(30):
            wire = rng.choice([A_WIRE, B_WIRE, C_WIRE])
            segs = _segments(f"10.0.{n}.{rng.randrange(4)}", rng.randrange(65536), rng.randrange(1 << 32), wire,
                             size=rng.choice([300, 1000, 2048]))
            if rng.random() < 0.3:
                rng.shuffle(segs)
            for s in segs:
                if rng.random() < 0.05:
                    s = bytearray(s)
                    s[rng.randrange(len(s))] ^= 1 << rng.randrange(8)
                    s = bytes(s)
                if rng.random() < 0.03:
                    continue
                steps.append(("record", T0 + rng.random() * LEARNING_SECONDS * 2, s))
        steps.sort(key=lambda s: s[1])
        steps.append(("write", T0 + LEARNING_SECONDS * 3))
        _daemon(f"random/{n}", _view(blocklist=[(A_JA4, "a")] if n % 2 else []), steps)


def test_blocklist():
    a = _segments("10.0.0.5", 40000, 1, A_WIRE)
    b = _segments("10.0.0.6", 40001, 1, B_WIRE)
    c = _segments("10.0.0.7", 40002, 1, C_WIRE)

    def hits(times, segs=a):
        return [("record", t, r) for t in times for r in segs]

    _daemon("ja4 reported", _view([(A_JA4, "malware kit")]), hits([T0, T0 + 1]) + [("write", T0 + 2)])
    _daemon("ja3 reported, no label", _view([(B_JA3, "")]), hits([T0], b) + [("write", T0 + 2)])
    _daemon("ja4 label wins over ja3", _view([(A_JA3, "by ja3"), (A_JA4, "by ja4")]), hits([T0]) + [("write", T0 + 1)])
    _daemon("empty ja4 label, ja3 labelled", _view([(A_JA4, ""), (A_JA3, "by ja3")]), hits([T0]) + [("write", T0 + 1)])
    _daemon("not listed", _view([(B_JA4, "b")]), hits([T0], c) + [("write", T0 + 1)])
    _daemon("quarantined, then held", _view([(A_JA4, "kit")], quarantine=True, duration=600),
            hits([T0, T0 + 1, T0 + 599.999, T0 + 600, T0 + 600.5, T0 + 1300]) + [("write", T0 + 1301)])
    _daemon("quarantine per client", _view([(A_JA4, "kit"), (B_JA4, "kit2")], quarantine=True),
            hits([T0]) + hits([T0], b) + hits([T0 + 1]) + [("write", T0 + 2)])
    answers = [b'{"ok": false, "message": "no such set"}\n', b'{"ok": false}\n', b"", b"   \n",
               b"not json\n", b'{"ok": 1}', b'{"ok": 0, "message": 5}', b'{"ok": true, "ok": false}\n',
               b"x" * 70000, None, "file", b'{"ok": true}\n{"ok": false}\n', b'{"ok": NaN}']
    times = [T0 + 700 * i for i in range(len(answers) + 1)]
    _daemon("quarantine answers", _view([(A_JA4, "kit")], quarantine=True), hits(times) + [("write", times[-1] + 1)],
            answers=answers)
    _daemon("quarantine answer not an object", _view([(A_JA4, "kit")], quarantine=True),
            hits([T0, T0 + 700]), answers=[b"[1]\n"])
    _daemon("quarantine answer a string", _view([(A_JA4, "kit")], quarantine=True), hits([T0]),
            answers=[b'"ok"\n'])
    _daemon("settings change", _view(), [
        *hits([T0]), ("view", _view([(A_JA4, "kit")])), *hits([T0 + 1]),
        ("view", _view([(A_JA4, "kit")], quarantine=True, duration=60)), *hits([T0 + 2]),
        ("view", _view([(A_JA4, "kit")], quarantine=False)), *hits([T0 + 3]),
        ("view", _view([(A_JA4, "kit")], quarantine=True, duration=0)), *hits([T0 + 4]),
        ("view", _view()), *hits([T0 + 5]), ("write", T0 + 6)])


def test_state_file():
    good: list[bytes] = []

    # A state file the daemon wrote itself, restored.
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "s.json"
        d = tlsfp_daemon.TlsFingerprintDaemon(_config(_view()), state_path=path, clock=lambda: T0)
        for r in _segments("10.0.0.5", 1, 1, A_WIRE) + _segments("10.0.0.6", 2, 1, B_WIRE):
            d.handle_segment(xdp.HelloSegment.from_bytes(r))
        d.write_state()
        good.append(path.read_bytes())
    later = [("record", LATER, r) for r in _segments("10.0.0.7", 3, 1, C_WIRE)]
    later += [("record", LATER, r) for r in _segments("10.0.0.7", 4, 1, A_WIRE)]
    later.append(("write", LATER + 1))
    _daemon("restored", _view(), later, state=good[0])
    for name, raw in [("not json", b"{"), ("empty", b""), ("a list", b"[]"), ("not utf-8", b"\xff\xfe"),
                      ("started too big", b'{"started": 1e999}'), ("clients a list", b'{"clients": [1]}'),
                      ("events a number", b'{"events": 5}'), ("big int", b'{"started": ' + b"9" * 400 + b"}"),
                      ("nested", b"[" * 5000 + b"]" * 5000),
                      ("too deep", b"[" * 100000 + b"]" * 100000), ("bom", b"\xef\xbb\xbf{}"),
                      ("crlf", good[0].replace(b", ", b",\r\n"))]:
        _daemon(f"state {name}", _view(), later, state=raw)


# --- recording the helper client -----------------------------------------------------------------------


def _client(name: str, answer, request: dict, *, max_bytes: int | None = None) -> None:
    case: dict = {"op": "client", "name": name, "answer": _answer_json(answer), "cmd": request}
    kwargs = {} if max_bytes is None else {"max_bytes": max_bytes}
    with FakeHelper(answer) as fake:
        try:
            case["reply"] = helper_client.send_command(request, SOCK, **kwargs)
        except helper_client.HelperError as exc:
            case["error"] = _text(str(exc))
        except Exception as exc:  # noqa: BLE001 -- 1.x lets it through
            case["raised"] = type(exc).__name__
    case["request"] = fake.request
    if max_bytes is not None:
        case["max_bytes"] = max_bytes
    _record(json.loads(json.dumps(case)))


def test_client():
    q = {"cmd": "quarantine_ip", "ip": "10.0.0.5", "duration_seconds": 7200}
    for name, answer in [
        ("ok", b'{"ok": true}\n'), ("ok, no newline", b'{"ok": true}'), ("message", b'{"ok": false, "message": "x"}\n'),
        ("closed", b""), ("blank", b" \r\n\t"), ("not json", b"nope"), ("not utf-8", b"\xff\xfe\n"),
        ("bytes repr", b"'\"\\\x00\x7f\x80\n\t\r"), ("two lines", b'{"a": 1}\n{"b": 2}\n'), ("a list", b"[1, 2]"),
        ("nan", b'{"x": NaN, "y": -Infinity}'), ("duplicate", b'{"a": 1, "a": 2}'), ("unicode", '{"é": " "}'.encode()),
        ("exactly the limit", b'{"a": "' + b"x" * (65536 - 10) + b'"}'), ("past the limit", b"x" * 65537),
        ("way past", b"x" * 300000), ("no socket", None), ("a file", "file"),
        ("utf-16", '{"ok": true}'.encode("utf-16")), ("utf-16-be", '{"ok": true}'.encode("utf-16-be")),
        ("utf-16-le", '{"ok": "\u00e9"}'.encode("utf-16-le")), ("utf-32", '{"ok": 1}'.encode("utf-32")),
        ("utf-32-le", '{"a": 1}'.encode("utf-32-le")), ("utf-8 bom", '\ufeff{"ok": true}'.encode()),
        ("two bytes", b"1\x00"), ("odd utf-16", '{"ok": true}'.encode("utf-16") + b"x"),
    ]:
        _client(name, answer, q)
    _client("odd request", b'{"ok": true}', {"cmd": "x", "é": " \U0001F600", "n": [1, 2.5, None, True]})
    _client("small limit", b'{"ok": true, "pad": "xxxxxxxx"}', q, max_bytes=10)


def teardown_module():
    try:
        os.rmdir(SOCK_DIR)
    except OSError:
        pass
