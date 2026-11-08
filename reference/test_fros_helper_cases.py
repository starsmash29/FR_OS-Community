"""Requests to FR_OS 1.x's apply-helper, run with the capture plugin
(reference/generate.sh lists this module with the other inputs).

Each case writes one request to 1.x's own request handler
(frfw.helper.server._Handler) over a socket pair, from a peer with the
full role, the sensor role or none, and records the reply. What the
read-only commands read is given by the case: what `nft` answers (its
argv is recorded too), the pending-apply record and Kea's lease file.

Only commands without side effects are ever dispatched: a peer with a
role sends the read-only ones, or none at all (a request 1.x refuses
or doesn't know); a peer with no role sends every command, which 1.x
refuses before it looks at anything else. Nothing here asserts
anything about 1.x.

A case 2.x answers differently on purpose carries "decided", naming the
entry of testdata/reference/decisions.md.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import types
from pathlib import Path
from unittest import mock

import pytest

from frfw import paths
from frfw.helper import server as helper_server
from frfw.helper.peer import PeerPolicy
from frfw.helper.protocol import COMMANDS

#: 2026-11-01T00:00:00Z, the capture plugin's FIXED_NOW.
NOW = 1793491200.0

TABLE = "fr_os"
META = {"metainfo": {"version": "1.0.6", "release_name": "Lester Gooch #5", "json_schema_version": 1}}

#: What nft says about a set (or table) that isn't loaded.
NOT_LOADED = {"rc": 1, "stdout": "",
              "stderr": "Error: No such file or directory\nlist set inet fr_os x\n                     ^\n"}

#: The commands that change something, or read the machine itself (the
#: conntrack table, the neighbour table): never dispatched here.
READ_ONLY = ("ping", "apply_status", "bruteforce_status", "ztna_sessions_status", "ids_quarantine_status",
             "iot_isolation_status", "dhcp_leases")


def _record(case: dict) -> None:
    capture = sys.modules.get("fros_capture")
    if capture is not None:
        capture._record("helper", case)


def _send(line: bytes, role: str, nft, files: dict, tmp_path: Path) -> tuple[object, list]:
    """1.x's reply to `line` (None if it sent none) and the nft argvs it
    ran."""
    uid = os.getuid()
    policy = PeerPolicy(frozenset({uid}) if role == "full" else frozenset(),
                        frozenset({uid}) if role == "sensor" else frozenset())
    for name in ("apply-pending.json", "config.rejected.yaml", "kea-leases4.csv"):
        (tmp_path / name).unlink(missing_ok=True)
    if files.get("apply_pending") is not None:
        (tmp_path / "apply-pending.json").write_bytes(bytes.fromhex(files["apply_pending"]))
    if files.get("rejected"):
        (tmp_path / "config.rejected.yaml").write_text("version: 1\n")
    if files.get("kea_leases") is not None:
        (tmp_path / "kea-leases4.csv").write_bytes(bytes.fromhex(files["kea_leases"]))
    server = types.SimpleNamespace(peer_policy=policy, kea_leases_path=tmp_path / "kea-leases4.csv",
                                   config_path=tmp_path / "config.yaml")

    calls: list = []

    def run(argv, *args, **kwargs):
        calls.append(list(argv))
        if nft is None:
            raise FileNotFoundError(2, "No such file or directory", "nft")
        answer = nft.get(argv[-1], NOT_LOADED)
        return subprocess.CompletedProcess(argv, answer["rc"], answer["stdout"], answer["stderr"])

    ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

    def write():
        try:
            theirs.sendall(line)
            theirs.shutdown(socket.SHUT_WR)
        except OSError:
            pass  # 1.x stopped reading (a line over its limit)

    writer = threading.Thread(target=write)
    writer.start()
    try:
        with mock.patch.object(subprocess, "run", run), mock.patch("time.time", return_value=NOW), \
                mock.patch.object(paths, "APPLY_PENDING_PATH", tmp_path / "apply-pending.json"), \
                mock.patch.object(paths, "REJECTED_CONFIG_PATH", tmp_path / "config.rejected.yaml"):
            try:
                helper_server._Handler(ours, "", server)
            except Exception:  # 1.x crashes: the peer gets no reply
                pass
        # The reply, then the end of it, before the rest of a long line
        # is thrown away (a close with unread data resets the peer).
        ours.shutdown(socket.SHUT_WR)
        out = b""
        theirs.settimeout(5)
        while chunk := theirs.recv(1 << 16):
            out += chunk
    finally:
        ours.close()
    writer.join()
    theirs.close()
    return (json.loads(out) if out else None), calls


def _case(line: bytes, role: str, tmp_path: Path, *, nft=None, files=None, decided=None) -> None:
    files = files or {}
    reply, calls = _send(line, role, nft, files, tmp_path)
    try:
        written = {"line": line.decode("utf-8")}
    except UnicodeDecodeError:
        written = {"line_hex": line.hex()}
    case = {**written, "role": role, "uid": os.getuid(), "nft": nft, "files": files, "now": NOW,
            "reply": reply, "nft_calls": calls}
    if decided:
        case["decided"] = decided
    _record(case)


def _request(cmd, **extra) -> bytes:
    return json.dumps({"cmd": cmd, **extra}).encode() + b"\n"


# --- framing: what reaches the dispatch, and with which cmd ---------------

PAD = 65536 - len(b'{"cmd": "ping", "pad": ""}')

LINES = [
    (b"", None),
    (b"\n", None),
    (b"   \r\n", None),
    (b"{}\n", None),
    (b"[]\n", None),
    (b'"ping"\n', None),
    (b"null\n", None),
    (b"5\n", None),
    (b"{\n", None),
    (b"not json\n", None),
    (b'{"cmd": "ping"}\n', None),
    (b'{"cmd":"ping"}\n', None),
    (b'  {"cmd": "ping"}  \r\n', None),
    (b'{"cmd": "ping", "x": [1, {"y": null}]}\n', None),
    (b'{"cmd": "ping"} x\n', None),
    (b'{"cmd": "ping"}{}\n', None),
    (b'{"cmd": "ping"}\n{"cmd": "nope"}\n', None),
    (b'{"cmd": "nope"}\n', None),
    (b'{"cmd": "PING"}\n', None),
    (b'{"cmd": "ping "}\n', None),
    (b'{"cmd": ""}\n', None),
    (b'{"cmd": null}\n', None),
    (b'{"x": "ping"}\n', None),
    (b'{"cmd": 5}\n', None),
    (b'{"cmd": -0}\n', None),
    (b'{"cmd": 123456789012345678901234567890}\n', None),
    (b'{"cmd": 1.5}\n', None),
    (b'{"cmd": -0.0}\n', None),
    (b'{"cmd": 1e16}\n', None),
    (b'{"cmd": 1E-7}\n', None),
    (b'{"cmd": 1e400}\n', None),
    (b'{"cmd": true}\n', None),
    (b'{"cmd": false}\n', None),
    (b'{"cmd": []}\n', None),
    (b'{"cmd": ["ping"]}\n', None),
    (b'{"cmd": {}}\n', None),
    (b'{"cmd": {"cmd": "ping"}}\n', None),
    (b'{"cmd": "p\\u00e9ng"}\n', None),
    (b'{"cmd": "p\xc3\xa9ng"}\n', None),
    (b'{"cmd": "it\'s"}\n', None),
    (b'{"cmd": "say \\"hi\\" it\'s"}\n', None),
    (b'{"cmd": "tab\\there\\u0000\\u007f\\u0085\\u00a0\\u2028"}\n', None),
    (b'{"cmd": "\\ud83d\\ude00 \xf0\x9f\x98\x80"}\n', None),
    (b'{"cmd": "back\\\\slash"}\n', None),
    (b'{"cmd": "\xff"}\n', None),
    (b'{"cmd": "\xc3"}\n', None),
    (b'{"cmd": "ping", "pad": "' + b"a" * (PAD - 1) + b'"}\n', None),
    (b'{"cmd": "ping", "pad": "' + b"a" * PAD + b'"}\n', None),
    (b'{"cmd": "ping", "pad": "' + b"a" * (PAD + 1) + b'"}\n', None),
    # Decided (testdata/reference/decisions.md, "2026-11-08: the helper's
    # requests"): what 1.x's json.loads and readline let through.
    (b'{"cmd": "ping"}', "no newline"),
    (b'{"cmd": "nope"}', "no newline"),
    (b'{"cmd": "ping", "pad": "' + b"a" * (PAD - 1) + b'"}' + b" " * 2 + b"\n", "longer than 64 KiB"),
    (b'{"cmd": "apply", "cmd": "ping"}\n', "a name twice"),
    (b'{"cmd": "ping", "x": NaN}\n', "NaN"),
    (b'{"cmd": "ping", "x": -Infinity}\n', "NaN"),
    (b'{"cmd": "\\ud800"}\n', "a lone surrogate"),
    (b'{"cmd": "ping", "x": "\\udfff"}\n', "a lone surrogate"),
    (b'\xef\xbb\xbf{"cmd": "ping"}\n', "a BOM"),
]


@pytest.mark.parametrize("index", range(len(LINES)))
@pytest.mark.parametrize("role", ["full", "sensor", "none"])
def test_line(index, role, tmp_path):
    line, decided = LINES[index]
    _case(line, role, tmp_path, decided=decided)


# --- who may send what --------------------------------------------------

@pytest.mark.parametrize("cmd", COMMANDS + ("nope", "Ping"))
def test_no_role(cmd, tmp_path):
    _case(_request(cmd), "none", tmp_path)


@pytest.mark.parametrize("cmd", [c for c in COMMANDS if c not in ("quarantine_ip", "conntrack_sample",
                                                                      "iot_sync_isolation")] + ["nope"])
def test_sensor(cmd, tmp_path):
    _case(_request(cmd), "sensor", tmp_path)


# --- the nft sets the status commands read -------------------------------

def _set(name: str, elems, **extra) -> dict:
    body = {"family": "inet", "name": name, "table": TABLE, "type": "ipv4_addr", "handle": 7, **extra}
    if elems is not None:
        body["elem"] = elems
    return {"rc": 0, "stdout": json.dumps({"nftables": [META, {"set": body}]}), "stderr": ""}


def _timed(val, expires=None, timeout=3600) -> dict:
    elem = {"val": val, "timeout": timeout}
    if expires is not None:
        elem["expires"] = expires
    return {"elem": elem}


SETS = {
    "empty": {},
    "loaded, empty": {name: _set(name, None) for name in (
        "bruteforce_jail", "bruteforce_jail6", "bruteforce_jail_mac", "ids_quarantine", "ids_quarantine_mac",
        "authenticated_ztna_users", "authenticated_ztna_tunnel", "authenticated_ztna_users6",
        "authenticated_ztna_tunnel6", "iot_isolated")},
    "members": {
        "bruteforce_jail": _set("bruteforce_jail", [_timed("10.73.1.5", 3412), _timed("10.73.1.6", 1),
                                                    _timed("10.73.1.7"), _timed("10.73.1.8", 0)]),
        "bruteforce_jail6": _set("bruteforce_jail6", [
            _timed("2001:db8:1::5", 30), _timed({"prefix": {"addr": "2001:db8:2::", "len": 64}}, 50),
            _timed({"prefix": {"addr": "2001:db8:3::", "len": "64"}}, 5), _timed({"range": ["::1", "::2"]}, 5)],
            type="ipv6_addr", flags=["interval", "timeout"]),
        "bruteforce_jail_mac": _set("bruteforce_jail_mac", [_timed("52:54:00:12:34:56", 899)], type="ether_addr"),
        "ids_quarantine": _set("ids_quarantine", [_timed("10.73.2.9", 3599), _timed("10.73.2.10", 12.9),
                                                  _timed({"prefix": {"addr": "10.73.3.0", "len": 24}}, 9)]),
        "ids_quarantine_mac": _set("ids_quarantine_mac", [_timed("aa:bb:cc:dd:ee:01", 10)], type="ether_addr"),
        "authenticated_ztna_users": _set("authenticated_ztna_users", [
            _timed({"concat": ["10.73.1.20", "AA:BB:CC:DD:EE:01"]}, 100),
            _timed({"concat": ["10.73.1.21", ""]}, 100), _timed({"concat": ["10.73.1.22"]}, 100),
            _timed({"concat": ["10.73.1.23", "aa:bb:cc:dd:ee:03", "x"]}, 100), _timed("10.73.1.24", 100),
            _timed({"concat": [5, "aa:bb:cc:dd:ee:05"]}, 100), _timed({"concat": ["10.73.1.26", 7]}, 100)],
            type=["ipv4_addr", "ether_addr"]),
        "authenticated_ztna_tunnel": _set("authenticated_ztna_tunnel", [
            _timed("10.99.0.2", 50), _timed({"concat": ["10.99.0.3", "aa:bb:cc:dd:ee:09"]}, 50)]),
        "authenticated_ztna_users6": _set("authenticated_ztna_users6", [
            _timed({"concat": ["2001:db8:1::20", "aa:bb:cc:dd:ee:0A"]}, 40)], type=["ipv6_addr", "ether_addr"]),
        "authenticated_ztna_tunnel6": _set("authenticated_ztna_tunnel6", [_timed("fd00:99::2")], type="ipv6_addr"),
        "iot_isolated": _set("iot_isolated", ["aa:bb:cc:dd:ee:10", "AA:BB:CC:DD:EE:11", {"elem": {"val": "aa:bb:cc:dd:ee:12"}},
                                              {"elem": {"val": 5}}, {"elem": None}, {}, 7], type="ether_addr"),
    },
    "odd entries": {
        "bruteforce_jail": _set("bruteforce_jail", ["10.73.1.5", 5, None, {"elem": "10.73.1.6"}, {"x": 1},
                                                    {"elem": {"val": "10.73.1.7", "expires": True}},
                                                    {"elem": {"val": "10.73.1.8", "expires": None}},
                                                    {"elem": {"val": "10.73.1.9", "expires": 123456789012345678901}}]),
        "ids_quarantine": {"rc": 0, "stdout": json.dumps({"nftables": [META, {"set": None}, {"table": {}},
                                                                         {"set": {"elem": []}}, {"set": {"name": "x"}}]}),
                           "stderr": ""},
        "authenticated_ztna_users": {"rc": 0, "stdout": "", "stderr": ""},
        "iot_isolated": {"rc": 0, "stdout": "{}", "stderr": ""},
    },
    "two sets in one answer": {
        "bruteforce_jail": {"rc": 0, "stdout": json.dumps({"nftables": [
            META, {"set": {"name": "a", "elem": [_timed("10.73.1.5", 3)]}},
            {"set": {"name": "b", "elem": [_timed("10.73.1.6", 4)]}}]}), "stderr": ""},
    },
    "table missing": {name: {"rc": 1, "stdout": "", "stderr": "Error: Could not process rule: No such file or directory\n"}
                      for name in ("bruteforce_jail", "ids_quarantine", "authenticated_ztna_users", "iot_isolated")},
    "set does not exist": {name: {"rc": 1, "stdout": "", "stderr": f"Error: set {name} does not exist\n"}
                           for name in ("bruteforce_jail", "ids_quarantine", "authenticated_ztna_users", "iot_isolated")},
    "permission denied": {name: {"rc": 1, "stdout": "", "stderr": "  Error: Operation not permitted (you must be root)\n\n"}
                          for name in ("bruteforce_jail", "ids_quarantine", "authenticated_ztna_users", "iot_isolated")},
    "later set fails": {"bruteforce_jail": _set("bruteforce_jail", [_timed("10.73.1.5", 3)]),
                        "bruteforce_jail6": {"rc": 2, "stdout": "", "stderr": "Error: syntax error\n"},
                        "ids_quarantine": _set("ids_quarantine", [_timed("10.73.2.9", 3)]),
                        "ids_quarantine_mac": {"rc": 1, "stdout": "", "stderr": "Error: boom\n"},
                        "authenticated_ztna_users": _set("authenticated_ztna_users", None),
                        "authenticated_ztna_tunnel": {"rc": 1, "stdout": "", "stderr": "Error: tunnel\n"}},
    "silent failure": {name: {"rc": 3, "stdout": "", "stderr": " \n"}
                       for name in ("bruteforce_jail", "ids_quarantine", "authenticated_ztna_users", "iot_isolated")},
    "not JSON": {name: {"rc": 0, "stdout": "table inet fr_os {", "stderr": ""}
                 for name in ("bruteforce_jail", "ids_quarantine", "authenticated_ztna_users", "iot_isolated")},
}


@pytest.mark.parametrize("cmd", ["bruteforce_status", "ztna_sessions_status", "ids_quarantine_status",
                                 "iot_isolation_status"])
@pytest.mark.parametrize("sets", sorted(SETS))
def test_sets(cmd, sets, tmp_path):
    _case(_request(cmd), "full", tmp_path, nft=SETS[sets])


@pytest.mark.parametrize("cmd", ["bruteforce_status", "ztna_sessions_status", "ids_quarantine_status",
                                 "iot_isolation_status"])
def test_no_nft(cmd, tmp_path):
    _case(_request(cmd), "full", tmp_path, nft=None)


# --- the pending apply (ROADMAP SEC-26) -----------------------------------

def _pending(**fields) -> str:
    record = {"id": "a1b2c3", "deadline": NOW + 90.25, "seconds": 120, "by": "kolos",
              "addresses": ["10.73.1.1"], "previous": "version: 1\n"}
    record.update(fields)
    return json.dumps({k: v for k, v in record.items() if v is not ...}).encode().hex()


PENDING = [
    None,
    _pending(),
    _pending(deadline=NOW - 5),
    _pending(deadline=NOW - 0.5),
    _pending(deadline=NOW + 0.0005),
    _pending(deadline=NOW),
    _pending(deadline=1e300),
    _pending(deadline=int(NOW) + 30),
    _pending(deadline=str(NOW + 30.5)),
    _pending(deadline=" 1793491230 "),
    _pending(deadline="1_793_491_230"),
    _pending(deadline="nan"),
    _pending(deadline="-Infinity"),
    _pending(deadline="abc"),
    _pending(deadline=True),
    _pending(deadline=None),
    _pending(deadline=[1]),
    _pending(id=5), _pending(id=1.5), _pending(id=None), _pending(id=True), _pending(id=["x", 1]),
    _pending(id={"a": None}), _pending(id="", by=""),
    _pending(seconds="120"), _pending(seconds=" -7 "), _pending(seconds="1_20"), _pending(seconds="12.0"),
    _pending(seconds=120.9), _pending(seconds=-0.5), _pending(seconds=True), _pending(seconds=None),
    _pending(seconds="\u0661\u0662"), _pending(seconds=10 ** 30),
    _pending(by=None), _pending(by=0), _pending(by=7), _pending(by=False), _pending(by=[]), _pending(by=["a"]),
    _pending(by={"x": 1}), _pending(by=0.0), _pending(by="ad\u00efn"),
    _pending(addresses=None), _pending(addresses=[]), _pending(addresses="10.0.0.1"),
    _pending(addresses=["10.73.1.1", 5, None, True, [1]]), _pending(addresses={"a": 1, "b": 2}),
    _pending(addresses=5), _pending(addresses=True), _pending(addresses=0), _pending(addresses=""),
    _pending(previous=...), _pending(id=...), _pending(deadline=...), _pending(seconds=...),
    _pending(by=..., addresses=...), _pending(previous=None), _pending(previous=5),
    json.dumps({"id": "a", "deadline": NOW, "seconds": 1, "previous": "", "extra": 1}).encode().hex(),
    b'{"id": "x", "deadline": 1e400, "seconds": 1, "previous": ""}'.hex(),
    b'{"id": "x", "deadline": 1793491300, "seconds": 1e400, "previous": ""}'.hex(),
    b'{"id": "x", "deadline": 1793491300, "seconds": NaN, "previous": ""}'.hex(),
    b'{"id": "x", "deadline": 1793491300, "seconds": 1, "previous": "", "id": "y"}'.hex(),
    b"[1, 2]".hex(), b'"text"'.hex(), b"".hex(), b"{".hex(), b"\xff\xfe".hex(), b"null".hex(),
    b'{"id": "caf\xc3\xa9", "deadline": 1793491300, "seconds": 1, "previous": ""}'.hex(),
]


@pytest.mark.parametrize("index", range(len(PENDING)))
@pytest.mark.parametrize("rejected", [False, True])
def test_apply_status(index, rejected, tmp_path):
    _case(_request("apply_status"), "full", tmp_path, files={"apply_pending": PENDING[index], "rejected": rejected})


# --- Kea's leases ---------------------------------------------------------

HEADER = "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id\n"
LATER = int(NOW) + 3600


def _lease(address="10.73.1.50", hwaddr="aa:bb:cc:dd:ee:01", expire=LATER, hostname="cam-1", state=0) -> str:
    return f"{address},{hwaddr},01:aa:bb:cc:dd:ee:01,3600,{expire},1,0,0,{hostname},{state},,0\n"


LEASES = [
    None,
    "",
    HEADER,
    HEADER + _lease(),
    HEADER + _lease() + _lease(address="10.73.1.9", hwaddr="AA-BB-CC-DD-EE-02", hostname="Phone.")
    + _lease(address="10.73.1.10", hwaddr=" aa:bb:cc:dd:ee:03 ", hostname=""),
    HEADER + _lease() + _lease(expire=LATER + 60, hostname="renewed"),
    HEADER + _lease() + _lease(state=2),
    HEADER + _lease(state=2) + _lease(),
    HEADER + _lease(expire=int(NOW)) + _lease(address="10.73.1.51", expire=int(NOW) + 1),
    HEADER + _lease(state=1) + _lease(address="10.73.1.52", state=" 0 ") + _lease(address="10.73.1.53", state=""),
    HEADER + _lease(expire="") + _lease(address="10.73.1.54", expire="abc") + _lease(address="10.73.1.55", expire="1_793_499_999")
    + _lease(address="10.73.1.56", expire=" +1793499999 ") + _lease(address="10.73.1.57", expire="1793499999.0")
    + _lease(address="10.73.1.58", expire="\u0661" * 10) + _lease(address="10.73.1.59", expire=str(10 ** 25)),
    HEADER + _lease(hwaddr="aa:bb:cc:dd:ee") + _lease(address="10.73.1.60", hwaddr="")
    + _lease(address="10.73.1.61", hwaddr="gg:bb:cc:dd:ee:01") + _lease(address="10.73.1.62", hwaddr="aabb.ccdd.ee01")
    + _lease(address="10.73.1.63", hwaddr="\u0130a:bb:cc:dd:ee:01") + _lease(address="10.73.1.64", hwaddr="\x1caa:bb:cc:dd:ee:01\x1f"),
    HEADER + _lease(address="2001:db8::5") + _lease(address="10.73.1.065") + _lease(address="10.73.1.256")
    + _lease(address=" 10.73.1.66 ") + _lease(address="") + _lease(address="10.73.1.67/32"),
    HEADER + _lease(hostname="a&#x2cb") + _lease(address="10.73.1.70", hostname="  spaced name  ")
    + _lease(address="10.73.1.71", hostname="dots...") + _lease(address="10.73.1.72", hostname="tab\there")
    + _lease(address="10.73.1.73", hostname="caf\u00e9\u2028x") + _lease(address="10.73.1.74", hostname="x" * 300)
    + _lease(address="10.73.1.75", hostname="<script>alert(1)</script>") + _lease(address="10.73.1.76", hostname=". ."),
    HEADER + '10.73.1.80,aa:bb:cc:dd:ee:80,,3600,%d,1,0,0,"quoted, name",0,,0\n' % LATER
    + '10.73.1.81,aa:bb:cc:dd:ee:81,,3600,%d,1,0,0,"say ""hi""",0,,0\n' % LATER
    + '10.73.1.82,aa:bb:cc:dd:ee:82,,3600,%d,1,0,0,"multi\nline",0,,0\n' % LATER
    + '10.73.1.83,aa:bb:cc:dd:ee:83,,3600,%d,1,0,0,a"b"c,0,,0\n' % LATER
    + '10.73.1.84,aa:bb:cc:dd:ee:84,,3600,%d,1,0,0,"ab"cd,0,,0\n' % LATER
    + '"10.73.1.85","aa:bb:cc:dd:ee:85",,3600,"%d",1,0,0,"q",0,,0\n' % LATER,
    HEADER.replace("\n", "\r\n") + _lease().replace("\n", "\r\n") + _lease(address="10.73.1.90").replace("\n", "\r"),
    HEADER + _lease().rstrip("\n"),
    HEADER + "\n\n" + _lease() + "\r\n" + _lease(address="10.73.1.91"),
    HEADER + "10.73.1.92,aa:bb:cc:dd:ee:92\n" + "10.73.1.93,aa:bb:cc:dd:ee:93,,3600,%d\n" % LATER
    + "10.73.1.94,aa:bb:cc:dd:ee:94,,3600,%d,1,0,0,extra,0,,0,9,9,9\n" % LATER,
    "address,hwaddr,expire,state,hostname\n10.73.1.95,aa:bb:cc:dd:ee:95,%d,0,short\n" % LATER,
    "hwaddr,address,state,expire\naa:bb:cc:dd:ee:96,10.73.1.96,0,%d\n" % LATER,
    "address,address,hwaddr,expire,state\n10.73.1.97,10.73.1.98,aa:bb:cc:dd:ee:97,%d,0\n" % LATER,
    "\n" + HEADER + _lease(),
    "ADDRESS,HWADDR,EXPIRE,STATE\n10.73.1.99,aa:bb:cc:dd:ee:99,%d,0\n" % LATER,
    HEADER + _lease(address="10.73.1.100") + _lease(address="10.73.1.20") + _lease(address="10.73.1.3")
    + _lease(address="10.73.10.1") + _lease(address="9.9.9.9"),
    HEADER + '10.73.1.110,aa:bb:cc:dd:ee:10,,3600,%d,1,0,0,"unterminated,0,,0\n' % LATER,
    HEADER + _lease(address="10.73.1.111") + '10.73.1.112,aa:bb:cc:dd:ee:12,,3600,%d,1,0,0,"open' % LATER,
    HEADER + _lease(hostname="nul\x00byte") + _lease(address="10.73.1.113", hostname="\ufeffbom"),
]

#: Bytes that aren't UTF-8, which 1.x reads with errors="replace".
RAW_LEASES = [
    (HEADER + _lease(hostname="ok")).encode() + b"10.73.1.120,aa:bb:cc:dd:ee:20,,3600,%d,1,0,0,bad\xff\xfe\xe2\x82name,0,,0\n" % LATER,
    b"\xef\xbb\xbf" + (HEADER + _lease(address="10.73.1.121")).encode(),
    (HEADER + _lease(address="10.73.1.122")).encode() + b"10.73.1.123,aa:bb:cc:dd:ee:23,,3600,%d,1,0,0,x\xed\xa0\x80\xf0\x90\x80y\xf4\x90\x80\x80z\xc0\xafw,0,,0\n" % LATER,
]


@pytest.mark.parametrize("index", range(len(LEASES) + len(RAW_LEASES)))
@pytest.mark.parametrize("role", ["full", "sensor"])
def test_dhcp_leases(index, role, tmp_path):
    if index < len(LEASES):
        data = LEASES[index]
        hexed = None if data is None else data.encode().hex()
    else:
        hexed = RAW_LEASES[index - len(LEASES)].hex()
    _case(_request("dhcp_leases"), role, tmp_path, files={"kea_leases": hexed})


def test_dhcp_leases_field_limit(tmp_path):
    data = HEADER + _lease(hostname="h" * 131073)
    _case(_request("dhcp_leases"), "full", tmp_path, files={"kea_leases": data.encode().hex()})
