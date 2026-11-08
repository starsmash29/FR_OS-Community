"""FR_OS 1.x's applies, run against a recorded fake of the system, with
the capture plugin (reference/generate.sh runs this module after the
render module, so it sees every config the run accepted).

Each case is a short session with 1.x's apply-helper request handler
(frfw.helper.server._handle_request): an apply, a dry run, an apply held
for confirmation and then confirmed or reverted, a rollback, a save.
Nothing is run and nothing outside the case's own directory is touched:

- every absolute path 1.x's modules hold (module constants and the
  default arguments bound when a function was defined) is moved under
  the case's root, which is recorded as "@ROOT@";
- subprocess.run answers from the case's table (the first entry whose
  argv is a prefix of the call's), and every call is recorded with its
  input and timeout;
- the clock is FIXED_NOW, the effective uid 0, randomness a recorded
  byte stream, and no account exists;
- a read or write outside the root (and Python's own tree) is recorded
  as a leak: the Go replay refuses a case with one.

The case records the files before, every request's reply (or the type
of the exception 1.x let through) and its calls, and the files after.
Nothing here asserts anything about 1.x.
"""

from __future__ import annotations

import copy
import datetime as _dt
import grp
import hashlib
import json
import os
import pwd
import re
import shutil
import subprocess
import sys
import tempfile
import types
from pathlib import Path

import pytest
import yaml

#: 2026-11-01T00:00:00Z, the capture plugin's FIXED_NOW.
NOW = 1793491200.0

#: Where 1.x's constants point that the root takes in: the trees it
#: reads and writes, and the programs it checks for by path (the others
#: are named on PATH, and stay as they are).
ROOTED = ("/etc/", "/proc/", "/sys/", "/run/", "/var/", "/usr/sbin/", "/usr/local/share/")

#: The host's OpenSSL, as Python's ssl module reports it (frfw.pqc):
#: Debian 12's, without hybrid key exchange.
OPENSSL = ((3, 0, 15), "OpenSSL 3.0.15 3 Sep 2024")
HYBRID_OPENSSL = ((3, 5, 1), "OpenSSL 3.5.1 1 Jul 2025")

#: Files larger than this are recorded by digest.
MAX_TEXT = 1 << 16

#: What a program says unless the case says otherwise: the first entry
#: whose argv is a prefix of the call's ("after": n lets the first n such
#: calls through to the entries below it).
BASE = [
    {"argv": ["ip", "-j"], "stdout": "[]"},
    {"argv": ["nft", "-j", "list"], "rc": 1,
     "stderr": "Error: No such file or directory\nlist set inet fr_os x\n                     ^\n"},
    {"argv": ["nft", "list", "ruleset"], "stdout": ""},
    {"argv": ["systemctl", "is-active"], "rc": 3, "stdout": "inactive\n"},
    {"argv": ["systemctl", "is-enabled"], "rc": 1, "stdout": "disabled\n"},
    {"argv": ["systemctl", "is-system-running"], "stdout": "running\n"},
    {"argv": ["ss"], "stdout": ""},
    {"argv": ["/usr/bin/ssh", "-Q", "kex"], "stdout": "curve25519-sha256\nsntrup761x25519-sha512\n"},
]


def _record(case: dict) -> None:
    capture = sys.modules.get("fros_capture")
    if capture is not None:
        capture._record("apply", case)


# --- the fake system --------------------------------------------------------------

class _Fake:
    def __init__(self, root: Path, table: list, random: bytes):
        self.root = root
        self.table = table + BASE
        self.random = random
        self.used = 0
        self.calls: list = []
        self.passed: dict[int, int] = {}
        self.leaks: set[str] = set()
        self.active = False
        allowed = {str(root), os.path.realpath(root), "/dev/null", "/dev/urandom", "/usr/share/zoneinfo",
                   "/etc/localtime", "/proc/self", tempfile.gettempdir(), os.path.realpath(tempfile.gettempdir())}
        allowed |= {p for p in sys.path if p and os.path.isabs(p)}
        self.allowed = tuple(sorted(allowed))

    def bytes(self, n: int) -> bytes:
        out = self.random[self.used:self.used + n]
        if len(out) < n:
            raise AssertionError("the case's random bytes ran out")
        self.used += n
        return out

    def watch(self, path) -> None:
        if not self.active or not isinstance(path, (str, bytes, os.PathLike)):
            return
        p = os.fsdecode(os.fspath(path))
        if not os.path.isabs(p):
            return
        if not any(p == a or p.startswith(a.rstrip("/") + "/") for a in self.allowed):
            self.leaks.add(p)

    def run(self, args, *pos, input=None, timeout=None, check=False, text=None, capture_output=False,
            universal_newlines=None, encoding=None, **kwargs):
        argv = [os.fspath(a) for a in args]
        stdin = input
        if isinstance(stdin, bytes):
            stdin = stdin.decode("utf-8", "surrogateescape")
        self.calls.append({"argv": argv, "input": _digest(stdin), "timeout": timeout})
        seen = _rooted(argv, str(self.root))
        answer = {"argv": []}
        for i, a in enumerate(self.table):
            if seen[:len(a["argv"])] != a["argv"]:
                continue
            if self.passed.get(i, 0) < a.get("after", 0):  # this entry answers a later call
                self.passed[i] = self.passed.get(i, 0) + 1
                continue
            answer = a
            break
        if answer.get("error") == "missing":
            raise FileNotFoundError(2, "No such file or directory", argv[0])
        if answer.get("error") == "timeout":
            raise subprocess.TimeoutExpired(args, timeout)
        out, err = answer.get("stdout", ""), answer.get("stderr", "")
        if not (text or universal_newlines or encoding):
            out, err = out.encode(), err.encode()
        proc = subprocess.CompletedProcess(args, answer.get("rc", 0), out, err)
        if check and proc.returncode:
            raise subprocess.CalledProcessError(proc.returncode, args, out, err)
        return proc


def _digest(text):
    if text is None or len(text) <= 4096:
        return text
    return {"sha256": hashlib.sha256(text.encode("utf-8", "surrogateescape")).hexdigest(), "len": len(text)}


def _moved(value, root: Path):
    if isinstance(value, Path) and value.is_absolute() and str(value).startswith(ROOTED):
        return root / str(value).lstrip("/")
    if isinstance(value, str) and value.startswith(ROOTED) and "\n" not in value and " " not in value:
        return str(root) + value
    if isinstance(value, tuple) and value and all(isinstance(v, (Path, str)) for v in value):
        moved = tuple(_moved(v, root) for v in value)
        return moved if any(m is not v for m, v in zip(moved, value)) else value
    return value


def _reroot(monkeypatch, root: Path) -> None:
    """Every frfw module's paths, and its functions' default arguments,
    under root."""
    def defaults(fn) -> None:
        fn = getattr(fn, "__func__", fn)
        fn = getattr(fn, "__wrapped__", fn)
        if not isinstance(fn, types.FunctionType):
            return
        if fn.__defaults__:
            new = tuple(_moved(d, root) for d in fn.__defaults__)
            if any(n is not d for n, d in zip(new, fn.__defaults__)):
                monkeypatch.setattr(fn, "__defaults__", new)
        if fn.__kwdefaults__:
            new = {k: _moved(d, root) for k, d in fn.__kwdefaults__.items()}
            if any(new[k] is not d for k, d in fn.__kwdefaults__.items()):
                monkeypatch.setattr(fn, "__kwdefaults__", new)

    for name, mod in list(sys.modules.items()):
        if mod is None or not (name == "frfw" or name.startswith("frfw.")):
            continue
        for attr, value in list(vars(mod).items()):
            moved = _moved(value, root)
            if moved is not value:
                monkeypatch.setattr(mod, attr, moved)
            if getattr(value, "__module__", None) != name:
                continue
            if isinstance(value, type):
                for member in list(vars(value).values()):
                    defaults(member)
            else:
                defaults(value)


class _FixedDatetime(_dt.datetime):
    @classmethod
    def now(cls, tz=None):
        return _dt.datetime.fromtimestamp(NOW, tz)


_hook_fake: list = []


def _audit(event, args):
    if not _hook_fake:
        return
    fake = _hook_fake[0]
    if event in ("open", "os.listdir", "os.scandir", "os.mkdir", "os.remove", "os.rmdir", "os.chmod",
                 "os.truncate", "os.utime", "shutil.copyfile", "shutil.rmtree"):
        fake.watch(args[0] if args else None)
    elif event in ("os.rename", "os.link", "os.symlink"):
        fake.watch(args[0])
        fake.watch(args[1])


sys.addaudithook(_audit)


@pytest.fixture
def system(monkeypatch, tmp_path):
    from frfw import apply as frfw_apply
    from frfw import apply_confirm, ipv6, wireguard

    root = tmp_path / "root"
    root.mkdir()
    state = {}

    def make(table: list, random: bytes, openssl) -> _Fake:
        import ssl

        fake = _Fake(root, table, random)
        state["fake"] = fake
        (major, minor, patch), text = openssl
        monkeypatch.setattr(ssl, "OPENSSL_VERSION_INFO", (major, minor, patch, 0, 0))
        monkeypatch.setattr(ssl, "OPENSSL_VERSION", text)
        return fake

    _reroot(monkeypatch, root)
    from frfw import management

    monkeypatch.setattr(management, "ssh_login_users", management.ssh_login_users)  # each session sets it
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: state["fake"].run(*a, **k))
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "chown", lambda *a, **k: None)
    monkeypatch.setattr(os, "fchown", lambda *a, **k: None)
    monkeypatch.setattr(shutil, "which", lambda name, *a, **k: "/usr/bin/" + name)
    monkeypatch.setattr(grp, "getgrnam", lambda name: (_ for _ in ()).throw(KeyError(name)))
    monkeypatch.setattr(pwd, "getpwnam", lambda name: (_ for _ in ()).throw(KeyError(name)))
    monkeypatch.setattr("time.time", lambda: NOW)
    monkeypatch.setattr(frfw_apply, "datetime", _FixedDatetime)
    monkeypatch.setattr(apply_confirm.secrets, "token_hex", lambda n=32: state["fake"].bytes(n).hex())
    monkeypatch.setattr(ipv6.secrets, "randbits",
                        lambda k: int.from_bytes(state["fake"].bytes((k + 7) // 8), "big") >> (-k % 8))
    import base64

    def keypair():
        raw = base64.b64encode(state["fake"].bytes(32)).decode()
        return raw, wireguard.public_key_of(raw)

    monkeypatch.setattr(wireguard, "generate_keypair", keypair)
    real_stat = os.stat

    def stat(path, *a, **k):
        if "fake" in state:
            state["fake"].watch(path)
        return real_stat(path, *a, **k)

    monkeypatch.setattr(os, "stat", stat)
    yield root, make
    _hook_fake.clear()


def _snapshot(root: Path) -> dict:
    """The tree under root: each file's mode and text (with the root's
    path as the replay writes it), its digest when it is large."""
    files = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        rel = os.path.relpath(dirpath, root)
        if not filenames and not dirnames:
            files[rel + "/"] = None
        for name in sorted(filenames):
            path = Path(dirpath) / name
            data = path.read_bytes()
            entry: dict = {"mode": oct(path.stat().st_mode & 0o7777)}
            try:
                text = _rooted(data.decode("utf-8"), str(root))
            except UnicodeDecodeError:
                text = None
            if text is not None and len(text.encode()) > MAX_TEXT:
                entry["sha256"] = hashlib.sha256(text.encode()).hexdigest()
                entry["len"] = len(text.encode())
            elif text is not None:
                entry["text"] = text
            else:
                entry["hex"] = data.hex()
            files[os.path.relpath(path, root)] = entry
    return files


def _rooted(value, root: str):
    """value with the root's path, and Python's temporary names, as the
    replay can match them."""
    if isinstance(value, str):
        tmp = tempfile.gettempdir()
        value = value.replace(root, "@ROOT@")
        value = re.sub(re.escape(tmp) + r"/tmp[A-Za-z0-9_]+", "@TMP@/tmp*", value)
        return value.replace(tmp + "/", "@TMP@/")
    if isinstance(value, list):
        return [_rooted(v, root) for v in value]
    if isinstance(value, dict):
        return {(_rooted(k, root) if isinstance(k, str) else k): _rooted(v, root) for k, v in value.items()}
    return value


def _wait(server, later: float) -> list[str]:
    """apply_confirm.wait as the revert unit runs it, `later` seconds
    after FIXED_NOW, its sleeps moving the clock on."""
    from unittest import mock

    from frfw import apply_confirm

    clock = [NOW + later]

    def sleep(seconds: float) -> None:
        clock[0] += seconds

    with mock.patch("time.time", lambda: clock[0]):
        return apply_confirm.wait(config_path=server.config_path, clock=lambda: clock[0], sleep=sleep)


def _session(system, name: str, setup: dict, requests: list, table: list | None = None,
             random: bytes = b"", decided: str | None = None, openssl=OPENSSL,
             login_users: tuple[str, ...] = ()) -> None:
    from frfw.helper import server as helper_server
    from frfw.helper.peer import PeerPolicy

    root, make = system
    from frfw import management

    fake = make(table or [], random, openssl)
    management.ssh_login_users = lambda: list(login_users)  # the fixture puts it back
    for rel, content in setup.items():
        path = root / rel
        if rel.endswith("/"):
            path.mkdir(parents=True, exist_ok=True)
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    before = _snapshot(root)
    server = types.SimpleNamespace(
        config_path=root / "etc/fr_os/config.yaml", backup_dir=root / "etc/fr_os/backups",
        kea_config_path=root / "etc/kea/kea-dhcp4.conf", sensor_config_path=root / "etc/fr_os/sensor-config.yaml",
        peer_policy=PeerPolicy(frozenset({0}), frozenset()))
    steps = []
    _hook_fake[:] = [fake]
    fake.active = True
    for request in requests:
        if callable(request):
            request = request(steps)
        start = len(fake.calls)
        try:
            if "wait" in request:  # fr-apply-revert.service, request["wait"] s later
                reply = {"messages": _wait(server, request["wait"])}
            else:
                reply = helper_server._handle_request(copy.deepcopy(request), server)
            step = {"request": request, "reply": json.loads(json.dumps(reply))}
        except BaseException as exc:  # 1.x lets it through: the peer gets no reply
            step = {"request": request, "raised": type(exc).__name__, "error": str(exc)}
        step["calls"] = fake.calls[start:]
        steps.append(step)
    fake.active = False
    _hook_fake.clear()
    case = {"id": name, "setup": before, "table": fake.table, "random": random.hex(), "now": NOW,
            "openssl": [*openssl[0], openssl[1]], "login_users": list(login_users),
            "steps": steps, "files": _snapshot(root), "leaks": sorted(fake.leaks)}
    if decided:
        case["decided"] = decided
    _record(_rooted(case, str(root)))


# --- what the sessions apply ------------------------------------------------------

def _devices(raw: dict) -> list[str]:
    from frfw.config.loader import parse_config

    config = parse_config(copy.deepcopy(raw))
    names = {i.device for i in config.interfaces.values() if i.vlan_id is None}
    names |= {i.vlan_parent for i in config.interfaces.values() if i.vlan_id is not None}
    return sorted(n for n in names if n)


#: The kernel's per-device settings an apply reads and writes.
SYSCTLS = (("ipv6", "forwarding", "0"), ("ipv6", "accept_ra", "1"), ("ipv6", "accept_redirects", "1"),
           ("ipv6", "accept_source_route", "0"), ("ipv6", "autoconf", "1"), ("ipv6", "disable_ipv6", "0"),
           ("ipv6", "keep_addr_on_down", "0"), ("ipv4", "promote_secondaries", "0"))


def _setup(raw: dict) -> dict:
    text = yaml.safe_dump(raw, sort_keys=False)
    setup = {"etc/fr_os/config.yaml": text, "proc/sys/net/ipv4/ip_forward": "0\n", "usr/sbin/dhcpcd": "",
             "usr/sbin/dnsmasq": ""}
    for name in ["all", "default", "wg0"] + _devices(raw):
        if name not in ("all", "default", "wg0"):
            setup[f"sys/class/net/{name}/"] = ""
        for family, key, value in SYSCTLS:
            setup[f"proc/sys/net/{family}/conf/{name}/{key}"] = value + "\n"
    return setup


#: How many of the run's accepted configs are applied (every n-th, so
#: they spread over 1.x's suite), and how many of those with the XDP SNI
#: filter on (refused by decision).
SAMPLE = 40
SAMPLE_XDP = 4

RANDOM = hashlib.sha256(b"fr_os apply cases").digest() * 8


def _accepted() -> list:
    capture = sys.modules.get("fros_capture")
    if capture is None:
        return []
    plain, xdp = [], []
    for key, case in sorted(capture._cases["config"].items()):
        if case["ok"] and isinstance(case["input"], dict):
            try:
                _devices(case["input"])
            except Exception:
                continue
            on = (case["input"].get("xdp_sni_filter") or {}).get("enabled") is True
            (xdp if on else plain).append((key, case["input"]))

    def every(items: list, n: int) -> list:
        return items[::max(1, len(items) // n)][:n]

    return every(plain, SAMPLE) + every(xdp, SAMPLE_XDP)


def test_apply_sampled(system):
    """Each sampled config applied on a fresh router (every other one
    dry-run first), its devices up with no address yet."""
    for n, (key, raw) in enumerate(_accepted()):
        setup = _setup(raw)
        requests = [{"cmd": "apply", "dry_run": True}, {"cmd": "apply"}] if n % 2 else [{"cmd": "apply"}]
        xdp = (raw.get("xdp_sni_filter") or {}).get("enabled") is True
        _session(system, f"apply/{key}", setup, requests, _links(setup["etc/fr_os/config.yaml"]), RANDOM,
                 decided="xdp" if xdp else None)
        root, _ = system
        shutil.rmtree(root)
        root.mkdir()


# --- sessions: confirm, revert, rollback, save, and steps that fail ---------------

RICH = """\
version: 1
hostname: fr-router
interfaces:
  wan: {device: eth0, zone: wan}
  lan: {device: eth1, zone: lan, address: 10.0.0.1/24}
zones: {wan: {}, lan: {}, vpn: {}}
rules:
  - {name: lan-to-wan, action: accept, from_zone: lan, to_zone: wan}
  - {name: webui-from-vpn, action: accept, from_zone: vpn, to_zone: self, proto: tcp, dst_port: 443}
nat: {masquerade: [{out_zone: wan}]}
dhcp:
  lan: {range_start: 10.0.0.100, range_end: 10.0.0.200, dns_servers: [10.0.0.1]}
adblocker: {enabled: true, source_urls: ["https://example.com/hosts"], allowlist: [example.org], serve_lan: true}
ipv6: {enabled: true, lan_zones: [lan], ula_prefix: "fd12:3456:789a::/48"}
wireguard:
  enabled: true
  address: 10.9.0.1/24
  listen_port: 51820
  peers: [{name: phone, public_key: "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=", address: 10.9.0.2}]
pqc: {enabled: true}
ssh_pqc: {enabled: true}
"""

#: The same router, one rule more: an apply of it is held for
#: confirmation once RICH is the applied config.
RICH2 = RICH.replace("rules:\n", "rules:\n  - {name: lan-dns, action: accept, from_zone: lan, to_zone: self, "
                                  "proto: udp, dst_port: 53}\n", 1)

PLAIN = """\
version: 1
hostname: plain
interfaces:
  wan: {device: eth0, zone: wan}
  lan: {device: eth1, zone: lan, address: 192.168.7.1/24}
zones: {wan: {}, lan: {}}
rules: [{name: lan-to-wan, action: accept, from_zone: lan, to_zone: wan}]
nat: {masquerade: [{out_zone: wan}]}
"""

RUNNING = {"argv": ["nft", "list", "ruleset"], "stdout": "table inet fr_os {\n}\n"}


def _tree(text: str, applied: str | None = None, **extra) -> dict:
    setup = _setup(yaml.safe_load(text))
    setup["etc/fr_os/config.yaml"] = text
    if applied is not None:
        setup["etc/fr_os/applied-config.yaml"] = applied
    setup.update(extra)
    return setup


def _links(text: str) -> list:
    """`ip -j addr show dev X` for each device the config names, VLAN
    devices too: up, with no address yet."""
    from frfw.config.loader import parse_config

    config = parse_config(yaml.safe_load(text))
    names = set(_devices(yaml.safe_load(text))) | {i.device for i in config.interfaces.values() if i.device}
    return [{"argv": ["ip", "-j", "addr", "show", "dev", name],
             "stdout": json.dumps([{"ifname": name, "flags": ["BROADCAST", "UP"], "addr_info": []}])}
            for name in sorted(names)]


def _pending_id(steps) -> str:
    for step in reversed(steps):
        pending = (step.get("reply") or {}).get("pending")
        if pending:
            return pending["id"]
    return ""


def _save(text: str) -> dict:
    return {"cmd": "save_config", "yaml": text}


SESSIONS = {
    "fresh rich": (_tree(RICH), [{"cmd": "apply"}], []),
    "fresh rich, dry run": (_tree(RICH), [{"cmd": "apply", "dry_run": True}], []),
    "fresh plain, running ruleset": (_tree(PLAIN), [{"cmd": "apply"}, {"cmd": "rollback"}], [RUNNING]),
    "no config": ({"proc/sys/net/ipv4/ip_forward": "0\n"}, [{"cmd": "apply"}, {"cmd": "apply", "dry_run": True}], []),
    "confirm": (_tree(RICH2, RICH), [
        {"cmd": "apply", "confirm": True, "user": "admin"},
        {"cmd": "apply_status"},
        {"cmd": "apply"},
        {"cmd": "apply_confirm", "id": "nope"},
        lambda steps: {"cmd": "apply_confirm", "id": _pending_id(steps)},
        {"cmd": "apply_status"},
        {"cmd": "apply_confirm", "id": "x"},
    ], [RUNNING]),
    "revert": (_tree(RICH2, RICH), [
        {"cmd": "apply", "confirm": True, "user": "x" * 80},
        {"cmd": "apply_revert"},
        {"cmd": "apply_status"},
        {"cmd": "restore_rejected"},
        {"cmd": "restore_rejected"},
        {"cmd": "apply_revert"},
    ], [RUNNING]),
    "revert unit": (_tree(RICH2, RICH), [
        {"wait": 0},
        {"cmd": "apply", "confirm": True},
        {"wait": 299.5},
        {"cmd": "apply_status"},
        {"wait": 0},
    ], [RUNNING]),
    "revert unit, confirmed": (_tree(RICH2, RICH), [
        {"cmd": "apply", "confirm": True},
        lambda steps: {"cmd": "apply_confirm", "id": _pending_id(steps)},
        {"wait": 400},
    ], [RUNNING]),
    "revert, previous config broken": (_tree(RICH2, RICH.replace("version: 1", "version: 1\nbogus: 1")), [
        {"cmd": "apply", "confirm": True},
        {"cmd": "apply_revert"},
        {"cmd": "apply_status"},
    ], [RUNNING]),
    "request shapes": (_tree(RICH2, RICH), [
        {"cmd": "apply", "dry_run": "no"},
        {"cmd": "apply", "dry_run": 0, "confirm": 1, "user": 5},
        {"cmd": "restore_rejected"},
        {"cmd": "apply_confirm", "id": None},
        {"cmd": "apply_confirm", "id": 7},
        {"cmd": "apply_revert", "x": 1},
    ], [RUNNING]),
    "moves management": (_tree(RICH2.replace("10.0.0.", "10.0.5."), RICH),
                         [{"cmd": "apply", "dry_run": True}, {"cmd": "apply", "confirm": True}], [RUNNING]),
    "applied record unreadable": (_tree(RICH2, "version: [\n"), [{"cmd": "apply", "confirm": True}], [RUNNING]),
    "confirm, same config": (_tree(RICH, RICH), [{"cmd": "apply", "confirm": True}], []),
    "confirm, nothing applied before": (_tree(RICH), [{"cmd": "apply", "confirm": True}], []),
    "confirm, revert unit fails": (_tree(RICH2, RICH), [{"cmd": "apply", "confirm": True}], [
        {"argv": ["systemctl", "restart", "fr-apply-revert.service"], "rc": 5, "stderr": "Unit not found.\n"}]),
    "confirm off": (_tree(RICH2.replace("pqc: {enabled: true}\n", "pqc: {enabled: true}\nmanagement: "
                                        "{confirm_apply_seconds: 0}\n"), RICH), [{"cmd": "apply", "confirm": True}], []),
    "rollback, no backups": (_tree(PLAIN), [{"cmd": "rollback"}], []),
    "rollback, backups": (_tree(PLAIN, None, **{
        "etc/fr_os/backups/ruleset-20261030T000000Z.nft": "table inet fr_os {\n}\n",
        "etc/fr_os/backups/ruleset-20261031T000000Z.nft": "table inet fr_os {\n}\n",
        "etc/fr_os/backups/other.txt": "x\n"}), [{"cmd": "rollback"}], []),
    "rollback, nft fails": (_tree(PLAIN, None, **{
        "etc/fr_os/backups/ruleset-20261031T000000Z.nft": "table inet fr_os {\n}\n"}), [{"cmd": "rollback"}],
        [{"argv": ["nft", "-f"], "rc": 1, "stderr": "Error: syntax error\n"}]),
    "save": (_tree(PLAIN), [
        _save(RICH), _save("version: 2\n"), _save("a: [\n"), {"cmd": "save_config", "yaml": 5},
        {"cmd": "save_config"}, _save(""), _save(PLAIN.replace("plain", "pléin"))], []),
    "save with secrets": (_tree(PLAIN), [_save(PLAIN + "metrics: {token_sha256: " + "ab" * 32 + "}\n"
                                              "ztna:\n  enabled: true\n  users:\n    - {username: kid, "
                                              "password_hash: \"$argon2id$v=19$x\"}\n")], []),
}

#: Steps that fail: what a program answers, by the step it breaks.
FAILURES = {
    "ruleset check": [{"argv": ["nft", "-c"], "rc": 1, "stderr": "Error: syntax error, unexpected\n"}],
    "ruleset load": [{"argv": ["nft", "-f"], "rc": 1, "stderr": "Error: Could not process rule\n"}],
    "no nft": [{"argv": ["nft"], "error": "missing"}],
    "kea check": [{"argv": ["kea-dhcp4", "-t"], "rc": 1, "stderr": "DHCP4_CONFIG_LOAD_FAIL\n"}],
    "kea restart": [{"argv": ["systemctl", "restart", "--", "kea-dhcp4-server"], "rc": 1, "stderr": "Job failed.\n"}],
    "dnsmasq check": [{"argv": ["dnsmasq", "--test"], "rc": 1, "stderr": "dnsmasq: bad option\n"}],
    "adblock restart": [{"argv": ["systemctl", "restart", "--", "fr-adblock-dns"], "rc": 1, "stderr": "failed\n"}],
    "address": [{"argv": ["ip", "addr", "replace", "10.0.0.1/24"], "rc": 2, "stderr": "RTNETLINK answers: File exists\n"}],
    "link up": [{"argv": ["ip", "link", "set", "dev", "eth1", "up"], "rc": 1, "stderr": "Cannot find device\n"}],
    "systemctl timeout": [{"argv": ["systemctl", "restart"], "error": "timeout"}],
    "wireguard sync": [{"argv": ["wg", "syncconf"], "rc": 1, "stderr": "Unable to modify interface\n"}],
    "wireguard new": [{"argv": ["ip", "link", "show", "dev", "wg0"], "rc": 1, "stderr": "Device does not exist.\n"},
                      {"argv": ["ip", "link", "add"], "rc": 2, "stderr": "Error: Unknown device type.\n"}],
    "wireguard address": [{"argv": ["ip", "addr", "replace", "10.9.0.1/24"], "rc": 2, "stderr": "bad\n"}],
    "wg": [{"argv": ["wg"], "error": "missing"}],
    "dhcpcd": [{"argv": ["systemctl", "restart", "--", "fr-dhcp6"], "rc": 1, "stderr": "failed\n"}],
    "ra": [{"argv": ["systemctl", "restart", "--", "fr-ra"], "rc": 1, "stderr": "failed\n"}],
    "ra check": [{"argv": ["@ROOT@/usr/sbin/dnsmasq", "--test"], "rc": 1, "stderr": "bad\n"}],
    "ula": [{"argv": ["ip", "-6", "addr", "replace", "fd12:3456:789a::1/64"], "rc": 2, "stderr": "bad\n"}],
    "ssh reload": [{"argv": ["systemctl", "try-reload-or-restart", "--", "ssh"], "rc": 1, "stderr": "failed\n"}],
    "ssh stop": [{"argv": ["systemctl", "stop", "--", "ssh.service"], "rc": 1, "stderr": "failed\n"}],
    "ssh is-enabled": [{"argv": ["systemctl", "is-enabled", "--", "ssh.service"], "stdout": "enabled\n"},
                       {"argv": ["systemctl", "is-active", "--", "ssh.service"], "stdout": "active\n"}],
    "webui listening": [{"argv": ["ss"], "stdout": "LISTEN 0 4096 127.0.0.1:443 0.0.0.0:*\n"}],
    "system starting": [{"argv": ["systemctl", "is-system-running"], "rc": 1, "stdout": "starting\n"}],
    "revert unit": [{"argv": ["systemctl", "restart", "--", "fr-apply-revert.service"], "rc": 5,
                     "stderr": "Unit fr-apply-revert.service not found.\n"}],
    "revert unit missing": [{"argv": ["systemctl", "restart", "--", "fr-apply-revert.service"], "error": "missing"}],
    "kea active": [{"argv": ["systemctl", "is-active", "--", "kea-dhcp4-server"], "stdout": "active\n"}],
}


@pytest.mark.parametrize("name", sorted(SESSIONS))
def test_session(system, name):
    setup, requests, table = SESSIONS[name]
    links = _links(setup["etc/fr_os/config.yaml"]) if "etc/fr_os/config.yaml" in setup else []
    if name == "fresh rich":
        links = []  # what 1.x says when `ip` lists no device
    _session(system, f"session/{name}", setup, requests, table + links, RANDOM)


@pytest.mark.parametrize("name", ["ok", "sshd -t fails", "sshd missing", "not listening", "ssh up",
                                  "drop-in rejected", "no sshd"])
def test_ssh_users(system, name):
    mlkem = {"argv": ["/usr/bin/ssh", "-Q", "kex"], "stdout": "curve25519-sha256\nmlkem768x25519-sha256\n"}
    table = {"ok": [mlkem], "sshd -t fails": [mlkem, {"argv": ["sshd", "-t"], "rc": 255, "stderr": "line 3: Bad\n"}],
             "sshd missing": [mlkem, {"argv": ["sshd"], "error": "missing"}],
             "drop-in rejected": [{"argv": ["sshd", "-t"], "after": 1, "rc": 255, "stderr": "line 3: Bad\n"}],
             "no sshd": [{"argv": ["sshd"], "after": 1, "error": "missing"}],
             "not listening": [{"argv": ["systemctl", "is-active", "--", "ssh.service"], "stdout": "active\n"}],
             "ssh up": [{"argv": ["systemctl", "is-active", "--", "ssh.service"], "stdout": "active\n"},
                        {"argv": ["ss", "-Hltn", "sport = :22"], "stdout": "LISTEN 0 128 10.0.0.1:22 0.0.0.0:*\n"
                                                                     "LISTEN 0 128 127.0.0.1:22 0.0.0.0:*\n"}]}[name]
    _session(system, f"ssh/{name}", _tree(RICH2, RICH, **{"run/sshd/": ""}), [{"cmd": "apply", "confirm": True}],
             table + [RUNNING] + _links(RICH2), RANDOM, login_users=("alice", "bob"))


def test_hybrid_pqc(system):
    _session(system, "session/hybrid pqc", _tree(RICH), [{"cmd": "apply"}], [RUNNING] + _links(RICH), RANDOM,
             openssl=HYBRID_OPENSSL)


@pytest.mark.parametrize("name", sorted(FAILURES))
def test_failure(system, name):
    _session(system, f"failure/{name}", _tree(RICH2, RICH), [{"cmd": "apply", "confirm": True}],
             FAILURES[name] + [RUNNING] + _links(RICH2), RANDOM)
