"""FR_OS 1.x's applies, run against a recorded fake of the system, with
the capture plugin (reference/generate.sh runs this module after the
render module, so it sees every config the run accepted).

Each case is a short session with 1.x's apply-helper request handler
(frfw.helper.server._handle_request): an apply, a dry run, an apply held
for confirmation and then confirmed or reverted, a rollback, a save; or
the commands that act on one host, with the neighbour table and nft
answering from the case's table (a ban, a quarantine, a ZTNA sign-in,
IoT isolation, the conntrack sample, an activity-log entry), and the
ones that read the system for the webUI's views (the firewall's drops,
WireGuard, the XDP counters, IPv6, the listening sockets, the RAM
modules, the IoT scan), with every program's output as it comes and
then odd; and moving the webUI's address (config.yaml rewritten with
yaml.safe_dump, then applied) and refreshing the ad-block lists, with
urllib.request.urlopen answering from the case's "fetch" table.
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
        self.fetch: list = []
        #: The case's accounts, when it gives them (the CLI's
        #: ensure-accounts): users by uid, groups with gid and members,
        #: changed by useradd, groupadd, usermod and gpasswd; None is no
        #: account at all.
        self.accounts: dict | None = None
        self.active = False
        allowed = {str(root), os.path.realpath(root), "/dev/null", "/dev/urandom", "/usr/share/zoneinfo",
                   "/usr/share/locale", "/usr/local/share/locale",  # argparse's gettext
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
        if not proc.returncode and self.accounts is not None:
            _account_change(self.accounts, argv)
        if check and proc.returncode:
            raise subprocess.CalledProcessError(proc.returncode, args, out, err)
        return proc


#: The first id an account the case creates gets: none a real one has.
FIRST_ID = 64900


def _account_change(accounts: dict, argv: list[str]) -> None:
    """What useradd, groupadd, usermod and gpasswd change, as the Go
    replay's fake does."""
    users, groups = accounts["users"], accounts["groups"]

    def next_id() -> int:
        return FIRST_ID + len(accounts.setdefault("made", []))

    if argv[:1] == ["useradd"] and argv[-2] == "--":
        uid = next_id()
        accounts["made"].append(argv[-1])
        users[argv[-1]] = uid
        if "--user-group" in argv:
            groups[argv[-1]] = {"gid": uid, "members": []}
    elif argv[:1] == ["groupadd"] and argv[-2] == "--":
        gid = next_id()
        accounts["made"].append(argv[-1])
        groups[argv[-1]] = {"gid": gid, "members": []}
    elif argv[:3] == ["usermod", "--append", "--groups"] and argv[-2] == "--" and argv[3] in groups:
        groups[argv[3]]["members"].append(argv[-1])
    elif argv[:2] == ["gpasswd", "--delete"] and argv[3] in groups:
        groups[argv[3]]["members"] = [m for m in groups[argv[3]]["members"] if m != argv[2]]


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

    # Every module an apply uses is imported before the paths are moved:
    # one first imported during a session would keep the router's paths.
    from frfw import accounts, cli, provision, rule_hits, schedule_refresh, xdp  # noqa: F401
    from frfw.adblock import dns_service  # noqa: F401
    from frfw.helper import server  # noqa: F401
    from frfw.webui import audit  # noqa: F401

    _reroot(monkeypatch, root)
    monkeypatch.setattr(accounts, "NOLOGIN", "/usr/sbin/nologin")  # a shell's name, not a file it opens
    from frfw import management

    monkeypatch.setattr(management, "ssh_login_users", management.ssh_login_users)  # each session sets it
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: state["fake"].run(*a, **k))
    # The XDP SNI filter as on an installed router: its object shipped,
    # never compiled from a checkout (frfw.xdp.ensure_compiled); and GRO's
    # SIOCETHTOOL ioctl answered from the case's table, as a call
    # ["ioctl", "SIOCETHTOOL", device, command(, value)] whose rc is the
    # errno and whose stdout is the value read.
    monkeypatch.setattr(xdp, "_checkout_source", lambda: None)

    def ethtool(device: str, cmd: int, data: int = 0) -> int:
        name = {xdp._ETHTOOL_GGRO: "ETHTOOL_GGRO", xdp._ETHTOOL_SGRO: "ETHTOOL_SGRO"}[cmd]
        argv = ["ioctl", "SIOCETHTOOL", xdp._device(device), name]
        if cmd == xdp._ETHTOOL_SGRO:
            argv.append(str(data))
        proc = state["fake"].run(argv, text=True)
        if proc.returncode:
            raise OSError(proc.returncode, os.strerror(proc.returncode))
        return int(proc.stdout) if proc.stdout.strip() else 0

    monkeypatch.setattr(xdp, "_ethtool_value", ethtool)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    def chown(path, uid, gid, *a, **k):
        """Nothing changes; with the case's accounts, recorded as a call
        ["chown", path, uid, gid]."""
        fake = state.get("fake")
        if fake is not None and fake.accounts is not None:
            fake.calls.append({"argv": ["chown", os.fspath(path), str(uid), str(gid)], "input": None,
                               "timeout": None})

    def getgrnam(name):
        fake = state.get("fake")
        groups = (fake.accounts or {}).get("groups", {}) if fake is not None else {}
        if name not in groups:
            raise KeyError(name)
        g = groups[name]
        return types.SimpleNamespace(gr_name=name, gr_gid=g["gid"], gr_mem=list(g["members"]))

    def getpwnam(name):
        fake = state.get("fake")
        users = (fake.accounts or {}).get("users", {}) if fake is not None else {}
        if name not in users:
            raise KeyError(name)
        return types.SimpleNamespace(pw_name=name, pw_uid=users[name], pw_gid=users[name])

    monkeypatch.setattr(os, "chown", chown)
    monkeypatch.setattr(os, "fchown", lambda *a, **k: None)
    monkeypatch.setattr(shutil, "which", lambda name, *a, **k: "/usr/bin/" + name)
    monkeypatch.setattr(grp, "getgrnam", getgrnam)
    monkeypatch.setattr(pwd, "getpwnam", getpwnam)
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
    import urllib.error
    import urllib.request

    def urlopen(request, timeout=None):
        """The case's "fetch" table: a body (text, or hex), an HTTP
        status, or a URLError's reason; never the network."""
        url = request.full_url if isinstance(request, urllib.request.Request) else request
        for answer in state["fake"].fetch:
            if answer["url"] != url:
                continue
            if "status" in answer:
                raise urllib.error.HTTPError(url, answer["status"], answer["reason"], {}, None)
            if "error" in answer:
                raise urllib.error.URLError(answer["error"])
            body = bytes.fromhex(answer["hex"]) if "hex" in answer else answer["body"].encode()
            return _Response(body)
        raise urllib.error.URLError("not in the case's table")

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    yield root, make
    _hook_fake.clear()


class _Response:
    def __init__(self, body: bytes):
        self.body = body

    def read(self) -> bytes:
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _snapshot(root: Path, max_text: int = MAX_TEXT) -> dict:
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
            if text is not None and len(text.encode()) > max_text:
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
             login_users: tuple[str, ...] = (), fetch: list | None = None, accounts: dict | None = None) -> None:
    from frfw.helper import server as helper_server
    from frfw.helper.peer import PeerPolicy

    root, make = system
    from frfw import management

    fake = make(table or [], random, openssl)
    fake.fetch = fetch or []
    management.ssh_login_users = lambda: list(login_users)  # the fixture puts it back
    if accounts is not None:
        fake.accounts = copy.deepcopy(accounts)
    fp = _fingerprint(setup)
    for rel, content in setup.items():
        path = root / rel
        if rel.endswith("/"):
            path.mkdir(parents=True, exist_ok=True)
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, dict):  # {"size": n}: n zero bytes, sparse
            with open(path, "wb") as f:
                f.truncate(content["size"])
            continue
        path.write_text(content.replace(FINGERPRINT, fp))
    before = _snapshot(root, max_text=1 << 20)  # in full: the replay writes it
    for rel, content in setup.items():
        if isinstance(content, dict):
            before[rel] = {"mode": before[rel]["mode"], "size": content["size"]}
        elif isinstance(content, str) and FINGERPRINT in content:
            before[rel]["text"] = before[rel]["text"].replace(fp, FINGERPRINT)
    server = types.SimpleNamespace(
        config_path=root / "etc/fr_os/config.yaml", backup_dir=root / "etc/fr_os/backups",
        kea_config_path=root / "etc/kea/kea-dhcp4.conf", sensor_config_path=root / "etc/fr_os/sensor-config.yaml",
        ztna_state_path=root / "etc/fr_os/ztna_state.json", audit_log_path=root / "var/log/fr_os/audit.log",
        kea_leases_path=root / "var/lib/kea/kea-leases4.csv", adblock_hosts_path=root / "etc/fr_os/adblock.hosts",
        adblock_category_dir=root / "etc/fr_os/adblock.d",
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
            elif "cli" in request:  # firewall-cli, its argv with the root as "@ROOT@"
                reply = _cli([a.replace("@ROOT@", str(root)) for a in request["cli"]])
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
    if fetch is not None:
        case["fetch"] = fetch
    if accounts is not None:
        case["accounts"] = accounts
    if decided:
        case["decided"] = decided
    _record(_rooted(case, str(root)))


#: In a setup file, the fingerprint of the setup's config.yaml as each
#: implementation computes its own (decisions.md, "The schedule record's
#: fingerprint").
FINGERPRINT = "@FP@"


def _fingerprint(setup: dict) -> str:
    from frfw import schedule_refresh
    from frfw.config.loader import parse_config

    text = setup.get("etc/fr_os/config.yaml")
    if not any(isinstance(v, str) and FINGERPRINT in v for v in setup.values()):
        return FINGERPRINT
    return schedule_refresh.config_fingerprint(parse_config(yaml.safe_load(text)))


def _cli(argv: list[str]) -> dict:
    """firewall-cli with argv: its exit status and what it printed."""
    import contextlib
    import io

    from frfw import cli

    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(argv)
        except SystemExit as exc:  # argparse
            code = exc.code if isinstance(exc.code, int) else 1
    return {"code": code, "stdout": out.getvalue(), "stderr": err.getvalue()}


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


#: The XDP program's object, as the image ships it (frfw.paths.XDP_BPF_OBJ_PATH).
XDP_OBJECT = "usr/local/share/fr_os/bpf/xdp_sni_filter.o"
XDP_OBJECT_TEXT = "an XDP object\n"
XDP_DIGEST = hashlib.sha256(XDP_OBJECT_TEXT.encode()).hexdigest()


def _setup(raw: dict) -> dict:
    text = yaml.safe_dump(raw, sort_keys=False)
    setup = {"etc/fr_os/config.yaml": text, "proc/sys/net/ipv4/ip_forward": "0\n", "usr/sbin/dhcpcd": "",
             "usr/sbin/dnsmasq": ""}
    if (raw.get("xdp_sni_filter") or {}).get("enabled") is True:
        setup[XDP_OBJECT] = XDP_OBJECT_TEXT
    for name in ["all", "default", "wg0"] + _devices(raw):
        if name not in ("all", "default", "wg0"):
            setup[f"sys/class/net/{name}/"] = ""
        for family, key, value in SYSCTLS:
            setup[f"proc/sys/net/{family}/conf/{name}/{key}"] = value + "\n"
    return setup


#: How many of the run's accepted configs are applied (every n-th, so
#: they spread over 1.x's suite), and how many of those with the XDP SNI
#: filter on.
SAMPLE = 40
SAMPLE_XDP = 8

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
        _session(system, f"apply/{key}", setup, requests, _links(setup["etc/fr_os/config.yaml"]), RANDOM)
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


# --- the XDP SNI filter (frfw.xdp.sync_sni_filter, phase 4d-2) -----------------------
#
# Loading, keeping, replacing and unloading the program, attaching it in
# either mode (and GRO with generic mode), the blocklist, the settings,
# the readers' restart, and every program failing in turn. Nothing runs:
# `bpftool`, `ip` and the ioctl answer from the case's table, and the
# pins are files in the case's tree.

XDP = PLAIN + "xdp_sni_filter: {enabled: true, interfaces: [lan], blocklist: [ads.example.com, Tracker.Example.NET., " \
              "tracker.example.net, a.b]}\n"
XDP_TWO = XDP.replace("  lan: {device: eth1, zone: lan, address: 192.168.7.1/24}\n",
                      "  lan: {device: eth1, zone: lan, address: 192.168.7.1/24}\n"
                      "  guest: {device: eth2, zone: lan, address: 192.168.8.1/24}\n").replace(
    "interfaces: [lan]", "interfaces: [lan, guest]")
XDP_OFF = XDP.replace("{enabled: true, interfaces: [lan]", "{enabled: false, interfaces: [lan]")
XDP_OBSERVE = XDP + "app_control: {enabled: true, observe_sni: true}\ntls_fingerprint: {enabled: true}\n"
XDP_ADBLOCK = XDP + ("adblocker: {enabled: true, source_urls: [\"https://example.com/hosts\"], "
                     "xdp_critical_limit: 5000}\n")
XDP_RICH = RICH + "xdp_sni_filter: {enabled: true, interfaces: [lan], blocklist: [ads.example.com]}\n"
XDP_RICH2 = RICH2 + "xdp_sni_filter: {enabled: true, interfaces: [lan], blocklist: [ads.example.com, b.example]}\n"

PIN = "sys/fs/bpf/fr_os_xdp/"
PINS = {PIN + "prog/xdp_sni_filter": "", PIN + "prog/xdp_sni_split": "", PIN + "maps/sni_blocklist": "",
        PIN + "maps/stats": "", PIN + "maps/events": ""}
OBSERVING_PINS = {**PINS, PIN + "maps/settings": "", PIN + "maps/hello_pkts": ""}
BPFTOOL_PROG = ["bpftool", "-j", "prog", "show", "pinned", "@ROOT@/" + PIN + "prog/xdp_sni_filter"]
BLOCKLIST_PIN = "@ROOT@/" + PIN + "maps/sni_blocklist"


def _json_answer(argv, value) -> dict:
    return {"argv": argv, "stdout": json.dumps(value)}


def _state(attached: dict, program: str | None = XDP_DIGEST, gro_off: tuple = ()) -> str:
    return json.dumps({"attached": attached, "program": program, "gro_off": list(gro_off)})


def _xdp_link(device: str, mode: int, prog_id: int, name: str = "xdp_sni_filter", multi: bool = False) -> dict:
    prog = {"id": prog_id, "name": name, "tag": "0123456789abcdef", "jited": 1}
    xdp = {"attached": [{"mode": mode, "prog": prog}]} if multi else {"mode": mode, "prog": prog}
    return _json_answer(["ip", "-j", "link", "show", "dev", device], [{"ifname": device, "xdp": xdp}])


def _lpm(name: str) -> dict:
    from frfw import xdp

    key = xdp.build_lpm_key(name)
    return {"key": {"prefixlen": int.from_bytes(key[:4], "little"), "reversed": list(key[4:4 + xdp.LPM_KEY_LEN])},
            "value": 1}


NATIVE_FAILS = {"argv": ["ip", "link", "set", "dev", "eth1", "xdpdrv"], "rc": 2,
                "stderr": "Error: Underlying driver does not support XDP in native mode.\n"}
PINNED_42 = {"argv": BPFTOOL_PROG, "stdout": json.dumps({"id": 42, "type": "xdp", "name": "xdp_sni_filter"})}
OBJ = {XDP_OBJECT: XDP_OBJECT_TEXT}
STATE = "etc/fr_os/xdp_state.json"

XDP_SESSIONS = {
    "native": (_tree(XDP, **OBJ), [{"cmd": "apply"}], []),
    "dry run": (_tree(XDP, **OBJ), [{"cmd": "apply", "dry_run": True}], []),
    "two devices": (_tree(XDP_TWO, **OBJ), [{"cmd": "apply"}], [
        {"argv": ["ip", "link", "set", "dev", "eth2", "xdpdrv"], "rc": 2, "stderr": "Error: native.\n"},
        {"argv": ["ioctl", "SIOCETHTOOL", "eth2", "ETHTOOL_GGRO"], "stdout": "1"}]),
    "generic, gro off": (_tree(XDP, **OBJ), [{"cmd": "apply"}], [
        NATIVE_FAILS, {"argv": ["ioctl", "SIOCETHTOOL", "eth1", "ETHTOOL_GGRO"], "stdout": "1"}]),
    "generic, gro already off": (_tree(XDP, **OBJ), [{"cmd": "apply"}], [
        NATIVE_FAILS, {"argv": ["ioctl", "SIOCETHTOOL", "eth1", "ETHTOOL_GGRO"], "stdout": "0"}]),
    "generic, gro unreadable": (_tree(XDP, **OBJ), [{"cmd": "apply"}], [
        NATIVE_FAILS, {"argv": ["ioctl", "SIOCETHTOOL", "eth1", "ETHTOOL_GGRO"], "rc": 95}]),
    "generic, gro stays on": (_tree(XDP, **OBJ), [{"cmd": "apply"}], [
        NATIVE_FAILS, {"argv": ["ioctl", "SIOCETHTOOL", "eth1", "ETHTOOL_GGRO"], "stdout": "1"},
        {"argv": ["ioctl", "SIOCETHTOOL", "eth1", "ETHTOOL_SGRO"], "rc": 1}]),
    "attach fails": (_tree(XDP, **OBJ), [{"cmd": "apply"}], [
        NATIVE_FAILS, {"argv": ["ip", "link", "set", "dev", "eth1", "xdpgeneric"], "rc": 2,
                       "stderr": "Error: no such device.\n"}]),
    "kept": (_tree(XDP, **OBJ, **PINS, **{STATE: _state({"eth1": "xdpdrv"})}), [{"cmd": "apply"}], [
        _xdp_link("eth1", 1, 42), PINNED_42,
        _json_answer(["bpftool", "map", "dump", "pinned", BLOCKLIST_PIN], [_lpm("ads.example.com"), _lpm("old.example")])]),
    "kept, generic, gro back on": (_tree(XDP, **OBJ, **PINS, **{STATE: _state({"eth1": "xdpgeneric"})}),
                                   [{"cmd": "apply"}], [
        _xdp_link("eth1", 2, 42, multi=True), PINNED_42,
        {"argv": ["ioctl", "SIOCETHTOOL", "eth1", "ETHTOOL_GGRO"], "stdout": "1"}]),
    "kept, native, gro was off": (_tree(XDP, **OBJ, **PINS, **{STATE: _state({"eth1": "xdpdrv"}, gro_off=["eth1"])}),
                                  [{"cmd": "apply"}], [_xdp_link("eth1", 1, 42), PINNED_42]),
    "older program attached": (_tree(XDP, **OBJ, **PINS, **{STATE: _state({"eth1": "xdpdrv"})}), [{"cmd": "apply"}], [
        _xdp_link("eth1", 1, 7), PINNED_42]),
    "other program attached": (_tree(XDP, **OBJ, **PINS, **{STATE: _state({"eth1": "xdpdrv"})}), [{"cmd": "apply"}], [
        _xdp_link("eth1", 1, 9, name="someone_else"), PINNED_42]),
    "pinned id unknown": (_tree(XDP, **OBJ, **PINS, **{STATE: _state({"eth1": "xdpdrv"})}), [{"cmd": "apply"}], [
        _xdp_link("eth1", 1, 7), {"argv": BPFTOOL_PROG, "rc": 255, "stderr": "Error: bpf obj get: No such file\n"}]),
    "after reboot": (_tree(XDP, **OBJ, **{STATE: _state({"eth1": "xdpdrv"})}), [{"cmd": "apply"}], []),
    "replaced": (_tree(XDP, **OBJ, **PINS, **{STATE: _state({"eth1": "xdpdrv"}, program="0" * 64)}),
                 [{"cmd": "apply"}], [_xdp_link("eth1", 1, 7), PINNED_42]),
    "replaced, origin unknown": (_tree(XDP, **OBJ, **PINS, **{STATE: _state({"eth1": "xdpdrv"}, program=None)}),
                                 [{"cmd": "apply"}], [_xdp_link("eth1", 1, 7), PINNED_42]),
    "replace fails": (_tree(XDP, **OBJ, **PINS, **{STATE: _state({"eth1": "xdpdrv"}, program="0" * 64)}),
                      [{"cmd": "apply"}], [
        {"argv": ["bpftool", "prog", "loadall"], "rc": 255, "stderr": "libbpf: prog 'x': BPF program load failed\n"}]),
    "load fails": (_tree(XDP, **OBJ), [{"cmd": "apply"}], [
        {"argv": ["bpftool", "prog", "loadall"], "rc": 255, "stderr": "libbpf: failed to load object\n"}]),
    "no object": (_tree(XDP), [{"cmd": "apply"}], []),
    "no bpftool": (_tree(XDP, **OBJ), [{"cmd": "apply"}], [{"argv": ["bpftool"], "error": "missing"}]),
    "blocklist dump fails": (_tree(XDP, **OBJ), [{"cmd": "apply"}], [
        {"argv": ["bpftool", "map", "dump"], "rc": 255, "stderr": "Error: bpf obj get\n"}]),
    "blocklist update fails": (_tree(XDP, **OBJ), [{"cmd": "apply"}], [
        {"argv": ["bpftool", "map", "update"], "after": 1, "rc": 255, "stderr": "Error: update failed\n"}]),
    "blocklist delete fails": (_tree(XDP, **OBJ, **PINS, **{STATE: _state({"eth1": "xdpdrv"})}), [{"cmd": "apply"}], [
        _json_answer(["bpftool", "map", "dump", "pinned", BLOCKLIST_PIN], [_lpm("old.example")]),
        {"argv": ["bpftool", "map", "delete"], "rc": 255, "stderr": "Error: delete failed\n"}]),
    "link unreadable": (_tree(XDP, **OBJ, **PINS, **{STATE: _state({"eth1": "xdpdrv"})}), [{"cmd": "apply"}], [
        {"argv": ["ip", "-j", "link", "show", "dev", "eth1"], "stdout": "{not json"}, PINNED_42]),
    "link fails": (_tree(XDP, **OBJ, **PINS, **{STATE: _state({"eth1": "xdpdrv"})}), [{"cmd": "apply"}], [
        {"argv": ["ip", "-j", "link", "show", "dev", "eth1"], "rc": 1, "stderr": "Device does not exist.\n"},
        PINNED_42]),
    "device dropped": (_tree(XDP, **OBJ, **PINS, **{STATE: _state({"eth1": "xdpdrv", "eth2": "xdpgeneric"},
                                                                  gro_off=["eth2"])}), [{"cmd": "apply"}], [
        _xdp_link("eth1", 1, 42), _xdp_link("eth2", 2, 42), PINNED_42]),
    "device dropped, gone": (_tree(XDP, **OBJ, **PINS, **{STATE: _state({"eth1": "xdpdrv", "eth9": "xdpgeneric"},
                                                                        gro_off=["eth9"])}), [{"cmd": "apply"}], [
        _xdp_link("eth1", 1, 42), PINNED_42, {"argv": ["ioctl", "SIOCETHTOOL", "eth9"], "rc": 19}]),
    "detach fails": (_tree(XDP, **OBJ, **PINS, **{STATE: _state({"eth1": "xdpdrv"})}), [{"cmd": "apply"}], [
        _xdp_link("eth1", 1, 7), PINNED_42,
        {"argv": ["ip", "link", "set", "dev", "eth1", "xdpdrv", "off"], "rc": 2, "stderr": "Error: busy.\n"}]),
    "observing": (_tree(XDP_OBSERVE, **OBJ, **OBSERVING_PINS, **{STATE: _state({"eth1": "xdpdrv"})}),
                  [{"cmd": "apply"}], [_xdp_link("eth1", 1, 42), PINNED_42]),
    "observing, old program": (_tree(XDP_OBSERVE, **OBJ, **PINS, **{PIN + "maps/settings": ""},
                                     **{STATE: _state({"eth1": "xdpdrv"})}), [{"cmd": "apply"}], [
        _xdp_link("eth1", 1, 42), PINNED_42]),
    "observing, older program": (_tree(XDP_OBSERVE, **OBJ, **PINS, **{STATE: _state({"eth1": "xdpdrv"})}),
                                 [{"cmd": "apply"}], [_xdp_link("eth1", 1, 42), PINNED_42]),
    "observing, settings fail": (_tree(XDP_OBSERVE, **OBJ, **OBSERVING_PINS, **{STATE: _state({"eth1": "xdpdrv"})}),
                                 [{"cmd": "apply"}], [
        _xdp_link("eth1", 1, 42), PINNED_42,
        {"argv": ["bpftool", "map", "update", "pinned", "@ROOT@/" + PIN + "maps/settings"], "rc": 255,
         "stderr": "Error: update failed\n"}]),
    "settings off": (_tree(XDP, **OBJ, **OBSERVING_PINS, **{STATE: _state({"eth1": "xdpdrv"})}), [{"cmd": "apply"}], [
        _xdp_link("eth1", 1, 42), PINNED_42]),
    "readers fail": (_tree(XDP, **OBJ), [{"cmd": "apply"}], [
        {"argv": ["systemctl", "try-restart", "--", "fr-xdp-sni-logger.service"], "rc": 5, "stderr": "failed\n"},
        {"argv": ["systemctl", "try-restart", "--", "fr-tls-fp.service"], "error": "timeout"}]),
    "off": (_tree(XDP_OFF, **PINS, **{STATE: _state({"eth1": "xdpgeneric"}, gro_off=["eth1"])}), [{"cmd": "apply"}], [
        _xdp_link("eth1", 2, 42)]),
    "off, dry run": (_tree(XDP_OFF, **PINS, **{STATE: _state({"eth1": "xdpgeneric"})}),
                     [{"cmd": "apply", "dry_run": True}], [_xdp_link("eth1", 2, 42)]),
    "off, nothing attached": (_tree(XDP_OFF, **{STATE: _state({})}), [{"cmd": "apply"}], []),
    "off, after reboot": (_tree(XDP_OFF, **{STATE: _state({"eth1": "xdpdrv", "eth2": "xdpgeneric"},
                                                          gro_off=["eth2"])}), [{"cmd": "apply"}], [
        {"argv": ["ioctl", "SIOCETHTOOL", "eth2"], "rc": 19}]),
    "off, detach fails": (_tree(XDP_OFF, **PINS, **{STATE: _state({"eth1": "xdpdrv"})}), [{"cmd": "apply"}], [
        _xdp_link("eth1", 1, 42),
        {"argv": ["ip", "link", "set", "dev", "eth1", "xdpdrv", "off"], "rc": 2, "stderr": "Error: busy.\n"}]),
    "state unreadable": (_tree(XDP, **OBJ, **{STATE: "{not json"}), [{"cmd": "apply"}], []),
    "state odd": (_tree(XDP, **OBJ, **{STATE: json.dumps({"attached": {"eth1": "xdpdrv"}, "program": 5,
                                                          "gro_off": ["eth1", 3]})}), [{"cmd": "apply"}], []),
    "state not a list": (_tree(XDP, **OBJ, **{STATE: json.dumps({"attached": {}, "gro_off": "eth1"})}),
                         [{"cmd": "apply"}], []),
    "too many names": (_tree(XDP_ADBLOCK, **OBJ, **{"etc/fr_os/adblock.hosts": "".join(
        f"0.0.0.0 d{i}.example\n" for i in range(4100))}), [{"cmd": "apply"}], []),
    "names from the ad-block list": (_tree(XDP_ADBLOCK, **OBJ, **{"etc/fr_os/adblock.hosts":
        "0.0.0.0 Zz.Example.\n0.0.0.0 ads.example.com\n0.0.0.0 " + "x" * 40 + ".example\n"}),
        [{"cmd": "apply"}], []),
    "ad-block name not ASCII": (_tree(XDP_ADBLOCK, **OBJ, **{"etc/fr_os/adblock.hosts": "0.0.0.0 b\u00fccher.de\n"}),
                                [{"cmd": "apply"}], []),
    "ad-block name only dots": (_tree(XDP_ADBLOCK, **OBJ, **{"etc/fr_os/adblock.hosts": "0.0.0.0 ...\n"}),
                                [{"cmd": "apply"}], []),
}


@pytest.mark.parametrize("name", sorted(XDP_SESSIONS))
def test_xdp_session(system, name):
    setup, requests, table = XDP_SESSIONS[name]
    _session(system, f"xdp/{name}", setup, requests, table + _links(setup["etc/fr_os/config.yaml"]), RANDOM)


#: A later step fails: the filter goes back to the previous config's.
XDP_FAILURES = {
    "ssh reload": [{"argv": ["systemctl", "try-reload-or-restart", "--", "ssh"], "rc": 1, "stderr": "failed\n"}],
    "webui listening": [{"argv": ["ss"], "stdout": "LISTEN 0 4096 127.0.0.1:443 0.0.0.0:*\n"}],
}


@pytest.mark.parametrize("name", sorted(XDP_FAILURES))
def test_xdp_failure(system, name):
    setup = _tree(XDP_RICH2, XDP_RICH, **OBJ, **PINS, **{STATE: _state({"eth1": "xdpdrv"})})
    _session(system, f"xdp failure/{name}", setup, [{"cmd": "apply", "confirm": True}],
             XDP_FAILURES[name] + [_xdp_link("eth1", 1, 42), PINNED_42, RUNNING] + _links(XDP_RICH2), RANDOM)


def test_xdp_failure_nothing_applied(system):
    """No config was applied before: the filter's undo is unknown unless
    nothing was attached or loaded."""
    for name, extra in (("unknown", {**PINS, STATE: _state({"eth1": "xdpdrv"})}), ("fresh", {})):
        setup = _tree(XDP_RICH2, None, **OBJ, **extra)
        _session(system, f"xdp failure/nothing applied, {name}", setup, [{"cmd": "apply"}],
                 XDP_FAILURES["ssh reload"] + [_xdp_link("eth1", 1, 42), PINNED_42, RUNNING] + _links(XDP_RICH2),
                 RANDOM)
        root, _ = system
        shutil.rmtree(root)
        root.mkdir()


# --- the commands that act on one host (phase 2c-1) ---------------------------------
#
# The brute-force jail, the IDS quarantine, ZTNA's sign-in, IoT isolation,
# the conntrack sample and the activity log: each with the neighbour
# table, nft and the files they read answering from the case's table.

HOSTS = """\
version: 1
hostname: fr-router
interfaces:
  wan: {device: eth0, zone: wan, address: 203.0.113.2/24}
  lan: {device: eth1, zone: lan, address: 10.0.0.1/24}
  iot: {device: eth2, zone: iot, address: 10.0.2.1/24}
zones: {wan: {}, lan: {}, iot: {}, vpn: {}}
rules:
  - {name: lan-to-wan, action: accept, from_zone: lan, to_zone: wan}
  - {name: iot-to-wan, action: accept, from_zone: iot, to_zone: wan}
nat: {masquerade: [{out_zone: wan}]}
ipv6: {enabled: true, lan_zones: [lan], ula_prefix: "fd12:3456:789a::/48"}
wireguard:
  enabled: true
  address: 10.9.0.1/24
  listen_port: 51820
  peers: [{name: phone, public_key: "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=", address: 10.9.0.2}]
ztna:
  enabled: true
  session_ttl_seconds: 900
  users: [{username: kid, password_hash: "$argon2id$v=19$x"}]
iot: {enabled: true, zones: [iot], trusted_macs: ["aa:bb:cc:00:00:01"]}
"""

MAC = "aa:bb:cc:dd:ee:01"


def _neigh(dst, dev="eth1", lladdr="AA:BB:CC:DD:EE:01", state=("REACHABLE",)):
    entry = {"dst": dst, "dev": dev, "lladdr": lladdr}
    if state is not None:
        entry["state"] = list(state) if isinstance(state, tuple) else state
    return entry


def _answer(argv, entries) -> dict:
    return {"argv": argv, "stdout": json.dumps(entries)}


#: The router's neighbour table, as each lookup asks for it.
NEIGH = [
    _answer(["ip", "-j", "-6", "neigh", "show", "to", "fd12:3456:789a::50"],
            [_neigh("fd12:3456:789a::49"), _neigh("fd12:3456:789A::50")]),
    _answer(["ip", "-j", "-6", "neigh", "show", "to", "fd12:3456:789a::60"], [_neigh("fd12:3456:789a::60", "eth0")]),
    _answer(["ip", "-j", "-6", "neigh", "show", "to", "fd12:3456:789a::70"], [_neigh("fd12:3456:789a::70", state="STALE")]),
    _answer(["ip", "-j", "-6", "neigh", "show", "to", "fd12:3456:789a::80"],
            [_neigh("fd12:3456:789a::80", state=("FAILED",)), _neigh("fd12:3456:789a::80", lladdr="zz", state=("STALE",)),
             _neigh("fd12:3456:789a::80", lladdr="AA:BB:CC:DD:EE:08", state=("PERMANENT", "x"))]),
    _answer(["ip", "-j", "-6", "neigh", "show", "to", "fd12:3456:789a::90"], [_neigh("fd12:3456:789a::90", state=None)]),
    _answer(["ip", "-j", "-6", "neigh", "show", "to", "fd12:3456:789a::91"], [_neigh("fd12:3456:789a::91", state=5)]),
    _answer(["ip", "-j", "-6", "neigh", "show", "to", "fd12:3456:789a::92"],
            [{"dst": "fd12:3456:789a::92", "dev": ["eth1"], "lladdr": MAC, "state": ["REACHABLE"]}]),
    {"argv": ["ip", "-j", "-6", "neigh", "show", "to", "fd12:3456:789a::93"], "rc": 1, "stderr": "bad\n"},
    {"argv": ["ip", "-j", "-6", "neigh", "show", "to", "fd12:3456:789a::94"], "stdout": "{not json"},
    {"argv": ["ip", "-j", "-6", "neigh", "show", "to", "fd12:3456:789a::95"], "error": "timeout"},
    _answer(["ip", "-j", "-4", "neigh", "show", "to", "10.0.0.50"], [_neigh("10.0.0.50")]),
    _answer(["ip", "-j", "-4", "neigh", "show", "to", "203.0.113.9"], [_neigh("203.0.113.9", "eth0")]),
    _answer(["ip", "-j", "-4", "neigh", "show"],
            [_neigh("10.0.0.52"), _neigh("10.0.0.50"), _neigh("10.0.0.1"), _neigh("203.0.113.5", "eth0"),
             _neigh("10.0.0.53", state=("FAILED",)), _neigh("10.0.0.54", lladdr="aa:bb:cc:dd:ee:02"),
             _neigh("not an address"), _neigh(167772215)]),
    _answer(["ip", "-j", "-6", "neigh", "show"],
            [_neigh("fd12:3456:789a::50"), _neigh("fe80::1%eth1", lladdr="aa:bb:cc:dd:ee:03"),
             _neigh("2001:db8::9", "eth0", lladdr="aa:bb:cc:dd:ee:04"), _neigh("FD12:3456:789A::51", lladdr="aa:bb:cc:dd:ee:05")]),
    # ZTNA's own reads (frfw.ztna): no family, NOARP counts.
    _answer(["ip", "-j", "neigh", "show", "to", "10.0.0.50"], [_neigh("10.0.0.50")]),
    _answer(["ip", "-j", "neigh", "show", "to", "10.0.0.51"], [_neigh("10.0.0.51", lladdr="aa:bb:cc:dd:ee:51", state=("NOARP",))]),
    _answer(["ip", "-j", "neigh", "show", "to", "10.0.0.56"], [_neigh("10.0.0.56", dev="-x")]),
    _answer(["ip", "-j", "neigh", "show", "to", "fd12:3456:789a::50"], [_neigh("fd12:3456:789a::50", state=("DELAY",))]),
    _answer(["ip", "-j", "neigh", "show", "dev", "eth1"],
            [_neigh("10.0.0.50"), _neigh("fd12:3456:789a::50"), _neigh("fe80::a"), _neigh("ff02::1"),
             _neigh("10.0.0.77", lladdr="aa:bb:cc:dd:ee:77"), _neigh("10.0.0.50"), _neigh("fd12:3456:789a::51", state=("FAILED",)),
             _neigh("::ffff:169.254.0.1"), _neigh("0.0.0.0"), _neigh("10.0.0.57", lladdr=None), "x"]),
]


def _set(name, elems) -> dict:
    return {"argv": ["nft", "-j", "--", "list", "set", "inet", "fr_os", name],
            "stdout": json.dumps({"nftables": [{"metainfo": {}}, {"set": {"name": name, "elem": elems}}]})}


ZTNA_SETS = [
    _set("authenticated_ztna_users", [{"elem": {"val": {"concat": ["10.0.0.50", "AA:BB:CC:DD:EE:01"]}, "expires": 800}},
                                      {"elem": {"val": "10.0.0.51", "expires": 5}}]),
    _set("authenticated_ztna_tunnel", [{"elem": {"val": "10.9.0.2", "expires": 700}}]),
    _set("authenticated_ztna_users6", [{"elem": {"val": {"concat": ["fd12:3456:789a::50", MAC]}, "expires": 600}}]),
]


def _cmd(cmd, **fields) -> dict:
    return {"cmd": cmd, **fields}


CONNTRACK = (
    "ipv4     2 tcp      6 431999 ESTABLISHED src=10.0.0.50 dst=93.184.216.34 sport=51000 dport=443 "
    "src=93.184.216.34 dst=203.0.113.2 sport=443 dport=51000 [ASSURED] mark=0 zone=0 use=2\n"
    "ipv4     2 udp      17 29 src=10.0.0.52 dst=9.9.9.9 sport=40000 dport=53 src=9.9.9.9 dst=203.0.113.2 "
    "sport=53 dport=40000 mark=0 use=1\n"
    "ipv4     2 icmp     1 29 src=10.0.0.50 dst=1.1.1.1 type=8 code=0 id=5 src=1.1.1.1 dst=203.0.113.2 type=0\n"
    "ipv6     10 tcp      6 300 ESTABLISHED src=fd12:3456:789a::50 dst=2001:db8::1 sport=50001 dport=443 "
    "src=2001:db8::1 dst=fd12:3456:789a::50 sport=443 dport=50001 [ASSURED] use=1\n"
    "ipv6     10 udp      17 30 src=fd12:3456:789A::51 dst=2001:db8::1 sport=x dport=53 src=2001:db8::1 "
    "dst=fd12:3456:789a::51 sport=53 dport=+0_9 use=1\n"
    "ipv6     10 tcp      6 300 ESTABLISHED src=2001:db8::99 dst=fd12:3456:789a::50 sport=1 dport=22 use=1\n"
    "ipv6     10 tcp      6 300 src=fe80::1%eth1 dst=fe80::2 sport=1 dport=2 use=1\n"
    "ipv6     10 tcp      6 300 src=bogus:: dst=fe80::2 sport=1 dport=2 use=1\n"
    "ipv4 2 tcp\n"
    "short line\n"
    "ipv4     2 tcp      6 1 src=1.2.3.4 dst=5.6.7.8 sport=1\n"
)

COMMAND_SESSIONS = {
    "ban": (_tree(HOSTS), [
        _cmd("ban_ip"), _cmd("ban_ip", ip=5), _cmd("ban_ip", ip=""), _cmd("ban_ip", ip="10.0.0.9", duration_seconds="x"),
        _cmd("ban_ip", ip="10.0.0.9", duration_seconds=True), _cmd("ban_ip", ip="10.0.0.9", duration_seconds=None),
        _cmd("ban_ip", ip="nonsense"), _cmd("ban_ip", ip="fe80::1%eth1"), _cmd("ban_ip", ip="10.0.0.9", duration_seconds=0),
        _cmd("ban_ip", ip="10.0.0.9", duration_seconds=-5), _cmd("ban_ip", ip="::ffff:10.0.0.9"), _cmd("ban_ip", ip="10.0.0.9"),
        _cmd("ban_ip", ip="10.0.0.9", duration_seconds=10 ** 20), _cmd("ban_ip", ip="fd12:3456:789a::50", duration_seconds=60),
        _cmd("ban_ip", ip="FD12:3456:789A::50"), _cmd("ban_ip", ip="2001:db8::7"), _cmd("ban_ip", ip="fd12:3456:789a::60"),
        _cmd("ban_ip", ip="fd12:3456:789a::70"), _cmd("ban_ip", ip="fd12:3456:789a::80"),
        _cmd("ban_ip", ip="fd12:3456:789a::90"), _cmd("ban_ip", ip="fd12:3456:789a::91"),
        _cmd("ban_ip", ip="fd12:3456:789a::92"), _cmd("ban_ip", ip="fd12:3456:789a::93"),
        _cmd("ban_ip", ip="fd12:3456:789a::94"), _cmd("ban_ip", ip="fd12:3456:789a::95"),
        _cmd("source_device"), _cmd("source_device", ip=["x"]), _cmd("source_device", ip="x"),
        _cmd("source_device", ip="10.0.0.9"), _cmd("source_device", ip="fd12:3456:789a::50"),
        _cmd("source_device", ip="fd12::1%x"), _cmd("source_device", ip="::ffff:1.2.3.4"),
        _cmd("source_device", ip="fd12:3456:789a::60"),
    ], NEIGH),
    "ban, nft refuses": (_tree(HOSTS), [_cmd("ban_ip", ip="10.0.0.9"), _cmd("ban_ip", ip="10.0.0.10")], [
        {"argv": ["nft", "--", "add", "element", "inet", "fr_os", "bruteforce_jail", "{", "10.0.0.9 timeout 3600s"],
         "rc": 1, "stderr": "Error: No such file or directory; did you mean set 'x'?\n"},
        {"argv": ["nft", "--", "add"], "rc": 1, "stderr": ""}]),
    "ban, no nft": (_tree(HOSTS), [_cmd("ban_ip", ip="10.0.0.9"), _cmd("quarantine_ip", ip="10.0.0.9"),
                                   _cmd("authorize_ztna", ip="10.9.0.2", username="kid"),
                                   _cmd("ztna_status", ip="10.9.0.2")], [{"argv": ["nft"], "error": "missing"}]),
    "ban, no config": ({}, [_cmd("ban_ip", ip="fd12:3456:789a::50"), _cmd("source_device", ip="fd12:3456:789a::50"),
                            _cmd("quarantine_ip", ip="10.0.0.1"), _cmd("quarantine_ip", ip="fd12:3456:789a::50"),
                            _cmd("conntrack_sample"), _cmd("authorize_ztna", ip="10.0.0.50", username="kid"),
                            _cmd("ztna_status", ip="10.0.0.50"), _cmd("iot_sync_isolation", macs=[])], NEIGH),
    "quarantine": (_tree(HOSTS), [
        _cmd("quarantine_ip"), _cmd("quarantine_ip", ip="10.0.0.50"), _cmd("quarantine_ip", ip="10.0.0.51"),
        _cmd("quarantine_ip", ip="203.0.113.9", duration_seconds=60), *[
            _cmd("quarantine_ip", ip=ip) for ip in (
                "10.0.0.1", "127.0.0.1", "0.0.0.0", "224.0.0.1", "169.254.1.1", "240.0.0.1", "255.255.255.255", "::1",
                "::", "fe80::1", "ff02::1", "::ffff:10.0.0.50", "10.0.0.5%x", "fd12::1%eth1", "x", "1:2", "10.9.0.1",
                "203.0.113.2", "010.0.0.5", "1.2.3", "2001:db8::/64", "fd12:3456:789a::61", "fd12:3456:789a::93",
                "200::1", "4000::1")],
        _cmd("quarantine_ip", ip="10.0.0.60", duration_seconds=0), _cmd("quarantine_ip", ip="10.0.0.60", duration_seconds=604801),
        _cmd("quarantine_ip", ip="10.0.0.60", duration_seconds=604800), _cmd("quarantine_ip", ip="10.0.0.60", duration_seconds="1"),
        _cmd("quarantine_ip", ip="fd12:3456:789a::50", duration_seconds=120),
        _cmd("quarantine_ip", ip="FD12:3456:789A::50"),
    ], NEIGH),
    "quarantine, nft refuses": (_tree(HOSTS), [_cmd("quarantine_ip", ip="10.0.0.50"),
                                               _cmd("quarantine_ip", ip="fd12:3456:789a::50")], NEIGH + [
        {"argv": ["nft", "--", "add", "element", "inet", "fr_os", "ids_quarantine_mac"], "rc": 1, "stderr": "Error: x\n"}]),
    "conntrack": (_tree(HOSTS, None, **{"proc/net/nf_conntrack": CONNTRACK}), [_cmd("conntrack_sample")], NEIGH),
    "conntrack, IPv4 only": (_tree(HOSTS, None, **{"proc/net/nf_conntrack": CONNTRACK.split("ipv6")[0]}),
                             [_cmd("conntrack_sample")], NEIGH),
    "conntrack, none": (_tree(HOSTS), [_cmd("conntrack_sample")], NEIGH),
    "conntrack, unreadable": (_tree(HOSTS, None, **{"proc/net/nf_conntrack/": ""}), [_cmd("conntrack_sample")], NEIGH),
    "ztna": (_tree(HOSTS), [
        _cmd("authorize_ztna"), _cmd("authorize_ztna", ip="10.0.0.50"), _cmd("authorize_ztna", ip="10.0.0.50", username=""),
        _cmd("authorize_ztna", ip="x", username="kid"), _cmd("authorize_ztna", ip="fd12::1%eth1", username="kid"),
        _cmd("authorize_ztna", ip="10.0.0.50", username="nobody"),
        _cmd("ztna_status", ip="10.0.0.50"),
        _cmd("authorize_ztna", ip="10.0.0.50", username="kid"),
        _cmd("authorize_ztna", ip="10.9.0.2", username="kid", extra=1),
        _cmd("authorize_ztna", ip="fd12:3456:789a:ffff::3", username="kid"),
        _cmd("authorize_ztna", ip="fd12:3456:789a:ffff::", username="kid"),
        _cmd("authorize_ztna", ip="fd12:3456:789a:ffff:0:1:0:0", username="kid"),
        _cmd("authorize_ztna", ip="10.9.0.255", username="kid"),
        _cmd("authorize_ztna", ip="198.51.100.7", username="kid"),
        _cmd("authorize_ztna", ip="FD12:3456:789A::50", username="kid"),
        _cmd("authorize_ztna", ip="10.0.0.51", username="kid"),
        _cmd("authorize_ztna", ip="10.0.0.56", username="kid"),
        _cmd("authorize_ztna", ip="fd12:3456:789a::50", username="kid"),
        _cmd("ztna_status"), _cmd("ztna_status", ip="x%y"), _cmd("ztna_status", ip="nope"),
        _cmd("ztna_status", ip="10.0.0.50"), _cmd("ztna_status", ip="10.9.0.2"), _cmd("ztna_status", ip="10.0.0.51"),
        _cmd("ztna_status", ip="198.51.100.7"), _cmd("ztna_status", ip="fd12:3456:789a::50"),
        _cmd("ztna_status", ip="FD12:3456:789A::50"),
    ], NEIGH + ZTNA_SETS),
    "ztna, state file odd": (_tree(HOSTS, None, **{"etc/fr_os/ztna_state.json": '{"10.9.0.2": {"username": 7}, '
                                                   '"10.0.0.50": "x", "z": 1, "z": 2}'}),
                             [_cmd("ztna_status", ip="10.9.0.2"), _cmd("ztna_status", ip="10.0.0.50"),
                              _cmd("authorize_ztna", ip="10.9.0.2", username="kid"), _cmd("ztna_status", ip="10.9.0.2")],
                             NEIGH + ZTNA_SETS),
    "ztna, state file not json": (_tree(HOSTS, None, **{"etc/fr_os/ztna_state.json": "{"}),
                                  [_cmd("ztna_status", ip="10.9.0.2"), _cmd("authorize_ztna", ip="10.9.0.2", username="kid")],
                                  NEIGH + ZTNA_SETS),
    "ztna, state file a list": (_tree(HOSTS, None, **{"etc/fr_os/ztna_state.json": "[1]"}),
                                [_cmd("ztna_status", ip="10.0.0.51"), _cmd("ztna_status", ip="10.9.0.2"),
                                 _cmd("authorize_ztna", ip="10.9.0.2", username="kid")],
                                NEIGH + ZTNA_SETS),
    "ztna, neighbour table fails": (_tree(HOSTS), [
        _cmd("authorize_ztna", ip="10.0.0.50", username="kid"), _cmd("ztna_status", ip="10.0.0.60"),
        _cmd("authorize_ztna", ip="10.0.0.61", username="kid"), _cmd("authorize_ztna", ip="10.0.0.62", username="kid"),
        _cmd("authorize_ztna", ip="10.0.0.63", username="kid")], [
        {"argv": ["ip", "-j", "neigh", "show", "to", "10.0.0.50"], "rc": 1, "stderr": "Cannot open netlink\n"},
        {"argv": ["ip", "-j", "neigh", "show", "to", "10.0.0.60"], "error": "missing"},
        {"argv": ["ip", "-j", "neigh", "show", "to", "10.0.0.61"], "error": "timeout"},
        {"argv": ["ip", "-j", "neigh", "show", "to", "10.0.0.62"], "stdout": "[{"},
        {"argv": ["ip", "-j", "neigh", "show", "to", "10.0.0.63"], "rc": 2, "stderr": ""}]),
    "ztna, disabled": (_tree(PLAIN), [_cmd("authorize_ztna", ip="10.0.0.50", username="kid"),
                                      _cmd("ztna_status", ip="10.0.0.50")], NEIGH),
    "ztna, no ULA yet": (_tree(HOSTS.replace(', ula_prefix: "fd12:3456:789a::/48"', "")),
                         [_cmd("authorize_ztna", ip="10.9.0.2", username="kid")], NEIGH),
    "ztna, generated ULA": (_tree(HOSTS.replace(', ula_prefix: "fd12:3456:789a::/48"', ""), None, **{
        "etc/fr_os/ipv6_ula.json": '{"generated": "fd99:8877:6655::/48"}\n'}),
        [_cmd("authorize_ztna", ip="10.9.0.2", username="kid"),
         _cmd("authorize_ztna", ip="fd99:8877:6655:ffff::2", username="kid")], NEIGH),
    "iot": (_tree(HOSTS), [
        _cmd("iot_sync_isolation"), _cmd("iot_sync_isolation", macs="aa:bb:cc:00:00:02"),
        _cmd("iot_sync_isolation", macs=[5]), _cmd("iot_sync_isolation", macs=["aa-bb-cc-00-00-02"]),
        _cmd("iot_sync_isolation", macs=["AA:BB:CC:00:00:0G"]), _cmd("iot_sync_isolation", macs=["a"] * 4097),
        _cmd("iot_sync_isolation", macs=["AA:BB:CC:00:00:01", "aa:bb:cc:00:00:02", "AA:BB:CC:00:00:02", "aa:bb:cc:00:00:03"]),
        _cmd("iot_sync_isolation", macs=["aa:bb:cc:00:00:01"]), _cmd("iot_sync_isolation", macs=[]),
        _cmd("iot_sync_isolation", macs=["aa:bb:cc:00:00:02\n"]),
    ], []),
    "iot, nft refuses": (_tree(HOSTS), [_cmd("iot_sync_isolation", macs=["aa:bb:cc:00:00:02"]),
                                        _cmd("iot_sync_isolation", macs=[])],
                         [{"argv": ["nft", "-f", "-"], "after": 1, "rc": 1, "stderr": ""},
                          {"argv": ["nft", "-f", "-"], "rc": 1, "stderr": "Error: Could not process rule\n"}]),
    "iot, no nft": (_tree(HOSTS), [_cmd("iot_sync_isolation", macs=["aa:bb:cc:00:00:02"])],
                    [{"argv": ["nft"], "error": "missing"}]),
    "iot, disabled": (_tree(PLAIN), [_cmd("iot_sync_isolation", macs=["aa:bb:cc:00:00:02"])], []),
    "audit": (_tree(HOSTS), [
        _cmd("audit_append"), _cmd("audit_append", entry=[1]), _cmd("audit_append", entry={f"k{i}": i for i in range(21)}),
        _cmd("audit_append", entry={"ts": 1}), _cmd("audit_append", entry={"via": "x"}),
        _cmd("audit_append", entry={"1x": 1}), _cmd("audit_append", entry={"a-b": 1}),
        _cmd("audit_append", entry={"k" * 41: 1}), _cmd("audit_append", entry={"": 1}),
        _cmd("audit_append", entry={"ok": [1]}), _cmd("audit_append", entry={"ok": {"a": 1}}),
        _cmd("audit_append", entry={}),
        _cmd("audit_append", entry={"action": "login", "user": "admin", "ok": True, "n": 5, "big": 10 ** 30, "f": 1.5,
                                    "none": None, "long": "é" * 600, "név": "x", "_x": "tab\there", "k" * 40: 0.1}),
        _cmd("audit_append", entry={f"k{i}": i for i in range(20)}),
    ], []),
}


# --- the commands that read the system for the webUI's views (phase 2c-2) ---------
# What the firewall dropped, the WireGuard peers, the XDP counters, the
# IPv6 the provider gave, what listens, the RAM modules, and the IoT scan:
# each program's output as the kernel and the tools write it, then odd.

VIEWS = HOSTS.replace("lan_zones: [lan], ", "").replace(
    "  iot: {device: eth2, zone: iot, address: 10.0.2.1/24}\n",
    "  iot: {device: eth2, zone: iot, address: 10.0.2.1/24}\n"
    "  guest: {device: eth3, zone: guest, address: 10.0.3.1/24}\n").replace(
    "zones: {wan: {}, lan: {}, iot: {}, vpn: {}}", "zones: {wan: {}, lan: {}, iot: {}, guest: {}, vpn: {}}").replace(
    "  - {name: iot-to-wan, action: accept, from_zone: iot, to_zone: wan}\n",
    "  - {name: iot-to-wan, action: accept, from_zone: iot, to_zone: wan}\n"
    "  - {name: no-printer, action: drop, from_zone: iot, to_zone: wan, src_address: [10.0.2.9]}\n").replace(
    'ula_prefix: "fd12:3456:789a::/48"}',
    'ula_prefix: "fd12:3456:789a::/48", pinholes: [\n'
    '    {name: web, zone: lan, host: "::10", proto: tcp, port: 443},\n'
    '    {name: cam, zone: guest, host: "2001:db8:100:1::7", proto: udp, port: "8000-8010"},\n'
    '    {name: printer, zone: iot, host: "::9", proto: tcp, port: 631}]}')

WG_KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="


def _seq(argv, answers) -> list:
    """Table entries that answer the n-th call of argv with answers[n]
    (the last one from then on)."""
    return [{"argv": argv, "after": i, **a} for i, a in reversed(list(enumerate(answers)))]


def _json(argv, value) -> dict:
    return {"argv": argv, "stdout": json.dumps(value)}


def _addr6(local, prefixlen, scope="global", family="inet6", **extra) -> dict:
    return {"family": family, "local": local, "prefixlen": prefixlen, "scope": scope, **extra}


ADDR6 = ["ip", "-j", "-6", "addr", "show"]
ROUTE6 = ["ip", "-j", "-6", "route", "show", "table", "main"]
ACTIVE = [{"argv": ["systemctl", "is-active", "--", "fr-dhcp6"], "stdout": "active\n"},
          {"argv": ["systemctl", "is-active", "--", "fr-ra"], "stdout": "activating\n"}]

LINKS6 = [
    {"ifname": "lo", "addr_info": [_addr6("::1", 128, "host")]},
    {"ifname": "eth0", "addr_info": [_addr6("2001:db8:1::5", 64), _addr6("2001:db8:1::9", 128), _addr6("fe80::1", 64, "link"),
                                     _addr6("203.0.113.2", 24, family="inet"), _addr6("2001:DB8:1:0::7", "64")]},
    {"ifname": "eth1", "addr_info": [_addr6("2001:db8:100::1", 64), _addr6("2001:db8:100:5::1", 64),
                                     _addr6("fd12:3456:789a::1", 64), _addr6("2001:db8:100:9::1", 80)]},
    {"ifname": "eth3", "addr_info": [_addr6("fd12:3456:789a:1::1", 64), _addr6("fd12:3456:789a:9::1", 64)]},
    {"ifname": "eth2"},
    {"ifname": "eth9", "addr_info": [_addr6("2001:db8:300::1", 64)]},
]
ROUTES6 = [
    {"dst": "default", "gateway": "fe80::1", "dev": "eth0", "protocol": "ra"},
    {"dst": "default", "gateway": "FE80::0:2", "dev": "eth0"},
    {"dst": "default", "dev": "eth0"},
    {"dst": "default", "gateway": "fe80::3", "dev": "eth1"},
    {"dst": "2001:db8:100::/56", "type": "unreachable", "protocol": "dhcp", "dev": "lo"},
    {"dst": "2001:db8:200::/64", "type": "unreachable", "protocol": "dhcp"},
    {"dst": "2001:db8:300::/96", "type": "unreachable", "protocol": "dhcp"},
    {"dst": "fe80::/64", "type": "unreachable", "protocol": "dhcp"},
    {"dst": "ff00::/8", "type": "unreachable", "protocol": "dhcp"},
    {"dst": "2001:db8:400::/48", "type": "unreachable", "protocol": "kernel"},
    {"dst": 5, "type": "unreachable", "protocol": "dhcp"},
    {"dst": "", "type": "unreachable", "protocol": "dhcp"},
    {"dst": "2001:db8:1::/64", "dev": "eth0", "protocol": "ra"},
]

WG_DUMP = ("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxw=\tprivate\t51820\toff\n"
           "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\t(none)\t198.51.100.20:40000\t10.9.0.2/32\t1793491100\t1024\t2048\t25\n"
           "peer2=\t(none)\t(none)\t10.9.0.3/32\t0\t\t\toff\n"
           "short\tline\n"
           "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\t(none)\t[2001:db8::20]:40001\t10.9.0.2/32\t 1_793 \t+5\t0\toff\n")


def _drop(message, ts="1793491100123456", **extra) -> str:
    record = {"MESSAGE": message, **extra}
    if ts is not None:
        record["__REALTIME_TIMESTAMP"] = ts
    return json.dumps(record)


JOURNAL = "\n".join([
    _drop("fr_os/drop/input: IN=eth0 OUT= MAC=00:11 SRC=198.51.100.7 DST=203.0.113.2 LEN=60 PROTO=TCP SPT=40000 DPT=22"),
    _drop("kernel: fr_os/drop/forward: IN=eth1 OUT=eth0 SRC=10.0.0.50 DST=9.9.9.9 PROTO=UDP SPT=5000 DPT=53",
          ts="1793491150000000"),
    _drop("fr_os/drop/ipv6-input:IN=eth0 SRC=2001:db8::1 DST=2001:db8::2 PROTO=ICMPv6 IN=eth9 X DPT="),
    _drop("fr_os/drop/input", ts="x"),
    _drop("fr_os/drop/ input  : SRC=1.2.3.4", ts=None),
    _drop("fr_os/drop/input: SRC=5.6.7.8", ts=1793491100.5),
    _drop("fr_os/drop/input: SRC=5.6.7.9", ts="1793491100123456"),
    _drop("something else: SRC=1.1.1.1"),
    _drop([102, 114]),
    "not json",
    "",
    json.dumps({"__REALTIME_TIMESTAMP": "1"}),
    _drop("fr_os/drop/input: SRC=7.7.7.7", ts=[1]),
    _drop("fr_os/drop/input: SRC=8.8.8.8", ts=None, extra=1),
]) + "\n"

SS = """\
tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=612,fd=3))
tcp   LISTEN 0      128             [::]:22            [::]:*    users:(("sshd",pid=612,fd=4))
tcp   LISTEN 0      4096      10.0.0.1:443       0.0.0.0:*    users:(("fr-webui",pid=700,fd=7),("fr-webui",pid=701,fd=7))
udp   UNCONN 0      0       0.0.0.0%eth1:67         0.0.0.0:*    users:(("kea-dhcp4",pid=800,fd=12))
udp   UNCONN 0      0       0.0.0.0%eth1:67         0.0.0.0:*    users:(("kea-dhcp4",pid=800,fd=12))
udp   UNCONN 0      0                *:68               *:*
udp   UNCONN 0      0    [fe80::1]%eth0:546            [::]:*
tcp   LISTEN 0      10       127.0.0.1:631       0.0.0.0:*
udp   UNCONN 0      0          0.0.0.0:5353      0.0.0.0:*    users:(("x",
udp   UNCONN 0      0          0.0.0.0:51820     0.0.0.0:*
tcp   LISTEN 0      10       10.0.0.1:x       0.0.0.0:*
tcp   LISTEN 0      10       nonsense:80       0.0.0.0:*
raw   UNCONN 0      0          0.0.0.0:1      0.0.0.0:*
tcp   LISTEN 0
udp   UNCONN 0      0       10.0.0.1:0099999999999999999999      0.0.0.0:*
tcp   LISTEN 0      10       noport       0.0.0.0:*
"""

IP_ADDR = [
    {"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1"}, {"family": "inet6", "local": "::1"}]},
    {"ifname": "eth0", "addr_info": [{"family": "inet", "local": "203.0.113.2"}, {"family": "inet6"}]},
    {"ifname": "eth1"},
    {"ifname": "eth1", "addr_info": [{"local": "10.0.0.1"}]},
    {"ifname": 5, "addr_info": [{"local": 7}]},
    {"ifname": True, "addr_info": []},
    {"ifname": None, "addr_info": {"x": 1}},
    {"ifname": 5.5, "addr_info": ["no", {"local": "fe80::1"}]},
]

DMIDECODE = """\
# dmidecode 3.4
Getting SMBIOS data from sysfs.
SMBIOS 3.3.0 present.

Handle 0x0010, DMI type 16, 23 bytes
Physical Memory Array
\tLocation: System Board Or Motherboard
\tMaximum Capacity: 64 GB

Handle 0x0011, DMI type 17, 92 bytes
Memory Device
\tSize: 16 GB
\tSpeed: 3200 MT/s
\tPart Number: CMK32GX4M2E3200C16
\tConfigured Memory Speed: 2666 MT/s

Handle 0x0012, DMI type 17, 92 bytes
Memory Device
\tSize: No Module Installed
\tSpeed: Unknown

Handle 0x0013, DMI type 17, 92 bytes
Memory Device
\tSize: 8 GB
\tSpeed: 2400MT/s
\tPart Number:    
\tConfigured Memory Speed: Unknown
\tNote: a: b

Handle 0x0014, DMI type 17, 92 bytes
Memory Device
    Size: 4096 MB
    Configured Memory Speed: 0 MT/s
    Speed: ٣٢٠٠ MT/s
Memory Device
\tSize: 4 GB
"""

BPF_STATS = "sys/fs/bpf/fr_os_xdp/maps/stats"
BPFTOOL = ["bpftool", "map", "dump", "pinned", "@ROOT@/" + BPF_STATS]
IOT_SCAN = ["systemctl", "start", "--", "fr-iot-scan.service"]

VIEW_REQUESTS = [_cmd(c) for c in ("iot_scan", "wireguard_status", "firewall_drops", "xdp_stats", "ipv6_status",
                                   "listening_sockets", "hw_ram_info")]

VIEW_SESSIONS = {
    "views": (_tree(VIEWS, None, **{"etc/fr_os/wireguard/private.key": WG_KEY + "\n", BPF_STATS: ""}), VIEW_REQUESTS, [
        *ACTIVE, _json(ADDR6, LINKS6), _json(ROUTE6, ROUTES6),
        {"argv": ["wg", "show", "wg0", "dump"], "stdout": WG_DUMP},
        {"argv": ["journalctl"], "stdout": JOURNAL},
        {"argv": ["ss", "-Hlntup"], "stdout": SS}, _json(["ip", "-j", "addr", "show"], IP_ADDR),
        {"argv": ["dmidecode"], "stdout": DMIDECODE},
        _json(BPFTOOL, [{"key": 0, "value": 12}, {"key": 4, "value": 3}, {"key": True, "value": 7}, {"key": 99, "value": 1},
                        {"key": -1, "value": 1}, {"key": 9, "value": {"a": [1]}}, {"key": 3, "value": 5, "key": 2}]),
    ]),
    "views, nothing yet": (_tree(HOSTS), VIEW_REQUESTS, []),
    "views, booting": (_tree(HOSTS), [_cmd("iot_scan"), _cmd("ipv6_status")],
                       [{"argv": ["systemctl", "is-system-running"], "stdout": "starting\n"}]),
    "views, programs missing": (_tree(HOSTS, None, **{BPF_STATS: ""}), VIEW_REQUESTS,
                                [{"argv": [p], "error": "missing"} for p in
                                 ("systemctl", "wg", "journalctl", "bpftool", "ip", "ss", "dmidecode")]),
    "views, ip missing": (_tree(HOSTS), [_cmd("listening_sockets")], [{"argv": ["ip"], "error": "missing"}]),
    "views, programs time out": (_tree(HOSTS, None, **{BPF_STATS: ""}), VIEW_REQUESTS[:6],
                                 [{"argv": [p], "error": "timeout"} for p in
                                  ("systemctl", "wg", "journalctl", "bpftool", "ip", "ss")]),
    "views, ip times out": (_tree(HOSTS), [_cmd("listening_sockets")], [{"argv": ["ip"], "error": "timeout"}]),
    "views, programs fail": (_tree(HOSTS, None, **{BPF_STATS: ""}), [*VIEW_REQUESTS, _cmd("iot_scan"),
                                                                     *[_cmd("listening_sockets")] * 2, _cmd("hw_ram_info")], [
        *_seq(IOT_SCAN, [{"rc": 1, "stderr": "Job for fr-iot-scan.service failed.\n"}, {"rc": 5, "stdout": " out \n"}]),
        {"argv": ["wg"], "rc": 1, "stderr": "Unable to access interface: No such device\n"},
        {"argv": ["journalctl"], "rc": 1, "stdout": JOURNAL.splitlines()[0]},
        {"argv": ["bpftool"], "rc": 255, "stderr": "Error: bpf obj get: Operation not permitted\n"},
        {"argv": ADDR6, "rc": 1, "stderr": "Cannot open netlink socket: Permission denied\n"},
        *_seq(["ss"], [{"rc": 1, "stderr": "Cannot open netlink socket\n"}, {"rc": 1}, {"stdout": ""}]),
        {"argv": ["ip", "-j", "addr"], "rc": 2},
        *_seq(["dmidecode"], [{"rc": 1, "stderr": "/dev/mem: Permission denied\n"}, {"rc": 2, "stderr": " \n"}]),
    ]),
    "views, odd output": (_tree(VIEWS, None, **{"etc/fr_os/wireguard/private.key": "not a key\n", BPF_STATS: ""}), [
        *[_cmd("wireguard_status")] * 2, *[_cmd("firewall_drops")] * 2, *[_cmd("xdp_stats")] * 9,
        *[_cmd("listening_sockets")] * 7, *[_cmd("hw_ram_info")] * 2], [
        *_seq(["wg"], [{"stdout": "if\n" + "k\t\tx\ty\t1\t2\tbig\n"}, {"stdout": ""}]),
        *_seq(["journalctl"], [{"stdout": "[1]\n"}, {"stdout": _drop("fr_os/drop/x:", ts=10 ** 400) + "\n"}]),
        *_seq(BPFTOOL, [{"stdout": "{not json"}, {"stdout": "5"}, {"stdout": '[{"key": 1.0, "value": 1}]'},
                        {"stdout": '[{"key": "x", "value": 1}]'}, {"stdout": '[{"key": 1}]'}, {"stdout": "[[1]]"},
                        {"stdout": '["k"]'}, {"stdout": "[7]"}, {"stdout": '{"key": 1}'}]),
        *_seq(["ip", "-j", "addr", "show"], [{"stdout": "{"}, {"stdout": "[{}]"}, {"stdout": '[{"ifname": [1]}]'},
                                             {"stdout": '[{"ifname": "a", "addr_info": ["local"]}]'},
                                             {"stdout": '[{"ifname": "a", "addr_info": [5]}]'},
                                             {"stdout": '[{"ifname": "a", "addr_info": 5}]'}, {"stdout": "7"}]),
        *_seq(["dmidecode"], [{"stdout": "Memory Device\n\tSize: 1 GB\n\tSpeed: ²666 MT/s\n"},
                              {"stdout": "Memory Device\n\tSize: 1 GB\n\tConfigured Memory Speed: 1¹ MT/s\n"}]),
    ]),
    "views, ipv6 off": (_tree(PLAIN), [_cmd("ipv6_status")], []),
    "views, no config": ({}, [_cmd("ipv6_status")], []),
    "views, no kernel ipv6": (
        {k: v for k, v in _tree(HOSTS).items() if not k.startswith("proc/sys/net/ipv6/")}, [_cmd("ipv6_status")], []),
    "views, ipv6 address only": (_tree(VIEWS), [_cmd("ipv6_status")], [
        _json(ADDR6, [{"ifname": "eth0", "addr_info": [_addr6("2001:db8:1::5", 64)]}])]),
    "views, ipv6 prefix too small": (_tree(VIEWS), [_cmd("ipv6_status")], [*ACTIVE,
        _json(ADDR6, [{"ifname": "eth1", "addr_info": [_addr6("2001:db8:100::1", 64)]}]),
        _json(ROUTE6, [{"dst": "2001:db8:100::/64", "type": "unreachable", "protocol": "dhcp"}])]),
    "views, ipv6 /64 handed on": (_tree(VIEWS), [_cmd("ipv6_status")], [
        _json(ADDR6, [{"ifname": "eth3", "addr_info": [_addr6("2001:db8:100:1::1", 64)]},
                      {"ifname": "eth1", "addr_info": [_addr6("2001:db8:100::1", 64)]}])]),
    "views, ipv6 no LAN zone": (_tree(VIEWS.replace("ipv6: {enabled: true, ", "ipv6: {enabled: true, lan_zones: [], ")),
                                 [_cmd("ipv6_status")], [
        _json(ROUTE6, [{"dst": "2001:db8:100::/56", "type": "unreachable", "protocol": "dhcp"}])]),
    "views, ipv6 odd output": (_tree(VIEWS), [_cmd("ipv6_status")] * 16, [
        *_seq(ADDR6, [{"stdout": "{"}, {"stdout": "5"}, {"stdout": '["x"]'}, {"stdout": '{"a": 1}'},
                      *[_json(ADDR6, [{"ifname": "eth0", "addr_info": info}]) for info in (
                          5, None, [{"family": "inet6", "scope": "global", "local": None, "prefixlen": 64}],
                          [{"family": "inet6", "scope": "global", "prefixlen": 64}],
                          [{"family": "inet6", "scope": "global", "local": "2001:db8::1"}],
                          [_addr6("2001:db8::1", "x")], [_addr6("2001:db8::1", None)], [_addr6("2001:db8::1", 1.9)],
                          [_addr6("nonsense", 64)], [_addr6("2001:db8::1", 129)], ["x"],
                          [_addr6("fd00::1", 64)])],
                      ]),
        _json(ROUTE6, []),
    ]),
    "views, ipv6 odd ULA device": (_tree(VIEWS), [_cmd("ipv6_status")] * 2, [
        *_seq(ADDR6, [_json(ADDR6, [{"ifname": ["eth1"], "addr_info": [_addr6("fd12:3456:789a::1", 64)]}]),
                      _json(ADDR6, [{"ifname": 7, "addr_info": [_addr6("fd12:3456:789a::1", 64)]}])])]),
    "views, ipv6 odd routes": (_tree(VIEWS), [_cmd("ipv6_status")] * 8, [
        *_seq(ROUTE6, [{"stdout": "x"}, {"stdout": '[1]'}, *[_json(ROUTE6, [route]) for route in (
            {"dst": "default", "dev": "eth0", "gateway": "nonsense"},
            {"dst": "default", "dev": "eth0", "gateway": 1},
            {"dst": "nonsense", "type": "unreachable", "protocol": "dhcp"},
            {"dst": "2001:db8::1/64", "type": "unreachable", "protocol": "dhcp"},
            {"dst": -1, "type": "unreachable", "protocol": "dhcp"},
            {"dst": "default", "dev": ["eth0"], "gateway": "fe80::1", "type": "unreachable", "protocol": "dhcp"})]]),
        {"argv": ADDR6, "rc": 0, "stdout": ""},
    ]),
    "views, ipv6 ip fails": (_tree(VIEWS), [_cmd("ipv6_status")] * 3, [
        *_seq(ADDR6, [{"error": "missing"}, {"error": "timeout"}, {"stdout": "[]"}]),
        {"argv": ROUTE6, "rc": 1, "stderr": ""}]),
}
COMMAND_SESSIONS.update(VIEW_SESSIONS)


@pytest.mark.parametrize("name", sorted(COMMAND_SESSIONS))
def test_command_session(system, name):
    setup, requests, table = COMMAND_SESSIONS[name]
    _session(system, f"command/{name}", setup, requests, table, RANDOM)


# --- moving the webUI, and refreshing the ad-block lists (phase 2c-3) ------------------
#
# set_management_addresses rewrites config.yaml with yaml.safe_dump and
# applies it, held for confirmation; refresh_adblock downloads the lists
# the config names, with urllib answering from the case's "fetch" table.

#: RICH with comments, an alias and a list the management settings and
#: the IPv6 settings share (the rewritten text anchors it).
MANAGED = "# the router at home\n" + RICH.replace(
    "ipv6: {enabled: true, lan_zones: [lan],", "management: {zones: &mz [lan], confirm_apply_seconds: 60}\n"
    "ipv6: {enabled: true, lan_zones: *mz,  # LAN only\n       ", 1)


def _manage(addresses=None, **fields) -> dict:
    request = {"cmd": "set_management_addresses", **fields}
    if addresses is not None:
        request["addresses"] = addresses
    return request


MANAGEMENT_SESSIONS = {
    "moved": (_tree(MANAGED, MANAGED), [
        _manage(["10.0.0.1"], user="admin"), {"cmd": "apply_status"},
        _manage(["10.0.0.1"]),
        lambda steps: {"cmd": "apply_confirm", "id": _pending_id(steps)},
        _manage(["10.0.0.1"], user="y" * 80),
    ], []),
    "refused requests": (_tree(MANAGED, MANAGED), [
        _manage(), _manage([]), _manage("10.0.0.1"), _manage([5]), _manage(["10.0.0.1", None]), _manage({"a": 1}),
        _manage(["192.0.2.9"]), _manage(["not an address"]), _manage([""]),
    ], []),
    "unapplied changes": (_tree(RICH2, RICH), [_manage(["10.0.0.1"])], []),
    "waiting": (_tree(RICH2, RICH), [{"cmd": "apply", "confirm": True}, _manage(["10.0.0.1"])], []),
    "nothing applied yet": (_tree(RICH), [_manage(["10.0.0.1"], user=7)], []),
    "no config": ({}, [_manage(["10.0.0.1"])], []),
    "empty config": ({"etc/fr_os/config.yaml": ""}, [_manage(["10.0.0.1"])], []),
    "not a mapping": ({"etc/fr_os/config.yaml": "- a\n"}, [_manage(["10.0.0.1"])], []),
    "management not a mapping": ({"etc/fr_os/config.yaml": "management: [1]\n"}, [_manage(["10.0.0.1"])], []),
    "management a number": ({"etc/fr_os/config.yaml": "management: 5\n"}, [_manage(["10.0.0.1"])], []),
    "management zero": ({"etc/fr_os/config.yaml": "management: 0\n"}, [_manage(["10.0.0.1"])], []),
    "bad yaml": ({"etc/fr_os/config.yaml": "a: [\n"}, [_manage(["10.0.0.1"])], []),
    "apply fails": (_tree(MANAGED, MANAGED), [_manage(["10.0.0.1"])], FAILURES["ruleset load"]),
    "moving refused": (_tree(RICH, RICH), [_manage(["10.0.0.1"])], FAILURES["revert unit"]),
}


@pytest.mark.parametrize("name", sorted(MANAGEMENT_SESSIONS))
def test_management_session(system, name):
    setup, requests, table = MANAGEMENT_SESSIONS[name]
    text = setup.get("etc/fr_os/config.yaml")
    try:
        links = _links(text) if text else []
    except Exception:  # not a config
        links = []
    _session(system, f"management/{name}", setup, requests, table + [RUNNING] + links, RANDOM)


#: A router whose ad-blocker has a base list of two sources and two
#: categories; local names and an allowlist that must never be blocked.
ADBLOCK = PLAIN + """\
dhcp:
  lan: {range_start: 192.168.7.100, range_end: 192.168.7.200, dns_servers: [192.168.7.1]}
adblocker:
  enabled: true
  source_urls: ["https://lists.example/hosts", "https://lists.example/missing"]
  categories:
    social: ["https://lists.example/social", "http://down.example/social"]
    malware: ["https://lists.example/malware"]
  allowlist: [good.example]
  serve_lan: true
local_dns: {domain: home.arpa, hosts: {nas.home.arpa: 192.168.7.10}}
"""

HOSTS_LIST = """\
# a hosts-format list
127.0.0.1 localhost
0.0.0.0 ads.example tracker.example  # two on one line
0.0.0.0 ADS.Example
::  v6.example
0.0.0.0 cdn.good.example good.example notgood.example
0.0.0.0 use-application-dns.net
0.0.0.0 nas.home.arpa home.arpa
0.0.0.0 -bad.example bad-.example ok-1.example under_score.example
0.0.0.0 x.""" + "a" * 64 + """.example
999.0.0.1 not-an-address.example
||filter.example^
https://url.example/path
plain.example.
single
0.0.0.0
\tspaced.example\t
"""

MALWARE_LIST = "evil.example\nEvil.Example\nworse.example # yes\n\x0bvertical.example\x85next.example\n"


def _fetch(url, **answer) -> dict:
    return {"url": url, **answer}


ADBLOCK_FETCH = [
    _fetch("https://lists.example/hosts", body=HOSTS_LIST),
    _fetch("https://lists.example/missing", status=404, reason="Not Found"),
    _fetch("https://lists.example/social", hex=b"0.0.0.0 social.example\n0.0.0.0 caf\xe9.example\n\xff\xfe\n".hex()),
    _fetch("http://down.example/social", error="[Errno -2] Name or service not known"),
    _fetch("https://lists.example/malware", body=MALWARE_LIST),
]

STALE = {"etc/fr_os/adblock.d/old.hosts": "0.0.0.0 old.example\n", "etc/fr_os/adblock.d/.hosts": "x\n",
         "etc/fr_os/adblock.d/notes.txt": "kept\n", "etc/fr_os/adblock.d/malware.hosts": "0.0.0.0 before.example\n"}

ADBLOCK_SESSIONS = {
    "refresh": (_tree(ADBLOCK, **STALE), ADBLOCK_FETCH),
    "a category down": (_tree(ADBLOCK, **STALE), [
        a if a["url"] != "https://lists.example/malware" else _fetch(a["url"], status=503, reason="Slow Down")
        for a in ADBLOCK_FETCH]),
    "everything down": (_tree(ADBLOCK, **STALE), [_fetch(a["url"], error="timed out") for a in ADBLOCK_FETCH]),
    "categories only": (_tree(ADBLOCK.replace(
        '  source_urls: ["https://lists.example/hosts", "https://lists.example/missing"]\n', ""),
        **{"etc/fr_os/adblock.hosts": "0.0.0.0 old.example\n"}), ADBLOCK_FETCH),
    "base list only": (_tree(PLAIN + "adblocker: {enabled: true, source_urls: [\"https://lists.example/hosts\"]}\n",
                             **STALE), ADBLOCK_FETCH),
    "nothing to fetch": (_tree(PLAIN), ADBLOCK_FETCH),
    "no config": ({}, ADBLOCK_FETCH),
    "bad config": ({"etc/fr_os/config.yaml": "version: 2\n"}, ADBLOCK_FETCH),
}


@pytest.mark.parametrize("name", sorted(ADBLOCK_SESSIONS))
def test_adblock_session(system, name):
    setup, fetch = ADBLOCK_SESSIONS[name]
    _session(system, f"adblock/{name}", setup, [{"cmd": "refresh_adblock"}], [], RANDOM, fetch=fetch)


# --- firewall-cli (phase 4f-1) ----------------------------------------------------
#
# The commands the units run: the boot's apply (fr-firewall.service,
# `apply --fail-closed`), an apply from the console (held with
# --confirm-within, or not), validate and render, the hourly schedule
# check with the rule hit counters, the DNS query log trim, the ad-block
# refresh, and ensure-accounts with the case's accounts. A step
# {"cli": argv} records the exit status and what was printed.

CONFIG = "@ROOT@/etc/fr_os/config.yaml"


def _c(*argv) -> dict:
    return {"cli": list(argv)}


#: RICH, its LAN address moved: an apply of it fails where `ip` can't
#: set the new address.
RICH_MOVED = RICH.replace("address: 10.0.0.1/24", "address: 10.0.0.2/24")
NEW_ADDRESS_FAILS = {"argv": ["ip", "addr", "replace", "10.0.0.2/24"], "rc": 2,
                     "stderr": "RTNETLINK answers: Permission denied\n"}
KEA_FAILS = {"argv": ["kea-dhcp4", "-t"], "rc": 1, "stderr": "DHCP4_CONFIG_LOAD_FAIL\n"}
NO_TABLE = {"argv": ["nft", "list", "table"], "rc": 1, "stderr": "Error: No such file or directory\n"}

SCHED = PLAIN.replace(
    "rules: [{name: lan-to-wan, action: accept, from_zone: lan, to_zone: wan}]\n",
    "timezone: Europe/Berlin\n"
    "rules:\n"
    "  - {name: lan-to-wan, action: accept, from_zone: lan, to_zone: wan}\n"
    "  - {name: kids-night, action: drop, from_zone: lan, to_zone: wan,\n"
    "     schedule: {days: [weekdays], start: \"21:30\", end: \"06:30\"}}\n")


def _schedule_state(fingerprint: str, offset: int = 120) -> str:
    return json.dumps({"clock": {"utc_offset_minutes": offset, "kernel_minuteswest": 0},
                       "timezone": "Europe/Berlin", "config_fingerprint": fingerprint})


def _held(previous: str, by: str = "admin") -> str:
    """An apply held for confirmation, its deadline passed."""
    return json.dumps({"id": "00" * 8, "deadline": NOW - 5, "seconds": 120, "by": by,
                       "addresses": ["10.0.0.1"], "previous": previous})


COUNTERS = {"argv": ["nft", "-j", "list", "table", "inet", "fr_os"], "stdout": json.dumps({"nftables": [
    {"metainfo": {"version": "1.0.6"}},
    {"rule": {"family": "inet", "table": "fr_os", "chain": "forward", "handle": 5, "comment": "rule:lan-to-wan",
              "expr": [{"counter": {"packets": 12, "bytes": 900}}, {"accept": None}]}},
    {"rule": {"comment": "rule:kids-night", "expr": [{"counter": {"packets": 3, "bytes": 180}}, {"drop": None}]}},
    {"rule": {"comment": "rule:kids-night", "expr": [{"counter": {"packets": 2, "bytes": 120}}, {"drop": None}]}},
    {"rule": {"comment": "masquerade", "expr": [{"counter": {"packets": 7}}]}},
    {"chain": {"name": "forward"}}]})}
HITS = {"etc/fr_os/rule_hits.json": json.dumps({"rules": {
    "lan-to-wan": {"since": 1790000000.0, "last_hit": None, "packets": 20},
    "gone": {"since": 1790000000.0, "last_hit": 1791000000.5, "packets": 4}}})}

#: 16 MiB, the query log's limit (frfw.adblock.dns_service).
QUERY_LOG = "var/log/fr_os-dns/queries.log"
QUERY_LOG_MAX = 16 * 1024 * 1024

CLI_SESSIONS = {
    "validate": (_tree(PLAIN, None, **{"etc/fr_os/bad.yaml": "version: 2\n", "etc/fr_os/broken.yaml": "a: [\n",
                                       "etc/fr_os/empty.yaml": ""}), [
        _c("validate", CONFIG), _c("validate"), _c("validate", "@ROOT@/etc/fr_os/bad.yaml"),
        _c("validate", "@ROOT@/etc/fr_os/broken.yaml"), _c("validate", "@ROOT@/etc/fr_os/empty.yaml"),
        _c("validate", "@ROOT@/etc/fr_os/missing.yaml"), _c("validate", "@ROOT@/etc/fr_os")], []),
    "render": (_tree(RICH), [_c("render", CONFIG), _c("render", "@ROOT@/etc/fr_os/missing.yaml")], []),
    "render, scheduled": (_tree(SCHED), [_c("render")], []),
    "usage": ({}, [_c(), _c("bogus"), _c("apply", "--confirm-within", "x"), _c("validate", "a", "b"),
                   _c("dns-log-trim", "x")], []),
    "apply": (_tree(PLAIN), [_c("apply", CONFIG), _c("apply", "--dry-run", CONFIG), _c("apply")], []),
    "apply, dry run": (_tree(RICH), [_c("apply", "--dry-run")], []),
    "apply, no config": ({}, [_c("apply"), _c("apply", "--dry-run")], []),
    "apply, bad config": (_tree(PLAIN, None, **{"etc/fr_os/config.yaml": "version: 2\n"}), [_c("apply")], []),
    "apply, fails": (_tree(RICH2, RICH), [_c("apply")], [KEA_FAILS, RUNNING]),
    "apply, confirm-within out of range": (_tree(RICH2, RICH), [
        _c("apply", "--confirm-within", "59"), _c("apply", "--confirm-within", "3601"),
        _c("apply", "--confirm-within", "-1", "--dry-run")], [RUNNING]),
    "apply, held": (_tree(RICH2, RICH), [
        _c("apply", "--confirm-within", "120"), _c("apply"), _c("apply", "--confirm-within", "60"),
        {"cmd": "apply_status"}, _c("apply", "--dry-run")], [RUNNING]),
    "apply, held, revert unit fails": (_tree(RICH2, RICH), [_c("apply", "--confirm-within", "120")], [
        {"argv": ["systemctl", "restart", "--", "fr-apply-revert.service"], "rc": 5,
         "stderr": "Unit fr-apply-revert.service not found.\n"}, RUNNING]),
    "apply, nothing to go back to": (_tree(RICH), [_c("apply", "--confirm-within", "120")], []),
    "apply, the same config": (_tree(RICH, RICH), [_c("apply", "--confirm-within", "120")], [RUNNING]),
    "apply, moves management": (_tree(RICH2.replace("10.0.0.", "10.0.5."), RICH),
                                [_c("apply"), _c("apply", "--dry-run")], [RUNNING]),
    "boot": (_tree(PLAIN), [_c("apply", "--fail-closed", CONFIG)], []),
    "boot, dry run": (_tree(PLAIN), [_c("apply", "--fail-closed", "--dry-run")], []),
    "boot, no config": ({"proc/sys/net/ipv4/ip_forward": "0\n"}, [_c("apply", "--fail-closed", CONFIG)], []),
    "boot, no config, nft fails": ({}, [_c("apply", "--fail-closed")], [
        {"argv": ["nft", "-f"], "rc": 1, "stderr": "Error: Could not process rule\n"}]),
    "boot, bad config, no ruleset": (_tree(PLAIN, None, **{"etc/fr_os/config.yaml": "version: 2\n"}),
                                     [_c("apply", "--fail-closed")], [NO_TABLE]),
    "boot, bad config, ruleset loaded": (_tree(PLAIN, None, **{"etc/fr_os/config.yaml": "version: 2\n"}),
                                         [_c("apply", "--fail-closed")], [RUNNING]),
    "boot, fails, the last applied works": (_tree(RICH_MOVED, RICH), [_c("apply", "--fail-closed")],
                                            [NEW_ADDRESS_FAILS, RUNNING]),
    "boot, fails, the last applied the same": (_tree(RICH, RICH), [_c("apply", "--fail-closed")],
                                               [KEA_FAILS, RUNNING]),
    "boot, fails, nothing applied before": (_tree(RICH), [_c("apply", "--fail-closed")], [KEA_FAILS, RUNNING]),
    "boot, fails, the last applied fails too": (_tree(RICH_MOVED, RICH), [_c("apply", "--fail-closed")],
                                                [KEA_FAILS, RUNNING]),
    "boot, fails, no ruleset": (_tree(RICH_MOVED, RICH), [_c("apply", "--fail-closed")],
                                [KEA_FAILS, {"argv": ["nft", "-f"], "rc": 1, "stderr": "Error: bad\n"}, NO_TABLE]),
    "boot, held": (_tree(RICH2, RICH), [_c("apply", "--confirm-within", "120"), _c("apply", "--fail-closed"),
                                        {"cmd": "apply_status"}], [RUNNING]),
    "boot, held, the earlier config fails": (_tree(RICH2, RICH, **{"etc/fr_os/apply-pending.json": _held(RICH)}),
                                             [_c("apply", "--fail-closed")], [KEA_FAILS, RUNNING]),
    "boot, held, the earlier config broken": (_tree(RICH2, RICH, **{
        "etc/fr_os/apply-pending.json": _held("version: 1\nbogus: 1\n")}), [_c("apply", "--fail-closed")], [RUNNING]),
    "boot, held, the earlier config fails, no ruleset": (_tree(RICH2, RICH, **{
        "etc/fr_os/apply-pending.json": _held(RICH)}), [_c("apply", "--fail-closed")],
        [KEA_FAILS, {"argv": ["nft", "-f"], "rc": 1, "stderr": "Error: bad\n"}, NO_TABLE]),
    "schedule check, no schedules": (_tree(PLAIN), [_c("schedule-check", CONFIG)], []),
    "schedule check, not recorded": (_tree(SCHED, None, **HITS), [_c("schedule-check")], [COUNTERS]),
    "schedule check, up to date": (_tree(SCHED), [_c("apply"), _c("schedule-check")], [COUNTERS]),
    "schedule check, refresh": (_tree(SCHED, SCHED, **{"etc/fr_os/schedule_state.json": _schedule_state(
        FINGERPRINT)}), [_c("schedule-check")], [COUNTERS]),
    "schedule check, config changed": (_tree(SCHED, SCHED, **{"etc/fr_os/schedule_state.json": _schedule_state(
        "0" * 64)}), [_c("schedule-check")], [COUNTERS]),
    "schedule check, odd record": (_tree(SCHED, None, **{"etc/fr_os/schedule_state.json": "[1]"}),
                                   [_c("schedule-check")], []),
    "schedule check, no clock": (_tree(SCHED, None, **{"etc/fr_os/schedule_state.json": json.dumps(
        {"config_fingerprint": FINGERPRINT})}), [_c("schedule-check")], []),
    "schedule check, no nft": (_tree(SCHED), [_c("schedule-check")], [{"argv": ["nft", "-j"], "error": "missing"}]),
    "schedule check, no config": ({}, [_c("schedule-check")], []),
    "dns log trim, small": ({QUERY_LOG: "query[A] example.com\n"}, [_c("dns-log-trim")], []),
    "dns log trim, at the limit": ({QUERY_LOG: {"size": QUERY_LOG_MAX}}, [_c("dns-log-trim")], []),
    "dns log trim, over": ({QUERY_LOG: {"size": QUERY_LOG_MAX + 1}}, [_c("dns-log-trim"), _c("dns-log-trim")], []),
    "dns log trim, missing": ({}, [_c("dns-log-trim")], []),
}

CLI_FETCH_SESSIONS = {
    "adblock refresh, scheduled, off": (_tree(PLAIN), [_c("adblock-refresh", "--scheduled", CONFIG)]),
    "adblock refresh, scheduled": (_tree(ADBLOCK, **STALE), [_c("adblock-refresh", "--scheduled")]),
    "adblock refresh, by hand, off": (_tree(PLAIN), [_c("adblock-refresh")]),
    "adblock refresh, everything down": (_tree(ADBLOCK, **STALE), [_c("adblock-refresh")]),
    "adblock refresh, no config": ({}, [_c("adblock-refresh")]),
    "adblock refresh, bad config": ({"etc/fr_os/config.yaml": "version: 2\n"}, [_c("adblock-refresh")]),
}


@pytest.mark.parametrize("name", sorted(CLI_SESSIONS))
def test_cli_session(system, name):
    setup, requests, table = CLI_SESSIONS[name]
    text = setup.get("etc/fr_os/config.yaml")
    links = []
    for t in {text, setup.get("etc/fr_os/applied-config.yaml")} - {None}:
        try:
            links += _links(t)
        except Exception:  # not a config: nothing to list
            pass
    _session(system, f"cli/{name}", setup, requests, table + links, RANDOM)


@pytest.mark.parametrize("name", sorted(CLI_FETCH_SESSIONS))
def test_cli_fetch_session(system, name):
    setup, requests = CLI_FETCH_SESSIONS[name]
    fetch = ADBLOCK_FETCH
    if name.endswith("everything down"):
        fetch = [_fetch(a["url"], error="timed out") for a in ADBLOCK_FETCH]
    _session(system, f"cli/{name}", setup, requests, [], RANDOM, fetch=fetch)


#: The accounts ensure-accounts finds: root only, or all of FR_OS's.
ROOT_ONLY = {"users": {"root": 0}, "groups": {"root": {"gid": 0, "members": []}}}
ALL_ACCOUNTS = {"users": {"root": 0, "fr_os-webui": 64800, "fr_os-sensor": 64801},
                "groups": {"root": {"gid": 0, "members": []}, "fr_os-webui": {"gid": 64800, "members": []},
                           "fr_os-sensor": {"gid": 64801, "members": []},
                           "fr_os-feeds": {"gid": 64802, "members": ["fr_os-webui", "fr_os-sensor"]},
                           "fr_os-ssh": {"gid": 64803, "members": []}}}
OLD_ACCOUNTS = copy.deepcopy(ALL_ACCOUNTS)
OLD_ACCOUNTS["groups"]["fr_os-webui"]["members"] = ["fr_os-sensor"]
OLD_ACCOUNTS["groups"]["fr_os-feeds"]["members"] = ["fr_os-webui"]
FEEDS = {"var/log/fr_os-sni/events.jsonl": "{}\n", QUERY_LOG: "", "run/fr_os/apply.sock": ""}
STATE_DIRS = {"etc/fr_os/webui/": "", "etc/fr_os/sensors/": "", "var/log/fr_os/": ""}

ACCOUNT_SESSIONS = {
    "fresh": ({}, ROOT_ONLY, []),
    "in place": (STATE_DIRS, ALL_ACCOUNTS, []),
    "an earlier version's": ({**STATE_DIRS, **FEEDS, "var/log/fr_os/audit.log": "x\n"}, OLD_ACCOUNTS, []),
    "no feeds group yet": (FEEDS, {**ROOT_ONLY, "users": {"root": 0, "fr_os-webui": 64800}}, []),
    "useradd fails": ({}, ROOT_ONLY, [{"argv": ["useradd"], "rc": 1,
                                        "stderr": "useradd: cannot lock /etc/passwd; try again later.\n"}]),
    "useradd fails quietly": ({}, ROOT_ONLY, [{"argv": ["useradd"], "rc": 9, "stdout": "  taken \n"}]),
    "no groupadd": ({}, ROOT_ONLY, [{"argv": ["groupadd"], "error": "missing"}]),
    "gpasswd fails": ({}, OLD_ACCOUNTS, [{"argv": ["gpasswd"], "rc": 3, "stderr": "gpasswd: bad\n"}]),
    "no root account": ({}, {"users": {}, "groups": {}}, []),
}


@pytest.mark.parametrize("name", sorted(ACCOUNT_SESSIONS))
def test_cli_accounts(system, name):
    setup, accounts, table = ACCOUNT_SESSIONS[name]
    _session(system, f"cli/accounts/{name}", setup, [_c("ensure-accounts")], table, RANDOM, accounts=accounts)
