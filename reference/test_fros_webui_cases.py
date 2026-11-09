"""FR_OS 1.x's webUI, driven request by request, with the capture plugin
(reference/generate.sh runs this module last).

Each case is a short browser session against 1.x's own FastAPI app
(frfw.webui.app.create_app), through Starlette's TestClient: sign-in,
first-run setup, the second factor, the session and its CSRF token,
sign-out, the accounts, and the dashboard's apply buttons. Nothing is run
and no socket is opened:

- every absolute path 1.x's modules hold is moved under the case's root
  (recorded as "@ROOT@"), as test_fros_apply_cases.py does, and the case
  writes there what the kernel would show (/proc, /sys/class/net); the
  host's CPU count, root file system, kernel release and installed
  package record are fixed values, and programs answer from a table;
- the apply-helper and the update-helper answer from the case's table
  (frfw.helper.client.send_command: the first entry whose "cmd" matches
  and whose "times" are not used up; a command with no entry gets the
  transport error a missing socket gives), and every request is recorded
  with its socket and timeout;
- the clock starts at FIXED_NOW and moves only where a step says so;
  randomness is a recorded byte stream (secrets.token_bytes, token_hex,
  token_urlsafe and pyotp's base32 secret all draw from it), so the
  cookies, CSRF tokens, salts and second-factor secrets are reproducible.

The case records the files before, every request (method, path, form,
headers, the cookies sent) and its response (status, headers, body), the
helper requests each one made, and the files after. Nothing here asserts
anything about 1.x.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import time
from pathlib import Path

import pyotp
import pytest
from fastapi.testclient import TestClient

from frfw.helper import client as helper_client
from frfw.helper import update_client
from frfw.webui import mfa as webui_mfa
from frfw.webui.app import create_app
from frfw.webui.auth import COOKIE_NAME, AdminStore, SessionManager
from frfw.webui.auth_rate_limiter import BruteforceGuard

#: 2026-11-01T00:00:00Z, the capture plugin's FIXED_NOW.
NOW = 1793491200.0

#: Bodies larger than this are recorded by digest.
MAX_TEXT = 1 << 18

#: The bytes a case draws from, enough for any session here.
RANDOM_BYTES = 1 << 14

APPLY_SOCKET = "apply.sock"
UPDATE_SOCKET = "update.sock"

#: The router's CPUs, and its root file system (os.statvfs_result):
#: 4 KiB blocks, 8 GiB, 6 GiB free.
CPUS = 4
UNAME = ("Linux", "fr-router", "6.1.0-53-amd64", "#1 SMP PREEMPT_DYNAMIC Debian 6.1.153-1", "x86_64")
DISK = (4096, 4096, 2097152, 1572864, 1572864, 524288, 400000, 400000, 0, 255)

#: The kernel's view of a small router: two NICs, the LAN one up.
SYSTEM_FILES = {
    "proc/uptime": "93784.52 360000.10\n",
    "proc/loadavg": "0.40 0.32 0.25 1/187 4242\n",
    "proc/meminfo": "MemTotal:        4028416 kB\nMemFree:         2514944 kB\nMemAvailable:    3145728 kB\n",
    "proc/cmdline": "BOOT_IMAGE=/vmlinuz-6.1.0-53-amd64 root=/dev/sda1 ro quiet\n",
    "proc/mounts": "/dev/sda1 / ext4 rw,relatime 0 0\n",
    "sys/class/net/eth0/address": "52:54:00:12:34:56\n",
    "sys/class/net/eth0/carrier": "0\n",
    "sys/class/net/eth0/type": "1\n",
    "sys/class/net/eth1/address": "52:54:00:12:34:57\n",
    "sys/class/net/eth1/carrier": "1\n",
    "sys/class/net/eth1/speed": "1000\n",
    "sys/class/net/eth1/type": "1\n",
}

#: What the helpers answer unless the case says otherwise: a router with
#: nothing pending and nothing to report.
BASE = [
    {"cmd": "ping", "reply": {"ok": True, "message": "pong"}},
    {"cmd": "apply_status", "reply": {"ok": True, "pending": None, "rejected": False}},
    {"cmd": "audit_append", "reply": {"ok": True}},
    {"cmd": "source_device", "reply": {"ok": True, "device": None}},
    {"cmd": "bruteforce_status", "reply": {"ok": True, "banned": [], "count": 0}},
    {"cmd": "ids_quarantine_status", "reply": {"ok": True, "quarantined": [], "count": 0, "macs": []}},
    {"cmd": "ztna_sessions_status", "reply": {"ok": True, "sessions": [], "count": 0}},
    {"cmd": "hw_ram_info", "reply": {"ok": True, "modules": []}},
    {"cmd": "dhcp_leases", "reply": {"ok": True, "leases": [], "count": 0}},
    {"cmd": "firewall_drops", "reply": {"ok": True, "drops": []}},
    {"cmd": "wireguard_status", "reply": {"ok": True, "public_key": "R" * 43 + "=", "up": False, "peers": {}}},
    {"cmd": "xdp_stats", "reply": {"ok": True, "stats": {}}},
    {"cmd": "iot_isolation_status", "reply": {"ok": True, "isolated": [], "count": 0}},
    {"cmd": "listening_sockets", "reply": {"ok": True, "listeners": [], "addresses": {}}},
    {"cmd": "ipv6_status", "reply": {"ok": True, "state": "off", "summary": "IPv6 is off.", "devices": [],
                                     "addresses": [], "default_routes": [], "prefixes": [],
                                     "service_active": False, "lan": [], "ra_active": False, "excluded": []}},
    {"cmd": "ban_ip", "reply": {"ok": True, "message": "jailed"}},
    {"cmd": "apply", "reply": {"ok": True, "message": "applied"}},
    {"cmd": "ping", "socket": UPDATE_SOCKET, "reply": {"ok": True, "message": "pong"}},
]

CONFIG = """\
version: 1
hostname: fr-router
interfaces:
  wan:
    device: eth0
    zone: wan
  lan:
    device: eth1
    zone: lan
    address: 192.168.1.1/24
zones:
  wan: {}
  lan: {}
rules:
- name: lan-to-wan
  action: accept
  from_zone: lan
  to_zone: wan
"""

ADMIN = {"username": "admin", "password": "Correct-horse-9", "role": "admin"}
VIEWER = {"username": "watcher", "password": "Viewer-pass-77", "role": "viewer"}
TOTP_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"


def _record(case: dict) -> None:
    capture = sys.modules.get("fros_capture")
    if capture is not None:
        capture._record("webui", case)


class _Fake:
    """The clock, the random byte stream and the helpers' table of one case."""

    def __init__(self, name: str, table: list):
        self.now = NOW
        stream, block = b"", 0
        while len(stream) < RANDOM_BYTES:
            stream += hashlib.sha256(f"{name}/{block}".encode()).digest()
            block += 1
        self.random = stream
        self.used = 0
        self.table = [dict(entry) for entry in table + BASE]
        self.calls: list[dict] = []

    def bytes(self, n: int) -> bytes:
        out = self.random[self.used:self.used + n]
        if len(out) != n:
            raise AssertionError("the case's random bytes ran out")
        self.used += n
        return out

    def send(self, cmd: dict, socket_path, timeout: float = 10.0, max_bytes: int = 0) -> dict:
        call = {"socket": Path(socket_path).name, "request": cmd, "timeout": timeout}
        for entry in self.table:
            if entry["cmd"] != cmd.get("cmd") or entry.get("socket", APPLY_SOCKET) != call["socket"]:
                continue
            if "times" in entry:
                if entry["times"] == 0:
                    continue
                entry["times"] -= 1
            if "error" not in entry:
                self.calls.append({**call, "reply": entry["reply"]})
                return json.loads(json.dumps(entry["reply"]))
            break
        message = f"cannot reach apply-helper at {socket_path}: [Errno 2] No such file or directory"
        self.calls.append({**call, "error": message})
        raise helper_client.HelperError(message)


@pytest.fixture
def webui(monkeypatch, tmp_path):
    from importlib import metadata

    from frfw import integrity
    from frfw.webui import audit

    import test_fros_apply_cases as system

    state: dict = {}

    def b32() -> str:
        return base64.b32encode(state["fake"].bytes(20)).decode()

    def urlsafe(n: int | None = 32) -> str:
        return base64.urlsafe_b64encode(state["fake"].bytes(32 if n is None else n)).rstrip(b"=").decode()

    def no_distribution(name):
        raise metadata.PackageNotFoundError(name)

    monkeypatch.setattr(time, "time", lambda: state["fake"].now)
    monkeypatch.setattr(secrets, "token_bytes", lambda n=32: state["fake"].bytes(32 if n is None else n))
    monkeypatch.setattr(secrets, "token_hex", lambda n=32: state["fake"].bytes(32 if n is None else n).hex())
    monkeypatch.setattr(secrets, "token_urlsafe", urlsafe)
    monkeypatch.setattr(pyotp, "random_base32", b32)
    monkeypatch.setattr(webui_mfa.pyotp, "random_base32", b32)
    monkeypatch.setattr(helper_client, "send_command", lambda *a, **k: state["fake"].send(*a, **k))
    monkeypatch.setattr(update_client, "send_command", lambda *a, **k: state["fake"].send(*a, **k))
    # What the host would tell: the router's own CPUs and disk, and the
    # installed package's RECORD (none here).
    monkeypatch.setattr(os, "cpu_count", lambda: CPUS)
    monkeypatch.setattr(os, "uname", lambda: os.uname_result(UNAME))
    monkeypatch.setattr(os, "statvfs", lambda path: os.statvfs_result(DISK))
    monkeypatch.setattr(integrity.metadata, "distribution", no_distribution)
    monkeypatch.setattr(integrity, "_cache", {})
    monkeypatch.setattr(audit, "_writers", {})
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: state["system"].run(*a, **k))

    def make(name: str, table: list, programs: list) -> tuple[_Fake, Path]:
        state["fake"] = _Fake(name, table)
        root = tmp_path / name.replace("/", "_")
        root.mkdir()
        system._reroot(monkeypatch, root)
        state["system"] = system._Fake(root, programs, b"")
        state["fake"].system = state["system"]
        system._hook_fake[:] = [state["system"]]
        return state["fake"], root

    yield make
    system._hook_fake[:] = []


def _files(root: Path) -> dict:
    out = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            data = path.read_bytes()
            rel = str(path.relative_to(root))
            if len(data) > MAX_TEXT:
                out[rel] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
                continue
            try:
                out[rel] = data.decode("utf-8")
            except UnicodeDecodeError:
                out[rel] = {"hex": data.hex()}
    return out


def _rooted(value, root: str):
    if isinstance(value, str):
        return value.replace(root, "@ROOT@")
    if isinstance(value, list):
        return [_rooted(v, root) for v in value]
    if isinstance(value, dict):
        return {k: _rooted(v, root) for k, v in value.items()}
    return value


def _setup(root: Path, setup: dict) -> None:
    files = {**SYSTEM_FILES, "etc/fr_os/config.yaml": CONFIG, **setup.get("files", {})}
    for rel, text in files.items():
        if text is None:
            continue
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    store = AdminStore()
    for account in setup.get("accounts", []):
        store.set_password(account["username"], account["password"], account.get("role"),
                           must_change=account.get("must_change", False))
        if account.get("totp"):
            store.set_mfa(account["username"], {"totp": {"secret": account["totp"], "last_step": -1}})
    # The secret key is made now, from the stream, so every cookie is.
    SessionManager()


def _csrf(client: TestClient) -> str:
    cookie = client.cookies.get(COOKIE_NAME)
    return client.app.state.session_manager.csrf_token_for(cookie) if cookie else ""


def _totp(_page: str = "") -> str:
    return pyotp.TOTP(TOTP_SECRET).at(time.time())


def _page_tid(page: str) -> str:
    return re.search(r'name="tid" value="([^"]+)"', page).group(1)


def _page_totp(page: str) -> str:
    """The code for the secret the enrolment page shows."""
    secret = re.search(r"<code[^>]*>([A-Z2-7 ]{16,})</code>", page).group(1).replace(" ", "")
    return pyotp.TOTP(secret).at(time.time())


def _session(webui, name: str, setup: dict, steps: list, table: list | None = None) -> None:
    programs = setup.get("programs", [])
    fake, root = webui(name, table or [], programs)
    _setup(root, setup)
    files_before = _files(root)
    fake.system.active = True
    app = create_app()
    client = TestClient(app, base_url="https://router.lan", follow_redirects=False,
                        raise_server_exceptions=False)
    recorded = []
    last = ""
    for step in steps:
        if "advance" in step:
            fake.now += step["advance"]
            recorded.append({"advance": step["advance"]})
            continue
        method = "POST" if "post" in step else "GET"
        path = step.get("post") or step.get("get")
        form = {k: v(last) if callable(v) else v for k, v in step.get("form", {}).items()}
        headers = dict(step.get("headers", {}))
        csrf = step.get("csrf", "field" if method == "POST" else None)
        if csrf == "field":
            form["csrf_token"] = _csrf(client)
        elif csrf == "header":
            headers["X-CSRF-Token"] = _csrf(client)
        elif csrf == "wrong":
            form["csrf_token"] = "0" * 64
        sent_cookies = dict(client.cookies)
        fake.calls = []
        fake.system.calls = []
        if method == "POST":
            if "json" in step:
                response = client.post(path, json=step["json"], headers=headers)
            else:
                response = client.post(path, data=form, headers=headers)
        else:
            response = client.get(path, headers=headers)
        body = response.content
        record = {
            "method": method, "path": path, "form": form, "json": step.get("json"),
            "headers": headers, "cookies": sent_cookies,
            "status": response.status_code,
            "response_headers": [[k, v] for k, v in response.headers.multi_items()
                                 if k.lower() not in ("date", "server", "content-length")],
            "helper": fake.calls,
            "programs": fake.system.calls,
        }
        if len(body) > MAX_TEXT:
            record["body_sha256"] = hashlib.sha256(body).hexdigest()
        else:
            try:
                record["body"] = body.decode("utf-8")
            except UnicodeDecodeError:
                record["body_hex"] = body.hex()
        recorded.append(record)
        last = body.decode("utf-8", "replace")
    fake.system.active = False
    case = {
        "session": name, "now": NOW, "random": fake.random[:fake.used].hex(),
        "cpus": CPUS, "disk": list(DISK), "uname": list(UNAME), "table": table or [], "base": BASE,
        "programs": programs, "program_base": fake.system.table[len(programs):],
        "files_before": files_before, "steps": recorded, "files_after": _files(root),
        "leaks": sorted(fake.system.leaks),
    }
    _record(_rooted(case, str(root)))


def _login(account=ADMIN) -> list:
    return [{"post": "/login", "form": {"username": account["username"], "password": account["password"]},
             "csrf": None}]


HELD = {"id": "a1b2c3d4e5f60718", "remaining": 280, "seconds": 300, "by": "admin",
        "addresses": ["192.168.1.1"]}

SESSIONS = {
    # -- signing in ------------------------------------------------------------------
    "login/form-no-account": ({"accounts": [], "files": {"etc/fr_os/config.yaml": None}}, [{"get": "/login"}, {"get": "/"}]),
    "login/form": ({"accounts": [ADMIN]}, [{"get": "/login"}, {"get": "/login?error=Bad+password"}]),
    "login/ok": ({"accounts": [ADMIN]}, [*_login(), {"get": "/"}, {"get": "/static/fros.css"}]),
    "login/wrong-password": ({"accounts": [ADMIN]}, [
        {"post": "/login", "form": {"username": "admin", "password": "nope"}, "csrf": None},
        {"get": "/"}]),
    "login/unknown-user": ({"accounts": [ADMIN]}, [
        {"post": "/login", "form": {"username": "root", "password": "Correct-horse-9"}, "csrf": None}]),
    "login/missing-field": ({"accounts": [ADMIN]}, [
        {"post": "/login", "form": {"username": "admin"}, "csrf": None}]),
    "login/locked-after-failures": ({"accounts": [ADMIN]}, [
        *[{"post": "/login", "form": {"username": "admin", "password": f"wrong-{i}"}, "csrf": None}
          for i in range(6)],
        *_login(),
        {"advance": 16 * 60}, *_login()]),
    "login/viewer": ({"accounts": [ADMIN, VIEWER]}, [
        *_login(VIEWER), {"get": "/"}, {"post": "/apply"}, {"get": "/users"}, {"post": "/logout"}]),
    # -- first-run setup -------------------------------------------------------------
    "setup/first-run": ({"accounts": [{**ADMIN, "must_change": True}]}, [
        *_login(), {"get": "/"}, {"get": "/setup"},
        {"post": "/setup", "form": {"username": "kolos", "password": "Short", "password_confirm": "Short"}},
        {"post": "/setup", "form": {"username": "kolos", "password": "New-pass-2026!",
                                    "password_confirm": "Other-pass-2026!"}},
        {"post": "/setup", "form": {"username": "kolos", "password": "New-pass-2026!",
                                    "password_confirm": "New-pass-2026!"}},
        {"get": "/"}]),
    # -- the session -----------------------------------------------------------------
    "session/expires": ({"accounts": [ADMIN]}, [*_login(), {"get": "/"}, {"advance": 12 * 3600 + 1},
                                                {"get": "/"}]),
    "session/logout": ({"accounts": [ADMIN]}, [*_login(), {"post": "/logout"}, {"get": "/"}]),
    "session/logout-everywhere": ({"accounts": [ADMIN]}, [
        *_login(), {"post": "/account/logout-everywhere"}, {"get": "/"}]),
    "session/no-cookie": ({"accounts": [ADMIN]}, [{"get": "/"}, {"get": "/rules"}, {"post": "/apply",
                                                                                     "csrf": None}]),
    "session/forged-cookie": ({"accounts": [ADMIN]}, [
        {"get": "/", "headers": {"Cookie": f"{COOKIE_NAME}=eyJ1c2VybmFtZSI6ImFkbWluIn0.forged.sig"}}]),
    "csrf/missing": ({"accounts": [ADMIN]}, [*_login(), {"post": "/apply", "csrf": None}]),
    "csrf/wrong": ({"accounts": [ADMIN]}, [*_login(), {"post": "/apply", "csrf": "wrong"}]),
    "csrf/header": ({"accounts": [ADMIN]}, [*_login(), {"post": "/apply", "csrf": "header"}]),
    # -- the account -----------------------------------------------------------------
    "account/password": ({"accounts": [ADMIN]}, [
        *_login(), {"get": "/account"},
        {"post": "/account/password", "form": {"current_password": "bad", "new_password": "Another-pass-1",
                                               "new_password_confirm": "Another-pass-1"}},
        {"post": "/account/password", "form": {"current_password": "Correct-horse-9",
                                               "new_password": "Another-pass-1",
                                               "new_password_confirm": "Another-pass-1"}},
        {"get": "/"}]),
    "users/manage": ({"accounts": [ADMIN]}, [
        *_login(), {"get": "/users"},
        {"post": "/users/add", "form": {"new_username": "watcher", "new_password": "Viewer-pass-77",
                                        "role": "viewer"}},
        {"post": "/users/add", "form": {"new_username": "bad name", "new_password": "x", "role": "viewer"}},
        {"post": "/users/watcher/role", "form": {"role": "admin"}},
        {"post": "/users/watcher/password", "form": {"new_password": "Reset-pass-2026"}},
        {"post": "/users/admin/delete"},
        {"post": "/users/watcher/delete"},
        {"get": "/users"}]),
    # -- the second factor -----------------------------------------------------------
    "mfa/totp-login": ({"accounts": [{**ADMIN, "totp": TOTP_SECRET}]}, [
        *_login(), {"get": "/login/mfa"},
        {"post": "/login/mfa/totp", "form": {"code": "000000"}, "csrf": None},
        {"post": "/login/mfa/totp", "form": {"code": _totp}, "csrf": None},
        {"get": "/"}]),
    "mfa/totp-reuse": ({"accounts": [{**ADMIN, "totp": TOTP_SECRET}]}, [
        *_login(), {"post": "/login/mfa/totp", "form": {"code": _totp}, "csrf": None},
        {"post": "/logout"},
        *_login(), {"post": "/login/mfa/totp", "form": {"code": _totp}, "csrf": None}]),
    "mfa/ticket-expires": ({"accounts": [{**ADMIN, "totp": TOTP_SECRET}]}, [
        *_login(), {"advance": 301}, {"post": "/login/mfa/totp", "form": {"code": _totp}, "csrf": None}]),
    "mfa/totp-enrol": ({"accounts": [ADMIN]}, [
        *_login(), {"get": "/account/mfa"}, {"get": "/account/mfa/totp"},
        {"post": "/account/mfa/totp", "form": {"tid": _page_tid, "code": "123456",
                                               "password": "Correct-horse-9"}},
        {"get": "/account/mfa/totp"},
        {"post": "/account/mfa/totp", "form": {"tid": _page_tid, "code": _page_totp, "password": "bad"}},
        {"get": "/account/mfa/totp"},
        {"post": "/account/mfa/totp", "form": {"tid": _page_tid, "code": _page_totp,
                                               "password": "Correct-horse-9"}},
        {"get": "/account/mfa"},
        {"post": "/users/mfa-policy", "form": {"require": "true"}},
        {"post": "/account/mfa/remove", "form": {"kind": "totp", "password": "Correct-horse-9"}},
        {"get": "/"}]),
    # -- the dashboard's buttons -----------------------------------------------------
    "dashboard/apply": ({"accounts": [ADMIN]}, [
        *_login(), {"post": "/apply?dry_run=1"}, {"post": "/apply"}, {"get": "/"}],
        [{"cmd": "apply", "reply": {"ok": True, "message": "Syntax OK (dry-run, not applied)"}, "times": 1},
         {"cmd": "apply", "reply": {"ok": True, "message": "Ruleset applied"}}]),
    "dashboard/apply-fails": ({"accounts": [ADMIN]}, [*_login(), {"post": "/apply"}],
                              [{"cmd": "apply", "reply": {"ok": False, "message": "Apply failed at Kea"}}]),
    "dashboard/held": ({"accounts": [ADMIN]}, [
        *_login(), {"get": "/"}, {"post": "/apply/confirm", "form": {"id": "ffffffffffffffff"}},
        {"post": "/apply/confirm", "form": {"id": HELD["id"]}}, {"get": "/"}],
        [{"cmd": "apply_status", "reply": {"ok": True, "pending": HELD, "rejected": False}, "times": 2},
         {"cmd": "apply_confirm", "reply": {"ok": False, "message": "That is not the apply waiting"},
          "times": 1},
         {"cmd": "apply_confirm", "reply": {"ok": True, "message": "Apply confirmed"}}]),
    "dashboard/revert-restore-rollback": ({"accounts": [ADMIN]}, [
        *_login(), {"post": "/apply/revert"}, {"get": "/"}, {"post": "/apply/rejected/restore"},
        {"post": "/rollback"}],
        [{"cmd": "apply_revert", "reply": {"ok": True, "message": "Went back"}},
         {"cmd": "apply_status", "reply": {"ok": True, "pending": None, "rejected": True}, "times": 1},
         {"cmd": "restore_rejected", "reply": {"ok": True, "message": "Loaded"}},
         {"cmd": "rollback", "reply": {"ok": False, "message": "No ruleset backups found"}}]),
    "dashboard/helper-down": ({"accounts": [ADMIN]}, [*_login(), {"get": "/"}, {"post": "/apply"}],
                              [{"cmd": "apply_status", "error": True}, {"cmd": "apply", "error": True}]),
    "dashboard/alerts-seen": ({"accounts": [ADMIN]}, [
        *_login(), {"post": "/alerts/seen", "form": {"until": "1793491100.5"}},
        {"post": "/alerts/seen", "form": {"until": "soon"}}]),
}


@pytest.mark.parametrize("name", sorted(SESSIONS))
def test_webui_session(webui, name):
    setup, steps, *table = SESSIONS[name]
    _session(webui, name, setup, steps, table[0] if table else None)
