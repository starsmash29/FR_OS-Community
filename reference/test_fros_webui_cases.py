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
- the update screen's request to GitHub for the latest release
  (frfw.update._fetch_json) answers from the same table, under the
  "https" socket with the URL as the command: its JSON, an HTTP error
  ("status") or a connection that failed ("reason");
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
import datetime as _dt
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import time
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote_plus

import pyotp
import pytest
from fastapi.testclient import TestClient

import frfw
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

#: The update check's GitHub API requests answer from the same table,
#: under this "socket", with the URL as the command.
HTTPS = "https"

#: Where FR_OS 2 looks for its releases unless update.repo says
#: otherwise (decisions.md, 3c-1).
COMMUNITY_REPO = "starsmash29/FR_OS-Community"
LATEST_URL = f"https://api.github.com/repos/{COMMUNITY_REPO}/releases/latest"

#: The TLS library the system screen names (pqc.ssl.OPENSSL_VERSION).
TLS_LIBRARY = "Go crypto/tls (X25519MLKEM768)"

#: What the integrity card says (the harness's integrity.check).
INTEGRITY_NOTE = "FR_OS 2 keeps no list of its files' hashes yet"

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
    {"cmd": "save_config", "save": True, "reply": {"ok": True, "message": "Config saved to /etc/fr_os/config.yaml"}},
    {"cmd": "ping", "socket": UPDATE_SOCKET, "reply": {"ok": True, "message": "pong"}},
    # A router that can't resolve api.github.com.
    {"cmd": LATEST_URL, "socket": HTTPS, "reason": "[Errno -3] Temporary failure in name resolution"},
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

    def fetch(self, url: str, timeout: float) -> object:
        """frfw.update._fetch_json: an entry with the URL answers its JSON,
        an HTTP error ("status") or a failed connection ("reason")."""
        call = {"socket": HTTPS, "request": {"url": url}, "timeout": timeout}
        for entry in self.table:
            if entry.get("socket") != HTTPS or entry["cmd"] != url:
                continue
            if "times" in entry:
                if entry["times"] == 0:
                    continue
                entry["times"] -= 1
            if "status" in entry:
                self.calls.append({**call, "status": entry["status"]})
                raise urllib.error.HTTPError(url, entry["status"], "error", {}, None)
            if "reason" in entry:
                from frfw import update as update_mod

                message = f"could not reach {url}: <urlopen error {entry['reason']}>"
                self.calls.append({**call, "error": message})
                raise update_mod.UpdateError(message)
            self.calls.append({**call, "reply": entry["reply"]})
            return json.loads(json.dumps(entry["reply"]))
        raise AssertionError(f"no answer for {url}")

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
                if entry.get("save"):  # what the real save_config leaves on disk
                    (self.system.root / "etc/fr_os/config.yaml").write_text(cmd["yaml"], encoding="utf-8")
                return json.loads(json.dumps(entry["reply"]))
            break
        message = f"cannot reach apply-helper at {socket_path}: [Errno 2] No such file or directory"
        self.calls.append({**call, "error": message})
        raise helper_client.HelperError(message)


@pytest.fixture
def webui(monkeypatch, tmp_path):
    from importlib import metadata

    from frfw import integrity, pqc, wireguard
    from frfw import update as update_mod
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
    # The router's OpenSSL knows the hybrid group (Debian 13's 3.5), and
    # the host has no OpenSSH for the PQC status to ask.
    monkeypatch.setattr(pqc, "openssl_supports_hybrid_tls", lambda *a: True)
    monkeypatch.setattr(pqc, "shutil", SimpleNamespace(which=lambda *a, **k: None))
    # The system screen names the TLS library: FR_OS 2's webUI uses Go's
    # crypto/tls, not the host's OpenSSL (decisions.md, 3b-3).
    monkeypatch.setattr(pqc.ssl, "OPENSSL_VERSION", TLS_LIBRARY)
    monkeypatch.setattr(integrity, "_cache", {})
    # The system screen's integrity card: FR_OS 2 has no hash list of its
    # files yet, so both say the same (decisions.md, 3b-3).
    monkeypatch.setattr(integrity, "check", lambda **k: integrity.IntegrityReport(
        0, verifiable=False, note=INTEGRITY_NOTE))
    # A key pair the VPN screen makes: its private key from the stream.
    real_x25519 = wireguard.X25519PrivateKey
    monkeypatch.setattr(wireguard, "X25519PrivateKey", SimpleNamespace(
        generate=lambda: real_x25519.from_private_bytes(state["fake"].bytes(32)),
        from_private_bytes=real_x25519.from_private_bytes))
    monkeypatch.setattr(audit, "_writers", {})
    # The update screen asks GitHub for FR_OS 2's latest release
    # (decisions.md, 3c-1), through the case's table.
    monkeypatch.setattr(update_mod, "DEFAULT_REPO", COMMUNITY_REPO)
    monkeypatch.setattr(update_mod, "_fetch_json", lambda url, timeout: state["fake"].fetch(url, timeout))
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: state["system"].run(*a, **k))
    # The rules screen and the schedules read the wall clock through
    # datetime.now, which doesn't go through time.time.
    from frfw.nft import schedule
    from frfw.webui.routes import rules as rules_routes

    class _Clock(_dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return _dt.datetime.fromtimestamp(state["fake"].now, tz)

    monkeypatch.setattr(schedule, "datetime", _Clock)
    monkeypatch.setattr(rules_routes, "datetime", _Clock)

    def make(name: str, table: list, programs: list) -> tuple[_Fake, Path]:
        state["fake"] = _Fake(name, table)
        root = tmp_path / name.replace("/", "_")
        root.mkdir()
        system._reroot(monkeypatch, root)
        # Mount points are as the kernel reports them in /proc/mounts,
        # not files under the root: not moved.
        from frfw import persistence
        monkeypatch.setattr(persistence, "LIVE_MEDIUM_MOUNT", "/run/live/medium")
        monkeypatch.setattr(persistence, "LIVE_PERSISTENCE_PREFIX", "/run/live/persistence/")
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
    # A redirect carries the root form-encoded (a helper error's socket
    # path in ?error=), so that form is replaced too.
    if isinstance(value, str):
        return value.replace(root, "@ROOT@").replace(quote_plus(root), quote_plus("@ROOT@"))
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


class _Authenticator:
    """A security key in software: one ES256 credential whose key comes
    from `seed`, signing deterministically (RFC 6979), so its answers --
    the attestation ("none", as most keys send) and every assertion -- are
    the same on every run. `origin`, `challenge` and `bad_signature` give
    the answers a phishing page, a replay or a broken key would."""

    def __init__(self, seed: str):
        from cryptography.hazmat.primitives.asymmetric import ec

        order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        scalar = int.from_bytes(hashlib.sha256(seed.encode()).digest(), "big") % (order - 1) + 1
        self.key = ec.derive_private_key(scalar, ec.SECP256R1())
        self.id = hashlib.sha256(f"{seed}/id".encode()).digest()[:16]
        self.count = 0

    @staticmethod
    def _b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    def _cose(self) -> bytes:
        import cbor2

        numbers = self.key.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: numbers.x.to_bytes(32, "big"),
                            -3: numbers.y.to_bytes(32, "big")})

    def _client_data(self, kind: str, options: dict, origin: str, challenge: str | None) -> bytes:
        return json.dumps({"type": kind, "challenge": challenge or options["challenge"], "origin": origin,
                           "crossOrigin": False}, separators=(",", ":")).encode()

    def register(self, origin: str = "https://router.lan", challenge: str | None = None):
        def answer(page: str) -> dict:
            import cbor2

            start = json.loads(page)
            options = start["options"]
            rp_hash = hashlib.sha256(options["rp"]["id"].encode()).digest()
            auth_data = (rp_hash + bytes([0x41]) + self.count.to_bytes(4, "big") + bytes(16)
                         + len(self.id).to_bytes(2, "big") + self.id + self._cose())
            attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
            return {"tid": start["tid"], "credential": {
                "id": self._b64(self.id), "rawId": self._b64(self.id), "type": "public-key",
                "response": {
                    "clientDataJSON": self._b64(self._client_data("webauthn.create", options, origin, challenge)),
                    "attestationObject": self._b64(attestation), "transports": ["usb"]},
                "clientExtensionResults": {}}}
        return answer

    def sign(self, origin: str = "https://router.lan", challenge: str | None = None,
             bad_signature: bool = False, count: int | None = None):
        def answer(page: str) -> dict:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import ec

            options = json.loads(page)
            self.count = self.count + 1 if count is None else count
            auth_data = (hashlib.sha256(options["rpId"].encode()).digest() + bytes([0x01])
                         + self.count.to_bytes(4, "big"))
            client_data = self._client_data("webauthn.get", options, origin, challenge)
            signed = auth_data + hashlib.sha256(client_data).digest()
            if bad_signature:
                signed = signed[:-1] + bytes([signed[-1] ^ 1])
            signature = self.key.sign(signed, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
            return {"id": self._b64(self.id), "rawId": self._b64(self.id), "type": "public-key",
                    "response": {"clientDataJSON": self._b64(client_data),
                                 "authenticatorData": self._b64(auth_data),
                                 "signature": self._b64(signature), "userHandle": None},
                    "clientExtensionResults": {}}
        return answer


def _page_key_id(page: str) -> str:
    return re.search(r'name="key_id" value="([^"]+)"', page).group(1)


def _session(webui, name: str, setup: dict, steps: list, table: list | None = None) -> None:
    programs = setup.get("programs", [])
    fake, root = webui(name, table or [], programs)
    _setup(root, setup)
    files_before = _files(root)
    # What the setup drew (salts, the session key) is in files_before;
    # the steps draw from here on.
    random_start = fake.used
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
        sent_json = step["json"](last) if callable(step.get("json")) else step.get("json")
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
                response = client.post(path, json=sent_json, headers=headers)
            else:
                response = client.post(path, data=form, headers=headers)
        else:
            response = client.get(path, headers=headers)
        body = response.content
        record = {
            "method": method, "path": path, "form": form, "json": sent_json,
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
        "session": name, "version": frfw.__version__, "codename": frfw.__codename__, "now": NOW,
        "random": fake.random[:fake.used].hex(), "random_start": random_start,
        "cpus": CPUS, "disk": list(DISK), "uname": list(UNAME), "table": table or [], "base": BASE,
        "programs": programs, "program_base": fake.system.table[len(programs):],
        "files_before": files_before, "steps": recorded, "files_after": _files(root),
        "leaks": sorted(fake.system.leaks),
    }
    _record(_rooted(case, str(root)))


def _login(account=ADMIN) -> list:
    return [{"post": "/login", "form": {"username": account["username"], "password": account["password"]},
             "csrf": None}]


_KEY_ENROL = _Authenticator("enrol")
_KEY_LOGIN = _Authenticator("login")

#: A router with every protection on, for the dashboard: what each part
#: shows, and what the rule check, the attack surface and the checklist
#: find (an any-to-any rule, one open from the internet, a shadowed, a
#: redundant, an expired and an unused one; a service nothing needs).
FULL_CONFIG = """\
version: 1
hostname: edge-gw
interfaces:
  wan:
    device: eth0
    zone: wan
  lan:
    device: eth1
    zone: lan
    address: 192.168.1.1/24
  iot:
    device: eth2
    zone: iot
    address: 192.168.20.1/24
zones:
  wan: {}
  lan: {}
  iot: {}
  vpn: {}
nat:
  masquerade:
  - out_zone: wan
  port_forwards:
  - name: web
    in_zone: wan
    proto: tcp
    dst_port: 8443
    to_address: 192.168.1.10
    to_port: 443
dhcp:
  lan:
    range_start: 192.168.1.100
    range_end: 192.168.1.200
    dns_servers: [192.168.1.1]
rules:
- name: lan-to-wan
  action: accept
  from_zone: lan
  to_zone: wan
- name: lan-web
  action: accept
  from_zone: lan
  to_zone: wan
  proto: tcp
  dst_port: 443
- name: everything
  action: accept
- name: wan-in
  action: accept
  from_zone: wan
  to_zone: lan
- name: block-iot
  action: drop
  from_zone: iot
  to_zone: wan
  proto: tcp
  dst_port: 443
- name: old-temp
  action: accept
  from_zone: lan
  to_zone: self
  proto: tcp
  dst_port: 8080
  expires: "2026-10-01T00:00:00Z"
- name: ssh-self
  action: accept
  from_zone: lan
  to_zone: self
  proto: tcp
  dst_port: 22
- name: admin-pc
  action: accept
  from_zone: lan
  to_zone: self
  src_address: [192.168.1.50]
- name: db-from-iot
  action: accept
  from_zone: iot
  to_zone: self
  proto: tcp
  dst_port: 5000-5999
adblocker:
  enabled: true
  source_urls: [https://lists.example/hosts]
ai_ids:
  enabled: true
tls_fingerprint:
  enabled: true
xdp_sni_filter:
  enabled: true
  interfaces: [lan, iot]
iot:
  enabled: true
  zones: [iot]
  isolated_macs: ["aa:bb:cc:dd:ee:01"]
pqc:
  enabled: true
ipv6:
  enabled: true
management:
  ipv6: true
wireguard:
  enabled: true
  address: 10.99.0.1/24
"""

#: The same router with nothing to answer: the helper and the services
#: down, the kernel's figures unreadable, a NIC not there.
UNAVAILABLE_CONFIG = """\
version: 1
hostname: lab
interfaces:
  lan:
    device: eth5
    zone: lan
    address: 192.168.1.1/24
zones:
  lan: {}
ai_ids:
  enabled: true
xdp_sni_filter:
  enabled: true
  interfaces: [lan]
tls_fingerprint:
  enabled: true
logging:
  drops: false
update:
  auto_install_security: true
"""

#: Everything in order: the checklist's full score.
CLEAN_CONFIG = """\
version: 1
hostname: home
interfaces:
  wan:
    device: eth0
    zone: wan
  lan:
    device: eth1
    zone: lan
    address: 192.168.1.1/24
  guest:
    device: eth2
    zone: guest
    address: 192.168.30.1/24
zones:
  wan: {}
  lan: {}
  guest: {}
nat:
  masquerade:
  - out_zone: wan
rules:
- name: lan-to-wan
  action: accept
  from_zone: lan
  to_zone: wan
update:
  auto_install_security: true
"""

LISTENERS = [
    {"proto": "tcp", "address": "0.0.0.0", "port": 443, "device": None, "process": "fr-webui"},
    {"proto": "tcp", "address": "0.0.0.0", "port": 22, "device": None, "process": "sshd"},
    {"proto": "udp", "address": "0.0.0.0", "port": 53, "device": None, "process": None},
    {"proto": "tcp", "address": "127.0.0.1", "port": 5432, "device": None, "process": "postgres"},
    {"proto": "tcp", "address": "0.0.0.0", "port": 8080, "device": None, "process": "python3"},
    {"proto": "tcp", "address": "0.0.0.0", "port": 5050, "device": None, "process": None},
    {"proto": "udp", "address": "0.0.0.0", "port": 67, "device": "eth1", "process": "kea-dhcp4"},
    {"proto": "udp", "address": "::", "port": 546, "device": None, "process": "dhcpcd"},
    {"proto": "udp", "address": "0.0.0.0", "port": 51820, "device": None, "process": None},
    {"proto": "tcp", "address": "2001:db8::1", "port": 443, "device": None, "process": "fr-webui"},
    {"proto": "tcp", "address": "203.0.113.5", "port": 9000, "device": None, "process": "nc"},
    {"proto": "udp", "address": "0.0.0.0", "port": 53530, "device": None, "process": None},
    {"proto": "tcp", "address": "192.168.20.1", "port": 1883, "device": None, "process": "mosquitto"},
]

#: The interfaces' addresses the attack surface sees with LISTENERS.
SURFACE_ADDRESSES = {"eth0": ["203.0.113.5", "fe80::1"], "eth1": ["192.168.1.1", "2001:db8::1"],
                     "eth2": ["192.168.20.1"], "lo": ["127.0.0.1"]}

DROPS = [{"ts": NOW - 60 * i, "chain": "input" if i % 3 else "forward", "src": f"203.0.113.{i}",
          "dst": "203.0.113.5" if i % 4 else None, "proto": "tcp" if i % 2 else "udp",
          "dport": 23 + i if i % 5 else None, "in": "eth0" if i % 6 else None} for i in range(12)]

ALERTS = "".join(json.dumps(e) + "\n" for e in [
    {"ts": NOW - 7200, "user": "admin", "event": "user added", "alert": "Admin account added: old"},
    {"ts": NOW - 3600, "user": "admin", "event": "login", "client": "198.51.100.7",
     "alert": "Admin sign-in from a new address"},
    {"ts": NOW - 1800, "user": "admin", "event": "apply"},
    {"ts": NOW - 600.5, "user": "admin", "event": "ssh key added", "client": "192.168.1.50",
     "alert": "SSH key added for admin"},
])

HELD = {"id": "a1b2c3d4e5f60718", "remaining": 280, "seconds": 300, "by": "admin",
        "addresses": ["192.168.1.1"]}


#: The first screens that write the config (phase 3b-1): rules, NAT,
#: interfaces, DHCP and segments. Every save goes through save_config,
#: which BASE answers by writing the YAML where the real helper would.
RULES_CONFIG = """\
version: 1
hostname: fr-router
timezone: Europe/Budapest
interfaces:
  wan: {device: eth0, zone: wan}
  lan: {device: eth1, zone: lan, address: 192.168.1.1/24}
  dmz: {device: eth2, zone: dmz, address: 10.0.2.1/24}
zones: {wan: {}, lan: {}, dmz: {}}
nat:
  masquerade: [{out_zone: wan}]
rules:
- {name: lan-to-wan, action: accept, from_zone: lan, to_zone: wan}
- {name: web, action: accept, from_zone: lan, to_zone: wan, proto: tcp, dst_port: 443, log: true}
- {name: kids-night, action: drop, from_zone: lan, to_zone: wan, src_mac: 'aa:bb:cc:dd:ee:01',
   schedule: {days: [weekdays], start: '21:30', end: '06:30', cut_established: true}}
- {name: weekend, action: accept, from_zone: lan, to_zone: dmz, schedule: {days: [sat, sun], start: '00:00', end: '23:59'}}
- {name: old-temp, action: accept, from_zone: lan, to_zone: dmz, proto: tcp, dst_port: 8000-8100, expires: '2026-10-01T12:00'}
- {name: soon, action: accept, from_zone: lan, to_zone: dmz, proto: udp, dst_port: 53, expires: '2026-11-01T09:00'}
- {name: ssh, action: accept, from_zone: lan, to_zone: self, proto: tcp, dst_port: 22, require_ztna: true}
- {name: everything, action: accept}
- {name: dmz-mail, action: accept, from_zone: wan, to_zone: dmz, proto: tcp, dst_port: 25,
   src_address: [203.0.113.0/24, '2001:db8::/32'], dst_address: 10.0.2.25}
"""

NAT_CONFIG = """\
version: 1
hostname: fr-router
interfaces:
  wan: {device: eth0, zone: wan}
  lan: {device: eth1, zone: lan, address: 192.168.1.1/24}
  guest: {device: eth2, zone: guest, address: 192.168.40.1/24}
zones: {wan: {}, lan: {}, guest: {}}
nat:
  masquerade: [{out_zone: wan}]
  port_forwards:
  - {name: web, in_zone: wan, proto: tcp, dst_port: 8443, to_address: 192.168.1.10, to_port: 443}
dhcp:
  lan:
    range_start: 192.168.1.100
    range_end: 192.168.1.199
    dns_servers: [192.168.1.1]
    reservations:
    - {mac: 'aa:bb:cc:dd:ee:01', address: 192.168.1.50, hostname: nas}
ipv6: {enabled: true, lan_zones: [lan]}
rules:
- {name: lan-to-wan, action: accept, from_zone: lan, to_zone: wan}
"""

NO_LAN_CONFIG = """\
version: 1
hostname: fr-router
interfaces:
  wan: {device: eth0, zone: wan}
  office: {device: eth1, zone: office, address: 192.168.30.1/24}
zones: {wan: {}, office: {}}
nat:
  masquerade: [{out_zone: wan}]
"""

HITS = json.dumps({"rules": {
    "web": {"since": NOW - 200 * 86400, "last_hit": NOW - 7200, "packets": 12},
    "weekend": {"since": NOW - 120 * 86400, "last_hit": None, "packets": 0},
    "dmz-mail": {"since": NOW - 5 * 86400, "last_hit": None, "packets": 0}}})

RULE = {"name": "block-dmz", "action": "drop", "from_zone": "lan", "to_zone": "wan", "proto": "tcp",
        "dst_port": "8080-8090", "src_address": " 192.168.1.0/25 , 2001:db8:1::/48,", "dst_address": "",
        "log": "on", "require_ztna": "", "src_mac": " AA:BB:CC:DD:EE:02 ", "schedule_days": ["mon", "fri"],
        "schedule_start": "08:00", "schedule_end": "17:00", "cut_established": "true",
        "expires": "2026-12-24T18:00"}

#: A router with every filter on (phase 3b-2's screens).
FILTER_CONFIG = """\
version: 1
hostname: edge-gw
interfaces:
  wan:
    device: eth0
    zone: wan
  lan:
    device: eth1
    zone: lan
    address: 192.168.1.1/24
  iot:
    device: eth2
    zone: iot
    address: 192.168.20.1/24
zones:
  wan: {}
  lan: {}
  iot: {}
nat:
  masquerade:
  - out_zone: wan
dhcp:
  lan:
    range_start: 192.168.1.100
    range_end: 192.168.1.200
    dns_servers: [192.168.1.1]
    reservations:
    - mac: "aa:bb:cc:dd:ee:10"
      address: 192.168.1.10
rules:
- name: lan-to-wan
  action: accept
  from_zone: lan
  to_zone: wan
adblocker:
  enabled: true
  source_urls: [https://lists.example/hosts]
  serve_lan: true
  query_logging: true
  categories:
    malware: [https://lists.example/malware]
    my-list: [https://lists.example/mine, https://lists.example/mine2]
  allowlist: [ok.example]
local_dns:
  domain: lan
  hosts:
    nas.lan: 192.168.1.10
    printer.lan: 192.168.1.11
  overrides:
    intranet.example: 192.168.1.12
ai_ids:
  enabled: true
  excluded_macs: ["aa:bb:cc:dd:ee:10"]
  quarantine_duration_seconds: 900
tls_fingerprint:
  enabled: true
  blocklist:
  - fingerprint: t13d1516h2_8daaf6152771_e5627efa2ab1
    label: old curl
  - 0123456789abcdef0123456789abcdef
xdp_sni_filter:
  enabled: true
  interfaces: [lan, iot]
  blocklist: [ads.example.com, tracker.example.net]
app_control:
  enabled: true
  observe_sni: true
  blocked_apps: [tiktok]
iot:
  enabled: true
  zones: [iot]
  auto_isolate: true
  trusted_macs: ["aa:bb:cc:dd:ee:02"]
  isolated_macs: ["aa:bb:cc:dd:ee:03"]
"""

SENSORS = "etc/fr_os/sensors/"

AI_EVENTS = json.dumps([
    {"ip": "192.168.1.20", "score": 7.5, "reasons": ["conn_rate", "scan"], "conn_rate": 120.0,
     "unique_dst_ratio": 0.9, "sni_block_count": 0, "ts": NOW - 600},
    {"ip": "2001:db8::20", "mac": "aa:bb:cc:dd:ee:20", "score": 9, "reasons": ["dga"], "conn_rate": 3,
     "unique_dst_ratio": 0.1, "sni_block_count": 2, "nxdomain_count": 40, "dga_nxdomain_count": 12,
     "dns_threat_count": 1, "ts": NOW - 60}])

APP_USAGE = json.dumps({"generated": NOW - 30, "apps": {
    "youtube": {"hits_24h": 340, "active_clients": 2, "last_seen": NOW - 40, "clients": {
        "192.168.1.20": {"hits_24h": 40, "last_seen": NOW - 40, "active": True, "sources": ["dns", "sni"]},
        "192.168.1.21": {"hits_24h": 300, "last_seen": NOW - 4000, "active": False, "sources": ["dns"]},
        "192.168.1.99": {"hits_24h": 300, "last_seen": "never"}}},
    "whatsapp": {"hits_24h": 12, "active_clients": 0, "last_seen": NOW - 9000},
    "tiktok": {"hits_24h": 3, "active_clients": 2, "last_seen": NOW - 100, "clients": {}}}})

INVENTORY = json.dumps({"scanned_at": NOW - 120, "messages": ["scanned iot: 3 devices", "isolated 2"], "devices": [
    {"mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.20.5", "hostname": "cam-1", "vendor": "Hikvision",
     "services": ["_rtsp._tcp"], "category": "iot", "score": 6, "reasons": ["vendor Hikvision", "rtsp"]},
    {"mac": "aa:bb:cc:dd:ee:02", "ip": "192.168.1.21", "hostname": None, "vendor": "Apple",
     "services": [], "category": "general", "score": -3, "reasons": ["randomized MAC"]},
    {"mac": "aa:bb:cc:dd:ee:03", "ip": None, "vendor": None, "services": [], "category": "unknown",
     "score": 0, "reasons": []},
    {"mac": "AA-BB-CC-DD-EE-04", "ip": "192.168.20.6", "hostname": "plug", "vendor": "Tuya",
     "services": ["_hap._tcp"], "category": "iot", "score": 4, "reasons": ["vendor Tuya"]},
    {"mac": "not a mac", "ip": "192.168.20.7", "category": "weird", "score": 1, "reasons": ["?"]}]})

TLS_STATE = json.dumps({"generated": NOW - 50, "learning": False,
                        "stats": {"hellos": 4242, "parse_errors": 3}, "clients": {
    "192.168.1.20": {
        "t13d1516h2_8daaf6152771_e5627efa2ab1": {"ja3": ["0123456789abcdef0123456789abcdef"],
                                                "sni": ["example.com"], "count": 3, "last_seen": NOW - 300},
        "t13d1715h2_5b57614c22b0_3d5424432f57": {"ja3": ["aa" * 16, "bb" * 16], "sni": ["a.example", "b.example"],
                                                "count": 90, "last_seen": NOW - 30}},
    "192.168.20.5": {
        "t13d1715h2_5b57614c22b0_3d5424432f57": {"ja3": [], "sni": [], "count": 1, "last_seen": NOW - 9000}}},
    "events": [
        {"type": "new", "client": "192.168.1.20", "ja4": "t13d1715h2_5b57614c22b0_3d5424432f57", "ts": NOW - 3000},
        {"type": "blocklist", "label": "old curl", "client": "192.168.1.20",
         "ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1", "sni": "example.com", "action": "quarantined",
         "ts": NOW - 300}]})

XDP_STATE = json.dumps({"attached": {"eth1": "xdpdrv", "eth2": "xdpgeneric", "eth9": "xdpdrv"},
                        "program": "/sys/fs/bpf/fr_os/xdp", "gro_off": []})


def _ip_link(device: str, mode: int, name: str = "xdp_sni_filter") -> dict:
    return {"argv": ["ip", "-j", "link", "show", "dev", device], "stdout": json.dumps([{
        "ifname": device, "xdp": {"mode": mode, "prog": {"id": 42, "name": name}}}])}


# -- the ZTNA gate, the VPN and the system screen (phase 3b-3) -------------------


def _scrypt_hash(password: str, salt: bytes) -> str:
    """admin_account.hash_password's format, with a salt of the case's own."""
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**15, r=8, p=3, maxmem=256 * 1024 * 1024, dklen=32)
    return f"scrypt$32768$8$3${salt.hex()}${digest.hex()}"


def _pbkdf2_hash(password: str, salt: bytes) -> str:
    """A hash written before security-lessons G2: replaced on sign-in."""
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return f"pbkdf2_sha256$200000${salt.hex()}${digest.hex()}"


ALICE = ("alice", "Alice-pass-123")
BOB = ("bob", "Bob-legacy-456")

ZTNA_CONFIG = CONFIG + f"""\
- name: ssh-gated
  action: accept
  from_zone: lan
  to_zone: self
  proto: tcp
  dst_port: 22
  require_ztna: true
ztna:
  enabled: true
  session_ttl_seconds: 7260
  users:
  - username: alice
    password_hash: {_scrypt_hash(ALICE[1], bytes(range(16)))}
  - username: bob
    password_hash: {_pbkdf2_hash(BOB[1], bytes(range(16, 32)))}
"""

PHONE_KEY = "Q" * 43 + "="
LAPTOP_KEY = "M" * 43 + "="
ROUTER_KEY = "R" * 43 + "="

VPN_CONFIG = """\
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
  vpn: {}
nat:
  masquerade:
  - out_zone: wan
rules:
- name: lan-to-wan
  action: accept
  from_zone: lan
  to_zone: wan
wireguard:
  enabled: true
  address: 10.99.0.1/24
  listen_port: 51821
  endpoint: vpn.example.net
  zone: vpn
  peers:
  - name: phone
    public_key: %s
    address: 10.99.0.2/32
    dual_stack: true
  - name: laptop
    public_key: %s
    address: 10.99.0.3/32
""" % (PHONE_KEY, LAPTOP_KEY)

ULA_STATE = json.dumps({"generated": "fd12:3456:789a::/48"})

WG_UP = {"ok": True, "public_key": ROUTER_KEY, "up": True, "peers": {
    PHONE_KEY: {"latest_handshake": int(NOW) - 300, "endpoint": "203.0.113.5:40000"},
    LAPTOP_KEY: {"latest_handshake": 0}}}

#: A certificate file for the system screen's fingerprint and download
#: (any base64 between the markers: only its bytes are hashed).
CERT_PEM = ("-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(bytes(range(256)) * 2).decode()
            + "-----END CERTIFICATE-----\n")


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
    "mfa/webauthn-enrol": ({"accounts": [ADMIN]}, [
        *_login(), {"get": "/account/mfa"},
        {"post": "/account/mfa/webauthn/options", "json": {"password": "bad", "name": "Desk key"},
         "csrf": "header"},
        {"post": "/account/mfa/webauthn/options", "json": {"password": "Correct-horse-9", "name": "Desk key"},
         "csrf": "header", "headers": {"Host": "192.168.1.1"}},
        {"post": "/account/mfa/webauthn/options", "json": {"password": "Correct-horse-9", "name": "Desk key"},
         "csrf": None},
        {"post": "/account/mfa/webauthn/options", "json": {"password": "Correct-horse-9", "name": "Desk key"},
         "csrf": "header"},
        {"post": "/account/mfa/webauthn/register", "json": _KEY_ENROL.register(origin="https://evil.lan"),
         "csrf": "header"},
        {"post": "/account/mfa/webauthn/options", "json": {"password": "Correct-horse-9", "name": "Desk key"},
         "csrf": "header"},
        {"post": "/account/mfa/webauthn/register", "json": _KEY_ENROL.register(challenge="AAAA"),
         "csrf": "header"},
        {"post": "/account/mfa/webauthn/options", "json": {"password": "Correct-horse-9", "name": "Desk key"},
         "csrf": "header"},
        {"post": "/account/mfa/webauthn/register", "json": _KEY_ENROL.register(), "csrf": "header"},
        {"get": "/account/mfa"},
        {"post": "/account/mfa/webauthn/options", "json": {"password": "Correct-horse-9", "name": "Again"},
         "csrf": "header"},
        {"get": "/account/mfa"},
        {"post": "/account/mfa/remove", "form": {"kind": "webauthn", "key_id": _page_key_id,
                                                 "password": "Correct-horse-9"}},
        {"post": "/account/mfa/remove", "form": {"kind": "sms", "password": "Correct-horse-9"}},
        {"get": "/account/mfa"}]),
    "mfa/webauthn-login": ({"accounts": [ADMIN]}, [
        *_login(),
        {"post": "/account/mfa/webauthn/options", "json": {"password": "Correct-horse-9", "name": ""},
         "csrf": "header"},
        {"post": "/account/mfa/webauthn/register", "json": _KEY_LOGIN.register(), "csrf": "header"},
        {"post": "/logout"},
        *_login(), {"get": "/login/mfa"},
        {"get": "/login/mfa", "headers": {"Host": "192.168.1.1"}},
        {"post": "/login/mfa/webauthn/options", "csrf": None, "headers": {"Host": "192.168.1.1"}},
        {"post": "/login/mfa/webauthn/verify", "json": {"id": "x"}, "csrf": None},
        {"post": "/login/mfa/webauthn/options", "csrf": None},
        {"post": "/login/mfa/webauthn/verify", "json": _KEY_LOGIN.sign(bad_signature=True), "csrf": None},
        {"post": "/login/mfa/webauthn/options", "csrf": None},
        {"post": "/login/mfa/webauthn/verify", "json": _KEY_LOGIN.sign(origin="https://evil.lan"),
         "csrf": None},
        {"post": "/login/mfa/webauthn/options", "csrf": None},
        {"post": "/login/mfa/webauthn/verify", "json": _KEY_LOGIN.sign(), "csrf": None},
        {"get": "/"},
        {"post": "/logout"},
        *_login(),
        {"post": "/login/mfa/webauthn/options", "csrf": None},
        {"post": "/login/mfa/webauthn/verify", "json": _KEY_LOGIN.sign(count=1), "csrf": None},
        {"post": "/login/mfa/webauthn/options", "csrf": None},
        {"post": "/login/mfa/webauthn/verify", "json": _KEY_LOGIN.sign(count=9), "csrf": None},
        {"get": "/"}]),
    # -- the rules screen (3b-1) -------------------------------------------------------
    "rules/list": ({"accounts": [ADMIN], "files": {"etc/fr_os/config.yaml": RULES_CONFIG,
                                                  "etc/fr_os/rule_hits.json": HITS}},
                   [*_login(), {"get": "/rules"}, {"get": "/rules?error=Bad+rule&success=Saved"},
                    {"advance": 9 * 3600}, {"get": "/rules"}]),
    "rules/add": ({"accounts": [ADMIN], "files": {"etc/fr_os/config.yaml": RULES_CONFIG}}, [
        *_login(),
        {"post": "/rules/add", "form": RULE},
        {"post": "/rules/add", "form": {"name": "block-guest-web", "action": "reject", "from_zone": "lan",
                                         "to_zone": "wan", "proto": "tcp", "dst_port": "443"}},
        {"post": "/rules/add", "form": {"name": "open", "action": "accept", "from_zone": "wan",
                                         "to_zone": "dmz"}},
        {"post": "/rules/add", "form": {"name": "web", "action": "accept", "from_zone": "lan", "to_zone": "wan",
                                         "proto": "tcp", "dst_port": "80"}},
        {"post": "/rules/add", "form": {"name": "dns", "action": "accept", "from_zone": "lan", "to_zone": "self",
                                         "proto": "udp", "dst_port": "53", "schedule_end": "06:00"}},
        {"post": "/rules/add", "form": {"name": "bad", "action": "maybe"}},
        {"post": "/rules/add", "form": {"name": "bad-port", "action": "accept", "proto": "any",
                                         "dst_port": "0443"}},
        {"post": "/rules/add", "form": {"name": "bad-zone", "action": "accept", "from_zone": "mars"}},
        {"post": "/rules/add", "form": {"name": "x", "action": "accept", "log": "maybe", "cut_established": "2"}},
        {"post": "/rules/add", "form": {"action": "accept"}},
        {"post": "/rules/add", "form": {"name": "", "action": ""}},
        {"get": "/rules"}]),
    "rules/move-delete": ({"accounts": [ADMIN], "files": {"etc/fr_os/config.yaml": RULES_CONFIG}}, [
        *_login(),
        {"post": "/rules/move/web", "form": {"direction": "up"}},
        {"post": "/rules/move/web", "form": {"direction": "up"}},
        {"post": "/rules/move/dmz-mail", "form": {"direction": "down"}},
        {"post": "/rules/move/web", "form": {"direction": "sideways"}},
        {"post": "/rules/move/nope", "form": {"direction": "down"}},
        {"post": "/rules/move/web", "form": {}},
        {"post": "/rules/delete/everything"},
        {"post": "/rules/delete/everything"},
        {"post": "/rules/remove-expired"},
        {"post": "/rules/remove-expired"},
        {"advance": 9 * 3600},
        {"post": "/rules/remove-expired"},
        {"get": "/rules"}]),
    "rules/timezone": ({"accounts": [ADMIN], "files": {"etc/fr_os/config.yaml": RULES_CONFIG}}, [
        *_login(),
        {"post": "/rules/timezone", "form": {"timezone": " America/New_York "}},
        {"get": "/rules"},
        {"post": "/rules/timezone", "form": {"timezone": "Mars/Olympus"}},
        {"post": "/rules/timezone", "form": {"timezone": ""}},
        {"get": "/rules"}]),
    "rules/invalid-config": ({"accounts": [ADMIN], "files": {
        "etc/fr_os/config.yaml": RULES_CONFIG.replace("action: drop, from_zone: lan, to_zone: wan, src_mac",
                                                      "action: maybe, from_zone: lan, to_zone: wan, src_mac"),
        "etc/fr_os/rule_hits.json": "{not json"}},
        [*_login(), {"get": "/rules"}, {"post": "/rules/remove-expired"},
         {"post": "/rules/delete/kids-night"}, {"get": "/rules"}]),
    "rules/empty-config": ({"accounts": [ADMIN], "files": {"etc/fr_os/config.yaml": None}}, [
        *_login(), {"get": "/rules"},
        {"post": "/rules/add", "form": {"name": "a", "action": "accept"}}]),
    "rules/save-refused": ({"accounts": [ADMIN], "files": {"etc/fr_os/config.yaml": RULES_CONFIG}}, [
        *_login(), {"post": "/rules/delete/web"}, {"post": "/rules/timezone", "form": {"timezone": "UTC"}}],
        [{"cmd": "save_config", "reply": {"ok": False, "message": "could not write config.yaml"}, "times": 1},
         {"cmd": "save_config", "error": True}]),
    "rules/viewer": ({"accounts": [ADMIN, VIEWER], "files": {"etc/fr_os/config.yaml": RULES_CONFIG}}, [
        *_login(VIEWER), {"get": "/rules"}, {"post": "/rules/delete/web"}]),
    # -- NAT -------------------------------------------------------------------------
    "nat/edit": ({"accounts": [ADMIN], "files": {"etc/fr_os/config.yaml": NAT_CONFIG}}, [
        *_login(), {"get": "/nat"},
        {"post": "/nat/masquerade/add", "form": {"out_zone": "wan"}},
        {"post": "/nat/masquerade/add", "form": {"out_zone": "guest"}},
        {"post": "/nat/masquerade/add", "form": {"out_zone": "nowhere"}},
        {"post": "/nat/masquerade/add", "form": {}},
        {"post": "/nat/masquerade/delete/guest"},
        {"post": "/nat/portforward/add", "form": {"name": "ssh", "in_zone": "wan", "proto": "tcp",
                                                  "dst_port": " 2_222 ", "to_address": "192.168.1.20",
                                                  "to_port": "22"}},
        {"post": "/nat/portforward/add", "form": {"name": "game", "in_zone": "wan", "proto": "udp",
                                                  "dst_port": "27015.0", "to_address": "192.168.1.30",
                                                  "to_port": ""}},
        {"post": "/nat/portforward/add", "form": {"name": "web", "in_zone": "wan", "proto": "tcp",
                                                  "dst_port": "8443", "to_address": "192.168.1.11",
                                                  "to_port": "0"}},
        {"post": "/nat/portforward/add", "form": {"name": "big", "in_zone": "wan", "proto": "tcp",
                                                  "dst_port": "99999999999999999999", "to_address": "192.168.1.11"}},
        {"post": "/nat/portforward/add", "form": {"name": "bad", "in_zone": "wan", "proto": "icmp",
                                                  "dst_port": "1.5", "to_address": "x", "to_port": "abc"}},
        {"post": "/nat/portforward/add", "form": {"name": "out", "in_zone": "wan", "proto": "tcp",
                                                  "dst_port": "80", "to_address": "8.8.8.8"}},
        {"post": "/nat/portforward/delete/game"},
        {"post": "/nat/portforward/delete/nothing"},
        {"get": "/nat"}]),
    "nat/empty": ({"accounts": [ADMIN], "files": {"etc/fr_os/config.yaml": NO_LAN_CONFIG.replace(
        "nat:\n  masquerade: [{out_zone: wan}]\n", "")}}, [
        *_login(), {"get": "/nat"},
        {"post": "/nat/portforward/delete/web"}, {"post": "/nat/masquerade/delete/wan"}]),
    # -- interfaces ------------------------------------------------------------------
    "interfaces/edit": ({"accounts": [ADMIN], "files": {
        "etc/fr_os/config.yaml": NAT_CONFIG,
        "sys/class/net/eth2/address": "52:54:00:12:34:58\n",
        "sys/class/net/wlan0/address": "52:54:00:12:34:59\n",
        "sys/class/net/wlan0/carrier": "garbage\n",
        "sys/class/net/wlan0/speed": "-1\n",
        "sys/class/net/lo/address": "00:00:00:00:00:00\n"}}, [
        *_login(), {"get": "/interfaces"}, {"get": "/interfaces?edit=lan"}, {"get": "/interfaces?edit=nope"},
        {"post": "/interfaces/save", "form": {"name": "dmz", "device": "eth3", "zone": "dmz",
                                              "address": " 10.0.3.1/24 "}},
        {"post": "/interfaces/save", "form": {"name": "lan", "device": "eth1", "zone": "lan",
                                              "address": "192.168.1.1/33"}},
        {"post": "/interfaces/save", "form": {"name": "x", "device": "eth4"}},
        {"post": "/interfaces/delete/dmz"},
        {"post": "/interfaces/delete/dmz"},
        {"post": "/interfaces/delete/guest"},
        {"post": "/interfaces/delete/lan"},
        {"post": "/interfaces/ipv6", "form": {}},
        {"post": "/interfaces/ipv6", "form": {"enabled": "yes"}},
        {"post": "/interfaces/ipv6", "form": {"enabled": "sure"}},
        {"get": "/interfaces"}],
        [{"cmd": "ipv6_status", "reply": {
            "ok": True, "state": "ok", "summary": "IPv6 from the provider: 2001:db8:100::/56.",
            "devices": ["eth0"], "addresses": [["eth0", "2001:db8::5/64", "slaac"], ["eth0", "2001:db8::6/128", "dhcpv6"]],
            "default_routes": [["eth0", "fe80::1"]], "prefixes": ["2001:db8:100::/56"], "service_active": True,
            "lan": [["lan", "eth1", "2001:db8:100:1::/64"], ["guest", "eth2", None]],
            "ula": [["lan", "eth1", "fd12:3456:789a:1::1/64"]],
            "pinholes": [["nas-https", "lan", "tcp/443", ["2001:db8:100:1::50"]], ["cam", "guest", "udp/554", None],
                         ["game", "lan", "tcp/27015", []]],
            "ra_active": True, "excluded": ["guest"]}, "times": 2},
         {"cmd": "ipv6_status", "reply": {"ok": False, "message": "netlink said no"}}]),
    "interfaces/ipv6-off": ({"accounts": [ADMIN], "files": {"etc/fr_os/config.yaml": RULES_CONFIG}}, [
        *_login(), {"get": "/interfaces"}, {"post": "/interfaces/ipv6", "form": {"enabled": "on"}},
        {"post": "/interfaces/ipv6", "form": {"enabled": "off"}}]),
    "interfaces/helper-gone": ({"accounts": [ADMIN], "files": {"etc/fr_os/config.yaml": RULES_CONFIG}}, [
        *_login(), {"get": "/interfaces"}], [{"cmd": "ipv6_status", "error": True}]),
    # -- DHCP ------------------------------------------------------------------------
    "dhcp/edit": ({"accounts": [ADMIN], "files": {"etc/fr_os/config.yaml": NAT_CONFIG}}, [
        *_login(), {"get": "/dhcp"},
        {"post": "/dhcp/guest/save", "form": {"range_start": "192.168.40.100", "range_end": "192.168.40.150",
                                              "dns_servers": " 1.1.1.1, ,9.9.9.9 ", "lease_time": "7_200"}},
        {"post": "/dhcp/lan/save", "form": {"range_start": "192.168.1.100", "range_end": "192.168.1.120",
                                            "dns_servers": "192.168.1.1"}},
        {"post": "/dhcp/lan/save", "form": {"range_start": "192.168.1.100", "range_end": "192.168.1.120",
                                            "dns_servers": "192.168.1.1", "lease_time": "soon"}},
        {"post": "/dhcp/lan/save", "form": {"range_start": "10.9.9.9", "range_end": "192.168.1.120",
                                            "dns_servers": "192.168.1.1", "lease_time": ""}},
        {"post": "/dhcp/lan/save", "form": {"range_start": "192.168.1.100"}},
        {"post": "/dhcp/wan/save", "form": {"range_start": "1.1.1.1", "range_end": "1.1.1.2",
                                            "dns_servers": "1.1.1.1"}},
        {"post": "/dhcp/lan/reservations/add", "form": {"mac": "aa:bb:cc:dd:ee:02", "address": "192.168.1.51",
                                                        "hostname": " printer "}},
        {"post": "/dhcp/lan/reservations/add", "form": {"mac": "aa:bb:cc:dd:ee:01", "address": "192.168.1.52"}},
        {"post": "/dhcp/lan/reservations/add", "form": {"mac": "zz", "address": "192.168.1.53"}},
        {"post": "/dhcp/dmz/reservations/add", "form": {"mac": "aa:bb:cc:dd:ee:03", "address": "10.0.0.5"}},
        {"post": "/dhcp/lan/reservations/delete/aa:bb:cc:dd:ee:02"},
        {"post": "/dhcp/dmz/reservations/delete/aa:bb:cc:dd:ee:02"},
        {"post": "/dhcp/guest/delete"},
        {"post": "/dhcp/nothing/delete"},
        {"get": "/dhcp"}]),
    # -- segments --------------------------------------------------------------------
    "segments/add": ({"accounts": [ADMIN], "files": {"etc/fr_os/config.yaml": CONFIG}}, [
        *_login(), {"get": "/segments"}, {"get": "/segments?first_run=1"},
        {"post": "/segments", "form": {}},
        {"post": "/segments", "form": {"segment": ["dmz"]}},
        {"post": "/segments", "form": {"segment": ["iot", "guest"]}},
        {"post": "/segments", "form": {"segment": ["guest"]}},
        {"get": "/segments"}, {"get": "/rules"}, {"get": "/dhcp"}]),
    "segments/iot": ({"accounts": [ADMIN], "files": {"etc/fr_os/config.yaml": CONFIG + "nat:\n  masquerade:\n  - out_zone: wan\n"}}, [
        *_login(), {"post": "/segments", "form": {"segment": ["iot", "guest"]}}, {"get": "/segments"}]),
    "segments/no-lan": ({"accounts": [ADMIN], "files": {"etc/fr_os/config.yaml": NO_LAN_CONFIG}}, [
        *_login(), {"get": "/segments"}, {"post": "/segments", "form": {"segment": ["iot"]}}]),
    "segments/overlap": ({"accounts": [ADMIN], "files": {"etc/fr_os/config.yaml": CONFIG.replace(
        "192.168.1.1/24", "192.168.0.1/16")}}, [
        *_login(), {"post": "/segments", "form": {"segment": ["guest"]}}]),
    # -- AI IDS ----------------------------------------------------------------------
    "ai-ids/show": ({"accounts": [ADMIN], "files": {
        "etc/fr_os/config.yaml": FILTER_CONFIG, SENSORS + "ai_ids_state.json": AI_EVENTS},
        "programs": [{"argv": ["systemctl", "is-active", "--", "fr-ai-ids.service"], "stdout": "active\n"}]}, [
        *_login(), {"get": "/ai-ids"}, {"get": "/ai-ids"},
        {"post": "/ai-ids/settings", "form": {"enabled": "true", "excluded_macs": " aa:bb:cc:dd:ee:10 ,, AA:BB:CC:DD:EE:11",
                                             "quarantine_duration_seconds": "3600"}},
        {"post": "/ai-ids/settings", "form": {"quarantine_duration_seconds": "0"}},
        {"post": "/ai-ids/settings", "form": {"quarantine_duration_seconds": "1.5"}},
        {"post": "/ai-ids/settings", "form": {}},
        {"get": "/ai-ids"}],
        [{"cmd": "ids_quarantine_status", "reply": {
            "ok": True, "count": 2, "quarantined": [{"ip": "192.168.1.20", "expires_in": 512}],
            "macs": [{"mac": "aa:bb:cc:dd:ee:20", "expires_in": 77}]}, "times": 1},
         {"cmd": "ids_quarantine_status", "reply": {"ok": False, "message": "no quarantine set"}}]),
    "ai-ids/empty": ({"accounts": [ADMIN], "files": {
        "etc/fr_os/config.yaml": None, SENSORS + "ai_ids_state.json": "{\"not\": \"a list\"}"},
        "programs": [{"argv": ["systemctl"], "error": "missing"}]}, [
        *_login(), {"get": "/ai-ids"}]),
    "ai-ids/invalid": ({"accounts": [ADMIN], "files": {
        "etc/fr_os/config.yaml": FILTER_CONFIG.replace("quarantine_duration_seconds: 900",
                                                       "quarantine_duration_seconds: -5"),
        SENSORS + "ai_ids_state.json": "[broken"}}, [*_login(), {"get": "/ai-ids"}]),
    # -- applications ----------------------------------------------------------------
    "apps/show": ({"accounts": [ADMIN], "files": {
        "etc/fr_os/config.yaml": FILTER_CONFIG, SENSORS + "appid_usage.json": APP_USAGE,
        SENSORS + "iot_inventory.json": INVENTORY},
        "programs": [{"argv": ["systemctl", "is-active", "--", "fr-appid.service"], "stdout": "inactive\n"}]}, [
        *_login(), {"get": "/apps"},
        {"post": "/apps/settings", "form": {"enabled": "1", "block_via_xdp": "on"}},
        {"post": "/apps/block", "form": {"blocked_apps": ["youtube", "zz-unknown", "messenger", "youtube", "aa-x"]}},
        {"post": "/apps/block", "form": {"blocked_apps": ["netflix", "tiktok"]}},
        {"post": "/apps/block", "form": {}},
        {"post": "/apps/settings", "form": {"enabled": "maybe"}},
        {"get": "/apps"}]),
    "apps/nothing": ({"accounts": [ADMIN], "files": {
        "etc/fr_os/config.yaml": CONFIG, SENSORS + "appid_usage.json": "{\"apps\": []}",
        SENSORS + "iot_inventory.json": "[]"}}, [*_login(), {"get": "/apps"}]),
    # -- TLS fingerprints ------------------------------------------------------------
    "tls/show": ({"accounts": [ADMIN], "files": {
        "etc/fr_os/config.yaml": FILTER_CONFIG, SENSORS + "tls_fingerprints.json": TLS_STATE,
        SENSORS + "iot_inventory.json": INVENTORY},
        "programs": [{"argv": ["systemctl", "is-active", "--", "fr-tls-fp.service"], "stdout": "active\n"}]}, [
        *_login(), {"get": "/tls"},
        {"post": "/tls/block", "form": {"fingerprint": " T13D1715H2_5B57614C22B0_3D5424432F57 ",
                                        "label": " blocked from 192.168.1.20 "}},
        {"post": "/tls/block", "form": {"fingerprint": "not-a-fingerprint"}},
        {"post": "/tls/block", "form": {"label": "x"}},
        {"post": "/tls/unblock", "form": {"fingerprint": "0123456789ABCDEF0123456789ABCDEF"}},
        {"post": "/tls/settings", "form": {"enabled": "true", "quarantine_on_match": "true"}},
        {"get": "/tls"}]),
    "tls/nothing": ({"accounts": [ADMIN], "files": {
        "etc/fr_os/config.yaml": CONFIG, SENSORS + "tls_fingerprints.json": "[1, 2]"}}, [
        *_login(), {"get": "/tls"}, {"post": "/tls/settings", "form": {}}, {"post": "/tls/unblock",
                                                                          "form": {"fingerprint": "abc"}},
        {"get": "/tls"}]),
    # -- IoT -------------------------------------------------------------------------
    "iot/show": ({"accounts": [ADMIN], "files": {
        "etc/fr_os/config.yaml": FILTER_CONFIG, SENSORS + "iot_inventory.json": INVENTORY}}, [
        *_login(), {"get": "/iot"}, {"get": "/iot"}, {"get": "/iot"},
        {"post": "/iot/device", "form": {"mac": " AA:BB:CC:DD:EE:04 ", "action": "trust"}},
        {"post": "/iot/device", "form": {"mac": "aa:bb:cc:dd:ee:02", "action": "isolate"}},
        {"post": "/iot/device", "form": {"mac": "aa:bb:cc:dd:ee:03", "action": "clear"}},
        {"post": "/iot/device", "form": {"mac": "aa:bb:cc:dd:ee:03", "action": "forget"}},
        {"post": "/iot/device", "form": {"mac": "zz", "action": "trust"}},
        {"post": "/iot/device", "form": {"mac": "aa:bb:cc:dd:ee:05", "action": "isolate"}},
        {"post": "/iot/scan"}, {"post": "/iot/scan"}, {"post": "/iot/scan"},
        {"post": "/iot/settings", "form": {"enabled": "true", "zones": ["iot", "lan"], "auto_isolate": "true",
                                           "isolation_mode": "block"}},
        {"post": "/iot/settings", "form": {"enabled": "true", "zones": ["nope"]}},
        {"get": "/iot"}],
        [{"cmd": "iot_isolation_status", "reply": {"ok": True, "isolated": ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:03"],
                                                   "count": 2}, "times": 1},
         {"cmd": "iot_isolation_status", "reply": {"ok": False, "message": "no isolation set"}, "times": 1},
         {"cmd": "iot_isolation_status", "error": True, "times": 1},
         {"cmd": "iot_sync_isolation", "reply": {"ok": True, "count": 3}, "times": 1},
         {"cmd": "iot_sync_isolation", "reply": {"ok": False, "message": "nft refused"}, "times": 1},
         {"cmd": "iot_sync_isolation", "error": True, "times": 1},
         {"cmd": "iot_scan", "reply": {"ok": True, "message": "scanned"}, "times": 1},
         {"cmd": "iot_scan", "reply": {"ok": False, "message": "scan unit failed"}, "times": 1},
         {"cmd": "iot_scan", "error": True}]),
    "iot/off": ({"accounts": [ADMIN], "files": {
        "etc/fr_os/config.yaml": CONFIG, SENSORS + "iot_inventory.json": json.dumps(
            {"messages": ["error: no zones"], "devices": []})}}, [
        *_login(), {"get": "/iot"}, {"post": "/iot/scan"},
        {"post": "/iot/device", "form": {"mac": "aa:bb:cc:dd:ee:09", "action": "trust"}},
        {"post": "/iot/settings", "form": {"enabled": "true", "zones": ["lan"]}},
        {"post": "/iot/scan"}, {"get": "/iot"}],
        [{"cmd": "iot_scan", "reply": {"ok": True, "message": "scanned"}}]),
    "iot/invalid": ({"accounts": [ADMIN], "files": {
        "etc/fr_os/config.yaml": FILTER_CONFIG.replace("isolation_mode", "x").replace("auto_isolate: true",
                                                                                       "auto_isolate: 5")}}, [
        *_login(), {"get": "/iot"}, {"post": "/iot/scan"}]),
    # -- ad-block and local names ----------------------------------------------------
    "adblock/show": ({"accounts": [ADMIN], "files": {
        "etc/fr_os/config.yaml": FILTER_CONFIG,
        "etc/fr_os/adblock.hosts": "# list\n0.0.0.0 a.example\n0.0.0.0 b.example\n\n #x\n",
        "etc/fr_os/adblock.d/malware.hosts": "0.0.0.0 bad.example\n"},
        "programs": [{"argv": ["systemctl", "is-active", "--", "fr-adblock-dns"], "stdout": "active\n"}]}, [
        *_login(), {"get": "/adblock"},
        {"post": "/adblock/local-dns/add", "form": {"kind": "hosts", "name": " Server.LAN. ", "address": " 192.168.1.13 "}},
        {"post": "/adblock/local-dns/add", "form": {"kind": "hosts", "name": "nas.lan", "address": "192.168.1.14"}},
        {"post": "/adblock/local-dns/add", "form": {"kind": "cname", "name": "x.lan", "address": "1.2.3.4"}},
        {"post": "/adblock/local-dns/add", "form": {"kind": "overrides", "name": "bad name", "address": "1.2.3.4"}},
        {"post": "/adblock/local-dns/remove", "form": {"kind": "hosts", "name": "printer.lan"}},
        {"post": "/adblock/local-dns/remove", "form": {"kind": "hosts", "name": "printer.lan"}},
        {"post": "/adblock/local-dns/remove", "form": {"kind": "cname", "name": "nas.lan"}},
        {"post": "/adblock/local-dns/domain", "form": {"domain": " Home.Arpa. "}},
        {"post": "/adblock/local-dns/domain", "form": {}},
        {"post": "/adblock/settings", "form": {
            "enabled": "true", "source_urls": "https://a.example/hosts, https://b.example/hosts\nhttps://a.example/hosts",
            "xdp_critical_limit": "500", "categories": ["phishing", "malware"],
            "allowlist": "OK.example\nfine.example,ok.example", "serve_lan": "true", "force_dns": "true"}},
        {"post": "/adblock/settings", "form": {"categories": ["warez"]}},
        {"post": "/adblock/settings", "form": {"xdp_critical_limit": "-1"}},
        {"post": "/adblock/refresh"}, {"post": "/adblock/refresh"}, {"post": "/adblock/refresh"},
        {"get": "/adblock"}],
        [{"cmd": "refresh_adblock", "reply": {"ok": True, "message": "Refreshed: 1234 domains"}, "times": 1},
         {"cmd": "refresh_adblock", "reply": {"ok": False}, "times": 1},
         {"cmd": "refresh_adblock", "reply": {"ok": True}}]),
    "adblock/off": ({"accounts": [ADMIN], "files": {"etc/fr_os/config.yaml": CONFIG}}, [
        *_login(), {"get": "/adblock"},
        {"post": "/adblock/local-dns/add", "form": {"kind": "hosts", "name": "nas.lan", "address": "192.168.1.10"}},
        {"post": "/adblock/settings", "form": {"enabled": "true"}},
        {"get": "/adblock"}]),
    "adblock/last-name": ({"accounts": [ADMIN], "files": {"etc/fr_os/config.yaml": FILTER_CONFIG.replace(
        "  domain: lan\n", "").replace("    printer.lan: 192.168.1.11\n", "").replace(
        "  overrides:\n    intranet.example: 192.168.1.12\n", "")}}, [
        *_login(), {"post": "/adblock/local-dns/remove", "form": {"kind": "hosts", "name": "nas.lan"}},
        {"get": "/adblock"}]),
    "adblock/refresh-gone": ({"accounts": [ADMIN]}, [*_login(), {"post": "/adblock/refresh"}],
                             [{"cmd": "refresh_adblock", "error": True}]),
    # -- the XDP SNI filter ----------------------------------------------------------
    "xdp/show": ({"accounts": [ADMIN], "files": {
        "etc/fr_os/config.yaml": FILTER_CONFIG, "etc/fr_os/xdp_state.json": XDP_STATE},
        "programs": [_ip_link("eth1", 1), {"argv": ["ip", "-j", "link", "show", "dev", "eth2"], "stdout": json.dumps([{
            "ifname": "eth2", "xdp": {"attached": [{"mode": 3, "prog": {"id": 7, "name": "other"}},
                                                   {"mode": 2, "prog": {"id": 42, "name": "xdp_sni_filter"}}]}}])},
                     {"argv": ["ip", "-j", "link", "show", "dev", "eth9"], "rc": 1, "stderr": "Device does not exist"}]}, [
        *_login(), {"get": "/xdp"}, {"get": "/xdp"},
        {"post": "/xdp/blocklist/remove", "form": {"domain": "ads.example.com"}},
        {"post": "/xdp/blocklist/remove", "form": {"domain": "missing.example"}},
        {"post": "/xdp/settings", "form": {"enabled": "true", "interfaces": ["lan"],
                                           "blocklist": " a.example, b.example\na.example\n\n"}},
        {"post": "/xdp/settings", "form": {"interfaces": ["dmz"]}},
        {"get": "/xdp"}],
        [{"cmd": "xdp_stats", "reply": {"ok": True, "stats": {"drop_match": 17, "pass": 9}}, "times": 1},
         {"cmd": "xdp_stats", "error": True}]),
    "xdp/not-attached": ({"accounts": [ADMIN], "files": {
        "etc/fr_os/config.yaml": FILTER_CONFIG, "etc/fr_os/xdp_state.json": "{broken"}}, [
        *_login(), {"get": "/xdp"}],
        [{"cmd": "xdp_stats", "reply": {"ok": False, "message": "no map"}}]),
    "xdp/off": ({"accounts": [ADMIN], "files": {"etc/fr_os/config.yaml": CONFIG}}, [
        *_login(), {"get": "/xdp"}, {"post": "/xdp/blocklist/remove", "form": {"domain": "x.example"}},
        {"get": "/xdp"}]),
    # -- the ZTNA gate ------------------------------------------------------------------
    "ztna/admin": ({"accounts": [ADMIN], "files": {"etc/fr_os/config.yaml": ZTNA_CONFIG}}, [
        *_login(), {"get": "/ztna"}, {"get": "/ztna?success=ok"},
        {"post": "/ztna/settings", "form": {"enabled": "true", "session_ttl_seconds": "3600"}},
        {"post": "/ztna/settings", "form": {"session_ttl_seconds": "59"}},
        {"post": "/ztna/settings", "form": {"session_ttl_seconds": "x"}},
        {"post": "/ztna/users/add", "form": {"new_username": "carol", "new_password": "short"}},
        {"post": "/ztna/users/add", "form": {"new_username": "carol", "new_password": "Strong-pass-789x"}},
        {"post": "/ztna/users/add", "form": {"new_username": "alice", "new_password": "New-secret-pass-1"}},
        {"post": "/ztna/users/add", "form": {"new_username": "bad name!", "new_password": "Some-good-pass-2"}},
        {"post": "/ztna/users/remove/bob"}, {"post": "/ztna/users/remove/nobody"},
        {"get": "/ztna"}]),
    "ztna/gate": ({"files": {"etc/fr_os/config.yaml": ZTNA_CONFIG}}, [
        {"get": "/ztna/login"}, {"get": "/ztna/login?error=Bad+%3Cthing%3E"},
        {"post": "/ztna/login", "form": {"username": "nobody", "password": "x"}, "csrf": None},
        {"post": "/ztna/login", "form": {"username": ALICE[0], "password": "wrong"}, "csrf": None},
        {"post": "/ztna/login", "form": {"username": ALICE[0], "password": ALICE[1]}, "csrf": None},
        {"post": "/ztna/login", "form": {"username": BOB[0], "password": BOB[1]}, "csrf": None},
        {"post": "/ztna/login", "form": {"username": ALICE[0], "password": ALICE[1]}, "csrf": None},
        {"post": "/ztna/login", "form": {"username": ALICE[0]}, "csrf": None},
        {"get": "/ztna/status?success=Welcome"}, {"get": "/ztna/status"}, {"get": "/ztna/status"},
        {"get": "/ztna/status?error=x"}, {"get": "/ztna/status"}, {"get": "/ztna"}],
        [{"cmd": "authorize_ztna", "reply": {"ok": True, "message": "authorized"}, "times": 1},
         {"cmd": "authorize_ztna", "reply": {"ok": False, "message": "not a direct client"}, "times": 1},
         {"cmd": "authorize_ztna", "reply": {"ok": False}, "times": 1},
         {"cmd": "ztna_status", "reply": {"ok": True, "authorized": True, "username": "alice",
                                          "expires_in": 7199, "mac": "aa:bb:cc:dd:ee:01", "direct": True}, "times": 1},
         {"cmd": "ztna_status", "reply": {"ok": True, "authorized": True, "expires_in": 59, "mac": ""}, "times": 1},
         {"cmd": "ztna_status", "reply": {"ok": True, "authorized": False, "direct": False}, "times": 1},
         {"cmd": "ztna_status", "reply": {"ok": False, "message": "no set"}, "times": 1},
         {"cmd": "ztna_status", "error": True}]),
    "ztna/lockout": ({"files": {"etc/fr_os/config.yaml": ZTNA_CONFIG}}, [
        *[{"post": "/ztna/login", "form": {"username": ALICE[0], "password": f"wrong-{i}"}, "csrf": None}
          for i in range(10)],
        {"post": "/ztna/login", "form": {"username": ALICE[0], "password": ALICE[1]}, "csrf": None}]),
    "ztna/off": ({"accounts": [ADMIN]}, [
        {"post": "/ztna/login", "form": {"username": "a", "password": "b"}, "csrf": None},
        *_login(), {"get": "/ztna"}, {"post": "/ztna/settings", "form": {}},
        {"post": "/ztna/users/remove/a"}, {"get": "/ztna"}]),
    # -- the VPN ----------------------------------------------------------------------
    "vpn/show": ({"accounts": [ADMIN], "files": {
        "etc/fr_os/config.yaml": VPN_CONFIG, "etc/fr_os/ipv6_ula.json": ULA_STATE}}, [
        *_login(), {"get": "/vpn"},
        {"post": "/vpn/peers/add", "form": {"name": " tablet ", "public_key": " " + "U" * 43 + "= "}},
        {"post": "/vpn/peers/add", "form": {"name": "watch", "full_tunnel": "true"}},
        {"post": "/vpn/peers/add", "form": {"name": "pc"}},
        {"post": "/vpn/peers/add", "form": {"name": "bad", "public_key": "nope"}},
        {"post": "/vpn/peers/remove/laptop"}, {"post": "/vpn/peers/remove/nobody"},
        {"post": "/vpn/settings", "form": {"enabled": "true", "address": " 10.99.0.1/24 ", "listen_port": "51822",
                                           "endpoint": " 198.51.100.7 "}},
        {"get": "/vpn"}],
        [{"cmd": "wireguard_status", "reply": WG_UP}]),
    "vpn/off": ({"accounts": [ADMIN]}, [
        *_login(), {"get": "/vpn"}, {"post": "/vpn/peers/add", "form": {"name": "phone"}},
        {"post": "/vpn/settings", "form": {"enabled": "true"}},
        {"post": "/vpn/settings", "form": {"enabled": "true", "listen_port": "51820"}},
        {"post": "/vpn/peers/add", "form": {"name": "phone"}},
        {"post": "/vpn/settings", "form": {"listen_port": "0"}},
        {"post": "/vpn/settings", "form": {}},
        {"get": "/vpn"}]),
    "vpn/no-key": ({"accounts": [ADMIN], "files": {"etc/fr_os/config.yaml": VPN_CONFIG}}, [
        *_login(), {"post": "/vpn/peers/add", "form": {"name": "pc"}},
        {"post": "/vpn/peers/add", "form": {"name": "pc"}}, {"get": "/vpn"}],
        [{"cmd": "wireguard_status", "reply": {"ok": False, "message": "wg0 is down"}, "times": 1},
         {"cmd": "wireguard_status", "reply": {"ok": True, "up": False, "peers": {}}, "times": 1},
         {"cmd": "wireguard_status", "error": True}]),
    "vpn/full": ({"accounts": [ADMIN], "files": {"etc/fr_os/config.yaml": VPN_CONFIG.replace(
        "10.99.0.1/24", "10.99.0.1/30").replace("""  - name: laptop
    public_key: %s
    address: 10.99.0.3/32
""" % LAPTOP_KEY, "")}}, [
        *_login(), {"post": "/vpn/peers/add", "form": {"name": "pc", "public_key": LAPTOP_KEY}}, {"get": "/vpn"}]),
    "vpn/invalid": ({"accounts": [ADMIN], "files": {"etc/fr_os/config.yaml": VPN_CONFIG.replace(
        "zone: vpn\n  peers", "zone: nowhere\n  peers")}}, [
        *_login(), {"get": "/vpn"}, {"post": "/vpn/peers/add", "form": {"name": "pc"}}]),
    # -- the system screen ------------------------------------------------------------
    "system/show": ({"accounts": [ADMIN], "files": {
        "etc/fr_os/config.yaml": CONFIG + "metrics:\n  site: hq\n  token_sha256: " + "ab" * 32 + "\n",
        "etc/fr_os/webui/cert.pem": CERT_PEM}}, [
        *_login(), {"get": "/system"},
        {"post": "/system/pqc/settings", "form": {"enabled": "true"}},
        {"post": "/system/management", "form": {"allow_wan": "true"}},
        {"get": "/system"},
        {"post": "/system/management", "form": {}},
        {"post": "/system/management-ipv6", "form": {"ipv6": "true"}},
        {"post": "/system/management-ipv6", "form": {}},
        {"post": "/system/management-addresses", "form": {}},
        {"post": "/system/management-addresses", "form": {"addresses": ["192.168.1.1", "10.0.0.1"]}},
        {"post": "/system/management-addresses", "form": {"addresses": ["192.168.1.1"]}},
        {"post": "/system/management-addresses", "form": {"addresses": ["192.168.1.1"]}},
        {"post": "/system/metrics/site", "form": {"site": " branch-2 "}},
        {"post": "/system/metrics/site", "form": {"site": "Bad Site"}},
        {"post": "/system/metrics/site", "form": {}},
        {"post": "/system/metrics/token", "form": {"action": "generate"}},
        {"post": "/system/metrics/token", "form": {"action": "disable"}},
        {"post": "/system/metrics/token", "form": {"action": "other"}},
        {"get": "/system/cert.pem"}, {"get": "/system"}],
        [{"cmd": "set_management_addresses", "reply": {"ok": True, "message": "Moved: confirm within 120 s"}, "times": 1},
         {"cmd": "set_management_addresses", "reply": {"ok": False, "message": "not an address of this router"},
          "times": 1},
         {"cmd": "set_management_addresses", "reply": {"ok": False}}]),
    "system/vpn": ({"accounts": [ADMIN], "files": {
        "etc/fr_os/config.yaml": VPN_CONFIG + "management:\n  allow_wan: true\n  addresses: [192.168.1.1, 10.99.0.1]\n",
        "etc/fr_os/webui/cert.pem": "-----BEGIN CERTIFICATE-----\n!!\n-----END CERTIFICATE-----\n",
        "proc/cmdline": "BOOT_IMAGE=/live/vmlinuz boot=live persistence quiet\n",
        "proc/mounts": "/dev/sdb1 /run/live/medium iso9660 ro 0 0\n/dev/sdb3 /run/live/persistence/sdb3 ext4 rw 0 0\n"
                       "/dev/sdc1 /run/live/persistence/sdc1 ext4 rw 0 0\n"}}, [
        *_login(), {"get": "/system"}, {"get": "/system/cert.pem"},
        {"post": "/system/management-ipv6", "form": {"ipv6": "true"}}]),
    "system/live": ({"accounts": [ADMIN], "files": {
        "etc/fr_os/config.yaml": VPN_CONFIG.replace("wireguard:\n  enabled: true", "wireguard:\n  enabled: true"),
        "proc/cmdline": "BOOT_IMAGE=/live/vmlinuz boot=live quiet\n",
        "proc/mounts": "/dev/sdb1 /run/live/medium iso9660 ro 0 0\n"}}, [
        *_login(), {"get": "/system"}]),
    "system/invalid": ({"accounts": [ADMIN], "files": {
        "etc/fr_os/config.yaml": CONFIG.replace("version: 1", "version: 2") + "pqc:\n  enabled: true\n"}}, [
        *_login(), {"get": "/system"}, {"get": "/system/cert.pem"},
        {"post": "/system/metrics/token", "form": {"action": "generate"}}]),
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
    # -- the dashboard ---------------------------------------------------------------
    "dashboard/everything": ({"accounts": [ADMIN, VIEWER], "files": {
        "etc/fr_os/config.yaml": FULL_CONFIG,
        "etc/fr_os/adblock.hosts": "# FR_OS\n" + "".join(f"0.0.0.0 ad{i}.example\n" for i in range(1234)) + "\n  \n",
        "etc/fr_os/webui_pqc_openssl.cnf": "[fr_os_groups]\nGroups = X25519MLKEM768:X25519\n",
        "etc/fr_os/rule_hits.json": json.dumps({"rules": {
            "lan-web": {"since": NOW - 100 * 86400, "last_hit": None, "packets": 0},
            "wan-in": {"since": NOW - 100 * 86400, "last_hit": NOW - 3600, "packets": 7},
            "ssh-self": {"since": NOW - 10 * 86400, "last_hit": None, "packets": 0}}}),
        "etc/fr_os/update_check.json": json.dumps({"current_version": frfw.__version__, "latest_version": "9.9.9",
                                                   "update_available": True, "security": True}),
        "etc/fr_os/backups/ruleset-20261030-120000.nft": "table inet fr_os {}\n",
        "etc/fr_os/backups/ruleset-20261031-120000.nft": "table inet fr_os {}\n",
        "etc/fr_os/backups/notes.txt": "not a backup\n",
        "var/log/fr_os/audit.log": ALERTS,
        "etc/fr_os/webui/alerts_seen.json": json.dumps({"admin": NOW - 5000}),
        "proc/cmdline": "BOOT_IMAGE=/live/vmlinuz boot=live components quiet\n",
        "proc/cpuinfo": "processor\t: 0\nmodel name\t: Intel(R) Celeron(R) N5105 @ 2.00GHz\n",
        "proc/loadavg": "5.25 3.10 2.00 3/201 4300\n",
        "sys/class/net/eth2/carrier": "1\n"},
        "programs": [{"argv": ["systemctl", "is-active", "--", "fr-ai-ids.service"], "stdout": "active\n"}]},
        [*_login(), {"get": "/"}, {"post": "/logout"}, *_login(VIEWER), {"get": "/"}],
        [{"cmd": "ids_quarantine_status", "reply": {"ok": True, "quarantined": [], "count": 2, "macs": []}},
         {"cmd": "firewall_drops", "reply": {"ok": True, "drops": DROPS}},
         {"cmd": "listening_sockets", "reply": {"ok": True, "listeners": LISTENERS, "addresses": {
             "eth0": ["203.0.113.5", "fe80::1"], "eth1": ["192.168.1.1", "2001:db8::1"], "eth2": ["192.168.20.1"],
             "lo": ["127.0.0.1"]}}}]),
    "dashboard/unavailable": ({"accounts": [ADMIN], "files": {
        "etc/fr_os/config.yaml": UNAVAILABLE_CONFIG,
        "etc/fr_os/update_check.json": json.dumps({"current_version": "0.0.1", "update_available": True}),
        "proc/loadavg": None, "proc/meminfo": "MemTotal: 1 GB\n", "proc/uptime": "42.9 1\n"},
        "programs": [{"argv": ["systemctl", "is-active", "--", "fr-tls-fp.service"], "error": "missing"}]},
        [*_login(), {"get": "/"}],
        [{"cmd": "ids_quarantine_status", "reply": {"ok": False, "message": "no quarantine set"}},
         {"cmd": "listening_sockets", "reply": {"ok": False, "message": "ss failed"}}]),
    # 1.x catches only OSError around these, so a helper that can't be
    # reached fails the whole page.
    "dashboard/helper-gone": ({"accounts": [ADMIN]}, [*_login(), {"get": "/"}],
                              [{"cmd": "listening_sockets", "error": True}]),
    "dashboard/invalid-config": ({"accounts": [ADMIN], "files": {
        "etc/fr_os/config.yaml": "version: 1\nzones:\n  lan: {}\nrules:\n- name: bad\n  action: maybe\n",
        "proc/uptime": "7322.0 1\n"}},
        [*_login(), {"get": "/"}]),
    "dashboard/clean": ({"accounts": [{**ADMIN, "username": "kolos", "totp": TOTP_SECRET}], "files": {
        "etc/fr_os/config.yaml": CLEAN_CONFIG,
        "etc/fr_os/update_check.json": json.dumps({"current_version": frfw.__version__,
                                                   "update_available": False}),
        "etc/fr_os/webui_pqc_openssl.cnf": "Groups = X25519\n"}},
        [{"post": "/login", "form": {"username": "kolos", "password": ADMIN["password"]}, "csrf": None},
         {"post": "/login/mfa/totp", "form": {"code": _totp}, "csrf": None}, {"get": "/"}],
        [{"cmd": "listening_sockets", "reply": {"ok": True, "listeners": LISTENERS[:2], "addresses": {}}}]),
    # -- the security checklist --------------------------------------------------------
    "security/show": ({"accounts": [ADMIN, VIEWER]}, [
        *_login(), {"get": "/security"}, {"post": "/logout"}, *_login(VIEWER), {"get": "/security"}]),
    "security/everything": ({"accounts": [ADMIN], "files": {
        "etc/fr_os/config.yaml": FULL_CONFIG,
        "etc/fr_os/update_check.json": json.dumps({"current_version": frfw.__version__, "latest_version": "9.9.9",
                                                   "update_available": True, "security": True})}},
        [*_login(), {"get": "/security"}],
        [{"cmd": "listening_sockets", "reply": {"ok": True, "listeners": LISTENERS, "addresses": SURFACE_ADDRESSES}}]),
    "security/clean": ({"accounts": [{**ADMIN, "totp": TOTP_SECRET}], "files": {
        "etc/fr_os/config.yaml": CLEAN_CONFIG,
        "etc/fr_os/update_check.json": json.dumps({"current_version": frfw.__version__,
                                                   "update_available": False})}},
        [*_login(), {"post": "/login/mfa/totp", "form": {"code": _totp}, "csrf": None}, {"get": "/security"}],
        [{"cmd": "listening_sockets", "reply": {"ok": True, "listeners": LISTENERS[:2], "addresses": {}}}]),
    "security/invalid": ({"accounts": [ADMIN], "files": {"etc/fr_os/config.yaml": "version: 1\nzones: []\n"}},
                         [*_login(), {"get": "/security"}]),
    "security/sockets-refused": ({"accounts": [ADMIN]}, [*_login(), {"get": "/security"}],
                                 [{"cmd": "listening_sockets", "reply": {"ok": False, "message": "ss failed"}}]),
    # 1.x catches only OSError around listening_sockets here.
    "security/helper-gone": ({"accounts": [ADMIN]}, [*_login(), {"get": "/security"}],
                             [{"cmd": "listening_sockets", "error": True}]),
    "security/anonymous": ({"accounts": [ADMIN]}, [{"get": "/security"}, {"get": "/surface"}, {"get": "/update"}]),
    # -- the attack surface --------------------------------------------------------------
    "surface/show": ({"accounts": [ADMIN, VIEWER], "files": {"etc/fr_os/config.yaml": FULL_CONFIG}},
        [*_login(), {"get": "/surface"}, {"post": "/logout"}, *_login(VIEWER), {"get": "/surface"}],
        [{"cmd": "listening_sockets", "reply": {"ok": True, "listeners": LISTENERS, "addresses": SURFACE_ADDRESSES}}]),
    "surface/allow-wan": ({"accounts": [ADMIN], "files": {"etc/fr_os/config.yaml": CONFIG + "management:\n  allow_wan: true\n"}},
        [*_login(), {"get": "/surface"}],
        [{"cmd": "listening_sockets", "reply": {"ok": True, "listeners": LISTENERS[:3], "addresses": {
            "eth0": ["198.51.100.7", "fe80::2"], "eth1": ["192.168.1.1"]}}}]),
    "surface/needed": ({"accounts": [ADMIN], "files": {"etc/fr_os/config.yaml": CLEAN_CONFIG}},
        [*_login(), {"get": "/surface"}],
        [{"cmd": "listening_sockets", "reply": {"ok": True, "listeners": [LISTENERS[0], LISTENERS[1], LISTENERS[3]],
                                                "addresses": {}}}]),
    "surface/quiet": ({"accounts": [ADMIN]}, [*_login(), {"get": "/surface"}]),
    "surface/invalid": ({"accounts": [ADMIN], "files": {"etc/fr_os/config.yaml": "version: 1\nzones: []\n"}},
                        [*_login(), {"get": "/surface"}]),
    "surface/refused": ({"accounts": [ADMIN]}, [*_login(), {"get": "/surface"}, {"get": "/surface"}],
                        [{"cmd": "listening_sockets", "times": 1, "reply": {"ok": False, "message": "ss failed"}},
                         {"cmd": "listening_sockets", "reply": {"ok": False}}]),
    "surface/helper-gone": ({"accounts": [ADMIN]}, [*_login(), {"get": "/surface"}],
                            [{"cmd": "listening_sockets", "error": True}]),
    # -- the update screen (read-only: what the update-helper does is a later phase) -------
    "update/offline": ({"accounts": [ADMIN, VIEWER]}, [
        *_login(), {"get": "/update"}, {"post": "/logout"}, *_login(VIEWER), {"get": "/update"}]),
    "update/current": ({"accounts": [ADMIN], "files": {
        "etc/fr_os/update_check.json": json.dumps({"current_version": frfw.__version__, "update_available": False,
                                                   "checked_at": "2026-10-31T12:00:00+00:00", "error": None})}},
        [*_login(), {"get": "/update"}],
        [{"cmd": LATEST_URL, "socket": HTTPS, "reply": {"tag_name": f"v{frfw.__version__}", "name": "FR_OS",
                                                       "body": "Fixes.", "html_url": "https://example.invalid/r"}},
         {"cmd": "kernel_status", "socket": UPDATE_SOCKET, "reply": {"ok": True, "kernel": {
             "summary": "Running the image's own kernel.", "state": "image", "available": True, "ready": None}}}]),
    "update/available": ({"accounts": [ADMIN], "files": {
        "etc/fr_os/update_check.json": json.dumps({
            "current_version": frfw.__version__, "update_available": True, "latest_version": "9.9.9",
            "security": True, "checked_at": "2026-10-31T12:00:00+00:00", "error": "GitHub returned 502",
            "auto_install_error": "signature did not verify"}),
        "etc/fr_os/update_state.json": json.dumps({
            "current_version": "0.0.9", "previous_version": "0.2.0",
            "last_update": {"action": "update", "version": "0.2.1", "applied_at": "2026-10-20T08:00:00+00:00",
                            "status": "ok", "message": "Updated <b>fine</b>"}})}},
        [*_login(), {"get": "/update"}],
        [{"cmd": LATEST_URL, "socket": HTTPS, "reply": {
            "tag_name": "v9.9.9", "name": "FR_OS 9.9.9 [Security]", "body": "Fixes <script>CVE</script>\n\nSecurity: no",
            "published_at": "2026-10-30T00:00:00Z"}},
         {"cmd": "kernel_status", "socket": UPDATE_SOCKET, "reply": {"ok": True, "kernel": {
             "summary": "Kernel 6.1.0-54 is on trial.", "state": "trial", "available": True, "ready": "6.1.0-55-amd64",
             "last_check": {"at": "2026-10-31T03:00:00+00:00", "error": True, "message": "apt failed"}}}}]),
    "update/answers": ({"accounts": [ADMIN], "files": {
        "etc/fr_os/update_state.json": json.dumps({"previous_version": None, "last_update": {"action": "rollback"}})}},
        [*_login(), *[{"get": "/update"}] * 7],
        [{"cmd": LATEST_URL, "socket": HTTPS, "times": 1, "status": 404},
         {"cmd": LATEST_URL, "socket": HTTPS, "times": 1, "status": 403},
         {"cmd": LATEST_URL, "socket": HTTPS, "times": 1, "reply": ["not", "a", "release"]},
         {"cmd": LATEST_URL, "socket": HTTPS, "times": 1, "reply": {"tag_name": "nightly-7", "body": None}},
         {"cmd": LATEST_URL, "socket": HTTPS, "times": 1, "reply": {"tag_name": "", "name": None}},
         {"cmd": LATEST_URL, "socket": HTTPS, "times": 1, "reply": {"tag_name": "v0.1.9", "body": "x"}},
         {"cmd": LATEST_URL, "socket": HTTPS, "times": 1, "reply": {"tag_name": "1.0.0", "body": "security: YES"}},
         {"cmd": "kernel_status", "socket": UPDATE_SOCKET, "times": 1, "reply": {"ok": False, "message": "no state"}},
         {"cmd": "kernel_status", "socket": UPDATE_SOCKET, "times": 1, "reply": {"ok": False}},
         {"cmd": "kernel_status", "socket": UPDATE_SOCKET, "times": 1, "reply": {"ok": True, "kernel": None}},
         {"cmd": "kernel_status", "socket": UPDATE_SOCKET, "times": 1, "reply": {"ok": True, "kernel": {
             "summary": "Kept.", "state": "good", "available": False, "ready": "6.1.0-55-amd64"}}},
         {"cmd": "kernel_status", "socket": UPDATE_SOCKET, "times": 1, "reply": {"ok": True, "kernel": {
             "summary": "No apt.", "available": False}}}]),
    "update/repo": ({"accounts": [ADMIN], "files": {
        "etc/fr_os/config.yaml": CONFIG + "update:\n  repo: someone/fr-fork\n  kernel_updates: false\n",
        "etc/fr_os/update_state.json": "[1, 2]"}},
        [*_login(), {"get": "/update"}],
        [{"cmd": "https://api.github.com/repos/someone/fr-fork/releases/latest", "socket": HTTPS,
          "reason": "timed out"}]),
    "update/settings": ({"accounts": [ADMIN, VIEWER]}, [
        *_login(), {"post": "/update/auto-security", "form": {"enabled": "true"}}, {"get": "/update?success=ok"},
        {"post": "/update/auto-security", "form": {}},
        {"post": "/update/kernel-updates", "form": {"enabled": "true"}},
        {"post": "/update/kernel-updates", "form": {"enabled": "off"}}, {"get": "/update?error=%3Cb%3E"},
        {"post": "/update/kernel-updates", "form": {"enabled": "maybe"}},
        {"post": "/update/auto-security", "form": {"enabled": "1"}, "csrf": "wrong"},
        {"post": "/logout"}, *_login(VIEWER), {"post": "/update/auto-security", "form": {"enabled": "true"}}]),
    "update/save-refused": ({"accounts": [ADMIN], "files": {
        "etc/fr_os/config.yaml": CONFIG + "update:\n  repo: not a repo\n"}},
        [*_login(), {"get": "/update"}, {"post": "/update/auto-security", "form": {"enabled": "true"}},
         {"post": "/update/kernel-updates", "form": {}}]),
}


@pytest.mark.parametrize("name", sorted(SESSIONS))
def test_webui_session(webui, name):
    setup, steps, *table = SESSIONS[name]
    _session(webui, name, setup, steps, table[0] if table else None)
