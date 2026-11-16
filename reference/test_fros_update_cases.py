"""FR_OS 1.x's signed release update (frfw.update, the update-helper's
apply and rollback in frfw.helper.update_server, and `firewall-cli update`
in frfw.cli), with the capture plugin: installs and rollbacks from a
release in the cache or downloaded, refused for their version, their
signature, their tarball or the state file, failing at each step after
the release verified, and the update check and the periodic check with
every answer GitHub can give.

What 1.x does to install a release -- pip and its source tree -- isn't
FR_OS 2's (decisions.md, "phase 4f-4b"), so the steps that change the
system are recorded, not run: `install` (_install_release_dir, with the
release's directory name), `restart` (_restart_services) and `webui`
(_restart_webui_delayed), each made to fail when the case says. What is
recorded around them is 1.x's own: what was downloaded, the order of the
steps, the reply or the output and exit status, the state file, the check
cache and the cache directory left, and the security alerts.

The tarballs are FR_OS 2 releases in shape (fr_os-<version>/ with its
VERSION, bin/firewall-cli and bin/fr-update-helper), named as FR_OS 2
names them, and signed with a key made here from a fixed seed, for these
cases only. Each case records 1.x's answer; nothing here asserts anything
about 1.x.
"""

from __future__ import annotations

import datetime
import gzip
import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
import types
import urllib.error
from pathlib import Path

import pytest


def _record(case: dict) -> None:
    capture = sys.modules.get("fros_capture")
    if capture is not None:
        capture._record("update", case)


_PKCS8_PREFIX = bytes.fromhex("302e020100300506032b657004220420")


def _private_pem(seed: int) -> bytes:
    der = _PKCS8_PREFIX + hashlib.sha256(f"fros update case key {seed}".encode()).digest()
    return subprocess.run(["openssl", "pkey", "-inform", "DER"], input=der, capture_output=True,
                          check=True).stdout


def _public_pem(seed: int) -> bytes:
    return subprocess.run(["openssl", "pkey", "-pubout"], input=_private_pem(seed), capture_output=True,
                          check=True).stdout


def _sign(seed: int, data: bytes, tmp: Path) -> bytes:
    key = tmp / f"sign-{seed}.key"
    key.write_bytes(_private_pem(seed))
    message = tmp / "message"
    message.write_bytes(data)
    out = tmp / "sig"
    subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(key), "-in", str(message),
                    "-out", str(out)], check=True, capture_output=True)
    return out.read_bytes()


def tarball_name(version: str) -> str:
    return f"fr_os-{version.lstrip('v')}-amd64.tar.gz"


#: 2026-11-01T00:00:00.250000Z: every timestamp an update writes.
NOW = datetime.datetime(2026, 11, 1, 0, 0, 0, 250000, tzinfo=datetime.timezone.utc)
REPO = "starsmash29/FR_OS-Community"


def _members(version: str, extra: list[tuple] = (), drop: tuple = ()) -> list[tuple]:
    """(name, kind, body) of a release tarball: kind "file", "dir" or a
    link ("symlink", "hardlink") with body its target."""
    top = f"fr_os-{version.lstrip('v')}"
    members = [
        (f"{top}/", "dir", b""),
        (f"{top}/VERSION", "file", f"{version.lstrip('v')}\n".encode()),
        (f"{top}/bin/", "dir", b""),
        (f"{top}/bin/firewall-cli", "file", f"cli {version}".encode()),
        (f"{top}/bin/fr-update-helper", "file", f"updater {version}".encode()),
        (f"{top}/systemd/fr-webui.service", "file", b"[Unit]\n"),
    ]
    members = [m for m in members if m[0] not in drop]
    return members + list(extra)


def _tarball(members: list[tuple]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tar:
        for name, kind, body in members:
            info = tarfile.TarInfo(name)
            info.mtime = 1700000000
            if kind == "dir":
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                tar.addfile(info)
            elif kind == "symlink":
                info.type, info.linkname = tarfile.SYMTYPE, body.decode()
                tar.addfile(info)
            elif kind == "hardlink":
                info.type, info.linkname = tarfile.LNKTYPE, body.decode()
                tar.addfile(info)
            else:
                info.size, info.mode = len(body), 0o755 if "/bin/" in name else 0o644
                tar.addfile(info, io.BytesIO(body))
    # No time in the gzip header: the same case, the same bytes.
    return gzip.compress(buf.getvalue(), mtime=0)


def _release(tmp: Path, version: str, members: list[tuple] | None = None, *, seed: int = 1,
             sums_name: str | None = None, tamper: bool = False, sums_upper: bool = False) -> dict[str, bytes]:
    """The three files of version's release."""
    data = _tarball(_members(version) if members is None else members)
    digest = hashlib.sha256(data).hexdigest()
    if sums_upper:
        digest = digest.upper()
    sums = f"{digest}  {sums_name or tarball_name(version)}\n".encode()
    if tamper:
        data = _tarball(_members(version, extra=[(f"fr_os-{version.lstrip('v')}/bin/extra", "file", b"x")]))
    return {tarball_name(version): data, "SHA256SUMS": sums, "SHA256SUMS.sig": _sign(seed, sums, tmp)}


def _hex(files: dict[str, bytes]) -> dict[str, str]:
    return {name: data.hex() for name, data in sorted(files.items())}


_TMP_RE = re.compile(r"/tmp[a-z0-9_]{8}/")


class _World:
    """What a case runs in: the files under tmp, the downloads and GitHub's
    answers from the table, the steps recorded."""

    def __init__(self, tmp: Path, monkeypatch, case: dict):
        from frfw import cli, release_signing, update

        self.tmp, self.case, self.steps, self.alerts = tmp, case, [], []
        self.root = tmp / "root"
        self.state_path = self.root / "etc/fr_os/update_state.json"
        self.check_path = self.root / "etc/fr_os/update_check.json"
        self.releases = self.root / "opt/fr_os/releases"
        keys = tmp / "keys"
        keys.mkdir()
        (keys / "case.pem").write_bytes(_public_pem(1))
        monkeypatch.setattr(release_signing, "TRUSTED_KEYS_DIR", keys)
        monkeypatch.setattr(release_signing, "source_tarball_name", tarball_name)
        monkeypatch.setattr(update, "_installed_version", lambda: case["installed"])
        monkeypatch.setattr(cli, "__version__", case["installed"])
        monkeypatch.setattr(update, "_now", lambda: NOW.isoformat())
        # FR_OS 2's releases are published from FR_OS-Community.
        monkeypatch.setattr(update, "DEFAULT_REPO", REPO)
        monkeypatch.setattr(update.urllib.request, "urlopen", self._urlopen)
        monkeypatch.setattr(update, "_install_release_dir", self._install)
        monkeypatch.setattr(update, "_restart_services", lambda services: self._step("restart"))
        monkeypatch.setattr(update, "_restart_webui_delayed", lambda *a: self._step("webui"))
        monkeypatch.setattr(update.paths, "UPDATE_CHECK_PATH", self.check_path)
        monkeypatch.setattr(cli, "_console_alert", lambda message, **who: self.alerts.append(
            {"message": message, **who}))
        for fn in (update.apply_update, update.rollback_update):
            monkeypatch.setattr(fn, "__kwdefaults__", {**fn.__kwdefaults__, "state_path": self.state_path,
                                                       "releases_dir": self.releases})
        for name, text in (("state", self.state_path), ("check_cache", self.check_path)):
            if case.get(name) is not None:
                text.parent.mkdir(parents=True, exist_ok=True)
                text.write_bytes(case[name].encode("utf-8", "surrogateescape"))
        for version, files in case.get("cache", {}).items():
            d = self.releases / version
            d.mkdir(parents=True, exist_ok=True)
            for name, data in files.items():
                (d / name).write_bytes(bytes.fromhex(data))
        if case.get("config") is not None:
            (self.root / "etc/fr_os").mkdir(parents=True, exist_ok=True)
            (self.root / "etc/fr_os/config.yaml").write_text(case["config"])

    def _step(self, name: str, detail: str = "") -> None:
        self.steps.append(name + (" " + detail if detail else ""))
        if self.case.get("fail") == name:
            from frfw import update

            raise update.UpdateError(self.case["fail_message"])

    def _install(self, release_dir: Path) -> None:
        self._step("install", release_dir.name)

    def _urlopen(self, request, timeout=None):
        url = request.full_url
        answers = {**self.case.get("downloads", {}), **self.case.get("github", {})}
        if url not in answers:
            raise urllib.error.URLError("[Errno -3] Temporary failure in name resolution")
        if url in self.case.get("downloads", {}):
            self.steps.append("download " + url)
        a = answers[url]
        if "error" in a:
            raise urllib.error.URLError(a["error"])
        if a.get("status", 200) >= 400:
            raise urllib.error.HTTPError(url, a["status"], a["reason"], {}, io.BytesIO(b""))
        body = bytes.fromhex(a["data"]) if "data" in a else a["body"].encode()

        class _Response(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                self.close()

        return _Response(body)

    def clean(self, text):
        if text is None:
            return None
        return _TMP_RE.sub("/@TMP@/", str(text).replace(str(self.root), "@ROOT@"))

    def left(self) -> dict:
        def read(path: Path):
            if not path.exists():
                return None
            return path.read_text(errors="surrogateescape")
        cache = {}
        if self.releases.is_dir():
            for d in sorted(self.releases.iterdir()):
                cache[d.name] = sorted(p.name for p in d.iterdir() if p.name != "src") if d.is_dir() else None
        return {"steps": self.steps, "state_after": read(self.state_path),
                "check_cache_after": read(self.check_path), "cache_after": cache, "alerts": self.alerts}


def _run(tmp_path, monkeypatch, case: dict) -> None:
    from frfw import cli, update
    from frfw.helper import update_server

    world = _World(tmp_path, monkeypatch, case)
    if case["op"] == "helper":
        server = types.SimpleNamespace(repo=case.get("repo", REPO), state_path=world.state_path,
                                       releases_dir=world.releases)
        try:
            reply = update_server._handle_request(json.loads(case["request"]), server)
        except Exception as exc:  # noqa: BLE001 -- recorded: the handler's "invalid request"
            reply = {"raised": type(exc).__name__, "text": str(exc)}
        outcome = {"reply": json.loads(world.clean(json.dumps(reply)))}
    else:
        argv = [a.replace("@ROOT@", str(world.root)) for a in case["argv"]]
        out, err = io.StringIO(), io.StringIO()
        monkeypatch.setattr(sys, "stdout", out)
        monkeypatch.setattr(sys, "stderr", err)
        code = cli.main(argv)
        monkeypatch.undo()
        outcome = {"code": code, "stdout": world.clean(out.getvalue()), "stderr": world.clean(err.getvalue())}
    left = world.left()
    left["state_after"] = world.clean(left["state_after"])
    for a in left["alerts"]:
        a["message"] = world.clean(a["message"])
    _record({"id": case["id"], "now": NOW.timestamp(), "key": _public_pem(1).decode(), **case, **outcome, **left})


BASE = f"https://github.com/{REPO}/releases/download"
API = f"https://api.github.com/repos/{REPO}/releases/latest"

CONFIG = """version: 1
hostname: fr
interfaces:
  wan: {device: eth0, zone: wan, dhcp: true}
  lan: {device: eth1, zone: lan, address: 192.168.1.1/24}
zones: {wan: {}, lan: {}}
update: {auto_install_security: AUTO}
"""


def _downloads(version: str, files: dict[str, bytes], *, tag: str | None = None, missing: str | None = None,
               error: str | None = None) -> dict:
    tag = tag or ("v" + version.lstrip("v"))
    d = {}
    for name, data in files.items():
        url = f"{BASE}/{tag}/{name}"
        if name == missing:
            d[url] = {"status": 404, "reason": "Not Found"}
        elif name == error:
            d[url] = {"error": "[Errno 111] Connection refused"}
        else:
            d[url] = {"data": data.hex()}
    return d


def _state(previous, current="2.0.0", last=None) -> str:
    return json.dumps({"current_version": current, "previous_version": previous, "last_update": last or {}},
                      indent=2) + "\n"


def _helper_cases(tmp: Path) -> dict[str, dict]:
    good = _release(tmp, "2.0.1")
    old = _release(tmp, "2.0.0")
    c = {}

    def apply(name, version="2.0.1", **kw):
        c[name] = {"op": "helper", "request": json.dumps({"cmd": "apply", "version": version}),
                   "installed": kw.pop("installed", "2.0.0"), **kw}

    apply("from the cache", cache={"2.0.1": _hex(good)})
    apply("with its v, from the cache", "v2.0.1", cache={"v2.0.1": _hex(_release(tmp, "v2.0.1"))})
    apply("downloaded", downloads=_downloads("2.0.1", good))
    apply("downloaded with its v", "v2.0.1", downloads=_downloads("2.0.1", good))
    apply("the cache incomplete: downloaded", cache={"2.0.1": _hex({tarball_name("2.0.1"): good[tarball_name(
        "2.0.1")]})}, downloads=_downloads("2.0.1", good))
    apply("the tarball missing", downloads=_downloads("2.0.1", good, missing=tarball_name("2.0.1")))
    apply("SHA256SUMS missing", downloads=_downloads("2.0.1", good, missing="SHA256SUMS"))
    apply("the signature missing", downloads=_downloads("2.0.1", good, missing="SHA256SUMS.sig"))
    apply("no network", downloads=_downloads("2.0.1", good, error=tarball_name("2.0.1")))
    apply("nothing published")
    apply("the same version", "2.0.0")
    apply("the same version with its v", "v2.0.0")
    apply("the same version written with zeros", "02.0.00")
    apply("an older version", "1.9.9")
    apply("older by its numbers", "2.0.9", installed="2.0.10")
    apply("newer by its numbers", "2.0.10", installed="2.0.9", cache={"2.0.10": _hex(_release(tmp, "2.0.10"))})
    apply("a much newer version", "10.0.0", cache={"10.0.0": _hex(_release(tmp, "10.0.0"))})
    for bad in ["2.0", "2.0.1 ", " 2.0.1", "2.0.1\n", "v", "2.0.1.1", "../../etc", "2.0.1/../..", "latest",
                "V2.0.1", "2.0.x"]:
        apply(f"not a version {bad!r}", bad)
    apply("an installed version that isn't one", installed="0.0.0-dev")
    apply("an installed version that isn't one, to an older one", "0.0.1", installed="dev")
    for name, request in {"no version": {"cmd": "apply"}, "an empty version": {"cmd": "apply", "version": ""},
                          "a number": {"cmd": "apply", "version": 2}, "null": {"cmd": "apply", "version": None},
                          "a list": {"cmd": "apply", "version": ["2.0.1"]}}.items():
        c[f"apply, {name}"] = {"op": "helper", "request": json.dumps(request), "installed": "2.0.0"}
    apply("signed by another key", cache={"2.0.1": _hex(_release(tmp, "2.0.1", seed=2))})
    apply("the tarball changed after signing", cache={"2.0.1": _hex(_release(tmp, "2.0.1", tamper=True))})
    apply("SHA256SUMS lists another name", cache={"2.0.1": _hex(_release(tmp, "2.0.1", sums_name="other.tar.gz"))})
    apply("SHA256SUMS in uppercase", cache={"2.0.1": _hex(_release(tmp, "2.0.1", sums_upper=True))})
    apply("a signature that isn't one", cache={"2.0.1": _hex({**good, "SHA256SUMS.sig": b"x" * 64})})
    apply("a member outside", cache={"2.0.1": _hex(_release(tmp, "2.0.1", _members("2.0.1", extra=[
        ("fr_os-2.0.1/../../evil", "file", b"x")])))})
    apply("an absolute member", cache={"2.0.1": _hex(_release(tmp, "2.0.1", _members("2.0.1", extra=[
        ("/etc/evil", "file", b"x")])))})
    apply("a member outside behind a link", cache={"2.0.1": _hex(_release(tmp, "2.0.1", _members("2.0.1", extra=[
        ("fr_os-2.0.1/up", "symlink", b"../.."), ("fr_os-2.0.1/up/evil", "file", b"x")])))})
    apply("links are skipped", cache={"2.0.1": _hex(_release(tmp, "2.0.1", _members("2.0.1", extra=[
        ("fr_os-2.0.1/bin/abs", "symlink", b"/usr/lib/x"), ("fr_os-2.0.1/bin/rel", "symlink", b"../VERSION"),
        ("fr_os-2.0.1/bin/hard", "hardlink", b"fr_os-2.0.1/VERSION")])))})
    apply("two directories", cache={"2.0.1": _hex(_release(tmp, "2.0.1", _members("2.0.1", extra=[
        ("other/", "dir", b"")])))})
    apply("a file beside the directory", cache={"2.0.1": _hex(_release(tmp, "2.0.1", _members("2.0.1", extra=[
        ("README", "file", b"x")])))})
    apply("only files", cache={"2.0.1": _hex(_release(tmp, "2.0.1", [("VERSION", "file", b"2.0.1\n")]))})
    apply("the directory implied", cache={"2.0.1": _hex(_release(tmp, "2.0.1", [
        m for m in _members("2.0.1") if m[1] != "dir"]))})
    for step in ("install", "restart", "webui"):
        apply(f"the {step} step fails", cache={"2.0.1": _hex(good)}, fail=step,
              fail_message=f"`{step}` failed: exit status 1")
    apply("a failed download keeps the earlier rollback target", state=_state("1.9.9"),
          downloads=_downloads("2.0.1", good, missing=tarball_name("2.0.1")))
    apply("a failed verification keeps it too", state=_state("1.9.9"),
          cache={"2.0.1": _hex(_release(tmp, "2.0.1", seed=2))})
    apply("a failed install records the running one", state=_state("1.9.9"), cache={"2.0.1": _hex(good)},
          fail="install", fail_message="pip failed")
    for name, text in {"not JSON": "not json", "a list": "[1, 2]", "null": "null", "empty": "",
                       "a number as the previous": _state(5), "a list as the last": _state("1.9.9", last=[1]),
                       "a falsy last": _state("1.9.9", last=0), "extra keys": json.dumps(
                           {"x": 1, "previous_version": "1.9.9", "current_version": "9.9.9"}),
                       "duplicate keys": '{"previous_version": "1.0.0", "previous_version": "1.9.9"}'}.items():
        apply(f"a state file, {name}, kept through a failure", state=text,
              downloads=_downloads("2.0.1", good, missing=tarball_name("2.0.1")))
    apply("a state file, extra keys, after success", state=json.dumps({"x": 1, "previous_version": "1.9.9"}),
          cache={"2.0.1": _hex(good)})
    apply("from another repository's releases", cache={}, repo="someone/fork",
          downloads={f"https://github.com/someone/fork/releases/download/v2.0.1/{n}": {"data": d.hex()}
                     for n, d in good.items()})
    apply("a repository that isn't one", repo="not a repo", downloads=_downloads("2.0.1", good))
    apply("a repository that isn't one, with the cache", repo="not a repo", cache={"2.0.1": _hex(good)})

    def rollback(name, **kw):
        c[f"rollback, {name}"] = {"op": "helper", "request": json.dumps({"cmd": "rollback"}),
                                  "installed": kw.pop("installed", "2.0.1"), **kw}

    rollback("nothing recorded")
    rollback("from the cache", state=_state("2.0.0", "2.0.1"), cache={"2.0.0": _hex(old)})
    rollback("downloaded", state=_state("2.0.0", "2.0.1"), downloads=_downloads("2.0.0", old))
    rollback("not cached, no network", state=_state("2.0.0", "2.0.1"),
             downloads=_downloads("2.0.0", old, error=tarball_name("2.0.0")))
    rollback("to a newer one (whatever was recorded)", state=_state("2.0.2", "2.0.1"),
             cache={"2.0.2": _hex(_release(tmp, "2.0.2"))})
    rollback("to the same one", state=_state("2.0.1", "2.0.1"), cache={"2.0.1": _hex(good)})
    rollback("with its v", state=_state("v2.0.0", "2.0.1"), cache={"v2.0.0": _hex(_release(tmp, "v2.0.0"))})
    for name, previous in {"null": None, "empty": "", "zero": 0, "false": False, "a number": 5,
                           "a list": ["2.0.0"], "a path": "../../usr", "with a space": "2.0.0 ",
                           "a map": {"v": "2.0.0"}}.items():
        rollback(f"the previous {name}", state=_state(previous, "2.0.1"), cache={"2.0.0": _hex(old)})
    rollback("signed by another key", state=_state("2.0.0", "2.0.1"),
             cache={"2.0.0": _hex(_release(tmp, "2.0.0", seed=2))})
    for step in ("install", "restart", "webui"):
        rollback(f"the {step} step fails", state=_state("2.0.0", "2.0.1"), cache={"2.0.0": _hex(old)}, fail=step,
                 fail_message=f"`{step}` failed: exit status 1")
    rollback("a state file that isn't JSON", state="{", cache={"2.0.0": _hex(old)})
    rollback("a state with a last attempt", state=_state("2.0.0", "2.0.1", last={
        "action": "apply", "version": "2.0.1", "status": "failed"}), cache={"2.0.0": _hex(old)})
    c["ping"] = {"op": "helper", "request": json.dumps({"cmd": "ping"}), "installed": "2.0.0"}
    return c


def _cli_cases(tmp: Path) -> dict[str, dict]:
    good = _release(tmp, "2.0.1")
    old = _release(tmp, "2.0.0")
    cfg = "@ROOT@/etc/fr_os/config.yaml"
    c = {}

    def cli(name, argv, **kw):
        c[f"cli {name}"] = {"op": "cli", "argv": argv, "installed": kw.pop("installed", "2.0.0"), **kw}

    cli("apply", ["update", "apply", "2.0.1"], cache={"2.0.1": _hex(good)})
    cli("apply, older", ["update", "apply", "1.0.0"])
    cli("apply, a failed step", ["update", "apply", "2.0.1"], cache={"2.0.1": _hex(good)}, fail="restart",
        fail_message="`systemctl try-restart -- fr-firewall.service` failed: Job failed.")
    cli("apply, another repository", ["update", "apply", "2.0.1", "--repo", "someone/fork"],
        downloads={f"https://github.com/someone/fork/releases/download/v2.0.1/{n}": {"data": d.hex()}
                   for n, d in good.items()})
    cli("apply, a repository that isn't one", ["update", "apply", "2.0.1", "--repo", "x"])
    cli("rollback", ["update", "rollback"], installed="2.0.1", state=_state("2.0.0", "2.0.1"),
        cache={"2.0.0": _hex(old)})
    cli("rollback, nothing recorded", ["update", "rollback"], installed="2.0.1")

    def github(status=200, **body):
        if status != 200:
            return {API: {"status": status, "reason": "Server Error" if status >= 500 else "Not Found"}}
        return {API: {"body": json.dumps(body)}}

    newer = github(tag_name="v2.0.1", name="FR_OS 2.0.1", body="Fixes.\n", html_url="https://example.test/r")
    security = github(tag_name="v2.0.1", name="v2.0.1 [security]", body="Fixes a hole.",
                      html_url="https://example.test/s")
    security_line = github(tag_name="v2.0.1", name="2.0.1", body="Notes\n  Security: YES  \nmore")
    for name, answer in {"no release": github(404), "newer": newer, "newer, no notes": github(tag_name="v2.0.1"),
                         "the same": github(tag_name="v2.0.0"), "older": github(tag_name="v1.0.0"),
                         "a tag that isn't a version": github(tag_name="nightly"),
                         "no tag": github(name="x"), "GitHub fails": github(500),
                         "not JSON": {API: {"body": "<html>"}}, "a list": {API: {"body": "[]"}},
                         "no network": {}}.items():
        cli(f"check, {name}", ["update", "check", cfg], github=answer, config=CONFIG.replace("AUTO", "false"))
    cli("check, a repository from the config", ["update", "check", cfg],
        github={"https://api.github.com/repos/someone/fork/releases/latest": {"body": json.dumps(
            {"tag_name": "v3.0.0"})}},
        config=CONFIG.replace("update: {auto_install_security: AUTO}", "update:\n  auto_install_security: false\n  repo: someone/fork"))
    cli("check, a config that doesn't parse", ["update", "check", cfg], github=newer, config="version: [")
    cli("check, no config", ["update", "check", cfg], github=newer)
    cli("check, a codename", ["update", "check", cfg], github=github(tag_name="v3.0.0"), installed="2.3.4")

    for name, kw in {
        "up to date": {"github": github(tag_name="v2.0.0")},
        "no release": {"github": github(404)},
        "an update": {"github": newer},
        "a security update, not installed": {"github": security},
        "a security line": {"github": security_line},
        "a security update installed": {"github": security, "config": CONFIG.replace("AUTO", "true"),
                                        "cache": {"2.0.1": _hex(good)}},
        "a security update that fails": {"github": security, "config": CONFIG.replace("AUTO", "true"),
                                         "downloads": _downloads("2.0.1", good, missing=tarball_name("2.0.1"))},
        "a security update, a broken config": {"github": security, "config": "update: {auto_install_security: true"},
        "the check fails": {"github": github(500)},
        "the check fails, an earlier check kept": {"github": {}, "check_cache": json.dumps({
            "checked_at": "2026-10-31T00:00:00+00:00", "current_version": "2.0.0", "update_available": True,
            "latest_version": "2.0.1", "security": False, "html_url": "", "error": None,
            "auto_install_error": None})},
        "the check fails, an earlier version's check": {"github": {}, "check_cache": json.dumps({
            "current_version": "1.9.9", "latest_version": "2.0.1"})},
        "the check fails, a broken cache": {"github": {}, "check_cache": "{"},
    }.items():
        kw.setdefault("config", CONFIG.replace("AUTO", "false"))
        cli(f"auto, {name}", ["update", "auto", cfg], **kw)
    return c


def _names(builder) -> list[str]:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        return sorted(builder(Path(tmp)))


@pytest.mark.parametrize("name", _names(_helper_cases))
def test_helper(tmp_path, monkeypatch, name):
    work = tmp_path / "make"
    work.mkdir()
    _run(tmp_path, monkeypatch, {"id": name, **_helper_cases(work)[name]})


@pytest.mark.parametrize("name", _names(_cli_cases))
def test_cli(tmp_path, monkeypatch, name):
    work = tmp_path / "make"
    work.mkdir()
    _run(tmp_path, monkeypatch, {"id": name, **_cli_cases(work)[name]})
