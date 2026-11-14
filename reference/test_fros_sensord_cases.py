"""FR_OS 1.x's application identification and AI-IDS daemons
(frfw.appid.daemon, frfw.ai_ids.daemon) run on recorded input, for FR_OS
2 (sensord.jsonl; reference/generate.sh runs this module). The libraries
under them (the catalog, name matching, usage counts, the anomaly engine,
the DGA heuristic and the line readers) are recorded by
reference/test_fros_appid_cases.py and reference/test_fros_aiids_cases.py;
this is what the daemons add:

- `view`: what each daemon takes from a config, which FR_OS 2's apply
  writes into the sensors' view (apply.SensorView): fr-appid's sources
  (`source_units`), and fr-ai-ids's switch, excluded MACs and the
  addresses they resolve to (`resolve_excluded_ips`), the networks it
  scores (`internal_networks`), the configured addresses it never
  quarantines (`infrastructure_ips` without the routing table and
  resolv.conf, which it reads at run time), the threat categories whose
  answers it counts and the quarantine time; and fr-iot-scan's
  switch, IoT-zone interfaces (`_iot_interfaces`), MAC lists, and
  isolation settings;
- `appid`: an `AppIdDaemon` started on a usage file (none, good, broken),
  fed query-log and SNI event lines at recorded clocks, writing its
  usage file: every file, byte for byte, and an exception it lets
  through at start (it then dies; the steps are those of a daemon
  started without the file);
- `aiids`: an `IDSDaemon` with the view of a config, a routing table and
  a resolv.conf, and an event log (none, good, broken), fed SNI and
  query-log lines, conntrack samples and evaluations at recorded clocks.
  Each sample and quarantine goes through 1.x's real helper client to a
  fake apply-helper on a Unix socket that answers recorded bytes:
  recorded are each request line, what the daemon prints, the events
  each evaluation flags and the event log it writes, byte for byte, and
  an exception it lets through (it then dies);
- `iotscan`: 1.x's IoT scan (`frfw.iot.scanner.run_scan`) on the view
  of a config, a neighbour table and an OUI registry, with its two
  helper calls (`dhcp_leases`, `iot_sync_isolation`) going through
  1.x's real helper client to the fake apply-helper: recorded are each
  request line, the messages, the inventory file and an exception it
  lets through (the scan then dies and writes nothing); the mDNS
  answers are given (the library's scan is reference/test_fros_iot_cases.py's);
- `mdns`: 1.x's mDNS discovery (`frfw.iot.mdns.discover`) on a real UDP
  socket, aimed at a fake responder on loopback (127.0.0.2) instead of
  the multicast group: every query it got (less the random id), and
  what discovery found from the answers sent back from given
  addresses and ports, damaged, foreign, from the router's own
  address, too many, too big; or the error it raised.

The socket's path is recorded as @SOCK@. Nothing here asserts anything
about 1.x.
"""

from __future__ import annotations

import contextlib
import copy
import dataclasses
import io
import json
import random
import socket
import struct
import sys
import threading
import time
import tempfile
from pathlib import Path

from frfw import paths
from frfw.ai_ids import daemon as ids_daemon
from frfw.ai_ids.engine import AnomalyEngine
from frfw.appid import daemon as appid_daemon
from frfw.iot import mdns as iot_mdns
from frfw.iot import scanner as iot_scanner
from frfw.config import parse_config
from frfw.helper import client as helper_client

sys.path.insert(0, str(Path(__file__).parent))
from test_fros_tlsfpd_cases import SOCK, SOCK_DIR, FakeHelper, _answer_json, _text  # noqa: E402

T0 = 1_700_000_000.0


def _record(case: dict) -> None:
    capture = sys.modules.get("fros_capture")
    if capture is not None:
        capture._record("sensord", case)


# --- configs and the view ---------------------------------------------------------------------------


def _base() -> dict:
    return {
        "version": 1,
        "hostname": "r",
        "interfaces": {
            "wan": {"device": "eth0", "zone": "wan"},
            "lan": {"device": "eth1", "zone": "lan", "address": "10.0.0.1/24"},
        },
        "zones": {"wan": {}, "lan": {}},
        "rules": [{"name": "out", "action": "accept", "from_zone": "lan", "to_zone": "wan"}],
        "nat": {"masquerade": [{"out_zone": "wan"}]},
        "dhcp": {
            "lan": {
                "range_start": "10.0.0.100",
                "range_end": "10.0.0.200",
                "dns_servers": ["10.0.0.1"],
                "reservations": [{"mac": "aa:bb:cc:dd:ee:ff", "address": "10.0.0.50"}],
            }
        },
        "ai_ids": {"enabled": True},
    }


def _with(**changes) -> dict:
    """The base config with top-level keys replaced (None: removed)."""
    raw = _base()
    for key, value in changes.items():
        if value is None:
            raw.pop(key, None)
        else:
            raw[key] = value
    return raw


def _view(config) -> dict:
    """What FR_OS 2's sensor view holds for these daemons, from 1.x's
    own functions."""
    units = appid_daemon.source_units(config)
    sources = ["dns" if u != appid_daemon.XDP_LOGGER_UNIT else "sni" for u in units]
    with tempfile.TemporaryDirectory() as tmp:
        empty = Path(tmp) / "empty"
        empty.write_text("")
        infrastructure = ids_daemon.infrastructure_ips(config, route_path=empty, resolv_path=empty)
    threat = sorted(n for n in ids_daemon.THREAT_CATEGORIES if n in config.adblocker.categories)
    return {
        "app_control": {"sources": sources},
        "ai_ids": {
            "enabled": config.ai_ids.enabled,
            "excluded_macs": list(config.ai_ids.excluded_macs),
            "excluded_ips": sorted(ids_daemon.resolve_excluded_ips(config)),
            "internal_networks": [str(n) for n in ids_daemon.internal_networks(config)],
            "infrastructure": sorted(infrastructure),
            "threat_categories": threat,
            "query_log": config.adblocker.enabled and config.adblocker.query_logging,
            "quarantine_duration_seconds": config.ai_ids.quarantine_duration_seconds,
        },
        # The shape decided in phase 4c (crates/fros-iot's View): the IoT
        # zones' interfaces in config order, as `_iot_interfaces` lists them.
        "iot": {
            "enabled": config.iot.enabled,
            "interfaces": [{"device": i.device, "address": i.address or None}
                           for i in iot_scanner._iot_interfaces(config)],
            "trusted_macs": list(config.iot.trusted_macs),
            "isolated_macs": list(config.iot.isolated_macs),
            "auto_isolate": config.iot.auto_isolate,
            "isolation_mode": config.iot.isolation_mode.value,
        },
    }


_LIST = ["https://lists.example/x.txt"]
ADBLOCK = {"enabled": True, "query_logging": True,
           "categories": {"malware": _LIST, "phishing": _LIST, "gambling": _LIST}}

VIEW_CONFIGS = {
    "base": _base(),
    "ids off": _with(ai_ids={"enabled": False}),
    "no ai_ids": _with(ai_ids=None),
    "excluded with reservation": _with(ai_ids={"enabled": True, "excluded_macs": ["aa:bb:cc:dd:ee:ff"],
                                               "quarantine_duration_seconds": 999}),
    "excluded upper case": _with(ai_ids={"enabled": True, "excluded_macs": ["AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"]}),
    "excluded without reservation": _with(ai_ids={"enabled": True, "excluded_macs": ["11:22:33:44:55:66"]}),
    "no masquerade": _with(nat=None),
    "two lans": _with(
        interfaces={
            "wan": {"device": "eth0", "zone": "wan", "address": "192.0.2.2/24"},
            "lan": {"device": "eth1", "zone": "lan", "address": "10.0.0.1/24"},
            "iot": {"device": "eth2", "zone": "iot", "address": "10.0.5.1/24"},
            "guest": {"device": "eth3", "zone": "guest", "address": "10.0.0.129/25"},
        },
        zones={"wan": {}, "lan": {}, "iot": {}, "guest": {}},
    ),
    "wireguard": _with(wireguard={"enabled": True, "address": "10.8.0.1/24", "listen_port": 51820},
                       zones={"wan": {}, "lan": {}, "vpn": {}}),
    "adblock": _with(adblocker=ADBLOCK),
    "adblock no logging": _with(adblocker={**ADBLOCK, "query_logging": False}),
    "adblock off": _with(adblocker={**ADBLOCK, "enabled": False}),
    "adblock gambling only": _with(adblocker={**ADBLOCK, "categories": {"gambling": _LIST}}),
    "appid dns": _with(adblocker=ADBLOCK, app_control={"enabled": True}),
    "appid off": _with(adblocker=ADBLOCK, app_control={"enabled": False, "observe_sni": True},
                       xdp_sni_filter={"enabled": True, "interfaces": ["lan"]}),
    "appid sni": _with(app_control={"enabled": True, "observe_sni": True},
                       xdp_sni_filter={"enabled": True, "interfaces": ["lan"]}),
    "appid both": _with(adblocker=ADBLOCK, app_control={"enabled": True, "observe_sni": True},
                        xdp_sni_filter={"enabled": True, "interfaces": ["lan"]}),
    "dns servers": _with(dhcp={"lan": {"range_start": "10.0.0.100", "range_end": "10.0.0.200",
                                       "dns_servers": ["9.9.9.9", "1.1.1.1", "10.0.0.1"]}}),
    "quarantine time": _with(ai_ids={"enabled": True, "quarantine_duration_seconds": 604800}),
    "iot": _with(
        interfaces={
            "wan": {"device": "eth0", "zone": "wan"},
            "lan": {"device": "eth1", "zone": "lan", "address": "10.0.0.1/24"},
            "cams": {"device": "eth1.30", "zone": "iot", "address": "10.0.30.1/24"},
            "plugs": {"device": "eth2", "zone": "iot"},
            "tv": {"device": "eth3", "zone": "media", "address": "10.0.40.1/24"},
        },
        zones={"wan": {}, "lan": {}, "iot": {}, "media": {}},
        iot={"enabled": True, "zones": ["media", "iot"], "auto_isolate": True, "isolation_mode": "block",
             "trusted_macs": ["AA:BB:CC:00:00:01"], "isolated_macs": ["AA:BB:CC:00:00:02", "aa:bb:cc:00:00:03"]},
    ),
    "iot off": _with(zones={"wan": {}, "lan": {}}, iot={"enabled": False, "zones": ["lan"]}),
    "iot internet only": _with(iot={"enabled": True, "zones": ["lan"]}),
}


def test_view():
    for name, raw in VIEW_CONFIGS.items():
        try:
            config = parse_config(copy.deepcopy(raw))
        except Exception as exc:  # noqa: BLE001 -- an input the table got wrong
            raise AssertionError(f"{name}: {exc}") from exc
        _record({"op": "view", "name": name, "config": raw, "view": _view(config)})


# --- fr-appid --------------------------------------------------------------------------------------------


def _dns(client: str, name: str, qtype: str = "A", serial: int = 1) -> str:
    return f"Nov 14 08:00:00 dnsmasq[123]: {serial} {client}/40000 query[{qtype}] {name} from {client}"


def _sni(client: str, sni: str, action: str = "pass") -> str:
    return json.dumps({"ts": T0, "action": action, "saddr": client, "sport": 40000,
                       "daddr": "93.184.216.34", "dport": 443, "sni": sni})


def _appid(name: str, config_name: str, steps, *, state: bytes | None = None) -> None:
    config = parse_config(copy.deepcopy(VIEW_CONFIGS[config_name]))
    clock = [T0]
    case: dict = {"op": "appid", "name": name, "view": _view(config)["app_control"],
                  "state": None if state is None else state.hex(), "steps": []}
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "appid_usage.json"
        if state is not None:
            path.write_bytes(state)

        def start():
            return appid_daemon.AppIdDaemon(config, usage_path=path, clock=lambda: clock[0])

        try:
            d = start()
        except Exception as exc:  # noqa: BLE001 -- what 1.x does is the point
            case["crash"] = type(exc).__name__
            path.unlink()
            d = start()
        handlers = dict(d.sources())
        for kind, now, *args in steps:
            clock[0] = now
            if kind == "write":
                d.write_snapshot()
                case["steps"].append({"write": now, "file": path.read_text()})
                continue
            unit = appid_daemon.XDP_LOGGER_UNIT if kind == "sni" else f"{paths.ADBLOCK_DNS_SERVICE_NAME}.service"
            handler = handlers.get(unit)
            if handler is not None:  # a source the config doesn't follow isn't read
                handler(args[0])
            case["steps"].append({kind: args[0], "now": now})
    _record(case)


def test_appid():
    both = [
        ("dns", T0, _dns("10.0.0.5", "www.netflix.com")),
        ("dns", T0 + 1, _dns("10.0.0.5", "www.netflix.com", "AAAA")),
        ("dns", T0 + 2, _dns("10.0.0.5", "WWW.NETFLIX.COM", "HTTPS")),
        ("dns", T0 + 11, _dns("10.0.0.5", "www.netflix.com")),
        ("dns", T0 + 12, _dns("10.0.0.6", "nflxvideo.net", "PTR")),
        ("dns", T0 + 13, _dns("10.0.0.6", "api.spotify.com")),
        ("dns", T0 + 14, "not a query line"),
        ("sni", T0 + 15, _sni("10.0.0.5", "www.netflix.com")),
        ("sni", T0 + 16, _sni("10.0.0.7", "open.spotify.com", "drop")),
        ("sni", T0 + 17, _sni("10.0.0.7", "open.spotify.com", "other")),
        ("sni", T0 + 18, "{not json"),
        ("sni", T0 + 19, _sni("", "www.netflix.com")),
        ("sni", T0 + 20, json.dumps([1, 2])),
        ("write", T0 + 30),
        ("dns", T0 + 3700, _dns("fd00::5", "www.youtube.com")),
        ("write", T0 + 3730),
        ("write", T0 + 25 * 3600 + 30),
    ]
    _appid("both sources", "appid both", both)
    _appid("dns only", "appid dns", both)
    _appid("sni only", "appid sni", both)
    _appid("no sources", "appid off", both[:3] + [("write", T0 + 30)])

    good = None
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "u.json"
        clock = [T0 - 600]
        d = appid_daemon.AppIdDaemon(parse_config(copy.deepcopy(VIEW_CONFIGS["appid both"])), usage_path=path,
                                     clock=lambda: clock[0])
        d.handle_dns_log_line(_dns("10.0.0.5", "www.netflix.com"))
        d.handle_sni_event_line(_sni("10.0.0.8", "open.spotify.com"))
        d.write_snapshot()
        good = path.read_bytes()
    states = {
        "good": good,
        "empty": b"",
        "not json": b"{oops",
        "a list": b"[]",
        "apps a list": b'{"apps": []}',
        "not utf-8": b'{"apps": {"\xff": {}}}',
        "huge int": b'{"apps": {"netflix": {"10.0.0.5": {"first_seen": 1e400, "last_seen": 1, "buckets": {}}}}}',
        "bad row": b'{"apps": {"netflix": {"10.0.0.5": {"first_seen": "x"}, "10.0.0.6": 5}}}',
    }
    for label, state in states.items():
        _appid(f"state {label}", "appid both", [("dns", T0, _dns("10.0.0.9", "www.netflix.com")),
                                                ("write", T0 + 30)], state=state)


# --- fr-ai-ids -------------------------------------------------------------------------------------------


ROUTE = (
    "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
    "eth0\t00000000\t010200C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
    "eth1\t0000000A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
)
RESOLV = "# generated\nnameserver 192.0.2.53\nnameserver ::1\nnameserver bogus\nsearch lan\n"


def _flows(*flows) -> bytes:
    return (json.dumps({"ok": True, "flows": list(flows)}) + "\n").encode()


def _flow(src: str, dst: str, dport: int = 443, sport: int = 40000, mac: str | None = None,
          proto: str = "tcp") -> dict:
    flow = {"proto": proto, "src": src, "sport": sport, "dst": dst, "dport": dport}
    if mac is not None:
        flow["src_mac"] = mac
    return flow


def _scan(src: str, n: int, base: int = 0, mac: str | None = None) -> bytes:
    """`n` new connections from `src` to `n` destinations."""
    dst = (lambda i: f"2001:db8::{i + base + 1:x}") if ":" in src else (lambda i: f"198.51.100.{(i + base) % 250 + 1}")
    return _flows(*[_flow(src, dst(i), sport=30000 + base + i, mac=mac) for i in range(n)])


OK = b'{"ok": true}\n'


def _aiids(name: str, config_name: str, steps, *, events: bytes | None = None, route: str = ROUTE,
           resolv: str = RESOLV, window: float = 10.0) -> None:
    """Steps: ("sni", now, line), ("dns", now, line), ("conntrack", now,
    answer), ("evaluate", now, wall, [quarantine answers])."""
    config = parse_config(copy.deepcopy(VIEW_CONFIGS[config_name]))
    clock = [0.0]
    wall = [T0]
    calls: list[dict] = []
    case: dict = {"op": "aiids", "name": name, "view": _view(config)["ai_ids"], "route": route,
                  "resolv": resolv, "window": window,
                  "events": None if events is None else events.hex(), "steps": []}
    answers: list = []

    def helper(call):
        answer = answers.pop(0) if answers else OK
        with FakeHelper(answer) as fake:
            try:
                return call()
            finally:
                calls.append({"answer": _answer_json(answer), "request": fake.request})

    def quarantine(ip, duration):
        return helper(lambda: helper_client.quarantine_ip(ip, duration, socket_path=SOCK))

    def conntrack():
        return helper(lambda: helper_client.conntrack_sample(socket_path=SOCK))

    # The socket's directory is the TLS daemon's recording's, which its
    # teardown removes when that module runs first.
    SOCK_DIR.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "route").write_text(route)
        (tmp / "resolv.conf").write_text(resolv)
        events_path = tmp / "ai_ids_events.json"
        if events is not None:
            events_path.write_bytes(events)
        d = ids_daemon.IDSDaemon(
            config, engine=AnomalyEngine(window_seconds=window), quarantine_fn=quarantine,
            conntrack_fn=conntrack, events_path=events_path, clock=lambda: clock[0],
            adblock_category_dir=paths.ADBLOCK_CATEGORY_DIR, route_path=tmp / "route",
            resolv_path=tmp / "resolv.conf",
        )
        real_time = ids_daemon.time.time
        ids_daemon.time.time = lambda: wall[0]
        try:
            for kind, now, *args in steps:
                clock[0] = now
                out: dict = {"now": now}
                start = len(calls)
                printed = io.StringIO()
                if kind == "conntrack":
                    answers[:] = [args[0]]
                    out["conntrack"] = _answer_json(args[0])
                elif kind == "evaluate":
                    wall[0] = args[0]
                    answers[:] = list(args[1])
                    out["evaluate"] = True
                    out["wall"] = args[0]
                else:
                    out[kind] = args[0]
                try:
                    with contextlib.redirect_stdout(printed), contextlib.redirect_stderr(printed):
                        if kind == "sni":
                            d.handle_sni_event_line(args[0])
                        elif kind == "dns":
                            d.handle_dns_log_line(args[0])
                        elif kind == "conntrack":
                            d.poll_conntrack_once()
                        else:
                            flagged = d.evaluate_and_enforce()
                            out["flagged"] = [dataclasses.asdict(e) for e in flagged]
                except Exception as exc:  # noqa: BLE001 -- 1.x dies here
                    out["crash"] = type(exc).__name__
                out["helper"] = calls[start:]
                out["log"] = printed.getvalue()
                if kind == "evaluate":
                    out["file"] = events_path.read_bytes().hex() if events_path.exists() else None
                case["steps"].append(out)
                if "crash" in out:
                    break
        finally:
            ids_daemon.time.time = real_time
    _record(json.loads(_text(json.dumps(case))))


def _blocks(src: str, n: int, at: float):
    return [("sni", at + i * 0.1, _sni(src, "evil.test", "drop")) for i in range(n)]


def test_aiids():
    # SNI blocklist hits over the absolute floor; one excluded, one infrastructure.
    steps = (
        _blocks("10.0.0.5", 4, 1.0)
        + _blocks("10.0.0.50", 4, 1.0)
        + _blocks("10.0.0.1", 4, 1.0)
        + _blocks("192.0.2.9", 4, 1.0)  # outside: never scored
        + [("sni", 2.0, _sni("10.0.0.6", "evil.test", "pass")), ("sni", 2.1, "garbage")]
        + [("evaluate", 11.0, T0 + 11, [OK, OK])]
    )
    _aiids("sni floor", "excluded with reservation", steps)
    _aiids("sni floor, nothing excluded", "base", steps)
    _aiids("helper refuses", "base", steps[:-1] + [("evaluate", 11.0, T0 + 11,
                                                     [b'{"ok": false, "message": "no"}\n', b'{"ok": false}\n'])])
    _aiids("helper unreachable", "base", steps[:-1] + [("evaluate", 11.0, T0 + 11, [None, "file"])])
    _aiids("helper not json", "base", steps[:-1] + [("evaluate", 11.0, T0 + 11, [b"nope\n", b"\n"])])
    _aiids("helper reply not an object", "base", steps[:-1] + [("evaluate", 11.0, T0 + 11, [b"[1]\n"])])

    # Conntrack: a scan from one host, long-lived flows not counted twice.
    scan = [("conntrack", 1.0, _scan("10.0.0.7", 80)), ("conntrack", 6.0, _scan("10.0.0.7", 80)),
            ("conntrack", 7.0, _scan("10.0.0.7", 80, base=80)),
            ("evaluate", 11.0, T0 + 11, [OK])]
    _aiids("conntrack scan", "base", scan)
    _aiids("conntrack scan, two lans", "two lans", [
        ("conntrack", 1.0, _flows(*[_flow("10.0.5.9", f"198.51.100.{i}", sport=1000 + i) for i in range(1, 90)],
                                  *[_flow("10.0.0.130", f"198.51.100.{i}", sport=2000 + i) for i in range(1, 90)],
                                  _flow("192.0.2.2", "198.51.100.1"))),
        ("evaluate", 11.0, T0 + 11, [OK, OK]),
    ])
    _aiids("conntrack answers", "base", [
        ("conntrack", 1.0, b'{"ok": false, "message": "busy"}\n'),
        ("conntrack", 2.0, None),
        ("conntrack", 3.0, b"{bad\n"),
        ("conntrack", 4.0, b'{"ok": true}\n'),
        ("conntrack", 5.0, b'{"ok": true, "flows": "abc"}\n'),
        ("conntrack", 6.0, b'{"ok": true, "flows": [1, null, {"src": "10.0.0.7"}, '
                           b'{"proto": "tcp", "src": "10.0.0.7", "sport": "x", "dst": "a", "dport": 1}, '
                           b'{"proto": "tcp", "src": 7, "sport": 1, "dst": "a", "dport": 1}, '
                           b'{"proto": "tcp", "src": "10.0.0.7", "sport": 1.9, "dst": "a", "dport": "2"}]}\n'),
        ("evaluate", 11.0, T0 + 11, []),
    ])
    _aiids("conntrack flows a number", "base", [("conntrack", 1.0, b'{"ok": true, "flows": 5}\n')])
    _aiids("conntrack reply a list", "base", [("conntrack", 1.0, b"[]\n")])

    # IPv6: scored by MAC, quarantined through its latest address.
    mac = "02:00:00:00:00:0a"
    _aiids("ipv6 by mac", "base", [
        ("conntrack", 1.0, _scan("fd00::a", 40, mac=mac)),
        ("conntrack", 2.0, _scan("fd00::b", 40, base=40, mac=mac.upper())),
        ("conntrack", 3.0, _scan("fd00::c", 40, base=80)),
        ("sni", 4.0, _sni("fd00::b", "evil.test", "drop")),
        ("sni", 4.1, _sni("fd00:0::b", "evil.test", "drop")),
        ("conntrack", 5.0, _flows(_flow("fd00::d", "2001:db8::1", mac="not a mac"),
                                  _flow("fe80::1%eth1", "2001:db8::1", mac=mac))),
        ("evaluate", 11.0, T0 + 11, [OK]),
    ])
    _aiids("ipv6 excluded by mac", "excluded upper case", [
        ("conntrack", 1.0, _scan("fd00::a", 80, mac="11:22:33:44:55:66")),
        ("evaluate", 11.0, T0 + 11, [OK]),
    ])

    # DNS: NXDOMAIN floods (DGA-looking and not) and threat-category answers.
    rng = random.Random(4)
    dga = ["".join(rng.choice("bcdfghjklmnpqrstvwxz0123456789") for _ in range(16)) + ".com" for _ in range(12)]
    nx = [f"host{i}.example" for i in range(32)]
    dns = (
        [("dns", 1.0 + i * 0.01, f"{i} 10.0.0.8/5000 reply {n} is NXDOMAIN") for i, n in enumerate(dga)]
        + [("dns", 2.0 + i * 0.01, f"Nov 14 08:00:00 dnsmasq[1]: {i} 10.0.0.9/5000 cached {n} is NXDOMAIN")
           for i, n in enumerate(nx)]
        + [("dns", 3.0 + i * 0.01, f"{i} 10.0.0.10/5000 {paths.ADBLOCK_CATEGORY_DIR}/malware.hosts bad{i}.example is 0.0.0.0")
           for i in range(4)]
        + [("dns", 3.5 + i * 0.01, f"{i} 10.0.0.11/5000 {paths.ADBLOCK_CATEGORY_DIR}/gambling.hosts ad{i}.example is ::")
           for i in range(4)]
        + [("dns", 4.0, "1 192.0.2.7/5000 reply x.example is NXDOMAIN"), ("dns", 4.1, "dnsmasq started"),
           ("dns", 4.2, "config doh.canary is NXDOMAIN")]
        + [("evaluate", 11.0, T0 + 11, [OK, OK, OK])]
    )
    _aiids("dns", "adblock", dns)
    _aiids("dns, gambling only", "adblock gambling only", dns)

    # The routing table and resolv.conf, read at each evaluation.
    gw = _blocks("10.0.0.2", 4, 1.0) + _blocks("10.0.0.3", 4, 1.0) + [("evaluate", 11.0, T0 + 11, [OK, OK])]
    route = ROUTE.replace("010200C0", "0200000A") + "eth0\t00000000\tzz\t0003\t0\n" + "short\n"
    _aiids("gateway from route", "base", gw, route=route, resolv="nameserver 10.0.0.3\n")
    _aiids("no route, no resolv", "base", gw, route="", resolv="")
    _aiids("dhcp dns servers", "dns servers", _blocks("10.0.0.1", 4, 1.0) + [("evaluate", 11.0, T0 + 11, [OK])])

    # The event log: kept to the last 50, whatever was there before.
    old = json.dumps([{"ts": 1.5, "ip": f"10.0.0.{i}", "score": 1.0, "reasons": ["x"]} for i in range(49)]).encode()
    for label, events in {"49 old": old, "not json": b"{x", "a dict": b'{"a": 1}', "empty": b"",
                          "odd values": b'[1, "two", {"k": [1e5, -0.0, 1e300, NaN]}, {"\\u00e9": "\\ud800"}]'}.items():
        _aiids(f"event log {label}", "base", _blocks("10.0.0.5", 4, 1.0) + _blocks("10.0.0.6", 4, 1.0)
               + [("evaluate", 11.0, T0 + 11, [OK, OK])], events=events)
    _aiids("event log not utf-8", "base", _blocks("10.0.0.5", 4, 1.0) + [("evaluate", 11.0, T0 + 11, [OK])],
           events=b"[\xff]")

    # Windows: baselines over several, then a burst.
    steps = []
    for w in range(8):
        t = w * 10.0
        steps.append(("conntrack", t + 1, _scan("10.0.0.12", 6, base=w * 6)))
        steps.append(("evaluate", t + 10, T0 + t + 10, [OK]))
    steps.append(("conntrack", 81.0, _scan("10.0.0.12", 120, base=60)))
    steps.append(("evaluate", 90.0, T0 + 90, [OK]))
    _aiids("baseline then burst", "base", steps)


# --- the IoT scan --------------------------------------------------------------------------------

ARP = ("IP address       HW type     Flags       HW address            Mask     Device\n"
       "10.0.30.5        0x1         0x2         24:0a:c4:11:22:33     *        eth1.30\n"
       "10.0.30.6        0x1         0x2         aa:bb:cc:00:00:01     *        eth1.30\n"
       "10.0.40.7        0x1         0x2         00:11:22:33:44:77     *        eth3\n"
       "10.0.0.8         0x1         0x2         00:11:22:33:44:88     *        eth1\n")
OUI = b"Registry,Assignment,Organization Name,Organization Address\nMA-L,240AC4,Espressif Inc.,CN\n"
LEASES = (b'{"ok": true, "leases": [{"mac": "AA:BB:CC:00:00:02", "ip": "10.0.30.9", '
          b'"hostname": "plug-01", "interface": "eth1.30"}]}\n')


def _iotscan(name: str, config_name: str, answers: list, *, mdns_results: dict | None = None) -> None:
    """`answers`: the fake helper's bytes for each call in turn (then
    {"ok": true}); `mdns_results`: what discovery found."""
    config = parse_config(copy.deepcopy(VIEW_CONFIGS[config_name]))
    calls: list[dict] = []
    answers = list(answers)
    mdns_results = {} if mdns_results is None else mdns_results

    def helper(call):
        answer = answers.pop(0) if answers else OK
        with FakeHelper(answer) as fake:
            try:
                return call()
            finally:
                calls.append({"answer": _answer_json(answer), "request": fake.request})

    SOCK_DIR.mkdir(exist_ok=True)
    case: dict = {"op": "iotscan", "name": name, "view": _view(config)["iot"], "arp": ARP,
                  "oui": OUI.hex(), "mdns": mdns_results, "now": T0}
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "arp").write_text(ARP)
        (tmp / "oui.csv").write_bytes(OUI)
        state = tmp / "iot_inventory.json"
        try:
            result = iot_scanner.run_scan(
                config,
                leases_fn=lambda: helper(lambda: helper_client.dhcp_leases(socket_path=SOCK)),
                sync_fn=lambda macs: helper(lambda: helper_client.iot_sync_isolation(macs, socket_path=SOCK)),
                mdns_fn=lambda addresses: {ip: set(s) for ip, s in mdns_results.items()},
                arp_path=tmp / "arp", oui_path=tmp / "oui.csv", state_path=state, now=T0,
            )
            case["messages"] = result.messages
        except Exception as exc:  # noqa: BLE001 -- 1.x dies here
            case["crash"] = type(exc).__name__
        case["helper"] = calls
        case["state"] = state.read_text() if state.exists() else None
    _record(json.loads(_text(json.dumps(case))))


def test_iotscan():
    _iotscan("leases and isolation", "iot", [LEASES], mdns_results={"10.0.30.5": ["_hap._tcp"]})
    _iotscan("no helper", "iot", [None, None])
    _iotscan("not a socket", "iot", ["file", "file"])
    _iotscan("helper refuses", "iot", [b'{"ok": false, "message": "not allowed"}\n',
                                      b'{"ok": false, "message": "nft failed"}\n'])
    _iotscan("leases not utf-8", "iot", [b'{"ok": true, "leases": ["\xff"]}\n'])
    _iotscan("sync not utf-8", "iot", [LEASES, b'\xfe\n'])
    _iotscan("leases not json", "iot", [b"nope\n"])
    _iotscan("leases not an object", "iot", [b"[1, 2]\n"])
    _iotscan("sync too big", "iot", [LEASES, b"[" * 100_000 + b"\n"])
    _iotscan("sync too deep", "iot", [LEASES, b"[" * 5_000 + b"\n"])
    _iotscan("isolated answered", "iot", [LEASES, b'{"ok": true, "isolated": ["aa:bb:cc:00:00:02"]}\n'])
    _iotscan("internet only", "iot internet only", [])
    _iotscan("off", "iot off", [])


# --- mDNS discovery ---------------------------------------------------------------------------------

MDNS_PORT = 45353      # the fake responder's port (the group's, 5353, in 1.x)
MDNS_BIND = 45530      # the port discovery sends from (IOT_MDNS_REPLY_PORT, 53530, in 1.x)
RESPONDER = "127.0.0.2"


def _name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        raw = label.encode()
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _ptrs(*services: str, flags: int = 0x8400) -> bytes:
    meta = _name("_services._dns-sd._udp.local")
    answers = b"".join(meta + struct.pack("!HHIH", 12, 0x8001, 4500, len(_name(t))) + _name(t)
                       for t in services)
    return struct.pack("!HHHHHH", 0, flags, 0, len(services), 0, 0) + answers


class Responder:
    """Sockets on loopback at (ip, port) for each answer's source; once
    the first query reaches RESPONDER, sends every answer from its
    source to where the query came from, in order; keeps every query
    it got."""

    def __init__(self, answers):
        self.answers = answers
        self.queries: list[bytes] = []
        self.socks = {}
        for ip, port, _ in answers:
            if (ip, port) not in self.socks:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.bind((ip, port))
                self.socks[(ip, port)] = s
        if (RESPONDER, MDNS_PORT) not in self.socks:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind((RESPONDER, MDNS_PORT))
            self.socks[(RESPONDER, MDNS_PORT)] = s
        self.main = self.socks[(RESPONDER, MDNS_PORT)]
        self.thread = threading.Thread(target=self._serve)
        self.thread.start()

    def _serve(self):
        self.main.settimeout(3.0)
        try:
            data, peer = self.main.recvfrom(65536)
        except OSError:
            return
        self.queries.append(data)
        for ip, port, packet in self.answers:
            self.socks[(ip, port)].sendto(packet, peer)

    def close(self):
        self.thread.join(timeout=5)
        self.main.setblocking(False)
        while True:
            try:
                self.queries.append(self.main.recv(65536))
            except OSError:
                break
        for s in self.socks.values():
            s.close()


def _mdns(name: str, addresses: list[str], answers=(), *, max_packets: int = 512, timeout: float = 1.0,
          taken: bool = False) -> None:
    """`answers`: (source ip, source port, packet) the responder sends
    back; `taken`: the port discovery binds is already bound."""
    responder = Responder(list(answers))
    blocker = None
    if taken:
        blocker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        blocker.bind(("0.0.0.0", MDNS_BIND))
    case: dict = {"op": "mdns", "name": name, "addresses": addresses, "port": MDNS_PORT, "bind": MDNS_BIND,
                  "responder": RESPONDER, "max_packets": max_packets, "timeout": timeout, "taken": taken,
                  "answers": [[ip, port, packet.hex()] for ip, port, packet in answers]}
    try:
        found = iot_mdns.discover(addresses, timeout=timeout, target=(RESPONDER, MDNS_PORT),
                                  bind_port=MDNS_BIND, max_packets=max_packets)
        case["found"] = {ip: sorted(s) for ip, s in sorted(found.items())}
    except iot_mdns.MdnsError as exc:
        case["error"] = str(exc)
    finally:
        if blocker is not None:
            blocker.close()
        if not responder.queries:
            # Nothing was sent: let the responder's wait end.
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(b"", (RESPONDER, MDNS_PORT))
            responder.close()
            responder.queries = [q for q in responder.queries if q]
        else:
            responder.close()
    case["queries"] = [q[2:].hex() for q in responder.queries]
    _record(case)


def test_mdns():
    hap = _ptrs("_hap._tcp.local")
    lo = "127.0.0.1"
    _mdns("one responder", [lo], [(RESPONDER, MDNS_PORT, _ptrs("_hap._tcp.local", "_matter._tcp.local"))])
    _mdns("no answer", [lo])
    _mdns("no address", [])
    _mdns("address not local", ["192.0.2.1"], [(RESPONDER, MDNS_PORT, hap)])
    _mdns("one address not local", ["192.0.2.1", lo], [(RESPONDER, MDNS_PORT, hap)])
    _mdns("two addresses", [lo, "127.0.0.4"], [(RESPONDER, MDNS_PORT, hap)])
    _mdns("own and foreign ignored", [lo, "127.0.0.3"], [
        ("127.0.0.3", MDNS_PORT, _ptrs("_own._tcp.local")),
        (RESPONDER, MDNS_PORT + 1, _ptrs("_foreign._tcp.local")),
        ("127.0.0.5", MDNS_PORT, _ptrs("_googlecast._tcp.local")),
        (RESPONDER, MDNS_PORT, hap),
    ])
    _mdns("damaged answers", [lo], [
        (RESPONDER, MDNS_PORT, b""),
        (RESPONDER, MDNS_PORT, b"\x00\x00\x84"),
        (RESPONDER, MDNS_PORT, hap[:-3]),
        (RESPONDER, MDNS_PORT, _ptrs("_ipp._tcp.local", flags=0)),
        (RESPONDER, MDNS_PORT, b"\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00\xc0\x0c"),
        ("127.0.0.6", MDNS_PORT, _ptrs("_airplay._tcp.local")),
    ])
    _mdns("max packets", [lo], [(RESPONDER, MDNS_PORT, _ptrs(f"_s{i}._tcp.local")) for i in range(4)],
          max_packets=2)
    many = [f"_s{i:03d}._tcp.local" for i in range(80)]
    _mdns("services per host", [lo], [(RESPONDER, MDNS_PORT, _ptrs(*many[:40])),
                                      (RESPONDER, MDNS_PORT, _ptrs(*many[40:]))])
    rng = random.Random(4302)
    _mdns("random bytes", [lo], [(RESPONDER, MDNS_PORT, bytes(rng.randrange(256) for _ in range(rng.randrange(1, 200))))
                                 for _ in range(20)] + [(RESPONDER, MDNS_PORT, hap)])
    big = _ptrs(*[f"_{'x' * 50}{i:04d}._tcp.local" for i in range(150)])
    _mdns("bigger than a packet", [lo], [(RESPONDER, MDNS_PORT, big)])
    _mdns("port taken", [lo], [(RESPONDER, MDNS_PORT, hap)], taken=True)


def teardown_module():
    if SOCK.exists():
        SOCK.unlink()
    try:
        SOCK_DIR.rmdir()
    except OSError:
        pass
