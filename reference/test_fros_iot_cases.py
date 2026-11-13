"""FR_OS 1.x's IoT discovery (frfw.iot, phase 14) fed every shape of
input, recorded for FR_OS 2's crates/fros-iot (iot.jsonl;
reference/generate.sh runs this module).

Recorded:

- MAC addresses normalized, vendor lookups, and the IEEE registry CSV
  read in every shape (quoting, line ends, damage): which prefixes it
  kept, or the exception;
- the kernel's neighbour table (/proc/net/arp) read in every shape;
- the mDNS query 1.x sends and its parser fed responses built from RFC
  6762/6763 structures, then damaged, truncated and randomized (pointer
  loops, long names, too many records);
- the "is this IoT?" scoring of seeded observations;
- whole scans (`run_scan`) with every input injected: the sensor's view
  of the config, the helper's lease and isolation answers, the mDNS
  results, the ARP and OUI files; the messages, the devices and the
  inventory file 1.x writes, byte for byte; and `resync_from_inventory`.

The config a scan reads is recorded as the "view" FR_OS 2's Go side
will hand the Rust scanner (one JSON object, decided in phase 4c): the
IoT zones' interfaces in config order with their address, the trusted
and isolated MACs, auto_isolate and the isolation mode. The scans here
take a fake config built from that view, so the view is all they read.

Nothing here asserts anything about 1.x.
"""

from __future__ import annotations

import json
import random
import struct
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

from frfw.helper.client import HelperError
from frfw.iot import mdns, scanner
from frfw.iot.arp import read_arp_table
from frfw.iot.classify import Observation, classify
from frfw.iot.mdns import MdnsError, build_query, parse_services
from frfw.iot.oui import load_vendor_db, normalize_mac, vendor_for

T0 = 1_700_000_000.0
TMP = Path(tempfile.mkdtemp(prefix="fros-iot-cases-"))


def _record(case: dict) -> None:
    capture = sys.modules.get("fros_capture")
    if capture is not None:
        capture._record("iot", case)


def _file(name: str, data: bytes) -> Path:
    path = TMP / name
    path.write_bytes(data)
    return path


# --- MAC addresses and vendors ----------------------------------------------------------------


def test_macs():
    values = ["aa:bb:cc:dd:ee:ff", "AA:BB:CC:DD:EE:FF", "AA-BB-CC-DD-EE-FF", " aa:bb:cc:dd:ee:ff\n",
              "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:ff:00", "aabb.ccdd.eeff", "aa:bb:cc:dd:ee:fg", "", "::::::",
              "a:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff\n", "aa:bb:cc:dd:ee:ff\x1c", "\u3000aa:bb:cc:dd:ee:ff",
              "AA:BB:CC:DD:EE:F\u212a", "\uff21A:bb:cc:dd:ee:ff", "aa-bb:cc-dd:ee-ff", "aa:bb:cc:dd:ee:-f",
              "00:00:00:00:00:00", "02:00:00:00:00:01", "aa_bb_cc_dd_ee_ff", None, 5, ["aa:bb:cc:dd:ee:ff"]]
    for value in values:
        _record({"op": "mac", "input": value, "mac": normalize_mac(value)})
    db = {"240AC4": "Espressif Inc.", "001122": "Cimsys Inc", "FCFFFF": "x"}
    for mac in ["24:0a:c4:11:22:33", "26:0a:c4:11:22:33", "00:11:22:33:44:55", "02:11:22:33:44:55",
                "fc:ff:ff:00:00:00", "fe:ff:ff:00:00:00", "ff:ff:ff:ff:ff:ff", "aa:bb:cc:dd:ee:ff"]:
        _record({"op": "vendor", "mac": mac, "db": db, "vendor": vendor_for(mac, db)})


def _oui_case(name: str, data: bytes) -> None:
    case = {"op": "oui", "name": name, "file": data.hex()}
    try:
        db = load_vendor_db(_file("oui.csv", data))
    except Exception as exc:  # 1.x catches OSError only
        case["crash"] = type(exc).__name__
    else:
        case["db"] = [[k, v] for k, v in db.items()]
    _record(case)


def test_oui():
    header = b"Registry,Assignment,Organization Name,Organization Address\n"
    good = (header + b'MA-L,240AC4,Espressif Inc.,"Room 204, Building 2, Shanghai"\n'
            b"MA-L,001122,CIMSYS Inc,KR\nMA-M,0011223,Small,US\nMA-S,001122334,Tiny,US\n"
            b'MA-L,fcffff,"Quoted ""Name"" Ltd",DE\n')
    _oui_case("good", good)
    shapes = {
        "empty": b"",
        "header only": header,
        "crlf": good.replace(b"\n", b"\r\n"),
        "cr": good.replace(b"\n", b"\r"),
        "no final newline": good.rstrip(b"\n"),
        "blank lines": b"\n\n" + good + b"\n\n",
        "short rows": b"MA-L\nMA-L,240AC4\nMA-L,240AC4,\n,,,\n",
        "padded": b"MA-L, 240ac4 ,  Espressif  ,x\nMA-L,240AC,Short,x\nMA-L,240AC4C,Long,x\n",
        "repeat prefix": b"MA-L,240AC4,First,x\nMA-L,001122,Other,x\nMA-L,240AC4,Second,x\n",
        "quoted newline": b'MA-L,240AC4,"Line\nBreak",x\nMA-L,001122,"CR\r\nLF",x\n',
        "quote in field": b'MA-L,240AC4,Espr"essif,x\nMA-L,001122,"Ab"cd,x\nMA-L,AABBCC,"open,x\n',
        "unterminated quote": b'MA-L,240AC4,"never closed\nMA-L,001122,Next,x\n',
        "quote at end": b'MA-L,240AC4,"quoted"',
        "lowercase registry": b"ma-l,240AC4,Nope,x\n",
        "non-ascii": "MA-L,240AC4,Espressif \u00e9\u4e2d\u6587,x\n".encode(),
        "bad utf-8": b"MA-L,240AC4,Bad \xff\xfe\xc3 utf8,x\nMA-L,001122,\xe2\x82,x\n",
        "nul": b"MA-L,240AC4,Nul\x00here,x\nMA-L,001122,After,x\n",
        "unicode prefix": "MA-L,\uff12\uff14\uff10AC4,Wide,x\n".encode(),
        "huge field": b"MA-L,240AC4," + b"x" * 140000 + b",x\n",
        "huge quoted field": b'MA-L,240AC4,"' + b"x" * 140000 + b'",x\n',
        "field at limit": b"MA-L,240AC4," + b"x" * 131072 + b",x\n",
        "field over limit": b"MA-L,240AC4," + b"x" * 131073 + b",x\n",
        "cr in field": b"MA-L,240AC4,a\rb,x\n",
        "lone cr then lf": b"MA-L,240AC4,a\r\nMA-L,001122,b\n",
        "space after quote": b'MA-L,240AC4,"q" ,x\n',
        "quote after text": b'MA-L,240AC4,ab"c"d,x\n',
        "vt and ff": b"MA-L,240AC4,a\x0bb\x0cc,x\n",
        "unicode line separators": "MA-L,240AC4,a\u2028b\u0085c,x\n".encode(),
    }
    for name, data in shapes.items():
        _oui_case(name, data)
    rng = random.Random(14)
    for i in range(80):
        data = bytearray(good)
        for _ in range(rng.randint(1, 5)):
            data[rng.randrange(len(data))] = rng.choice(b'",\n\r\x00 aM-L0\xff')
        _oui_case(f"damaged {i}", bytes(data))
    case = {"op": "oui", "name": "missing", "path": str(TMP / "no-such-oui.csv"),
            "db": [[k, v] for k, v in load_vendor_db(TMP / "no-such-oui.csv").items()]}
    _record(case)


# --- the neighbour table ------------------------------------------------------------------------


ARP_HEADER = "IP address       HW type     Flags       HW address            Mask     Device\n"


def _arp_case(name: str, data: bytes) -> None:
    case = {"op": "arp", "name": name, "file": data.hex()}
    try:
        entries = read_arp_table(_file("arp", data))
    except Exception as exc:
        case["crash"] = type(exc).__name__
    else:
        case["entries"] = [[e.ip, e.mac, e.device] for e in entries]
    _record(case)


def test_arp():
    good = (ARP_HEADER +
            "10.0.0.50        0x1         0x2         24:0a:c4:11:22:33     *        eth1\n"
            "10.0.0.51        0x1         0x0         00:00:00:00:00:00     *        eth1\n"
            "10.0.0.52        0x1         0x6         AA:BB:CC:DD:EE:FF     *        eth1\n"
            "10.9.0.6         0x1         0x2         00:11:22:33:44:88     *        eth2\n")
    _arp_case("good", good.encode())
    rows = ["10.0.0.1 0x1 0x2 aa:bb:cc:dd:ee:ff * eth1", "10.0.0.1 0x1 0x2 aa:bb:cc:dd:ee:ff *",
            "10.0.0.1 0x1 2 aa:bb:cc:dd:ee:ff * eth1", "10.0.0.1 0x1 0X2 aa:bb:cc:dd:ee:ff * eth1",
            "10.0.0.1 0x1 0x_2 aa:bb:cc:dd:ee:ff * eth1", "10.0.0.1 0x1 -0x2 aa:bb:cc:dd:ee:ff * eth1",
            "10.0.0.1 0x1 -0x1 aa:bb:cc:dd:ee:ff * eth1", "10.0.0.1 0x1 +3 aa:bb:cc:dd:ee:ff * eth1",
            "10.0.0.1 0x1 zz aa:bb:cc:dd:ee:ff * eth1", "10.0.0.1 0x1 0x aa:bb:cc:dd:ee:ff * eth1",
            "10.0.0.1 0x1 0xffffffffffffffffffffffffffffff aa:bb:cc:dd:ee:ff * eth1",
            "10.0.0.1 0x1 \u0662 aa:bb:cc:dd:ee:ff * eth1", "10.0.0.1 0x1 1_0 aa:bb:cc:dd:ee:ff * eth1",
            "10.0.0.1 0x1 0x2 00:00:00:00:00:00 * eth1", "10.0.0.1 0x1 0x2 aa-bb-cc-dd-ee-ff * eth1",
            "10.0.0.1 0x1 0x2 aa:bb:cc:dd:ee * eth1", "10.0.0.1\t0x1\t0x2\taa:bb:cc:dd:ee:ff\t*\teth1\textra",
            "x y 0x2 aa:bb:cc:dd:ee:ff * eth1", "10.0.0.1 0x1 0x2 aa:bb:cc:dd:ee:ff * eth\u00e91",
            "10.0.0.1\x1c0x1\x1c0x2\x1caa:bb:cc:dd:ee:ff\x1c*\x1ceth1",
            "10.0.0.1\u30000x1 0x2 aa:bb:cc:dd:ee:ff * eth1", ""]
    for i, row in enumerate(rows):
        _arp_case(f"row {i}", (ARP_HEADER + row + "\n").encode())
        _arp_case(f"row {i} no header", (row + "\n").encode())
    for name, data in {"empty": b"", "header only": ARP_HEADER.encode(),
                       "crlf": good.replace("\n", "\r\n").encode(), "cr": good.replace("\n", "\r").encode(),
                       "vt lines": good.replace("\n", "\x0b").encode(),
                       "unicode lines": good.replace("\n", "\u2028").encode(),
                       "fs lines": good.replace("\n", "\x1c").encode(),
                       "bad utf-8": good.encode() + b"10.0.0.9 0x1 0x2 aa:bb:cc:dd:ee:01 * \xff\n"}.items():
        _arp_case(name, data)
    _record({"op": "arp", "name": "missing", "path": str(TMP / "no-such-arp"),
             "entries": [[e.ip, e.mac, e.device] for e in read_arp_table(TMP / "no-such-arp")]})


# --- mDNS --------------------------------------------------------------------------------------


def _name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        raw = label.encode()
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _rr(owner: bytes, rtype: int, rdata: bytes, rclass: int = 0x8001, ttl: int = 4500) -> bytes:
    return owner + struct.pack("!HHIH", rtype, rclass, ttl, len(rdata)) + rdata


def _response(answers: list[bytes], *, flags: int = 0x8400, questions: list[bytes] = (), extra: int = 0,
              counts: tuple | None = None) -> bytes:
    qd, an = len(questions), len(answers)
    if counts is not None:
        qd, an, ns, ar = counts
    else:
        ns, ar = 0, extra
    return struct.pack("!HHHHHH", 0, flags, qd, an, ns, ar) + b"".join(questions) + b"".join(answers)


def _packets() -> dict[str, bytes]:
    meta = _name("_services._dns-sd._udp.local")
    ptr = lambda target: _rr(meta, 12, _name(target))
    p = {
        "one service": _response([ptr("_hap._tcp.local")]),
        "several": _response([ptr("_hap._tcp.local"), ptr("_googlecast._tcp.local"), ptr("_matter._tcp.local")]),
        "query not response": _response([ptr("_hap._tcp.local")], flags=0),
        "instance enumeration": _response([_rr(_name("_hap._tcp.local"), 12, _name("Lamp._hap._tcp.local"))]),
        "upper case": _response([ptr("_HAP._TCP.LOCAL")]),
        "upper meta": _response([_rr(_name("_SERVICES._DNS-SD._UDP.LOCAL"), 12, _name("_ipp._tcp.local"))]),
        "no local": _response([ptr("_hap._tcp")]),
        "not a service": _response([ptr("hap._tcp.local"), ptr("_hap._sctp.local"), ptr("_-x._tcp.local"),
                                    ptr("_a._tcp.local"), ptr("_" + "a" * 63 + "._tcp.local"),
                                    ptr("_" + "a" * 64 + "._tcp.local"), ptr("_x_y._tcp.local"),
                                    ptr("_x._tcp.local.local"), ptr("a._b._tcp.local")]),
        "non-ascii": _response([ptr("_h\u00e9p._tcp.local")]),
        "a records": _response([_rr(_name("lamp.local"), 1, b"\x0a\x00\x00\x05"), ptr("_hap._tcp.local")]),
        "compressed target": _response([meta + struct.pack("!HHIH", 12, 1, 120, 2) + b"\xc0\x0c"]),
        "with question": _response([ptr("_hap._tcp.local")], questions=[meta + b"\x00\x0c\x00\x01"]),
        "header only": _response([]),
        "short header": b"\x00\x00\x84",
        "empty": b"",
        "too many records": _response([ptr("_hap._tcp.local")], counts=(0, 1, 0, 256)),
        "just enough records": _response([ptr("_hap._tcp.local")], counts=(0, 1, 0, 254)),
        "truncated rr": _response([ptr("_hap._tcp.local")])[:-3],
        "rdata past end": _response([meta + struct.pack("!HHIH", 12, 1, 120, 200) + _name("_hap._tcp.local")]),
        "label past end": b"\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00\x3f_hap",
        "pointer loop": b"\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00\xc0\x0c",
        "pointer chain": b"\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00" +
                         b"".join(struct.pack("!H", 0xC000 | (14 + 2 * i)) for i in range(40)) + b"\x00",
        "truncated pointer": b"\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00\xc0",
        "label type 0x40": b"\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00\x40",
        "label type 0x80": b"\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00\x80",
        "name too long": _response([_rr(b"".join(bytes([63]) + b"a" * 63 for _ in range(4)) + b"\x00", 12,
                                        _name("_hap._tcp.local"))]),
        "name at 255": _response([_rr(b"".join(bytes([62]) + b"a" * 62 for _ in range(4)) + b"\x02ab\x00", 12,
                                      _name("_hap._tcp.local")), ptr("_hap._tcp.local")]),
        "trailing garbage": _response([ptr("_hap._tcp.local")]) + b"\xff\xff\xff",
        "fewer records than counted": _response([ptr("_hap._tcp.local")], counts=(0, 3, 0, 0)),
        "bad then good": _response([ptr("_hap._tcp.local"), b"\xc0"], counts=(0, 2, 0, 0)),
        "rdata pointing forward": _response([meta + struct.pack("!HHIH", 12, 1, 120, 2) + b"\xc0\x30"] +
                                            [b"\x00" * 20 + _name("_hap._tcp.local")], counts=(0, 1, 0, 0)),
    }
    return p


def test_mdns():
    for query_id in (0, 1, 0x1234, 0xFFFF):
        _record({"op": "mdns_query", "query_id": query_id, "packet": build_query(query_id=query_id).hex()})
    packets = _packets()
    rng = random.Random(6762)
    base = packets["several"]
    for i in range(600):
        data = bytearray(base)
        for _ in range(rng.randint(1, 6)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        if rng.random() < 0.2:
            data = data[: rng.randrange(len(data) + 1)]
        packets[f"damaged {i}"] = bytes(data)
    for i in range(200):
        packets[f"random {i}"] = bytes(rng.randrange(256) for _ in range(rng.randint(0, 120)))
    for name, packet in packets.items():
        _record({"op": "mdns", "name": name, "packet": packet.hex(), "services": sorted(parse_services(packet))})


# --- classification ---------------------------------------------------------------------------


def _observation_dict(o: Observation) -> dict:
    return {"mac": o.mac, "ip": o.ip, "hostname": o.hostname, "interface": o.interface, "vendor": o.vendor,
            "services": list(o.services)}


def test_classify():
    rng = random.Random(1414)
    vendors = [None, "", "Espressif Inc.", "ESPRESSIF", "Tuya Smart Inc.", "Signify B.V.", "Amazon Technologies Inc.",
               "Google, Inc.", "Apple, Inc.", "Intel Corporate", "Raspberry Pi Trading Ltd", "Ring LLC",
               "Bring LLC", "TP-LINK TECHNOLOGIES CO.,LTD.", "Caf\u00e9 Espressif", "ESPRESS\u0130F"]
    services = ["_hap._tcp", "_hap._udp", "_googlecast._tcp", "_ipp._tcp", "_workstation._tcp", "_ssh._tcp",
                "_companion-link._tcp", "_http._tcp", "_matter._tcp", "_smb._tcp", "_printer._tcp"]
    hostnames = ["", "esp_112233", "ESP-ABC", "tasmota-1", "living-room-camera", "DESKTOP-ABC", "kolos-iphone",
                 "android-1234", "my-pc", "printer-pc", "\u0130phone", "Galaxy-S", "x" * 30, "esp\u00e9"]
    macs = ["24:0a:c4:11:22:33", "3a:11:22:33:44:55", "00:11:22:33:44:66", "02:00:00:00:00:01", "ff:ff:ff:ff:ff:ff"]
    observations = []
    for _ in range(800):
        observations.append(Observation(
            mac=rng.choice(macs), ip=None, hostname=rng.choice(hostnames), interface="eth1",
            vendor=rng.choice(vendors), services=tuple(sorted(set(rng.sample(services, rng.randint(0, 4)))))))
    for o in observations:
        c = classify(o)
        _record({"op": "classify", "observation": _observation_dict(o), "category": c.category, "score": c.score,
                 "reasons": list(c.reasons)})


# --- whole scans -------------------------------------------------------------------------------


ESP = "24:0a:c4:11:22:33"
LAPTOP = "3a:11:22:33:44:55"
STATIC = "00:11:22:33:44:66"
OUI = b"Registry,Assignment,Organization Name,Organization Address\nMA-L,240AC4,Espressif Inc.,CN\n"
ARP = (ARP_HEADER +
       "10.0.0.60        0x1         0x2         00:11:22:33:44:66     *        eth1\n"
       "10.0.0.50        0x1         0x2         24:0a:c4:11:22:33     *        eth1\n"
       "10.9.0.6         0x1         0x2         00:11:22:33:44:88     *        eth2\n"
       "10.0.0.70        0x1         0x2         00:11:22:33:44:99     *        eth3\n")
VIEW = {"enabled": True,
        "interfaces": [{"device": "eth1", "address": "10.0.0.1/24"}, {"device": "eth3", "address": None}],
        "trusted_macs": [], "isolated_macs": [], "auto_isolate": False, "isolation_mode": "internet_only"}


def _config(view: dict) -> SimpleNamespace:
    interfaces = {f"if{i}": SimpleNamespace(device=i_["device"], address=i_["address"], zone="iot")
                  for i, i_ in enumerate(view["interfaces"])}
    iot = SimpleNamespace(enabled=view["enabled"], zones=["iot"], trusted_macs=list(view["trusted_macs"]),
                          isolated_macs=list(view["isolated_macs"]), auto_isolate=view["auto_isolate"],
                          isolation_mode=SimpleNamespace(value=view["isolation_mode"]))
    return SimpleNamespace(interfaces=interfaces, iot=iot)


def _answer(spec):
    """A recorded helper/mDNS answer: {"raise": text} raises, anything else is returned."""
    def call(*args, **kwargs):
        if isinstance(spec, dict) and "raise" in spec:
            raise spec["error_type"](spec["raise"]) if "error_type" in spec else HelperError(spec["raise"])
        return spec
    return call


def _scan_case(name: str, *, view=VIEW, leases=None, mdns_results=None, sync=None, arp=ARP.encode(),
               oui: bytes | None = OUI, now: float = T0) -> None:
    leases = {"ok": True, "leases": []} if leases is None else leases
    mdns_results = {} if mdns_results is None else mdns_results
    sync_calls = []

    def sync_fn(macs):
        sync_calls.append(list(macs))
        if sync is None:
            return {"ok": True, "isolated": list(macs)}
        return _answer(sync)()

    def mdns_fn(addresses):
        if isinstance(mdns_results, dict) and "raise" in mdns_results:
            raise MdnsError(mdns_results["raise"])
        return {ip: set(s) for ip, s in mdns_results.items()}

    arp_path = _file("scan-arp", arp)
    oui_path = _file("scan-oui.csv", oui) if oui is not None else TMP / "no-oui.csv"
    state_path = TMP / "inventory.json"
    if state_path.exists():
        state_path.unlink()
    result = scanner.run_scan(_config(view), leases_fn=_answer(leases), sync_fn=sync_fn, mdns_fn=mdns_fn,
                              arp_path=arp_path, oui_path=oui_path, state_path=state_path, now=now)
    _record({"op": "scan", "name": name, "view": view, "leases": leases, "mdns": mdns_results,
             "sync": sync, "arp": arp.hex(), "oui": None if oui is None else oui.hex(),
             "oui_path": str(oui_path), "now": now, "sync_calls": sync_calls, "messages": result.messages,
             "isolated": result.isolated, "devices": result.devices,
             "state": state_path.read_text() if state_path.exists() else None})


def test_scan():
    leases = {"ok": True, "leases": [
        {"ip": "10.0.0.50", "mac": ESP, "hostname": "esp_112233", "expire": 1},
        {"ip": "10.0.0.80", "mac": LAPTOP, "hostname": "kolos-iphone"},
        {"ip": "10.9.0.5", "mac": "00:11:22:33:44:77", "hostname": "guest-phone"},
    ]}
    mdns_ok = {"10.0.0.50": ["_esphomelib._tcp", "_http._tcp"], "10.0.0.80": ["_companion-link._tcp"],
               "10.0.0.99": ["_hap._tcp"], "10.0.0.98": ["_ipp._tcp"]}
    _scan_case("disabled", view=dict(VIEW, enabled=False))
    _scan_case("empty")
    _scan_case("typical", leases=leases, mdns_results=mdns_ok)
    _scan_case("auto isolate", view=dict(VIEW, auto_isolate=True), leases=leases, mdns_results=mdns_ok)
    _scan_case("block mode", view=dict(VIEW, auto_isolate=True, isolation_mode="block"), leases=leases,
               mdns_results=mdns_ok)
    _scan_case("trusted wins", view=dict(VIEW, auto_isolate=True, trusted_macs=[ESP], isolated_macs=[ESP, STATIC]),
               leases=leases, mdns_results=mdns_ok)
    _scan_case("manual isolated", view=dict(VIEW, isolated_macs=["00:11:22:33:44:66", "aa:aa:aa:aa:aa:aa"]),
               leases=leases)
    _scan_case("leases refused", leases={"ok": False, "message": "no lease file"}, mdns_results=mdns_ok)
    _scan_case("leases refused, odd message", leases={"ok": False, "message": ["a", 1]})
    _scan_case("leases refused, no message", leases={"ok": False})
    _scan_case("leases helper down", leases={"raise": "cannot connect to /run/fr_os/helper.sock"})
    _scan_case("leases ok but none", leases={"ok": True, "leases": None})
    _scan_case("leases ok but missing", leases={"ok": True})
    _scan_case("leases odd ok", leases={"ok": 1, "leases": leases["leases"]})
    _scan_case("mdns error", leases=leases, mdns_results={"raise": "cannot bind UDP port 5354"})
    _scan_case("no static address", view=dict(VIEW, interfaces=[{"device": "eth1", "address": None}]),
               leases=leases)
    _scan_case("no interfaces", view=dict(VIEW, interfaces=[]), leases=leases)
    _scan_case("two zones", view=dict(VIEW, interfaces=[{"device": "eth1", "address": "10.0.0.1/24"},
                                                         {"device": "eth2", "address": "10.9.0.1/16"}]),
               leases=leases, mdns_results=mdns_ok)
    _scan_case("no oui file", leases=leases, oui=None)
    _scan_case("sync refused", view=dict(VIEW, auto_isolate=True), leases=leases, mdns_results=mdns_ok,
               sync={"ok": False, "message": "nft failed"})
    _scan_case("sync helper down", view=dict(VIEW, auto_isolate=True), leases=leases, mdns_results=mdns_ok,
               sync={"raise": "helper timed out"})
    _scan_case("sync returns other set", view=dict(VIEW, auto_isolate=True), leases=leases, mdns_results=mdns_ok,
               sync={"ok": True, "isolated": ["ff:ff:ff:ff:ff:ff", ESP]})
    _scan_case("sync ok without list", view=dict(VIEW, auto_isolate=True), leases=leases, sync={"ok": True})
    odd = {"ok": True, "leases": [
        {"ip": "10.0.0.51", "mac": "24-0A-C4-00-00-01", "hostname": None},
        {"ip": "10.0.0.52", "mac": 5, "hostname": "x"},
        {"ip": 5, "mac": "24:0a:c4:00:00:02"},
        {"ip": "10.0.0.256", "mac": "24:0a:c4:00:00:03"},
        {"ip": "10.0.0.053", "mac": "24:0a:c4:00:00:04"},
        {"ip": " 10.0.0.54", "mac": "24:0a:c4:00:00:05"},
        {"ip": "10.0.0.55", "mac": "24:0a:c4:00:00:06", "hostname": ["a", 1]},
        {"ip": "10.0.0.56", "mac": "24:0a:c4:00:00:07", "hostname": 0},
        {"ip": "10.0.0.57", "mac": "24:0a:c4:00:00:08", "hostname": 12.5},
        {"ip": "10.0.0.58", "mac": ESP, "hostname": "later lease for the same mac"},
        {"ip": "10.0.0.0", "mac": "24:0a:c4:00:00:09"},
        {"ip": "10.0.0.255", "mac": "24:0a:c4:00:00:0a"},
        {"mac": "24:0a:c4:00:00:0b"},
        {"ip": "10.0.0.59"},
        {"ip": "\u0661\u0660.0.0.60", "mac": "24:0a:c4:00:00:0c"},
        {"ip": "10.0.0.61/32", "mac": "24:0a:c4:00:00:0d"},
        {"ip": "10.0.0.62", "mac": "24:0a:c4:00:00:0e", "hostname": "\u00e9\u0130 {x} 'q'"},
    ]}
    _scan_case("odd leases", leases=odd, mdns_results={"10.0.0.51": ["_hap._tcp"], "10.0.0.58": ["_ipp._tcp"]})
    _scan_case("arp only", arp=ARP.encode(), mdns_results={"10.0.0.60": ["_workstation._tcp"]})
    _scan_case("arp and lease disagree", leases={"ok": True, "leases": [{"ip": "10.0.0.66", "mac": STATIC}]})
    _scan_case("float now", leases=leases, now=T0 + 0.999)
    _scan_case("many devices", view=dict(VIEW, auto_isolate=True), leases={"ok": True, "leases": [
        {"ip": f"10.0.0.{i}", "mac": f"24:0a:c4:00:01:{i:02x}", "hostname": f"dev{i}"} for i in range(2, 60)]},
        mdns_results={f"10.0.0.{i}": ["_hap._tcp"] for i in range(2, 60, 3)})
    rng = random.Random(1415)
    for i in range(40):
        n = rng.randint(0, 12)
        ls = [{"ip": f"10.0.0.{rng.randint(1, 254)}", "mac": f"{rng.choice(['24:0a:c4', '3a:11:22', '00:11:22'])}"
               f":{rng.randrange(256):02x}:{rng.randrange(256):02x}:{rng.randrange(4):02x}",
               "hostname": rng.choice(["", "esp_1", "iphone", "camera", "pc"])} for _ in range(n)]
        md = {l["ip"]: rng.sample(["_hap._tcp", "_ssh._tcp", "_ipp._tcp", "_http._tcp"], rng.randint(0, 2))
              for l in ls if rng.random() < 0.5}
        view = dict(VIEW, auto_isolate=rng.random() < 0.5,
                    trusted_macs=[l["mac"] for l in ls if rng.random() < 0.1],
                    isolated_macs=[l["mac"] for l in ls if rng.random() < 0.1])
        _scan_case(f"random {i}", view=view, leases={"ok": True, "leases": ls}, mdns_results=md)


def test_resync():
    view = dict(VIEW, auto_isolate=True, trusted_macs=[STATIC], isolated_macs=["aa:aa:aa:aa:aa:aa"])
    inventories = {
        "none": None,
        "empty": {},
        "typical": {"devices": [{"mac": ESP, "category": "iot"}, {"mac": STATIC, "category": "iot"},
                                {"mac": LAPTOP, "category": "general"}]},
        "odd macs": {"devices": [{"mac": "24-0A-C4-11-22-33", "category": "iot"}, {"mac": 5, "category": "iot"},
                                 {"category": "iot"}, {"mac": "x", "category": "iot"}]},
        "odd categories": {"devices": [{"mac": ESP, "category": ["iot"]}, {"mac": LAPTOP, "category": None},
                                       {"mac": "00:11:22:33:44:01"}, {"mac": "00:11:22:33:44:02", "category": "IOT"}]},
        "devices not a list": {"devices": "abc"},
        "devices a dict": {"devices": {"a": 1}},
        "device not a dict": {"devices": [ESP]},
    }
    for name, inventory in inventories.items():
        for auto in (True, False):
            v = dict(view, auto_isolate=auto)
            calls = []

            def sync_fn(macs):
                calls.append(list(macs))
                return {"ok": True, "isolated": list(macs)}

            case = {"op": "resync", "name": f"{name} auto={auto}", "view": v, "inventory": inventory}
            try:
                case["reply"] = scanner.resync_from_inventory(_config(v), inventory, sync_fn=sync_fn)
                case["sync_calls"] = calls
            except Exception as exc:
                case["crash"] = type(exc).__name__
            _record(case)
