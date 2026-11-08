"""Extra inputs for FR_OS 1.x's parse_config, run with the capture plugin
next to 1.x's own suite (reference/generate.sh).

1.x's tests check the configs a feature needs; FR_OS 2 must also match
1.x on the odd ones its parser lets through or stops: what Python's
ipaddress, datetime.fromisoformat and isinstance accept (a netmask after
the slash, a whole number for an address, true for an integer, an ISO
week date, an IPv6 scope). This module only feeds such values to
parse_config, one change at a time to a config that is otherwise
accepted; the plugin records what 1.x answered. Nothing here asserts
anything about 1.x.
"""

from __future__ import annotations

import copy

import pytest

from frfw.config import loader
from frfw.config.errors import ConfigError

KEY = "A" * 43 + "="
KEY2 = "B" * 43 + "="

BASE = {
    "version": 1,
    "hostname": "fr-router",
    "timezone": "Europe/Budapest",
    "zones": {"wan": {}, "lan": {"description": "LAN"}, "iot": {}, "vpn": {}},
    "interfaces": {
        "wan": {"device": "eth0", "zone": "wan"},
        "lan": {"device": "eth1", "zone": "lan", "address": "10.73.1.1/24"},
        "iot": {"device": "eth1.30", "zone": "iot", "address": "192.168.30.1/24",
                "vlan": {"parent": "eth1", "id": 30}},
    },
    "rules": [
        {"name": "ssh", "action": "accept", "from_zone": "lan", "to_zone": "self", "proto": "tcp", "dst_port": 22},
        {"name": "lan-out", "action": "accept", "from_zone": "lan", "to_zone": "wan"},
        {"name": "night", "action": "drop", "from_zone": "iot", "to_zone": "wan",
         "schedule": {"days": ["weekdays"], "start": "22:00", "end": "06:00"}},
        {"name": "temp", "action": "accept", "from_zone": "lan", "to_zone": "wan", "proto": "tcp",
         "dst_port": "8000-8100", "expires": "2026-12-01T18:00"},
        {"name": "by-addr", "action": "drop", "from_zone": "lan", "to_zone": "wan",
         "src_address": ["10.73.1.5/32", "2001:db8:5::/48"]},
    ],
    "nat": {"masquerade": [{"out_zone": "wan"}],
            "port_forwards": [{"name": "web", "in_zone": "wan", "proto": "tcp", "dst_port": 8443,
                               "to_address": "10.73.1.10", "to_port": 443}]},
    "dhcp": {"lan": {"range_start": "10.73.1.100", "range_end": "10.73.1.199", "dns_servers": ["10.73.1.1"],
                     "reservations": [{"mac": "AA:BB:CC:DD:EE:01", "address": "10.73.1.50", "hostname": "nas"}]}},
    "adblocker": {"enabled": True, "source_urls": ["https://example.org/hosts"], "serve_lan": True,
                  "allowlist": ["example.com"], "categories": {"social": ["https://example.org/social"]}},
    "app_control": {"enabled": True, "blocked_apps": ["tiktok"]},
    "local_dns": {"domain": "lan", "hosts": {"nas.lan": "10.73.1.50"}, "overrides": {"printer.home.arpa": "10.73.1.60"}},
    "xdp_sni_filter": {"enabled": True, "interfaces": ["lan"], "blocklist": ["bad.example"]},
    "tls_fingerprint": {"enabled": True, "blocklist": ["t13d1516h2_8daaf6152771_e5627efa2ab1",
                                                       {"fingerprint": "0" * 32, "label": "x"}]},
    "iot": {"enabled": True, "zones": ["iot"], "trusted_macs": ["aa:bb:cc:dd:ee:02"]},
    "ai_ids": {"enabled": True, "excluded_macs": ["aa:bb:cc:dd:ee:03"]},
    "ztna": {"enabled": True, "users": [{"username": "kolos", "password_hash": "pbkdf2$x"}]},
    "update": {"repo": "starsmash29/FR_OS-pblk"},
    "metrics": {"site": "budapest-office", "token_sha256": "a" * 64},
    "management": {"zones": ["lan"], "addresses": ["10.73.1.1"]},
    "wireguard": {"enabled": True, "address": "10.99.0.1/24", "endpoint": "vpn.example.org",
                  "peers": [{"name": "phone", "public_key": KEY, "address": "10.99.0.2/32"}]},
    "logging": {"drops": True, "drops_per_minute": 20},
    "ipv6": {"enabled": True, "pinholes": [{"name": "nas-https", "zone": "lan", "host": "::5054:ff:fe12:3456",
                                            "proto": "tcp", "port": 443}]},
}

DELETE = object()

# Odd values worth trying in many places.
COMMON = [None, True, False, 0, 1, -1, 1.0, 1.5, "", "x", [], {}, [1], {"a": 1}, 2**70]

IPV4 = ["10.73.1.10", "10.73.1.010", "010.73.1.10", "10.73.1", "10.73.1.256", "10.73.1.10 ", " 10.73.1.10",
        "10.73.1.10/32", "1.2.3.4.5", "١.٢.٣.٤", "0.0.0.0", "255.255.255.255", "10.73.1.+1", 167772170, True]

IFACE = ["10.73.1.1/24", "10.73.1.1/255.255.255.0", "10.73.1.1/0.0.0.255", "10.73.1.1/024", "10.73.1.1/ 24",
         "10.73.1.1/33", "10.73.1.1/-1", "10.73.1.1", "10.73.1.1/", "10.73.1.1/24/1", "10.73.1.1/255.0.255.0",
         "10.73.1.1/0", "10.73.1.1/255.255.255.255", "10.73.1.1/0.0.0.0", "10.73.1.1/+24", "10.73.1.1/٢٤"]

NETS = ["10.0.0.5/32", "10.0.0.5/24", " 10.0.0.0/8 ", "\x1c10.0.0.0/8", "10.0.0.0/255.0.0.0", "2001:db8::/32",
        "2001:db8::1/64", "2001:DB8::/32", "fe80::1%eth0/64", "fe80::%eth0/64", "fe80::1%/64", "::ffff:1.2.3.4",
        "::ffff:1.2.3.4/120", "::", "::/0", "0.0.0.0/0", "1::2::3", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8:9",
        "1:2:3:4:5:6:7::", "::1:2:3:4:5:6:7", ":1::", "1::2:", "12345::", "g::", "::1.2.3", "1:2:3:4:5:6:1.2.3.4",
        "1:2:3:4:5:6:7:1.2.3.4", "0:0:0:0:0:0:0:0", "1:0:0:2:0:0:0:3", "1:0:0:2:0:0:3:4", "2001:db8::/129",
        "2001:db8::/0x20", "10.0.0.0/8/8", "10.0.0.0", "a" * 50, ["10.0.0.0/8", "10.0.0.0/8"], [], ["10.0.0.0/8", 5]]

PORTS = [22, 0, 65535, 65536, True, False, "22", "22-22", "22-21", "0-10", "1-65535", "1-65536", "٢٢-٢٣",
         "22 -23", "022-023", "123456-1", "1-2-3", 22.0, None, [], -5]

ISO = ["2026-12-01T18:00", "2026-12-01 18:00", "2026-12-01", "20261201T1800", "2026-12-01T18", "2026-12-01T18:00:00",
       "2026-12-01T18:00:00.5", "2026-12-01T18:00:00,123456789", "2026-12-01T18:00Z", "2026-12-01T18:00+01:00",
       "2026-12-01T18:00-0530", "2026-12-01T18:00+01", "2026-12-01T18:00+24:00", "2026-12-01T18:00+1",
       "2026-W49-2T10:00", "2026W492T10", "2026-W53-1", "2020-W53-7", "2026-W00-1", "2026-W49-8",
       "2026-12-01x18:00", "2026-12-01ö18:00", "2026-12-0118:00", "2026-13-01T00:00", "2026-02-29T00:00",
       "2028-02-29T00:00", "2026-12-01T24:00", "2026-12-01T23:60", "2026-12-01T18:00:60", " 2026-12-01T18:00 ",
       "2026-12-01T18:00\n", "2026-3-29T02:30", "2026-03-29T02:30", "2026-10-25T02:30", "2026-03-29T03:00",
       "2026-10-25T03:00", "2026-10-25T01:59:59", "1970-01-01T00:00", "0001-01-01T00:00", "9999-12-31T23:59",
       "2026-12-01T18:00:00.", "2026-12-01T18:0", "2026-12-01T1800", "2026-12-01T18:0000", "2026-12-01T18:00:00Z",
       "2026-12-01T18:00:00.123Z", "2026-12-01T18:00+00:00", "2026-12-01T18:00-00:00", "2026-12-01T18:00:00+01:00:30",
       "2026-12-01T18:00:00+01:00:30.5", "202612", "2026-12", 1764612000, True]

ZONES = ["Europe/Budapest", "UTC", "Etc/GMT+5", "Local", "", "./UTC", "Europe/../UTC", "Europe", "zone.tab",
         "posixrules", "/etc/localtime", "Europe/Budapest/", "europe/budapest", "America/New_York", "Asia/Kolkata",
         "Australia/Lord_Howe", 5, None]

V6HOST = ["::5054:ff:fe12:3456", "::", "::1", "::2", "::fdff:ffff:ffff:ff80", "::fdff:ffff:ffff:ff7f",
          "2001:db8::5", "fd00::5", "fe80::5", "::ffff:1.2.3.4", "::5%eth0", "5", "", None, "2001:db8::/64"]


def _set(config, path, value):
    target = config
    for key in path[:-1]:
        target = target[key]
    if value is DELETE:
        target.pop(path[-1], None)
    else:
        target[path[-1]] = value


def _mutations():
    out = []

    def add(path, values):
        for value in values:
            out.append((path, value))

    add(("version",), [1, 1.0, True, 2, "1", None, DELETE])
    add(("hostname",), ["fr-router", "fr.router.lan", "-x", "x-", "a" * 63, "a" * 64, "a..b", "fr_router",
                        "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 61, "fr-router\n", "", 5, DELETE])
    add(("timezone",), ZONES + [DELETE])
    add(("zones",), [None, [], {"wan": None, "lan": [], "iot": {}, "vpn": {}}, {"self": {}}])
    add(("zones", "lan"), [None, [], "x", {"description": ["x"]}])
    add(("interfaces",), [{}, None, []])
    add(("interfaces", "lan", "address"), IFACE + [None, 5])
    add(("interfaces", "lan", "device"), ["eth1", "eth1\n", "-eth1", ".", "..", "a" * 15, "a" * 16, "eth 1", 5])
    add(("interfaces", "iot", "vlan"), [{"parent": "eth1", "id": 4094}, {"parent": "eth1", "id": 4095},
                                        {"parent": "eth1", "id": True}, {"parent": "eth1.30", "id": 30},
                                        {"parent": 5, "id": 30}, {"id": 30}, "eth1", None])
    add(("rules", 0, "dst_port"), PORTS)
    add(("rules", 0, "proto"), ["tcp", "udp", "icmp", "any", "TCP", None, 5, DELETE])
    add(("rules", 0, "action"), ["drop", "reject", "ACCEPT", None, ["accept"]])
    add(("rules", 0, "from_zone"), ["self", None, "nope", 5, DELETE])
    add(("rules", 0, "to_zone"), [None, "nope", 5, DELETE])
    add(("rules", 0, "name"), ["Ssh", "ssh", "lan-out", "1ssh", "s", 5])
    add(("rules", 0, "log"), [1, "yes", [], 0.0])
    add(("rules", 0, "src_mac"), ["AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee", "aa-bb-cc-dd-ee-ff", "aa:bb:cc:dd:ee:ff\n", 5])
    add(("rules", 1, "src_address"), NETS)
    add(("rules", 1, "dst_address"), ["2001:db8::/32", "10.0.0.0/8", ["10.0.0.0/8", "2001:db8::/32"]])
    add(("rules", 2, "schedule"), [
        {"days": "daily", "start": "00:00", "end": "24:00"}, {"days": ["MON", "fri"], "start": "08:00", "end": "17:00"},
        {"days": [], "start": "08:00", "end": "17:00"}, {"days": ["mon", 1], "start": "08:00", "end": "17:00"},
        {"days": ["Weekend"], "start": "24:00", "end": "08:00"}, {"start": "08:00", "end": "08:00"},
        {"start": "8:00", "end": "17:00"}, {"start": "08:00", "end": "17:00", "cut_established": True},
        {"start": "08:00", "end": "17:00", "cut_established": 1}, {"start": "08:00", "end": "17:00\n"},
        {"days": ["mon"], "start": "23:59", "end": "00:00"}, {"days": "FRİ", "start": "08:00", "end": "17:00"}, "x"])
    add(("rules", 3, "expires"), ISO)
    add(("nat", "masquerade"), [[], None, "", "wan", [{"out_zone": "self"}], [{"out_zone": None}], {"a": 1}])
    add(("nat", "port_forwards", 0, "dst_port"), [True, 0, 65535, 65536, "443", 1.0])
    add(("nat", "port_forwards", 0, "to_port"), [True, False, DELETE, 99999])
    add(("nat", "port_forwards", 0, "to_address"), IPV4)
    add(("nat", "port_forwards", 0, "proto"), ["udp", "icmp", "any", None])
    add(("dhcp", "lan", "range_start"), IPV4 + ["10.73.1.1", "10.73.1.0", "10.73.1.255", "10.73.2.1", "10.73.1.200"])
    add(("dhcp", "lan", "dns_servers"), [[], ["1.1.1.1", "1.1.1.1"], "1.1.1.1", [167772161], None])
    add(("dhcp", "lan", "lease_time"), [True, False, 0, -1, 2**63 - 1, 2**63, 2**64, 3600.0, "3600"])
    add(("dhcp", "lan", "reservations"), [None, {}, [{"mac": "aa:bb:cc:dd:ee:01", "address": "10.73.1.50"},
                                                    {"mac": "AA:BB:CC:DD:EE:01", "address": "10.73.1.51"}],
                                          [{"mac": "aa:bb:cc:dd:ee:01", "address": "10.73.1.50", "hostname": 5}]])
    add(("adblocker", "allowlist"), [["example.com\n"], ["example.com."], ["Example.COM", "example.com"], ["com"], ["com."],
                                     ["-x.com"], [5], "example.com", None])
    add(("adblocker", "source_urls"), [["http://x"], ["https://"], ["https://a b"], ["https://a\x1fb"],
                                       ["ftp://x"], ["https://x\n"], ["https:// x"], []])
    add(("adblocker", "categories"), [{"ads": ["https://x"]}, {"Social": ["https://x"]}, {"social": []}, None, []])
    add(("adblocker", "xdp_critical_limit"), [0, -1, True, 2**64, 1.0, "5"])
    add(("adblocker", "force_dns"), [True, 1])
    add(("adblocker", "serve_lan"), [False, 1])
    add(("app_control", "blocked_apps"), [["tiktok", "tiktok"], ["nope"], [], ["whatsapp", "telegram"], "tiktok"])
    add(("app_control", "block_via_xdp"), [True, 1])
    add(("local_dns", "domain"), ["lan", "LAN.", " home.arpa ", "com", "nas.lan", "-x", "", 0, 5, ["lan"]])
    add(("local_dns", "hosts"), [{"NAS.lan.": "10.73.1.50"}, {"nas": "10.73.1.50"}, {"nas.lan": "10.73.1.050"},
                                 {"printer.home.arpa": "10.73.1.60"}, {"tiktok.com": "10.73.1.5"},
                                 {"x.tiktokv.com": "10.73.1.5"}, {"nas.lan": 5}, [], None])
    add(("local_dns", "unknown"), [1])
    add(("xdp_sni_filter", "blocklist"), [["Bad.Example."], ["bad.example\n"], ["a" * 31], ["a" * 32], ["a" * 30 + "."],
                                          ["-bad.example"], ["bad..example"], [5], "bad.example"])
    add(("xdp_sni_filter", "interfaces"), [[], ["wan", "lan"], ["nope"], "lan", [5]])
    add(("tls_fingerprint", "blocklist"), [[" T13D1516H2_8DAAF6152771_E5627EFA2AB1 "], ["0" * 31], ["0" * 32, "0" * 32],
                                           [{"fingerprint": "0" * 32, "label": "x" * 81}], [{"label": "x"}], [5]])
    add(("iot", "zones"), [["wan"], ["iot", "iot"], [], ["nope"], "iot"])
    add(("iot", "isolation_mode"), ["block", "BLOCK", None, 5])
    add(("iot", "isolated_macs"), [["AA:BB:CC:DD:EE:02"], ["aa:bb:cc:dd:ee:04", "aa:bb:cc:dd:ee:04"]])
    add(("ai_ids", "quarantine_duration_seconds"), [1, 0, True, 7 * 24 * 3600, 7 * 24 * 3600 + 1, 1.0, 2**70])
    add(("ai_ids", "excluded_macs"), [["AA:BB:CC:DD:EE:03"], "x", [5]])
    add(("ztna", "session_ttl_seconds"), [59, 60, 30 * 24 * 3600, 30 * 24 * 3600 + 1, True])
    add(("ztna", "users"), [[], [{"username": "a" * 64, "password_hash": "x"}], [{"username": "a" * 65, "password_hash": "x"}],
                            [{"username": ".a", "password_hash": "x"}], [{"username": "kolos", "password_hash": ""}],
                            [{"username": "k", "password_hash": "x"}, {"username": "k", "password_hash": "y"}]])
    add(("update", "repo"), ["a/b", "a/..b", "-a/b", "a/.b", "a" * 40 + "/b", "a/b\n", "", 5])
    add(("update", "kernel_updates"), [False, 0])
    add(("metrics", "site"), ["Office", "a" * 63, "a" * 64, "office\n", None, 5])
    add(("metrics", "token_sha256"), ["A" * 64, "a" * 63, None])
    add(("management", "addresses"), [["10.73.1.1", "10.73.1.1"], ["10.99.0.1"], ["192.168.30.1"], [167848193],
                                      ["10.73.1.01"], [], None, "10.73.1.1"])
    add(("management", "zones"), [["wan"], ["iot"], ["lan", "lan"], [], None, "lan"])
    add(("management", "allow_wan"), [True, 1])
    add(("management", "confirm_apply_seconds"), [0, 59, 60, 3600, 3601, True, 300.0])
    add(("management", "ipv6"), [True, 1])
    add(("wireguard", "address"), ["10.99.0.1/30", "10.99.0.1/31", "10.99.0.0/24", "10.99.0.255/24", "10.99.0.1",
                                   "10.73.1.200/24", "10.99.0.1/255.255.255.0", 5, "", None, "10.99.0.1/0.0.0.255"])
    add(("wireguard", "peers", 0, "address"), ["10.99.0.2", 174260226, True, "10.99.0.1/32", "10.99.0.255/32",
                                               "10.99.1.2/32", "10.99.0.2/31", None, "10.99.0.2/255.255.255.255"])
    add(("wireguard", "peers", 0, "public_key"), [KEY2, "A" * 44, "A" * 42 + "==", "A" * 42 + "A=", "A" * 43,
                                                  "A" * 42 + "\n=", "Á" * 43 + "=", 5])
    add(("wireguard", "peers"), [[{"name": "a", "public_key": KEY, "address": "10.99.0.2/32"},
                                  {"name": "b", "public_key": KEY, "address": "10.99.0.3/32"}],
                                 [{"name": "a", "public_key": KEY, "address": "10.99.0.2/32"},
                                  {"name": "b", "public_key": KEY2, "address": "10.99.0.2/32"}],
                                 [{"name": ".a", "public_key": KEY, "address": "10.99.0.2/32"}], {}, None])
    add(("wireguard", "zone"), ["wan", "lan", "nope", None, 5])
    add(("wireguard", "enabled"), [False, 1])
    add(("wireguard", "endpoint"), ["1.2.3.4", "-x", 5, ""])
    add(("wireguard", "private_key"), ["x"])
    add(("wireguard", "listen_port"), [0, 65535, True, 51820.0])
    add(("logging", "drops_per_minute"), [0, 10000, 10001, True])
    add(("ipv6", "enabled"), [False, 1])
    add(("ipv6", "ula_prefix"), ["fd12:3456:789a::/48", "fd00::/48", "fc00::/48", "fd12:3456:789a::1/48",
                                 "fd12:3456:789a::/56", "fd12:3456:789a::%x/48", "FD12:3456:789A::/48", 5, None])
    add(("ipv6", "lan_zones"), [["lan"], ["wan"], ["lan", "lan"], ["nope"], ["vpn"], [], "lan", [5]])
    add(("ipv6", "pinholes", 0, "host"), V6HOST)
    add(("ipv6", "pinholes", 0, "port"), PORTS + ["1-1000", "1-1001"])
    add(("ipv6", "pinholes", 0, "from"), ["2001:db8:42::/48", "2001:db8:42::1/48", "fd00::/8", "fe80::/10", "fe80::/9",
                                          "ff00::/8", "::/0", "2001:db8::%x/48", "10.0.0.0/8", 5])
    add(("ipv6", "pinholes", 0, "zone"), ["wan", "nope", "iot", 5])
    add(("ipv6", "pinholes", 0, "extra"), [1])
    add(("ipv6", "extra"), [1])
    for section in ("nat", "dhcp", "adblocker", "app_control", "local_dns", "xdp_sni_filter", "tls_fingerprint",
                    "iot", "ai_ids", "ztna", "update", "metrics", "management", "wireguard", "logging", "ipv6",
                    "pqc", "rules"):
        add((section,), COMMON + [DELETE])
    return out


MUTATIONS = _mutations()


@pytest.mark.parametrize("index", range(len(MUTATIONS)))
def test_parse_config_edge_case(index):
    path, value = MUTATIONS[index]
    config = copy.deepcopy(BASE)
    _set(config, path, value)
    try:
        loader.parse_config(config)
    except (ConfigError, Exception):  # recorded by the plugin, or not a ConfigError at all
        pass
