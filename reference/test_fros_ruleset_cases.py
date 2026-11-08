"""Extra inputs for FR_OS 1.x's build_ruleset, run with the capture
plugin after 1.x's own suite and the edge-case modules
(reference/generate.sh lists this module last).

1.x's tests build rulesets from a few dozen configs. FR_OS 2 must give
the same script for every config 1.x accepts, so this module builds one
from each config the run so far saw accepted (1.x's suite and
test_fros_edge_cases.py), again at a later moment when a rule expires,
and with other clocks when a rule has a schedule. It adds rules with
schedules of every shape (days, windows past midnight, "24:00") under
clocks with odd offsets and a kernel zone of its own, where the cuts at
the two midnights fall, and runtime members of every set. The plugin
records what 1.x built. Nothing here asserts anything about 1.x.
"""

from __future__ import annotations

import copy
import random
import sys

import pytest

from frfw.config import loader
from frfw.nft import builder
from frfw.nft.schedule import ScheduleClock

#: Later than every expiry the configs here carry (2027-01-15).
LATER = 1800000000.0

#: (utc_offset_minutes, kernel_minuteswest): zones from UTC-12 to UTC+14,
#: half and quarter hours, and a kernel zone that differs from the
#: configured one (systemd sets it when the RTC keeps local time).
CLOCKS = [(0, 0), (60, 0), (120, -120), (60, -60), (-300, 300), (-240, 300), (330, 0), (345, -345),
          (-570, 570), (840, -840), (-720, 0), (120, 0), (0, -120), (630, -600), (-180, 0)]


def _accepted_configs() -> list:
    capture = sys.modules.get("fros_capture")
    if capture is None:
        return []
    return [case["input"] for _, case in sorted(capture._cases["config"].items()) if case["ok"]]


def _build(raw, **kwargs) -> None:
    try:
        config = loader.parse_config(copy.deepcopy(raw))
        builder.build_ruleset(config, **kwargs)
    except Exception:  # recorded by the plugin when 1.x answered; a crash is not
        pass


def test_every_accepted_config():
    rng = random.Random(1)
    for raw in _accepted_configs():
        _build(raw)
        rules = raw.get("rules") if isinstance(raw, dict) else None
        rules = rules if isinstance(rules, list) else []
        if any(isinstance(r, dict) and r.get("expires") is not None for r in rules):
            _build(raw, now=LATER)
        if any(isinstance(r, dict) and r.get("schedule") is not None for r in rules):
            for offset, west in rng.sample(CLOCKS, 3):
                _build(raw, clock=ScheduleClock(offset, west))


BASE = {
    "version": 1,
    "hostname": "fr-router",
    "zones": {"wan": {}, "lan": {}, "guest": {}},
    "interfaces": {
        "wan": {"device": "eth0", "zone": "wan"},
        "lan": {"device": "eth1", "zone": "lan", "address": "10.73.1.1/24"},
        "guest": {"device": "eth2", "zone": "guest", "address": "10.73.2.1/24"},
    },
    "rules": [{"name": "lan-out", "action": "accept", "from_zone": "lan", "to_zone": "wan"}],
    "nat": {"masquerade": [{"out_zone": "wan"}]},
}

DAY_KEYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
DAY_WORDS = [["weekdays"], ["weekend"], ["daily"], ["weekdays", "sat"], ["weekend", "mon"]]


def _schedule(rng: random.Random) -> dict:
    if rng.random() < 0.3:
        days = rng.choice(DAY_WORDS)
    else:
        days = rng.sample(DAY_KEYS, rng.randint(1, 7))
    minutes = [0, 1, 30, 59, 60, 90, 330, 345, 359, 360, 720, 1080, 1290, 1320, 1380, 1410, 1439]
    start = rng.choice(minutes + [rng.randrange(1440)])
    end = rng.choice(minutes + [rng.randrange(1440), 1440])
    if end == start:  # refused ("use 00:00-24:00 for a whole day")
        end = 1440

    def hhmm(m: int) -> str:
        return f"{m // 60:02d}:{m % 60:02d}"

    return {"days": days, "start": hhmm(start), "end": hhmm(end)}


def _schedule_configs() -> list:
    rng = random.Random(2)
    out = []
    for _ in range(150):
        raw = copy.deepcopy(BASE)
        for i in range(rng.randint(1, 3)):
            action = rng.choice(["accept", "drop", "reject"])
            rule = {"name": f"timed-{i}", "action": action, "from_zone": rng.choice(["lan", "guest"]),
                    "to_zone": rng.choice(["wan", "self"]), "schedule": _schedule(rng)}
            if action != "accept" and rng.random() < 0.5:
                rule["schedule"]["cut_established"] = True
            if rng.random() < 0.3:
                rule["proto"], rule["dst_port"] = "tcp", rng.choice([443, "8000-8100"])
            raw["rules"].append(rule)
        out.append((raw, rng.sample(CLOCKS, 2)))
    return out


SCHEDULES = _schedule_configs()


@pytest.mark.parametrize("index", range(len(SCHEDULES)))
def test_schedule(index):
    raw, clocks = SCHEDULES[index]
    for offset, west in clocks:
        _build(raw, clock=ScheduleClock(offset, west))


RUNTIME_BASE = {
    **copy.deepcopy(BASE),
    "ztna": {"enabled": True, "session_ttl_seconds": 3600,
             "users": [{"username": "kolos", "password_hash": "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2g"}]},
    "iot": {"enabled": True, "zones": ["guest"]},
}

RUNTIMES = [
    builder.RuntimeSets(bruteforce_jail=(("10.73.1.5", 60), ("10.73.1.6", 0), ("10.73.1.7", -5))),
    builder.RuntimeSets(ids_quarantine=(("10.73.2.9", 3600), ("10.73.2.10", 1))),
    builder.RuntimeSets(ids_quarantine_mac=(("aa:bb:cc:dd:ee:01", 10), ("AA:BB:CC:DD:EE:02", 10),
                                            ("aa:bb:cc:dd:ee:03 ", 10), ("aa-bb-cc-dd-ee-04", 10))),
    builder.RuntimeSets(bruteforce_jail6=(("2001:db8:1::5", 30), ("2001:db8:1::/64", 30), ("2001:db8:1::5/128", 9),
                                          ("2001:DB8:2:0:0:0:0:1", 5), ("2001:db8:3::/48", 7),
                                          ("2001:db8:3:4::/64", 7), ("2001:db8:9::/64", 0))),
    builder.RuntimeSets(bruteforce_jail_mac=(("52:54:00:12:34:56", 900), ("52:54:00:12:34:5", 900))),
    builder.RuntimeSets(ztna=(("10.73.1.20", "aa:bb:cc:dd:ee:01", 100), ("10.99.0.2", "", 50),
                              ("2001:db8:1::20", "aa:bb:cc:dd:ee:01", 100), ("fd00:99::2", "", 40),
                              ("2001:DB8:1:0::21", "aa:bb:cc:dd:ee:02", 1), ("::ffff:10.73.1.22", "", 5),
                              ("10.73.1.023", "aa:bb:cc:dd:ee:03", 5), ("not-an-ip", "", 5),
                              ("10.73.1.24", "AA:BB:CC:DD:EE:04", 5), ("10.73.1.25", "", 0))),
    builder.RuntimeSets(iot_isolated=("aa:bb:cc:dd:ee:10", "AA:BB:CC:DD:EE:11", "aa:bb:cc:dd:ee:12\n")),
    builder.RuntimeSets(bruteforce_jail=(("10.73.1.5", 60),), ids_quarantine=(("10.73.2.9", 3600),),
                        ztna=(("10.73.1.20", "aa:bb:cc:dd:ee:01", 100),), iot_isolated=("aa:bb:cc:dd:ee:10",),
                        ids_quarantine_mac=(("aa:bb:cc:dd:ee:01", 10),), bruteforce_jail6=(("2001:db8:1::5", 30),),
                        bruteforce_jail_mac=(("52:54:00:12:34:56", 900),)),
]


@pytest.mark.parametrize("index", range(len(RUNTIMES)))
def test_runtime(index):
    _build(RUNTIME_BASE, runtime=RUNTIMES[index])
    off = copy.deepcopy(RUNTIME_BASE)
    off["ztna"]["enabled"] = False
    off["iot"]["enabled"] = False
    _build(off, runtime=RUNTIMES[index])
