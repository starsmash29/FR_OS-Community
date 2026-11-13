"""FR_OS 1.x's AI-IDS scoring (frfw.ai_ids.engine, phases 11 and 15) and
the pieces of its daemon that read the logs, fed every shape of input and
recorded for FR_OS 2's crates/fros-aiids (aiids.jsonl;
reference/generate.sh runs this module).

Recorded:

- the DGA heuristic (frfw.adblock.dga) on real-looking, random and odd
  names: the label it scores, its entropy and bigram ratio, the verdict;
- the arithmetic the engine leans on, where Python is exact and a naive
  port is not: statistics.mean and statistics.pstdev (exact fractions,
  correctly rounded) and round(x, n);
- the anomaly engine driven through seeded traffic of every feature,
  baselines, sweeps and odd clocks: every evaluate() answer and every
  tracked_ips() list;
- the daemon's two line readers (`handle_dns_log_line`,
  `handle_sni_event_line`): what each line hands the engine, if anything.

Nothing here asserts anything about 1.x.
"""

from __future__ import annotations

import dataclasses
import json
import random
import statistics
import sys

from frfw.adblock.dga import common_bigram_ratio, looks_generated, registered_label, shannon_entropy
from frfw.ai_ids.daemon import IDSDaemon
from frfw.ai_ids.engine import SWEEP_INTERVAL, AnomalyEngine

T0 = 1_700_000_000.0


def _record(case: dict) -> None:
    capture = sys.modules.get("fros_capture")
    if capture is not None:
        capture._record("aiids", case)


# --- the DGA heuristic ------------------------------------------------------------------------


def test_dga():
    rng = random.Random(15)
    names = ["", ".", "..", "com", "example.com", "www.example.co.uk", "example.co.uk", "co.uk", "x.co",
             "d1a2b3c4d5.cloudfront.net", "xjwqpzkvbtrm.com", "xjwqpzkvbtrm.co.uk", "www.xjwqpzkvbtrm.com.",
             "XJWQPZKVBTRM.COM", "xn--bcher-kva.example", "xn--qwrtzpsdfghjk.com", "kq3v9x2m7zp1.net",
             "kq3v-9x2m-7zp1.net", "a-b-c-d-e-f-g-h-i-j.com", "abcdefghij.com", "abcdefghijklmnop.org",
             "thisisatestdomain.com", "googleapis.com", "x..com", "x.com..", "x.com.", ".x.com", "x_y.com",
             "\u00e9xjwqpzkvbtrm.com", "xjwqpzkvbtrm\u212a.com", "XJWQPZ\u0130KVBTRM.com", "\u0130.com",
             "xjwqpzkvbtrm.gob.mx", "xjwqpzkvbtrm.ltd.uk", "ltd.uk", "a.ltd.uk", "xjwqpzkvbtrm.c\u00f6m",
             "1234567890.com", "1234567890abcdef.com", "qqqqqqqqqqqqqqqq.com", "qwertyuiopasdfgh.com",
             "-----------.com", "zzzzzzzzzz-zzz.com", "abcdefghi.com", "abcdefghijk.com"]
    for _ in range(600):
        length = rng.randint(1, 30)
        alphabet = rng.choice(["abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyz0123456789",
                               "etaoinshrdlu", "bcdfghjklmnpqrstvwxz-", "aeiou0123456789"])
        label = "".join(rng.choice(alphabet) for _ in range(length))
        tld = rng.choice(["com", "net", "co.uk", "org", "ru", "com.au", ""])
        prefix = rng.choice(["", "www.", "a.b."])
        names.append(prefix + label + ("." + tld if tld else ""))
    for name in names:
        label = registered_label(name)
        case = {"op": "dga", "input": name, "label": label, "generated": looks_generated(name)}
        if label is not None:
            compact = label.replace("-", "")
            case["entropy"] = shannon_entropy(compact)
            case["bigram_ratio"] = common_bigram_ratio(compact)
        _record(case)
    for text in ["", "a", "ab", "aaaa", "abcd", "hello world", "\u00e9\u00e9a", "0123456789", "a1b2c3",
                 "thequickbrownfoxjumpsoverthelazydog", "zzxxqqjj", "th", "t-h"]:
        _record({"op": "dga_parts", "input": text, "entropy": shannon_entropy(text),
                 "bigram_ratio": common_bigram_ratio(text)})


# --- exact arithmetic ---------------------------------------------------------------------------


def test_stats():
    rng = random.Random(1111)
    lists = [[0.0], [1.0], [0.0, 0.0, 0.0, 0.0, 0.0], [1.0, 2.0, 3.0, 4.0, 5.0], [0.1, 0.2, 0.3],
             [1e300, -1e300, 1.0], [1e-300, 3e-300, 5e-310], [5e-324, 5e-324, 1e-323], [1e16, 1.0, -1e16],
             [1 / 3, 2 / 3, 1.0], [0.1] * 30, [7 / 60] * 29 + [8 / 60], [1.5, 2.5, 2.5, 2.75, 3.25, 4.75],
             [1e308, 1e308], [-1e308, -1e308, -1e308], [0.0, 1.7976931348623157e308]]
    for _ in range(300):
        kind = rng.randrange(5)
        n = rng.randint(1, 30)
        if kind == 0:
            values = [rng.randint(0, 20) / 60 for _ in range(n)]
        elif kind == 1:
            values = [float(rng.randint(0, 40)) for _ in range(n)]
        elif kind == 2:
            values = [rng.random() for _ in range(n)]
        elif kind == 3:
            values = [rng.uniform(-1, 1) * 10 ** rng.randint(-300, 300) for _ in range(n)]
        else:
            values = [rng.randint(1, 50) / rng.randint(1, 50) for _ in range(n)]
        lists.append(values)
    for values in lists:
        _record({"op": "stats", "values": values, "mean": statistics.mean(values),
                 "pstdev": statistics.pstdev(values)})
    xs = [0.0, -0.0, 0.125, 0.375, 2.675, 1.005, 0.5, 1.5, 2.5, -2.5, 1e-7, 123456.7891, 1e300, 5e-324, 0.1 + 0.2,
          3.0005, 2.0004999999999997, 1 / 3, 99.995, 0.0005, 0.0015, 1e15 + 0.3, -0.004, -0.006]
    rng = random.Random(1112)
    xs += [rng.random() * 10 ** rng.randint(-5, 6) for _ in range(300)]
    xs += [rng.randint(0, 100000) / 1000 + 0.0005 for _ in range(100)]
    for x in xs:
        for n in (2, 3):
            _record({"op": "round", "x": x, "n": n, "result": round(x, n)})


# --- the engine -------------------------------------------------------------------------------


def _event(event) -> dict | None:
    if event is None:
        return None
    out = dataclasses.asdict(event)
    out["reasons"] = list(out["reasons"])
    return out


def _run_engine(name: str, engine_args: dict, steps: list[dict]) -> None:
    engine = AnomalyEngine(**engine_args)
    recorded = []
    for step in steps:
        out = dict(step)
        do = step["do"]
        if do == "conn":
            engine.observe_connection(step["src"], step["dst"], now=step["now"])
        elif do == "sni":
            engine.observe_sni_block(step["src"], now=step["now"])
        elif do == "nx":
            engine.observe_dns_nxdomain(step["src"], step["name"], generated=step["generated"], now=step["now"])
        elif do == "threat":
            engine.observe_dns_threat_block(step["src"], now=step["now"])
        elif do == "evaluate":
            out["event"] = _event(engine.evaluate(step["ip"], now=step["now"]))
        elif do == "tracked":
            out["ips"] = engine.tracked_ips()
        recorded.append(out)
    _record({"op": "engine", "name": name, "args": engine_args, "steps": recorded})


def _host_traffic(rng: random.Random, ips: list[str], windows: int, window: float, start: float,
                  spikes: dict[int, str]) -> list[dict]:
    """Seeded traffic: every IP does a little of everything in each
    window, and the windows listed in `spikes` carry one feature's
    burst; every IP is evaluated at each window's end."""
    steps = []
    t = start
    for w in range(windows):
        for ip in ips:
            for _ in range(rng.randint(0, 6)):
                steps.append({"do": "conn", "src": ip, "dst": f"192.0.2.{rng.randint(1, 4)}",
                              "now": t + rng.random() * window})
            if rng.random() < 0.2:
                steps.append({"do": "sni", "src": ip, "now": t + rng.random() * window})
            for _ in range(rng.randint(0, 3)):
                name = rng.choice(["a.example", "b.example", "c.example"])
                steps.append({"do": "nx", "src": ip, "name": name, "generated": False, "now": t + rng.random() * window})
            if rng.random() < 0.1:
                steps.append({"do": "threat", "src": ip, "now": t + rng.random() * window})
            burst = spikes.get(w)
            if burst == "conn":
                for i in range(rng.randint(200, 600)):
                    steps.append({"do": "conn", "src": ip, "dst": "192.0.2.1", "now": t + rng.random() * window})
            elif burst == "scan":
                for i in range(rng.randint(20, 80)):
                    steps.append({"do": "conn", "src": ip, "dst": f"198.51.100.{i}", "now": t + rng.random() * window})
            elif burst == "sni":
                for _ in range(rng.randint(3, 12)):
                    steps.append({"do": "sni", "src": ip, "now": t + rng.random() * window})
            elif burst == "dga":
                for i in range(rng.randint(10, 60)):
                    steps.append({"do": "nx", "src": ip, "name": f"q{rng.random():.6f}.example",
                                  "generated": rng.random() < 0.8, "now": t + rng.random() * window})
            elif burst == "threat":
                for _ in range(rng.randint(2, 9)):
                    steps.append({"do": "threat", "src": ip, "now": t + rng.random() * window})
        t += window
        for ip in ips:
            steps.append({"do": "evaluate", "ip": ip, "now": t})
    return steps


def test_engine():
    steps = []
    for i in range(30):
        steps.append({"do": "conn", "src": "10.0.0.5", "dst": f"192.0.2.{i % 30}", "now": T0 + i * 0.1})
    steps += [{"do": "evaluate", "ip": "10.0.0.5", "now": T0 + 5}, {"do": "evaluate", "ip": "10.0.0.9", "now": T0 + 5},
              {"do": "tracked", "now": T0}]
    _run_engine("floor scan", {}, steps)
    _run_engine("floors exactly", {"window_seconds": 10.0}, [
        *({"do": "conn", "src": "a", "dst": "d", "now": T0} for _ in range(50)),
        *({"do": "sni", "src": "a", "now": T0} for _ in range(3)),
        *({"do": "threat", "src": "a", "now": T0} for _ in range(3)),
        *({"do": "nx", "src": "a", "name": f"n{i}", "generated": True, "now": T0} for i in range(30)),
        *({"do": "nx", "src": "a", "name": "n0", "generated": True, "now": T0} for i in range(30)),
        {"do": "evaluate", "ip": "a", "now": T0 + 10},
        {"do": "evaluate", "ip": "a", "now": T0 + 10.000001},
        {"do": "evaluate", "ip": "a", "now": T0 + 10},
    ])
    rng = random.Random(1515)
    for name, spikes in [("conn spike", {12: "conn"}), ("scan", {8: "scan", 20: "scan"}),
                         ("sni beacon", {6: "sni", 7: "sni", 30: "sni"}), ("dga", {10: "dga"}),
                         ("threat", {9: "threat"}), ("all", {6: "conn", 11: "scan", 15: "sni", 18: "dga", 22: "threat"}),
                         ("quiet", {})]:
        for window in (60.0, 10.0, 7.0):
            steps = _host_traffic(rng, ["10.0.0.5", "10.0.0.6"], 36, window, T0, spikes)
            steps.sort(key=lambda s: (s["now"], s["do"] == "evaluate"))
            steps.append({"do": "tracked", "now": T0})
            _run_engine(f"{name} {window}", {"window_seconds": window}, steps)
    for threshold in (0.0, 1.0, 2.5, 100.0, -1.0):
        steps = _host_traffic(random.Random(int(threshold * 10) + 7), ["10.0.0.7"], 20, 60.0, T0, {14: "conn"})
        steps.sort(key=lambda s: (s["now"], s["do"] == "evaluate"))
        _run_engine(f"threshold {threshold}", {"zscore_threshold": threshold}, steps)
    # A zero-variance baseline: stdev 0 becomes 1e-6.
    steps = []
    for w in range(8):
        for i in range(3):
            steps.append({"do": "conn", "src": "h", "dst": f"d{i}", "now": T0 + w * 60 + i})
        steps.append({"do": "evaluate", "ip": "h", "now": T0 + w * 60 + 59})
    for i in range(10):
        steps.append({"do": "conn", "src": "h", "dst": f"x{i}", "now": T0 + 8 * 60 + i})
    steps.append({"do": "evaluate", "ip": "h", "now": T0 + 8 * 60 + 59})
    _run_engine("flat baseline", {}, steps)
    # The sweep: every SWEEP_INTERVAL observations, IPs silent for an hour go.
    steps = [{"do": "conn", "src": f"10.1.0.{i}", "dst": "d", "now": T0 + i} for i in range(50)]
    steps.append({"do": "tracked", "now": T0})
    steps += [{"do": "sni", "src": "10.2.0.1", "now": T0 + 3600 + 25 + i * 0.01} for i in range(SWEEP_INTERVAL)]
    steps.append({"do": "tracked", "now": T0})
    steps += [{"do": "sni", "src": "10.2.0.1", "now": T0 + 7200 + i} for i in range(SWEEP_INTERVAL + 3)]
    steps += [{"do": "tracked", "now": T0}, {"do": "evaluate", "ip": "10.1.0.3", "now": T0 + 8000},
              {"do": "evaluate", "ip": "10.2.0.1", "now": T0 + 7200 + 210}]
    _run_engine("sweep", {}, steps)
    # Clocks that run backwards, repeat and jump.
    steps = []
    rng = random.Random(1516)
    t = T0
    for _ in range(1500):
        t += rng.choice([0.0, 0.0, 0.5, -30.0, 61.0, -1000.0, 4000.0])
        do = rng.choice(["conn", "conn", "sni", "nx", "threat", "evaluate", "evaluate"])
        ip = rng.choice(["a", "b", "c"])
        if do == "conn":
            steps.append({"do": do, "src": ip, "dst": rng.choice(["x", "y", "z", "w", "v", "u"]), "now": t})
        elif do == "nx":
            steps.append({"do": do, "src": ip, "name": rng.choice(["n1", "n2", "n3"]), "generated": rng.random() < 0.5,
                          "now": t})
        elif do == "evaluate":
            steps.append({"do": do, "ip": ip, "now": t})
        else:
            steps.append({"do": do, "src": ip, "now": t})
    steps.append({"do": "tracked", "now": t})
    _run_engine("odd clock", {"window_seconds": 60.0}, steps)
    _run_engine("odd window", {"window_seconds": 0.001}, [
        {"do": "conn", "src": "a", "dst": "b", "now": 1.0},
        {"do": "conn", "src": "a", "dst": "c", "now": 1.0005},
        {"do": "evaluate", "ip": "a", "now": 1.001},
        {"do": "evaluate", "ip": "a", "now": 1.0011},
    ])


# --- the daemon's line readers -------------------------------------------------------------------


class _Recorder:
    def __init__(self):
        self.calls = []

    def observe_sni_block(self, src_ip, *, now):
        self.calls.append(["sni", src_ip])

    def observe_dns_nxdomain(self, src_ip, name, *, generated, now):
        self.calls.append(["nx", src_ip, name, generated])

    def observe_dns_threat_block(self, src_ip, *, now):
        self.calls.append(["threat", src_ip])


def _reader(threat_files):
    daemon = object.__new__(IDSDaemon)
    daemon.engine = _Recorder()
    daemon._clock = lambda: T0
    daemon._threat_files = set(threat_files)
    # Which sources are scored depends on the config (4e); here every
    # source is handed on as it is, to record only the parsing.
    daemon._source = lambda ip: ip
    return daemon


def test_lines():
    threat = ["/var/lib/fr_os/adblock/malware.hosts", "/x"]
    dns = ["5 10.0.0.5/1234 reply qwkzjxv.example is NXDOMAIN",
           "5 10.0.0.5/1234 cached qwkzjxv.example is NXDOMAIN",
           "Nov 13 10:00:00 dnsmasq[9]: 5 10.0.0.5/1234 reply XJWQPZKVBTRM.COM is NXDOMAIN",
           "5 10.0.0.5/1234 reply x.example is NODATA-IPv4",
           "5 10.0.0.5/1234 reply x.example is 1.2.3.4",
           "5 10.0.0.5/1234 config x.example is NXDOMAIN",
           "5 10.0.0.5/1234 reply x.example is NXDOMAIN\n",
           "5 10.0.0.5/1234 reply x.example is NXDOMAIN ",
           "5 10.0.0.5/1234 reply  x.example is NXDOMAIN",
           "5 10.0.0.5/1234 reply x.ex\u00c9mple is NXDOMAIN",
           "5 10.0.0.5/1234 reply x.\u0130x is NXDOMAIN",
           "5 10.0.0.5/1234 reply \u03a3\u03a3.example is NXDOMAIN",
           "5 10.0.0.5/1234 reply x\x1cy is NXDOMAIN",
           "5 10.0.0.5/1234 reply x\u00a0y is NXDOMAIN",
           "5 10.0.0.5/1234 reply x\u200by is NXDOMAIN",
           "5 10.0.0.5/1234 reply x is NXDOMAIN\nmore",
           "5 10.0.0.5/1234 reply x\nis NXDOMAIN",
           "5 fd00::1/1234 reply x.example is NXDOMAIN",
           "\u0665 10.0.0.5/\u0661 reply x.example is NXDOMAIN",
           "5 10.0.0.5/1234 /var/lib/fr_os/adblock/malware.hosts bad.example is 0.0.0.0",
           "5 10.0.0.5/1234 /var/lib/fr_os/adblock/malware.hosts bad.example is ::",
           "5 10.0.0.5/1234 /var/lib/fr_os/adblock/malware.hosts bad.example is ::1",
           "5 10.0.0.5/1234 /var/lib/fr_os/adblock/ads.hosts bad.example is 0.0.0.0",
           "5 10.0.0.5/1234 /x y is 0.0.0.0",
           "5 10.0.0.5/1234 /x y is 0.0.0.0\n",
           "5 10.0.0.5/1234 x y is 0.0.0.0",
           "5 10.0.0.5/1234 / y is 0.0.0.0",
           "5 10.0.0.5/1234 /x  y is 0.0.0.0",
           "5 10.0.0.5/1234 query[A] x.example from 10.0.0.5",
           "5 10.0.0.5/1234 ", "5 10.0.0.5/1234", "5 10.0.0.5/1234 \n", "", "x"]
    daemon = _reader(threat)
    for line in dns:
        daemon.engine.calls.clear()
        daemon.handle_dns_log_line(line)
        _record({"op": "dns_line", "line": line, "threat_files": threat, "calls": list(daemon.engine.calls)})
    sni = ['{"action": "drop", "saddr": "10.0.0.5", "sni": "x"}', '{"action": "pass", "saddr": "10.0.0.5"}',
           '{"action": "drop"}', '{"action": "drop", "saddr": 5}', '{"action": "drop", "saddr": ""}',
           '{"action": "drop", "saddr": null}', '{"action": "DROP", "saddr": "a"}',
           '{"action": "drop", "action": "pass", "saddr": "a"}', '{"action": "pass", "action": "drop", "saddr": "a"}',
           '{"action": "drop", "saddr": "\\u00e9"}', '[]', 'null', '', '{', ' {"action": "drop", "saddr": "a"}\n',
           '{"action": "drop", "saddr": "a"} {}', "[" * 50000, '{"action": "drop", "saddr": "\\udc00"}']
    for line in sni:
        daemon.engine.calls.clear()
        case = {"op": "sni_line", "line": line}
        try:
            daemon.handle_sni_event_line(line)
        except Exception as exc:
            case["crash"] = type(exc).__name__
        else:
            case["calls"] = json.dumps(daemon.engine.calls)
        _record(case)
