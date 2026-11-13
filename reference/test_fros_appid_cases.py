"""FR_OS 1.x's application identification (frfw.appid, phase 16) fed every
shape of input, recorded for FR_OS 2's crates/fros-appid (appid.jsonl;
reference/generate.sh runs this module).

Five things are recorded:

- the catalog parser on the bundled signatures.json and on catalogs
  broken every way (wrong types, missing keys, duplicate ids): what it
  kept, or the exact CatalogError text;
- the name matcher on every catalog name and on variants of them (case,
  trailing dots, whitespace, look-alike suffixes, non-ASCII text, seeded
  random names), and `blocking_names` for sets of app ids;
- the usage tracker driven through records, pruning, its client limit
  and snapshots, and restored from state files valid and broken: what
  json.dumps writes for each snapshot, or the type of the exception;
- the fr-appid daemon's de-duplication (`AppIdDaemon.observe`) with its
  clock, including the purge of its table past 20,000 entries;
- the daemon's two line readers (`handle_dns_log_line`,
  `handle_sni_event_line`): which (client, name, source) each line
  hands on, if any.

Nothing here asserts anything about 1.x.
"""

from __future__ import annotations

import json
import random
import sys
import threading

from frfw.appid import SIGNATURES_PATH, AppMatcher, CatalogError, blocking_names, parse_catalog
from frfw.appid.daemon import AppIdDaemon
from frfw.appid.usage import MAX_CLIENTS_PER_APP, UsageTracker

T0 = 1_700_000_000.0
CATALOG_TEXT = SIGNATURES_PATH.read_text()
CATALOG = parse_catalog(json.loads(CATALOG_TEXT))


def _record(case: dict) -> None:
    capture = sys.modules.get("fros_capture")
    if capture is not None:
        capture._record("appid", case)


def _catalog_view(catalog) -> dict:
    return {
        "apps": [
            {"id": a.id, "name": a.name, "category": a.category, "domains": list(a.domains), "exact": list(a.exact)}
            for a in catalog.apps
        ],
        "source": catalog.source,
        "license": catalog.license,
        "ref": catalog.ref,
        "generated": catalog.generated,
        "categories": catalog.categories(),
    }


def _catalog_case(name: str, text: str) -> None:
    case = {"op": "catalog", "name": name, "input": text}
    try:
        catalog = parse_catalog(json.loads(text))
    except CatalogError as exc:
        case["error"] = str(exc)
    except Exception as exc:  # 1.x would crash
        case["crash"] = type(exc).__name__
    else:
        case["catalog"] = _catalog_view(catalog)
    _record(case)


# --- catalog ---------------------------------------------------------------------------------


def test_catalog():
    _catalog_case("bundled", CATALOG_TEXT)
    odd_ids = ["a'b", 'a"b', "a'\"b", "a\\b", "line\nbreak", "tab\there", "nul\x00", "del\x7f", "\x85",
               "caf\u00e9", "zero\u200bwidth", "\u2028", "\ud7ff", "\ue000", "\U0001f600", "\U000e0001",
               "\u00ad", "\u0378", "\U00010fff", " ", "\u3000", ""]
    values = [None, True, False, 0, 1, -7, 10**20, 1.0, 1.5, -0.0, 1e16, 1e-7, 123456789.125, "x",
              [], [1, "a"], {}, {"k": [None, 2.5]}, [["n"], {"a": "b'"}], "MiXeD.Case.", "\u0130x", "\u212a",
              "\u03a3\u03a3", "\u1e9e", "\uff21"]
    shapes = {
        "not a dict": "[]",
        "a string": '"apps"',
        "null": "null",
        "no apps": "{}",
        "apps null": '{"apps": null}',
        "apps a dict": '{"apps": {}}',
        "apps a string": '{"apps": "x"}',
        "empty apps": '{"apps": []}',
        "empty with header": '{"apps": [], "source": 1, "license": null, "ref": [1, 2], "generated": {"a": 1}}',
    }
    for name, text in shapes.items():
        _catalog_case(name, text)
    entry = {"id": "a", "name": "A", "category": "c", "domains": ["a.example"], "exact": ["x.a.example"]}
    for bad in [None, 1, 1.5, True, "entry", [], ["id"], {}]:
        _catalog_case(f"entry {json.dumps(bad)}", json.dumps({"apps": [entry, bad]}))
    for key in ["id", "name", "category"]:
        broken = dict(entry)
        del broken[key]
        _catalog_case(f"missing {key}", json.dumps({"apps": [broken]}))
    for key in ["domains", "exact"]:
        broken = dict(entry)
        del broken[key]
        _catalog_case(f"missing {key}", json.dumps({"apps": [broken]}))
        for value in values:
            broken = dict(entry, **{key: value})
            _catalog_case(f"{key} {json.dumps(value)}", json.dumps({"apps": [broken]}))
            broken = dict(entry, **{key: [value, "Z.Example"]})
            _catalog_case(f"{key} [{json.dumps(value)}]", json.dumps({"apps": [broken]}))
    for key in ["id", "name", "category"]:
        for value in values:
            _catalog_case(f"{key} = {json.dumps(value)}", json.dumps({"apps": [dict(entry, **{key: value})]}))
    for odd in odd_ids:
        _catalog_case(f"id {odd!r}", json.dumps({"apps": [dict(entry, id=odd), dict(entry, id=odd)]}))
        _catalog_case(f"id {odd!r} ascii-off", json.dumps({"apps": [dict(entry, id=odd), dict(entry, id=odd)]},
                                                         ensure_ascii=False))
        _catalog_case(f"name {odd!r}", json.dumps({"apps": [dict(entry, name=odd)]}))
    for first, second in [(1, "1"), (1.0, "1.0"), (True, "True"), (None, "None"), ([1], "[1]"), ({}, "{}")]:
        _catalog_case(f"dup {first!r}", json.dumps({"apps": [dict(entry, id=first), dict(entry, id=second)]}))
    _catalog_case("dup third", json.dumps({"apps": [dict(entry, id="a"), dict(entry, id="b"), dict(entry, id="a")]}))
    _catalog_case("duplicate keys", '{"apps": [{"id": "a", "id": "b", "name": "n", "category": "c"}], "apps": []}')
    _catalog_case("duplicate keys 2", '{"apps": [], "apps": [{"id": "a", "id": "b", "name": "n", "category": "c"}]}')


# --- matching ---------------------------------------------------------------------------------


def _names_for_catalog(catalog, rng: random.Random) -> list[str]:
    names = ["", ".", "..", " ", "\t", "com", "example.com", "a..b", ".netflix.com", "netflix..com",
             "xnetflix.com", "netflix.com.evil", "www.netflix.com", "NETFLIX.COM", "netflix.com.",
             "netflix.com..", " netflix.com ", "\tnetflix.com\n", "\x1cnetflix.com\x1f", "\x85netflix.com\u3000",
             "\u200bnetflix.com", "netflix.com\x00", "NETFL\u0130X.COM", "netfl\u0131x.com", "\uff4e\uff45tflix.com",
             "\u212a.com", "\u03a3.com", "\u1e9e.com", "netflix.c\u00f6m", ". netflix.com", "netflix.com. ",
             "netflix.com .", "rr3---sn-4g5e6nsz.googlevideo.com", "steamcdn-a.akamaihd.net",
             "x.steamcdn-a.akamaihd.net", "akamaihd.net"]
    for app in catalog.apps:
        for name in app.domains + app.exact:
            names += [name, "www." + name, name.upper(), name + ".", "x." + name + "..", name[1:], "a" + name,
                      name.replace(".", "..", 1)]
            labels = name.split(".")
            names.append(".".join(labels[1:]))
    alphabet = "abcnetflix.-_ \t.\u00e9\u0130\u212aXYZ0123456789"
    for _ in range(400):
        names.append("".join(rng.choice(alphabet) for _ in range(rng.randint(0, 24))))
    return names


def _match_case(name: str, catalog_name: str, catalog, names: list[str]) -> None:
    matcher = AppMatcher(catalog)
    _record({"op": "match", "name": name, "catalog": catalog_name, "names": names,
             "apps": [matcher.match(n) for n in names]})


def test_match():
    rng = random.Random(16)
    _match_case("bundled", "bundled", CATALOG, _names_for_catalog(CATALOG, rng))
    # Precedence: the first app to claim a name keeps it; exact before suffix.
    text = json.dumps({"apps": [
        {"id": "first", "name": "F", "category": "c", "domains": ["shared.example", "Upper.Example"],
         "exact": ["exact.shared.example"]},
        {"id": "second", "name": "S", "category": "c", "domains": ["shared.example", "exact.shared.example"],
         "exact": ["shared.example", "deep.exact.shared.example"]},
        {"id": "third", "name": "T", "category": "d", "domains": ["", ".", "trail.example.", "a..b", " sp.example"],
         "exact": [".", ""]},
    ]})
    _catalog_case("precedence", text)
    catalog = parse_catalog(json.loads(text))
    names = ["shared.example", "x.shared.example", "exact.shared.example", "y.exact.shared.example",
             "deep.exact.shared.example", "z.deep.exact.shared.example", "upper.example", "UPPER.EXAMPLE.",
             "", ".", "x.", "trail.example", "trail.example.", "x.trail.example.", "a..b", "x.a..b", "b",
             "sp.example", " sp.example", "x. sp.example", "x.sp.example", "example"]
    _match_case("precedence", "precedence", catalog, names + _names_for_catalog(catalog, rng))


def test_blocking_names():
    ids = [a.id for a in CATALOG.apps]
    rng = random.Random(161)
    sets = [[], ["netflix"], ["netflix", "netflix"], ["unknown"], ids, ids[::-1], ["steam", "unknown", "zoom"]]
    for _ in range(20):
        sets.append(rng.sample(ids, rng.randint(1, 6)))
    for app_ids in sets:
        _record({"op": "blocking", "catalog": "bundled", "app_ids": app_ids,
                 "names": blocking_names(app_ids, CATALOG)})


# --- usage ------------------------------------------------------------------------------------


def _run_usage(name: str, tracker: UsageTracker, steps: list[dict], restored_from: str | None = None) -> None:
    recorded = []
    for step in steps:
        out = dict(step)
        if step["do"] == "record":
            tracker.record(step["app"], step["client"], step["source"], now=step["now"])
        elif step["do"] == "prune":
            tracker.prune(now=step["now"])
        elif step["do"] == "snapshot":
            out["json"] = json.dumps(tracker.snapshot(now=step["now"]))
        recorded.append(out)
    case = {"op": "usage", "name": name, "steps": recorded}
    if restored_from is not None:
        case["restore"] = restored_from
    _record(case)


def test_usage():
    h = 3600.0
    _run_usage("one hit", UsageTracker(), [
        {"do": "record", "app": "netflix", "client": "10.0.0.5", "source": "dns", "now": T0},
        {"do": "snapshot", "now": T0},
        {"do": "snapshot", "now": T0 + 900},
        {"do": "snapshot", "now": T0 + 900.5},
        {"do": "snapshot", "now": T0 + 25 * h},
        {"do": "snapshot", "now": T0 + 26 * h},
    ])
    steps = []
    rng = random.Random(1616)
    apps = ["netflix", "youtube", "zoom", "steam", "b-app", "a-app"]
    clients = ["10.0.0.5", "10.0.0.50", "10.0.0.6", "fd00::1", "fe80::1%eth0", "", "Z", "\u00e9"]
    now = T0
    for i in range(400):
        now += rng.choice([0.0, 0.25, 1.0, 59.0, 899.0, 901.0, 1800.0, 3599.5, 3600.0, 7200.0])
        steps.append({"do": "record", "app": rng.choice(apps), "client": rng.choice(clients),
                      "source": rng.choice(["dns", "sni", "other"]), "now": now})
        if i % 37 == 0:
            steps.append({"do": "snapshot", "now": now + rng.choice([0.0, 600.0, 3600.0, 86400.0])})
        if i % 53 == 0:
            steps.append({"do": "prune", "now": now + rng.choice([0.0, 90000.0])})
    steps.append({"do": "snapshot", "now": now})
    _run_usage("random", UsageTracker(), steps)
    # Out-of-order clocks and the bucket boundary.
    _run_usage("clock", UsageTracker(), [
        {"do": "record", "app": "a", "client": "c", "source": "dns", "now": T0 + 10},
        {"do": "record", "app": "a", "client": "c", "source": "sni", "now": T0},
        {"do": "record", "app": "a", "client": "c", "source": "dns", "now": 3600.0 * 472223},
        {"do": "record", "app": "a", "client": "c", "source": "dns", "now": 3600.0 * 472223 - 0.001},
        {"do": "record", "app": "a", "client": "d", "source": "dns", "now": -1.5},
        {"do": "record", "app": "a", "client": "d", "source": "dns", "now": 0.0},
        {"do": "record", "app": "a", "client": "e", "source": "dns", "now": 1e-300},
        {"do": "record", "app": "a", "client": "e", "source": "dns", "now": 0.1 + 0.2},
        {"do": "snapshot", "now": T0},
        {"do": "snapshot", "now": 0.0},
        {"do": "snapshot", "now": -3600.0},
    ])
    # The per-app client limit: the least recently seen client goes.
    steps = [{"do": "record", "app": "a", "client": f"10.0.{i // 256}.{i % 256}", "source": "dns",
              "now": T0 + (i % 7)} for i in range(MAX_CLIENTS_PER_APP + 40)]
    steps.append({"do": "record", "app": "a", "client": "10.0.0.3", "source": "sni", "now": T0 + 100})
    steps += [{"do": "record", "app": "a", "client": f"new{i}", "source": "dns", "now": T0 + 3} for i in range(10)]
    steps.append({"do": "snapshot", "now": T0 + 200})
    _run_usage("client limit", UsageTracker(), steps)


def _restore_case(name: str, text: str, then: list[dict] | None = None) -> None:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = None
    except Exception as exc:
        _record({"op": "usage", "name": name, "restore": text, "crash": type(exc).__name__})
        return
    try:
        tracker = UsageTracker.restore(data)
    except Exception as exc:  # 1.x's daemon would not start
        _record({"op": "usage", "name": name, "restore": text, "crash": type(exc).__name__})
        return
    _run_usage(name, tracker, (then or []) + [{"do": "snapshot", "now": T0 + 60}], restored_from=text)


def test_usage_restore():
    tracker = UsageTracker()
    for i in range(30):
        tracker.record(["netflix", "zoom"][i % 2], f"10.0.0.{i % 5}", ["dns", "sni"][i % 3 % 2], now=T0 - 3000 + i * 100)
    good = json.dumps(tracker.snapshot(now=T0))
    _restore_case("round trip", good)
    _restore_case("round trip then record", good, [
        {"do": "record", "app": "netflix", "client": "10.0.0.1", "source": "dns", "now": T0 + 30}])
    shapes = ["", "x", "null", "[]", "{}", '{"apps": []}', '{"apps": {}}', '{"apps": null}', '{"apps": {"a": null}}',
              '{"apps": {"a": []}}', '{"apps": {"a": {}}}', '{"apps": {"a": {"clients": []}}}',
              '{"apps": {"a": {"clients": {}}}}', '{"apps": {"a": {"clients": {"c": null}}}}',
              '{"apps": {"a": {"clients": {"c": []}}}}', '{"apps": {"a": {"clients": {"c": "row"}}}}',
              '{"apps": {"a": {"clients": {"c": 5}}}}', '{"apps": {"a": {"clients": {"c": {}}}}}',
              "[" * 100000, '{"apps": ' + "[" * 20000 + "]" * 20000 + "}", b"\xff".decode("latin-1")]
    for i, text in enumerate(shapes):
        _restore_case(f"shape {i}", text)
    row = {"first_seen": T0 - 100, "last_seen": T0 - 50, "buckets": {str(int(T0 // 3600) * 3600): 3},
           "sources": ["dns"]}
    odd_values = [None, True, False, 0, 1, -1, 1.5, -0.0, 1e308, 10**30, "1", " 1 ", "1_0", "1.5", "1e3", "nan",
                  "-inf", "inf", "Infinity", "\u0661", "\u00a0 7 \u3000", "\x1c7", "0x10", "", [], {}, [1]]
    for key in ["first_seen", "last_seen"]:
        for value in odd_values:
            _restore_case(f"{key} {json.dumps(value)}", json.dumps(
                {"apps": {"a": {"clients": {"c": dict(row, **{key: value})}}}}))
        _restore_case(f"no {key}", json.dumps(
            {"apps": {"a": {"clients": {"c": {k: v for k, v in row.items() if k != key}}}}}))
    for value in odd_values:
        _restore_case(f"bucket count {json.dumps(value)}", json.dumps(
            {"apps": {"a": {"clients": {"c": dict(row, buckets={"1700000000": value})}}}}))
        _restore_case(f"buckets {json.dumps(value)}", json.dumps(
            {"apps": {"a": {"clients": {"c": dict(row, buckets=value)}}}}))
        _restore_case(f"sources {json.dumps(value)}", json.dumps(
            {"apps": {"a": {"clients": {"c": dict(row, sources=value)}}}}))
    for key in ["1700000000", " 1700000000 ", "1_700_000_000", "+1700000000", "-3600", "0", "1700000000.0",
                "1e9", "abc", "", "\u0661\u0667", "9" * 30, "9" * 5000, "1699999200", "99999999999999999999"]:
        _restore_case(f"bucket key {key[:40]!r}", json.dumps(
            {"apps": {"a": {"clients": {"c": dict(row, buckets={key: 2})}}}}))
    for sources in [["dns", "sni", "dns"], ["other"], ["DNS"], "dns", {"dns": 1}, [["dns"]], [None, "sni"]]:
        _restore_case(f"sources {json.dumps(sources)}", json.dumps(
            {"apps": {"a": {"clients": {"c": dict(row, sources=sources)}}}}))
    _restore_case("empty buckets", json.dumps({"apps": {"a": {"clients": {"c": dict(row, buckets={})}}}}))
    _restore_case("old buckets", json.dumps({"apps": {"a": {"clients": {"c": dict(row, buckets={"0": 5})}}}}))
    _restore_case("nan seen", '{"apps": {"a": {"clients": {"c": {"first_seen": NaN, "last_seen": NaN, '
                  '"buckets": {"1699999200": 1}}, "d": {"first_seen": 1, "last_seen": Infinity, '
                  '"buckets": {"1699999200": 1}}}}}}')
    _restore_case("nan then record", '{"apps": {"a": {"clients": {"c": {"first_seen": NaN, "last_seen": NaN, '
                  '"buckets": {"1699999200": 1}}}}}}',
                  [{"do": "record", "app": "a", "client": "c", "source": "dns", "now": T0}])
    # The exceptions 1.x's restore does not catch: OverflowError from
    # float() of a huge int and from int() of an infinity.
    _restore_case("first_seen huge int", '{"apps": {"a": {"clients": {"c": {"first_seen": 1' + "0" * 400 +
                  ', "last_seen": 1, "buckets": {"1699999200": 1}}}}}}')
    _restore_case("last_seen huge int", '{"apps": {"a": {"clients": {"c": {"first_seen": 1, "last_seen": -1' +
                  "0" * 400 + ', "buckets": {"1699999200": 1}}}}}}')
    _restore_case("huge int, no last_seen", '{"apps": {"a": {"clients": {"c": {"first_seen": 1' + "0" * 400 +
                  ', "buckets": {"1699999200": 1}}}}}}')
    _restore_case("count Infinity", '{"apps": {"a": {"clients": {"c": {"first_seen": 1, "last_seen": 1, '
                  '"buckets": {"1699999200": Infinity}}}}}}')
    _restore_case("count Infinity after a bad key", '{"apps": {"a": {"clients": {"c": {"first_seen": 1, '
                  '"last_seen": 1, "buckets": {"x": 1, "1699999200": Infinity}}}}}}')
    _restore_case("count Infinity after a bad row", '{"apps": {"a": {"clients": {"b": [], "c": {"first_seen": 1, '
                  '"last_seen": 1, "buckets": {"1699999200": -Infinity}}}}}}')
    _restore_case("duplicate keys", '{"apps": {"a": {"clients": {"c": {"first_seen": 1, "first_seen": 2, '
                  '"last_seen": 3, "buckets": {"1699999200": 1, "1699999200": 4}}}}, "a": {"clients": {}}}}')
    _restore_case("duplicate apps", '{"apps": {"a": {"clients": {"c": {"first_seen": 1, "last_seen": 3, '
                  '"buckets": {"1699999200": 1}}}}, "b": {}, "a": {"clients": {"d": {"first_seen": 1, '
                  '"last_seen": 3, "buckets": {"1699999200": 2}}}}}}')
    _restore_case("unicode keys", json.dumps({"apps": {"\u00e9": {"clients": {"\U0001f600": row, "Z": row, "a": row}},
                                                       "B": {"clients": {"c": row}}}}))
    _restore_case("lone surrogate key", json.dumps({"apps": {"\udc00": {"clients": {"c": row}}}}))
    _restore_case("negative counts", json.dumps({"apps": {"a": {"clients": {"c": dict(
        row, buckets={"1699999200": -5, "1700002800": 2})}}}}))
    _restore_case("float now buckets", json.dumps({"apps": {"a": {"clients": {"c": dict(
        row, buckets={"1699999200": 2.9, "1700002800": True})}}}}))
    _restore_case("big counts", json.dumps({"apps": {"a": {"clients": {"c": dict(
        row, buckets={"1699999200": 2 ** 62, "1700002800": 2 ** 62})}}}}))
    rng = random.Random(6116)
    for i in range(60):
        text = bytearray(good.encode())
        for _ in range(rng.randint(1, 4)):
            pos = rng.randrange(len(text))
            text[pos] = rng.choice(b'{}[]",:0123456789.-eE ntfaxN')
        _restore_case(f"damaged {i}", text.decode())


# --- the daemon: de-duplication and its two line readers -----------------------------------------


def _bare_daemon(clock) -> AppIdDaemon:
    daemon = object.__new__(AppIdDaemon)
    daemon.matcher = AppMatcher(CATALOG)
    daemon._clock = clock
    daemon._lock = threading.Lock()
    daemon._recent = {}
    daemon.tracker = UsageTracker()
    return daemon


def test_observe():
    clock = {"now": T0}
    daemon = _bare_daemon(lambda: clock["now"])
    rng = random.Random(1610)
    names = ["www.netflix.com", "WWW.NETFLIX.COM", "www.netflix.com.", "zoom.us", "example.com", "",
             "web.whatsapp.com", "steamcdn-a.akamaihd.net"]
    steps = []
    for _ in range(300):
        clock["now"] += rng.choice([0.0, 0.5, 9.99, 10.0, 10.01, 30.0, -5.0])
        client, name, source = rng.choice(["10.0.0.5", "10.0.0.6"]), rng.choice(names), rng.choice(["dns", "sni"])
        steps.append({"client": client, "name": name, "source": source, "now": clock["now"],
                      "app": daemon.observe(client, name, source)})
    _record({"op": "observe", "name": "random", "steps": steps,
             "json": json.dumps(daemon.tracker.snapshot(now=clock["now"]))})
    # Past 20,000 remembered (client, name, source) keys the table is
    # rebuilt with only the fresh ones: flood it, then probe.
    clock = {"now": T0}
    daemon = _bare_daemon(lambda: clock["now"])
    flood = {"count": 20005, "start": T0, "step": 0.001}
    for i in range(flood["count"]):
        clock["now"] = flood["start"] + i * flood["step"]
        daemon.observe(f"10.{i // 65536}.{i // 256 % 256}.{i % 256}", "www.netflix.com", "dns")
    probes = []
    for client, dt in [("10.0.0.0", 0.0), ("10.0.0.1", 0.0), ("10.0.78.30", 0.0), ("10.0.78.36", 0.0),
                       ("10.0.0.2", 5.0), ("10.0.78.35", 5.0)]:
        clock["now"] = flood["start"] + (flood["count"] - 1) * flood["step"] + dt
        probes.append({"client": client, "now": clock["now"],
                       "app": daemon.observe(client, "www.netflix.com", "dns"), "recent": len(daemon._recent)})
    _record({"op": "observe", "name": "flood", "flood": flood, "probes": probes,
             "json": json.dumps(daemon.tracker.snapshot(now=clock["now"]))})


def _line_reader():
    daemon = object.__new__(AppIdDaemon)
    seen = []
    daemon.observe = lambda client, name, source: seen.append([client, name, source])
    return daemon, seen


def test_lines():
    dns = ["2 10.0.0.5/46381 query[A] www.netflix.com from 10.0.0.5",
           "Nov 13 10:00:00 dnsmasq[123]: 2 10.0.0.5/46381 query[AAAA] www.netflix.com from 10.0.0.5",
           "Nov  3 10:00:00 dnsmasq[123]: 2 10.0.0.5/46381 query[HTTPS] x.example from 10.0.0.5",
           "nov 13 10:00:00 dnsmasq[123]: 2 10.0.0.5/46381 query[A] x.example from 10.0.0.5",
           "Nov 13 10:00:00 dnsmasq[]: 2 10.0.0.5/46381 query[A] x.example from 10.0.0.5",
           "Nov 13 10:00:00 dnsmasq[1]: ",
           "Nov 13 10:00:00 dnsmasq[1]: \n2 10.0.0.5/1 query[A] x.example from 10.0.0.5",
           "Nov \u0661\u0663 10:00:00 dnsmasq[\u0661]: 2 10.0.0.5/1 query[A] x.example from 10.0.0.5",
           "\u0662 10.0.0.5/\u0661 query[A] x.example from 10.0.0.5",
           "2 fd00::1/53 query[A] x.example from fd00::1",
           "2 FD00::A/53 query[A] x.example from x",
           "2 10.0.0.5%eth0/53 query[A] x.example from x",
           "2 10.0.0.5/53 query[PTR] 5.0.0.10.in-addr.arpa from 10.0.0.5",
           "2 10.0.0.5/53 query[ptr] x.example from 10.0.0.5",
           "2 10.0.0.5/53 query[Srv] x.example from 10.0.0.5",
           "2 10.0.0.5/53 query[TXT] x.example from 10.0.0.5",
           "2 10.0.0.5/53 query[type=65] x.example from 10.0.0.5",
           "2 10.0.0.5/53 query[] x.example from 10.0.0.5",
           "2 10.0.0.5/53 query[A] x.example from 10.0.0.5\n",
           "2 10.0.0.5/53 query[A] x.example from 10.0.0.5\n\n",
           "2 10.0.0.5/53 query[A] x.example from 10.0.0.5 ",
           "2 10.0.0.5/53 query[A] x.example  from 10.0.0.5",
           "2 10.0.0.5/53 query[A] x.example\tfrom 10.0.0.5",
           "2 10.0.0.5/53 query[A] x.ex\u00e9mple from \u00e9",
           "2 10.0.0.5/53 query[A] x.example\u3000y from 10.0.0.5",
           "2 10.0.0.5/53 query[A] x.example\x1cy from 10.0.0.5",
           "2 10.0.0.5/53 query[A] x\u200by from 10.0.0.5",
           "2 10.0.0.5/53 query[A] x.example from",
           "2 10.0.0.5/53 query[A]  from 10.0.0.5",
           "2 10.0.0.5/53 forwarded x.example to 1.1.1.1",
           "2 10.0.0.5/53 reply x.example is NXDOMAIN",
           " 2 10.0.0.5/53 query[A] x.example from 10.0.0.5",
           "", "x", "2 /53 query[A] x from y", "2 10.0.0.5/ query[A] x from y", "10.0.0.5/53 query[A] x from y"]
    daemon, seen = _line_reader()
    for line in dns:
        seen.clear()
        daemon.handle_dns_log_line(line)
        _record({"op": "dns_line", "line": line, "observed": list(seen)})
    sni = ['{"action": "pass", "saddr": "10.0.0.5", "sni": "www.netflix.com"}',
           '{"action": "drop", "saddr": "10.0.0.5", "sni": "x"}',
           '{"action": "log", "saddr": "10.0.0.5", "sni": "x"}',
           '{"action": "PASS", "saddr": "10.0.0.5", "sni": "x"}',
           '{"action": ["pass"], "saddr": "10.0.0.5", "sni": "x"}',
           '{"action": "pass", "saddr": "", "sni": "x"}',
           '{"action": "pass", "saddr": "10.0.0.5", "sni": ""}',
           '{"action": "pass", "saddr": 5, "sni": "x"}',
           '{"action": "pass", "saddr": "10.0.0.5", "sni": null}',
           '{"action": "pass", "saddr": "10.0.0.5"}',
           '{"action": "drop", "action": "pass", "saddr": "a", "sni": "b"}',
           '{"action": "pass", "saddr": "a", "sni": "\\ud800x"}',
           '{"action": "pass", "saddr": "\u00e9", "sni": "\u00e9"}',
           ' {"action": "pass", "saddr": "a", "sni": "b"} ', '[]', '"pass"', 'null', '', 'x', '{', '{"a": NaN}',
           '{"action": "pass", "saddr": "a", "sni": "b"} x', "[" * 50000]
    daemon, seen = _line_reader()
    for line in sni:
        seen.clear()
        case = {"op": "sni_line", "line": line}
        try:
            daemon.handle_sni_event_line(line)
        except Exception as exc:
            case["crash"] = type(exc).__name__
        else:
            # As JSON text: a lone surrogate in a name can't go in the
            # case file as it is.
            case["observed"] = json.dumps(seen)
        _record(case)
