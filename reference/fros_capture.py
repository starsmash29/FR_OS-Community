"""pytest plugin: record what FR_OS 1.x (Python) does, as the reference
FR_OS 2 must reproduce (AGENTS.md, "Differential tests").

Run inside a checkout of the Python FR_OS at the commit pinned in
reference/PIN, over its own test suite:

    FROS_CAPTURE_DIR=/path/out python3 -m pytest -p fros_capture tests --ignore=tests/webui -q

Every call of `parse_config` (the schema check) and `build_ruleset`
(the nft script) made anywhere in the suite is written down: the raw
input, and the result or the error. So is every `yaml.safe_load` of a
text (yaml.jsonl: the text and the value PyYAML built, or its error,
and what yaml.safe_dump writes for that value),
and every `parse_config` of a value that came straight from one
(yaml_config.jsonl: the text and parse_config's answer), since a YAML
value can be what JSON can't carry (a date, a key that isn't a
string). helper.jsonl holds the apply-helper requests
reference/test_fros_helper_cases.py sends (it records them itself,
through `_record`). A test's own assertions don't
matter here; what the 1.x code returned for that input does. Calls whose
input can't be written as JSON, or whose Config didn't come from a
recorded parse_config (a test built it by hand), are counted, not
recorded.

Defaults that depend on the moment (`now`, the schedule clock) are
fixed before the call and recorded, so each case replays exactly; `now`
is a fixed date, so a rerun records the same rulesets. (A config a test
builds from the current time or at random, such as an expiry an hour
from now or a fresh token, still changes from run to run.)
"""

from __future__ import annotations

import copy
import dataclasses
import datetime
import hashlib
import json
import math
import os
from pathlib import Path

#: 2026-11-01T00:00:00Z: `now` for calls that leave it to the clock.
FIXED_NOW = 1793491200.0

_raw_by_config: dict[int, object] = {}
#: id(value) -> (value, text) for each value yaml.safe_load built.
_text_by_value: dict[int, tuple[object, str]] = {}
_cases: dict[str, dict[str, dict]] = {"config": {}, "ruleset": {}, "yaml": {}, "yaml_config": {}, "helper": {}, "render": {}, "apply": {}, "webui": {}, "qr": {}, "tlsfp": {}, "appid": {}, "aiids": {}, "iot": {}, "xdp": {}, "xdpuser": {}, "tlsfpd": {}, "sensord": {}, "netdetect": {}, "release": {}}
_skipped = {"config_not_json": 0, "ruleset_unknown_config": 0, "ruleset_not_json": 0, "yaml_not_text": 0}


class _Recursive(Exception):
    pass


def _tagged(value, seen=()):
    """`value` as JSON that keeps its Python type: an object is always a
    tag ({"int": "5"}, {"map": [[key, value], ...]}, ...), never a plain
    mapping, so nothing is ambiguous."""
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:  # a lone surrogate, from an escape
            return {"surrogates": repr(value)}
        return value
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return {"int": str(value)}
    if isinstance(value, float):
        return {"float": repr(value)}
    if isinstance(value, datetime.datetime):
        offset = value.utcoffset()
        return {"datetime": [value.year, value.month, value.day, value.hour, value.minute, value.second,
                             value.microsecond, None if offset is None else int(offset.total_seconds())]}
    if isinstance(value, datetime.date):
        return {"date": value.isoformat()}
    if isinstance(value, bytes):
        return {"bytes": value.hex()}
    if id(value) in seen:
        raise _Recursive
    seen = seen + (id(value),)
    if isinstance(value, list):
        return [_tagged(v, seen) for v in value]
    if isinstance(value, tuple):
        return {"tuple": [_tagged(v, seen) for v in value]}
    if isinstance(value, (set, frozenset)):
        return {"set": sorted((_tagged(v, seen) for v in value), key=repr)}
    if isinstance(value, dict):
        return {"map": [[_tagged(k, seen), _tagged(v, seen)] for k, v in value.items()]}
    return {"other": type(value).__name__}


def _key(case: dict) -> str:
    return hashlib.sha256(json.dumps(case, sort_keys=True).encode()).hexdigest()[:16]


def _jsonable(value) -> bool:
    """`value` is exactly what JSON can carry, so the replay sees the same
    input: json.dumps would also take tuples, non-string keys (an int key
    becomes "1") and NaN, and hand back something else."""
    if value is None or isinstance(value, (bool, int, str)):
        return True
    if isinstance(value, float):
        return math.isfinite(value)
    if type(value) is list:
        return all(_jsonable(v) for v in value)
    if type(value) is dict:
        return all(type(k) is str and _jsonable(v) for k, v in value.items())
    return False


def _plain(value):
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    return value


def _unchanged(value, loaded) -> bool:
    try:
        return _tagged(value) == _tagged(loaded)
    except _Recursive:
        return False


def _record(kind: str, case: dict) -> None:
    _cases[kind].setdefault(_key(case), case)


def _patch():
    from frfw import config as config_pkg
    from frfw import nft as nft_pkg
    from frfw.config import loader
    from frfw.config.errors import ConfigError
    from frfw.nft import builder
    from frfw.nft.schedule import current_clock

    import yaml

    original_parse = loader.parse_config
    original_build = builder.build_ruleset
    original_safe_load = yaml.safe_load

    def safe_load(stream):
        if not isinstance(stream, str):
            _skipped["yaml_not_text"] += 1
            return original_safe_load(stream)
        try:
            value = original_safe_load(stream)
        except yaml.YAMLError as exc:
            _record("yaml", {"input": stream, "ok": False, "error": str(exc)})
            raise
        except Exception as exc:  # 1.x crashes: not a YAMLError
            _record("yaml", {"input": stream, "ok": False, "crash": type(exc).__name__})
            raise
        # yaml.safe_dump of it too, as 1.x's apply-helper writes a config
        # it changed (set_management_addresses).
        try:
            dumped = {"dump": yaml.safe_dump(value, sort_keys=False)}
        except Exception as exc:
            dumped = {"dump_crash": type(exc).__name__}
        try:
            _record("yaml", {"input": stream, "ok": True, "value": _tagged(value), **dumped})
        except _Recursive:
            _record("yaml", {"input": stream, "ok": True, "recursive": True, **dumped})
        _text_by_value[id(value)] = (value, stream)
        return value

    def parse_config(raw, *args, **kwargs):
        snapshot = copy.deepcopy(raw)
        held = _text_by_value.get(id(raw))
        text = held[1] if held is not None and held[0] is raw and not args and not kwargs else None
        if text is not None and not _unchanged(snapshot, original_safe_load(text)):
            text = None  # the test changed the value after loading it
        try:
            result = original_parse(raw, *args, **kwargs)
        except ConfigError as exc:
            if _jsonable(snapshot) and not args and not kwargs:
                _record("config", {"input": snapshot, "ok": False, "error": str(exc)})
            if text is not None:
                _record("yaml_config", {"input": text, "ok": False, "error": str(exc)})
            raise
        except Exception as exc:  # 1.x crashes: not a ConfigError
            if text is not None:
                _record("yaml_config", {"input": text, "ok": False, "crash": type(exc).__name__})
            raise
        if text is not None:
            _record("yaml_config", {"input": text, "ok": True})
        if _jsonable(snapshot) and not args and not kwargs:
            _record("config", {"input": snapshot, "ok": True})
            _raw_by_config[id(result)] = (result, snapshot)
        else:
            _skipped["config_not_json"] += 1
        return result

    def build_ruleset(config, *, clock=None, now=None, runtime=None):
        if now is None:
            # A fixed moment, not the clock: the same call records the
            # same case on every run.
            now = FIXED_NOW
        if clock is None and any(r.schedule is not None for r in config.rules):
            clock = current_clock(config.timezone, datetime.datetime.fromtimestamp(now, datetime.UTC))
        output = original_build(config, clock=clock, now=now, runtime=runtime)
        held = _raw_by_config.get(id(config))
        if held is None or held[0] is not config:
            _skipped["ruleset_unknown_config"] += 1
            return output
        case = {
            "input": held[1],
            "now": now,
            # Built here, not by a test: tuples in them are just lists.
            "clock": _plain(dataclasses.asdict(clock)) if clock is not None else None,
            "runtime": _plain(dataclasses.asdict(runtime)) if runtime is not None else None,
            "output": output,
        }
        if _jsonable(case):
            _record("ruleset", case)
        else:
            _skipped["ruleset_not_json"] += 1
        return output

    loader.parse_config = config_pkg.parse_config = parse_config
    yaml.safe_load = safe_load
    builder.build_ruleset = nft_pkg.build_ruleset = build_ruleset


def pytest_configure(config):
    _patch()


def pytest_unconfigure(config):
    out = Path(os.environ.get("FROS_CAPTURE_DIR", "reference-out"))
    out.mkdir(parents=True, exist_ok=True)
    for kind, cases in _cases.items():
        with open(out / f"{kind}.jsonl", "w", encoding="utf-8") as f:
            for key in sorted(cases):
                # Keys keep the order the config had: 1.x walks mappings
                # in that order (zones, interfaces...), so it shows in the
                # first error reported and in the ruleset's order.
                f.write(json.dumps({"id": key, **cases[key]}, ensure_ascii=False) + "\n")
    summary = {kind: len(cases) for kind, cases in _cases.items()} | {"skipped": _skipped}
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
