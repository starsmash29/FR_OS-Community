"""pytest plugin: record what FR_OS 1.x (Python) does, as the reference
FR_OS 2 must reproduce (AGENTS.md, "Differential tests").

Run inside a checkout of the Python FR_OS at the commit pinned in
reference/PIN, over its own test suite:

    FROS_CAPTURE_DIR=/path/out python3 -m pytest -p fros_capture tests --ignore=tests/webui -q

Every call of `parse_config` (the schema check) and `build_ruleset`
(the nft script) made anywhere in the suite is written down: the raw
input, and the result or the error. A test's own assertions don't
matter here; what the 1.x code returned for that input does. Calls whose
input can't be written as JSON, or whose Config didn't come from a
recorded parse_config (a test built it by hand), are counted, not
recorded.

Defaults that depend on the moment (`now`, the schedule clock) are
fixed before the call and recorded, so each case replays exactly; `now`
is a fixed date, so a rerun records the same rulesets. (A config a test
builds from the current time, such as an expiry an hour from now, still
changes from run to run.)
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
_cases: dict[str, dict[str, dict]] = {"config": {}, "ruleset": {}}
_skipped = {"config_not_json": 0, "ruleset_unknown_config": 0, "ruleset_not_json": 0}


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


def _record(kind: str, case: dict) -> None:
    _cases[kind].setdefault(_key(case), case)


def _patch():
    from frfw import config as config_pkg
    from frfw import nft as nft_pkg
    from frfw.config import loader
    from frfw.config.errors import ConfigError
    from frfw.nft import builder
    from frfw.nft.schedule import current_clock

    original_parse = loader.parse_config
    original_build = builder.build_ruleset

    def parse_config(raw, *args, **kwargs):
        snapshot = copy.deepcopy(raw)
        try:
            result = original_parse(raw, *args, **kwargs)
        except ConfigError as exc:
            if _jsonable(snapshot) and not args and not kwargs:
                _record("config", {"input": snapshot, "ok": False, "error": str(exc)})
            raise
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
