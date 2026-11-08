"""The files FR_OS 1.x's apply writes, rendered from every config the run
saw accepted, recorded for FR_OS 2's renderers (reference/generate.sh
runs this module last, after the ruleset module, so it sees every
config the run accepted).

For each accepted config it renders what apply_all writes or hands a
program: Kea's DHCPv4 config, the ad-block resolver's dnsmasq config,
dhcpcd's and the RA instance's configs and the kernel's IPv6 settings,
the WireGuard tunnel's `wg syncconf` text and sshd's management drop-in.
Those that depend on the router's generated ULA prefix (FND-1c: the RA,
the tunnel, sshd's listen addresses) are rendered again with one in the
state file, and recorded only where they differ. Then the two PQC
fragments, which only depend on whether the host can do hybrid key
exchange. Each case is recorded here, keyed by
the config case's id in config.jsonl; a renderer that raises records the
exception's type. Nothing here asserts anything about 1.x.
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

from frfw import ipv6, management, paths, pqc, wireguard
from frfw import kea
from frfw.adblock import dns_service
from frfw.config import loader

#: The router's generated ULA prefixes the state file holds (alternating
#: between configs): one with no zero groups, one whose text compresses.
GENERATED = ["fd12:3456:789a::/48", "fd00:0:1::/48"]

#: What render_conf is given as the router's private key: the renderer
#: only copies it.
PRIVATE_KEY = "cHJpdmF0ZS1rZXktb2YtdGhlLXJvdXRlci0wMDAwMDA="


def _record(case: dict) -> None:
    capture = sys.modules.get("fros_capture")
    if capture is not None:
        capture._record("render", case)


def _render(renders: dict) -> tuple[dict, dict]:
    output, error = {}, {}
    for name, render in renders.items():
        try:
            output[name] = render()
        except Exception as exc:  # the type is the answer
            error[name] = type(exc).__name__
    return output, error


def _with_state(tmp_path: Path, generated: str | None):
    state = tmp_path / "ipv6_ula.json"
    state.unlink(missing_ok=True)
    if generated is not None:
        state.write_text(json.dumps({"generated": generated}))
    paths.IPV6_ULA_STATE_PATH = state


#: How many configs the variants are made from: the first few with DHCP
#: and IPv6 on (each variant is one more config case and render case).
VARIANT_BASES = 12


def _accepted(capture) -> list:
    return [(key, case["input"]) for key, case in sorted(capture._cases["config"].items()) if case["ok"]]


def _variants(raw: dict) -> list[dict]:
    """What 1.x's suite has few configs with: a reservation's hostname
    outside ASCII (Kea's JSON escapes it), PQC on (sshd's drop-in then
    leaves KexAlgorithms to frfw.pqc's), query logging, and management
    over IPv6 with allow_wan."""
    out = []
    for zone in (raw.get("dhcp") or {}).values():
        for reservation in zone.get("reservations") or []:
            changed = copy.deepcopy(raw)
            for z in changed["dhcp"].values():
                for r in z.get("reservations") or []:
                    r["hostname"] = "caf\u00e9-\U0001f600-\u2028\x7f"
            out.append(changed)
            break
        break
    out.append(copy.deepcopy(raw) | {"pqc": {"enabled": True}})
    adblocker = raw.get("adblocker") or {}
    if adblocker.get("enabled"):
        out.append(copy.deepcopy(raw) | {"adblocker": adblocker | {"query_logging": True}})
    management = raw.get("management") or {}
    for extra in ({"ipv6": True}, {"ipv6": True, "allow_wan": True}, {"allow_wan": True}):
        out.append(copy.deepcopy(raw) | {"management": management | extra})
    return out


def test_variants():
    """Run first (pytest keeps the file's order): the configs it has 1.x
    accept are rendered with the rest below."""
    capture = sys.modules.get("fros_capture")
    if capture is None:
        return
    bases = [raw for _, raw in _accepted(capture)
             if isinstance(raw, dict) and raw.get("dhcp") and (raw.get("ipv6") or {}).get("enabled")]
    for raw in bases[:VARIANT_BASES]:
        for variant in _variants(raw):
            try:
                loader.parse_config(variant)
            except Exception:  # refused: recorded as such, not rendered
                pass


def test_every_accepted_config(tmp_path, monkeypatch):
    capture = sys.modules.get("fros_capture")
    if capture is None:
        return
    monkeypatch.setattr(paths, "IPV6_ULA_STATE_PATH", paths.IPV6_ULA_STATE_PATH)
    for n, (key, raw) in enumerate(_accepted(capture)):
        try:
            config = loader.parse_config(copy.deepcopy(raw))
        except Exception:
            continue  # accepted with arguments this module doesn't give
        base: dict = {}
        for generated in (None, GENERATED[n % 2]):
            _with_state(tmp_path, generated)
            renders = {
                "ra": lambda: ipv6.render_ra_conf(config, ipv6.ula_prefix(config)),
                "wireguard": lambda: wireguard.render_conf(config.wireguard, PRIVATE_KEY, ipv6.ula_prefix(config)),
                "sshd": lambda: management.sshd_dropin(config),
            }
            if generated is None:
                renders |= {
                    "kea": lambda: kea.render_kea_config(config),
                    "dnsmasq": lambda: dns_service.render_dnsmasq_config(config),
                    "dhcpcd": lambda: ipv6.render_dhcpcd_conf(config),
                    "sysctl": lambda: [list(kv) for kv in ipv6.sysctl_settings(config).items()],
                }
            output, error = _render(renders)
            if generated is None:
                base = output
            else:  # only what the state changed
                output = {k: v for k, v in output.items() if base.get(k) != v}
            _record({"config": key, "ula_state": generated, "output": output, "error": error})


def test_pqc(tmp_path):
    for hybrid in (False, True):
        conf = tmp_path / "openssl.cnf"
        pqc.write_openssl_pqc_conf(conf, hybrid=hybrid)
        _record({"pqc": "tls", "hybrid": hybrid, "output": {"tls": conf.read_text()}})
        kex = pqc._SSHD_DROPIN_TEMPLATE.format(kex_line=pqc.build_kex_line(hybrid=hybrid))
        _record({"pqc": "ssh", "hybrid": hybrid, "output": {"ssh": kex}})
