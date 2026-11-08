package config

import (
	"math/big"
	"strings"
)

// Decided names the decision (testdata/reference/decisions.md) that a
// config 1.x accepts falls under, which makes 2.x refuse it, or "". For
// this module's differential tests: they skip such cases.
func Decided(raw Value) string {
	top, _ := raw.(*Map)
	if top == nil {
		return ""
	}
	section := func(name string) *Map { m, _ := top.get(name, nil).(*Map); return m }
	if m := section("xdp_sni_filter"); m != nil && endsInNewline(m.get("blocklist", nil)) {
		return "trailing newline"
	}
	if m := section("adblocker"); m != nil && endsInNewline(m.get("allowlist", nil)) {
		return "trailing newline"
	}
	if m := section("adblocker"); m != nil && beyond64(m.get("xdp_critical_limit", nil)) {
		return "64-bit integers"
	}
	if rules, _ := top.get("rules", nil).([]Value); rules != nil {
		for _, r := range rules {
			if r, _ := r.(*Map); r != nil && r.get("dst_port", nil) == Value(true) {
				return "boolean ports"
			}
		}
	}
	if m := section("nat"); m != nil {
		forwards, _ := m.get("port_forwards", nil).([]Value)
		for _, f := range forwards {
			if f, _ := f.(*Map); f != nil && (f.get("dst_port", nil) == Value(true) || f.get("to_port", nil) == Value(true)) {
				return "boolean ports"
			}
		}
	}
	if m := section("dhcp"); m != nil {
		for _, v := range m.Values() {
			if pool, _ := v.(*Map); pool != nil && beyond64(pool.get("lease_time", nil)) {
				return "64-bit integers"
			}
		}
	}
	return ""
}

func endsInNewline(v Value) bool {
	list, _ := v.([]Value)
	for _, e := range list {
		if s, ok := e.(string); ok && strings.HasSuffix(s, "\n") {
			return true
		}
	}
	return false
}

func beyond64(v Value) bool {
	n, ok := v.(*big.Int)
	return ok && n.Sign() > 0 && !n.IsInt64()
}
