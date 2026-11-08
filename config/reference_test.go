package config

import (
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/starsmash29/fr_os-community/internal/reference"
)

// TestReference replays every config FR_OS 1.x's test suite fed its
// parse_config (AGENTS.md, "Differential tests"): each must be accepted
// or refused as 1.x did, and with 1.x's message.
func TestReference(t *testing.T) {
	cases, err := reference.ConfigCases()
	if err != nil {
		t.Fatal(err)
	}
	// reference/generate.sh records with TZ=UTC: an expiry without an
	// offset, in a config without a timezone, was read in UTC.
	defer func(l *time.Location) { Local = l }(Local)
	Local = time.UTC

	var accepted, refused, diffs int
	for _, c := range cases {
		raw, err := ParseJSON(c.Input)
		if err != nil {
			t.Fatalf("%s: %v", c.ID, err)
		}
		_, err = Parse(raw)
		if name := decided(raw); name != "" && c.OK {
			// A decided difference: 1.x accepted it, 2.x refuses it.
			if err == nil {
				t.Errorf("%s: decision %q: accepted here", c.ID, name)
			}
			diffs++
			continue
		}
		switch {
		case c.OK && err != nil:
			t.Errorf("%s: 1.x accepted it, refused here: %v", c.ID, err)
		case !c.OK && err == nil:
			t.Errorf("%s: 1.x refused it (%s), accepted here", c.ID, c.Error)
		case !c.OK && err.Error() != c.Error:
			t.Errorf("%s: refused with another message\n  1.x: %s\n  2.x: %s", c.ID, c.Error, err)
		case c.OK:
			accepted++
		default:
			refused++
		}
	}
	t.Logf("%d cases: %d accepted and %d refused as 1.x did, %d differ by decision", len(cases), accepted, refused, diffs)
}

// decided names the decision a case falls under (testdata/reference/
// decisions.md), or "".
func decided(raw Value) string {
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
	if m := section("dhcp"); m != nil {
		for _, z := range m.Keys() {
			if pool, _ := m.vals[z].(*Map); pool != nil && beyond64(pool.get("lease_time", nil)) {
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
